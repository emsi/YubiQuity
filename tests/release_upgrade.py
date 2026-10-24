#!/usr/bin/env python3
"""Exercise a real released binary's vault/PIN across a cryptography upgrade.

Run with the previous binary as the first argument and YUBIQUITY_TEST_BINARY
pointing to the candidate. Only disposable credentials and test secrets are used.
Verification uses Python FIDO/cryptography, independently of either Rust version.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from credential_integration import allow, register
from transport_integration import BINARY, daemon, deadline, open_device
from vault_integration import PASSWORD, approved, cli

PREVIOUS = Path(sys.argv.pop(1)).resolve()


class ReleaseUpgradeTests(unittest.TestCase):
    def test_existing_credentials_pin_and_new_writes_work_across_upgrade(self):
        self.assertNotEqual(PREVIOUS, BINARY.resolve())
        for binary in (PREVIOUS, BINARY):
            version = subprocess.check_output([str(binary), "--version"], text=True).strip()
            print(f"Testing {version}: {binary}", flush=True)
        with tempfile.TemporaryDirectory(prefix="yubiquity-upgrade-") as directory:
            vault = Path(directory) / "credentials.yq"
            cli("init", vault, binary=PREVIOUS)
            with daemon("run", vault=vault, passphrase=PASSWORD, binary=PREVIOUS) as (process, path, _), deadline(20), open_device(path) as device:
                ctap = Ctap2(device)
                original = approved(process, lambda: register(ctap, resident=True)).auth_data.credential_data
                ClientPin(ctap).set_pin("1234")
            previous_file = vault.read_bytes()
            metadata = json.loads(cli("list", vault).stdout)
            self.assertTrue(metadata["pin_configured"])
            self.assertEqual(metadata["credentials"][0]["credential_id"], original.credential_id.hex())
            with daemon("run", vault=vault, passphrase=PASSWORD) as (process, path, _), deadline(25), open_device(path) as device:
                ctap = Ctap2(device)
                pin = ClientPin(ctap)
                self.assertion(process, ctap, pin, "1234", original)
                # Authentication after upgrade requires no migration or rewrite.
                self.assertEqual(vault.read_bytes(), previous_file)
                pin.change_pin("1234", "5678")
                token = pin.get_pin_token("5678")
                digest = os.urandom(32)
                added = approved(process, lambda: ctap.make_credential(
                    digest, {"id": "example.test"}, {"id": b"bob", "name": "bob"},
                    [{"type": "public-key", "alg": -7}], options={"rk": True},
                    pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(token, digest),
                )).auth_data.credential_data
                self.assertion(process, ctap, pin, "5678", added)
            updated_file = vault.read_bytes()
            self.assertNotEqual(updated_file, previous_file)
            # Reopen in both directions: credentials created by either version,
            # and a changed PIN, must retain the same interoperable representation.
            for binary in (PREVIOUS, BINARY):
                with daemon("run", vault=vault, passphrase=PASSWORD, binary=binary) as (process, path, _), deadline(25), open_device(path) as device:
                    ctap = Ctap2(device)
                    pin = ClientPin(ctap)
                    for credential in (original, added):
                        self.assertion(process, ctap, pin, "5678", credential)
                self.assertEqual(vault.read_bytes(), updated_file)

    def assertion(self, process, ctap, pin, value, credential):
        digest = os.urandom(32)
        token = pin.get_pin_token(value)
        result = approved(process, lambda: ctap.get_assertion(
            "example.test", digest, allow(credential), pin_uv_protocol=1,
            pin_uv_param=pin.protocol.authenticate(token, digest),
        ))
        self.assertEqual(result.auth_data.flags, 5)
        self.assertEqual(result.credential["id"], credential.credential_id)
        credential.public_key.verify(result.auth_data + digest, result.signature)


if __name__ == "__main__":
    unittest.main(verbosity=2)
