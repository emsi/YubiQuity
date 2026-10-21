#!/usr/bin/env python3
"""Persistent CLI and actual disk/restart/crash tests through real hidraw.

Each case owns a private temporary directory. Passphrases use inherited pipes,
not arguments, environment variables or files. Normal persistent terminal
approvals are driven explicitly by the test; no automatic-presence daemon mode.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from credential_integration import Task, allow, answer, prompt, register
from transport_integration import BINARY, daemon, deadline, open_device, wait_removed

PASSWORD = b"disposable vault test passphrase"


def cli(command, vault, *arguments, passphrase=PASSWORD, check=True):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, passphrase)
    finally:
        os.close(write_fd)
    try:
        result = subprocess.run([str(BINARY), command, "--vault", str(vault), "--passphrase-fd", str(read_fd), *arguments],
                                pass_fds=(read_fd,), capture_output=True, text=True, timeout=30)
    finally:
        os.close(read_fd)
    if check and result.returncode:
        raise AssertionError(f"{command} failed: {result.stderr}")
    return result


def approved(process, function):
    task = Task(function)
    answer(process, "approve", prompt(process))
    return task.finish()


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="yubiquity-vault-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "vault.yq"
        cli("init", self.path)

    def error(self, code, function):
        with self.assertRaises(CtapError) as caught:
            function()
        self.assertEqual(caught.exception.code, code)

    def test_group_writable_user_ancestors_support_cli_init_and_list(self):
        local = Path(self.directory.name) / ".local"
        share = local / "share"
        app = share / "yubiquity"
        app.mkdir(parents=True, mode=0o700)
        for ancestor in (local, share):
            ancestor.chmod(0o775)
        path = app / "host-test/credentials.yq"

        cli("init", path)
        metadata = json.loads(cli("list", path).stdout)
        self.assertEqual(metadata["credentials"], [])
        self.assertFalse(metadata["pin_configured"])
        self.assertEqual(path.parent.stat().st_mode & 0o7777, 0o700)
        for private_file in (path, path.parent / ".credentials.yq.lock"):
            self.assertEqual(private_file.stat().st_mode & 0o7777, 0o600)
        for ancestor in (local, share):
            self.assertEqual(ancestor.stat().st_mode & 0o7777, 0o775)

    def test_restart_lock_metadata_and_exact_deletion(self):
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, unique), deadline(25), open_device(path) as device:
            credential = approved(process, lambda: register(Ctap2(device), resident=True)).auth_data.credential_data
            blocked = cli("list", self.path, check=False)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("locked by another process", blocked.stderr)
            process.stdin.write("lock\n")
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=5), 0)
            wait_removed(path, unique)
        metadata = json.loads(cli("list", self.path).stdout)
        self.assertEqual(metadata["credentials"][0]["credential_id"], credential.credential_id.hex())
        self.assertNotIn("name", metadata["credentials"][0])
        shown = json.loads(cli("list", self.path, "--show-users").stdout)
        self.assertEqual(shown["credentials"][0]["name"], "alice")
        self.assertNotIn("private_key", json.dumps(shown))
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            digest = os.urandom(32)
            assertion = approved(process, lambda: ctap.get_assertion("example.test", digest, allow(credential)))
            credential.public_key.verify(assertion.auth_data + digest, assertion.signature)
        encrypted_before = self.path.read_bytes()
        unconfirmed = cli("delete", self.path, "--credential-id", credential.credential_id.hex(), check=False)
        self.assertNotEqual(unconfirmed.returncode, 0)
        self.assertEqual(self.path.read_bytes(), encrypted_before)
        wrong_id = cli("delete", self.path, "--credential-id", "00" * 32, "--confirm", check=False)
        self.assertNotEqual(wrong_id.returncode, 0)
        self.assertEqual(self.path.read_bytes(), encrypted_before)
        cli("delete", self.path, "--credential-id", credential.credential_id.hex(), "--confirm")
        self.assertEqual(json.loads(cli("list", self.path).stdout)["credentials"], [])
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (_, path, _), deadline(10), open_device(path) as device:
            self.error(CtapError.ERR.NO_CREDENTIALS, lambda: Ctap2(device).get_assertion("example.test", os.urandom(32), allow(credential), options={"up": False}))

    def test_pin_retries_and_keys_survive_sigkill_and_block_across_restarts(self):
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, unique), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            credential = approved(process, lambda: register(ctap, resident=True)).auth_data.credential_data
            pin = ClientPin(ctap)
            pin.set_pin("1234")
            old_token = pin.get_pin_token("1234")
            for code in [CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_BLOCKED]:
                self.error(code, lambda: pin.get_pin_token("wrong"))
            self.assertEqual(pin.get_pin_retries()[0], 5)
            process.kill()
            process.wait(timeout=5)
            wait_removed(path, unique)
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap)
            self.assertEqual(pin.get_pin_retries()[0], 5)
            digest = os.urandom(32)
            self.error(CtapError.ERR.PIN_AUTH_INVALID, lambda: ctap.get_assertion("example.test", digest, allow(credential), pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(old_token, digest)))
            new_token = pin.get_pin_token("1234")
            self.assertNotEqual(old_token, new_token)
            self.assertEqual(pin.get_pin_retries()[0], 8)
            assertion = approved(process, lambda: ctap.get_assertion("example.test", digest, allow(credential), pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(new_token, digest)))
            self.assertEqual(assertion.auth_data.flags, 5)
            credential.public_key.verify(assertion.auth_data + digest, assertion.signature)
        remaining = 8
        for attempts in [3, 3, 2]:
            with daemon("run", vault=self.path, passphrase=PASSWORD) as (_, path, _), deadline(15), open_device(path) as device:
                pin = ClientPin(Ctap2(device))
                self.assertEqual(pin.get_pin_retries()[0], remaining)
                for attempt in range(attempts):
                    remaining -= 1
                    code = CtapError.ERR.PIN_BLOCKED if remaining == 0 else CtapError.ERR.PIN_AUTH_BLOCKED if attempt == 2 else CtapError.ERR.PIN_INVALID
                    self.error(code, lambda: pin.get_pin_token("wrong"))
                    self.assertEqual(pin.get_pin_retries()[0], remaining)
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap)
            self.assertEqual(pin.get_pin_retries()[0], 0)
            self.error(CtapError.ERR.PIN_BLOCKED, lambda: pin.get_pin_token("1234"))
            approved(process, ctap.reset)
            self.assertFalse(ctap.get_info().options["clientPin"])
        self.assertEqual(json.loads(cli("list", self.path).stdout)["credentials"], [])

    def test_real_write_failure_does_not_register_and_detaches(self):
        original = self.path.read_bytes()
        with daemon("run", vault=self.path, passphrase=PASSWORD, fail_writes=True) as (process, path, unique), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            # The failed write can race transport detach; neither a CTAP error
            # nor device disconnection is permitted to look like registration.
            with self.assertRaises((CtapError, OSError)):
                approved(process, lambda: register(ctap, resident=True))
            self.assertNotEqual(process.wait(timeout=5), 0)
            wait_removed(path, unique)
            self.assertIn("File too large", process.stderr.read())
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(list(self.path.parent.glob(".yubiquity-write-*")))
        self.assertEqual(json.loads(cli("list", self.path).stdout)["credentials"], [])

    def test_failed_retry_write_never_returns_a_pin_token(self):
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (_, path, _), deadline(10), open_device(path) as device:
            ClientPin(Ctap2(device)).set_pin("1234")
        original = self.path.read_bytes()
        with daemon("run", vault=self.path, passphrase=PASSWORD, fail_writes=True) as (process, path, unique), deadline(10), open_device(path) as device:
            pin = ClientPin(Ctap2(device))
            with self.assertRaises((CtapError, OSError)):
                pin.get_pin_token("1234")
            self.assertNotEqual(process.wait(timeout=5), 0)
            wait_removed(path, unique)
        self.assertEqual(self.path.read_bytes(), original)
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (_, path, _), deadline(10), open_device(path) as device:
            pin = ClientPin(Ctap2(device))
            self.assertEqual(pin.get_pin_retries()[0], 8)
            self.assertEqual(len(pin.get_pin_token("1234")), 32)

    def test_wrong_passphrase_corruption_and_initialization_do_not_overwrite(self):
        original = self.path.read_bytes()
        for command, password in [("list", b"definitely wrong passphrase"), ("init", PASSWORD)]:
            failed = cli(command, self.path, passphrase=password, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(self.path.read_bytes(), original)
            self.assertNotIn(password.decode(), failed.stdout + failed.stderr)
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        self.path.write_bytes(corrupt)
        failed = cli("list", self.path, check=False)
        self.assertIn("wrong vault passphrase or corrupt", failed.stderr)
        self.assertEqual(self.path.read_bytes(), corrupt)

    def test_stdin_eof_cancels_pending_request_and_locks(self):
        with daemon("run", vault=self.path, passphrase=PASSWORD) as (process, path, unique), deadline(15), open_device(path) as device:
            task = Task(lambda: register(Ctap2(device), resident=True))
            prompt(process)
            process.stdin.close()
            self.assertEqual(process.wait(timeout=5), 0)
            wait_removed(path, unique)
            with self.assertRaises((CtapError, OSError)):
                task.finish()
        self.assertEqual(json.loads(cli("list", self.path).stdout)["credentials"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
