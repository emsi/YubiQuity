#!/usr/bin/env python3
"""Independent Argon2/libsodium verification of disposable vault format v1.

Test fixtures only. This is not a supported credential export or import command.
"""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.exceptions import CryptoError
from vault_integration import PASSWORD, cli


class IndependentVaultCrypto(unittest.TestCase):
    def test_rust_vault_opens_with_argon2_and_libsodium_and_authenticates_header(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-vault-crypto-") as directory:
            path = Path(directory) / "vault.yq"
            cli("init", path)
            data = path.read_bytes()
            self.assertEqual(data[:8], b"YQVAULT\0")
            version, memory, passes, lanes = struct.unpack_from("<IIII", data, 8)
            self.assertEqual((version, memory, passes, lanes), (1, 65536, 3, 1))
            self.assertEqual(struct.unpack_from("<I", data, 64)[0], len(data) - 68)
            key = hash_secret_raw(PASSWORD, data[24:40], passes, memory, lanes, 32, Type.ID, version=19)
            plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(data[68:], data[:68], data[40:64], key)
            self.assertEqual(json.loads(plaintext), {"version": 1, "state": {"credentials": [], "pin": None}})
            bad_header = bytearray(data[:68])
            bad_header[12] ^= 1
            with self.assertRaises(CryptoError):
                crypto_aead_xchacha20poly1305_ietf_decrypt(data[68:], bytes(bad_header), data[40:64], key)
            # Independently encrypt a well-formed test PIN state and prove that
            # Rust authenticates/deserializes it. Never reads a user's vault.
            state = {"version": 1, "state": {"credentials": [], "pin": {"hash": [7] * 16, "retries": 4}}}
            encoded = json.dumps(state, separators=(",", ":")).encode()
            header = bytearray(data[:68])
            header[40:64] = bytes(range(24))  # fixed nonce only for this one test write
            struct.pack_into("<I", header, 64, len(encoded) + 16)
            ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(encoded, bytes(header), bytes(header[40:64]), key)
            path.write_bytes(bytes(header) + ciphertext)
            self.assertTrue(json.loads(cli("list", path).stdout)["pin_configured"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
