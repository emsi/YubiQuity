#!/usr/bin/env python3
"""Independent ClientPIN v1 tests through the real UHID/hidraw device.

Uses python-fido2/cryptography, not the Rust implementation's crypto helpers.
Only disposable in-memory state and public test PINs are used.
"""
import os
import unittest

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from credential_integration import Task, allow, answer, prompt, register
from transport_integration import daemon, deadline, open_device


class PinTests(unittest.TestCase):
    def error(self, code, function):
        with self.assertRaises(CtapError) as caught:
            function()
        self.assertEqual(caught.exception.code, code)

    def make_uv(self, ctap, client, token, user=b"alice"):
        digest = os.urandom(32)
        return ctap.make_credential(
            digest, {"id": "example.test"}, {"id": user, "name": user.decode(), "displayName": user.decode().title()},
            [{"type": "public-key", "alg": -7}], options={"rk": True},
            pin_uv_protocol=1, pin_uv_param=client.protocol.authenticate(token, digest),
        )

    def test_setup_uv_assertions_privacy_and_multiple_accounts(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            self.assertEqual(ctap.info.pin_uv_protocols, [1])
            self.assertFalse(ctap.info.options["clientPin"])
            self.assertNotIn("uv", ctap.info.options)
            pin = ClientPin(ctap)
            self.error(CtapError.ERR.PIN_NOT_SET, lambda: pin.get_pin_token("1234"))
            pin.set_pin("1234")
            self.assertTrue(ctap.get_info().options["clientPin"])
            # CTAP2.0 PIN_REQUIRED (0x36) is named PUAT_REQUIRED in newer clients.
            self.error(CtapError.ERR.PUAT_REQUIRED, lambda: register(ctap))
            self.error(CtapError.ERR.PIN_AUTH_INVALID, lambda: pin.set_pin("5678"))
            token = pin.get_pin_token("1234")
            self.assertEqual(len(token), 32)
            alice = self.make_uv(ctap, pin, token)
            self.assertEqual(alice.auth_data.flags, 0x45)
            bob = self.make_uv(ctap, pin, token, b"bob")
            digest = os.urandom(32)
            first = ctap.get_assertion("example.test", digest, pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(token, digest))
            self.assertEqual(first.auth_data.flags, 5)
            self.assertEqual(first.number_of_credentials, 2)
            self.assertEqual(first.user, {"id": b"bob", "name": "bob", "displayName": "Bob"})
            bob.auth_data.credential_data.public_key.verify(first.auth_data + digest, first.signature)
            second = ctap.get_next_assertion()
            self.assertEqual(second.auth_data.flags, 5)
            self.assertEqual(second.user["id"], b"alice")
            alice.auth_data.credential_data.public_key.verify(second.auth_data + digest, second.signature)
            silent = ctap.get_assertion("example.test", digest, allow(alice.auth_data.credential_data), options={"up": False})
            self.assertEqual(silent.auth_data.flags, 0)
            self.assertEqual(silent.user, {"id": b"alice"})

    def test_change_pin_invalidates_tokens_and_resets_retries(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap)
            pin.set_pin("1234")
            old = pin.get_pin_token("1234")
            self.error(CtapError.ERR.PIN_INVALID, lambda: pin.change_pin("wrong", "5678"))
            self.assertEqual(pin.get_pin_retries()[0], 7)
            pin.change_pin("1234", "5678")
            self.assertEqual(pin.get_pin_retries()[0], 8)
            self.error(CtapError.ERR.PIN_AUTH_INVALID, lambda: self.make_uv(ctap, pin, old))
            self.error(CtapError.ERR.PIN_INVALID, lambda: pin.get_pin_token("1234"))
            new = pin.get_pin_token("5678")
            self.assertNotEqual(old, new)
            self.assertEqual(pin.get_pin_retries()[0], 8)
            self.make_uv(ctap, pin, new)

    def test_bad_pin_rekeys_and_three_attempts_block_until_restart(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap)
            pin.set_pin("1234")
            previous = ctap.client_pin(1, 2)[1]
            for attempt, error in enumerate([CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_BLOCKED]):
                self.error(error, lambda: pin.get_pin_token("wrong"))
                self.assertEqual(pin.get_pin_retries()[0], 7 - attempt)
                current = ctap.client_pin(1, 2)[1]
                self.assertNotEqual(previous, current)
                previous = current
            self.error(CtapError.ERR.PIN_AUTH_BLOCKED, lambda: pin.get_pin_token("1234"))
            self.assertEqual(pin.get_pin_retries()[0], 5)

    def test_bad_token_mac_blocks_without_consuming_pin_retries(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap)
            pin.set_pin("1234")
            token = pin.get_pin_token("1234")
            for error in [CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.PIN_AUTH_BLOCKED]:
                self.error(error, lambda: self.make_uv(ctap, pin, b"\0" * 32))
            self.error(CtapError.ERR.PIN_AUTH_BLOCKED, lambda: self.make_uv(ctap, pin, token))
            self.assertEqual(pin.get_pin_retries()[0], 8)
            ctap.reset()
            self.assertFalse(ctap.get_info().options["clientPin"])
            pin.set_pin("1234")
            fresh = pin.get_pin_token("1234")
            self.assertNotEqual(token, fresh)
            self.make_uv(ctap, pin, fresh)

    def test_device_selection_requires_its_own_presence_and_creates_nothing(self):
        with daemon("dev-run") as (process, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            task = Task(lambda: register(ctap, pin_uv_param=b"", pin_uv_protocol=1))
            answer(process, "approve", prompt(process))
            self.error(CtapError.ERR.PIN_NOT_SET, task.finish)
            pin = ClientPin(ctap)
            pin.set_pin("1234")
            task = Task(lambda: ctap.get_assertion("example.test", os.urandom(32), pin_uv_param=b"", pin_uv_protocol=1))
            answer(process, "approve", prompt(process))
            self.error(CtapError.ERR.PIN_INVALID, task.finish)
            self.error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", os.urandom(32), options={"up": False}))
            self.assertEqual(pin.get_pin_retries()[0], 8)

    def test_malformed_crypto_and_pin_policy_are_rejected(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            pin = ClientPin(ctap, PinProtocolV1())
            peer, shared = pin._get_shared_secret()
            encrypted = pin.protocol.encrypt(shared, b"1234".ljust(64, b"\0"))
            self.error(CtapError.ERR.PIN_AUTH_INVALID, lambda: ctap.client_pin(1, 3, key_agreement=peer, new_pin_enc=encrypted, pin_uv_param=b"\0" * 16))
            invalid_peer = dict(peer)
            invalid_peer[-2] = b"\0" * 32
            invalid_peer[-3] = b"\0" * 32
            self.error(CtapError.ERR.INVALID_PARAMETER, lambda: ctap.client_pin(1, 3, key_agreement=invalid_peer, new_pin_enc=encrypted, pin_uv_param=b"\0" * 16))
            for plain in [b"123".ljust(64, b"\0"), b"a" * 64, b"1234\0not-padding".ljust(64, b"\0"), b"\xff" * 4 + b"\0" * 60]:
                encrypted = pin.protocol.encrypt(shared, plain)
                self.error(CtapError.ERR.PIN_POLICY_VIOLATION, lambda: ctap.client_pin(1, 3, key_agreement=peer, new_pin_enc=encrypted, pin_uv_param=pin.protocol.authenticate(shared, encrypted)))
            pin.set_pin("测试🔑PIN")
            pin.get_pin_token("测试🔑PIN")
            self.assertEqual(pin.get_pin_retries()[0], 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
