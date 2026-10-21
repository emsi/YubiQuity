#!/usr/bin/env python3
"""Independent real-hidraw credential and authorization verification.

All credentials are ephemeral; no public accounts, browser virtual authenticator,
existing vault or platform passkeys are involved.
"""
import hashlib
import os
import select
import struct
import threading
import time
import unittest

from cryptography.exceptions import InvalidSignature
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2 import cbor
from transport_integration import daemon, deadline, open_device


def register(ctap, user=b"alice", resident=False, **kwargs):
    return ctap.make_credential(
        os.urandom(32), {"id": "example.test", "name": "Example"},
        {"id": user, "name": user.decode(), "displayName": user.decode().title()},
        [{"type": "public-key", "alg": -7}], options={"rk": resident}, **kwargs,
    )


def allow(credential):
    return [{"type": "public-key", "id": credential.credential_id}]


def prompt(process):
    if not select.select([process.stdout], [], [], 5)[0]:
        raise TimeoutError("no approval prompt")
    line = process.stdout.readline()
    if not line.startswith("APPROVAL "):
        raise AssertionError(f"unexpected daemon output: {line}")
    return line.split()[1]


def answer(process, action, token):
    process.stdin.write(f"{action} {token}\n")
    process.stdin.flush()


class Task:
    def __init__(self, function):
        self.result = None
        self.error = None
        def run():
            try:
                self.result = function()
            except BaseException as error:
                self.error = error
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def finish(self, timeout=5):
        self.thread.join(timeout=timeout)
        if self.thread.is_alive():
            raise TimeoutError("FIDO operation did not finish")
        if self.error is not None:
            raise self.error
        return self.result


class CredentialTests(unittest.TestCase):
    def assert_ctap_error(self, code, function):
        with self.assertRaises(CtapError) as error:
            function()
        self.assertEqual(error.exception.code, code)

    def test_registration_signature_rp_and_exclusion(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            registration = register(ctap)
            self.assertEqual(registration.fmt, "none")
            self.assertEqual(registration.att_stmt, {})
            self.assertEqual(registration.auth_data.flags, 0x41)
            credential = registration.auth_data.credential_data
            second = register(ctap).auth_data.credential_data
            self.assertNotEqual(credential.credential_id, second.credential_id)
            self.assertNotEqual(dict(credential.public_key), dict(second.public_key))
            challenge_hash = os.urandom(32)
            assertion = ctap.get_assertion("example.test", challenge_hash, allow(credential))
            self.assertEqual(assertion.auth_data.rp_id_hash, hashlib.sha256(b"example.test").digest())
            self.assertEqual(assertion.auth_data.flags, 1)
            self.assertEqual(assertion.auth_data.counter, 0)
            credential.public_key.verify(assertion.auth_data + challenge_hash, assertion.signature)
            with self.assertRaises(InvalidSignature):
                credential.public_key.verify(assertion.auth_data + os.urandom(32), assertion.signature)
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("wrong.test", challenge_hash, allow(credential), options={"up": False}))
            self.assert_ctap_error(CtapError.ERR.CREDENTIAL_EXCLUDED, lambda: register(ctap, exclude_list=allow(credential)))
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", challenge_hash, options={"up": False}))

    def test_discoverable_accounts_replacement_and_reset(self):
        with daemon("dev-run", "approve") as (_, path, _), deadline(15), open_device(path) as device:
            ctap = Ctap2(device)
            old = register(ctap, b"alice", True).auth_data.credential_data
            alice = register(ctap, b"alice", True).auth_data.credential_data
            bob = register(ctap, b"bob", True).auth_data.credential_data
            challenge_hash = os.urandom(32)
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", challenge_hash, allow(old), options={"up": False}))
            first = ctap.get_assertion("example.test", challenge_hash)
            self.assertEqual(first.number_of_credentials, 2)
            self.assertEqual(first.user, {"id": b"bob"})
            self.assertEqual(first.credential["id"], bob.credential_id)
            bob.public_key.verify(first.auth_data + challenge_hash, first.signature)
            second = ctap.get_next_assertion()
            self.assertEqual(second.user, {"id": b"alice"})
            self.assertIsNone(second.number_of_credentials)
            alice.public_key.verify(second.auth_data + challenge_hash, second.signature)
            self.assert_ctap_error(CtapError.ERR.NOT_ALLOWED, ctap.get_next_assertion)
            ctap.reset()
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", challenge_hash, options={"up": False}))

    def test_terminal_approval_silent_probe_and_denial(self):
        with daemon("dev-run") as (process, path, _), deadline(20), open_device(path) as device:
            ctap = Ctap2(device)
            task = Task(lambda: register(ctap))
            token = prompt(process)
            answer(process, "approve", "wrong-token")
            time.sleep(0.15)
            self.assertTrue(task.thread.is_alive())
            answer(process, "approve", token)
            credential = task.finish().auth_data.credential_data
            assertion = ctap.get_assertion("example.test", os.urandom(32), allow(credential), options={"up": False})
            self.assertEqual(assertion.auth_data.flags, 0)
            self.assertFalse(select.select([process.stdout], [], [], 0.15)[0])
            task = Task(lambda: ctap.get_assertion("example.test", os.urandom(32), allow(credential)))
            token = prompt(process)
            answer(process, "deny", token)
            self.assert_ctap_error(CtapError.ERR.OPERATION_DENIED, task.finish)

    def test_cancellation_rejects_stale_approval_and_does_not_create_keys(self):
        with daemon("dev-run") as (process, path, _), deadline(20), open_device(path) as device:
            ctap = Ctap2(device)
            cancel = threading.Event()
            keepalives = []
            task = Task(lambda: register(ctap, resident=True, event=cancel, on_keepalive=keepalives.append))
            stale = prompt(process)
            cancel.set()
            self.assert_ctap_error(CtapError.ERR.KEEPALIVE_CANCEL, task.finish)
            self.assertIn(2, keepalives)
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", os.urandom(32), options={"up": False}))
            task = Task(lambda: register(ctap, resident=True))
            fresh = prompt(process)
            self.assertNotEqual(stale, fresh)
            answer(process, "approve", stale)
            time.sleep(0.15)
            self.assertTrue(task.thread.is_alive())
            answer(process, "approve", fresh)
            self.assertIsNotNone(task.finish().auth_data.credential_data)

    def test_approval_expires_and_cannot_authorize_the_next_request(self):
        # Exercise the production 30-second deadline, not a shortened test-only
        # timeout. No response/approval is sent until that deadline has expired.
        with daemon("dev-run") as (process, path, _), deadline(45), open_device(path) as device:
            ctap = Ctap2(device)
            start = time.monotonic()
            task = Task(lambda: register(ctap, resident=True))
            stale = prompt(process)
            self.assert_ctap_error(CtapError.ERR.USER_ACTION_TIMEOUT, lambda: task.finish(timeout=35))
            self.assertGreaterEqual(time.monotonic() - start, 29)
            self.assertLess(time.monotonic() - start, 36)
            self.assert_ctap_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion("example.test", os.urandom(32), options={"up": False}))
            task = Task(lambda: register(ctap, resident=True))
            fresh = prompt(process)
            self.assertNotEqual(stale, fresh)
            answer(process, "approve", stale)
            time.sleep(0.15)
            self.assertTrue(task.thread.is_alive())
            answer(process, "approve", fresh)
            self.assertIsNotNone(task.finish().auth_data.credential_data)

    def test_competing_channel_is_busy_and_recovers_after_cancel(self):
        # Linux delivers reports to all open hidraw descriptors. python-fido2
        # 1.1.2 rejects other CIDs rather than filtering them, so multiplex the
        # two channels on a raw descriptor for this transport-level test.
        with daemon("dev-run") as (process, path, _), deadline(20):
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
            try:
                def send(channel, command, payload):
                    initial = struct.pack(">IBH", channel, command | 0x80, len(payload)) + payload[:57]
                    os.write(fd, b"\0" + initial.ljust(64, b"\0"))
                    for index, offset in enumerate(range(57, len(payload), 59)):
                        report = struct.pack(">IB", channel, index) + payload[offset:offset + 59]
                        os.write(fd, b"\0" + report.ljust(64, b"\0"))

                def receive(channel, command):
                    end = time.monotonic() + 3
                    while time.monotonic() < end:
                        if select.select([fd], [], [], 0.1)[0]:
                            report = os.read(fd, 64)
                            if report[:5] == struct.pack(">IB", channel, command | 0x80):
                                return report
                    raise TimeoutError("expected channel response was not received")

                channels = []
                for _ in range(2):
                    nonce = os.urandom(8)
                    send(0xffffffff, 6, nonce)
                    reply = receive(0xffffffff, 6)
                    self.assertEqual(reply[7:15], nonce)
                    channels.append(struct.unpack(">I", reply[15:19])[0])
                first, second = channels
                self.assertNotEqual(first, second)
                registration = b"\x01" + cbor.encode({
                    1: os.urandom(32), 2: {"id": "example.test"},
                    3: {"id": b"alice"}, 4: [{"type": "public-key", "alg": -7}],
                })
                send(first, 0x10, registration)
                prompt(process)
                send(second, 0x10, b"\x04")
                self.assertEqual(receive(second, 0x3f)[7], CtapError.ERR.CHANNEL_BUSY)
                send(first, 0x11, b"")
                self.assertEqual(receive(first, 0x10)[7], CtapError.ERR.KEEPALIVE_CANCEL)
                send(second, 0x10, b"\x04")
                self.assertEqual(receive(second, 0x10)[7], 0)
                send(second, 0x10, registration)
                answer(process, "approve", prompt(process))
                self.assertEqual(receive(second, 0x10)[7], 0)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
