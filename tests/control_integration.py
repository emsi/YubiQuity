#!/usr/bin/env python3
"""Private user-service control plus real HID; all vaults/accounts are disposable."""
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from credential_integration import Task, allow, register
from transport_integration import BINARY, node_arguments, device_test_lock, deadline, open_device, wait_removed
from vault_integration import PASSWORD, cli


def ctl(path, action, *args, passphrase=PASSWORD, check=True, inherited=()):
    command = [str(BINARY), "control", "--socket", str(path), action, *args]
    secret_fd = None
    if action == "unlock":
        secret_fd, output = os.pipe()
        try:
            os.write(output, passphrase)
        finally:
            os.close(output)
        command += ["--passphrase-fd", str(secret_fd)]
    try:
        result = subprocess.run(command, pass_fds=inherited if secret_fd is None else (secret_fd,),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25)
    finally:
        if secret_fd is not None:
            os.close(secret_fd)
    if check and result.returncode:
        raise AssertionError(f"control {action} failed: {result.stdout} {result.stderr}")
    return json.loads(result.stdout)


def configure_pin(path, new, current=b"", check=True):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, bytes([len(current)]) + current + new)
    finally:
        os.close(write_fd)
    try:
        return ctl(path, "configure-pin", "--secret-fd", str(read_fd), check=check, inherited=(read_fd,))
    finally:
        os.close(read_fd)


class RunningService:
    def __init__(self, process, path):
        self.process = process
        self.path = path
        self.devices = []

    def unlock(self):
        result = ctl(self.path, "unlock")
        assert result["ok"] and result["state"] == "ready"
        if not select.select([self.process.stdout], [], [], 5)[0]:
            raise TimeoutError("service did not report its attached device")
        ready = self.process.stdout.readline().strip().split()
        assert len(ready) == 3 and ready[0] == "READY", ready
        self.devices.append((ready[1], ready[2]))
        return ready[1]

    def pending(self):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            status = ctl(self.path, "status")
            if status.get("pending"):
                return status["pending"]
            time.sleep(0.02)
        raise TimeoutError("no pending control approval")

    def approved(self, function):
        task = Task(function)
        pending = self.pending()
        ctl(self.path, "approve", pending["token"])
        return task.finish()


@contextlib.contextmanager
def service(vault, socket_path):
    with device_test_lock():
        process = subprocess.Popen([str(BINARY), "serve", "--vault", str(vault), "--socket", str(socket_path),
                                    *node_arguments()], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running = RunningService(process, socket_path)
        try:
            end = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"service startup failed: {process.stderr.read()}")
                try:
                    if socket_path.exists() and ctl(socket_path, "status")["state"] == "locked":
                        break
                except (OSError, AssertionError, json.JSONDecodeError):
                    pass
                if time.monotonic() > end:
                    raise TimeoutError("service did not start locked")
                time.sleep(0.02)
            yield running
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for path, unique in running.devices:
                wait_removed(path, unique)
            stdout, stderr = process.stdout.read(), process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            assert PASSWORD.decode() not in stdout + stderr
            assert "APPROVAL " not in stdout, "service must not send account/token prompts to the journal"
            if process.returncode == 0:
                assert not socket_path.exists(), "normal exit must remove the owned socket"


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="yubiquity-control-test-")
        self.addCleanup(self.directory.cleanup)
        self.vault = Path(self.directory.name) / "vault.yq"
        self.socket = Path(self.directory.name) / "control.sock"
        cli("init", self.vault)

    def test_desktop_pin_setup_persists_and_is_busy_during_browser_approval(self):
        with service(self.vault, self.socket) as running:
            self.assertFalse(configure_pin(self.socket, b"1234", check=False)["ok"])
            path = running.unlock()
            self.assertFalse(ctl(self.socket, "status")["pin_configured"])
            self.assertTrue(configure_pin(self.socket, b"1234")["pin_configured"])
            with deadline(20), open_device(path) as device:
                ctap = Ctap2(device)
                pin = ClientPin(ctap)
                pin.get_pin_token("1234")
                for _ in range(12):
                    rejected = configure_pin(self.socket, b"5678", b"wrong", check=False)
                    self.assertFalse(rejected["ok"])
                    self.assertIn("incorrect", rejected["error"])
                self.assertTrue(configure_pin(self.socket, b"5678", b"1234")["ok"])
                pin = ClientPin(ctap)
                token = pin.get_pin_token("5678")
                digest = b"r" * 32
                task = Task(lambda: ctap.make_credential(
                    digest, {"id": "example.test"}, {"id": b"alice", "name": "alice"},
                    [{"type": "public-key", "alg": -7}],
                    pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(token, digest)))
                pending = running.pending()
                rejected = configure_pin(self.socket, b"9999", b"5678", check=False)
                self.assertFalse(rejected["ok"])
                self.assertIn("in progress", rejected["error"])
                ctl(self.socket, "approve", pending["token"])
                task.finish()
            ctl(self.socket, "lock")
            path = running.unlock()
            self.assertTrue(ctl(self.socket, "status")["pin_configured"])
            with deadline(10), open_device(path) as device:
                pin = ClientPin(Ctap2(device))
                pin.get_pin_token("5678")
                self.assertEqual(pin.get_pin_retries()[0], 8)

    def error(self, code, function):
        with self.assertRaises(CtapError) as caught:
            function()
        self.assertEqual(caught.exception.code, code)

    def test_locked_start_explicit_approval_and_persistent_reunlock(self):
        with service(self.vault, self.socket) as running, deadline(35):
            self.assertEqual(ctl(self.socket, "status"), {"ok": True, "state": "locked"})
            self.assertFalse(select.select([running.process.stdout], [], [], 0.1)[0])
            original = self.vault.read_bytes()
            for _ in range(16):
                self.assertFalse(ctl(self.socket, "unlock", passphrase=b"incorrect test passphrase", check=False)["ok"])
                self.assertEqual(ctl(self.socket, "status")["state"], "locked")
                self.assertEqual(self.vault.read_bytes(), original)
            path = running.unlock()
            with open_device(path) as device:
                ctap = Ctap2(device)
                task = Task(lambda: register(ctap, resident=True))
                pending = running.pending()
                self.assertEqual(pending["rp_id"], "example.test")
                self.assertFalse(ctl(self.socket, "approve", "wrong-token", check=False)["ok"])
                self.assertTrue(task.thread.is_alive())
                ctl(self.socket, "deny", pending["token"])
                self.error(CtapError.ERR.OPERATION_DENIED, task.finish)
                credential = running.approved(lambda: register(ctap, resident=True)).auth_data.credential_data
            self.assertEqual(ctl(self.socket, "lock")["state"], "locked")
            wait_removed(*running.devices[-1])
            # Lock must release the vault lock and preserve only encrypted state.
            self.assertEqual(len(json.loads(cli("list", self.vault).stdout)["credentials"]), 1)
            path = running.unlock()
            self.assertFalse(ctl(self.socket, "approve", pending["token"], check=False)["ok"])
            with open_device(path) as device:
                digest = os.urandom(32)
                assertion = running.approved(lambda: Ctap2(device).get_assertion("example.test", digest, allow(credential)))
                credential.public_key.verify(assertion.auth_data + digest, assertion.signature)

    def test_cancel_and_slow_or_malformed_control_clients_do_not_block_hid(self):
        with service(self.vault, self.socket) as running, deadline(30):
            path = running.unlock()
            with socket.socket(socket.AF_UNIX) as slow, open_device(path) as device:
                slow.connect(str(self.socket))
                slow.sendall(b"\0")
                ctap = Ctap2(device)
                self.assertIn("FIDO_2_0", ctap.get_info().versions)
                cancel = threading.Event()
                task = Task(lambda: register(ctap, resident=True, event=cancel))
                stale = running.pending()["token"]
                cancel.set()
                self.error(CtapError.ERR.KEEPALIVE_CANCEL, task.finish)
                self.assertFalse(ctl(self.socket, "approve", stale, check=False)["ok"])
                with socket.socket(socket.AF_UNIX) as malformed:
                    malformed.settimeout(2)
                    malformed.connect(str(self.socket))
                    malformed.sendall(struct.pack(">I", 0xffffffff))
                    self.assertEqual(malformed.recv(1), b"")
                credential = running.approved(lambda: register(ctap, resident=True))
                self.assertIsNotNone(credential.auth_data.credential_data)

    def test_lock_cancels_pending_operation_and_invalidates_pin_token(self):
        with service(self.vault, self.socket) as running, deadline(35):
            path = running.unlock()
            with open_device(path) as device:
                ctap = Ctap2(device)
                pin = ClientPin(ctap)
                pin.set_pin("1234")
                old_token = pin.get_pin_token("1234")
                digest = os.urandom(32)
                task = Task(lambda: register(ctap, pin_uv_protocol=1, pin_uv_param=pin.protocol.authenticate(old_token, digest)))
                # register() creates a different hash, so the wrong MAC must
                # fail immediately without a presence request.
                self.error(CtapError.ERR.PIN_AUTH_INVALID, task.finish)
                request = lambda token, client: ctap.make_credential(
                    digest, {"id": "example.test"}, {"id": b"alice"},
                    [{"type": "public-key", "alg": -7}], options={"rk": True},
                    pin_uv_protocol=1, pin_uv_param=client.protocol.authenticate(token, digest))
                task = Task(lambda: request(old_token, pin))
                stale = running.pending()["token"]
                self.assertEqual(ctl(self.socket, "lock")["state"], "locked")
                wait_removed(*running.devices[-1])
                task.thread.join(timeout=3)
                self.assertFalse(task.thread.is_alive())
                self.assertIsNone(task.result)
            self.assertEqual(json.loads(cli("list", self.vault).stdout)["credentials"], [])
            with open_device(running.unlock()) as device:
                ctap = Ctap2(device)
                pin = ClientPin(ctap)
                self.error(CtapError.ERR.PIN_AUTH_INVALID, lambda: request(old_token, pin))
                self.assertFalse(ctl(self.socket, "approve", stale, check=False)["ok"])
                fresh = pin.get_pin_token("1234")
                self.assertNotEqual(old_token, fresh)
                self.assertEqual(running.approved(lambda: request(fresh, pin)).auth_data.flags, 0x45)

    def test_crash_leaves_only_a_recoverable_socket_and_restarts_locked(self):
        with service(self.vault, self.socket) as running, deadline(20):
            path = running.unlock()
            with open_device(path) as device:
                credential = running.approved(lambda: register(Ctap2(device), resident=True)).auth_data.credential_data
            running.process.kill()
            running.process.wait(timeout=5)
            wait_removed(*running.devices[-1])
            self.assertTrue(self.socket.is_socket())
        with service(self.vault, self.socket) as restarted, deadline(20):
            self.assertEqual(ctl(self.socket, "status")["state"], "locked")
            with open_device(restarted.unlock()) as device:
                digest = os.urandom(32)
                assertion = restarted.approved(lambda: Ctap2(device).get_assertion("example.test", digest, allow(credential)))
                credential.public_key.verify(assertion.auth_data + digest, assertion.signature)

    def test_other_uid_is_rejected_even_if_it_bypasses_directory_permissions(self):
        with service(self.vault, self.socket), deadline(10):
            # Root can traverse the 0700 directory, but the protocol must reject
            # that different peer UID. This is not protection against root.
            code = """
import socket, sys
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(2)
    client.connect(sys.argv[1])
    try:
        assert client.recv(1) == b''
    except ConnectionResetError:
        pass
"""
            subprocess.run(["sudo", "-n", "/usr/bin/python3", "-I", "-c", code, str(self.socket)], check=True, timeout=5)
            self.assertEqual(ctl(self.socket, "status")["state"], "locked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
