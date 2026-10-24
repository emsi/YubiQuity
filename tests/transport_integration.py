#!/usr/bin/env python3
"""Real UHID/hidraw tests using independent clients. No virtual browser API.

Requires a built debug binary, /dev/uhid, sudo -n, the hidraw cgroup rule,
fido2-tools and python3-fido2. All devices/nodes belong to temporary daemons.
"""
import contextlib
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import resource
import struct
import subprocess
import time
import unittest

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice, CTAPHID, get_descriptor, list_descriptors, open_connection

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("YUBIQUITY_TEST_BINARY", ROOT / "target/debug/yubiquity"))
HELPER = ROOT / "scripts/container-hidraw.py"


def node_arguments(mode=None):
    """Never silently fall back to the helper during native deployment tests."""
    mode = mode if mode is not None else os.environ.get("YUBIQUITY_TEST_DEVICE_MODE", "container")
    if mode == "native":
        return []
    if mode == "container":
        return ["--node-helper", str(HELPER)]
    raise ValueError("YUBIQUITY_TEST_DEVICE_MODE must be native or container")


@contextlib.contextmanager
def open_device(path):
    descriptor = get_descriptor(path)
    device = CtapHidDevice(descriptor, open_connection(descriptor))
    try:
        yield device
    finally:
        device.close()


@contextlib.contextmanager
def deadline(seconds):
    def expired(_signum, _frame):
        raise TimeoutError("transport test exceeded its deadline")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def wait_removed(path, unique):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        device_exists = False
        for candidate in Path("/sys/class/hidraw").glob("hidraw*"):
            try:
                if "HID_UNIQ=" + unique in (candidate / "device/uevent").read_text().splitlines():
                    device_exists = True
            except FileNotFoundError:
                pass
        if not device_exists and not os.path.lexists(path):
            return
        time.sleep(0.02)
    raise AssertionError(f"Device or node leaked after daemon exit: {path}, {unique}")


@contextlib.contextmanager
def device_test_lock():
    # Browser discovery sees every FIDO device on the host. Serialize this
    # workspace's test devices so concurrent runners cannot select each other's
    # disposable authenticator. The descriptor is close-on-exec, never a child lock.
    lock_fd = os.open(ROOT / "target/device-tests.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield


@contextlib.contextmanager
def daemon(command="probe", test_presence=None, *, vault=None, passphrase=None, fail_writes=False, binary=None):
    with device_test_lock():
        with _daemon(command, test_presence, vault=vault, passphrase=passphrase, fail_writes=fail_writes, binary=binary) as running:
            yield running


@contextlib.contextmanager
def _daemon(command="probe", test_presence=None, *, vault=None, passphrase=None, fail_writes=False, binary=None):
    args = [str(BINARY if binary is None else binary), command, *node_arguments()]
    if command == "init":
        args.append("--run")
    if test_presence is not None:
        args += ["--test-presence", test_presence]
    secret_fd = None
    if vault is not None:
        if passphrase is None:
            raise ValueError("persistent daemon requires an explicit test passphrase")
        secret_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, passphrase)
        finally:
            os.close(write_fd)
        args += ["--vault", str(vault), "--passphrase-fd", str(secret_fd)]

    def limit_writes():
        # Test-only OS fault injection, not a daemon environment hook: writes to
        # regular files fail with EFBIG. Pipes and hidraw are unaffected.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    try:
        process = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            pass_fds=() if secret_fd is None else (secret_fd,),
            preexec_fn=limit_writes if fail_writes else None,
        )
    finally:
        if secret_fd is not None:
            os.close(secret_fd)
    path = unique = None
    try:
        if not select.select([process.stdout], [], [], 30)[0]:
            raise TimeoutError("daemon did not become ready")
        ready = process.stdout.readline().strip().split()
        if len(ready) != 3 or ready[0] != "READY":
            process.wait(timeout=5)
            raise AssertionError(f"Startup failed: {process.stderr.read()}")
        _, path, unique = ready
        yield process, path, unique
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if path is not None:
            wait_removed(path, unique)
        process.stdout.close()
        process.stderr.close()
        process.stdin.close()


class TransportTests(unittest.TestCase):
    def test_unsupported_control_reports_fail_promptly_and_transport_recovers(self):
        with daemon() as (_, path, _), deadline(8):
            fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            try:
                # Linux HIDIOCSFEATURE/HIDIOCGFEATURE use the control channel,
                # not ordinary CTAPHID output reports. Both must receive an
                # explicit UHID error reply instead of hanging a hidraw caller.
                for number in (0x06, 0x07):
                    request = (3 << 30) | (2 << 16) | (ord("H") << 8) | number
                    with self.subTest(ioctl=number), self.assertRaises(OSError) as caught:
                        fcntl.ioctl(fd, request, bytearray(2), True)
                    self.assertEqual(caught.exception.errno, errno.EIO)
            finally:
                os.close(fd)
            with open_device(path) as device:
                self.assertEqual(device.call(CTAPHID.PING, b"control-recovery"), b"control-recovery")

    def test_independent_clients_and_maximum_ping(self):
        with daemon() as (_, path, unique), deadline(15):
            descriptors = [d for d in list_descriptors() if d.path == path]
            self.assertEqual(len(descriptors), 1)
            self.assertEqual(descriptors[0].serial_number, unique)
            with open_device(path) as device:
                self.assertEqual(device.version, 2)
                self.assertEqual(int(device.capabilities), 0x0c)
                for length in (0, 1, 57, 58, 116, 117, 1024, 7609):
                    data = bytes(i % 256 for i in range(length))
                    self.assertEqual(device.call(CTAPHID.PING, data), data)
                info = Ctap2(device).get_info()
                self.assertEqual(info.versions, ["FIDO_2_0"])
                self.assertFalse(info.options["rk"])
                self.assertFalse(info.options["up"])
                self.assertNotIn("clientPin", info.options)
                self.assertNotIn("uv", info.options)
            listing = subprocess.run(["fido2-token", "-L"], capture_output=True, text=True, timeout=5, check=True)
            self.assertIn(path, listing.stdout)
            info = subprocess.run(["fido2-token", "-I", path], capture_output=True, text=True, timeout=5, check=True)
            self.assertIn("FIDO_2_0", info.stdout)

    def test_sigkill_removes_kernel_device_and_container_node(self):
        with daemon() as (process, path, unique):
            process.kill()
            process.wait(timeout=5)
            wait_removed(path, unique)

    def test_partial_frame_timeout_and_recovery(self):
        with daemon() as (_, path, _), deadline(8):
            with open_device(path) as device:
                # Independent raw I/O on this client's allocated channel.
                channel = device._channel_id
                fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
                try:
                    first = struct.pack(">IBH", channel, 0x81, 100).ljust(64, b"\0")
                    os.write(fd, b"\0" + first)
                    self.assertTrue(select.select([fd], [], [], 2)[0])
                    result = os.read(fd, 64)
                    self.assertEqual(result[:8], struct.pack(">IBHB", channel, 0xbf, 1, 5))
                finally:
                    os.close(fd)
            # Reopen so the previous client's unread timeout report cannot affect
            # this test's independent recovery transaction.
            with open_device(path) as device:
                self.assertEqual(device.call(CTAPHID.PING, b"recovered"), b"recovered")

    def test_malformed_lengths_and_sequence_recover_on_the_same_channel(self):
        with daemon() as (_, path, _), deadline(10), open_device(path) as device:
            channel = device._channel_id
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                def write(report):
                    self.assertEqual(os.write(fd, b"\0" + report), 65)

                def receive():
                    self.assertTrue(select.select([fd], [], [], 2)[0], "missing HID response")
                    return os.read(fd, 64)

                for command, length in ((0x81, 7610), (0x81, 65535), (0x90, 0)):
                    write(struct.pack(">IBH", channel, command, length).ljust(64, b"\0"))
                    self.assertEqual(receive()[:8], struct.pack(">IBHB", channel, 0xbf, 1, 3))
                write(struct.pack(">IBH", channel, 0x81, 100).ljust(64, b"\0"))
                write(struct.pack(">IB", channel, 1).ljust(64, b"\0"))  # sequence 0 was required
                self.assertEqual(receive()[:8], struct.pack(">IBHB", channel, 0xbf, 1, 4))
                ping = struct.pack(">IBH", channel, 0x81, 2) + b"ok"
                write(ping.ljust(64, b"\0"))
                self.assertEqual(receive()[:len(ping)], ping)
            finally:
                os.close(fd)

    def test_repeated_malformed_cbor_is_rejected_without_prompt_and_recovers(self):
        with daemon("dev-run") as (process, path, _), deadline(20), open_device(path) as device:
            malformed = (
                b"\xa1",                         # truncated map
                b"\xa2\x01\x00\x01\x01",        # duplicate map key
                b"\x18\x01",                    # noncanonical integer
                b"\x9f\xff",                    # indefinite collection
                b"\x81" * 13 + b"\x00",        # nesting bound
                b"\x99\x01\x01",               # collection bound
                b"\x5b" + b"\xff" * 8,          # enormous claimed byte-string length
                b"\x61\xff",                    # invalid UTF-8
            )
            for iteration in range(8):
                for payload in malformed:
                    with self.subTest(iteration=iteration, payload=payload.hex()):
                        self.assertEqual(device.call(CTAPHID.CBOR, b"\x01" + payload), b"\x12")
                self.assertTrue(Ctap2(device).get_info().options["rk"])
                self.assertEqual(device.call(CTAPHID.PING, b"recovered"), b"recovered")
            self.assertFalse(select.select([process.stdout], [], [], 0)[0], "malformed input prompted for presence")
            self.assertIsNone(process.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
