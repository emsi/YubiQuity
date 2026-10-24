#!/usr/bin/env python3
"""Run the real udev rule engine against synthetic devices inside a private chroot.

Requires sudo/root *in the development container* for chroot, not host access or
mount capabilities. There are no bind mounts, real devices, uevent emission to
the host, installed rules, or running udev daemon. Only copied executables,
libraries, rules and umockdev fixtures exist inside the temporary root.
"""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

import gi
gi.require_version("UMockdev", "1.0")
from gi.repository import UMockdev

ROOT = Path(__file__).resolve().parents[1]
PRELOAD = Path("/usr/lib/x86_64-linux-gnu/libumockdev-preload.so.0")
BASE = "/devices/virtual/misc/uhid"
HID = BASE + "/0003:FFFF:0001.0001"
NODE = HID + "/hidraw/hidraw4242"


def copy_binary(root, path):
    path = Path(path)
    destination = root / path.relative_to("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, destination)
    destination.chmod(0o755)
    linked = subprocess.run(["ldd", str(path)], capture_output=True, text=True, check=True)
    for library in re.findall(r"(?:=>\s+)?(/[^\s()]+)", linked.stdout):
        source = Path(library)
        target = root / source.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)


class UdevBehaviorTests(unittest.TestCase):
    def test_acl_grants_an_already_running_process_access_without_new_groups(self):
        self.assertEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory(prefix="yubiquity-acl-") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            node = root / "device"
            # Private duplicate of the harmless null device, never host UHID.
            os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
            requests_read, requests_write = os.pipe()
            replies_read, replies_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(requests_write)
                os.close(replies_read)
                try:
                    os.setgroups([])
                    os.setgid(42420)
                    os.setuid(42420)
                    with os.fdopen(requests_read) as requests, os.fdopen(replies_write, "w", buffering=1) as replies:
                        for _ in requests:
                            try:
                                descriptor = os.open(node, os.O_RDWR)
                                os.close(descriptor)
                                allowed = True
                            except PermissionError:
                                allowed = False
                            replies.write(f"{allowed}:{os.getgroups()}\n")
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            os.close(requests_read)
            os.close(replies_write)
            try:
                with os.fdopen(requests_write, "w", buffering=1) as requests, os.fdopen(replies_read) as replies:
                    requests.write("check\n")
                    self.assertEqual(replies.readline(), "False:[]\n")
                    subprocess.run(["setfacl", "-m", "u:42420:rw", "--", str(node)], check=True)
                    requests.write("check\n")
                    self.assertEqual(replies.readline(), "True:[]\n")
                    # Recreated nodes are denied until the udev ACL action runs.
                    node.unlink()
                    os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
                    requests.write("check\n")
                    self.assertEqual(replies.readline(), "False:[]\n")
                    subprocess.run(["setfacl", "-m", "u:42420:rw", "--", str(node)], check=True)
                    requests.write("check\n")
                    self.assertEqual(replies.readline(), "True:[]\n")
                    self.assertEqual(node.stat().st_mode & 0o007, 0)
            finally:
                _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)

    def run_rule(self, *, name="YubiQuity Software FIDO2", unique="yubiquity-test",
                 hid=HID, action="add", target="hidraw"):
        self.assertEqual(os.geteuid(), 0, "run this isolated fixture with sudo -n /usr/bin/python3")
        with tempfile.TemporaryDirectory(prefix="yubiquity-udev-chroot-") as temporary:
            root = Path(temporary)
            for program in ("/usr/bin/udevadm", "/usr/bin/env", PRELOAD):
                copy_binary(root, program)
            for directory in ("etc/udev/rules.d", "usr/lib/udev/rules.d", "run/udev/data", "dev", "sys", "proc"):
                (root / directory).mkdir(parents=True, exist_ok=True)
            (root / "etc/group").write_text("root:x:0:\nyubiquity:x:4242:\n")
            (root / "etc/passwd").write_text("root:x:0:0:root:/:/bin/false\n")
            (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\n")
            shutil.copyfile(ROOT / "packaging/udev/72-yubiquity.rules", root / "etc/udev/rules.d/72-yubiquity.rules")
            (root / "etc/udev/rules.d/73-yubiquity-user-1000.rules").write_text(
                (ROOT / "packaging/user-access.rules.in").read_text().replace("@UID@", "1000"))
            # A later assignment must not override the final group/mode; an
            # earlier generic uaccess tag must be removed for matching devices.
            (root / "etc/udev/rules.d/70-fixture.rules").write_text('SUBSYSTEM=="hidraw", TAG+="uaccess"\n')
            (root / "etc/udev/rules.d/99-fixture.rules").write_text('SUBSYSTEM=="hidraw", MODE="0666", GROUP="root"\n')
            node = hid + "/hidraw/hidraw4242"
            testbed = UMockdev.Testbed.new()
            testbed.add_from_string(
                f"P: {BASE}\nE: SUBSYSTEM=misc\nE: DEVNAME=/dev/uhid\nE: MAJOR=10\nE: MINOR=239\nN: uhid\nA: dev=10:239\n\n"
                f"P: {hid}\nE: SUBSYSTEM=hid\nE: HID_NAME={name}\nE: HID_UNIQ={unique}\n\n"
                f"P: {node}\nE: SUBSYSTEM=hidraw\nE: DEVNAME=/dev/hidraw4242\nE: MAJOR=234\nE: MINOR=42\nN: hidraw4242\nA: dev=234:42\n\n")
            # Explicit multiline parent attribute tests the actual ATTRS matcher.
            testbed.set_attribute("/sys" + hid, "uevent", f"HID_ID=0003:0000FFFF:00000001\nHID_NAME={name}\nHID_UNIQ={unique}\n")
            shutil.copytree(testbed.get_root_dir(), root / "mock", symlinks=True,
                            ignore=shutil.ignore_patterns("ioctl", "uevent_socket"))
            # Rename the fixture's Unix socket directory into the private root;
            # its listener stays alive in this parent. No host socket is exposed.
            os.rename(Path(testbed.get_root_dir()) / "ioctl", root / "mock/ioctl")
            # umockdev uses PTYs by default. Do not expose those outside the
            # chroot: the rule test needs only metadata on private plain files.
            for filename in ("uhid", "hidraw4242"):
                mock_node = root / "mock/dev" / filename
                mock_node.unlink()
                mock_node.touch(mode=0o600)
            device = "/sys" + (BASE if target == "uhid" else node)
            result = subprocess.run(
                ["chroot", str(root), "/usr/bin/env", f"LD_PRELOAD={PRELOAD}",
                 # Synthetic sysfs is intentionally on an ordinary filesystem.
                 "UMOCKDEV_DIR=/mock", "SYSTEMD_DEVICE_VERIFY_SYSFS=0",
                 "/usr/bin/udevadm", "test", f"--action={action}", device],
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            return output

    def test_hidraw_rule_matches_and_final_assignments_survive_later_rules(self):
        for action in ("add", "change"):
            with self.subTest(action=action):
                output = self.run_rule(action=action)
                self.assertRegex(output, r"72-yubiquity\.rules:\d+ GROUP 4242")
                self.assertRegex(output, r"72-yubiquity\.rules:\d+ MODE 0660")
                self.assertNotRegex(output, r"99-fixture\.rules:1 (GROUP|MODE)")
                self.assertNotIn("CURRENT_TAGS=:uaccess:", output)
                self.assertIn("run: '/usr/bin/setfacl -m u:1000:rw -- /dev/hidraw4242'", output)

    def test_uhid_rule_matches(self):
        output = self.run_rule(target="uhid")
        self.assertRegex(output, r"72-yubiquity\.rules:\d+ GROUP 4242")
        self.assertRegex(output, r"72-yubiquity\.rules:\d+ MODE 0660")
        self.assertIn("run: '/usr/bin/setfacl -m u:1000:rw -- /dev/uhid'", output)

    def test_other_devices_and_remove_events_do_not_get_project_access(self):
        for parameters in ({"name": "Unrelated device"}, {"unique": "other-instance"},
                           {"hid": BASE + "/0003:1234:5678.0001"},
                           {"hid": "/devices/virtual/unrelated/0003:FFFF:0001.0001"},
                           {"action": "remove"}):
            with self.subTest(parameters=parameters):
                output = self.run_rule(**parameters)
                self.assertNotRegex(output, r"72-yubiquity\.rules:\d+ (GROUP|MODE)")
                self.assertNotIn("run: '/usr/bin/setfacl", output)
                self.assertIn("CURRENT_TAGS=:uaccess:", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
