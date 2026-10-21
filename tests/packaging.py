#!/usr/bin/env python3
"""Offline package checks; never install rules or start/enable a user service.

Verify an exact copy of the unit with a private temporary runtime directory.
If the install path is absent, temporarily link the built binary there and
remove only that link afterward. This is not systemd/udev runtime validation.
"""
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_exact_user_unit_and_unknown_directive_detection(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-package-check-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            unit = root / "yubiquity.service"
            original = (ROOT / "packaging/systemd/yubiquity.service").read_bytes()
            install = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/bin/yubiquity"
            created = None
            if not os.path.lexists(install):
                self.assertTrue(os.access(ROOT / "target/debug/yubiquity", os.X_OK), "run cargo build --locked first")
                install.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                # Exclusive creation: never replace an existing executable/link.
                install.symlink_to(ROOT / "target/debug/yubiquity")
                created = install.lstat()
            command = ["systemd-analyze", "--user", "--man=no",
                       "--generators=no", "--recursive-errors=yes", "verify",
                       str(unit)]
            env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime))
            try:
                self.assertTrue(os.access(install, os.X_OK), "installed binary is not executable")
                unit.write_bytes(original)
                verified = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                self.assertNotIn("Unknown", verified.stderr)
                # Verify that a broken directive cannot silently produce a green
                # check with the same analyzer options (some defaults allow warnings).
                unit.write_bytes(original.replace(b"Type=exec", b"Type=exec\nYubiQuityUnknownDirective=yes"))
                broken = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(broken.returncode, 0, broken.stdout + broken.stderr)
                self.assertIn("YubiQuityUnknownDirective", broken.stderr)
            finally:
                if created is not None:
                    current = install.lstat()
                    self.assertEqual((current.st_dev, current.st_ino), (created.st_dev, created.st_ino),
                                     "temporary install link changed; refusing to remove it")
                    install.unlink()

    def test_udev_rule_syntax(self):
        result = subprocess.run(["udevadm", "verify", "--resolve-names=never",
                                 str(ROOT / "packaging/udev/72-yubiquity.rules")],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
