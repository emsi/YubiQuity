#!/usr/bin/env python3
"""Offline CLI regressions: no UHID creation, secrets, host setup or browser."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/yubiquity"


class StartupTests(unittest.TestCase):
    def command(self, *args):
        return subprocess.run([str(BINARY), *map(str, args)], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=5)

    def test_missing_vault_fails_before_secret_input_and_creates_nothing(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-startup-") as root:
            root = Path(root)
            missing = root / "missing"
            for command in ("run", "list", "init"):
                result = self.command(command, "--vault", missing / "nested/credentials.yq")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(missing), result.stderr)
                self.assertNotIn("Vault passphrase", result.stderr)
                self.assertNotIn("read vault passphrase", result.stderr)
                self.assertFalse(missing.exists())

    def test_unsafe_leaf_reports_exact_path_and_mode_before_secret_input(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-startup-") as root:
            leaf = Path(root) / "private"
            leaf.mkdir(mode=0o755)
            result = self.command("init", "--vault", leaf / "credentials.yq")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(str(leaf), result.stderr)
            self.assertIn("0755", result.stderr)
            self.assertNotIn("Vault passphrase", result.stderr)
            self.assertEqual(list(leaf.iterdir()), [])

    def test_existing_vault_is_never_overwritten_or_prompted_for_initialization(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-startup-") as root:
            path = Path(root) / "credentials.yq"
            path.write_bytes(b"existing data, including a damaged vault, must survive")
            original = path.read_bytes()
            result = self.command("init", "--vault", path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
            self.assertNotIn("Vault passphrase", result.stderr)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(list(Path(root).iterdir())), 1)
            attached = self.command("init", "--run", "--vault", path)
            self.assertNotEqual(attached.returncode, 0)
            self.assertIn("already exists", attached.stderr)
            self.assertNotIn("Vault passphrase", attached.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_missing_service_is_checked_before_unlock_secret(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-startup-") as root:
            result = self.command("control", "--socket", Path(root) / "absent.sock", "unlock")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Vault passphrase", result.stderr)
            self.assertNotIn("read vault passphrase", result.stderr)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_doctor_is_read_only_and_reports_executable_and_process(self):
        with tempfile.TemporaryDirectory(prefix="yubiquity-startup-") as root:
            result = self.command("doctor", "--vault", Path(root) / "absent/credentials.yq")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Executable:", result.stdout)
            self.assertIn("Groups:", result.stdout)
            self.assertIn("native (no helper)", result.stdout)
            self.assertIn("dynamic hidraw permissions are not checked", result.stdout)
            self.assertNotIn("Vault passphrase", result.stderr)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_doctor_requires_explicit_probe_for_helper(self):
        result = self.command("doctor", "--node-helper", "/not/invoked")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--probe", result.stderr)

    def test_native_harness_cannot_silently_select_the_helper(self):
        from transport_integration import node_arguments
        self.assertEqual(node_arguments("native"), [])
        self.assertEqual(node_arguments("container")[0], "--node-helper")
        with self.assertRaises(ValueError):
            node_arguments("typo")


if __name__ == "__main__":
    unittest.main(verbosity=2)
