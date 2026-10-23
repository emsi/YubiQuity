#!/usr/bin/env python3
"""Validate a release .deb without installing it or changing host device rules.

Maintainer/setup scripts execute in a disposable chroot with fake system tools.
Requires passwordless sudo for chroot; no host /dev, /sys or /run is mounted.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest

PACKAGE = Path(sys.argv.pop(1)).resolve()


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, **kwargs)
    if result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


class ReleasePackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="yq-release-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name) / "package"
        run("dpkg-deb", "--raw-extract", str(PACKAGE), str(cls.root))

    def test_contents_versions_ownership_and_checksums(self):
        self.assertEqual(run("dpkg-deb", "-f", str(PACKAGE), "Package").stdout.strip(), "yubiquity")
        self.assertEqual(run("dpkg-deb", "-f", str(PACKAGE), "Architecture").stdout.strip(), "amd64")
        archive = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(PACKAGE)])
        with tarfile.open(fileobj=io.BytesIO(archive)) as files:
            for entry in files:
                self.assertEqual((entry.uid, entry.gid), (0, 0), entry.name)
                self.assertFalse(entry.mode & 0o022, entry.name)
                self.assertFalse(entry.mode & 0o6000, entry.name)
                self.assertNotIn("/home/", entry.name)
                self.assertFalse(entry.name.endswith(".yq"))
        for record in (self.root / "DEBIAN/md5sums").read_text().splitlines():
            expected, name = record.split("  ", 1)
            self.assertEqual(hashlib.md5((self.root / name).read_bytes(), usedforsecurity=False).hexdigest(), expected)
        doc = self.root / "usr/share/doc/yubiquity"
        manifest = json.loads((doc / "build.json").read_text())
        for name, expected in manifest["sha256"].items():
            executable = self.root / "usr/bin" / name
            self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), expected)
            result = run(str(executable), "--version", env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
            self.assertIn(manifest["version"], result.stdout)
        self.assertTrue((doc / "third-party/rust/COPYRIGHT-library.html").is_file())
        self.assertGreater(len((doc / "third-party/INDEX.txt").read_text().splitlines()), 50)
        run("sha256sum", "--check", "SHA256SUMS", cwd=PACKAGE.parent)

    def test_runtime_dependencies_resolve_without_a_toolchain(self):
        dependencies = run("dpkg-deb", "-f", str(PACKAGE), "Depends").stdout
        for package in ("pinentry-qt", "qt6-qpa-plugins", "qt6-wayland", "fido2-tools", "udev", "kmod", "passwd"):
            self.assertIn(package, dependencies)
        self.assertNotRegex(dependencies, r"\b(cargo|rustc|cmake|qt6-base-dev)\b")
        result = run("apt-get", "--simulate", "install", str(PACKAGE))
        self.assertIn("yubiquity", result.stdout)

    def test_desktop_rules_and_script_syntax(self):
        run("desktop-file-validate", str(self.root / "usr/share/applications/org.yubiquity.Desktop.desktop"))
        for rule in (self.root / "usr/lib/udev/rules.d").glob("*.rules"):
            run("udevadm", "verify", "--resolve-names=never", str(rule))
        self.assertIn("uhid", (self.root / "usr/lib/modules-load.d/yubiquity.conf").read_text())
        for path in (self.root / "DEBIAN/postinst", self.root / "DEBIAN/postrm", self.root / "usr/sbin/yubiquity-setup"):
            run("/bin/sh", "-n", str(path))

    def test_setup_and_maintainer_scripts_in_isolated_chroot(self):
        jail = Path(self.directory.name) / "jail"
        (jail / "bin").mkdir(parents=True)
        for directory in ("usr/bin", "usr/sbin", "run/udev"):
            (jail / directory).mkdir(parents=True)
        # Copy the shell and its loader/libraries, never bind-mount host paths.
        shell = Path("/bin/sh")
        shutil.copyfile(shell, jail / "bin/sh")
        (jail / "bin/sh").chmod(0o755)
        for library in re.findall(r"(/[^\s()]+)", run("ldd", str(shell)).stdout):
            destination = jail / library.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(library, destination)
            shutil.copymode(library, destination)
        (jail / "dev").mkdir()
        (jail / "dev/null").touch()  # Regular disposable sink, not a host device.

        def tool(name, body):
            path = jail / "usr/bin" / name
            path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
            path.chmod(0o755)

        tool("id", '''if [ "$#" -eq 1 ]; then echo 0
elif [ "$3" = tester ]; then echo 1000
elif [ "$3" = root ]; then echo 0
else exit 1; fi''')
        tool("getent", '[ -f /group-created ]')
        tool("groupadd", 'echo "groupadd $*" >> /calls; : > /group-created')
        for name in ("usermod", "modprobe", "udevadm"):
            tool(name, f'echo "{name} $*" >> /calls')
        tool("snap", '''if [ "$1" = list ]; then [ -f /firefox-installed ]
else echo "snap $*" >> /calls; fi''')
        for source, name in ((self.root / "DEBIAN/postinst", "postinst"),
                             (self.root / "DEBIAN/postrm", "postrm"),
                             (self.root / "usr/sbin/yubiquity-setup", "setup")):
            shutil.copyfile(source, jail / name)
        (jail / "vault.yq").write_bytes(b"untouched test sentinel")
        (jail / "firefox-installed").touch()
        with socket.socket(socket.AF_UNIX) as udev:
            udev.bind(str(jail / "run/udev/control"))
            for _ in range(2):
                run("sudo", "-n", "chroot", str(jail), "/bin/sh", "/postinst", "configure")
            run("sudo", "-n", "chroot", str(jail), "/bin/sh", "/setup", "tester")
            (jail / "firefox-installed").unlink()
            run("sudo", "-n", "chroot", str(jail), "/bin/sh", "/setup", "tester")
            calls = (jail / "calls").read_text()
            self.assertEqual(calls.count("groupadd --system yubiquity"), 1)
            self.assertEqual(calls.count("usermod -a -G yubiquity -- tester"), 2)
            self.assertEqual(calls.count("snap connect firefox:u2f-devices"), 1)
            self.assertEqual(calls.count("modprobe uhid"), 2)
            self.assertEqual(calls.count("udevadm trigger --action=change /sys/class/misc/uhid"), 2)
            for user in ("root", "nonexistent"):
                failure = subprocess.run(["sudo", "-n", "chroot", str(jail), "/bin/sh", "/setup", user],
                                         capture_output=True, text=True, timeout=10)
                self.assertNotEqual(failure.returncode, 0)
                self.assertEqual((jail / "calls").read_text(), calls)
            run("sudo", "-n", "chroot", str(jail), "/bin/sh", "/postrm", "purge")
        self.assertTrue((jail / "group-created").exists())
        self.assertEqual((jail / "vault.yq").read_bytes(), b"untouched test sentinel")


if __name__ == "__main__":
    unittest.main(verbosity=2)
