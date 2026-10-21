#!/usr/bin/env python3
"""Trusted development helper, not a setuid program or a general device broker.

Run only via the daemon's explicit --node-helper option. The daemon keeps stdin
open while it owns the virtual device. EOF (including daemon death) cleans up.
Never expose another device, change a pre-existing node, or log protocol data.
"""
import argparse
import os
from pathlib import Path
import re
import signal
import stat
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unique", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root for mknod; run the daemon itself unprivileged")
    if not re.fullmatch(r"yubiquity-[0-9a-f]{32}", args.unique):
        parser.error("invalid instance identity")
    if args.uid <= 0 or args.gid < 0 or str(args.uid) != os.environ.get("SUDO_UID"):
        parser.error("node owner must be the unprivileged user invoking sudo")

    matches = []
    for candidate in Path("/sys/class/hidraw").glob("hidraw*"):
        if not re.fullmatch(r"hidraw[0-9]+", candidate.name):
            continue
        try:
            properties = (candidate / "device/uevent").read_text().splitlines()
            if ("HID_UNIQ=" + args.unique in properties
                    and "HID_NAME=YubiQuity Software FIDO2" in properties):
                matches.append(candidate)
        except FileNotFoundError:
            continue
    if len(matches) != 1:
        parser.error("expected exactly one matching YubiQuity kernel device")
    sysfs = matches[0]
    numbers = (sysfs / "dev").read_text().strip()
    if not re.fullmatch(r"[0-9]+:[0-9]+", numbers):
        parser.error("invalid sysfs device numbers")
    major, minor = map(int, numbers.split(":"))
    expected_device = os.makedev(major, minor)
    node = Path("/dev") / sysfs.name
    created = None

    def terminate(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        if not os.path.lexists(node):
            os.mknod(node, stat.S_IFCHR | 0o600, expected_device)
            created = node.lstat()
            os.chown(node, args.uid, args.gid, follow_symlinks=False)
        info = node.lstat()
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != expected_device:
            raise RuntimeError("existing node does not match the requested HID device")
        print(node, flush=True)
        # Parent never writes data. Closing its only pipe writer signals cleanup.
        if sys.stdin.buffer.read(1):
            raise RuntimeError("unexpected input on lifecycle pipe")
    finally:
        if created is not None:
            try:
                current = node.lstat()
                if (current.st_ino, current.st_rdev) == (created.st_ino, created.st_rdev):
                    node.unlink()
                else:
                    print("Refusing to unlink a replaced device node", file=sys.stderr)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
