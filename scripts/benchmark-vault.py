#!/usr/bin/env python3
"""Measure normal production KDF parameters using a disposable release vault."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/release/yubiquity"


def run(command, vault):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"disposable benchmark passphrase")
    finally:
        os.close(write_fd)
    try:
        started = time.perf_counter()
        subprocess.run([str(BINARY), command, "--vault", str(vault), "--passphrase-fd", str(read_fd)],
                       pass_fds=(read_fd,), capture_output=True, check=True, timeout=30)
        return round((time.perf_counter() - started) * 1000, 2)
    finally:
        os.close(read_fd)


with tempfile.TemporaryDirectory(prefix="yubiquity-vault-benchmark-") as directory:
    path = Path(directory) / "vault.yq"
    create_ms = run("init", path)
    samples = [run("list", path) for _ in range(5)]
    print(json.dumps({"binary": str(BINARY), "argon2id": {"memory_kib": 65536, "passes": 3, "lanes": 1},
                      "create_ms": create_ms, "unlock_cli_ms": samples, "median_unlock_cli_ms": statistics.median(samples)}, indent=2))
