#!/usr/bin/env python3
"""Run bounded, seeded libFuzzer campaigns without UHID, browsers, or real secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = "nightly-2026-10-19"


def seeds(target):
    if target == "control":
        return [json.dumps(value).encode() for value in [
            {"command": "status"}, {"command": "lock"},
            {"command": "unlock", "passphrase": list(b"public disposable fuzz phrase")},
            {"command": "approve", "token": "1-123456"},
            {"command": "deny", "token": "1-123456"},
            {"command": "status", "extra": True},
        ]]
    # Canonical CTAP fixtures, deliberately public test inputs. Keep these in
    # source; the writable fuzzer corpus is generated under ignored target/.
    make = bytes.fromhex(
        "a5015820" + "00" * 32 +
        "02a16269646c6578616d706c652e74657374"
        "03a2626964456361726f6c646e616d65656361726f6c"
        "0481a263616c672664747970656a7075626c69632d6b6579"
        "07a162726bf5"
    )
    assertion = bytes.fromhex("a2016c6578616d706c652e74657374025820" + "00" * 32)
    pin = bytes.fromhex("a201010202")
    if target == "ctap":
        return [b"\x01" + make, b"\x02" + assertion, b"\x06" + pin,
                b"\x04", b"\x07", b"\x08", bytes.fromhex("06a201010201")]
    if target == "cbor":
        return [make, assertion, pin, b"\xa0", bytes.fromhex("a201010202"),
                bytes.fromhex("a201fb7ff800000000000002f5"),
                bytes.fromhex("a201010102"), b"\x81" * 14 + b"\xf6",
                b"\x5b" + b"\xff" * 8, b"\xff" * 7609]

    def step(report, *, action=1, elapsed=1):
        return bytes([action]) + struct.pack("<H", elapsed) + report.ljust(64, b"\0")

    request = struct.pack(">IBH", 1, 0x90, 1) + b"\x04"
    partial = struct.pack(">IBH", 1, 0x81, 7609) + b"x" * 57
    continuation = struct.pack(">IB", 1, 0) + b"y" * 59
    return [step(request), step(request) + step(bytes(64), action=4),
            step(request) + step(bytes(64), action=5),
            step(request) + step(bytes(64), action=6),
            step(request) + step(request, action=129),
            step(partial) + step(continuation),
            step(partial) + step(bytes(64), elapsed=750),
            step(request) + step(bytes(64), elapsed=30000)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["all", "cbor", "hid", "ctap", "control"], default="all")
    parser.add_argument("--seconds", type=int, default=60, help="time per target (default: 60)")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 86400:
        parser.error("--seconds must be between 1 and 86400")
    targets = ["cbor", "hid", "ctap", "control"] if args.target == "all" else [args.target]
    artifacts = ROOT / "target/fuzz-results" / str(time.time_ns())
    artifacts.mkdir(parents=True)
    print(f"Fuzz artifacts: {artifacts}", flush=True)
    # cargo-fuzz does not expose --locked. Pre-fetch with --locked, then compare
    # the lockfile before/after each run so silent re-resolution fails the check.
    subprocess.run(["cargo", "fetch", "--locked", "--manifest-path", "fuzz/Cargo.toml"], cwd=ROOT, check=True)
    lock = (ROOT / "fuzz/Cargo.lock").read_bytes()
    report = {"toolchain": TOOLCHAIN, "seconds_per_target": args.seconds, "targets": []}
    for target in targets:
        corpus = ROOT / "target/fuzz-corpus" / target
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in seeds(target):
            path = corpus / hashlib.sha256(seed).hexdigest()
            if not path.exists():
                with path.open("xb") as output:
                    output.write(seed)
        maximum = 16384 if target == "hid" else 8193 if target == "control" else 7610
        command = ["cargo", f"+{TOOLCHAIN}", "fuzz", "run", target, str(corpus), "--",
                   f"-max_total_time={args.seconds}", f"-max_len={maximum}",
                   "-timeout=5", "-rss_limit_mb=1024", "-seed=1",
                   f"-artifact_prefix={artifacts}/{target}-"]
        print(f"Fuzzing {target}: {args.seconds}s, ASan, max input {maximum} bytes", flush=True)
        with (artifacts / f"{target}.log").open("w") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        report["targets"].append({"target": target, "command": command, "exit_code": result.returncode})
        (artifacts / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        if (ROOT / "fuzz/Cargo.lock").read_bytes() != lock:
            raise RuntimeError("fuzz dependency lock changed during the campaign")
        if result.returncode:
            raise RuntimeError(f"{target} failed: see {artifacts / (target + '.log')}")
    print("All requested fuzz targets finished without a detected failure.", flush=True)


if __name__ == "__main__":
    main()
