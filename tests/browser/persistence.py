#!/usr/bin/env python3
"""Real browser ceremonies across a persistent daemon crash and fresh profiles.

The harness explicitly supplies terminal approvals to the normal persistent CLI.
The daemon has no automatic-presence flag in this mode. All state is disposable.
"""
import argparse
import json
from pathlib import Path
import select
import tempfile
import threading
import time

from ceremonies import ROOT, IsolatedDisplay, WebDriver
from rp import Fixture
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from transport_integration import daemon, open_device, wait_removed
from vault_integration import PASSWORD, cli


class TerminalApprovals:
    def __init__(self, process):
        self.process = process
        self.stop = threading.Event()
        self.error = None
        self.count = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.process.stdout], [], [], 0.1)[0]:
                    continue
                line = self.process.stdout.readline()
                if not line:
                    return
                if not line.startswith("APPROVAL "):
                    raise AssertionError("unexpected persistent daemon output")
                token = line.split()[1]
                self.process.stdin.write(f"approve {token}\n")
                self.process.stdin.flush()
                self.count += 1
        except BaseException as error:
            self.error = error

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, error_type, *_args):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise TimeoutError("approval reader did not stop")
        if error_type is None and self.error:
            raise self.error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=["firefox", "chrome", "both"], default="firefox")
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / f"persistent-{time.time_ns()}"
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    families = ["firefox", "chrome"] if args.browser == "both" else [args.browser] * 2
    with tempfile.TemporaryDirectory(prefix="yubiquity-browser-vault-") as temporary, Fixture() as fixture, IsolatedDisplay(artifacts) as display:
        vault = Path(temporary) / "vault.yq"
        cli("init", vault)
        with daemon("run", vault=vault, passphrase=PASSWORD) as (process, path, unique), TerminalApprovals(process) as approval:
            with open_device(path) as device:
                ClientPin(Ctap2(device)).set_pin("1234")
            with WebDriver(families[0], artifacts, True, display) as browser:
                browser.navigate(fixture.origin)
                registered = browser.ceremony("register", enter_pin=True, username="alice", resident=True, uv="required")
                assert registered["flags"] & 4
            assert approval.count > 0
            process.kill()
            process.wait(timeout=5)
            wait_removed(path, unique)
        with (artifacts / "ceremonies.jsonl").open("a") as log:
            log.write(json.dumps({"event": "persistent-daemon-killed", "device_removed": True}) + "\n")
        # New process, device and browser profile. Only the encrypted vault and
        # independently verified RP registration survive the first ceremony.
        with daemon("run", vault=vault, passphrase=PASSWORD) as (process, path, _), TerminalApprovals(process) as approval:
            with WebDriver(families[1], artifacts, True, display) as browser:
                browser.navigate(fixture.origin)
                for discoverable in [False, True]:
                    assertion = browser.ceremony("authenticate", enter_pin=True, username="alice", discoverable=discoverable, uv="required")
                    assert assertion["credentialId"] == registered["credentialId"]
                    assert assertion["user"] == "alice" and assertion["flags"] & 4
            assert approval.count >= 2
        metadata = json.loads(cli("list", vault).stdout)
        assert metadata["pin_configured"] and len(metadata["credentials"]) == 1
        print("PASS: persistent resident credential and PIN survived SIGKILL and fresh browser profiles", flush=True)


if __name__ == "__main__":
    main()
