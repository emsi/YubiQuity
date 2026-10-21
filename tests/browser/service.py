#!/usr/bin/env python3
"""Stock browsers through the normal locked service and explicit control approvals.

The harness explicitly approves disposable requests through the real local CLI;
the persistent daemon has no automatic-presence backend. No systemd is needed.
"""
import argparse
from pathlib import Path
import tempfile
import threading
import time
from ceremonies import ROOT, Fixture, IsolatedDisplay, WebDriver, open_device, Ctap2, ClientPin
from control_integration import service, ctl
from transport_integration import wait_removed
from vault_integration import cli


class ControlApprovals:
    def __init__(self, socket):
        self.socket = socket
        self.stop = threading.Event()
        self.count = 0
        self.error = None

    def __enter__(self):
        def approve():
            previous = None
            try:
                while not self.stop.is_set():
                    pending = ctl(self.socket, "status").get("pending")
                    if pending and pending["token"] != previous:
                        ctl(self.socket, "approve", pending["token"])
                        previous = pending["token"]
                        self.count += 1
                    self.stop.wait(0.1)
            except BaseException as error:
                self.error = error
        self.thread = threading.Thread(target=approve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, error_type, *_args):
        self.stop.set()
        self.thread.join(timeout=15)
        if self.thread.is_alive():
            raise TimeoutError("control approval client did not exit")
        if error_type is None:
            if self.error is not None:
                raise self.error
            assert self.count > 0, "browser flow did not request explicit control approval"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("firefox", "chrome"), default="firefox")
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / ("service-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    with tempfile.TemporaryDirectory(prefix="yubiquity-browser-service-") as temporary:
        vault = Path(temporary) / "vault.yq"
        socket = Path(temporary) / "control.sock"
        cli("init", vault)
        with Fixture() as fixture, IsolatedDisplay(artifacts) as display, service(vault, socket) as running:
            with open_device(running.unlock()) as device:
                ClientPin(Ctap2(device)).set_pin("1234")
            with ControlApprovals(socket), WebDriver(args.browser, artifacts, True, display) as browser:
                browser.navigate(fixture.origin)
                registration = browser.ceremony("register", enter_pin=True, username="alice", uv="required", resident=True)
            assert ctl(socket, "lock")["state"] == "locked"
            wait_removed(*running.devices[-1])
            running.unlock()
            # A fresh browser and new authenticator attachment must reuse the
            # saved credential/PIN, without re-enrollment or a browser mode.
            with ControlApprovals(socket), WebDriver(args.browser, artifacts, True, display) as browser:
                browser.navigate(fixture.origin)
                for discoverable in (False, True):
                    result = browser.ceremony("authenticate", enter_pin=True, username="alice", uv="required", discoverable=discoverable)
                    assert result["credentialId"] == registration["credentialId"]
                    assert result["user"] == "alice" and result["flags"] == 5
            assert ctl(socket, "lock")["state"] == "locked"
            wait_removed(*running.devices[-1])


if __name__ == "__main__":
    main()
