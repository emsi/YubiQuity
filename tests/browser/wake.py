#!/usr/bin/env python3
"""Real browser/UHID acceptance of desktop-mode unlock-on-request.

Disposable vault, explicit test-client unlocking and approvals; no production
automatic-presence mode and no browser virtual-authenticator API.
"""
import argparse
from pathlib import Path
import tempfile
import threading
import time

from ceremonies import ROOT, Fixture, IsolatedDisplay, WebDriver, open_device, Ctap2, ClientPin
from control_integration import service, ctl
from vault_integration import cli


class UnlockAndApprove:
    def __init__(self, socket):
        self.socket = socket
        self.stop = threading.Event()
        self.unlocks = 0
        self.approvals = 0
        self.error = None

    def __enter__(self):
        def work():
            try:
                seen = set()
                while not self.stop.is_set():
                    state = ctl(self.socket, "status")
                    unlock = state.get("unlock_request")
                    if unlock and unlock["token"] not in seen:
                        seen.add(unlock["token"])
                        result = ctl(self.socket, "unlock", "--request-token", unlock["token"])
                        assert result["state"] == "ready"
                        self.unlocks += 1
                    pending = state.get("pending")
                    if pending and pending["token"] not in seen:
                        seen.add(pending["token"])
                        ctl(self.socket, "approve", pending["token"])
                        self.approvals += 1
                    self.stop.wait(.02)
            except BaseException as error:
                self.error = error
        self.thread = threading.Thread(target=work)
        self.thread.start()
        return self

    def __exit__(self, kind, *_args):
        self.stop.set()
        self.thread.join(timeout=25)
        assert not self.thread.is_alive(), "control worker did not stop"
        if kind is None:
            if self.error:
                raise self.error
            assert self.unlocks == 1, "browser must request exactly one unlock"
            assert self.approvals > 0, "unlock must still require explicit approval"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("firefox", "chrome"), required=True)
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / ("wake-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    with tempfile.TemporaryDirectory(prefix="yubiquity-wake-") as temporary:
        vault, socket = Path(temporary) / "vault.yq", Path(temporary) / "control.sock"
        cli("init", vault)
        with Fixture() as rp, IsolatedDisplay(artifacts) as display, service(
                vault, socket, unlock_on_request=True) as running:
            # First unlock is deliberately manual; no startup metadata cache.
            path = running.unlock()
            with open_device(path) as device:
                ClientPin(Ctap2(device)).set_pin("1234")
            registration = None
            for operation, discoverable in (("register", True), ("authenticate", False), ("authenticate", True)):
                assert ctl(socket, "lock")["wake_available"]
                with open_device(path) as device:
                    assert Ctap2(device).get_info().options["clientPin"]
                assert "unlock_request" not in ctl(socket, "status"), "discovery must stay silent"
                with UnlockAndApprove(socket), WebDriver(args.browser, artifacts, True, display) as browser:
                    browser.navigate(rp.origin)
                    if operation == "register":
                        registration = browser.ceremony("register", enter_pin=True, username="alice", uv="required", resident=True)
                    else:
                        result = browser.ceremony("authenticate", enter_pin=True, username="alice", uv="required", discoverable=discoverable)
                        assert result["credentialId"] == registration["credentialId"]
                        assert result["flags"] == 5
            assert ctl(socket, "session", "--active", "false")["state"] == "locked"
            assert not ctl(socket, "status")["wake_available"]
            assert ctl(socket, "session", "--active", "true")["wake_available"]
            assert ctl(socket, "status")["state"] == "locked"


if __name__ == "__main__":
    main()
