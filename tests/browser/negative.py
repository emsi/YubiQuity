#!/usr/bin/env python3
"""Stock-browser error/recovery tests on real UHID and a disposable locked service.

All approvals are explicit control-client calls. No browser internals, extensions,
virtual authenticators or security overrides. PIN typing uses only our own Xvfb.
"""
import argparse
import json
from pathlib import Path
import tempfile
import time

from ceremonies import ROOT, Fixture, IsolatedDisplay, WebDriver, open_device, Ctap2, ClientPin
from control_integration import service, ctl
from transport_integration import wait_removed
from vault_integration import cli

DENIED_SHEET = ("something went wrong", "your identity couldn't be verified")


class Presence:
    def __init__(self, socket, action="approve"):
        self.socket = socket
        self.action = action
        self.tokens = []
        self.seen = set()

    def __call__(self, browser):
        pending = ctl(self.socket, "status").get("pending")
        if not pending or pending["token"] in self.seen:
            return
        token = pending["token"]
        self.seen.add(token)
        if pending["operation"] == "select-device":
            ctl(self.socket, "approve", token)
            return
        assert pending["rp_id"] == "localhost", pending
        self.tokens.append(token)
        if self.action == "abort":
            browser.script("window.abortController.abort()")
        elif self.action == "lock":
            assert ctl(self.socket, "lock")["state"] == "locked"
        else:
            ctl(self.socket, self.action, token)
        browser.record({"event": "local-presence", "action": self.action, "operation": pending["operation"]})

    def drained(self):
        end = time.monotonic() + 5
        while ctl(self.socket, "status").get("pending"):
            if time.monotonic() >= end:
                raise TimeoutError("browser operation left a pending approval")
            time.sleep(0.05)
        for token in self.tokens:
            assert not ctl(self.socket, "approve", token, check=False)["ok"], "stale token was accepted"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("firefox", "chrome"), default="firefox")
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / ("negative-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    with tempfile.TemporaryDirectory(prefix="yubiquity-browser-negative-") as temporary:
        vault = Path(temporary) / "vault.yq"
        socket = Path(temporary) / "control.sock"
        cli("init", vault)
        with Fixture() as fixture, Fixture(require_trusted_attestation=True) as strict, \
                IsolatedDisplay(artifacts) as display, service(vault, socket) as running, \
                WebDriver(args.browser, artifacts, True, display) as browser:
            try:
                path = running.unlock()
                browser.navigate(fixture.origin)
                original_vault = vault.read_bytes()
                for action, error in (("abort", "AbortError"), ("deny", "NotAllowedError")):
                    presence = Presence(socket, action)
                    browser.ceremony("register", username="alice", during_wait=presence,
                                     chrome_error=DENIED_SHEET if action == "deny" else None,
                                     expected_error=("browser", error))
                    assert presence.tokens, f"{action} did not reach actual registration approval"
                    presence.drained()
                    assert not fixture.credentials
                    assert vault.read_bytes() == original_vault, f"{action} persisted a credential"

                approve = Presence(socket)
                registration = browser.ceremony("register", username="alice", during_wait=approve)
                assert approve.tokens
                saved_vault = vault.read_bytes()

                for action, error in (("abort", "AbortError"), ("deny", "NotAllowedError")):
                    presence = Presence(socket, action)
                    browser.ceremony("authenticate", username="alice", during_wait=presence,
                                     chrome_error=DENIED_SHEET if action == "deny" else None,
                                     expected_error=("browser", error))
                    assert presence.tokens, f"{action} did not reach actual assertion approval"
                    presence.drained()
                    assert len(fixture.credentials) == 1 and vault.read_bytes() == saved_vault

                excluded = Presence(socket)
                browser.ceremony("register", username="alice", during_wait=excluded,
                                 chrome_error=("try a different device", "you already registered this device"),
                                 expected_error=("browser", "InvalidStateError"))
                excluded.drained()
                assert len(fixture.credentials) == 1 and vault.read_bytes() == saved_vault

                for kind in ("register", "authenticate"):
                    browser.ceremony(kind, username="alice", wrongRp=True,
                                     expected_error=("browser", "SecurityError"))
                    assert not ctl(socket, "status").get("pending")
                unknown = Presence(socket)
                browser.ceremony("authenticate", username="alice", unknownCredential=True,
                                 chrome_error=("try a different security key", "not registered with this website"),
                                 during_wait=unknown, expected_error=("browser", "NotAllowedError"))
                unknown.drained()
                assert vault.read_bytes() == saved_vault
                result = browser.ceremony("authenticate", username="alice", during_wait=Presence(socket))
                assert result["credentialId"] == registration["credentialId"]

                # A real browser obtains a credential but the RP rejects its
                # none attestation. This is the explicitly unsupported policy,
                # not a claim to implement a manufacturer CA trust store.
                browser.navigate(strict.origin)
                browser.ceremony("register", username="strict", during_wait=Presence(socket),
                                 expected_error=("complete", "Error"),
                                 error_contains="trusted manufacturer attestation required")
                assert strict.last_attestation == {"fmt": "none", "type": "NONE", "certificates": 0}
                assert not strict.credentials
                browser.record({"event": "attestation-policy-rejected", **strict.last_attestation})

                with open_device(path) as device:
                    ClientPin(Ctap2(device)).set_pin("1234")
                browser.navigate(fixture.origin)
                resident = browser.ceremony("register", username="bob", resident=True, uv="required",
                                           enter_pin=True, during_wait=Presence(socket))
                assert resident["flags"] == 0x45

                # Detach while the browser is waiting for actual login approval,
                # not just between ceremonies. The old request must fail; a new
                # attachment/request must not accept its stale approval token.
                detached = Presence(socket, "lock")
                browser.ceremony("authenticate", username="bob", uv="required", enter_pin=True,
                                 during_wait=detached, expected_error=("browser", "NotAllowedError"))
                assert detached.tokens, "lock did not interrupt a pending login approval"
                wait_removed(*running.devices[-1])
                detached.drained()
                path = running.unlock()
                detached.drained()
                result = browser.ceremony("authenticate", username="bob", uv="required",
                                          pin_sequence=("0000", "1234"), during_wait=Presence(socket))
                assert result["credentialId"] == resident["credentialId"] and result["flags"] == 5
                assert len(browser.last_pin_prompts) == 2
                assert any(word in browser.last_pin_prompts[1].lower() for word in ("incorrect", "wrong", "invalid"))
                with open_device(path) as device:
                    assert ClientPin(Ctap2(device)).get_pin_retries()[0] == 8
                result = browser.ceremony("authenticate", username="bob", uv="required", discoverable=True,
                                          enter_pin=True, during_wait=Presence(socket))
                assert result["credentialId"] == resident["credentialId"] and result["user"] == "bob"
                assert result["flags"] == 5
                assert ctl(socket, "lock")["state"] == "locked"
                wait_removed(*running.devices[-1])
                browser.record({"event": "negative-suite-passed"})
            except BaseException:
                display.screenshot("negative-failure")
                raise
    print(json.dumps({"ok": True, "artifacts": str(artifacts)}), flush=True)


if __name__ == "__main__":
    main()
