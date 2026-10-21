#!/usr/bin/env python3
"""Firefox native two-account selection with real UHID and independently verified identities.

The Chromium UI path remains a separate unverified release gate. This automation
uses Firefox's native popup keyboard/mouse UI, never privileged authenticator APIs.
"""
import time
from ceremonies import ROOT, Fixture, IsolatedDisplay, WebDriver, daemon, open_device, Ctap2, ClientPin


def main():
    artifacts = ROOT / "target/browser-results" / ("accounts-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    with Fixture() as fixture, IsolatedDisplay(artifacts) as display, daemon("dev-run", "approve") as (_, path, _):
        with open_device(path) as device:
            ClientPin(Ctap2(device)).set_pin("1234")
        with WebDriver("firefox", artifacts, True, display) as browser:
            browser.navigate(fixture.origin)
            registered = {}
            try:
                for user in ("alice", "bob"):
                    registered[user] = browser.ceremony("register", enter_pin=True, username=user, uv="required", resident=True)
                assert registered["alice"]["credentialId"] != registered["bob"]["credentialId"]
                for user in ("alice", "bob"):
                    result = browser.ceremony("authenticate", enter_pin=True, username=user, uv="required", discoverable=False)
                    assert result["user"] == user and result["credentialId"] == registered[user]["credentialId"]
                # The authenticator enumerates newest-first: bob, then alice.
                # With no allow list, the browser chooses from both results.
                for index, user in enumerate(("bob", "alice")):
                    result = browser.ceremony("authenticate", enter_pin=True, account_choice=index, uv="required", discoverable=True)
                    assert result["user"] == user and result["credentialId"] == registered[user]["credentialId"]
                    assert result["flags"] == 5
            except BaseException:
                display.screenshot("accounts-failure")
                raise


if __name__ == "__main__":
    main()
