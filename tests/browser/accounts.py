#!/usr/bin/env python3
"""Native two-account selection with real UHID and independently verified identities.

Uses native keyboard/mouse UI (Chrome screen recognition on the isolated display),
never privileged authenticator APIs.
"""
import argparse
import time
from ceremonies import ROOT, Fixture, IsolatedDisplay, WebDriver, daemon, open_device, Ctap2, ClientPin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("firefox", "chrome"), default="firefox")
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / ("accounts-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    with Fixture() as fixture, IsolatedDisplay(artifacts) as display, daemon("dev-run", "approve") as (_, path, _):
        with open_device(path) as device:
            ClientPin(Ctap2(device)).set_pin("1234")
        with WebDriver(args.browser, artifacts, True, display) as browser:
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
                    result = browser.ceremony("authenticate", enter_pin=True, username=user,
                                             account_choice=index if args.browser == "firefox" else None,
                                             uv="required", discoverable=True)
                    assert result["user"] == user and result["credentialId"] == registered[user]["credentialId"]
                    assert result["flags"] == 5
            except BaseException:
                display.screenshot("accounts-failure")
                raise


if __name__ == "__main__":
    main()
