#!/usr/bin/env python3
"""Opt-in public-site smoke tests using stock browsers and disposable real UHID.

This creates registrations on the named public services. Never part of CI and
never implicit: obtain the user's approval before passing the opt-in flag.
No site JavaScript, WebAuthn API or browser security setting is replaced.
"""
import argparse
import json
from pathlib import Path
import secrets
import tempfile
import time
from urllib.parse import urlencode

from ceremonies import ROOT, ELEMENT, IsolatedDisplay, WebDriver, WebDriverFailure, open_device, Ctap2, ClientPin
from control_integration import service, ctl
from transport_integration import wait_removed
from vault_integration import cli


def element(browser, selector):
    return browser.command("POST", "/element", {"using": "css selector", "value": selector})[ELEMENT]


def click(browser, selector):
    browser.command("POST", f"/element/{element(browser, selector)}/click", {})


def text_input(browser, selector, value):
    target = element(browser, selector)
    browser.command("POST", f"/element/{target}/clear", {})
    if value:
        browser.command("POST", f"/element/{target}/value", {"text": value})


def state(browser):
    # Observation only: use the site's own WebAuthn calls and success rendering.
    return browser.script("""return {origin:location.origin,path:location.pathname,
        body:document.body?.innerText ?? '',
        alerts:[...document.querySelectorAll('.alert-danger')].map(e=>e.innerText)}""")


def wait_ceremony(browser, socket, rp_id, operation, success, *, username=None, pin_required=False):
    end = time.monotonic() + 50
    seen = set()
    approvals = 0
    pins = 0
    pin_sent_at = None
    checked_at = clicked_at = 0
    account_attempts = 0
    pin_submit_attempts = 0
    pin_submitted_at = 0
    snapshot = None
    while time.monotonic() < end:
        pending = ctl(socket, "status").get("pending")
        if pending and pending["token"] not in seen:
            if pending["operation"] != "select-device":
                assert pending["rp_id"] == rp_id, pending
                assert pending["operation"] == operation, pending
                approvals += 1
            ctl(socket, "approve", pending["token"])
            seen.add(pending["token"])
            browser.record({"event": "public-presence-approved", "rp_id": pending["rp_id"],
                            "operation": pending["operation"]})
        try:
            snapshot = state(browser)
        except WebDriverFailure as error:
            if error.code != "unexpected alert open" or browser.family != "firefox":
                raise
            if pin_sent_at is not None and time.monotonic() - pin_sent_at < 1:
                time.sleep(0.1)
                continue
            message = browser.command("GET", "/alert/text")
            if "PIN" not in message or pins:
                raise AssertionError(f"unexpected public-test browser prompt: {message}")
            browser.display.screenshot(f"public-{rp_id}-pin-{time.time_ns()}")
            browser.display.type_test_pin()
            pins += 1
            pin_sent_at = time.monotonic()
            browser.record({"event": "public-native-pin", "rp_id": rp_id, "operation": operation})
            continue
        if snapshot is None:
            # Firefox may interrupt an in-flight read when its native PIN
            # prompt opens; the next command identifies the actual alert.
            time.sleep(0.1)
            continue
        assert snapshot["origin"] == "https://" + rp_id, snapshot
        if snapshot["alerts"]:
            raise AssertionError(snapshot["alerts"])
        if success(snapshot):
            assert approvals, "public ceremony succeeded without this authenticator's actual approval"
            assert not pin_required or pins == 1, "required native PIN interaction was not exercised"
            browser.record({"event": "public-site-success", "rp_id": rp_id, "operation": operation,
                            "username": username, "pin_prompts": pins, "page": snapshot})
            browser.display.screenshot(f"public-{rp_id}-{operation}-{time.time_ns()}")
            print(json.dumps({"browser": browser.family, "rp_id": rp_id, "operation": operation,
                              "username": username, "path": snapshot["path"], "ok": True}), flush=True)
            return snapshot
        if browser.family == "chrome" and time.monotonic() - checked_at > 0.5:
            checked_at = time.monotonic()
            if not pins:
                message = browser.display.chrome_pin_prompt(browser.version)
                if message is not None:
                    browser.display.type_test_pin()
                    pins += 1
                    pin_sent_at = time.monotonic()
                    browser.record({"event": "public-native-pin", "rp_id": rp_id, "operation": operation})
            elif (not approvals and time.monotonic() - pin_sent_at > 1.5
                  and time.monotonic() - pin_submitted_at > 1 and pin_submit_attempts < 3):
                message = browser.display.chrome_submit_typed_pin(browser.version)
                if message is not None:
                    pin_submitted_at = time.monotonic()
                    pin_submit_attempts += 1
                    browser.record({"event": "public-native-pin-submit", "rp_id": rp_id,
                                    "attempt": pin_submit_attempts})
            elif (operation == "authenticate" and username and time.monotonic() - pin_sent_at > 1.5
                  and time.monotonic() - clicked_at > 1 and account_attempts < 3):
                message = browser.display.chrome_confirm_account(browser.version, username, rp_id)
                if message is not None:
                    clicked_at = time.monotonic()
                    account_attempts += 1
                    browser.record({"event": "public-native-account", "rp_id": rp_id, "message": message})
        time.sleep(0.1)
    browser.record({"event": "public-site-timeout", "rp_id": rp_id, "operation": operation, "page": snapshot})
    raise TimeoutError(f"{browser.family} {rp_id} {operation} did not reach its success page")


def webauthn_io(browser, socket, username):
    options = urlencode({"regUserVerification": "required", "authUserVerification": "required",
                         "attachment": "cross_platform", "discoverableCredential": "required",
                         "attestation": "none", "regPubKeyAlgs": "es256",
                         "regHints": "security-key", "authHints": "security-key"})
    browser.navigate("https://webauthn.io/?" + options)
    text_input(browser, "#input-email", username)
    click(browser, "#register-button")
    wait_ceremony(browser, socket, "webauthn.io", "register",
                  lambda page: "Success! Now try to authenticate..." in page["body"],
                  username=username, pin_required=True)
    click(browser, "#login-button")
    wait_ceremony(browser, socket, "webauthn.io", "authenticate",
                  lambda page: page["path"] == "/profile" and username in page["body"],
                  username=username, pin_required=True)
    browser.navigate("https://webauthn.io/?" + options)
    text_input(browser, "#input-email", "")
    assert browser.script("return document.querySelector('#input-email').value") == ""
    browser.record({"event": "public-discoverable-request", "rp_id": "webauthn.io", "username_input": ""})
    click(browser, "#login-button")
    wait_ceremony(browser, socket, "webauthn.io", "authenticate",
                  lambda page: page["path"] == "/profile" and username in page["body"],
                  username=username, pin_required=True)


def yubico(browser, socket):
    browser.navigate("https://demo.yubico.com/webauthn-technical")
    click(browser, "button[type=submit]")
    wait_ceremony(browser, socket, "demo.yubico.com", "register",
                  lambda page: "Registration completed!" in page["body"]
                  and "You have successfully completed the WebAuthn registration." in page["body"])
    click(browser, 'a[href="/webauthn-technical/login"]')
    click(browser, "button[type=submit]")
    wait_ceremony(browser, socket, "demo.yubico.com", "authenticate",
                  lambda page: page["path"] == "/webauthn-technical/login"
                  and "Authentication successful!" in page["body"]
                  and "You have completed the WebAuthn authentication." in page["body"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-public-registration", action="store_true",
                        help="explicitly authorize disposable registration writes to the selected public sites")
    parser.add_argument("--browser", choices=("firefox", "chrome", "both"), default="both")
    parser.add_argument("--site", choices=("webauthn.io", "yubico", "both"), default="both")
    args = parser.parse_args()
    if not args.allow_public_registration:
        parser.error("public writes require prior user approval and --allow-public-registration")
    artifacts = ROOT / "target/browser-results" / ("public-" + str(time.time_ns()))
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    families = ("firefox", "chrome") if args.browser == "both" else (args.browser,)
    sites = ("webauthn.io", "yubico") if args.site == "both" else (args.site,)
    for family in families:
        for site in sites:
            username = "yq" + secrets.token_hex(5)
            with tempfile.TemporaryDirectory(prefix="yubiquity-public-test-") as temporary:
                vault = Path(temporary) / "vault.yq"
                socket = Path(temporary) / "control.sock"
                cli("init", vault)
                with IsolatedDisplay(artifacts) as display, service(vault, socket) as running, \
                        WebDriver(family, artifacts, True, display) as browser:
                    path = running.unlock()
                    if site == "webauthn.io":
                        with open_device(path) as device:
                            ClientPin(Ctap2(device)).set_pin("1234")
                    browser.command("POST", "/timeouts", {"implicit": 10000})
                    if site == "webauthn.io":
                        webauthn_io(browser, socket, username)
                    else:
                        yubico(browser, socket)
                    assert ctl(socket, "lock")["state"] == "locked"
                    wait_removed(*running.devices[-1])
    print(json.dumps({"ok": True, "artifacts": str(artifacts)}), flush=True)


if __name__ == "__main__":
    main()
