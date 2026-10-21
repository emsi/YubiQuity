#!/usr/bin/env python3
"""Stock-browser WebAuthn against the real external UHID device.

No virtual authenticator API, extension, WebAuthn preference, or sandbox override.
Each WebDriver session creates a disposable browser profile. Driver logs and a
failure screenshot are retained under target/browser-results/.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transport_integration import ROOT, daemon, open_device
from rp import Fixture
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin

ELEMENT = "element-6066-11e4-a52e-4f735466cecf"
BIN = Path.home() / ".local/bin"


class IsolatedDisplay:
    """Own a fresh X server: automated typing must never target the user's display."""
    def __init__(self, artifacts):
        self.artifacts = artifacts

    def __enter__(self):
        socket_dir = Path("/tmp/.X11-unix")
        if socket_dir.exists() and not os.access(socket_dir, os.W_OK):
            raise RuntimeError("Xvfb needs a writable /tmp/.X11-unix (normally root-owned mode 1777)")
        read_fd, write_fd = os.pipe()
        self.log = (self.artifacts / "xvfb.log").open("w")
        self.process = subprocess.Popen(
            ["Xvfb", "-displayfd", str(write_fd), "-screen", "0", "1280x1024x24", "-nolisten", "tcp"],
            pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=self.log,
        )
        os.close(write_fd)
        try:
            if not select.select([read_fd], [], [], 5)[0]:
                raise TimeoutError("isolated display did not start")
            number = os.read(read_fd, 32).strip().decode()
            if not number.isdecimal():
                raise RuntimeError("invalid isolated display number")
            self.display = ":" + number
            self.env = dict(os.environ, DISPLAY=self.display)
            self.env.pop("XAUTHORITY", None)
            self.env.pop("WAYLAND_DISPLAY", None)
            return self
        except BaseException:
            self.__exit__()
            raise
        finally:
            os.close(read_fd)

    def __exit__(self, *_args):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.log.close()

    def screenshot(self, label):
        from PIL import ImageGrab
        ImageGrab.grab(xdisplay=self.display).save(self.artifacts / f"{label}-pin-dialog.png")

    def type_test_pin(self, pin="1234"):
        if pin not in ("1234", "0000"):
            raise ValueError("only public disposable-test PIN values are accepted")
        subprocess.run(["xdotool", "key", "--clearmodifiers", "ctrl+a"], env=self.env, check=True, timeout=3)
        subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "50", pin], env=self.env, check=True, timeout=3)
        subprocess.run(["xdotool", "key", "--clearmodifiers", "Return"], env=self.env, check=True, timeout=3)

    def select_test_account(self, index, version):
        if index not in (0, 1):
            raise ValueError("the fixture account selector accepts only indexes 0 and 1")
        # Firefox's ordinary account popup assigns numeric access keys. The
        # second account is inside its split-button menu, so open that menu
        # first. Coordinates are for inspected en-US stable/ESR popups on this
        # fixed display, not authenticator protocol branches. Unknown layouts
        # fail explicitly; the RP independently verifies the chosen account.
        if index == 1:
            layouts = {153: ((562, 155), (538, 187)), 158: ((590, 153), (560, 185))}
            positions = layouts.get(int(version.split(".")[0]))
            if positions is None:
                raise ValueError(f"inspect the native account-menu layout for Firefox {version} before automating it")
            subprocess.run(["xdotool", "mousemove", *map(str, positions[0]), "click", "1"], env=self.env, check=True, timeout=3)
            time.sleep(0.2)
            self.screenshot(f"account-menu-{time.time_ns()}")
            subprocess.run(["xdotool", "mousemove", *map(str, positions[1]), "click", "1"], env=self.env, check=True, timeout=3)
        else:
            subprocess.run(["xdotool", "key", "--clearmodifiers", "alt+0"], env=self.env, check=True, timeout=3)


class WebDriverFailure(RuntimeError):
    def __init__(self, details):
        self.details = details
        self.code = details.get("error")
        super().__init__(str(details))


class WebDriver:
    def __init__(self, family, artifacts, headed=False, display=None):
        if family not in ("firefox", "chrome"):
            raise ValueError("unsupported browser family")
        self.family = family
        # Select stock distribution/ESR binaries without replacing project
        # symlinks, changing browser flags, or changing the authenticator mode.
        driver_name = "geckodriver" if family == "firefox" else "chromedriver"
        self.binary = Path(os.environ.get(f"YUBIQUITY_{family.upper()}_BINARY", BIN / f"yubiquity-{family}")).absolute()
        self.driver = Path(os.environ.get(f"YUBIQUITY_{family.upper()}_DRIVER", BIN / f"yubiquity-{driver_name}")).absolute()
        for executable in (self.binary, self.driver):
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ValueError(f"not an executable file: {executable}")
        self.label = f"{family}-{time.time_ns()}"
        self.artifacts = artifacts
        self.headed = headed
        self.display = display
        self.session = None
        self.process = None
        self.log = None

    def record(self, event):
        with (self.artifacts / "ceremonies.jsonl").open("a") as output:
            output.write(json.dumps(dict(event, browser=self.family, session=self.label)) + "\n")

    def request(self, method, path, body=None, timeout=50):
        payload = None if body is None else json.dumps(body).encode()
        request = Request(self.endpoint + path, payload, {"Content-Type": "application/json"}, method=method)
        try:
            with urlopen(request, timeout=timeout) as response:
                result = json.load(response)["value"]
        except HTTPError as error:
            details = json.load(error)["value"]
            raise WebDriverFailure(details) from error
        return result

    def command(self, method, path, body=None):
        return self.request(method, f"/session/{self.session}" + path, body)

    def __enter__(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{port}"
        self.log = (self.artifacts / f"{self.label}-driver.log").open("w")
        if self.family == "firefox":
            args = [str(self.driver), "--host", "127.0.0.1", "--port", str(port)]
            capabilities = {"browserName": "firefox", "moz:firefoxOptions": {
                "binary": str(self.binary), "args": [] if self.headed else ["-headless"],
            }}
        else:
            args = [str(self.driver), f"--port={port}", "--allowed-ips=127.0.0.1"]
            capabilities = {"browserName": "chrome", "goog:chromeOptions": {
                "binary": str(self.binary), "args": [] if self.headed else ["--headless=new"],
            }}
        # Preserve browser dialogs until the test explicitly interacts with them;
        # WebDriver's default is to dismiss them when polling page script state.
        capabilities["unhandledPromptBehavior"] = "ignore"
        try:
            self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, env=None if self.display is None else self.display.env)
            end = time.monotonic() + 10
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError(f"{self.family} driver exited; see {self.log.name}")
                try:
                    self.request("GET", "/status", timeout=1)
                    break
                except (URLError, TimeoutError):
                    if time.monotonic() >= end:
                        raise
                    time.sleep(0.1)
            result = self.request("POST", "/session", {"capabilities": {"alwaysMatch": capabilities}})
            self.session = result["sessionId"]
            self.version = result["capabilities"]["browserVersion"]
            self.record({"event": "started", "version": result["capabilities"].get("browserVersion"),
                         "headed": self.headed, "binary": str(self.binary), "driver": str(self.driver),
                         "binary_resolved": str(self.binary.resolve()), "driver_resolved": str(self.driver.resolve())})
            print(f"{self.family}: {result['capabilities'].get('browserVersion')}", flush=True)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, error_type, *_args):
        if error_type is not None:
            self.record({"event": "failed", "exception": error_type.__name__})
        if self.session:
            if error_type is not None:
                try:
                    screenshot = self.command("GET", "/screenshot")
                    (self.artifacts / f"{self.label}-failure.png").write_bytes(base64.b64decode(screenshot))
                    result = self.script("return {result:window.result,body:document.body.innerText}")
                    (self.artifacts / f"{self.label}-failure.json").write_text(json.dumps(result, indent=2))
                except Exception:
                    pass
            try:
                self.command("DELETE", "")
            except Exception:
                pass
        if self.process is not None:
            # The driver and its disposable browser are in our own process group.
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=5)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()

    def script(self, source, *args):
        return self.command("POST", "/execute/sync", {"script": source, "args": list(args)})

    def navigate(self, origin):
        self.command("POST", "/url", {"url": origin})

    def ceremony(self, kind, *, enter_pin=False, pin_sequence=None, account_choice=None,
                 expected_error=None, error_contains=None, during_wait=None, **settings):
        if account_choice is not None and (self.family != "firefox" or self.display is None):
            raise ValueError("account popup automation currently requires Firefox on an isolated display")
        pins = list(pin_sequence) if pin_sequence is not None else (["1234"] if enter_pin else [])
        self.last_pin_prompts = []
        self.script("window.settings=Object.assign({username:'alice',resident:false,discoverable:false,uv:'discouraged'},arguments[0]);window.result=null", settings)
        element = self.command("POST", "/element", {"using": "css selector", "value": "#" + kind})
        self.command("POST", f"/element/{element[ELEMENT]}/click", {})
        end = time.monotonic() + 40
        pin_sent_at = None
        while time.monotonic() < end:
            try:
                result = self.script("return window.result")
            except WebDriverFailure as error:
                if error.code == "unexpected alert open" and pin_sent_at is not None and time.monotonic() - pin_sent_at < 1:
                    time.sleep(0.1)
                    continue
                if error.code != "unexpected alert open" or not pins:
                    raise
                message = self.command("GET", "/alert/text")
                if "PIN" not in message:
                    raise AssertionError(f"Unexpected browser dialog: {message}")
                if self.display is None:
                    raise RuntimeError("PIN typing requires the test-owned isolated display")
                self.display.screenshot(f"{self.family}-{kind}-{time.time_ns()}")
                # WebDriver identifies the actual password prompt but does not
                # support typing into it. Send keys only on our isolated display.
                self.display.type_test_pin(pins.pop(0))
                self.last_pin_prompts.append(message)
                self.record({"event": "native-pin-prompt", "attempt": len(self.last_pin_prompts), "message": message})
                pin_sent_at = time.monotonic()
                continue
            if result is not None:
                if pins:
                    raise AssertionError("ceremony finished without exercising every requested PIN attempt")
                if expected_error is not None:
                    if result.get("ok") or (result.get("phase"), result.get("name")) != expected_error:
                        raise AssertionError(f"expected {expected_error}, received {result}")
                    if error_contains is not None and error_contains not in result.get("error", ""):
                        raise AssertionError(f"expected error containing {error_contains!r}, received {result}")
                    event = "expected-rejection"
                elif not result.get("ok"):
                    raise AssertionError(f"{self.family} {kind}: {result}")
                else:
                    event = "verified"
                self.record({"event": event, "operation": kind, "settings": settings, "result": result})
                print(f"{self.family} {kind}: {json.dumps(result)}", flush=True)
                return result
            if during_wait is not None:
                during_wait(self)
            if account_choice is not None and pin_sent_at is not None and time.monotonic() - pin_sent_at > 1:
                self.display.screenshot(f"{self.label}-account-{account_choice}")
                self.display.select_test_account(account_choice, self.version)
                self.record({"event": "native-account-choice", "index": account_choice})
                account_choice = None
            time.sleep(0.1)
        raise TimeoutError(f"{self.family} {kind} did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=["firefox", "chrome", "both"], default="both")
    parser.add_argument("--headed", action="store_true", help="visible browser on a test-owned isolated Xvfb display")
    parser.add_argument("--pin-test", action="store_true", help="UV-required resident ceremonies on isolated Xvfb with public test PIN 1234")
    parser.add_argument("--attach-after-start", action="store_true", help="start the first browser before attaching the UHID device")
    args = parser.parse_args()
    artifacts = ROOT / "target/browser-results" / str(time.time_ns())
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    families = ["firefox", "chrome"] if args.browser == "both" else [args.browser]
    # One RP and authenticator across both browser sessions: re-use credentials
    # from the first browser in the second without a browser-specific device mode.
    from contextlib import ExitStack, nullcontext
    with ExitStack() as lifetime:
        fixture = lifetime.enter_context(Fixture())
        display = lifetime.enter_context(IsolatedDisplay(artifacts)) if args.headed or args.pin_test else None
        first = lifetime.enter_context(WebDriver(families[0], artifacts, args.headed or args.pin_test, display)) if args.attach_after_start else None
        if first is not None:
            first.navigate(fixture.origin)
        _, path, _ = lifetime.enter_context(daemon("dev-run", "approve"))
        with (artifacts / "ceremonies.jsonl").open("a") as output:
            output.write(json.dumps({"event": "device-attached", "after_browser_start": args.attach_after_start}) + "\n")
        if args.pin_test:
            with open_device(path) as device:
                ClientPin(Ctap2(device)).set_pin("1234")
        for family in families:
            session = nullcontext(first) if first is not None and family == families[0] else WebDriver(family, artifacts, args.headed or args.pin_test, display)
            with session as browser:
                browser.navigate(fixture.origin)
                settings = {"username": family, "uv": "required" if args.pin_test else "discouraged", "resident": args.pin_test}
                registered = browser.ceremony("register", enter_pin=args.pin_test, **settings)
                logged_in = browser.ceremony("authenticate", enter_pin=args.pin_test, discoverable=args.pin_test, **settings)
                assert logged_in["credentialId"] == registered["credentialId"]
                if args.pin_test:
                    assert registered["flags"] & 4 and logged_in["flags"] & 4
                if family == "chrome" and "firefox" in families:
                    browser.ceremony("authenticate", enter_pin=args.pin_test, username="firefox", discoverable=False,
                                     uv="required" if args.pin_test else "discouraged")
        if len(families) == 2:
            with WebDriver("firefox", artifacts, args.headed or args.pin_test, display) as browser:
                browser.navigate(fixture.origin)
                browser.ceremony("authenticate", enter_pin=args.pin_test, username="chrome", uv="required" if args.pin_test else "discouraged")


if __name__ == "__main__":
    main()
