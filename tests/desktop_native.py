#!/usr/bin/env python3
"""Exercise actual pinentry-qt windows on a private, test-owned Xvfb display.

No UHID, browser, real vault, host desktop, or real secret. Does not reuse DISPLAY.
The only typed passphrase is a fixed disposable fixture. Screenshots are taken
before typing, not while a secret is being displayed.
"""
import os
import json
import select
import socket
import struct
from pathlib import Path
import subprocess
import tempfile
import time

from PIL import ImageGrab

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "target/host-desktop"
BACKEND = ROOT / "target/host/release/yubiquity"
ARTIFACTS = ROOT / "target/desktop-native-results" / str(time.time_ns())


def main_window_smoke(env, temporary):
    """Actual entry point, private D-Bus single instance, SIGKILL watch cleanup."""
    bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    app = None
    try:
        assert select.select([bus.stdout], [], [], 5)[0], "Private D-Bus startup timed out"
        env = dict(env, DBUS_SESSION_BUS_ADDRESS=bus.stdout.readline().decode().strip(),
                   XDG_CONFIG_HOME=str(Path(temporary) / "settings"))
        path = str(Path(temporary) / "control.sock")
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(path)
            os.chmod(path, 0o600)
            server.listen(1)
            server.settimeout(30)
            command = [str(DESKTOP / "yubiquity-desktop"), "--backend",
                       str(BACKEND), "--socket", path]
            with (ARTIFACTS / "main-window.log").open("wb") as log:
                app = subprocess.Popen([str(ROOT / "scripts/desktop.sh"), "run", "--socket", path],
                                       env=env, stdout=log, stderr=log)
            peer, _ = server.accept()
            with peer:
                peer.settimeout(5)
                def read_exact(count):
                    data = b""
                    while len(data) < count:
                        chunk = peer.recv(count - len(data))
                        assert chunk, "Unexpected bridge EOF"
                        data += chunk
                    return data
                length = struct.unpack(">I", read_exact(4))[0]
                assert length < 8192
                assert json.loads(read_exact(length)) == {"command": "watch", "version": 1}
                data = json.dumps({"version": 1, "sequence": 1,
                                   "snapshot": {"ok": True, "state": "ready"}}).encode()
                peer.sendall(struct.pack(">I", len(data)) + data)
                second = subprocess.run(command, env=env, capture_output=True, timeout=5)
                assert second.returncode == 0, second.stderr.decode(errors="replace")
                assert app.poll() is None, "Second launch must activate, not replace, the first"
                update = subprocess.run(command + ["--require-new-instance"], env=env,
                                        capture_output=True, timeout=5)
                assert update.returncode != 0, "An update must not silently reuse the running GUI"
                assert b"Lock and quit" in update.stderr, update.stderr
                assert app.poll() is None, "Refusing a new launch must leave the existing app alone"
                time.sleep(0.1)
                ImageGrab.grab(xdisplay=env["DISPLAY"]).save(ARTIFACTS / "main-window.png")
                app.kill()
                app.wait(timeout=3)
                assert peer.recv(1) == b"", "GUI death must close its desktop lease"
        print("PASS build-and-run launcher, single instance, update refusal, SIGKILL watch cleanup", flush=True)
    finally:
        if app is not None and app.poll() is None:
            app.kill()
            app.wait(timeout=3)
        bus.terminate()
        bus.wait(timeout=3)


def main():
    ARTIFACTS.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="yubiquity-desktop-") as temporary:
        runtime = Path(temporary) / "runtime"
        runtime.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe()
        with (ARTIFACTS / "xvfb.log").open("wb") as log:
            xvfb = subprocess.Popen(["Xvfb", "-displayfd", str(write_fd), "-screen", "0",
                                     "1280x1024x24", "-nolisten", "tcp"],
                                    pass_fds=(write_fd,), stdout=log, stderr=log)
        os.close(write_fd)
        try:
            with os.fdopen(read_fd) as display_file:
                assert select.select([display_file], [], [], 5)[0], "Xvfb startup timed out"
                display = ":" + display_file.readline().strip()
            assert display[1:].isdigit(), "Xvfb failed to allocate a private display"
            env = dict(os.environ, DISPLAY=display, XDG_RUNTIME_DIR=str(runtime),
                       QT_QPA_PLATFORM="xcb", YUBIQUITY_NATIVE_TEST="1",
                       YUBIQUITY_TEST_ARTIFACTS=str(ARTIFACTS),
                       YUBIQUITY_TEST_BACKEND=str(BACKEND))
            env.pop("WAYLAND_DISPLAY", None)
            env.pop("DBUS_SESSION_BUS_ADDRESS", None)
            subprocess.run([str(DESKTOP / "desktop-tests"), "nativeApprovalPreview"],
                           env=env, check=True, timeout=10)
            for test in ("nativePinentryAccept", "nativePinentryCreate", "nativePinentryCancel"):
                case = subprocess.Popen([str(DESKTOP / "desktop-tests"), test],
                                        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 8
                    window = None
                    while time.monotonic() < deadline and case.poll() is None:
                        found = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "^YubiQuity$"],
                                               env=env, capture_output=True, text=True, timeout=2)
                        if found.returncode == 0:
                            windows = found.stdout.split()
                            assert len(windows) == 1, windows
                            window = windows[0]
                            break
                        time.sleep(0.05)
                    if window is None:
                        output = case.communicate(timeout=10)[0].decode(errors="replace")
                        raise AssertionError(f"{test}: no pinentry window\n{output}")
                    time.sleep(0.1)
                    ImageGrab.grab(xdisplay=display).save(ARTIFACTS / f"{test}.png")
                    def keys(*args):
                        subprocess.run(["xdotool", "windowfocus", "--sync", window, *args],
                                       env=env, check=True, timeout=3)
                    if test == "nativePinentryCancel":
                        keys("key", "Escape")
                    else:
                        keys("type", "--clearmodifiers", "--delay", "5", "disposable%test+passphrase")
                        if test == "nativePinentryCreate":
                            keys("key", "Tab")
                            keys("type", "--clearmodifiers", "--delay", "5", "disposable%test+passphrase")
                        keys("key", "Return")
                    output = case.communicate(timeout=20)[0].decode(errors="replace")
                    (ARTIFACTS / f"{test}.log").write_text(output)
                    assert case.returncode == 0, output
                    print(f"PASS {test}", flush=True)
                finally:
                    if case.poll() is None:
                        case.kill()
                        case.wait(timeout=3)
            main_window_smoke(env, temporary)
        finally:
            xvfb.terminate()
            xvfb.wait(timeout=3)
    print(f"Artifacts: {ARTIFACTS}")


if __name__ == "__main__":
    main()
