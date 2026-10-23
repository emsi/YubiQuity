#!/usr/bin/env python3
"""Isolated KWin 5.27 X11/Wayland workspace and tray regressions.

Always creates a private D-Bus, config/runtime dirs and Xvfb or virtual Wayland
compositor. Never connects to the host's desktop. The service and SNI host are
test-only fixtures; no UHID, secrets, browsers or credentials are used.
Requires kwin-x11, kwin-wayland, python3-dbus, python3-gi, xvfb and dbus-daemon.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

import dbus

ROOT = Path(__file__).resolve().parents[1]


def wait_for(check, message, seconds=8):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError(message)


def tray_fixture(address):
    from dbus.mainloop.glib import DBusGMainLoop
    import dbus.service
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    bus = dbus.bus.BusConnection(address)
    name = dbus.service.BusName("org.kde.StatusNotifierWatcher", bus=bus)

    class Watcher(dbus.service.Object):
        def __init__(self):
            super().__init__(name, "/StatusNotifierWatcher")
            self.items = []

        @dbus.service.method("org.freedesktop.DBus.Introspectable", out_signature="s")
        def Introspect(self):
            # Qt's dynamic interface discovers properties from introspection,
            # not just from the Properties.Get implementation.
            return '''<node><interface name="org.kde.StatusNotifierWatcher">
              <method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
              <method name="RegisterStatusNotifierHost"><arg type="s" direction="in"/></method>
              <property name="RegisteredStatusNotifierItems" type="as" access="read"/>
              <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
              <property name="ProtocolVersion" type="i" access="read"/>
              <signal name="StatusNotifierItemRegistered"><arg type="s"/></signal>
              <signal name="StatusNotifierHostRegistered"/>
            </interface><interface name="org.freedesktop.DBus.Properties">
              <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
              <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
            </interface></node>'''

        @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s", sender_keyword="sender")
        def RegisterStatusNotifierItem(self, service, sender=None):
            item = sender + service if service.startswith("/") else service + "/StatusNotifierItem"
            self.items.append(item)
            self.StatusNotifierItemRegistered(item)

        @dbus.service.signal("org.kde.StatusNotifierWatcher", signature="s")
        def StatusNotifierItemRegistered(self, item):
            pass

        @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s")
        def RegisterStatusNotifierHost(self, _service):
            pass

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            return self.GetAll(interface)[prop]

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
        def GetAll(self, _interface):
            return {"RegisteredStatusNotifierItems": dbus.Array(self.items, signature="s"),
                    "IsStatusNotifierHostRegistered": dbus.Boolean(True),
                    "ProtocolVersion": dbus.Int32(0)}

    watcher = Watcher()
    GLib.MainLoop().run()
    return watcher


class Service:
    def __init__(self, path):
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(path))
        os.chmod(path, 0o600)
        self.server.listen(8)
        self.server.settimeout(.1)
        self.watcher = None
        self.sequence = 0
        self.state = "locked"
        self.pending = None
        self.commands = []
        self.stopping = threading.Event()
        self.mutex = threading.RLock()
        self.error = None
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    @staticmethod
    def send(peer, value):
        data = json.dumps(value).encode()
        peer.sendall(struct.pack(">I", len(data)) + data)

    def publish(self):
        with self.mutex:
            if self.watcher:
                self.sequence += 1
                state = {"ok": True, "state": self.state}
                if self.pending:
                    state["pending"] = self.pending
                self.send(self.watcher, {"version": 1, "sequence": self.sequence, "snapshot": state})

    def request(self, token):
        self.pending = {"token": token, "operation": "register", "rp_id": "example.test",
                        "account": "disposable", "remaining_ms": 30000}
        self.publish()

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    peer, _ = self.server.accept()
                except socket.timeout:
                    continue
                peer.settimeout(3)
                def read_exact(size):
                    data = b""
                    while len(data) < size:
                        chunk = peer.recv(size - len(data))
                        if not chunk:
                            raise RuntimeError("fixture request ended early")
                        data += chunk
                    return data
                size = struct.unpack(">I", read_exact(4))[0]
                assert size <= 8192
                command = json.loads(read_exact(size))
                if command["command"] == "watch":
                    self.watcher = peer
                    self.publish()
                else:
                    with self.mutex:
                        self.commands.append(command)
                        self.send(peer, {"ok": True, "state": self.state})
                        peer.close()
        except BaseException as error:
            self.error = error

    def close(self):
        self.stopping.set()
        self.thread.join(4)
        if self.watcher:
            self.watcher.close()
        self.server.close()
        assert not self.thread.is_alive()
        if self.error:
            raise self.error


def run(platform, artifacts):
    artifacts.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="yubiquity-workspaces-") as temporary, contextlib.ExitStack() as stack:
        root = Path(temporary)
        runtime, config = root / "runtime", root / "config"
        runtime.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        # Files only in this test's private configuration, never ~/.config.
        (config / "kwinrc").write_text("[Desktops]\nNumber=2\n[Compositing]\nEnabled=false\n")
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(config),
                   XDG_CACHE_HOME=str(root / "cache"), QT_QPA_PLATFORM="xcb",
                   KWIN_COMPOSE="Q", LIBGL_ALWAYS_SOFTWARE="1")
        for key in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "SESSION_MANAGER",
                    "XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID", "QT_QPA_PLATFORMTHEME"):
            env.pop(key, None)

        def spawn(args, label, child_env=env, **kwargs):
            log = stack.enter_context((artifacts / (label + ".log")).open("wb"))
            process = subprocess.Popen(args, env=child_env, stderr=log, stdout=kwargs.pop("stdout", log), **kwargs)
            def stop():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            stack.callback(stop)
            return process

        daemon = spawn(["dbus-daemon", "--session", "--nofork", "--print-address=1"], "bus", stdout=subprocess.PIPE)
        assert select.select([daemon.stdout], [], [], 5)[0]
        address = daemon.stdout.readline().decode().strip()
        assert address.startswith("unix:"), address
        env["DBUS_SESSION_BUS_ADDRESS"] = address
        bus = dbus.bus.BusConnection(address)
        stack.callback(bus.close)
        spawn(["/usr/bin/python3", __file__, "--tray-fixture", address], "tray")
        wait_for(lambda: bus.name_has_owner("org.kde.StatusNotifierWatcher"), "private tray did not start")

        if platform == "x11":
            read_fd, write_fd = os.pipe()
            spawn(["Xvfb", "-displayfd", str(write_fd), "-screen", "0", "1280x1024x24", "-nolisten", "tcp"],
                  "xvfb", pass_fds=(write_fd,))
            os.close(write_fd)
            with os.fdopen(read_fd) as display:
                assert select.select([display], [], [], 5)[0]
                number = display.readline().strip()
            assert number.isdigit()
            env["DISPLAY"] = ":" + number
            dbus.Interface(bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"), "org.freedesktop.DBus").UpdateActivationEnvironment(
                {key: env[key] for key in ("DISPLAY", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "QT_QPA_PLATFORM")})
            spawn(["kwin_x11"], "kwin")
        else:
            # The distro executable has cap_sys_resource, outside container bounds.
            # A byte-for-byte test copy WITHOUT file capabilities needs no elevation.
            executable = root / "kwin_wayland"
            shutil.copyfile(shutil.which("kwin_wayland"), executable)
            executable.chmod(0o700)
            compositor_env = dict(env, QT_QPA_PLATFORM="offscreen")
            spawn([str(executable), "--virtual", "--no-lockscreen", "--no-global-shortcuts", "--no-kactivities",
                   "--socket", "yubiquity-test-wayland"], "kwin", compositor_env)
            wait_for(lambda: (runtime / "yubiquity-test-wayland").exists(), "Wayland compositor did not start")
            env["WAYLAND_DISPLAY"] = "yubiquity-test-wayland"
            env["QT_QPA_PLATFORM"] = "wayland"

        wait_for(lambda: bus.name_has_owner("org.kde.KWin"), "private KWin did not start")
        def scripting_ready():
            try:
                return "loadScript" in str(bus.call_blocking("org.kde.KWin", "/Scripting", "org.freedesktop.DBus.Introspectable", "Introspect", "", (), timeout=2))
            except dbus.DBusException:
                return False
        wait_for(scripting_ready, "KWin scripting did not become ready")
        scripting = dbus.Interface(bus.get_object("org.kde.KWin", "/Scripting"), "org.kde.kwin.Scripting")
        serial = 0
        def script(code):
            nonlocal serial
            serial += 1
            name = f"yubiquity-test-{serial}"
            marker = f"YUBIQUITY_STATE_{serial}:"
            source = root / (name + ".js")
            source.write_text(code + '\nconsole.log(' + json.dumps(marker) + ''' + JSON.stringify({
                desktop: workspace.currentDesktop,
                windows: workspace.clientList().map(function(c) {
                    return {caption: c.caption, desktop: c.desktop, minimized: c.minimized,
                            transient: c.transient, pid: c.pid, resourceClass: String(c.resourceClass)};
                })
            }));''')
            identity = bus.call_blocking("org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting", "loadScript", "ss", (str(source), name), timeout=3)
            assert identity >= 0
            dbus.Interface(bus.get_object("org.kde.KWin", "/" + str(identity)), "org.kde.kwin.Script").run(timeout=3)
            def result():
                for line in (artifacts / "kwin.log").read_text(errors="replace").splitlines():
                    if marker in line:
                        return json.loads(line.split(marker, 1)[1])
                return None
            value = wait_for(result, "KWin script did not return a snapshot")
            scripting.unloadScript(name, timeout=3)
            return value

        script("workspace.desktops = 2; workspace.currentDesktop = 1;")
        service = Service(root / "control.sock")
        stack.callback(service.close)
        app = spawn([str(ROOT / "target/desktop/yubiquity-desktop"), "--backend", str(ROOT / "target/debug/yubiquity"),
                     "--socket", str(root / "control.sock")], "app")
        def windows(title):
            value = script("")
            return [w for w in value["windows"] if w["pid"] == app.pid and w["caption"] == title]
        wait_for(lambda: windows("YubiQuity"), "main window did not appear")
        tray = dbus.Interface(bus.get_object("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher"), "org.freedesktop.DBus.Properties")
        items = wait_for(lambda: tray.Get("org.kde.StatusNotifierWatcher", "RegisteredStatusNotifierItems"), "app did not register its tray icon")
        service_name, path = str(items[0]).split("/", 1)
        icon = dbus.Interface(bus.get_object(service_name, "/" + path), "org.kde.StatusNotifierItem")

        # Successful unlock transition should hide the vault window, not quit.
        service.state = "ready"
        service.publish()
        wait_for(lambda: not windows("YubiQuity"), "ready window did not hide to tray")
        assert app.poll() is None
        script("workspace.currentDesktop = 2;")
        service.request("request-on-desktop-2")
        approval = wait_for(lambda: windows("Create a passkey"), "approval missing")[0]
        assert approval["desktop"] == 2 and not approval["transient"], approval
        assert script("")["desktop"] == 2, "new approval switched the user's workspace"
        assert not windows("YubiQuity"), "request reopened the vault window"

        # Tray activation must show only the same pending request.
        icon.Activate(0, 0, timeout=3)
        assert not windows("YubiQuity")
        assert len(windows("Create a passkey")) == 1

        script("workspace.currentDesktop = 1;")
        icon.Activate(0, 0, timeout=3)
        wait_for(lambda: any(w["desktop"] == 1 for w in windows("Create a passkey")),
                 "tray activation did not bring the request to the current desktop")
        assert script("")["desktop"] == 1, "tray activation switched desktops"

        # Closing the independent top-level still denies exactly its own token.
        script('workspace.clientList().forEach(function(c) { if(c.caption === "Create a passkey") c.closeWindow(); });')
        wait_for(lambda: service.commands, "closing approval did not send a decision")
        assert service.commands == [{"command": "deny", "token": "request-on-desktop-2"}], service.commands
        service.pending = None
        service.publish()
        wait_for(lambda: not windows("Create a passkey"), "denied popup remained")

        # Explicitly opening the main window should not get undone by heartbeats.
        icon.Activate(0, 0, timeout=3)
        wait_for(lambda: windows("YubiQuity"), "tray did not reopen main window")
        service.publish()
        time.sleep(.2)
        assert windows("YubiQuity"), "heartbeat hid the explicitly opened window"
        # xdg-shell does not report compositor-initiated minimized state to apps.
        # Exercise the cross-platform close-to-tray path on native Wayland.
        action = "c.minimized = true" if platform == "x11" else "c.closeWindow()"
        script('workspace.clientList().forEach(function(c) { if(c.caption === "YubiQuity") ' + action + '; });')
        wait_for(lambda: not windows("YubiQuity"), "minimize/close did not hide to tray")

        # New requests should follow subsequent workspace changes too.
        script("workspace.currentDesktop = 1;")
        service.request("new-request-on-desktop-1")
        approval = wait_for(lambda: windows("Create a passkey"), "second popup missing")[0]
        assert approval["desktop"] == 1 and not approval["transient"], approval
        assert script("")["desktop"] == 1
        service.pending = None
        service.publish()
        wait_for(lambda: not windows("Create a passkey"), "browser cancellation left a popup")
        assert len(service.commands) == 1, "cancellation approved or denied a different request"
        (artifacts / "result.json").write_text(json.dumps({"platform": platform, "result": "passed"}, indent=2))
        print(f"PASS KWin {platform}: tray, current-workspace prompts, recall, cancellation and hiding", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("x11", "wayland", "both"), default="both")
    parser.add_argument("--tray-fixture", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.tray_fixture:
        tray_fixture(args.tray_fixture)
        return
    artifacts = ROOT / "target/desktop-workspace-results" / str(time.time_ns())
    print(f"Artifacts: {artifacts}", flush=True)
    for platform in (("x11", "wayland") if args.platform == "both" else (args.platform,)):
        run(platform, artifacts / platform)


if __name__ == "__main__":
    main()
