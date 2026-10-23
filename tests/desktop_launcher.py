#!/usr/bin/env python3
"""Build/launch failure regressions with private tool and executable fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DesktopLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="yubiquity build ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        self.launcher = self.root / "scripts/desktop.sh"
        shutil.copyfile(ROOT / "scripts/desktop.sh", self.launcher)
        self.log = self.root / "events.jsonl"
        self.gui = self.root / "target/host-desktop/yubiquity-desktop"
        self.gui.parent.mkdir(parents=True)
        self.backend = self.root / "target/host/release/yubiquity"
        self.backend.parent.mkdir(parents=True)
        tools = self.root / "tools"
        tools.mkdir()
        # A failed rebuild must never run the previously built GUI.
        self.executable(self.gui, '''#!/usr/bin/python3
import os
with open(os.environ["YQ_TEST_LOG"], "a") as log:
    log.write('{"stage":"old-gui"}\\n')
''')
        replacement = '''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
backend = Path(sys.argv[sys.argv.index("--backend") + 1])
with open(os.environ["YQ_TEST_LOG"], "a") as log:
    log.write(json.dumps({"stage": "new-gui", "args": sys.argv[1:],
                          "backend": backend.read_text()}) + "\\n")
'''
        tool = '''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
stage = "cargo" if Path(sys.argv[0]).name == "cargo" else ("build" if "--build" in sys.argv else "configure")
with open(os.environ["YQ_TEST_LOG"], "a") as log:
    log.write(json.dumps({"stage": stage}) + "\\n")
if os.environ.get("YQ_TEST_FAIL") == stage:
    sys.exit(19)
if stage == "cargo":
    backend = Path(os.environ["CARGO_TARGET_DIR"]) / "release/yubiquity"
    backend.write_text("rebuilt backend")
if stage == "build":
    gui = Path(sys.argv[sys.argv.index("--build") + 1]) / "yubiquity-desktop"
    gui.write_text(REPLACEMENT)
    gui.chmod(0o700)
'''.replace("REPLACEMENT", repr(replacement))
        for name in ("cargo", "cmake"):
            self.executable(tools / name, tool)
        self.env = dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
                        YQ_TEST_LOG=str(self.log), CARGO_TARGET_DIR="unrelated-target")

    @staticmethod
    def executable(path, source):
        path.write_text(source)
        path.chmod(0o700)

    def invoke(self, *args):
        return subprocess.run(["bash", str(self.launcher), *args], cwd="/",
                              env=self.env, capture_output=True, text=True, timeout=10)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_run_rebuilds_both_and_preserves_paths_with_spaces(self):
        vault = str(self.root / "vault with spaces.yq")
        result = self.invoke("run", "--vault", vault)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        self.assertEqual([e["stage"] for e in events], ["cargo", "configure", "build", "new-gui"])
        self.assertEqual(events[-1]["backend"], "rebuilt backend")
        self.assertEqual(events[-1]["args"], ["--backend", str(self.backend),
                         "--require-new-instance", "--vault", vault])

    def test_any_build_failure_prevents_launch_of_old_gui(self):
        for failure in ("cargo", "configure", "build"):
            with self.subTest(failure=failure):
                self.log.write_text("")
                self.env["YQ_TEST_FAIL"] = failure
                result = self.invoke("run")
                self.assertEqual(result.returncode, 19, result.stderr)
                events = self.events()
                self.assertEqual(events[-1]["stage"], failure)
                self.assertFalse(any(e["stage"].endswith("gui") for e in events))

    def test_build_only_never_opens_gui(self):
        result = self.invoke("build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["stage"] for e in self.events()], ["cargo", "configure", "build"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
