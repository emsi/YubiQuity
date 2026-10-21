#!/usr/bin/env python3
"""Offline policy-integrity checks; not a Docker/browser launch test."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Moby profiles seccomp/v0.2.4, commit
# 245180c51918481c0525424b3ee025d2b435d46c, seccomp/default.json.
# SHA-256 of its jq -cS representation, including the trailing newline.
BASE_SHA256 = "e57021c16b3957ebd18a87e9cc18b401a0dd0e9cb8f35d077ee04f2fb601b559"


class ContainerSeccompTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / "packaging/docker/chrome-seccomp.json").read_text())

    def test_only_change_from_pinned_upstream_is_one_namespace_rule(self):
        base = dict(self.profile, syscalls=self.profile["syscalls"][1:])
        canonical = (json.dumps(base, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), BASE_SHA256)

    def test_namespace_exception_is_exactly_the_documented_three_syscalls(self):
        extension = dict(self.profile["syscalls"][0])
        self.assertIn("YubiQuity", extension.pop("comment"))
        self.assertEqual(extension, {
            "names": ["clone", "setns", "unshare"],
            "action": "SCMP_ACT_ALLOW", "args": [], "includes": {}, "excludes": {},
        })

    def test_default_deny_and_clone3_fallback_are_retained(self):
        self.assertEqual(self.profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertEqual(self.profile["defaultErrnoRet"], 1)
        self.assertIn({
            "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38,
            "excludes": {"caps": ["CAP_SYS_ADMIN"]},
        }, self.profile["syscalls"])
        # Avoid unintentionally importing the broader, older Playwright baseline.
        for rule in self.profile["syscalls"]:
            if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("includes"):
                self.assertFalse(set(rule["names"]) & {
                    "mount", "bpf", "perf_event_open", "io_uring_setup",
                })


class ComposeOverrideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = [shutil.which("docker-compose"),
                      "/usr/libexec/docker/cli-plugins/docker-compose",
                      "/usr/lib/docker/cli-plugins/docker-compose"]
        cls.compose = next((p for p in candidates if p and os.access(p, os.X_OK)), None)
        if cls.compose is None:
            raise unittest.SkipTest("install docker-compose-v2 for offline merge checks")

    def config(self, *, configured=True):
        # Synthetic input only. No Docker daemon, image pull, or container start.
        base = {
            "services": {"codex": {
                "image": "example.invalid/yubiquity-config-test:never-pulled",
                "user": "1000:1000", "entrypoint": ["/existing-entrypoint"],
                "privileged": True, "ipc": "host",
                "security_opt": ["no-new-privileges:true", "seccomp=unconfined", "apparmor=unconfined"],
                "devices": ["/dev/uhid:/dev/uhid:rw"],
                "device_cgroup_rules": ["c 234:* rwm"],
                "volumes": ["retained-home:/home/emsi"],
            }},
            "volumes": {"retained-home": {}},
        }
        env = dict(os.environ, DOCKER_HOST="unix:///nonexistent-yubiquity-compose-test.sock")
        env.pop("YUBIQUITY_SECCOMP", None)
        if configured:
            env["YUBIQUITY_SECCOMP"] = str(ROOT / "packaging/docker/chrome-seccomp.json")
        return subprocess.run([
            self.compose, "--env-file", "/dev/null", "-p", "yubiquity-compose-test",
            "-f", "-", "-f", str(ROOT / "compose.yubiquity.override.yaml"),
            "config", "--format", "json",
        ], input=json.dumps(base), env=env, cwd=ROOT, text=True,
            capture_output=True, timeout=15)

    def test_merge_replaces_conflicts_and_duplicates_but_preserves_base_identity(self):
        result = self.config()
        self.assertEqual(result.returncode, 0, result.stderr)
        service = json.loads(result.stdout)["services"]["codex"]
        self.assertEqual(service["security_opt"], [
            "no-new-privileges:false", "apparmor=docker-default",
            "seccomp=" + str(ROOT / "packaging/docker/chrome-seccomp.json"),
        ])
        self.assertEqual(service["devices"], [{"source": "/dev/uhid", "target": "/dev/uhid", "permissions": "rw"}])
        self.assertEqual(service["device_cgroup_rules"], ["c 234:* rwm"])
        self.assertEqual(service["ipc"], "private")
        self.assertEqual(int(service["shm_size"]), 1024 ** 3)
        self.assertFalse(service.get("privileged", False))
        self.assertFalse(service.get("cap_add"))
        self.assertEqual(service["user"], "1000:1000")
        self.assertEqual(service["entrypoint"], ["/existing-entrypoint"])
        self.assertEqual(service["image"], "example.invalid/yubiquity-config-test:never-pulled")
        self.assertEqual(service["volumes"][0]["source"], "retained-home")

    def test_missing_host_profile_variable_fails_before_container_creation(self):
        result = self.config(configured=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("YUBIQUITY_SECCOMP", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
