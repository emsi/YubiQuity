#!/usr/bin/env python3
"""Offline policy-integrity checks; not a Docker/browser launch test."""
import hashlib
import json
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
