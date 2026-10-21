#!/usr/bin/env python3
"""Offline safety/evidence guards; never contact public sites."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from public_sites import wait_ceremony


class PublicSiteTests(unittest.TestCase):
    def setUp(self):
        self.browser = Mock(family="firefox")
        self.page = {"origin": "https://webauthn.io", "path": "/profile", "body": "fixture", "alerts": []}
        self.pending = {"token": "fixture-only", "rp_id": "webauthn.io", "operation": "authenticate"}

    def test_external_writes_require_explicit_cli_opt_in(self):
        script = Path(__file__).with_name("public_sites.py")
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("public writes require prior user approval", result.stderr)
        self.assertNotIn("Artifacts:", result.stdout)

    @patch("public_sites.ctl")
    def test_never_approves_wrong_rp_or_operation(self, ctl):
        for pending in (dict(self.pending, rp_id="other.example"), dict(self.pending, operation="register")):
            ctl.reset_mock()
            ctl.return_value = {"pending": pending}
            with self.assertRaises(AssertionError):
                wait_ceremony(self.browser, "socket", "webauthn.io", "authenticate", lambda _: True)
            ctl.assert_called_once_with("socket", "status")

    @patch("public_sites.state")
    @patch("public_sites.ctl")
    def test_success_requires_actual_approval_origin_and_requested_pin(self, ctl, state):
        cases = (
            ({}, self.page, False),
            ({"pending": self.pending}, dict(self.page, origin="https://other.example"), False),
            ({"pending": self.pending}, self.page, True),
        )
        for status, page, require_pin in cases:
            ctl.return_value = status
            state.return_value = page
            with self.assertRaises(AssertionError):
                wait_ceremony(self.browser, "socket", "webauthn.io", "authenticate",
                              lambda _: True, pin_required=require_pin)
        self.browser.display.screenshot.assert_not_called()

    @patch("public_sites.state")
    @patch("public_sites.ctl")
    def test_records_observed_success_after_bound_approval(self, ctl, state):
        ctl.return_value = {"pending": self.pending}
        state.return_value = self.page
        result = wait_ceremony(self.browser, "socket", "webauthn.io", "authenticate", lambda _: True)
        self.assertEqual(result, self.page)
        ctl.assert_any_call("socket", "approve", "fixture-only")
        self.assertEqual(self.browser.record.call_args.args[0]["event"], "public-site-success")


if __name__ == "__main__":
    unittest.main(verbosity=2)
