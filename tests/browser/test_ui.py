#!/usr/bin/env python3
"""Offline tests of native-UI guards; actual browser runs remain separate."""
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from ceremonies import IsolatedDisplay, check_chrome_sandbox


class UiTests(unittest.TestCase):
    def setUp(self):
        self.display = IsolatedDisplay(Path("unused-test-artifacts"))
        self.display.env = {"DISPLAY": ":fixture-only"}
        self.screen = Mock()
        self.display.chrome_dialog = Mock()

    def dialog(self, text, words=()):
        self.display.chrome_dialog.return_value = (self.screen, text, text.lower(), list(words))

    def test_pin_requires_title_and_security_key_instruction(self):
        for text in ("PIN required", "Enter the PIN for your security key", "Choose a passkey"):
            self.dialog(text)
            self.assertIsNone(self.display.chrome_pin_prompt("155.0"))
        text = "PIN required Enter the PIN for your security key"
        self.dialog(text)
        self.assertEqual(self.display.chrome_pin_prompt("155.0"), text)

    def test_retry_waits_for_wrong_pin_feedback(self):
        text = "PIN required Enter the PIN for your security key"
        self.dialog(text)
        self.assertIsNone(self.display.chrome_pin_prompt("155.0", retry=True))
        self.dialog(text + " Incorrect PIN")
        self.assertIn("Incorrect", self.display.chrome_pin_prompt("155.0", retry=True))

    @patch("ceremonies.subprocess.run")
    def test_public_account_confirmation_requires_exact_requested_domain(self, run):
        for domain in ("localhost", "webauthn.io.example", "other.example"):
            self.dialog(f"Use a saved passkey for {domain} alice USB security key")
            self.assertIsNone(self.display.chrome_confirm_account("155.0", "alice", "webauthn.io"))
        run.assert_not_called()
        self.dialog("Use a saved passkey for webauthn.io alice USB security key")
        self.assertIsNotNone(self.display.chrome_confirm_account("155.0", "alice", "webauthn.io"))
        self.assertEqual(run.call_args.kwargs["env"], self.display.env)

    @patch("ceremonies.subprocess.run")
    def test_pin_resubmission_does_not_type_or_accept_an_error_sheet(self, run):
        for text in ("PIN required", "Choose a passkey", "PIN required Enter the PIN for your security key Incorrect PIN"):
            self.dialog(text)
            self.assertIsNone(self.display.chrome_submit_typed_pin("155.0"))
        run.assert_not_called()
        self.dialog("PIN required Enter the PIN for your security key")
        self.assertIsNotNone(self.display.chrome_submit_typed_pin("155.0"))
        self.assertEqual(run.call_args.args[0], ["xdotool", "key", "--clearmodifiers", "Return"])
        self.assertEqual(run.call_args.kwargs["env"], self.display.env)

    @patch("ceremonies.subprocess.run")
    def test_confirmation_requires_local_fixture_and_exact_account(self, run):
        text = "Use a saved passkey for localhost alice USB security key"
        self.dialog(text)
        self.assertIsNone(self.display.chrome_confirm_account("155.0", "ali"))
        self.assertIsNone(self.display.chrome_confirm_account("155.0", "bob"))
        self.dialog(text.replace("localhost", "example.com"))
        self.assertIsNone(self.display.chrome_confirm_account("155.0", "alice"))
        run.assert_not_called()
        self.dialog(text)
        self.assertEqual(self.display.chrome_confirm_account("155.0", "alice"), text)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "690", "394", "click", "1"])
        self.assertEqual(run.call_args.kwargs["env"], self.display.env)

    @patch("ceremonies.subprocess.run")
    def test_already_registered_error_can_use_close_button(self, run):
        word = {"text": "Close", "conf": "95", "left": "250", "top": "275", "width": "50", "height": "20"}
        text = "Try a different device You already registered this device Close Try again"
        self.dialog(text, [word])
        self.assertEqual(self.display.chrome_dismiss_error(
            "155.0", ("try a different device", "you already registered this device")), text)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "585", "375", "click", "1"])
        self.dialog(text, [])
        self.assertEqual(self.display.chrome_dismiss_error(
            "155.0", ("try a different device", "you already registered this device")), text)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "585", "376", "click", "1"])
        text = "Try a different security key You're using a security key that's not registered with this website"
        self.dialog(text, [])
        self.assertEqual(self.display.chrome_dismiss_error(
            "155.0", ("try a different security key", "not registered with this website")), text)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "585", "376", "click", "1"])

    @patch("ceremonies.subprocess.run")
    def test_chooser_selects_only_the_requested_word_box(self, run):
        words = [{"text": name, "conf": "95", "left": "65", "top": str(top),
                  "width": "40", "height": "20"} for name, top in (("bob", 240), ("alice", 305))]
        self.dialog("Choose a passkey Which passkey do you want to use for localhost? bob USB security key alice USB security key", words)
        self.assertIsNotNone(self.display.chrome_confirm_account("155.0", "alice"))
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "395", "405", "click", "1"])

    @patch("ceremonies.subprocess.run")
    def test_chooser_refuses_ambiguous_uncertain_or_out_of_bounds_text(self, run):
        word = {"text": "alice", "conf": "95", "left": "65", "top": "240", "width": "40", "height": "20"}
        for words in ([word, word], [dict(word, conf="20")], [dict(word, top="5")], []):
            self.dialog("Choose a passkey for localhost alice USB security key", words)
            self.assertIsNone(self.display.chrome_confirm_account("155.0", "alice"))
        run.assert_not_called()

    def test_unknown_browser_ui_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "inspect the native UI"):
            IsolatedDisplay(Path("unused-test-artifacts")).chrome_dialog("156.0")

    @patch("ceremonies.subprocess.run")
    def test_error_dismissal_requires_exact_failure_and_bounded_cancel_button(self, run):
        expected = ("something went wrong", "your identity couldn't be verified")
        text = "Something went wrong Your identity couldn’t be verified Cancel Try again"
        word = {"text": "Cancel", "conf": "95", "left": "250", "top": "255", "width": "50", "height": "20"}
        for wrong in ("PIN required Cancel", "Something went wrong Cancel", "Choose a passkey Cancel"):
            self.dialog(wrong, [word])
            self.assertIsNone(self.display.chrome_dismiss_error("155.0", expected))
        for words in ([], [word, word], [dict(word, conf="20")], [dict(word, top="5")]):
            self.dialog(text, words)
            self.assertIsNone(self.display.chrome_dismiss_error("155.0", expected))
        run.assert_not_called()
        self.dialog(text, [word])
        self.assertEqual(self.display.chrome_dismiss_error("155.0", expected), text)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "585", "355", "click", "1"])
        self.assertEqual(run.call_args.kwargs["env"], self.display.env)

    def test_namespace_and_seccomp_layers_must_all_be_reported_active(self):
        status = ("Layer 1 Sandbox\tNamespace\nPID namespaces\tYes\nNetwork namespaces\tYes\n"
                  "Seccomp-BPF sandbox\tYes\nSeccomp-BPF sandbox supports TSYNC\tYes\n"
                  "Ptrace Protection with Yama LSM (Non-broker)\tNo")
        check_chrome_sandbox(status)
        for line in status.splitlines()[:5]:
            with self.subTest(line=line), self.assertRaises(AssertionError):
                check_chrome_sandbox(status.replace(line, ""))
            with self.subTest(line=line), self.assertRaises(AssertionError):
                check_chrome_sandbox(status.replace(line, line.split("\t")[0] + "\tNo"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
