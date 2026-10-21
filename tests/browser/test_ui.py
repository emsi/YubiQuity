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
    def test_chooser_selects_only_the_requested_word_box(self, run):
        words = [{"text": name, "conf": "95", "left": "65", "top": str(top),
                  "width": "40", "height": "20"} for name, top in (("bob", 240), ("alice", 305))]
        self.dialog("Choose a passkey for localhost bob USB security key alice USB security key", words)
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
