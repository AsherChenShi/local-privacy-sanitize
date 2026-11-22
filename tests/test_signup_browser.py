"""Synthetic-only checks for the private offline browser worker."""

import os
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from signup_browser import BrowserError, _fill, fill_email


EMAIL = "synthetic@example.invalid"


class FixturePipe:
    def __init__(self, *, document="about:blank", field=42, value=EMAIL):
        self.calls = []
        self.replies = {
            "Target.createBrowserContext": {"browserContextId": "private"},
            "Target.createTarget": {"targetId": "form"},
            "Target.attachToTarget": {"sessionId": "form-session"},
            "Page.getFrameTree": {"frameTree": {"frame": {"id": "form-document", "url": document}}},
            "DOM.getDocument": {"root": {"nodeId": 4}},
            "DOM.querySelector": {"nodeId": field},
            "Runtime.evaluate": {"result": {"value": value}},
        }

    def call(self, method, params=None, *, session=None):
        self.calls.append((method, params, session))
        return self.replies.get(method, {})


class SignupBrowserTests(unittest.TestCase):
    def test_fill_only_after_isolating_exact_synthetic_document(self):
        pipe = FixturePipe()
        self.assertEqual(_fill(pipe, EMAIL), EMAIL)
        calls = [method for method, _, _ in pipe.calls]
        self.assertEqual(calls[-1], "Target.disposeBrowserContext")
        self.assertEqual(pipe.calls[1][1], {"url": "about:blank", "browserContextId": "private"})
        write_step = calls.index("Input.insertText")
        for method in ("Network.setBlockedURLs", "Network.emulateNetworkConditions", "DOM.focus"):
            self.assertLess(calls.index(method), write_step)
        document = pipe.calls[calls.index("Page.setDocumentContent")][1]["html"]
        self.assertIn("default-src 'none'", document)
        self.assertIn("form-action 'none'", document)
        self.assertNotIn("<script", document)
        self.assertNotIn(EMAIL, document)
        carrying_value = [(method, params) for method, params, _ in pipe.calls if EMAIL in str(params)]
        self.assertEqual(carrying_value, [("Input.insertText", {"text": EMAIL})])

    def test_rejects_navigation_or_missing_exact_field_without_writing_email(self):
        for pipe in (FixturePipe(document="about:srcdoc"), FixturePipe(field=0)):
            with self.subTest():
                with self.assertRaisesRegex(BrowserError, "BROWSER_FAILED"):
                    _fill(pipe, EMAIL)
                self.assertNotIn("Input.insertText", [method for method, _, _ in pipe.calls])

    def test_rejects_changed_value_without_exposing_it_in_error(self):
        with self.assertRaisesRegex(BrowserError, "^BROWSER_FAILED$") as error:
            _fill(FixturePipe(value="changed@example.invalid"), EMAIL)
        self.assertNotIn("@", str(error.exception))

    def test_non_synthetic_email_and_missing_browser_are_safe_failures(self):
        with self.assertRaisesRegex(BrowserError, "^INVALID_SYNTHETIC_EMAIL$"):
            fill_email("human@example.com", browser_path="/missing")
        with self.assertRaisesRegex(BrowserError, "^BROWSER_UNAVAILABLE$"):
            fill_email(EMAIL, browser_path="/missing")

    @unittest.skipUnless(os.environ.get("LOCAL_PRIVACY_TEST_CHROMIUM"), "optional native browser fixture")
    def test_actual_isolated_chromium(self):
        self.assertEqual(fill_email(EMAIL, browser_path=os.environ["LOCAL_PRIVACY_TEST_CHROMIUM"]), EMAIL)


if __name__ == "__main__":
    unittest.main()
