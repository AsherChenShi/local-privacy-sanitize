"""Synthetic documents for the independent offline preflight."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sanitize.py"
sys.path.insert(0, str(SCRIPT.parent))
try:
    from sanitize import Rejected, sanitize, scan_kind
finally:
    sys.path.pop(0)


class StructuredRedactionTests(unittest.TestCase):
    def test_json_retains_key_order_string_type_and_safe_numeric_lexemes(self):
        original = ('{\r\n  "type": "image", "count": 1200, "access_token": "SYNTHETIC_ONLY",\r\n'
                    '  "scale": -2.450e-007, "large": 900719925474099312345,\r\n'
                    '  "nested": ["synthetic@example.invalid", true, null, {"ok": "no"}]\r\n}\r\n')
        expected = original.replace("SYNTHETIC_ONLY", "[SECRET_001]").replace(
            "synthetic@example.invalid", "[EMAIL_001]")
        output, report = sanitize(original, format="json")
        self.assertEqual(output, expected)
        self.assertEqual(json.loads(output)["count"], 1200)
        self.assertIsInstance(json.loads(output)["access_token"], str)
        self.assertEqual(report["occurrences"], {"EMAIL": 1, "SECRET": 1})
        self.assertIsNone(scan_kind(output))

    def test_json_decodes_escaped_keys_and_secret_before_validated_replacement(self):
        source = r'{"\u0061ccess_token":"SYNTHETIC\u005fONLY","status":"\u006fk","count":1200}'
        output, _ = sanitize(source, format="json")
        self.assertEqual(output, source.replace(r"SYNTHETIC\u005fONLY", "[SECRET_001]"))
        self.assertIsNone(scan_kind(output))

    def test_clean_json_is_unchanged(self):
        raw = '{ "type": "image", "status": "\\u006fk", "price": 1.20e02 }\r\n'
        output, report = sanitize(raw, format="json")
        self.assertEqual(output, raw)
        self.assertEqual(report["occurrences"], {})

    def test_ambiguous_or_unsafe_json_blocks_without_rewriting(self):
        fixtures = {
            "DUPLICATE_JSON_KEY": ('{"token": "one", "token": "two"}',),
            "INVALID_JSON": ('{"x":NaN}', '{"x":Infinity}', '{"x":"value",}',
                             '{"x":01}', '{"x":"unterminated}', '{"x":"ok"}{}'),
            "SENSITIVE_JSON_KEY": ('{"admin@example.invalid":"OK"}',),
            "SENSITIVE_NON_STRING_JSON_VALUE": ('{"password":123}', '{"password":["synthetic"]}'),
        }
        for reason, samples in fixtures.items():
            for raw in samples:
                with self.subTest(reason=reason, raw=raw), self.assertRaisesRegex(Rejected, reason):
                    sanitize(raw, format="json")

    def test_markdown_preserves_table_cells_and_nested_link_structure(self):
        original = ("# Report\r\n\r\n| Target | Status |\r\n| --- | --- |\r\n"
                    "| https://ci.internal.test/run|READY |\r\n"
                    "| [Ops [nested]](https://ci.internal.test/foo(bar) \"note\") | keep\\|pipe |\r\n")
        expected = original.replace("https://ci.internal.test/run", "[URL_001]").replace(
            "https://ci.internal.test/foo(bar)", "#redacted-url-002")
        output, report = sanitize(original, format="markdown")
        self.assertEqual(output, expected)
        self.assertEqual(report["occurrences"], {"URL": 2})

    def test_markdown_checks_link_title_and_autolinks(self):
        original = ('[Site](<https://github.com/octocat/Hello-World> "synthetic@example.invalid")\n'
                    '<https://ci.internal.test/mine>\n')
        output, _ = sanitize(original, format="markdown")
        self.assertEqual(output, ('[Site](<https://github.com/octocat/Hello-World> "[EMAIL_001]")\n'
                                  '<redacted:URL_001>\n'))

    def test_markdown_preserves_hard_line_break_and_detects_rendered_sensitive_text(self):
        original = 'Authorization: Basic SYNTHETIC_ONLY  \r\nNext line.\r\n'
        output, _ = sanitize(original, format="markdown")
        self.assertEqual(output, 'Authorization: [SECRET_001]  \r\nNext line.\r\n')
        with self.assertRaisesRegex(Rejected, "AMBIGUOUS_MARKDOWN_RANGE"):
            sanitize('Contact synthetic&#64;example.invalid.', format="markdown")
        encoded = '[Reference](https&colon;//ci.internal.test/synthetic)\n'
        output, _ = sanitize(encoded, format="markdown")
        self.assertEqual(output, '[Reference](#redacted-url-001)\n')

    def test_markdown_reuses_strict_json_inside_fence(self):
        original = 'Before\r\n\r\n~~~json\r\n{"count":1200,"access_token":"SYNTHETIC_ONLY"}\r\n~~~~\r\nAfter\r\n'
        output, report = sanitize(original, format="markdown")
        self.assertEqual(output, original.replace("SYNTHETIC_ONLY", "[SECRET_001]"))
        self.assertEqual(report["occurrences"], {"SECRET": 1})
        self.assertIsNone(scan_kind(output))
        self.assertIsNone(scan_kind("Please summarize this locally reviewed sample.\n" + output))

    def test_reviewed_json_placeholder_does_not_hide_other_secrets_in_prompt(self):
        clean = '{"access_token":"[SECRET_001]","count":1200}'
        self.assertIsNone(scan_kind(clean))
        self.assertIsNone(scan_kind("Read the following block.\n" + clean))
        self.assertEqual(scan_kind(clean.replace("1200", '"backup@example.invalid"')), "EMAIL")
        self.assertEqual(scan_kind(clean.replace(']"', ']SYNTHETIC_TAIL"')), "SECRET")

    def test_invalid_markdown_fence_aborts(self):
        for fixture, reason in (
            ('```json\n{"access_token":"SYNTHETIC_ONLY",}\n```\n', "INVALID_JSON"),
            ('```json\n{"access_token":"SYNTHETIC_ONLY"}\n', "UNCLOSED_MARKDOWN_FENCE"),
            ('[see](https://ci.internal.test/foo(bar)\n', "AMBIGUOUS_MARKDOWN_LINK"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(Rejected, reason):
                sanitize(fixture, format="markdown")

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              text=True, capture_output=True, timeout=10)

    def test_typed_artifacts_can_be_rechecked_and_hash_bound(self):
        for suffix, source, artifact in (
            (".json", '{"password":"SYNTHETIC_ONLY","count":1200}\n', "sanitized.json"),
            (".md", '~~~json\n{"access_token":"SYNTHETIC_ONLY","count":1200}\n~~~\n', "sanitized.md"),
        ):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                document = root / ("input" + suffix)
                document.write_text(source, encoding="utf-8")
                output = root / "candidate"
                self.assertEqual(self.run_cli("check", "--input", document).returncode, 3)
                result = self.run_cli("sanitize", "--input", document, "--out-dir", output)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["artifact"], artifact)
                self.assertEqual((output / artifact).read_text(), source.replace("SYNTHETIC_ONLY", "[SECRET_001]"))
                check = self.run_cli("check", "--input", output / artifact)
                self.assertEqual(check.returncode, 0, check.stderr)
                self.assertTrue(json.loads(check.stdout)["review_required"])
                self.assertNotIn("SYNTHETIC_ONLY", result.stdout + result.stderr + check.stdout)

    def test_explicit_format_accepts_pasted_text_but_not_a_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for filename, fmt, expect in (
                ("pasted.txt", "json", 0), ("unsafe.json", "text", 2),
            ):
                document = root / filename
                output = root / (filename + "-out")
                document.write_text('{"password":"SYNTHETIC_ONLY"}', encoding="utf-8")
                result = self.run_cli("sanitize", "--input", document, "--format", fmt, "--out-dir", output)
                self.assertEqual(result.returncode, expect)
                self.assertEqual(output.exists(), expect == 0)

    def test_invalid_input_exports_no_candidate_or_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = root / "input.json"
            document.write_text('{"password":"SYNTHETIC_ONLY",}', encoding="utf-8")
            output = root / "candidate"
            result = self.run_cli("sanitize", "--input", document, "--out-dir", output)
            self.assertEqual(result.returncode, 2)
            self.assertIn("INVALID_JSON", result.stderr)
            self.assertNotIn("SYNTHETIC_ONLY", result.stdout + result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
