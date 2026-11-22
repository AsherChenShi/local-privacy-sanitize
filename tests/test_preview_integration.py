"""Exercise offline preview and ordinary-type selection with fictional data."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from sanitize import preview_rows, sanitize, write_bundle
finally:
    sys.path.pop(0)


ALPHA = "trace-one@example.invalid"
BETA = "trace-two@example.invalid"
CREDENTIAL = "SYNTHETIC_TRACE_PASSWORD"
PERSON = "SYNTHETIC_CUSTOMER_PERSON"
ADDRESS = "SYNTHETIC_PRIVATE_ADDRESS"


def payload_from_html(html):
    [payload] = re.findall(r'<script id="review-data" type="application/json">(.*?)</script>', html, re.S)
    return json.loads(payload)


class SpanTests(unittest.TestCase):
    def trace(self, source, format):
        edits = []
        output, report = sanitize(source, format=format, edits=edits)
        rows = preview_rows(source, edits)
        self.assertEqual(len(rows), sum(report["occurrences"].values()))
        self.assertEqual((output, report), sanitize(source, format=format))
        return output, rows

    def test_text_origins_follow_crlf_and_candidate_offsets_follow_multiline_redaction(self):
        pem = "-----BEGIN PRIVATE KEY-----\r\nSYNTHETIC_BODY\r\n-----END PRIVATE KEY-----"
        prefix = "🧪联系："
        source = prefix + ALPHA + "\r\n" + pem + "\r" + BETA + "\n"
        candidate, rows = self.trace(source, "text")
        self.assertEqual([(row["line"], row["column"], row["kind"]) for row in rows],
                         [(1, len(prefix) + 1, "EMAIL"), (2, 1, "SECRET"), (5, 1, "EMAIL")])
        self.assertEqual([candidate[row["start"]:row["end"]] for row in rows],
                         ["[EMAIL_001]", "[SECRET_001]", "[EMAIL_002]"])

    def test_json_preserves_offsets_through_escaped_text_and_multiple_replacements(self):
        source = (r'{"x":"\ud83d\ude0a trace \u0074race-one@example.invalid and trace-two@example.invalid",'
                  r'"api_key":"SYNTHETIC_TRACE_PASSWORD"}')
        candidate, rows = self.trace(source, "json")
        self.assertEqual([row["column"] for row in rows],
                         [source.index(r"\u0074race-one") + 1, source.index(BETA) + 1, source.index(CREDENTIAL) + 1])
        self.assertEqual([candidate[row["start"]:row["end"]] for row in rows],
                         ["[EMAIL_001]", "[EMAIL_002]", "[SECRET_001]"])
        self.assertIn("😊", json.loads(candidate)["x"])

    def test_markdown_composes_table_link_and_json_fence_ranges(self):
        url = "https://private.invalid/trace"
        source = ("| 入口 | 状态 |\r\n| --- | --- |\r\n| [工具](" + url + ") | READY |\r\n\r\n"
                  '```json\r\n{"email":"' + ALPHA + '","access_token":"' + CREDENTIAL + '"}\r\n```\r\n')
        candidate, rows = self.trace(source, "markdown")
        positions = [(3, source.splitlines()[2].index(url) + 1),
                     (6, source.splitlines()[5].index(ALPHA) + 1),
                     (6, source.splitlines()[5].index(CREDENTIAL) + 1)]
        self.assertEqual([(row["line"], row["column"]) for row in rows], positions)
        self.assertEqual([candidate[row["start"]:row["end"]] for row in rows],
                         ["#redacted-url-001", "[EMAIL_001]", "[SECRET_001]"])
        self.assertEqual(rows[0]["marker"], "[URL_001]")


class PreviewCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.default_policy = self.directory / ".config/local-privacy-sanitize/review-policy.local.json"
        self.source = self.directory / "private-filename-for-test.txt"
        self.output = self.directory / "candidate"

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "sanitize.py"), *map(str, args)],
                              env={**os.environ, "HOME": str(self.directory)}, text=True,
                              capture_output=True, timeout=10)

    def prepare(self, *args):
        return self.run_cli("sanitize", "--input", self.source, "--out-dir", self.output, *args)

    def test_preview_reports_three_changes_and_two_targeted_doubts_privately(self):
        lines = [f"普通记录 {i} 已处理" for i in range(1, 101)]
        lines[9] = "🧪联系：" + ALPHA
        lines[29] = "密码=" + CREDENTIAL
        lines[39] = "订单号: 523452; 日期 2026-11-22; 版本 1.2.3"
        lines[59] = "客户姓名：" + PERSON
        lines[79] = "收货地址：" + ADDRESS
        lines[94] = "联系：" + BETA
        self.source.write_bytes(("\r\n".join(lines) + "\r\n").encode())
        result = self.prepare("--preview")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["preview"], "review.html")
        review = self.output / "review.html"
        html = review.read_text()
        data = payload_from_html(html)
        self.assertEqual([(row["line"], row["kind"]) for row in data["changes"]],
                         [(10, "EMAIL"), (30, "SECRET"), (95, "EMAIL")])
        self.assertEqual([(row["line"], row["kind"]) for row in data["doubts"]],
                         [(60, "PERSON"), (80, "LOCATION")])
        candidate = (self.output / "sanitized.txt").read_bytes()
        self.assertEqual([candidate.decode()[row["start"]:row["end"]] for row in data["doubts"]],
                         [PERSON, ADDRESS])
        report = (self.output / "report.json").read_text()
        self.assertEqual(data["hash"], json.loads(report)["output_sha256"])
        for raw in (ALPHA, BETA, CREDENTIAL, PERSON, ADDRESS, self.source.name,
                    str(self.directory), lines[0], lines[39]):
            self.assertNotIn(raw, html + report + result.stdout + result.stderr)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(review.stat().st_mode & 0o777, 0o600)
        self.output = self.directory / "candidate-without-preview"
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "sanitized.txt").read_bytes(), candidate)
        self.assertFalse((self.output / "review.html").exists())

    def test_configured_categories_keep_high_sensitivity_and_reuse_choices_for_check(self):
        entities = self.directory / "entities.local.json"
        self.source.write_text(f"{PERSON} {ADDRESS} {ALPHA} 密码={CREDENTIAL} SENSITIVE_PROJECT_NAME\n")
        entities.write_text(json.dumps({"entities": [
            {"type": "PERSON", "values": [PERSON]}, {"type": "LOCATION", "values": [ADDRESS]},
            {"type": "SENSITIVE", "values": ["SENSITIVE_PROJECT_NAME"]},
        ]}))
        self.default_policy.parent.mkdir(parents=True)
        self.default_policy.write_text('{"ordinary_types":["PERSON"]}')
        result = self.prepare("--policy", entities, "--preview")
        self.assertEqual(result.returncode, 0, result.stderr)
        candidate = self.output / "sanitized.txt"
        self.assertEqual(candidate.read_text(),
                         f"[PERSON_001] {ADDRESS} [EMAIL_001] 密码=[SECRET_001] [SENSITIVE_001]\n")
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["ordinary_types"], ["PERSON"])
        result = self.run_cli("check", "--input", candidate, "--policy", entities)
        self.assertEqual(result.returncode, 0, result.stderr)
        override = self.directory / "override.local.json"
        override.write_text('{"ordinary_types":["PERSON","LOCATION"]}')
        result = self.run_cli("check", "--input", candidate, "--policy", entities, "--review-policy", override)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["occurrences"], {"LOCATION": 1})

    def test_invalid_policy_cannot_disable_high_sensitivity_or_publish_a_bundle(self):
        self.source.write_text(ALPHA)
        override = self.directory / "override.local.json"
        override.write_text('{"ordinary_types":["EMAIL"]}')
        result = self.prepare("--review-policy", override, "--preview")
        self.assertEqual(result.returncode, 2)
        self.assertIn("INVALID_REVIEW_POLICY", result.stderr)
        self.assertNotIn(ALPHA, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_clean_preview_is_empty_and_check_does_not_make_a_bundle(self):
        self.source.write_text("公开文档 https://docs.python.org/3/library/pathlib.html\n")
        result = self.prepare("--preview")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = payload_from_html((self.output / "review.html").read_text())
        self.assertEqual((data["changes"], data["doubts"]), ([], []))
        result = self.run_cli("check", "--preview", "--input", self.source)
        self.assertEqual(result.returncode, 2)
        self.assertIn("INVALID_ARGUMENTS", result.stderr)

    def test_failure_to_write_preview_rolls_back_the_entire_bundle(self):
        actual_open = os.open

        def fail_preview(path, *args, **kwargs):
            if path == "review.html":
                raise OSError("synthetic preview write failure")
            return actual_open(path, *args, **kwargs)

        with mock.patch("os.open", side_effect=fail_preview):
            with self.assertRaises(OSError):
                write_bundle(self.output, "fictional candidate", {}, preview="<html></html>")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
