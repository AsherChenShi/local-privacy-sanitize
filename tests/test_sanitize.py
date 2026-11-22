"""All names, addresses, account numbers and credentials here are synthetic."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sanitize.py"
spec = importlib.util.spec_from_file_location("sanitizer", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def policy(groups):
    return module.parse_policy(json.dumps({"entities": groups}, ensure_ascii=False))


class RedactionTests(unittest.TestCase):
    def test_aliases_and_distinct_people(self):
        entities = policy([{"type": "PERSON", "values": ["陈岚", "小陈"]},
                           {"type": "PERSON", "values": ["赵明"]}])
        result, report = module.sanitize("陈岚向赵明汇报。小陈不负责审批。", entities)
        self.assertEqual(result, "[PERSON_001]向[PERSON_002]汇报。[PERSON_001]不负责审批。")
        self.assertEqual(report["occurrences"], {"PERSON": 3})

    def test_full_synthetic_example_matches_reviewed_fixture(self):
        entities = module.parse_policy((ROOT / "examples/entities.example.json").read_text())
        source = (ROOT / "examples/input.example.txt").read_text()
        expected = (ROOT / "examples/output.expected.txt").read_text()
        self.assertEqual(module.sanitize(source, entities)[0], expected)

    def test_preserves_task_facts(self):
        facts = "2026年11月1日发现3个高危漏洞，11月8日修复2个，仍有1个未修复；预算100000元，使用25000元，占25%。"
        result, _ = module.sanitize("陈岚：" + facts, policy([{"type": "PERSON", "values": ["陈岚"]}]))
        self.assertEqual(result, "[PERSON_001]：" + facts)

    def test_phone_variants_share_identity(self):
        result, report = module.sanitize("13800000000；+86 138-0000-0000；１３８\u200b００００００００")
        self.assertEqual(result, "[PHONE_001]；[PHONE_001]；[PHONE_001]")
        self.assertGreater(report["normalization"]["fullwidth_ascii"], 0)

    def test_email_with_sentence_punctuation(self):
        result, _ = module.sanitize("Email demo@example.com. Next: demo@example.com，完。")
        self.assertNotIn("demo@", result)
        self.assertEqual(result.count("[EMAIL_001]"), 2)

    def test_email_local_case_is_not_conflated(self):
        result, _ = module.sanitize("Demo@example.com demo@example.com Demo@EXAMPLE.COM")
        self.assertEqual(result, "[EMAIL_001] [EMAIL_002] [EMAIL_001]")

    def test_url_credentials_removed_as_one_span(self):
        result, _ = module.sanitize("服务https://u:DEMO@example.com/p?token=DEMO_ONLY，连接正常")
        self.assertEqual(result, "服务[URL_001]，连接正常")

    def test_database_dsn(self):
        result, _ = module.sanitize("postgresql://demo:DEMO_ONLY@db.example.com:5432/private")
        self.assertEqual(result, "[URL_001]")

    def test_secret_formats(self):
        values = ["sk-" + "a" * 24, "ghp_" + "b" * 32,
                  "AKIA" + "A" * 16, "eyJkZW1v" + ".YWJj.ZGVm"]
        for value in values:
            with self.subTest(format=value[:4]):
                result, _ = module.sanitize(value)
                self.assertEqual(result, "[SECRET_001]")

    def test_labeled_and_bearer_credentials(self):
        for source in ("password='DEMO_ONLY'", '"api_key": "DEMO_ONLY"',
                       "密码：DEMO_ONLY", "Authorization: Bearer DEMO_ONLY"):
            with self.subTest(source=source):
                result, _ = module.sanitize(source)
                self.assertNotIn("DEMO_ONLY", result)
                self.assertIn("[SECRET_001]", result)

    def test_explicit_environment_and_http_credentials_are_fully_removed(self):
        for source, label in (
            ("SERVICE_TOKEN=DEMO_ONLY", "SERVICE_TOKEN="),
            ("Authorization: Basic DEMO_ONLY", "Authorization: "),
            ("Set-Cookie: session=DEMO_ONLY; refresh=DEMO_MORE", "Set-Cookie: "),
        ):
            with self.subTest(label=label):
                result, report = module.sanitize(source)
                self.assertEqual(result, label + "[SECRET_001]")
                self.assertEqual(report["occurrences"], {"SECRET": 1})

    def test_structured_scanner_checks_fields_even_after_json_decoding(self):
        escaped = r'{"\u0061ccess_token":"DEMO_ONLY"}'
        self.assertEqual(module.scan_kind(escaped), "SECRET")
        self.assertEqual(module.scan_kind({"stdout": escaped}), "SECRET")
        self.assertEqual(module.scan_kind({"ＡＰＩＫｅｙ": "DEMO_ONLY"}), "SECRET")
        self.assertEqual(module.scan_kind({"password": 0}), "SECRET")
        self.assertIsNone(module.scan_kind({"token_count": 1200, "access_token": None}))
        self.assertIsNone(module.scan_kind({"access_token": "[SECRET_001]", "password": " "}))
        with self.assertRaisesRegex(module.Rejected, "RESIDUAL_KNOWN_MATCH"):
            module.sanitize(escaped)
        with self.assertRaisesRegex(module.Rejected, "DUPLICATE_JSON_KEY"):
            module.scan_kind('{"Authorization":"Basic DEMO_ONLY","Authorization":""}')

    def test_multiline_private_key(self):
        source = "before\n-----BEGIN PRIVATE KEY-----\nDEMO_ONLY\n-----END PRIVATE KEY-----\nafter"
        self.assertEqual(module.sanitize(source)[0], "before\n[SECRET_001]\nafter")

    def test_truncated_private_key_blocks(self):
        with self.assertRaises(module.Rejected):
            module.sanitize("-----BEGIN PRIVATE KEY-----\nDEMO_ONLY")

    def test_quoted_secret_with_spaces_and_escaped_quotes(self):
        for source in ('password="DEMO ONLY SECRET"', "密码='DEMO ONLY SECRET'",
                       'password="DEMO \\"ONLY\\" SECRET"'):
            result, _ = module.sanitize(source)
            self.assertNotIn("DEMO", result)
            self.assertNotIn("SECRET\"", result)
            self.assertIn("[SECRET_001]", result)

    def test_incomplete_quoted_secret_blocks(self):
        with self.assertRaises(module.Rejected):
            module.sanitize('password="DEMO ONLY SECRET')

    def test_url_query_punctuation_is_not_left_visible(self):
        result, _ = module.sanitize("https://example.com/?token=DEMO,ONLY;SECRET，结束")
        self.assertEqual(result, "[URL_001]，结束")

    def test_match_limit_blocks_instead_of_partial_processing(self):
        with mock.patch.object(module, "MAX_MATCHES", 2):
            with self.assertRaises(module.Rejected):
                module.sanitize("a@example.com b@example.com c@example.com")

    def test_detection_normalization_preserves_unmatched_original(self):
        result, _ = module.sanitize("ＡＢＣ：１３８\u200b００００００００；预算１０００元。")
        self.assertEqual(result, "ＡＢＣ：[PHONE_001]；预算１０００元。")

    def test_obfuscated_unicode_email(self):
        result, _ = module.sanitize("邮箱ｄｅｍｏ＠ｅｘａｍｐｌｅ．ｃｏｍ。")
        self.assertEqual(result, "邮箱[EMAIL_001]。")

    def test_ids_and_card(self):
        source = "110101199001010000；123-45-6789；4111 1111 1111 1111；工号：EMP_DEMO"
        result, _ = module.sanitize(source)
        for value in ("110101", "123-45", "4111", "EMP_DEMO"):
            self.assertNotIn(value, result)
        for kind in ("CNID", "SSN", "CARD", "ACCOUNT"):
            self.assertIn("[" + kind + "_001]", result)

    def test_ips_and_sentence_punctuation(self):
        result, _ = module.sanitize("192.0.2.10. 地址2001:db8::1，回环::1，时间12:30:00")
        for value in ("192.0.2.10", "2001:db8::1", "::1"):
            self.assertNotIn(value, result)
        self.assertIn("12:30:00", result)

    def test_nested_alias_does_not_leave_email_suffix(self):
        entities = policy([{"type": "PERSON", "values": ["demo"]}])
        self.assertEqual(module.sanitize("demo@example.com", entities)[0], "[EMAIL_001]")

    def test_partially_overlapping_literals_mask_entire_union(self):
        entities = policy([{"type": "PERSON", "values": ["abc"]},
                           {"type": "ORG", "values": ["bcd"]}])
        self.assertEqual(module.sanitize("abcd!", entities)[0], "[SENSITIVE_001]!")

    def test_no_original_values_or_mapping_in_report(self):
        source = "陈岚 demo@example.com"
        _, report = module.sanitize(source, policy([{"type": "PERSON", "values": ["陈岚"]}]))
        encoded = json.dumps(report, ensure_ascii=False)
        for value in ("陈岚", "demo@example.com", "mapping"):
            self.assertNotIn(value, encoded)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_unconfigured_names_remain_and_are_never_claimed_safe(self):
        result, report = module.sanitize("虚构人员陈岚在示例企业工作。")
        self.assertIn("陈岚", result)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertIn("UNCONFIGURED_NAMES_AND_CONTEXT_MAY_REMAIN", report["warnings"])

    def test_empty_and_non_sensitive_text(self):
        for text in ("", "修复率为75%，仍有2项待办。", "Revenue was 1000, expense was 200."):
            self.assertEqual(module.sanitize(text)[0], text)

    def test_reserved_placeholders_cannot_spoof_redaction(self):
        with self.assertRaises(module.Rejected):
            module.sanitize("[PERSON_001] 加原文")

    def test_bidi_and_nul_block(self):
        for value in ("abc\x00def", "abc\u202edef"):
            with self.assertRaises(module.Rejected):
                module.sanitize(value)

    def test_no_network_is_required(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network used")):
            result, _ = module.sanitize("demo@example.com")
        self.assertEqual(result, "[EMAIL_001]")

    def test_token_registry_does_not_survive_between_documents(self):
        first = module.sanitize("a@example.com")[0]
        second = module.sanitize("b@example.com")[0]
        self.assertEqual(first, second)


class PolicyTests(unittest.TestCase):
    def test_invalid_schema_blocks(self):
        cases = ["[]", "{}", '{"entities": [], "allow": true}',
                 '{"entities": [], "entities": []}',
                 json.dumps({"entities": [{"type": "CUSTOM_PRIVATE_VALUE", "values": ["demo"]}]}),
                 json.dumps({"entities": [{"type": "PERSON", "values": ["a"]}]}),
                 json.dumps({"entities": [{"type": "PERSON", "values": ["demo", "demo"]}]}),
                 json.dumps({"entities": [{"type": "PERSON", "values": "demo"}]}),
                 json.dumps({"entities": [{"type": "PERSON", "values": [12]}]})]
        for data in cases:
            with self.subTest(case=data):
                with self.assertRaises(module.Rejected):
                    module.parse_policy(data)

    def test_normalized_alias_collisions_block(self):
        with self.assertRaises(module.Rejected):
            policy([{"type": "PERSON", "values": ["ＡＢ", "AB"]}])

    def test_explicit_literals_are_not_executed_as_regex(self):
        entities = policy([{"type": "PROJECT", "values": ["A+B"]}])
        self.assertEqual(module.sanitize("A+B;AAAB", entities)[0], "[PROJECT_001];AAAB")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.txt"
        self.source.write_text("demo@example.com", encoding="utf-8")
        self.out = self.root / "bundle"

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              text=True, capture_output=True, timeout=10)

    def prepare(self, *args):
        return self.run_cli("sanitize", "--input", self.source, "--out-dir", self.out, *args)

    def test_prepare_writes_private_bundle_and_safe_stdout(self):
        run = self.prepare()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("demo@example.com", run.stdout + run.stderr)
        self.assertNotIn(str(self.source), run.stdout + run.stderr)
        self.assertEqual(json.loads(run.stdout)["status"], "REVIEW_REQUIRED")
        self.assertEqual((self.out / "sanitized.txt").read_text(), "[EMAIL_001]")
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        for path in self.out.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["report.json", "sanitized.txt"])

    def test_existing_output_is_not_overwritten(self):
        self.out.mkdir()
        original = self.out / "sanitized.txt"
        original.write_text("keep")
        self.assertEqual(self.prepare().returncode, 2)
        self.assertEqual(original.read_text(), "keep")

    def test_unsupported_file_type(self):
        self.source = self.root / "private.pdf"
        self.source.write_bytes(b"%PDF DEMO_ONLY")
        self.assertEqual(self.prepare().returncode, 2)
        self.assertFalse(self.out.exists())

    def test_invalid_utf8_blocks_without_output(self):
        self.source.write_bytes(b"\xff\xfe")
        self.assertEqual(self.prepare().returncode, 2)
        self.assertFalse(self.out.exists())

    def test_oversized_input_blocks(self):
        self.source.write_bytes(b"x" * (module.MAX_BYTES + 1))
        self.assertEqual(self.prepare().returncode, 2)
        self.assertFalse(self.out.exists())

    def test_input_symlink_blocks(self):
        link = self.root / "link.txt"
        link.symlink_to(self.source)
        self.source = link
        self.assertEqual(self.prepare().returncode, 2)
        self.assertFalse(self.out.exists())

    def test_output_symlink_blocks(self):
        other = self.root / "other"
        other.mkdir()
        self.out.symlink_to(other, target_is_directory=True)
        self.assertEqual(self.prepare().returncode, 2)
        self.assertEqual(list(other.iterdir()), [])

    def test_fifo_is_not_read_or_blocked_on(self):
        self.source.unlink()
        os.mkfifo(self.source)
        self.assertEqual(self.prepare().returncode, 2)

    def test_invalid_policy_never_echoes_private_values(self):
        config = self.root / "private.json"
        config.write_text('{"PRIVATE_DEMO_VALUE": "PRIVATE_DEMO_VALUE"}')
        run = self.prepare("--policy", config)
        self.assertEqual(run.returncode, 2)
        self.assertNotIn("PRIVATE_DEMO_VALUE", run.stderr)
        self.assertFalse(self.out.exists())

    def test_unknown_cli_argument_is_not_echoed(self):
        run = self.prepare("--PRIVATE_DEMO_VALUE")
        self.assertEqual(run.returncode, 2)
        self.assertNotIn("PRIVATE_DEMO_VALUE", run.stdout + run.stderr)

    def test_check_finds_raw_information(self):
        run = self.run_cli("check", "--input", self.source)
        self.assertEqual(run.returncode, 3)
        self.assertNotIn("demo@example.com", run.stdout)

    def test_check_after_prepare_still_requires_review(self):
        self.assertEqual(self.prepare().returncode, 0)
        run = self.run_cli("check", "--input", self.out / "sanitized.txt")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)["review_required"])

    def test_check_does_not_hide_phone_inside_forged_placeholder(self):
        self.source.write_text("[PHONE_13800000000]")
        self.assertEqual(self.run_cli("check", "--input", self.source).returncode, 3)

    def test_output_hash_binds_exact_candidate(self):
        self.assertEqual(self.prepare().returncode, 0)
        report = json.loads((self.out / "report.json").read_text())
        data = (self.out / "sanitized.txt").read_bytes()
        self.assertEqual(report["output_sha256"], module.hashlib.sha256(data).hexdigest())

    def test_truncated_key_has_no_partial_output(self):
        self.source.write_text("-----BEGIN RSA PRIVATE KEY-----\nDEMO_ONLY")
        self.assertEqual(self.prepare().returncode, 2)
        self.assertFalse(self.out.exists())

    def test_partial_write_is_cleaned_up(self):
        original_open = os.open
        def failing_open(path, *args, **kwargs):
            if path == "report.json":
                raise OSError("PRIVATE_DEMO_VALUE")
            return original_open(path, *args, **kwargs)
        with mock.patch.object(module.os, "open", side_effect=failing_open):
            with self.assertRaises(OSError):
                module.write_bundle(self.out, "candidate", {})
        self.assertFalse(self.out.exists())

    def test_detected_residual_prevents_bundle_creation(self):
        matches = [module.Match(0, 2, "PERSON", "demo")]
        with mock.patch.object(module, "find_matches", side_effect=[[], matches]):
            with self.assertRaises(module.Rejected):
                module.sanitize("safe")

    def test_empty_and_missing_input_are_distinct(self):
        self.source.write_text("")
        self.assertEqual(self.prepare().returncode, 0)
        self.source.unlink()
        run = self.run_cli("check", "--input", self.source)
        self.assertEqual(run.returncode, 2)

    def test_diagnostic_suppresses_unexpected_exception_values(self):
        error_output = io.StringIO()
        with mock.patch.object(module, "read_local", side_effect=RuntimeError("PRIVATE_DEMO_VALUE")):
            with contextlib.redirect_stderr(error_output):
                result = module.main(["check", "--input", str(self.source)])
        self.assertEqual(result, 2)
        self.assertNotIn("PRIVATE_DEMO_VALUE", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
