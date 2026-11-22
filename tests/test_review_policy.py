"""Synthetic checks for reusable type selection and narrowly scoped review hints."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    import claude_privacy
    import codex_privacy
    from review_policy import (ORDINARY_TYPES, ReviewPolicyError, find_doubts,
                               load_review_policy, parse_review_policy, select_entities)
    from sanitize import Entity, read_local
finally:
    sys.path.pop(0)


class ReviewPolicyTests(unittest.TestCase):
    def test_category_allowlist_rejects_high_types_and_ambiguous_json(self):
        for value in ('{"ordinary_types":["SECRET"]}', '{"ordinary_types":["IP"]}',
                      '{"ordinary_types":{}}', '{"ordinary_types":["PERSON","PERSON"]}',
                      '{"ordinary_types":[],"ordinary_types":["PERSON"]}', '[]', '{"other":[]}'):
            with self.subTest(value=value), self.assertRaisesRegex(ReviewPolicyError, "INVALID_REVIEW_POLICY"):
                parse_review_policy(value)
        self.assertEqual(parse_review_policy('{"ordinary_types":[]}'), frozenset())
        self.assertEqual(parse_review_policy('{"ordinary_types":["PERSON","ORG"]}'), {"PERSON", "ORG"})

    def test_defaults_and_explicit_profile(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, "home", return_value=Path(directory)):
            self.assertEqual(load_review_policy(read_local=read_local), ORDINARY_TYPES)
            profile = Path(directory) / "specific.json"
            with self.assertRaises(ReviewPolicyError):
                load_review_policy(profile, read_local=read_local)
            profile.write_text('{"ordinary_types":["LOCATION"]}', encoding="utf-8")
            self.assertEqual(load_review_policy(profile, read_local=read_local), {"LOCATION"})
            self.assertEqual(load_review_policy(read_local=read_local), ORDINARY_TYPES)

    def test_ordinary_selection_never_removes_high_sensitivity_entities(self):
        person = Entity("PERSON", ("虚构个人甲",))
        project = Entity("PROJECT", ("虚构项目甲",))
        high = Entity("SENSITIVE", ("虚构绝密代号",))
        account = Entity("ACCOUNT", ("DEMO_ACCOUNT",))
        self.assertEqual(select_entities((person, project, high, account), {"PERSON"}), (person, high, account))

    def test_both_hook_checkers_share_the_profile_and_keep_high_rules(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, "home", return_value=Path(directory)):
            root = Path(directory)
            profile = root / ".config/local-privacy-sanitize/review-policy.local.json"
            profile.parent.mkdir(parents=True)
            local = root / "config"
            local.mkdir()
            (local / "entities.local.json").write_text(json.dumps({"entities": [
                {"type": "PERSON", "values": ["虚构联系对象"]},
                {"type": "SENSITIVE", "values": ["虚构绝密内容"]},
            ]}), encoding="utf-8")
            for text, expected in ((None, "PERSON"), ('{"ordinary_types":[]}', None),
                                   ('{"ordinary_types":["SECRET"]}', "PERSON")):
                if text:
                    profile.write_text(text, encoding="utf-8")
                cases = (("虚构联系对象", expected), ("虚构绝密内容", "SENSITIVE"),
                         ("access_token=SYNTHETIC_OPAQUE_ONLY", "SECRET"), ("普通聊天测试", None))
                for prompt, kind in cases:
                    event = {"hook_event_name": "UserPromptSubmit", "prompt": prompt}
                    with patch.object(codex_privacy, "read_hook_event", return_value=event):
                        result = codex_privacy.check_hook(local / "mode.json", "UserPromptSubmit",
                                                          controlled_by_plugin=True)
                        self.assertEqual(result, kind)
                    with patch.object(claude_privacy, "read_hook_event", return_value=event), \
                            patch.object(claude_privacy, "local_config", return_value=local), \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(claude_privacy.check_hook("UserPromptSubmit", None), kind)

    def test_doubts_skip_common_normal_text_and_already_masked_fields(self):
        normal = ("订单号：A-3012\r\n预算：1200\r\n版本：1.2.3.4\r\n"
                  "https://github.com/octocat/Hello-World\r\n联系人：[PERSON_001]\r\n"
                  "住址：未填写\r\n收货地址：—\r\n"
                  "会议安排已确认。\r\n内部项目: none\r\n")
        self.assertEqual(find_doubts(normal * 30, "text"), [])

    def test_doubts_only_store_candidate_coordinates_and_reason(self):
        candidate = "进度 🧪\r\n- **客户姓名**：虚构客户甲  \r\n住址：虚构演示路\r\n"
        doubts = find_doubts(candidate, "markdown")
        self.assertEqual([(row["line"], row["kind"], candidate[row["start"]:row["end"]]) for row in doubts],
                         [(2, "PERSON", "虚构客户甲"), (3, "LOCATION", "虚构演示路")])
        self.assertTrue(all(row["reason"] == "UNMASKED_LABELED_VALUE" for row in doubts))
        self.assertNotIn("虚构", json.dumps(doubts, ensure_ascii=False))

    def test_doubts_follow_json_and_bounded_markdown_fences(self):
        body = '{"客户姓名":"[PERSON_001]","住址":"虚构演示路","内部项目":"Example A"}'
        doc = "```text\n住址：普通说明样例\n```\n\n~~~json\n" + body + "\n~~~\n"
        self.assertEqual([entry["kind"] for entry in find_doubts(body, "json")], ["LOCATION", "PROJECT"])
        hints = find_doubts(doc, "markdown")
        self.assertEqual([(row["line"], row["kind"], doc[row["start"]:row["end"]]) for row in hints],
                         [(6, "LOCATION", "虚构演示路"), (6, "PROJECT", "Example A")])

    def test_grouped_same_line_doubt_masks_both_values(self):
        candidate = '{"客户姓名":"虚构甲","收件人":"虚构乙"}'
        [hint] = find_doubts(candidate, "json")
        masked = candidate[:hint["start"]] + "MASKED" + candidate[hint["end"]:]
        self.assertNotIn("虚构甲", masked)
        self.assertNotIn("虚构乙", masked)


if __name__ == "__main__":
    unittest.main()
