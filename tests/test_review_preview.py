"""Validate only synthetic metadata, with optional runtime testing of the browser page."""

import base64
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from review_preview import ORDINARY_TYPES, render_preview
finally:
    sys.path.pop(0)


CHANGE = {"line": 8, "column": 3, "start": 37, "end": 47, "kind": "EMAIL", "marker": "[EMAIL_001]"}
DOUBT = {"line": 9, "column": 5, "start": 54, "end": 67, "kind": "LOCATION",
         "reason": "UNMASKED_LABELED_VALUE"}
HASH = hashlib.sha256("synthetic candidate".encode("utf-8")).hexdigest()
UNTRUSTED = '</script><img src="https://example.invalid/leak">SYNTHETIC-PRIVATE-VALUE'


class CapturePage(HTMLParser):
    def __init__(self, page):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.policy = ""
        self.data = ""
        self.style = ""
        self.reading = None
        self.tags = []
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.policy = attrs["content"]
        if tag == "script":
            self.reading = "data" if attrs.get("id") == "review-data" else "script"
        elif tag == "style":
            self.reading = "style"

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.reading = None

    def handle_data(self, data):
        if self.reading == "data":
            self.data += data
        elif self.reading == "style":
            self.style += data
        elif self.reading == "script":
            self.scripts.append(data)


class ReviewPreviewTests(unittest.TestCase):
    def test_page_contains_derived_positions_only(self):
        page = render_preview([CHANGE], [DOUBT], HASH, ORDINARY_TYPES)
        parsed = CapturePage(page)
        data = json.loads(parsed.data)
        self.assertEqual(data["changes"], [CHANGE])
        self.assertEqual(data["doubts"], [DOUBT])
        self.assertEqual(data["hash"], HASH)
        self.assertNotIn("synthetic candidate", page)
        self.assertIn("待核对 1 项 · 已替换 1 项", page)
        self.assertIn("选择脱敏副本", page)

    def test_source_text_and_untrusted_metadata_are_rejected_without_echo(self):
        for changes, doubts, digest, ordinary in (
            ([{**CHANGE, "raw": UNTRUSTED}], [], HASH, ORDINARY_TYPES),
            ([{**CHANGE, "kind": UNTRUSTED}], [], HASH, ORDINARY_TYPES),
            ([{**CHANGE, "column": UNTRUSTED}], [], HASH, ORDINARY_TYPES),
            ([{**CHANGE, "marker": UNTRUSTED}], [], HASH, ORDINARY_TYPES),
            ([{**CHANGE, "marker": "[PHONE_001]"}], [], HASH, ORDINARY_TYPES),
            ([], [{**DOUBT, "reason": UNTRUSTED}], HASH, ORDINARY_TYPES),
            ([], [{**DOUBT, "path": "/Users/test/private.txt"}], HASH, ORDINARY_TYPES),
            ([], [], UNTRUSTED, ORDINARY_TYPES),
            ([], [], HASH, [UNTRUSTED]),
        ):
            with self.subTest(changes=bool(changes), doubts=bool(doubts)), self.assertRaisesRegex(
                ValueError, "^INVALID_REVIEW_METADATA$"
            ):
                render_preview(changes, doubts, digest, ordinary)

    def test_page_policy_limits_resources_to_the_bundled_script_and_style(self):
        parsed = CapturePage(render_preview([CHANGE], [DOUBT], HASH, ORDINARY_TYPES))
        self.assertIn("default-src 'none'", parsed.policy)
        self.assertIn("connect-src 'none'", parsed.policy)
        self.assertIn("form-action 'none'", parsed.policy)
        self.assertEqual(len(parsed.scripts), 1)
        for code in (parsed.style, parsed.scripts[0]):
            digest = base64.b64encode(hashlib.sha256(code.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", parsed.policy)
        for _, attrs in parsed.tags:
            self.assertFalse({"src", "href", "srcset", "action"} & attrs.keys())
            self.assertFalse(any(key.startswith("on") for key in attrs))
        javascript = parsed.scripts[0]
        for method in ("innerHTML", "outerHTML", "XMLHttpRequest", "fetch(", "localStorage",
                       "sessionStorage", "navigator.clipboard", "sendBeacon"):
            self.assertNotIn(method, javascript)
        self.assertIn("context.textContent = content.join", javascript)
        self.assertLess(javascript.index("if (hash !== data.hash)"), javascript.index("points = verified"))

    def test_empty_and_policy_summary_do_not_create_per_row_doubts(self):
        page = render_preview([], [], HASH, ["PERSON", "PROJECT"])
        self.assertIn("待核对 0 项 · 已替换 0 项", page)
        self.assertIn("未发现当前规则定义的疑点", page)
        self.assertIn("普通敏感中未选择替换的类型：组织、地址", page)
        self.assertEqual(json.loads(CapturePage(page).data)["doubts"], [])


if __name__ == "__main__":
    unittest.main()
