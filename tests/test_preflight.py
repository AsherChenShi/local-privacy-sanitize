"""Exercise the preflight window's shared checks and HTTP trust boundary."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import sys
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from preflight import MAX_BYTES, MAX_REQUEST, PreflightServer, policy_state, prepare, save_policy
    from review_policy import ORDINARY_TYPES, default_policy_path
    from sanitize import Rejected
finally:
    sys.path.pop(0)


EMAIL = "preflight-canary@example.invalid"
PUBLIC_URL = "https://github.com/AsherChenShi/local-privacy-sanitize"


def payload(text, fmt="text", dictionary="builtin"):
    return {"text": text, "format": fmt, "dictionary": dictionary}


class PrepareTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        home = patch("preflight.Path.home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)

    def test_clean_text_is_unchanged_and_still_requires_review(self):
        source = f"正常请求\n{PUBLIC_URL}"
        result = prepare(payload(source))
        self.assertEqual(result["candidate"], source)
        self.assertEqual(result["occurrences"], {})
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertFalse(list(self.home.iterdir()))

    def test_preserves_json_and_markdown_and_reports_locations_without_values(self):
        source = f'{{\r\n  "邮箱": "{EMAIL}", "recipient": "虚构姓名", "count": 2\r\n}}'
        result = prepare(payload(source, "json"))
        self.assertEqual(result["candidate"], source.replace(EMAIL, "[EMAIL_001]"))
        self.assertEqual(result["artifact"], "sanitized.json")
        self.assertEqual(json.loads(result["candidate"])["count"], 2)
        self.assertEqual(result["changes"][0]["line"], 2)
        self.assertEqual(result["doubts"][0]["line"], 2)
        metadata = json.dumps({key: value for key, value in result.items() if key != "candidate"}, ensure_ascii=False)
        self.assertNotIn(EMAIL, metadata)
        self.assertNotIn("虚构姓名", metadata)
        source = f"| contact |\r\n| --- |\r\n| {EMAIL} |\r\n\r\n```json\r\n{{\"count\": 2}}\r\n```\r\n"
        result = prepare(payload(source, "markdown"))
        self.assertEqual(result["candidate"], source.replace(EMAIL, "[EMAIL_001]"))
        self.assertEqual(result["artifact"], "sanitized.md")

    def test_custom_host_dictionaries_and_shared_type_selection(self):
        for host, setting in (("codex", "CODEX_HOME"), ("claude", "CLAUDE_CONFIG_DIR")):
            folder = self.home / host
            policy = folder / "local-privacy-sanitize/entities.local.json"
            policy.parent.mkdir(parents=True)
            policy.write_text('{"entities":[{"type":"PERSON","values":["虚构姓名"]},'
                              '{"type":"SENSITIVE","values":["虚构机密"]}]}', encoding="utf-8")
            source = f"虚构姓名 / 虚构机密 / {EMAIL}"
            with self.subTest(host=host), patch.dict("os.environ", {setting: str(folder)}):
                choices = self.home / ".config/local-privacy-sanitize/review-policy.local.json"
                choices.parent.mkdir(parents=True, exist_ok=True)
                choices.write_text('{"ordinary_types":[]}')
                self.assertEqual(prepare(payload(source, dictionary=host))["candidate"],
                                 "虚构姓名 / [SENSITIVE_001] / [EMAIL_001]")
                choices.unlink()
                self.assertEqual(prepare(payload(source, dictionary=host))["candidate"],
                                 "[PERSON_001] / [SENSITIVE_001] / [EMAIL_001]")
                policy.unlink()
                with self.assertRaisesRegex(Rejected, "DICTIONARY_NOT_FOUND"):
                    prepare(payload(source, dictionary=host))

    def test_failures_do_not_downgrade_or_emit_a_candidate(self):
        for request, code in ((payload("  "), "EMPTY_INPUT"), (payload("密" * (MAX_BYTES // 3 + 1)), "FILE_TOO_LARGE"),
                              (payload("x", dictionary="/private/values.json"), "INVALID_REQUEST"),
                              (payload('{"password":123}', "json"), "SENSITIVE_NON_STRING_JSON_VALUE")):
            with self.subTest(code=code), self.assertRaisesRegex(Rejected, code):
                prepare(request)
        policy = self.home / ".config/local-privacy-sanitize/review-policy.local.json"
        policy.parent.mkdir(parents=True)
        policy.write_text('{"ordinary_types":["EMAIL"]}')
        with self.assertRaisesRegex(Rejected, "INVALID_REVIEW_POLICY"):
            prepare(payload(EMAIL))

    def test_long_review_is_bounded(self):
        result = prepare(payload((EMAIL + "\n") * 30))
        self.assertEqual(result["change_count"], 30)
        self.assertEqual(len(result["changes"]), 20)
        self.assertEqual(result["candidate"].count("[EMAIL_001]"), 30)

    def test_policy_save_validates_permissions_and_rejects_stale_edits(self):
        previous = policy_state({})["ordinary_types"]
        self.assertEqual(set(previous), ORDINARY_TYPES)
        self.assertFalse(default_policy_path().exists())
        self.assertEqual(save_policy({"previous": previous, "ordinary_types": ["LOCATION"]}),
                         {"ordinary_types": ["LOCATION"]})
        path = default_policy_path()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        for selected, code in ((["EMAIL"], "INVALID_REVIEW_POLICY"), (["ORG", "ORG"], "INVALID_REVIEW_POLICY"),
                               (["PROJECT"], "REVIEW_POLICY_CHANGED")):
            with self.subTest(selected=selected), self.assertRaisesRegex(Rejected, code):
                save_policy({"previous": previous, "ordinary_types": selected})
        self.assertEqual(policy_state({}), {"ordinary_types": ["LOCATION"]})
        with patch("preflight.os.replace", side_effect=OSError("test write failure")), self.assertRaises(OSError):
            save_policy({"previous": ["LOCATION"], "ordinary_types": ["ORG"]})
        self.assertFalse(list(path.parent.glob(".review-policy-*")))
        self.assertEqual(policy_state({}), {"ordinary_types": ["LOCATION"]})

    def test_save_preserves_existing_invalid_or_symlinked_policy(self):
        path = default_policy_path()
        path.parent.mkdir(parents=True)
        path.write_text('{"some_existing_setting":true}')
        data = {"previous": sorted(ORDINARY_TYPES), "ordinary_types": []}
        with self.assertRaisesRegex(Rejected, "INVALID_REVIEW_POLICY"):
            save_policy(data)
        self.assertEqual(path.read_text(), '{"some_existing_setting":true}')
        path.unlink()
        external = self.home / "unrelated.json"
        external.write_text('{"ordinary_types":[]}')
        path.symlink_to(external)
        with self.assertRaisesRegex(Rejected, "INVALID_REVIEW_POLICY"):
            save_policy(data)
        self.assertTrue(path.is_symlink())
        self.assertEqual(external.read_text(), '{"ordinary_types":[]}')

    def test_both_prompt_hooks_read_the_saved_policy_with_high_sensitivity_enforced(self):
        for host, env_name, args in (("codex", "CODEX_HOME", ["plugin-hook", "UserPromptSubmit"]),
                                    ("claude", "CLAUDE_CONFIG_DIR", ["UserPromptSubmit"])):
            root = self.home / host
            entities = root / "local-privacy-sanitize/entities.local.json"
            entities.parent.mkdir(parents=True)
            entities.write_text('{"entities":[{"type":"PERSON","values":["样本姓名"]}]}', encoding="utf8")
            for chosen, source, blocked in (([], "样本姓名", False), (["PERSON"], "样本姓名", True),
                                            ([], f"样本姓名 / {EMAIL}", True),
                                            ([], '{"idToken":"synthesized-token"}', True)):
                save_policy({"previous": policy_state({})["ordinary_types"], "ordinary_types": chosen})
                result = subprocess.run([sys.executable, str(SCRIPTS / (host + "_privacy.py")), *args],
                                        env={**os.environ, "HOME": str(self.home), env_name: str(root)},
                                        input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": source}),
                                        capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(bool(result.stdout), blocked, (host, chosen))
                if blocked:
                    self.assertEqual(json.loads(result.stdout)["decision"], "block")
                    self.assertNotIn(EMAIL, result.stdout + result.stderr)


class LoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = PreflightServer()
        cls.addClassCleanup(cls.server.server_close)
        thread = Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(cls.server.shutdown)

    def request(self, method, path, body=None, **overrides):
        headers = {"Host": self.server.authority, "Origin": self.server.origin,
                   "Content-Type": "application/json", "X-Preflight-Key": self.server.key, **overrides}
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=8)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.headers, response.read()
        finally:
            connection.close()

    def test_only_exact_static_routes_and_loopback_host(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, headers, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
        self.assertNotIn(self.server.key.encode(), page)
        self.assertEqual(self.request("GET", "/preflight.js")[0], 200)
        self.assertEqual(self.request("GET", "/../../.git/config")[0], 404)
        self.assertEqual(self.request("GET", "/", Host="rebind.invalid")[0], 404)

    def test_rejects_cross_origin_unkeyed_oversized_and_unexpected_inputs(self):
        body = json.dumps(payload(EMAIL))
        for overrides, expected in (({"Host": "rebind.invalid"}, 403), ({"Origin": "https://remote.invalid"}, 403),
                                    ({"X-Preflight-Key": "wrong"}, 403), ({"Content-Type": "text/plain"}, 400),
                                    ({"Content-Length": str(MAX_REQUEST + 1)}, 413)):
            with self.subTest(overrides=overrides):
                status, _, reply = self.request("POST", "/prepare", body, **overrides)
                self.assertEqual(status, expected)
                self.assertNotIn(EMAIL.encode(), reply)
        status, _, reply = self.request("POST", "/prepare", '{"text":"first","text":"second"}')
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(reply), {"code": "INVALID_REQUEST"})

    def test_success_and_parse_failure_return_fixed_responses(self):
        with patch("preflight.load_review_policy", return_value=frozenset()):
            status, _, reply = self.request("POST", "/prepare", json.dumps(payload(EMAIL)))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(reply)["candidate"], "[EMAIL_001]")
            status, _, reply = self.request("POST", "/prepare", json.dumps(payload(f'{{"{EMAIL}"', "json")))
            self.assertEqual(status, 422)
            self.assertNotIn(EMAIL.encode(), reply)
            self.assertNotIn("candidate", json.loads(reply))

    def test_policy_endpoints_require_same_origin_key_and_limit_request_shape(self):
        with TemporaryDirectory() as folder, patch("preflight.Path.home", return_value=Path(folder)):
            status, _, reply = self.request("POST", "/policy/read", "{}")
            self.assertEqual(status, 200)
            previous = json.loads(reply)["ordinary_types"]
            body = json.dumps({"ordinary_types": [], "previous": previous})
            self.assertEqual(self.request("POST", "/policy/save", body, Origin="https://remote.invalid")[0], 403)
            self.assertEqual(self.request("POST", "/policy/save", body, **{"X-Preflight-Key": "wrong"})[0], 403)
            self.assertEqual(self.request("POST", "/policy/save", body, **{"Content-Length": "4097"})[0], 413)
            self.assertFalse(default_policy_path().exists())
            status, _, reply = self.request("POST", "/policy/save", body)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(reply), {"ordinary_types": []})
            status, _, reply = self.request("POST", "/policy/save", body)
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(reply), {"code": "REVIEW_POLICY_CHANGED"})
            self.assertEqual(self.request("POST", "/policy/read", json.dumps({"path": "config.json"}))[0], 422)
            def save_new_selection(kind):
                data = json.dumps({"ordinary_types": [kind], "previous": []})
                status, _, reply = self.request("POST", "/policy/save", data)
                return status, json.loads(reply)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = sorted(pool.map(save_new_selection, ("ORG", "LOCATION")))
            self.assertEqual([status for status, _ in results], [200, 409])
            self.assertEqual(policy_state({}), results[0][1])


if __name__ == "__main__":
    unittest.main()
