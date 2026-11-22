"""Behavioral checks for the shared URL policy using public examples and synthetic secrets."""

import importlib.util
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sanitize.py"
SPEC = importlib.util.spec_from_file_location("public_url_sanitizer", SCRIPT)
SANITIZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SANITIZER
sys.path.insert(0, str(SCRIPT.parent))
try:
    SPEC.loader.exec_module(SANITIZER)
finally:
    sys.path.pop(0)

REPO = "https://github.com/octocat/Hello-World"
API = "https://api.github.com/repos/octocat/Hello-World"
DOCS = "https://learn.chatgpt.com/docs/hooks"
FIXTURE = "SYNTHETIC_ONLY"


class PublicURLTests(unittest.TestCase):
    def assert_preserved(self, source):
        candidate, report = SANITIZER.sanitize(source)
        self.assertEqual(candidate, source)
        self.assertEqual(report["occurrences"], {})
        self.assertFalse(SANITIZER.scan_value({"content": [{"text": source}]}))

    def assert_redacted(self, url):
        self.assertTrue(SANITIZER.scan_value({"content": [{"text": url}]}))
        candidate, _ = SANITIZER.sanitize(f"打开 {url} 继续。")
        self.assertEqual(candidate, "打开 [URL_001] 继续。")

    def test_github_links_are_unchanged(self):
        sha = "d4a5" * 10
        for url in (
            REPO,
            f"{REPO}/blob/master/README#L1",
            f"{REPO}/actions/runs/45003806479",
            f"{REPO}?tab=readme-ov-file",
            f"{API}/actions/runs?head_sha={sha}&per_page=3",
            "https://raw.githubusercontent.com/octocat/Hello-World/master/README",
            "https://docs.github.com/en/rest/actions/workflow-runs",
        ):
            with self.subTest(url=url):
                self.assert_preserved(url)

    def test_official_documentation_links_are_unchanged(self):
        for url in (
            f"{DOCS}#userpromptsubmit",
            f"{DOCS}?surface=app&site_variant=chatgpt",
            "https://developers.openai.com/api/docs/guides/streaming-responses",
            "https://platform.openai.com/docs/api-reference/responses/create",
            "https://code.claude.com/docs/en/hooks#posttooluse",
            "https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit",
            "https://learn.microsoft.com/zh-cn/dotnet/api/system.uri?view=net-9.0",
        ):
            with self.subTest(url=url):
                self.assert_preserved(url)

    def test_public_links_in_punctuation_and_markdown(self):
        self.assert_preserved(f"查看[仓库]({REPO})。详见 <{DOCS}#userpromptsubmit>。")
        self.assert_preserved(f"Use `{REPO}` and `{DOCS}`.")

    def test_markdown_link_structure_survives_url_redaction(self):
        source = ("See [build](https://ci.internal.test/foo(bar))"
                  "[repo](https://github.com/octocat/Hello-World?token=SYNTHETIC_ONLY).")
        candidate, report = SANITIZER.sanitize(source)
        self.assertEqual(candidate, "See [build]([URL_001])[repo]([URL_002]).")
        self.assertEqual(report["occurrences"], {"URL": 2})
        self.assertTrue(SANITIZER.scan_value(source))

    def test_only_the_workflow_run_id_avoids_the_phone_rule(self):
        run_id = "13800138000"
        for url in (f"{REPO}/actions/runs/{run_id}", f"{API}/actions/runs/{run_id}"):
            with self.subTest(url=url):
                self.assert_preserved(url)
                source = f"查看[构建]({url})，值班电话 {run_id}。"
                candidate, report = SANITIZER.sanitize(source)
                self.assertEqual(candidate, f"查看[构建]({url})，值班电话 [PHONE_001]。")
                self.assertEqual(report["occurrences"], {"PHONE": 1})
                self.assert_redacted(f"{url}?token={FIXTURE}")
                self.assert_redacted(f"{url}?X-Amz-Signature={FIXTURE}")
                policy = (SANITIZER.Entity("SENSITIVE", (run_id,)),)
                self.assertTrue(SANITIZER.scan_value(url, policy))
        self.assertTrue(SANITIZER.scan_value(f"{REPO}/blob/main/{run_id}"))
        self.assertTrue(SANITIZER.scan_value(f"{REPO}/actions/runs/{run_id}/custom/data"))
        self.assert_redacted(f"https://intranet.test/actions/runs/{run_id}")

    def test_encoded_pii_inside_otherwise_public_links_is_redacted(self):
        encoded_phone = "".join(f"%{ord(digit):02X}" for digit in "13800138000")
        for url in (
            f"https://docs.github.com/en/reference/{encoded_phone}",
            f"{DOCS}#contact-{encoded_phone}",
            f"{DOCS}?view={encoded_phone}",
            f"{DOCS}?view=10%2E20%2E30%2E40",
        ):
            with self.subTest(url=url):
                self.assert_redacted(url)
        self.assert_preserved("https://docs.github.com/zh-CN/actions/%E6%A6%82%E8%A7%88")

    def test_ordinary_github_api_response_metadata_is_not_blocked(self):
        metadata = {
            "html_url": REPO,
            "url": API,
            "owner": {"avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4"},
            "git_refs_url": API + "/git/refs{/sha}",
            "git_commits_url": API + "/git/commits{/sha}",
        }
        self.assertFalse(SANITIZER.scan_value(metadata))
        for url in (
            metadata["owner"]["avatar_url"],
            metadata["git_refs_url"],
            metadata["git_commits_url"],
        ):
            with self.subTest(url=url):
                self.assert_preserved(url)

    def test_access_parameters_and_signatures_on_public_hosts_stay_blocked(self):
        for suffix in (
            f"?token={FIXTURE}",
            f"?ACCESS_TOKEN={FIXTURE}",
            f"?%61ccess%5ftoken={FIXTURE}",
            f"?signature={FIXTURE}",
            f"?X-Amz-Signature={FIXTURE}",
            f"?X-Goog-Signature={FIXTURE}",
            f"?sig={FIXTURE}",
            f"?tab=readme-ov-file&token={FIXTURE}",
            f"#access_token={FIXTURE}",
            f"#%61ccess_token%3d{FIXTURE}",
        ):
            with self.subTest(suffix=suffix):
                self.assert_redacted(REPO + suffix)

    def test_unknown_and_ambiguous_parameters_stay_blocked(self):
        for url in (
            f"{REPO}?unknown_parameter={FIXTURE}",
            f"{API}/actions/runs?per_page=3%26token%3D{FIXTURE}",
            f"{API}/actions/runs?per_page=3%2526token%253D{FIXTURE}",
            f"{API}/actions/runs?per_page=3;token={FIXTURE}",
            f"{DOCS}?locale=zh-CN;surface=app",
            REPO + "?redirect=https%3A%2F%2Fintranet.test%2Fdetails",
            REPO + "?tab=readme-ov-file&tab=other",
            f"{API}/git/refs{{/sha}}?token={FIXTURE}",
            f"https://avatars.githubusercontent.com/u/583231?v=4&sig={FIXTURE}",
        ):
            with self.subTest(url=url):
                self.assert_redacted(url)

    def test_protected_github_routes_stay_blocked(self):
        for url in (
            "https://github.com/login",
            "https://github.com/login/oauth/authorize",
            f"{REPO}/settings/secrets/actions",
            f"{API}/actions/secrets",
            f"{API}/actions/secrets/EXAMPLE",
        ):
            with self.subTest(url=url):
                self.assert_redacted(url)

    def test_unrecognized_and_internal_destinations_stay_blocked(self):
        for url in (
            f"https://demo:{FIXTURE}@github.com/octocat/Hello-World",
            "https://github.com@intranet.test/octocat/Hello-World",
            "https://github.com.intranet.test/octocat/Hello-World",
            "https://github.com:8443/octocat/Hello-World",
            "http://github.com/octocat/Hello-World",
            "https://docs.example.invalid/quickstart",
            "http://localhost:8080/manage",
            "https://10.20.30.40/console",
            "http://[::1]:8080/manage",
            "https://staff.corp.test/ops",
            "ssh://github.com/octocat/Hello-World",
        ):
            with self.subTest(url=url):
                self.assert_redacted(url)

    def test_credentials_in_a_link_path_stay_blocked(self):
        for path_segment in ("ghp_" + "x" * 24, "%67hp%5F" + "%78" * 24, f"token/{FIXTURE}"):
            with self.subTest(path_segment=path_segment):
                self.assert_redacted(f"{REPO}/blob/main/{path_segment}")

    def test_credentials_and_pii_elsewhere_are_still_detected(self):
        token = "ghp_" + "x" * 24
        for value in (
            {"href": REPO, "description": f"Credential: {token}"},
            {"href": DOCS, "origin": "operator@example.invalid"},
        ):
            with self.subTest(value=value):
                self.assertTrue(SANITIZER.scan_value(value))
        result, _ = SANITIZER.sanitize(f"参考 {DOCS}，请勿分享 {token}。")
        self.assertIn(DOCS, result)
        self.assertNotIn(token, result)

    def test_safe_link_classification_needs_no_network(self):
        with mock.patch.multiple(
            socket,
            getaddrinfo=mock.Mock(side_effect=AssertionError("unexpected DNS")),
            socket=mock.Mock(side_effect=AssertionError("unexpected socket")),
        ):
            self.assert_preserved(f"{REPO}/issues/42")
            self.assert_redacted(f"{REPO}?sig={FIXTURE}")


if __name__ == "__main__":
    unittest.main()
