"""Exercise the read-only desktop plugin report against synthetic local metadata."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/privacy_status.py"
CODEX = "codex-privacy@local-privacy-tools"
CLAUDE = "claude-privacy@local-privacy-tools"
PRIVATE = "NOT_TO_BE_PRINTED_TEST_FIXTURE"


class PrivacyStatusTests(unittest.TestCase):
    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.root = Path(storage.name)
        self.config = self.root / "config"
        self.project = self.root / "project"
        self.project.mkdir()

    def write(self, relative, data):
        file = self.root / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return file

    def snapshot(self):
        return {
            path.relative_to(self.root): (path.stat().st_mtime_ns, path.read_bytes())
            for path in self.root.rglob("*") if path.is_file()
        }

    def status(self, host, *options, config_arg=True):
        args = [sys.executable, str(SCRIPT), host, "--project", str(self.project)]
        if config_arg:
            args.extend(("--config-dir", str(self.config)))
        before = self.snapshot()
        report = subprocess.run(
            [*args, *options], text=True, capture_output=True, timeout=6, check=True,
            env={**os.environ, "CODEX_HOME": str(self.config), "CLAUDE_CONFIG_DIR": str(self.config)},
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(report.stderr, "")
        self.assertNotIn(PRIVATE, report.stdout)
        self.assertNotIn(str(self.root), report.stdout)
        value = json.loads(report.stdout)
        self.assertEqual(value["host"], host)
        self.assertEqual(value["hook_execution"], "not_verified")
        self.assertIn("未受保护", value["message_zh"])
        self.assertIn("scripts/sanitize.py sanitize", value["local_preflight"])
        self.protection = value["protection_status"]
        self.assertIn("?token=SYNTHETIC_ONLY", value["verification"]["expect_block"])
        self.assertNotIn("?token=", value["verification"]["expect_pass"])
        return value["local_configuration"]

    def test_codex_lists_cache_switch_and_trust_separately(self):
        local_hash = "sha256:" + "e" * 64
        self.write("config/config.toml", f"""
[plugins."{CODEX}"]
enabled = true # separate from hook state
unused = "{PRIVATE}"
[hooks.state."{CODEX}:hooks/hooks.json:user_prompt_submit:0:0"]
enabled = false
trusted_content_hash = "{local_hash}"
[hooks.state."{CODEX}:hooks/hooks.json:post_tool_use:0:0"]
enabled = true
""")
        for version in ("0.2.1", "0.2.2"):
            self.write(
                f"config/plugins/cache/local-privacy-tools/codex-privacy/{version}/.codex-plugin/plugin.json",
                {"name": "codex-privacy", "version": version, "details": PRIVATE},
            )
        info = self.status("codex", config_arg=False)
        self.assertIs(info["configured_enabled"], True)
        self.assertEqual(info["local_plugin_cache"], {"versions": ["0.2.1", "0.2.2"], "status": "read"})
        self.assertEqual(info["hooks"]["UserPromptSubmit"], {
            "configured_enabled": False, "trust": "recorded_unverified",
        })
        self.assertEqual(info["hooks"]["PostToolUse"], {"configured_enabled": True, "trust": "unverified"})

    def test_codex_reports_hooks_off_and_does_not_assume_live_hooks_when_on(self):
        for configured, expected in (("false", "not_protected"), ("true", "unverified")):
            with self.subTest(configured=configured):
                self.write("config/config.toml", f'[features]\nhooks = {configured}\n[plugins."{CODEX}"]\nenabled = true\n')
                info = self.status("codex")
                self.assertIs(info["hooks_feature_enabled"], configured == "true")
                self.assertEqual(self.protection, expected)

    def test_codex_ignores_table_shaped_text_and_invalid_manifest_version(self):
        self.write("config/config.toml", f'''
config_note = """
[plugins."{CODEX}"]
enabled = true
"""
''')
        self.write(
            "config/plugins/cache/local-privacy-tools/codex-privacy/0.2.2/.codex-plugin/plugin.json",
            {"name": "codex-privacy", "version": PRIVATE},
        )
        info = self.status("codex")
        self.assertIsNone(info["configured_enabled"])
        self.assertEqual(info["local_plugin_cache"], {"versions": [], "status": "partial"})

    def test_claude_lists_scope_conflicts_and_runtime_capability(self):
        self.write("config/settings.json", {
            "enabledPlugins": {CLAUDE: False}, "credential": PRIVATE,
        })
        self.write("project/.claude/settings.json", {
            "enabledPlugins": {CLAUDE: True}, "disableAllHooks": True,
        })
        self.write("project/.claude/settings.local.json", {"enabledPlugins": {CLAUDE: False}})
        self.write("config/plugins/installed_plugins.json", {
            "version": 2,
            "plugins": {CLAUDE: [
                {"scope": "user", "version": "0.2.1", "installPath": PRIVATE},
                {"scope": "project", "version": "0.2.2", "projectPath": str(self.project)},
                {"scope": "project", "version": "9.9.9", "projectPath": str(self.root / PRIVATE)},
            ]},
        })
        info = self.status("claude", "--runtime-version", "2.1.222")
        self.assertEqual(info["install_registry"], {"metadata_status": "read", "entries": [
            {"scope": "project", "version": "0.2.2"},
            {"scope": "user", "version": "0.2.1"},
        ]})
        self.assertIs(info["settings"]["user"]["configured_enabled"], False)
        self.assertIs(info["settings"]["project"]["configured_enabled"], True)
        self.assertIs(info["settings"]["local"]["configured_enabled"], False)
        self.assertIs(info["settings"]["project"]["all_hooks_disabled"], True)
        self.assertEqual(info["hook_trust"], "unverified")
        self.assertEqual(info["command_hook_failure_blocking"], "below_documented_minimum")
        self.assertEqual(self.status("claude", "--runtime-version", "2.1.295")["command_hook_failure_blocking"],
                         "documented_supported")

    def test_reports_unreadable_or_missing_without_guessing_switch(self):
        self.write("config/settings.json", f'{{"enabledPlugins":{{"{CLAUDE}":true,"{CLAUDE}":false}},'
                   f'"unrelated":"{PRIVATE}"}}')
        info = self.status("claude", config_arg=False)
        self.assertEqual(info["settings"]["user"]["metadata_status"], "unreadable")
        self.assertIsNone(info["settings"]["user"]["configured_enabled"])
        self.assertEqual(info["install_registry"], {"metadata_status": "missing", "entries": []})
        self.assertEqual(info["command_hook_failure_blocking"], "unknown")
        info = self.status("codex")
        self.assertEqual(info["metadata_status"], "missing")
        self.assertIsNone(info["configured_enabled"])


if __name__ == "__main__":
    unittest.main()
