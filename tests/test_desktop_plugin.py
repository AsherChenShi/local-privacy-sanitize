import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CANARY = "desktop-test@example.invalid"


class DesktopPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="privacy plugin ")
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        cls.market = cls.root / "marketplace"
        subprocess.run([sys.executable, str(ROOT / "scripts/build_codex_plugin.py"),
                        str(cls.market)], check=True, timeout=10)
        market = json.loads((cls.market / ".agents/plugins/marketplace.json").read_text())
        entry = market["plugins"][0]
        cls.plugin = cls.market / entry["source"]["path"]
        cls.manifest = json.loads((cls.plugin / ".codex-plugin/plugin.json").read_text())
        if entry["name"] != cls.manifest["name"]:
            raise ValueError("Plugin name differs from marketplace entry")
        cls.hooks = json.loads((cls.plugin / cls.manifest["hooks"]).read_text())["hooks"]

    def call_hook(self, event, **fields):
        definition = self.hooks[event][0]["hooks"][0]
        result = subprocess.run(
            ["/bin/sh", "-c", definition["command"]],
            env={**os.environ, "CODEX_HOME": str(self.root / "codex"),
                 "PLUGIN_ROOT": str(self.plugin),
                 "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]},
            input=json.dumps({"hook_event_name": event, **fields}), text=True,
            capture_output=True, check=True, timeout=10,
        )
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def test_manifest_hooks_run_from_packaged_copy(self):
        for event, field in (("UserPromptSubmit", "prompt"), ("PostToolUse", "tool_response")):
            with self.subTest(event=event):
                self.assertEqual(self.call_hook(event, **{field: CANARY})["decision"], "block")
                self.assertIsNone(self.call_hook(event, **{field: "合成安全文本"}))

    def test_plugin_switch_is_independent_of_old_terminal_mode(self):
        state = self.root / "codex/local-privacy-sanitize/mode.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text('{"mode":"off"}')
        self.assertEqual(self.call_hook("UserPromptSubmit", prompt=CANARY)["decision"], "block")
        self.assertEqual(json.loads(state.read_text()), {"mode": "off"})

    def test_zip_contains_only_expected_local_plugin_files(self):
        with zipfile.ZipFile(self.market.with_suffix(".zip")) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(set(archive.namelist()), {
                "marketplace/.agents/plugins/marketplace.json",
                "marketplace/plugins/codex-privacy/.codex-plugin/plugin.json",
                "marketplace/plugins/codex-privacy/hooks/hooks.json",
                "marketplace/plugins/codex-privacy/scripts/codex_privacy.py",
                "marketplace/plugins/codex-privacy/scripts/sanitize.py",
                "marketplace/plugins/codex-privacy/scripts/privacy_status.py",
                "marketplace/plugins/codex-privacy/scripts/hook_supervisor.py",
                "marketplace/plugins/codex-privacy/scripts/structured_redaction.py",
                "marketplace/plugins/codex-privacy/scripts/review_policy.py",
                "marketplace/plugins/codex-privacy/scripts/review_preview.py",
                "marketplace/plugins/codex-privacy/scripts/signup_broker.py",
                "marketplace/plugins/codex-privacy/scripts/signup_browser.py",
                "marketplace/plugins/codex-privacy/scripts/signup_local.py",
                "marketplace/plugins/codex-privacy/scripts/signup_mcp.py",
            })
            for name in archive.namelist():
                self.assertEqual(archive.read(name), (self.root / name).read_bytes())

    def test_packaged_status_does_not_create_configuration(self):
        config = self.root / "missing-config"
        result = subprocess.run([sys.executable, str(self.plugin / "scripts/privacy_status.py"),
                                 "codex", "--config-dir", str(config)],
                                check=True, timeout=10, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["hook_execution"], "not_verified")
        self.assertFalse(config.exists())


if __name__ == "__main__":
    unittest.main()
