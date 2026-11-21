import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/codex_privacy.py"
PROMPT_EVENT = "UserPromptSubmit"
TOOL_EVENT = "PostToolUse"
CANARY = "privacy-test@example.invalid"


class PrivacyHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="privacy test ")
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name)
        self.hooks = self.config / "hooks.json"
        self.state = self.config / "local-privacy-sanitize/mode.json"

    def control(self, action, want_success=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--config-dir", str(self.config), action],
            text=True, capture_output=True, check=want_success, timeout=10,
        )
        return result

    def run_hook(self, event, payload):
        definition = json.loads(self.hooks.read_text())["hooks"][event][-1]["hooks"][0]
        data = payload if isinstance(payload, str) else json.dumps(payload)
        result = subprocess.run(
            shlex.split(definition["command"]), input=data, text=True,
            capture_output=True, check=True, timeout=10,
        )
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def prompt(self, value):
        return self.run_hook(PROMPT_EVENT, {"hook_event_name": PROMPT_EVENT, "prompt": value})

    def check_modes(self, send):
        self.control("install")
        self.assertIsNone(send())
        self.control("on")
        self.assertEqual(send()["decision"], "block")
        self.control("off")
        self.assertIsNone(send())

    def test_same_prompt_passes_off_and_blocks_on(self):
        self.check_modes(lambda: self.prompt(f"联系人是 {CANARY}"))

    def test_nested_tool_result_honors_same_switch(self):
        self.check_modes(lambda: self.run_hook(TOOL_EVENT, {
            "hook_event_name": TOOL_EVENT, "tool_response": {"content": [{"text": CANARY}]},
        }))

    def test_on_allows_clean_prompt_and_locally_sanitized_placeholder(self):
        self.control("install")
        self.control("on")
        self.assertIsNone(self.prompt("请评估成本和交付时间。"))
        self.assertIsNone(self.prompt("请联系 [EMAIL_001]。"))

    def test_local_entity_policy_is_used_without_echoing_the_value(self):
        self.control("install")
        alias = "虚构客户名称"
        self.state.with_name("entities.local.json").write_text(
            json.dumps({"entities": [{"type": "ORG", "values": [alias]}]}),
        )
        self.control("on")
        result = self.prompt(alias)
        self.assertEqual(result["decision"], "block")
        self.assertNotIn(alias, result["reason"])

    def test_preserves_other_hooks_and_mode_on_reinstall(self):
        unrelated = {"description": "Existing config", "hooks": {
            PROMPT_EVENT: [{"hooks": [{"type": "command", "command": "true"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "true"}]}],
        }}
        self.hooks.write_text(json.dumps(unrelated))
        self.control("install")
        self.control("on")
        installed = self.hooks.read_bytes()
        self.control("install")
        self.assertEqual(self.hooks.read_bytes(), installed)
        self.assertEqual(json.loads(self.control("status").stdout),
                         {"mode": "on", "hooks_registered": True})
        updated = json.loads(installed)
        self.assertEqual(updated["description"], unrelated["description"])
        self.assertEqual(updated["hooks"][PROMPT_EVENT][:-1], unrelated["hooks"][PROMPT_EVENT])
        self.assertEqual(updated["hooks"]["Stop"], unrelated["hooks"]["Stop"])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_on_requires_registration_and_invalid_config_is_preserved(self):
        self.assertNotEqual(self.control("on", want_success=False).returncode, 0)
        self.assertFalse(self.state.exists())
        self.hooks.write_text("invalid user settings")
        self.assertEqual(self.control("install", want_success=False).returncode, 2)
        self.assertEqual(self.hooks.read_text(), "invalid user settings")

    def test_user_modified_privacy_hook_is_not_overwritten(self):
        self.control("install")
        hooks = json.loads(self.hooks.read_text())
        hooks["hooks"][TOOL_EVENT][0]["hooks"][0]["command"] = "true"
        self.hooks.write_text(json.dumps(hooks))
        self.assertEqual(self.control("install", want_success=False).returncode, 2)
        self.assertEqual(self.control("on", want_success=False).returncode, 2)
        self.assertEqual(json.loads(self.hooks.read_text()), hooks)
        self.assertEqual(json.loads(self.control("off").stdout)["mode"], "off")

    def test_corrupt_policy_blocks_when_on_and_off_can_recover(self):
        self.control("install")
        self.control("on")
        self.state.with_name("entities.local.json").write_text("invalid private settings")
        self.assertEqual(self.prompt("普通文本")["decision"], "block")
        self.assertEqual(self.control("on", want_success=False).returncode, 2)
        self.control("off")
        self.assertIsNone(self.prompt(CANARY))

    def test_missing_or_corrupt_state_with_registered_hook_blocks(self):
        self.control("install")
        self.state.unlink()
        self.assertEqual(self.prompt("普通文本")["decision"], "block")
        self.state.write_text('{"mode":"unexpected"}')
        self.assertEqual(self.prompt("普通文本")["decision"], "block")

    def test_invalid_input_and_unsupported_tool_media_block(self):
        self.control("install")
        self.control("on")
        self.assertEqual(self.run_hook(PROMPT_EVENT, "not json")["decision"], "block")
        self.assertEqual(self.run_hook(PROMPT_EVENT, {
            "hook_event_name": PROMPT_EVENT, "prompt": ["not supported"],
        })["decision"], "block")
        self.assertEqual(self.run_hook(TOOL_EVENT, {
            "hook_event_name": TOOL_EVENT, "tool_response": {"content": [{"type": "image"}]},
        })["decision"], "block")

    def test_off_ignores_event_body_and_does_not_access_policy(self):
        self.control("install")
        os.mkfifo(self.state.with_name("entities.local.json"))
        self.assertIsNone(self.run_hook(PROMPT_EVENT, "not even JSON"))


if __name__ == "__main__":
    unittest.main()
