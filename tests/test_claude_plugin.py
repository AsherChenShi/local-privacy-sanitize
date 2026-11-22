import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CANARY = "claude-plugin-canary@example.invalid"
BASH_OUTPUT = {"stdout": "three services are healthy", "stderr": "",
               "interrupted": False, "isImage": False}


class ClaudePluginTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="claude plugin ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.marketplace = self.root / "test-marketplace"
        self.config_dir = self.root / "config"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/build_claude_plugin.py"), str(self.marketplace)],
            check=True, timeout=10,
        )
        catalog = json.loads((self.marketplace / ".claude-plugin/marketplace.json").read_text())
        entry = next(item for item in catalog["plugins"] if item["name"] == "claude-privacy")
        self.plugin = self.marketplace / entry["source"]
        self.manifest = json.loads((self.plugin / ".claude-plugin/plugin.json").read_text())
        self.hooks = json.loads((self.plugin / "hooks/hooks.json").read_text())["hooks"]

    def invoke(self, event, payload, *, tool_name=None):
        matching = [
            group for group in self.hooks[event]
            if group.get("matcher", "") in ("", "*")
            or (tool_name and re.search(group["matcher"], tool_name))
        ]
        self.assertEqual(len(matching), 1, "expected exactly one Hook registration")
        [definition] = matching[0]["hooks"]
        self.assertEqual(definition["type"], "command")
        env = {
            **os.environ,
            "CLAUDE_PLUGIN_ROOT": str(self.plugin),
            "CLAUDE_PLUGIN_DATA": str(self.root / "plugin-data"),
            "CLAUDE_CONFIG_DIR": str(self.config_dir),
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        }
        if "args" in definition:
            argv = [definition["command"], *definition["args"]]
            argv = [arg.replace("${CLAUDE_PLUGIN_ROOT}", str(self.plugin)) for arg in argv]
        else:
            argv = ["/bin/sh", "-c", definition["command"]]
        data = payload if isinstance(payload, str) else json.dumps(payload)
        result = subprocess.run(
            argv, env=env, input=data, text=True, encoding="utf-8",
            capture_output=True, cwd=self.root, check=True, timeout=10,
        )
        self.assertFalse(CANARY in result.stdout or CANARY in result.stderr,
                         "the Hook re-emitted the canary")
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout) if result.stdout else None

    def submit(self, prompt):
        return self.invoke("UserPromptSubmit", {"hook_event_name": "UserPromptSubmit", "prompt": prompt})

    def tool_result(self, tool_name, response):
        result = self.invoke("PostToolUse", {
            "hook_event_name": "PostToolUse",
            "tool_name": tool_name,
            "tool_response": response,
        }, tool_name=tool_name)
        return self.replacement(result)

    def replacement(self, result):
        if result is None:
            return None
        output = result["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PostToolUse")
        self.assertIn("updatedToolOutput", output,
                      "Claude receives original tool output if Hook returns only a block decision")
        return output["updatedToolOutput"]

    def test_plugin_archive_is_self_contained(self):
        self.assertEqual(self.manifest["name"], "claude-privacy")
        expected = {
            ".claude-plugin/marketplace.json",
            "plugins/claude-privacy/.claude-plugin/plugin.json",
            "plugins/claude-privacy/hooks/hooks.json",
            "plugins/claude-privacy/scripts/claude_privacy.py",
            "plugins/claude-privacy/scripts/hook_supervisor.py",
            "plugins/claude-privacy/scripts/sanitize.py",
            "plugins/claude-privacy/scripts/structured_redaction.py",
            "plugins/claude-privacy/scripts/privacy_status.py",
        }
        with zipfile.ZipFile(self.marketplace.with_suffix(".zip")) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(set(archive.namelist()), {
                str(Path(self.marketplace.name) / relative) for relative in expected
            })
            for name in archive.namelist():
                self.assertEqual(archive.read(name), (self.root / name).read_bytes())

    def test_packaged_status_does_not_create_configuration(self):
        result = subprocess.run([sys.executable, str(self.plugin / "scripts/privacy_status.py"),
                                 "claude", "--config-dir", str(self.config_dir), "--project", str(self.root)],
                                check=True, timeout=10, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["hook_execution"], "not_verified")
        self.assertFalse(self.config_dir.exists())

    def test_prompt_detections_and_clean_prompt(self):
        blocked = self.submit("Contact " + CANARY)
        self.assertEqual(blocked["decision"], "block")
        self.assertIn("[EMAIL]", blocked["reason"])
        self.assertIs(blocked["hookSpecificOutput"]["suppressOriginalPrompt"], True)
        self.assertIsNone(self.submit("List two ways to check a service."))
        self.assertIsNone(self.submit("Contact [EMAIL_001]."))

    def test_malformed_prompt_events_block_without_raw_output(self):
        samples = (
            "{",
            {"hook_event_name": "UserPromptSubmit"},
            {"hook_event_name": "UserPromptSubmit", "prompt": None},
            {"hook_event_name": "PostToolUse", "prompt": CANARY},
        )
        for index, payload in enumerate(samples):
            with self.subTest(index=index):
                result = self.invoke("UserPromptSubmit", payload)
                self.assertEqual(result["decision"], "block")
                self.assertIsInstance(result["reason"], str)

    def test_local_dictionary_applies_when_loaded_by_plugin(self):
        policy = self.config_dir / "local-privacy-sanitize/entities.local.json"
        policy.parent.mkdir(parents=True)
        policy.write_text(json.dumps({"entities": [{"type": "PERSON", "values": ["Lan Yu"]}]}))
        result = self.submit("Summarize Lan Yu's sample work.")
        self.assertEqual(result["decision"], "block")
        self.assertNotIn("Lan Yu", result["reason"])

    def test_bash_replaces_both_channels_with_valid_tool_shape(self):
        for field in ("stdout", "stderr"):
            with self.subTest(field=field):
                output = self.tool_result("Bash", {**BASH_OUTPUT, field: CANARY})
                self.assertEqual(set(output), set(BASH_OUTPUT))
                self.assertIsInstance(output["stdout"], str)
                self.assertIsInstance(output["stderr"], str)
                self.assertIsInstance(output["interrupted"], bool)
                self.assertIs(output["isImage"], False)
                self.assertTrue(output["stdout"] or output["stderr"])

    def test_clean_bash_output_passes_through(self):
        self.assertIsNone(self.tool_result("Bash", BASH_OUTPUT))

    def test_bash_image_is_not_treated_as_clean_text(self):
        output = self.tool_result("Bash", {
            **BASH_OUTPUT, "stdout": "ZHVtbXk=", "isImage": True,
        })
        self.assertIs(output["isImage"], False)
        self.assertNotIn("ZHVtbXk=", json.dumps(output))

    def test_malformed_bash_event_gets_bash_shaped_replacement(self):
        output = self.replacement(self.invoke("PostToolUse", "{", tool_name="Bash"))
        self.assertEqual(set(output), set(BASH_OUTPUT))
        self.assertIs(output["isImage"], False)

    def test_mcp_replacement_preserves_supported_container_shape(self):
        items = [{"type": "text", "text": CANARY}, {"type": "text", "text": "reason"}]
        examples = (CANARY, items, {"content": items, "structuredContent": {"field": CANARY}})
        for sample in examples:
            with self.subTest(shape=type(sample).__name__):
                output = self.tool_result("mcp__test__sample", sample)
                self.assertIsInstance(output, type(sample))
                if isinstance(output, dict):
                    self.assertIsInstance(output["content"], list)
                    output = output["content"]
                if isinstance(output, list):
                    self.assertTrue(output)
                    self.assertEqual(output[0]["type"], "text")
                    self.assertIsInstance(output[0]["text"], str)
                self.assertNotIn("reason", json.dumps(output))

    def test_clean_mcp_output_passes_through(self):
        self.assertIsNone(self.tool_result("mcp__test__sample", {
            "content": [{"type": "text", "text": "Three active public projects."}],
            "structuredContent": {"projects": 3},
        }))

    def test_mcp_replaces_structured_credentials_without_echo(self):
        canary = "SYNTHETIC_OPAQUE_VALUE"
        for fields in (
            {"credentials": {"password": canary}},
            {"headers": {"Set-Cookie": ["session=" + canary]}},
        ):
            with self.subTest(fields=list(fields)):
                response = {"content": [{"type": "text", "text": "Build finished."}],
                            "structuredContent": fields}
                output = self.tool_result("mcp__test__sample", response)
                self.assertIsInstance(output["content"], list)
                self.assertNotIn(canary, json.dumps(output))
                self.assertNotIn("structuredContent", output)
        self.assertIsNone(self.tool_result("mcp__test__sample", {
            "structuredContent": {"token_count": 1200, "authorization_required": False},
        }))

    def test_mcp_uninspectable_content_is_replaced(self):
        for item in (
            {"type": "resource_link", "uri": "file:///test/SYNTHETIC_PATH"},
            {"type": "binary", "data": "SYNTHETIC_DATA"},
            {"type": "unknown", "text": "SYNTHETIC_UNKNOWN"},
            {"type": "text", "text": {"value": "SYNTHETIC_BAD_TEXT"}},
        ):
            with self.subTest(kind=item["type"]):
                output = self.tool_result("mcp__test__sample", {"content": [item]})
                self.assertEqual(output["content"][0]["type"], "text")
                self.assertNotIn("SYNTHETIC_", json.dumps(output))

    def test_read_known_text_shape_filters_sensitive_and_allows_clean(self):
        file = {"filePath": "test.txt", "numLines": 1, "startLine": 7, "totalLines": 9}
        clean = {"type": "text", "file": {**file, "content": "a clean text file"}}
        self.assertIsNone(self.tool_result("Read", clean))
        output = self.tool_result("Read", {"type": "text", "file": {**file, "content": CANARY}})
        self.assertEqual(output["type"], "text")
        self.assertEqual(set(output["file"]), set(clean["file"]))
        self.assertIn("Privacy check blocked", output["file"]["content"])
        self.assertNotIn(CANARY, json.dumps(output))

    def test_read_unknown_shape_warns_without_claiming_a_replacement(self):
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Read",
                   "tool_response": {"type": "image", "bytes": "SYNTHETIC_ONLY"}}
        output = self.invoke("PostToolUse", payload, tool_name="Read")
        self.assertNotIn("hookSpecificOutput", output)
        self.assertIn("replacement could not be verified", output["systemMessage"])
        self.assertNotIn("SYNTHETIC_ONLY", json.dumps(output))

    def test_opt_in_protected_read_roots_match_direct_path_and_symlink(self):
        protected = self.root / "protected"
        protected.mkdir()
        child = protected / "file.txt"
        child.write_text("synthetic content", encoding="utf-8")
        alias = self.root / "alias"
        alias.symlink_to(protected, target_is_directory=True)

        def read(path):
            return self.invoke("PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Read",
                                              "tool_input": {"file_path": str(path)}}, tool_name="Read")

        self.assertIsNone(read(child))
        policy = self.config_dir / "local-privacy-sanitize/protected_read_roots.local.json"
        policy.parent.mkdir(parents=True)
        policy.write_text(json.dumps({"roots": [str(protected)]}), encoding="utf-8")
        self.assertIsNone(read(self.root / "protected-similar" / "file.txt"))
        for candidate in (child, alias / child.name):
            with self.subTest(candidate=candidate.name):
                decision = read(candidate)["hookSpecificOutput"]
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertIn("configured protected path", decision["permissionDecisionReason"])

    def test_unreadable_protected_read_policy_denies_read(self):
        policy = self.config_dir / "local-privacy-sanitize/protected_read_roots.local.json"
        policy.parent.mkdir(parents=True)
        policy.write_text('{"roots":[],"roots":[]}', encoding="utf-8")
        result = self.invoke("PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Read",
                                            "tool_input": {"file_path": str(self.root / "sample.txt")}},
                             tool_name="Read")
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
