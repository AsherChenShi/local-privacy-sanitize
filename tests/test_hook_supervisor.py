import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANARY = "synthetic-timeout-test@example.invalid"
ENTRY = 'if __name__ == "__main__":\n'


class WorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="privacy-worker-test-")
        self.addCleanup(temporary.cleanup)
        self.scripts = Path(temporary.name) / "scripts"
        shutil.copytree(ROOT / "scripts", self.scripts, ignore=shutil.ignore_patterns("__pycache__"))
        supervisor = self.scripts / "hook_supervisor.py"
        source = supervisor.read_text(encoding="utf-8")
        self.assertIn("WORKER_TIMEOUT_SECONDS = 6", source)
        supervisor.write_text(source.replace("WORKER_TIMEOUT_SECONDS = 6", "WORKER_TIMEOUT_SECONDS = 0.8"),
                              encoding="utf-8")

    def inject(self, script, command):
        source = (ROOT / "scripts" / script).read_text(encoding="utf-8")
        self.assertIn(ENTRY, source)
        injected = ENTRY + '    if "--worker" in sys.argv:\n        ' + command + "\n"
        (self.scripts / script).write_text(source.replace(ENTRY, injected), encoding="utf-8")

    def invoke(self, script, args, event):
        result = subprocess.run([sys.executable, str(self.scripts / script), *args], input=json.dumps(event),
                                text=True, encoding="utf-8", capture_output=True, timeout=5, check=True)
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout) if result.stdout else None

    def test_both_adapters_allow_clean_input_and_block_failed_workers(self):
        event = {"hook_event_name": "UserPromptSubmit", "prompt": "A clean control."}
        cases = (
            ("codex_privacy.py", ["plugin-hook", "UserPromptSubmit"], "本地隐私检查超时"),
            ("claude_privacy.py", ["UserPromptSubmit"], "Privacy check timed out"),
        )
        for script, args, timeout_notice in cases:
            self.assertIsNone(self.invoke(script, args, event))
            for problem, command in (
                ("timeout", 'emit_shape("prompt"); import time; time.sleep(30)'),
                ("crash", 'raise RuntimeError(sys.stdin.read())'),
                ("invalid reply", 'emit_shape("prompt"); print(sys.stdin.read()); sys.exit(0)'),
            ):
                with self.subTest(script=script, problem=problem):
                    self.inject(script, command)
                    verdict = self.invoke(script, args, {**event, "prompt": CANARY})
                    self.assertEqual(verdict["decision"], "block")
                    if problem == "timeout":
                        self.assertIn(timeout_notice, verdict["reason"])

    def test_timed_out_known_claude_mcp_result_keeps_shaped_replacement(self):
        script = "claude_privacy.py"
        self.inject(script, 'emit_shape("mcp_object"); import time; time.sleep(30)')
        event = {"hook_event_name": "PostToolUse", "tool_name": "mcp__test__sample",
                 "tool_response": {"content": [{"type": "text", "text": CANARY}]}}
        decision = self.invoke(script, ["PostToolUse", "mcp"], event)
        replacement = decision["hookSpecificOutput"]["updatedToolOutput"]
        self.assertIn("Privacy check timed out", replacement["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
