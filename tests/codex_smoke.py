"""Exercise Codex and the installed hooks against a loopback Responses endpoint."""

import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/codex_privacy.py"
PROMPT_CANARY = "prompt-canary@example.invalid"
TOOL_CANARY = "tool-canary@example.invalid"
BLOCK_REASON = "检测到敏感信息。请在本地生成并复核脱敏副本，再重试。"


def events(index, invoke_tool):
    response = {"id": f"resp_demo_{index}", "status": "completed",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    yield {"type": "response.created", "response": {**response, "status": "in_progress"}}
    if invoke_tool:
        item = {
            "type": "function_call", "id": "fc_demo", "call_id": "call_demo",
            "name": "exec_command", "arguments": json.dumps({"cmd": "cat fixture.txt"}),
        }
        yield {"type": "response.output_item.added", "output_index": 0, "item": item}
    else:
        item = {"type": "message", "id": "msg_demo", "role": "assistant", "content": [
            {"type": "output_text", "text": "SMOKE_OK", "annotations": []},
        ]}
        yield {"type": "response.output_text.delta", "item_id": item["id"],
               "output_index": 0, "content_index": 0, "delta": "SMOKE_OK"}
    yield {"type": "response.output_item.done", "output_index": 0, "item": item}
    yield {"type": "response.completed", "response": response}


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/v1/responses":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        request = json.loads(body)
        self.server.requests.append(request)
        index = len(self.server.requests)
        invoke_tool = self.server.test_tool and index == 1
        stream = b"".join(b"data: " + json.dumps(event).encode() + b"\n\n"
                          for event in events(index, invoke_tool))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(stream)))
        self.end_headers()
        self.wfile.write(stream)


def smoke(codex):
    with tempfile.TemporaryDirectory(prefix="privacy-codex-smoke-") as temporary:
        root = Path(temporary)
        config_dir = root / "codex"
        workspace = root / "workspace"
        config_dir.mkdir()
        workspace.mkdir()
        (workspace / "fixture.txt").write_text(TOOL_CANARY)
        with HTTPServer(("127.0.0.1", 0), Receiver) as server:
            (config_dir / "config.toml").write_text(
                'model = "gpt-5.4"\nmodel_provider = "mock"\nweb_search = "disabled"\n'
                'approval_policy = "never"\nsandbox_mode = "read-only"\n'
                '[analytics]\nenabled = false\n[features]\n'
                'apps = false\nplugins = false\nmemories = false\nhooks = true\n'
                'enable_request_compression = false\n'
                '[model_providers.mock]\nname = "Mock"\n'
                f'base_url = "http://127.0.0.1:{server.server_port}/v1"\n'
                'wire_api = "responses"\nrequires_openai_auth = false\n'
                'request_max_retries = 0\nstream_max_retries = 0\n'
            )
            control = [sys.executable, str(SCRIPT), "--config-dir", str(config_dir)]
            subprocess.run([*control, "install"], check=True, capture_output=True)
            assert all(str(SCRIPT) in group["hooks"][0]["command"] for groups in
                       json.loads((config_dir / "hooks.json").read_text())["hooks"].values()
                       for group in groups)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()

            # The temporary config contains only the hook this test just registered.
            # Accept it for this test process without changing real user trust.
            env = {"PATH": os.environ["PATH"], "CODEX_HOME": str(config_dir),
                   "LANG": "en_US.UTF-8", "TMPDIR": str(root)}
            def run(prompt, test_tool=False):
                server.requests = []
                server.test_tool = test_tool
                result = subprocess.run(
                    [codex, "exec", "--skip-git-repo-check", "--ephemeral", "--json",
                     "--dangerously-bypass-hook-trust", "--cd", str(workspace), prompt],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    encoding="utf-8", env=env, timeout=30,
                )
                return result, server.requests.copy()

            try:
                result, requests = run(PROMPT_CANARY)
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                assert PROMPT_CANARY in json.dumps(requests)
                subprocess.run([*control, "on"], check=True, capture_output=True)
                result, requests = run(PROMPT_CANARY)
                assert not requests, "The blocked prompt reached the model endpoint"
                result, requests = run("Please answer with a short greeting.")
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                draft = root / "draft.txt"
                draft.write_text("请分析来自 " + PROMPT_CANARY + " 的虚构消息。", encoding="utf-8")
                bundle = root / "candidate"
                subprocess.run(
                    [sys.executable, str(SCRIPT.with_name("sanitize.py")), "sanitize",
                     "--input", str(draft), "--out-dir", str(bundle)],
                    check=True, capture_output=True,
                )
                candidate = (bundle / "sanitized.txt").read_text(encoding="utf-8")
                result, requests = run(candidate)
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                model_input = json.dumps(requests, ensure_ascii=False)
                assert "[EMAIL_001] 的虚构消息" in model_input and PROMPT_CANARY not in model_input
                result, requests = run("Apply the local test now.", test_tool=True)
                assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                assert BLOCK_REASON in json.dumps(requests[-1], ensure_ascii=False)
                assert TOOL_CANARY not in json.dumps(requests)
                subprocess.run([*control, "off"], check=True, capture_output=True)
                result, requests = run("Apply the local test now.", test_tool=True)
                assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                assert TOOL_CANARY in json.dumps(requests[-1])
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    binaries = sys.argv[1:] or [shutil.which("codex")]
    for binary in binaries:
        if not binary:
            sys.exit("Codex CLI was not found. Pass its executable as an argument.")
        smoke(binary)
        print(f"PASS: {binary}: off forwards text, on blocks known values and allows sanitized text")
