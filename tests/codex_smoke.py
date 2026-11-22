"""Exercise Codex and the installed hooks against a loopback Responses endpoint."""

import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from threading import Thread

from privacy_smoke_fixtures import CREDENTIAL_RESULT, MCP_SERVER, MCP_TOOL, METRIC_RESULT, OPAQUE_CREDENTIAL
from url_smoke_fixtures import PRIVILEGED_URL_CASES, PUBLIC_URL_FIXTURE, PUBLIC_URLS


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/codex_privacy.py"
PROMPT_CANARY = "prompt-canary@example.invalid"
TOOL_CANARY = "tool-canary@example.invalid"
BLOCK_REASON = "检测到敏感信息。请在本地生成并复核脱敏副本，再重试。"


def events(index, lane, tools):
    response = {"id": f"resp_demo_{index}", "status": "completed",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    yield {"type": "response.created", "response": {**response, "status": "in_progress"}}
    if lane:
        item = {
            "type": "function_call", "id": "fc_demo", "call_id": "call_demo",
            "name": "exec_command", "arguments": json.dumps({"cmd": "cat fixture.txt"}),
        }
        if lane == "mcp":
            namespace = f"mcp__{MCP_SERVER.replace('-', '_')}"
            namespaced = any(tool.get("type") == "namespace" and tool.get("name") == namespace
                             for tool in tools)
            item.update(name="sample" if namespaced else MCP_TOOL, arguments="{}")
            if namespaced:
                item["namespace"] = namespace
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
        lane = self.server.lane if index == 1 else None
        stream = b"".join(b"data: " + json.dumps(event).encode() + b"\n\n"
                          for event in events(index, lane, request.get("tools", [])))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(stream)))
        self.end_headers()
        self.wfile.write(stream)


def smoke(codex, *, plugin=False):
    with tempfile.TemporaryDirectory(prefix="privacy-codex-smoke-") as temporary:
        root = Path(temporary)
        config_dir = root / "codex"
        workspace = root / "workspace"
        config_dir.mkdir()
        workspace.mkdir()
        fixture = workspace / "fixture.txt"
        fixture.write_text(TOOL_CANARY, encoding="utf-8")
        mcp_stub = Path(__file__).resolve().with_name("privacy_smoke_fixtures.py")
        with HTTPServer(("127.0.0.1", 0), Receiver) as server:
            (config_dir / "config.toml").write_text(
                'model = "gpt-5.4"\nmodel_provider = "mock"\nweb_search = "disabled"\n'
                'approval_policy = "never"\nsandbox_mode = "read-only"\n'
                '[analytics]\nenabled = false\n[features]\n'
                f'apps = false\nplugins = {str(plugin).lower()}\nmemories = false\nhooks = true\n'
                'enable_request_compression = false\n'
                '[model_providers.mock]\nname = "Mock"\n'
                f'base_url = "http://127.0.0.1:{server.server_port}/v1"\n'
                'wire_api = "responses"\nrequires_openai_auth = false\n'
                'request_max_retries = 0\nstream_max_retries = 0\n'
                f'[mcp_servers."{MCP_SERVER}"]\ncommand = {json.dumps(sys.executable)}\n'
                f'args = {json.dumps([str(mcp_stub), str(fixture), "structured"], ensure_ascii=False)}\n'
                f'[mcp_servers."{MCP_SERVER}".tools.sample]\napproval_mode = "approve"\n'
            )
            env = {"PATH": os.environ["PATH"], "CODEX_HOME": str(config_dir),
                   "LANG": "en_US.UTF-8", "TMPDIR": str(root)}
            control = [sys.executable, str(SCRIPT), "--config-dir", str(config_dir)]
            if plugin:
                market = root / "local market"
                steps = [
                    [sys.executable, str(SCRIPT.with_name("build_codex_plugin.py")), str(market)],
                    [codex, "plugin", "marketplace", "add", str(market)],
                    [codex, "plugin", "add", "codex-privacy@local-privacy-tools"],
                ]
                for step in steps:
                    setup = subprocess.run(step, capture_output=True, text=True,
                                           cwd=workspace, env=env, timeout=30)
                    assert setup.returncode == 0, setup.stdout + setup.stderr
            else:
                subprocess.run([*control, "install"], check=True, capture_output=True)

            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            # Persist the same user-level setting as the desktop Plugins switch.
            def set_enabled(value):
                if plugin:
                    config = config_dir / "config.toml"
                    pattern = r'(\[plugins\."codex-privacy@local-privacy-tools"\]\s*\n\s*enabled\s*=\s*)(?:true|false)'
                    updated, count = re.subn(pattern, lambda match: match[1] + str(value).lower(),
                                             config.read_text())
                    assert count == 1, "Plugin install did not save the expected Codex setting"
                    config.write_text(updated)
                else:
                    subprocess.run([*control, "on" if value else "off"], check=True, capture_output=True)

            def run(prompt, lane=None):
                server.requests = []
                server.lane = lane
                # These hooks came from the package or handler built by this test.
                # Trust applies only to this isolated command and canary data.
                result = subprocess.run(
                    [codex, "exec", "--skip-git-repo-check", "--ephemeral", "--json",
                     "--dangerously-bypass-hook-trust", "--cd", str(workspace), prompt],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    encoding="utf-8", env=env, timeout=30,
                )
                return result, server.requests.copy()

            try:
                set_enabled(False)
                result, requests = run(PROMPT_CANARY)
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                assert PROMPT_CANARY in json.dumps(requests)
                set_enabled(True)
                result, requests = run(PROMPT_CANARY)
                assert not requests, "The blocked prompt reached the model endpoint"
                result, requests = run("Please answer with a short greeting.")
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                result, requests = run("Read these public references:\n" + PUBLIC_URL_FIXTURE)
                assert result.returncode == 0 and len(requests) == 1, result.stdout + result.stderr
                assert all(url in json.dumps(requests) for url in PUBLIC_URLS)
                for index, (url, _) in enumerate(PRIVILEGED_URL_CASES, start=1):
                    _, requests = run("Inspect this synthetic link: " + url)
                    assert not requests, f"Privileged URL fixture {index} reached the model endpoint"
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
                result, requests = run("Apply the local test now.", lane="bash")
                assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                assert BLOCK_REASON in json.dumps(requests[-1], ensure_ascii=False)
                assert TOOL_CANARY not in json.dumps(requests)
                fixture.write_text(PUBLIC_URL_FIXTURE, encoding="utf-8")
                result, requests = run("Read the public link fixture.", lane="bash")
                assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                assert all(url in json.dumps(requests[-1]) for url in PUBLIC_URLS)
                for index, (url, private_value) in enumerate(PRIVILEGED_URL_CASES, start=1):
                    fixture.write_text(url, encoding="utf-8")
                    result, requests = run("Read the synthetic link fixture.", lane="bash")
                    assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                    assert BLOCK_REASON in json.dumps(requests[-1], ensure_ascii=False)
                    assert private_value not in json.dumps(requests), f"Tool URL fixture {index} reached the model"
                for lane in ("bash", "mcp"):
                    fixture.write_text(json.dumps(METRIC_RESULT), encoding="utf-8")
                    result, requests = run("Read the synthetic metric fixture.", lane=lane)
                    assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                    model_input = json.dumps(requests[-1], ensure_ascii=False)
                    assert METRIC_RESULT["status"] in model_input, f"{lane} discarded the ordinary metric"
                    assert "token_count" in model_input and str(METRIC_RESULT["token_count"]) in model_input

                    fixture.write_text(json.dumps(CREDENTIAL_RESULT), encoding="utf-8")
                    result, requests = run("Read the synthetic credential fixture.", lane=lane)
                    assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                    assert BLOCK_REASON in json.dumps(requests[-1], ensure_ascii=False)
                    assert OPAQUE_CREDENTIAL not in json.dumps(requests), f"Credential from {lane} reached the model"
                fixture.write_text(TOOL_CANARY, encoding="utf-8")
                set_enabled(False)
                result, requests = run("Apply the local test now.", lane="bash")
                assert result.returncode == 0 and len(requests) == 2, result.stdout + result.stderr
                assert TOOL_CANARY in json.dumps(requests[-1])
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", action="store_true")
    parser.add_argument("binaries", nargs="*")
    args = parser.parse_args()
    binaries = args.binaries or [shutil.which("codex")]
    for binary in binaries:
        if not binary:
            sys.exit("Codex CLI was not found. Pass its executable as an argument.")
        smoke(binary, plugin=args.plugin)
        print(f"PASS: {binary}: prompt, links, Bash JSON and structured MCP checks")
