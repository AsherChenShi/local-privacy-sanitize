#!/usr/bin/env python3
"""Exercise an installed Claude Code build against a loopback Anthropic model stub."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Thread
from urllib.parse import urlsplit

from hook_smoke_fixtures import FAKE_SECRET, PRIVATE_URL, changed_prompt_hook, injected_fault, reviewed_candidates
from privacy_smoke_fixtures import CREDENTIAL_RESULT, MCP_SERVER, MCP_TOOL, METRIC_RESULT, OPAQUE_CREDENTIAL
from url_smoke_fixtures import PRIVILEGED_URL_CASES, PUBLIC_URL_FIXTURE, PUBLIC_URLS


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "claude-privacy@local-privacy-tools"
PROMPT_CANARY = "claude-smoke-prompt@example.invalid"
TOOL_CANARY = "claude-smoke-tool@example.invalid"
MODEL = "claude-sonnet-4-6"


def response_events(index, lane, read_path):
    if lane:
        if lane == "bash":
            tool_name = "Bash"
            tool_input = {"command": "cat fixture.txt", "description": "Read the synthetic fixture"}
        elif lane == "read":
            tool_name = "Read"
            tool_input = {"file_path": read_path}
        else:
            tool_name, tool_input = MCP_TOOL, {}
        block = {"type": "tool_use", "id": "toolu_synthetic_01", "name": tool_name, "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(tool_input)}
        reason = "tool_use"
    else:
        block = {"type": "text", "text": ""}
        delta = {"type": "text_delta", "text": "MOCK_OK"}
        reason = "end_turn"
    message = {
        "id": f"msg_synthetic_{index}", "type": "message", "role": "assistant",
        "model": MODEL, "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 0},
    }
    return (
        {"type": "message_start", "message": message},
        {"type": "content_block_start", "index": 0, "content_block": block},
        {"type": "content_block_delta", "index": 0, "delta": delta},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None},
         "usage": {"output_tokens": 4}},
        {"type": "message_stop"},
    )


class ModelStub(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, content_type, payload, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.respond("application/json", b'{"data":[],"has_more":false}')

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if urlsplit(self.path).path != "/v1/messages":
            self.respond("application/json", b"{}")
            return

        request = json.loads(data)
        self.server.requests.append(request)
        index = len(self.server.requests)
        events = response_events(index, self.server.lane if index == 1 else None, self.server.read_path)
        if request.get("stream"):
            payload = "".join(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
            ).encode()
            self.respond("text/event-stream", payload)
        else:
            message = events[0]["message"]
            content = events[1]["content_block"]
            if content["type"] == "tool_use":
                content["input"] = json.loads(events[2]["delta"]["partial_json"])
            else:
                content["text"] = events[2]["delta"]["text"]
            message["content"] = [content]
            message.update(events[-2]["delta"])
            self.respond("application/json", json.dumps(message).encode())


def smoke(binary, *, prompts_only):
    with tempfile.TemporaryDirectory(prefix="claude privacy smoke ") as directory:
        tmp = Path(directory)
        workspace = tmp / "workspace"
        workspace.mkdir()
        fixture = workspace / "fixture.txt"
        mcp_stub = Path(__file__).resolve().with_name("privacy_smoke_fixtures.py")
        fixture.write_text(TOOL_CANARY + "\n", encoding="utf-8")
        marketplace = tmp / "market"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/build_claude_plugin.py"), str(marketplace)],
            timeout=15, check=True, capture_output=True,
        )
        with ThreadingHTTPServer(("127.0.0.1", 0), ModelStub) as server:
            config = tmp / "claude-config"
            config.mkdir()
            env = {
                "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                "LANG": "en_US.UTF-8",
                "TMPDIR": str(tmp),
                "CLAUDE_CONFIG_DIR": str(config),
                "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                "ANTHROPIC_API_KEY": "synthetic-local-smoke-key",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_AUTOUPDATER": "1",
                "DISABLE_TELEMETRY": "1",
                "DISABLE_ERROR_REPORTING": "1",
            }
            server.requests = []
            server.lane = None
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def cli(args, *, prompt=None, expect_success=True):
                result = subprocess.run(
                    [binary, *args], cwd=workspace, env=env,
                    input=prompt, stdin=subprocess.DEVNULL if prompt is None else None,
                    text=True, encoding="utf-8", capture_output=True, timeout=30,
                )
                if expect_success and result.returncode:
                    raise RuntimeError(
                        f"Claude CLI returned {result.returncode}: "
                        f"{result.stdout[-1500:]}{result.stderr[-1500:]}"
                    )
                return result

            def run(prompt, *, lane=None, expect_success=True, structured=False, read_path=fixture):
                server.requests = []
                server.lane = lane
                server.read_path = str(read_path)
                mcp_servers = {}
                builtin_tools = "Bash"
                allowed_tool = "Bash(cat fixture.txt)"
                if lane == "mcp":
                    mcp_servers[MCP_SERVER] = {
                        "type": "stdio", "command": sys.executable,
                        "args": [str(mcp_stub), str(fixture), "structured" if structured else "text"],
                    }
                    allowed_tool = MCP_TOOL
                elif lane == "read":
                    builtin_tools = allowed_tool = "Read"
                result = cli([
                    "-p", "--model", MODEL, "--output-format", "json",
                    "--setting-sources", "user", "--no-session-persistence",
                    "--strict-mcp-config", "--mcp-config", json.dumps({"mcpServers": mcp_servers}),
                    "--tools", builtin_tools, "--allowedTools", allowed_tool,
                ], prompt=prompt, expect_success=expect_success)
                return result, json.dumps(server.requests)

            try:
                cli(["plugin", "marketplace", "add", str(marketplace)])
                cli(["plugin", "install", PLUGIN, "--scope", "user"])
                registry = json.loads((config / "plugins/installed_plugins.json").read_text())
                [installed] = registry["plugins"][PLUGIN]
                plugin_root = Path(installed["installPath"])
                plugin_roots = [plugin_root, marketplace / "plugins/claude-privacy"]
                entrypoints = [path / "scripts/claude_privacy.py" for path in plugin_roots]
                manifests = [path / "hooks/hooks.json" for path in plugin_roots]
                version = re.search(r"\b([0-9]+)\.([0-9]+)\.([0-9]+)\b", cli(["--version"]).stdout)
                assert version, "Could not determine Claude native version"
                host_failure_block = tuple(map(int, version.groups())) >= (2, 1, 295)
                cli(["plugin", "disable", PLUGIN, "--scope", "user"])
                _, requests = run("Confirm this synthetic email " + PROMPT_CANARY)
                assert PROMPT_CANARY in requests, "Disabled plugin prevented the control request"
                candidates = list(reviewed_candidates(tmp))
                for candidate in candidates:
                    _, requests = run(candidate)
                    assert "1200" in requests and FAKE_SECRET not in requests and PRIVATE_URL not in requests

                cli(["plugin", "enable", PLUGIN, "--scope", "user"])
                blocked, requests = run("Confirm this synthetic email " + PROMPT_CANARY,
                                        expect_success=False)
                assert requests == "[]", "Enabled plugin allowed the synthetic address to reach the model"
                assert "Privacy check blocked" in blocked.stdout + blocked.stderr, "No Hook block feedback"
                for fault in ("hang", "crash", "bad_output"):
                    with injected_fault(entrypoints, fault, event="UserPromptSubmit"):
                        result, requests = run(PROMPT_CANARY, expect_success=False)
                    assert requests == "[]", f"The {fault} worker fault allowed a model request"
                    if fault == "hang":
                        assert "Privacy check timed out" in result.stdout + result.stderr, result.stdout + result.stderr
                print("PASS: worker timeout, crash and invalid decision all blocked")
                if host_failure_block:
                    with changed_prompt_hook(manifests, command=str(tmp / "missing-interpreter"), args=[]):
                        _, requests = run(PROMPT_CANARY, expect_success=False)
                    assert requests == "[]", "The configured Hook that could not start allowed a request"
                    with changed_prompt_hook(manifests, timeout=1):
                        with injected_fault(entrypoints, "hang", in_worker=False, event="UserPromptSubmit"):
                            _, requests = run(PROMPT_CANARY, expect_success=False)
                    assert requests == "[]", "The host timeout allowed a request"
                    print("PASS: Claude host blocked a missing launcher and a hard timeout")

                for candidate in candidates:
                    _, requests = run(candidate)
                    assert "1200" in requests and FAKE_SECRET not in requests and PRIVATE_URL not in requests
                print("PASS: JSON/Markdown preflight works with or without Hook")
                _, requests = run("Confirm this sanitized value [EMAIL_001].")
                assert "[EMAIL_001]" in requests and PROMPT_CANARY not in requests
                _, requests = run("Read these public references:\n" + PUBLIC_URL_FIXTURE)
                assert all(url in requests for url in PUBLIC_URLS)
                for index, (url, _) in enumerate(PRIVILEGED_URL_CASES, start=1):
                    blocked, requests = run("Inspect this synthetic link: " + url, expect_success=False)
                    assert requests == "[]", f"Privileged URL fixture {index} reached the model endpoint"
                    assert "Privacy check blocked" in blocked.stdout + blocked.stderr
                print("PASS: native enable/disable and prompt behavior, including links")

                for index, lane in enumerate(() if prompts_only else ("bash", "mcp", "read")):
                    if index:
                        cli(["plugin", "enable", PLUGIN, "--scope", "user"])
                    _, requests = run("Read the synthetic fixture.", lane=lane)
                    assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                    assert TOOL_CANARY not in requests, "Enabled plugin exposed the synthetic tool result"
                    assert "Privacy check blocked" in requests, "Model received no tool-result replacement"
                    if lane == "read":
                        with injected_fault(entrypoints, "hang", after_tool_shape=True):
                            _, requests = run("Read the synthetic fixture with an interrupted check.", lane=lane)
                        assert len(json.loads(requests)) >= 2 and TOOL_CANARY not in requests
                        assert "Privacy check timed out" in requests
                    fixture.write_text(PUBLIC_URL_FIXTURE, encoding="utf-8")
                    _, requests = run("Read the public link fixture.", lane=lane)
                    assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                    assert all(url in requests for url in PUBLIC_URLS)
                    for index, (url, private_value) in enumerate(PRIVILEGED_URL_CASES, start=1):
                        fixture.write_text(url, encoding="utf-8")
                        _, requests = run("Read the synthetic link fixture.", lane=lane)
                        assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                        assert "Privacy check blocked" in requests, "Model received no URL replacement"
                        assert private_value not in requests, f"Privileged {lane} fixture {index} reached the model"

                    fixture.write_text(json.dumps(METRIC_RESULT), encoding="utf-8")
                    _, requests = run("Read the synthetic metric fixture.", lane=lane, structured=True)
                    assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                    assert METRIC_RESULT["status"] in requests, f"{lane} discarded the ordinary metric"
                    assert "token_count" in requests and str(METRIC_RESULT["token_count"]) in requests

                    fixture.write_text(json.dumps(CREDENTIAL_RESULT), encoding="utf-8")
                    _, requests = run("Read the synthetic credential fixture.", lane=lane, structured=True)
                    assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                    assert "Privacy check blocked" in requests, "Model received no credential replacement"
                    assert OPAQUE_CREDENTIAL not in requests, f"Credential from {lane} reached the model"

                    fixture.write_text(TOOL_CANARY + "\n", encoding="utf-8")
                    cli(["plugin", "disable", PLUGIN, "--scope", "user"])
                    _, requests = run("Read the synthetic fixture.", lane=lane)
                    assert TOOL_CANARY in requests, "Disabled plugin prevented the raw tool-result control"
                    print(f"PASS: native {lane} replacement, including links and structured credentials")

                if not prompts_only:
                    cli(["plugin", "enable", PLUGIN, "--scope", "user"])
                    sensitive_dir = workspace / "protected"
                    sensitive_dir.mkdir()
                    protected = sensitive_dir / "fixture.txt"
                    protected.write_text("LOCAL_PROTECTED_FILE_MARKER", encoding="utf-8")
                    policy = config / "local-privacy-sanitize/protected_read_roots.local.json"
                    policy.parent.mkdir(exist_ok=True)
                    policy.write_text(json.dumps({"roots": [str(sensitive_dir)]}), encoding="utf-8")
                    _, requests = run("Read the protected synthetic fixture.", lane="read", read_path=protected)
                    assert len(json.loads(requests)) >= 2 and "LOCAL_PROTECTED_FILE_MARKER" not in requests
                    assert "Read was blocked for a configured protected path" in requests
                    fixture.write_text("ORDINARY_READ_CONTROL", encoding="utf-8")
                    _, requests = run("Read the ordinary synthetic fixture.", lane="read")
                    assert "ORDINARY_READ_CONTROL" in requests
                    print("PASS: protected Read blocked before read; ordinary Read still allowed")
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to an installed Claude Code binary")
    parser.add_argument("--prompts-only", action="store_true", help="Skip the tool smoke checks")
    args = parser.parse_args()
    smoke(str(args.binary.resolve()), prompts_only=args.prompts_only)
