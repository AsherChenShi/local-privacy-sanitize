#!/usr/bin/env python3
"""Exercise an installed Claude Code build against a loopback Anthropic model stub."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "claude-privacy@local-privacy-tools"
PROMPT_CANARY = "claude-smoke-prompt@example.invalid"
TOOL_CANARY = "claude-smoke-tool@example.invalid"
MODEL = "claude-sonnet-4-6"
MCP_TOOL = "mcp__privacy-fixture__sample"


def response_events(index, lane):
    if lane:
        tool_name = "Bash" if lane == "bash" else MCP_TOOL
        tool_input = {"command": "cat fixture.txt", "description": "Read the synthetic fixture"} if lane == "bash" else {}
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
        events = response_events(index, self.server.lane if index == 1 else None)
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


def run_mcp_stub():
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "privacy-fixture", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": [{
                "name": "sample", "description": "Return a synthetic privacy fixture",
                "inputSchema": {"type": "object", "properties": {}},
            }]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": TOOL_CANARY}]}
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


def smoke(binary, *, prompts_only):
    with tempfile.TemporaryDirectory(prefix="claude privacy smoke ") as directory:
        tmp = Path(directory)
        workspace = tmp / "workspace"
        workspace.mkdir()
        (workspace / "fixture.txt").write_text(TOOL_CANARY + "\n", encoding="utf-8")
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

            def run(prompt, *, lane=None, expect_success=True):
                server.requests = []
                server.lane = lane
                mcp_servers = {}
                allowed_tool = "Bash(cat fixture.txt)"
                if lane == "mcp":
                    mcp_servers["privacy-fixture"] = {
                        "type": "stdio", "command": sys.executable,
                        "args": [str(Path(__file__).resolve()), "--mock-mcp"],
                    }
                    allowed_tool = MCP_TOOL
                result = cli([
                    "-p", "--model", MODEL, "--output-format", "json",
                    "--setting-sources", "user", "--no-session-persistence",
                    "--strict-mcp-config", "--mcp-config", json.dumps({"mcpServers": mcp_servers}),
                    "--tools", "Bash", "--allowedTools", allowed_tool,
                ], prompt=prompt, expect_success=expect_success)
                return result, json.dumps(server.requests)

            try:
                cli(["plugin", "marketplace", "add", str(marketplace)])
                cli(["plugin", "install", PLUGIN, "--scope", "user"])
                cli(["plugin", "disable", PLUGIN, "--scope", "user"])
                _, requests = run("Confirm this synthetic email " + PROMPT_CANARY)
                assert PROMPT_CANARY in requests, "Disabled plugin prevented the control request"

                cli(["plugin", "enable", PLUGIN, "--scope", "user"])
                blocked, requests = run("Confirm this synthetic email " + PROMPT_CANARY,
                                        expect_success=False)
                assert requests == "[]", "Enabled plugin allowed the synthetic address to reach the model"
                assert "Privacy check blocked" in blocked.stdout + blocked.stderr, "No Hook block feedback"
                _, requests = run("Confirm this sanitized value [EMAIL_001].")
                assert "[EMAIL_001]" in requests and PROMPT_CANARY not in requests
                print("PASS: native enable/disable and prompt behavior")

                for lane in (() if prompts_only else ("bash", "mcp")):
                    if lane == "mcp":
                        cli(["plugin", "enable", PLUGIN, "--scope", "user"])
                    _, requests = run("Read the synthetic fixture.", lane=lane)
                    assert len(json.loads(requests)) >= 2, "No tool-result request reached the mock"
                    assert TOOL_CANARY not in requests, "Enabled plugin exposed the synthetic tool result"
                    assert "Privacy check blocked" in requests, "Model received no tool-result replacement"
                    cli(["plugin", "disable", PLUGIN, "--scope", "user"])
                    _, requests = run("Read the synthetic fixture.", lane=lane)
                    assert TOOL_CANARY in requests, "Disabled plugin prevented the raw tool-result control"
                    print(f"PASS: native {lane} replacement and disabled control")
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    if sys.argv[1:] == ["--mock-mcp"]:
        run_mcp_stub()
        sys.exit()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to an installed Claude Code binary")
    parser.add_argument("--prompts-only", action="store_true", help="Skip the tool smoke checks")
    args = parser.parse_args()
    smoke(str(args.binary.resolve()), prompts_only=args.prompts_only)
