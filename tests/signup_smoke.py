"""Exercise native privacy-enabled hosts with a local signup broker and fake models."""

import argparse
import base64
from contextlib import contextmanager
from functools import partial
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Thread
from urllib.parse import quote, quote_plus, urlsplit

from claude_smoke import MODEL as CLAUDE_MODEL, response_events as claude_events
from codex_smoke import events as codex_events
from signup_fixtures import signup_sites


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from signup_broker import SignupBroker
from signup_browser import fill_email
from signup_local import SignupAgentServer
from signup_mcp import SERVER_NAME


EMAIL = "synthetic-broker-mailbox@example.invalid"
DIRECT_INPUT = "prompt-protection-control@example.invalid"
ID_PATTERN = re.compile(r"(?<![A-Za-z0-9])[a-p]{32}(?![A-Za-z0-9])")
NAMESPACE = f"mcp__{SERVER_NAME}"
CLAUDE_PLUGIN = "claude-privacy@local-privacy-tools"
WIRE_MARKERS = (
    EMAIL.encode(), quote(EMAIL, safe="").encode(), quote_plus(EMAIL).encode(),
    base64.b64encode(EMAIL.encode()), base64.urlsafe_b64encode(EMAIL.encode()),
    b"synthetic-broker-mailbox",
)


@contextmanager
def serving(server):
    with server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


def contains_mailbox(payload):
    return any(marker.lower() in payload.lower() for marker in WIRE_MARKERS)


def codex_tool_events(index, tools, tool, arguments):
    if tool is None:
        return list(codex_events(index, None, tools))
    namespace = next((setting for setting in tools if setting.get("type") == "namespace"
                      and setting.get("name") == NAMESPACE), None)
    full_name = f"{NAMESPACE}__{tool}"
    if namespace is None:
        assert any(setting.get("name") == full_name for setting in tools), "signup MCP tool unavailable"
    item = {"type": "function_call", "id": f"fc_signup_{index}", "call_id": f"call_signup_{index}",
            "name": tool if namespace else full_name, "arguments": json.dumps(arguments)}
    if namespace is not None:
        item["namespace"] = NAMESPACE
    response = {"id": f"resp_signup_{index}", "status": "completed",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    return [
        {"type": "response.created", "response": {**response, "status": "in_progress"}},
        {"type": "response.output_item.added", "output_index": 0, "item": item},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]


def claude_tool_events(index, tools, tool, arguments):
    events = list(claude_events(index, None, ""))
    if tool is None:
        return events
    full_name = f"{NAMESPACE}__{tool}"
    assert any(setting.get("name") == full_name for setting in tools), "signup MCP tool unavailable"
    events[1]["content_block"] = {"type": "tool_use", "id": f"toolu_signup_{index}",
                                   "name": full_name, "input": {}}
    events[2]["delta"] = {"type": "input_json_delta", "partial_json": json.dumps(arguments)}
    events[4]["delta"] = {"stop_reason": "tool_use", "stop_sequence": None}
    return events


class MockSignupModel(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body, content_type="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(b'{"data":[],"has_more":false}')

    def tool_for_step(self, index, wire):
        if not self.server.exercise:
            return None, {}
        if index == 1:
            return "prepare", {"url": self.server.site_b.form_url}
        if index == 2:
            assert b"denied" in wire, "unapproved origin did not return denial"
            return "prepare", {"url": self.server.site_a.origin + "/cross-form"}
        if index == 3:
            assert b"denied" in wire, "cross-origin form action did not return denial"
            return "prepare", {"url": self.server.site_a.form_url}
        if index == 4:
            assert b"pending" in wire, "allowed signup request not pending"
            request_id = ID_PATTERN.search(wire.decode())
            assert request_id is not None, "model did not receive opaque request ID"
            self.server.approval_id = request_id.group()
            # Trusted local side of the test. This address is never in the tool frame.
            accepted = self.server.broker.approve(self.server.approval_id, EMAIL, submit=True)
            assert accepted == {"status": "approved"}, "trusted local approval failed"
            return "execute", {"request_id": self.server.approval_id}
        if index == 5:
            assert b"submitted" in wire, "approved signup did not return submitted"
            return "execute", {"request_id": self.server.approval_id}
        assert index == 6 and b"denied" in wire, "replay did not return denial"
        return None, {}

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        if contains_mailbox(self.path.encode() + self.headers.as_bytes() + body):
            self.server.failure = "synthetic mailbox reached model-facing HTTP"
            self.send_error(400)
            return
        endpoint = urlsplit(self.path).path
        if endpoint not in ("/v1/responses", "/v1/messages"):
            self.reply(b"{}")
            return
        self.server.requests.append(body)
        try:
            assert not contains_mailbox(body), "synthetic mailbox reached model wire"
            request = json.loads(body)
            index = len(self.server.requests)
            tool, args = self.tool_for_step(index, body)
            tools = request.get("tools", [])
            if endpoint == "/v1/responses":
                events = codex_tool_events(index, tools, tool, args)
                stream = b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in events)
                self.reply(stream, "text/event-stream")
            else:
                events = claude_tool_events(index, tools, tool, args)
                if request.get("stream"):
                    stream = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events)
                    self.reply(stream.encode(), "text/event-stream")
                else:
                    message = events[0]["message"]
                    block = events[1]["content_block"]
                    if tool:
                        block["input"] = args
                    else:
                        block["text"] = "MOCK_OK"
                    message["content"] = [block]
                    message.update(events[4]["delta"])
                    self.reply(json.dumps(message).encode())
        except (ValueError, AssertionError) as failure:
            # A controlled failure label, not arbitrary HTML, arguments or site content.
            self.server.failure = str(failure) if isinstance(failure, AssertionError) else "mock model protocol error"
            self.send_error(400)


def run_cli(binary, args, env, cwd, *, prompt=None, check=True):
    result = subprocess.run([str(binary), *args], cwd=cwd, env=env, input=prompt,
                            stdin=subprocess.DEVNULL if prompt is None else None,
                            capture_output=True, encoding="utf-8", timeout=45)
    assert not contains_mailbox((result.stdout + result.stderr).encode()), "synthetic mailbox leaked in CLI output"
    if check and result.returncode:
        raise RuntimeError("Native CLI setup or execution failed")
    return result


def codex_runner(root, binary, endpoint, socket):
    config = root / "config"
    config.mkdir()
    settings = config / "config.toml"
    settings.write_text(
        'model = "gpt-5.4"\nmodel_provider = "mock"\nweb_search = "disabled"\n'
        'approval_policy = "never"\nsandbox_mode = "read-only"\n'
        '[analytics]\nenabled = false\n[features]\napps = false\nplugins = true\n'
        'memories = false\nhooks = true\nenable_request_compression = false\n'
        '[model_providers.mock]\nname = "Mock"\n'
        f'base_url = "{endpoint}/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n'
        'request_max_retries = 0\nstream_max_retries = 0\n'
        f'[mcp_servers.{SERVER_NAME}]\ncommand = {json.dumps(sys.executable)}\n'
        f'args = {json.dumps([str(SCRIPTS / "signup_mcp.py"), "--socket", str(socket)])}\n'
        f'[mcp_servers.{SERVER_NAME}.tools.prepare]\napproval_mode = "approve"\n'
        f'[mcp_servers.{SERVER_NAME}.tools.execute]\napproval_mode = "approve"\n', encoding="utf-8",
    )
    env = {"PATH": os.environ["PATH"], "CODEX_HOME": str(config), "LANG": "en_US.UTF-8", "TMPDIR": str(root)}
    market = root / "market"
    subprocess.run([sys.executable, str(SCRIPTS / "build_codex_plugin.py"), str(market)], check=True, timeout=15)
    run_cli(binary, ["plugin", "marketplace", "add", str(market)], env, root)
    run_cli(binary, ["plugin", "add", "codex-privacy@local-privacy-tools"], env, root)
    assert re.search(r'\[plugins\."codex-privacy@local-privacy-tools"\]\s+enabled\s*=\s*true', settings.read_text())

    def run(prompt, *, check=True):
        return run_cli(binary, ["exec", "--skip-git-repo-check", "--ephemeral", "--json",
                                "--dangerously-bypass-hook-trust", "--cd", str(root), prompt],
                       env, root, check=check)

    return run


def claude_runner(root, binary, endpoint, socket):
    config = root / "config"
    config.mkdir()
    env = {"PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
           "LANG": "en_US.UTF-8", "TMPDIR": str(root), "CLAUDE_CONFIG_DIR": str(config),
           "ANTHROPIC_BASE_URL": endpoint, "ANTHROPIC_API_KEY": "synthetic-local-key",
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1",
           "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"}
    market = root / "market"
    subprocess.run([sys.executable, str(SCRIPTS / "build_claude_plugin.py"), str(market)], check=True, timeout=15)
    run_cli(binary, ["plugin", "marketplace", "add", str(market)], env, root)
    run_cli(binary, ["plugin", "install", CLAUDE_PLUGIN, "--scope", "user"], env, root)
    assert json.loads((config / "settings.json").read_text())["enabledPlugins"][CLAUDE_PLUGIN] is True
    mcp_config = {"mcpServers": {SERVER_NAME: {"type": "stdio", "command": sys.executable,
                                              "args": [str(SCRIPTS / "signup_mcp.py"), "--socket", str(socket)]}}}

    def run(prompt, *, check=True):
        return run_cli(binary, ["-p", "--model", CLAUDE_MODEL, "--output-format", "json",
                                "--setting-sources", "user", "--no-session-persistence",
                                "--strict-mcp-config", "--mcp-config", json.dumps(mcp_config),
                                "--tools", "", "--allowedTools", f"{NAMESPACE}__prepare", f"{NAMESPACE}__execute"],
                       env, root, prompt=prompt, check=check)

    return run


def smoke(binary, runner, *, browser):
    # Use a short AF_UNIX socket path even in macOS's deep per-user temporary directory.
    with tempfile.TemporaryDirectory(prefix="privacy-signup-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        socket = root / "broker.sock"
        with signup_sites() as (origins, cafile, site_a, site_b):
            broker = SignupBroker([origins[0]], cafile, browser=partial(fill_email, browser_path=browser))
            with serving(SignupAgentServer(socket, broker)), serving(
                    ThreadingHTTPServer(("127.0.0.1", 0), MockSignupModel)) as model:
                model.broker = broker
                model.site_a = site_a
                model.site_b = site_b
                model.requests = []
                model.failure = None
                model.exercise = False
                run = runner(root, binary, f"http://127.0.0.1:{model.server_port}", socket)
                run(f"Try forwarding the blocking fixture {DIRECT_INPUT}", check=False)
                assert model.requests == [], "native privacy switch did not block a direct email control"
                model.exercise = True
                result = run("Exercise the locally authorized signup tool with the synthetic fixtures.", check=False)
                assert model.failure is None, model.failure
                assert result.returncode == 0 and len(model.requests) == 6, "native mock exchange incomplete"
                assert site_a.emails == [EMAIL], "approved site did not receive exactly one synthetic email"
                assert not site_b.requests and not site_b.emails, "unapproved origin was contacted"
                assert not any(contains_mailbox(body) for body in model.requests)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--browser", type=Path, required=True)
    options = parser.parse_args()
    if not options.codex and not options.claude:
        parser.error("Supply at least one native host")
    for binary, factory in ((options.codex, codex_runner), (options.claude, claude_runner)):
        if binary:
            smoke(binary.resolve(), factory, browser=options.browser.resolve())
            print(f"PASS {factory.__name__}: approved site received one email; cross-origin and replay denied; model wire clear")
