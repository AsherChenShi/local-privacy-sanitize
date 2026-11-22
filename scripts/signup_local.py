"""Local human approval and a restricted agent socket for synthetic signup tests."""

import argparse
from functools import partial
from getpass import getpass, GetPassWarning
import json
from pathlib import Path
import re
import socket
from socketserver import StreamRequestHandler, UnixStreamServer
import sys
import tempfile
from threading import Thread
from urllib.parse import urlsplit
import warnings

from hook_supervisor import load_strict_json
from signup_broker import SignupBroker
from signup_browser import fill_email


MAX_FRAME = 4096
DENIED = {"status": "denied"}
ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}")


class AgentRequest(StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            raw = self.rfile.readline(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
                result = DENIED
            else:
                result = self.server.dispatch(load_strict_json(raw))
        except (OSError, ValueError, RecursionError):
            result = DENIED
        try:
            self.wfile.write(json.dumps(result, ensure_ascii=True).encode("ascii") + b"\n")
        except (OSError, socket.timeout):
            pass


class SignupAgentServer(UnixStreamServer):
    """Socket interface for model requests. Approval stays in the local process."""

    def __init__(self, socket_path, broker, *, sites=None):
        self.broker = broker
        self.sites = None if sites is None else dict(sites)
        # The socket lives in a directory controlled by the trusted launcher.
        self.path = Path(socket_path)
        if self.path.parent.stat().st_mode & 0o077:
            raise ValueError("Use a private directory for the signup socket.")
        super().__init__(str(self.path), AgentRequest)
        self.path.chmod(0o600)

    def dispatch(self, request):
        if not isinstance(request, dict):
            return DENIED
        if set(request) == {"action", "url"} and request["action"] == "prepare":
            target = request["url"]
            if not isinstance(target, str):
                return DENIED
            url = target if self.sites is None else self.sites.get(target)
            if url is None:
                return DENIED
            return self.broker.prepare(url)
        if set(request) == {"action", "request_id"} and request["action"] == "execute":
            if isinstance(request["request_id"], str):
                return self.broker.execute(request["request_id"])
        return DENIED

    def server_close(self):
        super().server_close()
        # Never remove an existing endpoint if binding it failed.
        if getattr(self, "_owns_path", False):
            self.path.unlink(missing_ok=True)

    def server_activate(self):
        self._owns_path = True
        super().server_activate()

    def handle_error(self, request, client_address):
        print("The local agent request failed.", file=sys.stderr)


def parse_sites(specs):
    sites = {}
    origins = set()
    for spec in specs:
        alias, separator, url = spec.partition("=")
        if not separator or not ALIAS.fullmatch(alias) or alias in sites:
            raise ValueError("Expected unique local test site aliases.")
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.hostname != "127.0.0.1" or not parts.port
                or parts.netloc != f"127.0.0.1:{parts.port}" or parts.query or parts.fragment
                or not parts.path.startswith("/")):
            raise ValueError("Expected a loopback HTTPS test page with an explicit port.")
        sites[alias] = url
        origins.add(f"https://{parts.netloc}")
    return sites, origins


def local_console(broker):
    """Human-only terminal. The agent transport has no route to this input."""
    while True:
        for pending in broker.pending():
            print(json.dumps(pending, ensure_ascii=True))
        request_id = input("Pending request ID (Enter to refresh, q to quit): ").strip()
        if request_id == "q":
            return
        if not request_id:
            continue
        scope = broker.describe(request_id)
        if scope.get("status") != "pending":
            print("No pending request for that ID.")
            continue
        print("Scope for this one operation", json.dumps(scope, ensure_ascii=True))
        action = input("FILL verifies offline, SUBMIT sends one HTTPS POST, CANCEL revokes: ").strip()
        if action == "CANCEL":
            broker.cancel(request_id)
        elif action in ("FILL", "SUBMIT"):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", GetPassWarning)
                    email = getpass("Synthetic email ending in .invalid (hidden): ")
            except GetPassWarning:
                print("Hidden local input is unavailable. Approval was not recorded.")
                continue
            decision = broker.approve(request_id, email, submit=action == "SUBMIT")
            del email
            print(decision["status"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", action="append", required=True, metavar="ALIAS=HTTPS_URL")
    parser.add_argument("--ca-file", type=Path, required=True, help="CA for the local test sites")
    parser.add_argument("--browser", type=Path, required=True, help="Local Chrome or Chromium executable")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Start approval in a separate local interactive terminal.", file=sys.stderr)
        return 2
    try:
        sites, origins = parse_sites(args.site)
        browser = partial(fill_email, browser_path=args.browser)
        broker = SignupBroker(origins, args.ca_file, browser=browser)
        with tempfile.TemporaryDirectory(prefix="signup-", dir="/tmp") as directory:
            path = Path(directory) / "agent.sock"
            with SignupAgentServer(path, broker, sites=sites) as server:
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    print(f"Local MCP socket {path}", flush=True)
                    print("Configured test sites", ", ".join(sorted(sites)), flush=True)
                    local_console(broker)
                finally:
                    server.shutdown()
                    thread.join()
    except (EOFError, KeyboardInterrupt):
        return 0
    except (OSError, ValueError):
        print("Could not start the synthetic signup broker. Check site, TLS and browser settings.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
