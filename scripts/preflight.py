#!/usr/bin/env python3
"""Open an independent, loopback-only privacy preflight in a local browser."""

import argparse
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sys
import webbrowser

from hook_supervisor import load_strict_json
from review_policy import ReviewPolicyError, find_doubts, load_review_policy, select_entities
from review_preview import TYPE_LABELS
from sanitize import ARTIFACTS, MAX_BYTES, MAX_POLICY_BYTES, Rejected, parse_policy, preview_rows, read_local, sanitize


ASSETS = {
    "/": ("index.html", "text/html"),
    "/preflight.js": ("preflight.js", "text/javascript"),
    "/preflight.css": ("preflight.css", "text/css"),
}
HOST_SETTINGS = {"codex": ("CODEX_HOME", ".codex"), "claude": ("CLAUDE_CONFIG_DIR", ".claude")}
MAX_REQUEST = MAX_BYTES * 6 + 512  # A JSON string can expand to six bytes per input byte.
PREVIEW_LIMIT = 20
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def prepare(payload):
    """Use the existing redactor without writing source, candidate or diagnostic files."""
    if not isinstance(payload, dict) or set(payload) != {"text", "format", "dictionary"}:
        raise Rejected("INVALID_REQUEST")
    source, fmt, dictionary = (payload[key] for key in ("text", "format", "dictionary"))
    if (not isinstance(source, str) or not isinstance(fmt, str) or fmt not in ARTIFACTS
            or not isinstance(dictionary, str) or dictionary not in {"builtin", *HOST_SETTINGS}):
        raise Rejected("INVALID_REQUEST")
    if len(source) > MAX_BYTES or len(source.encode("utf-8")) > MAX_BYTES:
        raise Rejected("FILE_TOO_LARGE")
    if not source.strip():
        raise Rejected("EMPTY_INPUT")

    try:
        ordinary_types = load_review_policy(read_local=read_local)
    except ReviewPolicyError:
        raise Rejected("INVALID_REVIEW_POLICY") from None
    entities = ()
    if dictionary != "builtin":
        variable, default = HOST_SETTINGS[dictionary]
        config = Path(os.environ.get(variable) or Path.home() / default)
        policy = config / "local-privacy-sanitize" / "entities.local.json"
        try:
            entities = parse_policy(read_local(policy, MAX_POLICY_BYTES, {".json"}))
        except FileNotFoundError:
            if os.path.lexists(policy):
                raise Rejected("INVALID_POLICY") from None
            raise Rejected("DICTIONARY_NOT_FOUND") from None
        except (OSError, Rejected):
            raise Rejected("INVALID_POLICY") from None

    edits = []
    candidate, report = sanitize(source, select_entities(entities, ordinary_types), format=fmt, edits=edits)
    doubts = find_doubts(candidate, fmt)
    return {"status": report["status"], "candidate": candidate, "artifact": report["artifact"],
            "occurrences": report["occurrences"], "change_count": len(edits), "doubt_count": len(doubts),
            "changes": preview_rows(source, edits[:PREVIEW_LIMIT]), "doubts": doubts[:PREVIEW_LIMIT],
            "labels": TYPE_LABELS}


class PreflightHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_args):
        pass  # Request paths, headers and input never enter logs.

    def header(self, name):
        values = self.headers.get_all(name, [])
        return values[0] if len(values) == 1 else ""

    def respond(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(data)

    def reply_json(self, status, data):
        self.respond(status, "application/json", json.dumps(data).encode("ascii"))

    def do_GET(self):
        asset = self.server.assets.get(self.path)
        if self.header("Host") != self.server.authority or asset is None:
            return self.reply_json(404, {"code": "NOT_FOUND"})
        self.respond(200, *asset)

    def do_POST(self):
        if self.path != "/prepare":
            return self.reply_json(404, {"code": "NOT_FOUND"})
        key = self.header("X-Preflight-Key")
        if (self.header("Host") != self.server.authority or self.header("Origin") != self.server.origin
                or not compare_digest(key.encode("latin-1"), self.server.key.encode("ascii"))):
            return self.reply_json(403, {"code": "SESSION_REQUIRED"})
        length = self.header("Content-Length")
        if (self.header("Content-Type") != "application/json" or self.headers.get_all("Transfer-Encoding")
                or not length.isascii() or not length.isdecimal() or len(length) > 8):
            return self.reply_json(400, {"code": "INVALID_REQUEST"})
        size = int(length)
        if size > MAX_REQUEST:
            return self.reply_json(413, {"code": "FILE_TOO_LARGE"})
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise Rejected("INVALID_REQUEST")
            result = prepare(load_strict_json(raw))
        except Rejected as error:
            return self.reply_json(422, {"code": str(error)})
        except (ValueError, RecursionError):
            return self.reply_json(400, {"code": "INVALID_REQUEST"})
        except (OSError, TimeoutError):
            return self.reply_json(422, {"code": "LOCAL_IO_OR_DATA_ERROR"})
        except Exception:
            return self.reply_json(500, {"code": "INTERNAL_ERROR"})
        self.reply_json(200, result)


class PreflightServer(ThreadingHTTPServer):
    def __init__(self):
        directory = Path(__file__).with_name("preflight_ui")
        self.assets = {route: (mime, (directory / name).read_bytes()) for route, (name, mime) in ASSETS.items()}
        self.key = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", 0), PreflightHandler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.authority}"

    def handle_error(self, _request, _address):
        pass  # Never emit a traceback from request handling.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-open", action="store_true", help="Print the local address without launching a browser")
    args = parser.parse_args(argv)
    if os.name != "posix":
        print("Local preflight supports macOS and Linux.", file=sys.stderr)
        return 2
    try:
        with PreflightServer() as server:
            url = f"{server.origin}/#{server.key}"
            print(f"Local preflight (Ctrl+C to stop): {url}", flush=True)
            if not args.no_open:
                try:
                    webbrowser.open(url)
                except (OSError, webbrowser.Error):
                    pass  # The printed loopback URL remains usable.
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("Local preflight could not start. Check that its files are present and loopback is available.",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
