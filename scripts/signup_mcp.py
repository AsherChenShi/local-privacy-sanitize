#!/usr/bin/env python3
"""Stdio MCP client for a separately operated local signup broker."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

from hook_supervisor import load_strict_json


SERVER_NAME = "privacy_signup"
MAX_MCP_FRAME = 65536
MAX_BROKER_FRAME = 4096
REQUEST_ID = re.compile(r"[a-p]{32}")
RPC_ID = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
LOOPBACK_URL = re.compile(r"https://127\.0\.0\.1:[1-9][0-9]{0,4}/[A-Za-z0-9/_.-]{0,240}")
SITE_ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}")
PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
STATUSES = {
    "prepare": {"pending", "denied", "unavailable"},
    "execute": {"pending", "filled", "submitted", "denied", "expired", "unknown", "unavailable"},
}
TOOLS = [
    {
        "name": "prepare",
        "description": "Prepare an allowed local signup form by site alias or configured loopback URL.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}},
                        "required": ["url"], "additionalProperties": False},
    },
    {
        "name": "execute",
        "description": "Use independent local approval once. Return only a fixed status.",
        "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}},
                        "required": ["request_id"], "additionalProperties": False},
    },
]


def broker_call(path, event):
    """Use only the private local socket configured by the launcher."""
    path = Path(path)
    parent = path.parent.lstat()
    endpoint = path.lstat()
    uid = os.getuid()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid or parent.st_mode & 0o077
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != uid):
        raise ValueError("invalid local broker")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(15)
        client.connect(str(path))
        client.sendall(json.dumps(event, separators=(",", ":")).encode("ascii") + b"\n")
        with client.makefile("rb") as stream:
            frame = stream.readline(MAX_BROKER_FRAME + 1)
    if len(frame) > MAX_BROKER_FRAME or not frame.endswith(b"\n"):
        raise ValueError("invalid broker frame")
    return load_strict_json(frame)


def tool_result(params, call):
    args = params.get("arguments")
    name = params.get("name")
    if not isinstance(args, dict) or not isinstance(name, str):
        return {"status": "denied"}
    if name == "prepare" and set(args) == {"url"}:
        url = args["url"]
        if not isinstance(url, str) or not (SITE_ALIAS.fullmatch(url) or LOOPBACK_URL.fullmatch(url)):
            return {"status": "denied"}
    elif name == "execute" and set(args) == {"request_id"}:
        if not isinstance(args["request_id"], str) or not REQUEST_ID.fullmatch(args["request_id"]):
            return {"status": "denied"}
    else:
        return {"status": "denied"}
    try:
        response = call({"action": name, **args})
    except (OSError, ValueError, RecursionError):
        return {"status": "unavailable"}
    status = response.get("status") if isinstance(response, dict) else None
    if not isinstance(status, str) or status not in STATUSES[name]:
        return {"status": "unavailable"}
    safe = {"status": status}
    if name == "prepare" and status == "pending":
        request_id = response.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            return {"status": "unavailable"}
        safe["request_id"] = request_id
    return safe


def error_response(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def dispatch(request, call):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return error_response(None, -32600, "Invalid request")
    if "id" not in request:
        return None
    request_id = request["id"]
    if not (type(request_id) is int and -(2 ** 53) < request_id < 2 ** 53
            or isinstance(request_id, str) and RPC_ID.fullmatch(request_id)):
        return error_response(None, -32600, "Invalid request")
    method = request.get("method")
    params = request.get("params", {})
    if not isinstance(params, dict):
        return error_response(request_id, -32602, "Invalid parameters")
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if isinstance(version, str) and version in PROTOCOLS else "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": json.dumps(tool_result(params, call))}]}
    else:
        return error_response(request_id, -32601, "Method not found")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(source, output, call):
    while frame := source.readline(MAX_MCP_FRAME + 1):
        if len(frame) > MAX_MCP_FRAME or not frame.endswith(b"\n"):
            break
        try:
            response = dispatch(load_strict_json(frame), call)
        except (ValueError, RecursionError):
            response = error_response(None, -32700, "Invalid message")
        if response is not None:
            output.write(json.dumps(response).encode("ascii") + b"\n")
            output.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    args = parser.parse_args()
    try:
        serve(sys.stdin.buffer, sys.stdout.buffer, lambda event: broker_call(args.socket, event))
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
