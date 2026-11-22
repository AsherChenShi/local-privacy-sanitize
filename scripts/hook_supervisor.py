"""Run a local hook checker below the host timeout and consume only bounded status tags."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time


WORKER_TIMEOUT_SECONDS = 6
MAX_WORKER_REPLY = 96
SHAPES = frozenset({"prompt", "tool", "bash", "bash_interrupted", "mcp_text", "mcp_list",
                    "mcp_object", "read_text", "pre_read"})
KINDS = frozenset({"PERSON", "ORG", "LOCATION", "PROJECT", "ACCOUNT", "SENSITIVE", "URL",
                   "EMAIL", "CNID", "PHONE", "SSN", "SECRET", "CARD", "IP", "PROTECTED_PATH"})


@dataclass(frozen=True)
class Verdict:
    status: str
    shape: str | None = None
    kind: str | None = None


def _reply(output):
    # Trust only the fixed protocol. A diagnostic, traceback, or partial line
    # is never forwarded as host-facing output.
    parts = output.decode("ascii", errors="replace").splitlines()
    shape = parts[0] if b"\n" in output and parts and parts[0] in SHAPES else None
    if shape is None or len(parts) != 2 or not output.endswith(b"\n"):
        return Verdict("error", shape)
    value = parts[1]
    if value in ("allow", "error"):
        return Verdict(value, shape)
    if value in KINDS:
        return Verdict("match", shape, value)
    return Verdict("error", shape)


def supervise(script, args, *, timeout=None):
    """Inherit host stdin, enforce one monotonic deadline, and reap the checker."""
    deadline = time.monotonic() + (WORKER_TIMEOUT_SECONDS if timeout is None else timeout)
    output = bytearray()
    process = None
    command = [sys.executable, "-E", "-S", "-B", str(Path(script).resolve()), *args, "--worker"]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return Verdict("timeout", _reply(output).shape)
                chunk = os.read(process.stdout.fileno(), MAX_WORKER_REPLY + 1 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_WORKER_REPLY:
                    return Verdict("error", _reply(output).shape)
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        reply = _reply(output)
        return reply if code == 0 else Verdict("error", reply.shape)
    except subprocess.TimeoutExpired:
        return Verdict("timeout", _reply(output).shape)
    except OSError:
        return Verdict("error", _reply(output).shape)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def emit_shape(shape):
    if shape not in SHAPES:
        raise ValueError("unsupported worker shape")
    print(shape, flush=True)


def emit_status(kind):
    if kind is not None and kind not in KINDS and kind != "error":
        raise ValueError("unsupported worker status")
    print(kind or "allow", flush=True)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate hook key")
        result[key] = value
    return result


def _non_json_value(_value):
    raise ValueError("unsupported hook value")


def load_strict_json(raw):
    return json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_non_json_value)


def read_hook_event(expected, max_bytes):
    raw = sys.stdin.buffer.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("event too large")
    event = load_strict_json(raw)
    if not isinstance(event, dict) or event.get("hook_event_name") != expected:
        raise ValueError("unexpected event")
    return event
