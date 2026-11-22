#!/usr/bin/env python3
"""Offline Claude Code hooks for known sensitive values."""

import argparse
import json
import os
from pathlib import Path
import sys

from sanitize import MAX_BYTES, MAX_POLICY_BYTES, parse_policy, read_local, scan_kind


PROMPT = "UserPromptSubmit"
TOOL = "PostToolUse"
SENSITIVE = "Privacy check blocked sensitive content. Sanitize it locally and retry."
CHECK_ERROR = "The local privacy check could not inspect this content."


def local_entities():
    config = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    policy = config / "local-privacy-sanitize" / "entities.local.json"
    if not os.path.lexists(policy):
        return ()
    return parse_policy(read_local(policy, MAX_POLICY_BYTES, {".json"}))


def read_event(expected):
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("event too large")
    event = json.loads(raw)
    if event["hook_event_name"] != expected:
        raise ValueError("unexpected event")
    return event


def inspect_tool(response, lane, entities):
    if lane == "bash":
        if (not isinstance(response, dict)
                or not all(isinstance(response.get(key), str) for key in ("stdout", "stderr"))
                or not all(type(response.get(key)) is bool for key in ("interrupted", "isImage"))):
            raise ValueError("unsupported Bash result")
        if response["isImage"]:
            raise ValueError("opaque Bash result")
    else:
        if isinstance(response, dict):
            if not isinstance(response.get("structuredContent", {}), dict):
                raise ValueError("unsupported MCP structured result")
            items = response.get("content", [])
        elif isinstance(response, list):
            items = response
        elif isinstance(response, str):
            items = []
        else:
            raise ValueError("unsupported MCP result")
        if not isinstance(items, list) or any(
                not isinstance(item, dict) or item.get("type") != "text"
                or not isinstance(item.get("text"), str) for item in items):
            raise ValueError("unsupported MCP content")
    return scan_kind(response, entities)


def tool_replacement(response, lane, reason):
    if lane == "bash":
        interrupted = isinstance(response, dict) and response.get("interrupted") is True
        output = {"stdout": reason, "stderr": "", "interrupted": interrupted, "isImage": False}
    elif isinstance(response, str):
        output = reason
    else:
        content = [{"type": "text", "text": reason}]
        output = {"content": content} if isinstance(response, dict) else content
    # Claude's PostToolUse "block" alone leaves the original result model-visible.
    return {"hookSpecificOutput": {"hookEventName": TOOL, "updatedToolOutput": output}}


def decision(event_name, lane):
    response = None
    try:
        event = read_event(event_name)
        if event_name == PROMPT:
            value = event["prompt"]
            if not isinstance(value, str):
                raise ValueError("unsupported prompt")
            kind = scan_kind(value, local_entities())
        else:
            response = event["tool_response"]
            tool_name = event["tool_name"]
            if (lane == "bash" and tool_name != "Bash") or (
                    lane == "mcp" and not tool_name.startswith("mcp__")):
                raise ValueError("unexpected tool")
            kind = inspect_tool(response, lane, local_entities())
        if not kind:
            return None
        reason = f"{SENSITIVE} [{kind}]" if event_name == PROMPT else SENSITIVE
    except Exception:
        reason = CHECK_ERROR

    if event_name == PROMPT:
        return {
            "decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": PROMPT, "suppressOriginalPrompt": True},
        }
    return tool_replacement(response, lane, reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", choices=(PROMPT, TOOL))
    parser.add_argument("lane", nargs="?", choices=("bash", "mcp"))
    args = parser.parse_args()
    if (args.event == TOOL) != (args.lane is not None):
        parser.error("lane is required for PostToolUse only")
    result = decision(args.event, args.lane)
    if result is not None:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
