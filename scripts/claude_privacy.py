#!/usr/bin/env python3
"""Offline Claude Code hooks for known sensitive values."""

import argparse
import json
import os
from pathlib import Path
import sys

from hook_supervisor import emit_shape, emit_status, load_strict_json, read_hook_event, supervise
from review_policy import hook_entities
from sanitize import MAX_BYTES, MAX_POLICY_BYTES, parse_policy, read_local, scan_kind


PROMPT = "UserPromptSubmit"
TOOL = "PostToolUse"
PRE_TOOL = "PreToolUse"
SENSITIVE = "Privacy check blocked sensitive content. Sanitize it locally and retry."
CHECK_ERROR = "The local privacy check could not inspect this content. Use the independent local preflight."
CHECK_TIMEOUT = "Privacy check timed out. Use the independent local preflight."
PROTECTED_READ = "Read was blocked for a configured protected path. Use the independent local preflight."


def local_config():
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "local-privacy-sanitize"


def local_entities():
    policy = local_config() / "entities.local.json"
    if not os.path.lexists(policy):
        return ()
    entities = parse_policy(read_local(policy, MAX_POLICY_BYTES, {".json"}))
    return hook_entities(entities, read_local=read_local)


def check_protected_read(event):
    policy = local_config() / "protected_read_roots.local.json"
    if not os.path.lexists(policy):
        return None
    data = load_strict_json(read_local(policy, MAX_POLICY_BYTES, {".json"}))
    if not isinstance(data, dict) or set(data) != {"roots"} or not isinstance(data["roots"], list):
        raise ValueError("invalid protected Read configuration")
    raw_roots = data["roots"]
    if len(raw_roots) > 100 or any(not isinstance(root, str) or not Path(root).is_absolute() for root in raw_roots):
        raise ValueError("protected Read roots must be absolute directories")
    path = Path(event["tool_input"]["file_path"])
    if not path.is_absolute():
        cwd = Path(event["cwd"])
        if not cwd.is_absolute():
            raise ValueError("unexpected working directory")
        path = cwd / path
    lexical_path = Path(os.path.abspath(path))
    resolved_path = path.resolve()
    for root in raw_roots:
        lexical_root = Path(os.path.abspath(root))
        resolved_root = Path(root).resolve()
        if lexical_path.is_relative_to(lexical_root) or resolved_path.is_relative_to(resolved_root):
            return "PROTECTED_PATH"
        # Filesystems can be case-insensitive even when Path comparisons are not.
        if resolved_root.is_dir():
            for parent in resolved_path.parents:
                if parent.is_dir() and parent.samefile(resolved_root):
                    return "PROTECTED_PATH"
    return None


def read_is_text(response):
    if not isinstance(response, dict) or response.get("type") != "text":
        return False
    file = response.get("file")
    return (isinstance(file, dict)
            and all(isinstance(file.get(key), str) for key in ("filePath", "content"))
            and all(type(file.get(key)) is int for key in ("numLines", "startLine", "totalLines")))


def inspect_tool(response, lane, entities):
    if lane == "bash":
        if (not isinstance(response, dict)
                or not all(isinstance(response.get(key), str) for key in ("stdout", "stderr"))
                or not all(type(response.get(key)) is bool for key in ("interrupted", "isImage"))):
            raise ValueError("unsupported Bash result")
        if response["isImage"]:
            raise ValueError("opaque Bash result")
    elif lane == "read":
        if not read_is_text(response):
            raise ValueError("unsupported Read result")
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


def tool_shape(response, lane):
    if lane == "bash":
        return "bash_interrupted" if isinstance(response, dict) and response.get("interrupted") is True else "bash"
    if lane == "read":
        return "read_text" if read_is_text(response) else "tool"
    if isinstance(response, str):
        return "mcp_text"
    if isinstance(response, list):
        return "mcp_list"
    return "mcp_object" if isinstance(response, dict) else "tool"


def tool_replacement(shape, reason):
    if shape in ("bash", "bash_interrupted"):
        output = {"stdout": reason, "stderr": "", "interrupted": shape == "bash_interrupted", "isImage": False}
    elif shape == "read_text":
        output = {"type": "text", "file": {
            "filePath": "[REDACTED]", "content": reason, "numLines": 1, "startLine": 1, "totalLines": 1,
        }}
    elif shape == "mcp_text":
        output = reason
    elif shape in ("mcp_list", "mcp_object"):
        content = [{"type": "text", "text": reason}]
        output = {"content": content} if shape == "mcp_object" else content
    else:
        return {"systemMessage": f"{reason} The tool result's replacement could not be verified."}
    # Claude's PostToolUse "block" alone leaves the original result model-visible.
    return {"hookSpecificOutput": {"hookEventName": TOOL, "updatedToolOutput": output}}


def check_hook(event_name, lane):
    shape = "prompt" if event_name == PROMPT else "pre_read" if event_name == PRE_TOOL else None
    if shape is not None:
        emit_shape(shape)
    try:
        event = read_hook_event(event_name, MAX_BYTES)
        if event_name == PROMPT:
            value = event["prompt"]
            if not isinstance(value, str):
                raise ValueError("unsupported prompt")
            return scan_kind(value, local_entities())
        tool_name = event["tool_name"]
        if lane == "mcp":
            valid_tool = isinstance(tool_name, str) and tool_name.startswith("mcp__")
        else:
            valid_tool = tool_name == {"bash": "Bash", "read": "Read"}[lane]
        if not valid_tool:
            raise ValueError("unexpected tool")
        if event_name == PRE_TOOL:
            return check_protected_read(event)
        response = event["tool_response"]
        shape = tool_shape(response, lane)
        emit_shape(shape)
        return inspect_tool(response, lane, local_entities())
    except Exception:
        if shape is None:
            emit_shape("bash" if lane == "bash" else "tool")
        return "error"


def decision(event_name, lane):
    arguments = [event_name, lane] if lane else [event_name]
    verdict = supervise(__file__, arguments)
    if verdict.status == "allow":
        return None
    if verdict.status == "timeout":
        reason = CHECK_TIMEOUT
    elif verdict.kind == "PROTECTED_PATH":
        reason = PROTECTED_READ
    elif verdict.status == "match":
        reason = f"{SENSITIVE} [{verdict.kind}]" if event_name == PROMPT else SENSITIVE
    else:
        reason = CHECK_ERROR
    if event_name == PROMPT:
        return {
            "decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": PROMPT, "suppressOriginalPrompt": True},
        }
    if event_name == PRE_TOOL:
        return {"hookSpecificOutput": {"hookEventName": PRE_TOOL, "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return tool_replacement(verdict.shape or ("bash" if lane == "bash" else None), reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", choices=(PROMPT, TOOL, PRE_TOOL))
    parser.add_argument("lane", nargs="?", choices=("bash", "mcp", "read"))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if ((args.event == PROMPT) != (args.lane is None)
            or (args.event == PRE_TOOL and args.lane != "read")):
        parser.error("invalid lane for event")
    if args.worker:
        emit_status(check_hook(args.event, args.lane))
        return
    result = decision(args.event, args.lane)
    if result is not None:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
