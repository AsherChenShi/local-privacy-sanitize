#!/usr/bin/env python3
"""Opt-in local privacy controls for Codex UserPromptSubmit and PostToolUse."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile

from hook_supervisor import emit_shape, emit_status, read_hook_event, supervise
from review_policy import hook_entities
from sanitize import MAX_BYTES, MAX_POLICY_BYTES, Rejected, parse_policy, read_local, scan_kind


EVENT_FIELDS = {"UserPromptSubmit": "prompt", "PostToolUse": "tool_response"}
HOOK_LABEL = "local-privacy-sanitize"
BLOCK_MATCH = "检测到敏感信息。请在本地生成并复核脱敏副本，再重试。"
BLOCK_ERROR = "本地隐私检查未完成。请使用独立的本地预检并复核后再提交。"
BLOCK_TIMEOUT = "本地隐私检查超时。请使用独立的本地预检并复核后再提交。"
STATE_DIR = "local-privacy-sanitize"


def mode_file(config_dir):
    return config_dir / STATE_DIR / "mode.json"


def load_mode(path):
    state = json.loads(read_local(path, 128, {".json"}))
    if state == {"mode": "on"}:
        return "on"
    if state == {"mode": "off"}:
        return "off"
    raise ValueError("invalid mode")


def write_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".privacy-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def hook_definition(event, config_dir):
    argv = [sys.executable, "-E", "-S", str(Path(__file__).resolve()), "--config-dir",
            str(config_dir), "hook", event]
    return {
        "type": "command", "command": shlex.join(argv), "timeout": 10,
        "statusMessage": f"{HOOK_LABEL} [{event}]",
    }


def registration(config_dir, want_install):
    hooks_path = config_dir / "hooks.json"
    if not os.path.lexists(hooks_path):
        document = {}
    else:
        document = json.loads(read_local(hooks_path, MAX_BYTES, {".json"}))
    if not isinstance(document, dict):
        raise ValueError("invalid hooks document")
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("invalid hooks")

    added = False
    complete = True
    for event in EVENT_FIELDS:
        definition = hook_definition(event, config_dir)
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError("invalid hook groups")
        existing = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                raise ValueError("invalid hook group")
            for hook in group["hooks"]:
                if not isinstance(hook, dict):
                    raise ValueError("invalid hook")
                if str(hook.get("statusMessage", "")).startswith(HOOK_LABEL + " ["):
                    existing.append((group, hook))
        if existing:
            if (len(existing) != 1 or existing[0][1] != definition
                    or existing[0][0].get("matcher") not in (None, "", "*")):
                raise ValueError("conflicting privacy hook")
        elif want_install:
            groups.append({"hooks": [definition]})
            added = True
        else:
            complete = False
    return document, added, complete


def configure(config_dir, action):
    state = mode_file(config_dir)
    if state.parent.is_symlink():
        raise ValueError("symlink state directory")
    if action == "status":
        _, _, registered = registration(config_dir, False)
        mode = load_mode(state) if registered or os.path.lexists(state) else "off"
        return {"mode": mode, "hooks_registered": registered}
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(state.parent / "lock", flags, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == "off":
            # The user must be able to turn protection off even if hooks.json changed.
            write_json(state, {"mode": "off"})
            return {"mode": "off"}
        document, added, registered = registration(config_dir, action == "install")
        if action == "install":
            if not os.path.lexists(state):
                write_json(state, {"mode": "off"})
            mode = load_mode(state)
            if added:
                write_json(config_dir / "hooks.json", document)
        else:  # on
            if not registered:
                raise ValueError("install first")
            read_entities(state)
            mode = "on"
            write_json(state, {"mode": mode})
        return {"mode": mode, "hooks_registered": registered}


def read_entities(state):
    path = state.with_name("entities.local.json")
    if os.path.lexists(path):
        return parse_policy(read_local(path, MAX_POLICY_BYTES, {".json"}))
    return ()


def block(reason):
    print(json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False))
    return 0  # Codex consumes structured hook decisions from successful processes.


def check_hook(state, event, *, controlled_by_plugin=False):
    try:
        if not controlled_by_plugin and load_mode(state) == "off":
            return None
        payload = read_hook_event(event, MAX_BYTES)
        value = payload[EVENT_FIELDS[event]]
        if event == "UserPromptSubmit" and not isinstance(value, str):
            return "error"
        entities = hook_entities(read_entities(state), read_local=read_local)
        return scan_kind(value, entities)
    except Exception:
        return "error"


def run_hook(config_dir, action, event, *, worker):
    if worker:
        emit_shape("prompt" if event == "UserPromptSubmit" else "tool")
        emit_status(check_hook(mode_file(config_dir), event, controlled_by_plugin=action == "plugin-hook"))
        return 0
    verdict = supervise(__file__, ["--config-dir", str(config_dir), action, event])
    if verdict.status == "match":
        if event == "UserPromptSubmit":
            return block(f"{BLOCK_MATCH} [{verdict.kind}] 从安装包或仓库打开 open-preflight.command。")
        return block(BLOCK_MATCH)
    if verdict.status == "timeout":
        return block(BLOCK_TIMEOUT)
    if verdict.status != "allow":
        return block(BLOCK_ERROR)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path,
                        default=Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex"))
    parser.add_argument("action", choices=("install", "on", "off", "status", "hook", "plugin-hook"))
    parser.add_argument("event", nargs="?", choices=tuple(EVENT_FIELDS))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    config_dir = args.config_dir.expanduser().absolute()
    is_hook = args.action in ("hook", "plugin-hook")
    if is_hook and args.event:
        return run_hook(config_dir, args.action, args.event, worker=args.worker)
    if is_hook or args.event or args.worker:
        parser.error("event is required only for hook")
    try:
        print(json.dumps(configure(config_dir, args.action)))
    except (OSError, ValueError, Rejected, RecursionError):
        print("无法更新或读取隐私配置。请检查安装、权限或已有 Hook 定义。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
