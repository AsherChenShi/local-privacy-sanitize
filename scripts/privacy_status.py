#!/usr/bin/env python3
"""Inspect local plugin installation and configuration without running either host."""

import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from sanitize import MAX_BYTES, Rejected, read_local

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10 can inspect the tables written by Codex.
    tomllib = None


MARKETPLACE = "local-privacy-tools"
CODEX_PLUGIN = f"codex-privacy@{MARKETPLACE}"
CLAUDE_PLUGIN = f"claude-privacy@{MARKETPLACE}"
EVENTS = {
    "UserPromptSubmit": "user_prompt_submit",
    "PostToolUse": "post_tool_use",
}
CLAUDE_FAILURE_BLOCK_VERSION = (2, 1, 295)
PUBLIC_LINK = "https://github.com/octocat/Hello-World"
TOKEN_LINK = PUBLIC_LINK + "?token=SYNTHETIC_ONLY"
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
HASH_RECORD = re.compile(r'(?:sha256:)?[a-fA-F0-9]{64}')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def read_metadata(path, parser):
    """Return only a fixed status when metadata is missing or unsafe to interpret."""
    try:
        text = read_local(path, MAX_BYTES, {".json", ".toml"})
        value = parser(text)
        if not isinstance(value, dict):
            raise ValueError("expected metadata object")
        return "read", value
    except FileNotFoundError:
        return "missing", {}
    except (OSError, ValueError, Rejected, RecursionError):
        return "unreadable", {}


def json_object(text):
    return json.loads(text, object_pairs_hook=unique_object)


def object_member(value, key):
    entry = value.get(key)
    return entry if isinstance(entry, dict) else {}


def flag(value):
    return value if type(value) is bool else None


def version_number(value):
    return value if isinstance(value, str) and VERSION.fullmatch(value) else None


def hook_id(event):
    return f"{CODEX_PLUGIN}:hooks/hooks.json:{event}:0:0"


def read_codex_tables(text):
    if tomllib is not None:
        return tomllib.loads(text)

    # The fallback recognizes only the literal tables emitted by Codex. A
    # multi-line string could contain these same lines, so leave that file unknown.
    if '\"\"\"' in text or "'''" in text:
        raise ValueError("unsupported TOML syntax")
    plugin = {}
    features = {}
    states = {hook_id(event): {} for event in EVENTS.values()}
    target_tables = {f'[plugins."{CODEX_PLUGIN}"]': plugin, "[features]": features}
    target_tables.update({f'[hooks.state."{name}"]': value for name, value in states.items()})
    observed = set()
    table = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            header = line.split("#", 1)[0].rstrip()
            table = target_tables.get(header)
            if table is not None:
                if header in observed:
                    raise ValueError("duplicate table")
                observed.add(header)
        if table is None:
            continue
        match = re.fullmatch(r'(enabled|hooks|trusted_hash|trusted_content_hash)\s*=\s*(true|false|"[^"]*")(?:\s*#.*)?', line)
        if match:
            key, value = match.groups()
            if key in table:
                raise ValueError("duplicate key")
            table[key] = json.loads(value)
    return {"plugins": {CODEX_PLUGIN: plugin}, "hooks": {"state": states}, "features": features}


def codex_cache(config_dir):
    root = config_dir / "plugins" / "cache" / MARKETPLACE / "codex-privacy"
    try:
        versions = []
        unreadable = False
        for directory in root.iterdir():
            if not version_number(directory.name):
                continue
            status, manifest = read_metadata(directory / ".codex-plugin" / "plugin.json", json_object)
            if status == "read" and manifest.get("name") == "codex-privacy" and manifest.get("version") == directory.name:
                versions.append(directory.name)
            else:
                unreadable = True
        return {"versions": sorted(versions), "status": "partial" if unreadable else "read"}
    except FileNotFoundError:
        return {"versions": [], "status": "missing"}
    except OSError:
        return {"versions": [], "status": "unreadable"}


def codex_status(config_dir):
    config_status, config = read_metadata(config_dir / "config.toml", read_codex_tables)
    plugin = object_member(object_member(config, "plugins"), CODEX_PLUGIN)
    states = object_member(object_member(config, "hooks"), "state")
    events = {}
    for name, event in EVENTS.items():
        state = object_member(states, hook_id(event))
        trust_record = any(
            isinstance(state.get(key), str) and HASH_RECORD.fullmatch(state[key])
            for key in ("trusted_hash", "trusted_content_hash")
        )
        events[name] = {
            "configured_enabled": flag(state.get("enabled")),
            "trust": "recorded_unverified" if trust_record else "unverified",
        }
    return {
        "metadata_status": config_status,
        "configured_enabled": flag(plugin.get("enabled")),
        "hooks_feature_enabled": flag(object_member(config, "features").get("hooks")),
        "local_plugin_cache": codex_cache(config_dir),
        "hooks": events,
        "runtime_hook_support": "unverified",
    }


def claude_settings(path):
    status, config = read_metadata(path, json_object)
    return {
        "metadata_status": status,
        "configured_enabled": flag(object_member(config, "enabledPlugins").get(CLAUDE_PLUGIN)),
        "all_hooks_disabled": flag(config.get("disableAllHooks")),
    }


def claude_installations(config_dir, project):
    status, data = read_metadata(config_dir / "plugins" / "installed_plugins.json", json_object)
    matches = object_member(data, "plugins").get(CLAUDE_PLUGIN, [])
    if status != "read" or data.get("version") != 2 or not isinstance(matches, list):
        return {"metadata_status": status if status != "read" else "unrecognized", "entries": []}
    entries = set()
    unknown_entries = False
    for match in matches:
        if not isinstance(match, dict):
            unknown_entries = True
            continue
        scope = match.get("scope")
        version = version_number(match.get("version"))
        if scope not in ("user", "project", "local", "managed") or version is None:
            unknown_entries = True
        elif scope in ("user", "managed"):
            entries.add((scope, version))
        elif isinstance(match.get("projectPath"), str) and Path(match["projectPath"]) == project:
            entries.add((scope, version))
        elif not isinstance(match.get("projectPath"), str):
            unknown_entries = True
    return {
        "metadata_status": "partial" if unknown_entries else "read",
        "entries": [{"scope": scope, "version": version} for scope, version in sorted(entries)],
    }


def claude_status(config_dir, project, version):
    capability = "unknown"
    if version is not None:
        supported = tuple(map(int, version.split("."))) >= CLAUDE_FAILURE_BLOCK_VERSION
        capability = "documented_supported" if supported else "below_documented_minimum"
    return {
        "settings": {
            "user": claude_settings(config_dir / "settings.json"),
            "project": claude_settings(project / ".claude" / "settings.json"),
            "local": claude_settings(project / ".claude" / "settings.local.json"),
        },
        "install_registry": claude_installations(config_dir, project),
        "hook_trust": "unverified",
        "runtime_version_supplied": version,
        "command_hook_failure_blocking": capability,
    }


def protection_notice(host, status):
    if host == "codex":
        disabled = (status["configured_enabled"] is False or status["hooks_feature_enabled"] is False
                    or any(hook["configured_enabled"] is False for hook in status["hooks"].values()))
    else:
        disabled = all(scope["configured_enabled"] in (None, False) for scope in status["settings"].values()) and any(
            scope["configured_enabled"] is False for scope in status["settings"].values())
        disabled = disabled or status["settings"]["user"]["all_hooks_disabled"] is True
    return {
        "protection_status": "not_protected" if disabled else "unverified",
        "message_zh": ("当前配置有关闭的检查，相关发送路径未受保护。请先本地预检。" if disabled else
                       "当前会话的 Hook 尚未验证。敏感内容请按未受保护处理，先本地预检。"),
        "local_preflight": "python3 scripts/sanitize.py sanitize --input draft.md --out-dir out/review",
        "local_preflight_window": "python3 scripts/preflight.py",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=("codex", "claude"))
    parser.add_argument("--config-dir", type=Path, help="Override the host's user configuration directory")
    parser.add_argument("--project", type=Path, default=Path.cwd(),
                        help="Claude Code project root to inspect (default: current directory)")
    parser.add_argument("--runtime-version", help="Claude Code version shown by the host, such as 2.1.295")
    args = parser.parse_args(argv)
    version = version_number(args.runtime_version)
    if args.runtime_version is not None and (args.host != "claude" or version is None):
        parser.error("--runtime-version requires claude and a numeric version such as 2.1.295")

    if args.host == "codex":
        config_dir = args.config_dir or Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
        status = codex_status(config_dir)
    else:
        config_dir = args.config_dir or Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
        status = claude_status(config_dir, args.project.absolute(), version)
    report = {
        "host": args.host,
        "local_configuration": status,
        "hook_execution": "not_verified",
        **protection_notice(args.host, status),
        "verification": {
            "instruction": "Check hook enable and trust in the host. In a new local session, submit these fictional test prompts separately.",
            "expect_pass": f"Reply only TEST_OK. Public link: {PUBLIC_LINK}",
            "expect_block": f"Reply only TEST_OK. Fictional token link: {TOKEN_LINK}",
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
