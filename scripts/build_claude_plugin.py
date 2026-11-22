"""Build the Claude Code local marketplace and its distributable ZIP."""

import argparse
from pathlib import Path

from build_codex_plugin import build


PLUGIN = Path("plugins/claude-privacy")
FILES = {
    Path(".claude-plugin/marketplace.json"): "claude-desktop/marketplace.json",
    PLUGIN / ".claude-plugin/plugin.json": "claude-desktop/plugin.json",
    PLUGIN / "hooks/hooks.json": "claude-desktop/hooks.json",
    PLUGIN / "scripts/claude_privacy.py": "scripts/claude_privacy.py",
    PLUGIN / "scripts/sanitize.py": "scripts/sanitize.py",
    PLUGIN / "scripts/privacy_status.py": "scripts/privacy_status.py",
    PLUGIN / "scripts/hook_supervisor.py": "scripts/hook_supervisor.py",
    PLUGIN / "scripts/structured_redaction.py": "scripts/structured_redaction.py",
    PLUGIN / "scripts/review_policy.py": "scripts/review_policy.py",
    PLUGIN / "scripts/review_preview.py": "scripts/review_preview.py",
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New folder for the Claude Code marketplace")
    args = parser.parse_args()
    build(args.destination, FILES)
