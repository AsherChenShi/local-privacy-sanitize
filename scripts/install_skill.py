#!/usr/bin/env python3
"""Install only the skill payload; never overwrite an existing installation."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

PAYLOAD = (
    "SKILL.md",
    "agents/openai.yaml",
    "scripts/sanitize.py",
    "scripts/structured_redaction.py",
    "scripts/review_policy.py",
    "scripts/review_preview.py",
    "references/privacy-boundary.md",
    "references/architecture.md",
)


def install(source, destination):
    source, destination = Path(source), Path(destination)
    for relative in PAYLOAD:
        file = source / relative
        if file.is_symlink() or not file.is_file():
            raise ValueError("INVALID_PAYLOAD")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)  # Exclusive. An existing skill is never replaced.
    try:
        for relative in PAYLOAD:
            output = destination / relative
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (source / relative).open("rb") as reader, output.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
            output.chmod(0o600)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return len(PAYLOAD)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("codex", "claude"), default="codex")
    parser.add_argument("--destination", type=Path, help="Optional explicit destination for testing or project scope")
    args = parser.parse_args(argv)
    base = (Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills"
            if args.target == "codex" else Path.home() / ".claude" / "skills")
    destination = args.destination or base / "local-privacy-sanitize"
    try:
        count = install(Path(__file__).resolve().parents[1], destination)
    except (OSError, ValueError):
        print(json.dumps({"status": "INSTALL_BLOCKED", "reason": "EXISTING_TARGET_OR_IO_ERROR"}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "INSTALLED", "files": count, "target": args.target}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
