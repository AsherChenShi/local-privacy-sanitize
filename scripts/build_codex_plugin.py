"""Build the local Codex marketplace and an installable ZIP from public sources."""

import argparse
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SIGNUP_FILES = ("signup_browser.py", "signup_broker.py", "signup_local.py", "signup_mcp.py")
PLUGIN = Path("plugins/codex-privacy")
FILES = {
    Path(".agents/plugins/marketplace.json"): "desktop/marketplace.json",
    PLUGIN / ".codex-plugin/plugin.json": "desktop/plugin.json",
    PLUGIN / "hooks/hooks.json": "desktop/hooks.json",
    PLUGIN / "scripts/codex_privacy.py": "scripts/codex_privacy.py",
    PLUGIN / "scripts/sanitize.py": "scripts/sanitize.py",
    PLUGIN / "scripts/privacy_status.py": "scripts/privacy_status.py",
    PLUGIN / "scripts/hook_supervisor.py": "scripts/hook_supervisor.py",
    PLUGIN / "scripts/structured_redaction.py": "scripts/structured_redaction.py",
    PLUGIN / "scripts/review_policy.py": "scripts/review_policy.py",
    PLUGIN / "scripts/review_preview.py": "scripts/review_preview.py",
    **{PLUGIN / "scripts" / name: f"scripts/{name}" for name in SIGNUP_FILES},
}


def build(destination, files=FILES):
    destination.mkdir(parents=True)
    for target, source in files.items():
        path = destination / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / source).read_bytes())
    with zipfile.ZipFile(destination.with_suffix(".zip"), "x", zipfile.ZIP_DEFLATED) as archive:
        for target in files:
            archive.write(destination / target, str(Path(destination.name) / target))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New folder for the plugin marketplace")
    args = parser.parse_args()
    build(args.destination)
