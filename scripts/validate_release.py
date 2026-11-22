#!/usr/bin/env python3
"""Dependency-free structural and documentation checks for this skill package."""
import ast
import json
from pathlib import Path
import re
import sys


def validate(root):
    errors = []
    root = Path(root)
    required = (
        "SKILL.md", "README.md", "README.en.md", "agents/openai.yaml", ".gitignore",
        "scripts/sanitize.py", "scripts/install_skill.py", "scripts/validate_release.py",
        "scripts/hook_supervisor.py", "scripts/structured_redaction.py", "tests/hook_smoke_fixtures.py",
        "tests/test_structured_redaction.py", "tests/test_hook_supervisor.py", "references/architecture.md",
        "scripts/review_policy.py", "scripts/review_preview.py", "tests/test_preview_integration.py",
        "tests/test_review_policy.py", "tests/test_review_preview.py",
        "scripts/signup_broker.py", "scripts/signup_browser.py", "scripts/signup_local.py", "scripts/signup_mcp.py",
        "references/signup-lab.md", "tests/signup_fixtures.py", "tests/signup_smoke.py",
        "tests/test_signup_broker.py", "tests/test_signup_browser.py", "tests/test_signup_local.py", "tests/test_signup_mcp.py",
        "references/privacy-boundary.md", "examples/entities.example.json",
        "examples/input.example.txt", "tests/test_sanitize.py", "tests/test_package.py",
        "scripts/codex_privacy.py", "tests/test_codex_privacy.py", "tests/codex_smoke.py",
        "scripts/build_codex_plugin.py", "tests/test_desktop_plugin.py",
        "desktop/marketplace.json", "desktop/plugin.json", "desktop/hooks.json",
        "scripts/claude_privacy.py", "scripts/build_claude_plugin.py",
        "claude-desktop/marketplace.json", "claude-desktop/plugin.json", "claude-desktop/hooks.json",
        "tests/test_claude_plugin.py", "tests/claude_smoke.py",
        "tests/test_public_urls.py", "tests/url_smoke_fixtures.py",
        "scripts/privacy_status.py", "tests/test_privacy_status.py", "tests/privacy_smoke_fixtures.py",
        ".github/workflows/ci.yml",
    )
    for relative in required:
        if not (root / relative).is_file() or (root / relative).is_symlink():
            errors.append("missing_or_symlink_payload")
    if errors:
        return errors
    skill = (root / "SKILL.md").read_text(encoding="utf-8")
    front = re.match(r"\A---\nname: ([^\n]+)\ndescription: ([^\n]+)\n---\n", skill)
    if not front or front.group(1) != "local-privacy-sanitize" or len(front.group(2)) > 1024:
        errors.append("invalid_frontmatter")
    if "[TODO:" in skill:
        errors.append("unfinished_scaffold")
    for relative in ("README.md", "README.en.md", "SKILL.md",
                     "references/privacy-boundary.md", "references/architecture.md", "references/signup-lab.md"):
        content = (root / relative).read_text(encoding="utf-8")
        for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
            if "://" not in link and not link.startswith("#"):
                target = ((root / relative).parent / link.split("#")[0]).resolve()
                if not target.is_relative_to(root.resolve()) or not target.is_file():
                    errors.append("broken_local_documentation_link")
        if re.search(r"/Users/|/home/|ghp_[A-Za-z0-9]{30,}", content):
            errors.append("private_path_or_credential_in_documentation")
    interface = (root / "agents/openai.yaml").read_text(encoding="utf-8")
    values = {}
    for line in interface.splitlines()[1:]:
        match = re.fullmatch(r"  ([a-z_]+): (\".*\")", line)
        if not match:
            errors.append("invalid_interface_metadata")
            continue
        try:
            values[match.group(1)] = json.loads(match.group(2))
        except ValueError:
            errors.append("invalid_interface_string")
    if not 25 <= len(values.get("short_description", "")) <= 64:
        errors.append("invalid_short_description")
    if "$local-privacy-sanitize" not in values.get("default_prompt", ""):
        errors.append("missing_skill_invocation")
    ignored = (root / ".gitignore").read_text().splitlines()
    if not {"private/", "raw/", "out/", "*.local.json", "*.local.txt", ".env"}.issubset(ignored):
        errors.append("missing_private_artifact_ignores")
    allowed = {"__future__", "argparse", "collections", "dataclasses", "hashlib", "ipaddress",
               "json", "os", "pathlib", "re", "stat", "sys", "tomllib", "unicodedata", "sanitize",
               "hook_supervisor", "structured_redaction", "review_policy", "review_preview"}
    extra_imports = {
        "scripts/hook_supervisor.py": {"selectors", "subprocess", "time"},
        "scripts/structured_redaction.py": {"bisect", "html"},
        "scripts/review_policy.py": {"bisect"},
        "scripts/review_preview.py": {"base64"},
    }
    for relative in ("scripts/sanitize.py", "scripts/claude_privacy.py", "scripts/privacy_status.py",
                     "scripts/structured_redaction.py", "scripts/hook_supervisor.py",
                     "scripts/review_policy.py", "scripts/review_preview.py"):
        allowed_imports = allowed | extra_imports.get(relative, set())
        source = (root / relative).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import) and any(alias.name.split(".")[0] not in allowed_imports for alias in node.names):
                errors.append("unexpected_runtime_dependency")
            if (isinstance(node, ast.ImportFrom) and node.module != "urllib.parse"
                    and (node.module or "").split(".")[0] not in allowed_imports):
                errors.append("unexpected_runtime_dependency")
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in {"system", "popen", "eval", "exec", "__import__"}:
                    errors.append("dynamic_or_external_execution")
    json.loads((root / "examples/entities.example.json").read_text(encoding="utf-8"))
    return errors


if __name__ == "__main__":
    errors = validate(Path(__file__).resolve().parents[1])
    print(json.dumps({"status": "FAILED" if errors else "PASSED", "errors": sorted(set(errors))}))
    sys.exit(1 if errors else 0)
