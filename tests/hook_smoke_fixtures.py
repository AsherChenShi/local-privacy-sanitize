"""Fault injection and offline candidates for synthetic localhost native tests."""

from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FAKE_SECRET = "SYNTHETIC_PREFLIGHT_ONLY"
PRIVATE_URL = "https://service.private.invalid/synthetic"
FIXTURE_JSON = '{"access_token":"' + FAKE_SECRET + '","count":1200}'
FIXTURE_MARKDOWN = (
    "| Link | State |\n| --- | --- |\n| " + PRIVATE_URL + "| READY |\n\n"
    "```json\n" + FIXTURE_JSON + "\n```\n"
)


def reviewed_candidates(root):
    drafts = (("json", FIXTURE_JSON), ("md", FIXTURE_MARKDOWN))
    for extension, original in drafts:
        source = root / f"draft.{extension}"
        source.write_text(original, encoding="utf-8")
        bundle = root / f"candidate-{extension}"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/sanitize.py"), "sanitize",
             "--input", str(source), "--out-dir", str(bundle)],
            check=True, capture_output=True, timeout=10,
        )
        artifact = bundle / f"sanitized.{extension}"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/sanitize.py"), "check", "--input", str(artifact)],
            check=True, capture_output=True, timeout=10,
        )
        candidate = artifact.read_text(encoding="utf-8")
        assert FAKE_SECRET not in candidate and PRIVATE_URL not in candidate
        if extension == "json":
            assert json.loads(candidate) == {"access_token": "[SECRET_001]", "count": 1200}
        else:
            assert "| READY |" in candidate
            fenced = candidate.split("```json\n", 1)[1].split("\n```", 1)[0]
            assert json.loads(fenced)["count"] == 1200
        yield candidate


@contextmanager
def injected_fault(entrypoint, fault, *, in_worker=True, event=None, after_tool_shape=False):
    """Mutate only a test installation inside its temporary directory."""
    paths = (entrypoint,) if isinstance(entrypoint, Path) else entrypoint
    originals = {path.resolve(): path.read_bytes() for path in paths}
    entry = b'if __name__ == "__main__":'
    membership = "in" if in_worker else "not in"
    condition = f'if __name__ == "__main__" and "--worker" {membership} sys.argv:'
    if event:
        condition = condition[:-1] + f" and {event!r} in sys.argv:"
    action = {
        "hang": "import time; time.sleep(20)",
        "crash": "sys.exit(1)",
        "bad_output": "print('synthetic invalid hook verdict'); sys.exit(0)",
    }[fault]
    with tempfile.TemporaryDirectory(prefix="privacy-fault-") as directory:
        marker = Path(directory) / "injected-hook-ran"
        action = f"with open({str(marker)!r}, 'w') as privacy_test_marker: privacy_test_marker.write('ran')\n    {action}"
        if after_tool_shape:
            # Claude needs the result envelope before replacing a tool result.
            entry = b"def inspect_tool(response, lane, entities):\n"
            replacement = entry + f"    {action}\n".encode()
        else:
            replacement = f"{condition}\n    {action}\n\n".encode() + entry
        try:
            for path, original in originals.items():
                assert original.count(entry) == 1
                path.write_bytes(original.replace(entry, replacement, 1))
            yield
            assert marker.is_file(), f"The injected {fault} was not reached by the native Hook"
        finally:
            for path, original in originals.items():
                path.write_bytes(original)


@contextmanager
def changed_prompt_hook(manifest, **changes):
    paths = (manifest,) if isinstance(manifest, Path) else manifest
    originals = {path.resolve(): path.read_bytes() for path in paths}
    try:
        for path, original in originals.items():
            settings = json.loads(original)
            prompt_hook = settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]
            prompt_hook.update(changes)
            path.write_text(json.dumps(settings), encoding="utf-8")
        yield
    finally:
        for path, original in originals.items():
            path.write_bytes(original)
