import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("install_skill")
validator = load("validate_release")
builder = load("build_codex_plugin")


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_repository_passes_structural_validation(self):
        self.assertEqual(validator.validate(ROOT), [])

    def test_ci_preserves_supported_python_versions_on_available_runners(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        # JSON flow mappings are valid YAML. Compatibility comes from the
        # actions/python-versions manifest checked on 2026-11-16, not latest.
        available = {"3.9": {"ubuntu-22.04", "ubuntu-24.04"},
                     "3.12": {"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"},
                     "3.14": {"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"}}
        rows = [json.loads(row) for row in re.findall(r"^\s+- (\{.*\})$", workflow, re.M)]
        self.assertEqual({row["python-version"] for row in rows}, set(available))
        for row in rows:
            self.assertIn(row["os"], available[row["python-version"]])
        self.assertIn("runs-on: ${{ matrix.os }}", workflow)

    def test_install_only_curated_payload(self):
        destination = self.root / "installed"
        installer.install(ROOT, destination)
        files = sorted(str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(installer.PAYLOAD))
        for relative in installer.PAYLOAD:
            self.assertEqual((ROOT / relative).read_bytes(), (destination / relative).read_bytes())
        self.assertEqual((destination / "open-preflight.command").stat().st_mode & 0o777, 0o700)

    def test_installs_skill_into_custom_claude_config(self):
        config = self.root / "Claude config"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/install_skill.py"), "--target", "claude"],
                                env={**os.environ, "HOME": str(self.root), "CLAUDE_CONFIG_DIR": str(config)},
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["target"], "claude")
        self.assertTrue((config / "skills/local-privacy-sanitize/SKILL.md").is_file())
        self.assertFalse((self.root / ".claude").exists())

    def test_packaging_preserves_existing_outputs_and_cleans_failed_build(self):
        destination = self.root / "plugin-0.2.6"
        archive = self.root / "plugin-0.2.6.zip"
        archive.write_bytes(b"existing archive")
        with self.assertRaises(FileExistsError):
            builder.build(destination)
        self.assertFalse(destination.exists())
        self.assertEqual(archive.read_bytes(), b"existing archive")
        archive.unlink()
        with self.assertRaises(FileNotFoundError):
            builder.build(destination, {Path("missing"): "missing-source.txt"})
        self.assertFalse(destination.exists())
        self.assertFalse(archive.exists())
        builder.build(destination)
        self.assertTrue(archive.is_file())
        with self.assertRaises(FileExistsError):
            builder.build(destination)
        self.assertTrue((destination / ".agents/plugins/marketplace.json").is_file())

    def test_install_does_not_replace_existing_skill(self):
        destination = self.root / "installed"
        destination.mkdir()
        sentinel = destination / "SKILL.md"
        sentinel.write_text("existing user instructions")
        with self.assertRaises(FileExistsError):
            installer.install(ROOT, destination)
        self.assertEqual(sentinel.read_text(), "existing user instructions")

    def test_invalid_payload_is_rejected_before_install(self):
        destination = self.root / "installed"
        with self.assertRaises(ValueError):
            installer.install(self.root / "missing-source", destination)
        self.assertFalse(destination.exists())

    def copy_package(self):
        destination = self.root / "source"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "out"))
        return destination

    def test_missing_reference_is_reported(self):
        source = self.copy_package()
        with (source / "SKILL.md").open("a") as stream:
            stream.write("\n[missing](references/missing.md)\n")
        self.assertIn("broken_local_documentation_link", validator.validate(source))

    def test_network_dependency_is_rejected(self):
        source = self.copy_package()
        with (source / "scripts/sanitize.py").open("a") as stream:
            stream.write("\nimport socket\n")
        self.assertIn("unexpected_runtime_dependency", validator.validate(source))

    def test_symlink_payload_is_rejected(self):
        source = self.copy_package()
        file = source / "SKILL.md"
        content = self.root / "other.md"
        content.write_bytes(file.read_bytes())
        file.unlink()
        file.symlink_to(content)
        with self.assertRaises(ValueError):
            installer.install(source, self.root / "installed")

    def test_installed_payload_executes_without_repository(self):
        destination = self.root / "installed"
        installer.install(ROOT, destination)
        source = self.root / "demo.txt"
        source.write_text("demo@example.com")
        run = subprocess.run([sys.executable, str(destination / "scripts/sanitize.py"),
                              "sanitize", "--input", str(source), "--out-dir", str(self.root / "candidate"),
                              "--preview"],
                             capture_output=True, text=True, timeout=10, cwd=self.root)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["status"], "REVIEW_REQUIRED")
        preview = (self.root / "candidate/review.html").read_text(encoding="utf-8")
        self.assertIn("[EMAIL_001]", preview)
        self.assertNotIn("demo@example.com", preview)


if __name__ == "__main__":
    unittest.main()
