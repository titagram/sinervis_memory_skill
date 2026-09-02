import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPOSITORY_ROOT / "skills" / "hindsight-project-memory"


class RepositoryContractTest(unittest.TestCase):
    def test_standard_skill_package_is_discoverable(self):
        self.assertTrue((SKILL_ROOT / "SKILL.md").is_file())
        self.assertTrue((SKILL_ROOT / "scripts" / "project_memory.py").is_file())
        self.assertTrue((SKILL_ROOT / "references").is_dir())

    def test_frontmatter_declares_standard_name_and_trigger_description(self):
        text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"\A---\n(?P<frontmatter>.*?)\n---\n", text, re.DOTALL)
        self.assertIsNotNone(match)
        frontmatter = match.group("frontmatter")
        self.assertIn("name: hindsight-project-memory", frontmatter)
        self.assertRegex(frontmatter, r"(?m)^description: Use when ")

    def test_all_local_markdown_links_resolve_inside_skill(self):
        link_pattern = re.compile(r"\[[^]]+\]\((?!https?://|#)([^)]+)\)")
        failures = []
        for markdown_path in sorted(SKILL_ROOT.rglob("*.md")):
            text = markdown_path.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(text):
                target = raw_target.split("#", 1)[0]
                resolved = (markdown_path.parent / target).resolve()
                if not resolved.is_relative_to(SKILL_ROOT.resolve()) or not resolved.exists():
                    failures.append(f"{markdown_path.relative_to(SKILL_ROOT)} -> {raw_target}")
        self.assertEqual([], failures)

    def test_skill_entrypoint_references_every_runtime_python_file_for_bundlers(self):
        skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        missing = [
            str(path.relative_to(SKILL_ROOT))
            for path in sorted((SKILL_ROOT / "scripts").rglob("*.py"))
            if str(path.relative_to(SKILL_ROOT)) not in skill_text
        ]
        self.assertEqual([], missing)

    def test_package_contains_no_machine_or_carnovali_specific_material(self):
        forbidden = (
            "/Users/gabriele",
            ".hindsight/codex.json",
            "sinervis-carnovali",
            "Carnovali",
        )
        failures = []
        for path in sorted(SKILL_ROOT.rglob("*")):
            if not path.is_file() or path.suffix in {".pyc", ".png", ".jpg"}:
                continue
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                if marker in text:
                    failures.append(f"{path.relative_to(SKILL_ROOT)} contains {marker!r}")
        self.assertEqual([], failures)

    def test_package_contains_no_generated_cache(self):
        generated = [
            str(path.relative_to(REPOSITORY_ROOT))
            for path in REPOSITORY_ROOT.rglob("*")
            if path.name == "__pycache__" or path.suffix == ".pyc"
        ]
        self.assertEqual([], generated)

    def test_readme_supports_url_only_installation(self):
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        required_fragments = (
            "https://github.com/titagram/sinervis_memory_skill.git",
            "npx skills add",
            "--agent codex",
            "--agent claude-code",
            "--global",
            "hermes skills install",
            "~/.codex/skills/hindsight-project-memory",
            "~/.claude/skills/hindsight-project-memory",
            "skills/hindsight-project-memory/SKILL.md",
            "destination already exists",
            "gh repo clone",
            "${CODEX_HOME:-$HOME/.codex}/skills",
            "custom `CODEX_HOME`",
            "git clone --depth 1 https://github.com/titagram/sinervis_memory_skill.git",
            "trap cleanup_skill_checkout EXIT",
            "set -e",
            'test -f "$skill_destination/SKILL.md"',
            'test -d "$skill_destination/references"',
            'test -d "$skill_destination/scripts"',
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, readme)

    def test_repository_does_not_ship_a_custom_installer(self):
        custom_installers = [
            path
            for path in REPOSITORY_ROOT.rglob("*")
            if path.is_file() and path.name.lower() in {"install.sh", "install.py", "install.js"}
        ]
        self.assertEqual([], custom_installers)

    def test_hermes_scanner_excludes_only_development_tests(self):
        ignore_path = SKILL_ROOT / ".skillignore"
        self.assertTrue(ignore_path.is_file())
        patterns = [
            line.strip()
            for line in ignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(["tests/"], patterns)


if __name__ == "__main__":
    unittest.main()
