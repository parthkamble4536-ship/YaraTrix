"""
Tests for yaratrix.rule_loader — rule discovery, validation, and compilation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yara

from yaratrix.rule_loader import load_rules


# ─────────────────────────────────────────────────────────────────────────────
#  Inline rule constants (mirrors conftest.py)
# ─────────────────────────────────────────────────────────────────────────────

RULE_POWERSHELL = """
rule Suspicious_PowerShell_EncodedCommand {
    meta:
        mitre_technique = "T1059.001"
        mitre_tactic    = "execution"
        severity        = "high"
        description     = "Detects encoded PowerShell commands"
    strings:
        $enc = "EncodedCommand" nocase
    condition:
        $enc
}
"""

RULE_LSASS = """
rule LSASS_Memory_Access {
    meta:
        mitre_technique = "T1003.001"
        mitre_tactic    = "credential-access"
        severity        = "critical"
        description     = "Detects LSASS memory access"
    strings:
        $lsass = "lsass.exe" nocase
    condition:
        $lsass
}
"""

RULE_MISSING_META = """
rule Missing_Meta_Rule {
    strings:
        $s = "test_string"
    condition:
        $s
}
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Happy-path: valid rules dir
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadRulesValid:
    def test_compiled_rules_not_none(self, rules_dir: Path):
        loader = load_rules(rules_dir)
        assert loader.compiled is not None

    def test_correct_number_of_filepaths(self, rules_dir: Path):
        loader = load_rules(rules_dir)
        # two .yar files from conftest fixture
        assert len(loader.filepaths) == 2

    def test_no_errors_for_valid_rules(self, rules_dir: Path):
        loader = load_rules(rules_dir)
        assert loader.errors == []

    def test_rules_are_iterable(self, rules_dir: Path):
        loader = load_rules(rules_dir)
        rules = list(loader.compiled)
        assert len(rules) == 2

    def test_rule_identifiers_present(self, rules_dir: Path):
        loader = load_rules(rules_dir)
        names = {r.identifier for r in loader.compiled}
        assert "Suspicious_PowerShell_EncodedCommand" in names
        assert "LSASS_Memory_Access" in names


# ─────────────────────────────────────────────────────────────────────────────
#  Single file
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadRulesSingleFile:
    def test_load_single_yar_file(self, rule_yar_file: Path, tmp_path: Path):
        """load_rules should accept a dir containing a single .yar file."""
        loader = load_rules(tmp_path)
        assert loader.compiled is not None
        rule_names = {r.identifier for r in loader.compiled}
        assert "Suspicious_PowerShell_EncodedCommand" in rule_names


# ─────────────────────────────────────────────────────────────────────────────
#  Missing meta validation
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadRulesValidation:
    def test_missing_meta_produces_warning(self, tmp_path: Path):
        """A rule without required meta fields should produce a warning."""
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "bad_rule.yar").write_text(RULE_MISSING_META, encoding="utf-8")

        loader = load_rules(bad_dir, strict=False)
        # Should still compile (non-strict mode)
        assert loader.compiled is not None
        # But report the validation issue
        assert len(loader.warnings) > 0 or len(loader.errors) > 0

    def test_strict_mode_raises_on_missing_meta(self, tmp_path: Path):
        """In strict mode, a rule with missing meta should prevent compilation."""
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "bad_rule.yar").write_text(RULE_MISSING_META, encoding="utf-8")

        with pytest.raises((SystemExit, ValueError, Exception)):
            load_rules(bad_dir, strict=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Error handling
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadRulesErrors:
    def test_nonexistent_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules(Path("/nonexistent/path/that/does/not/exist"))

    def test_empty_dir_returns_no_compiled_rules(self, tmp_path: Path):
        """An empty directory produces no compiled rules (compiled is None)."""
        loader = load_rules(tmp_path)
        assert loader.compiled is None or list(loader.compiled) == []

    def test_invalid_yara_syntax_does_not_crash(self, tmp_path: Path):
        """A syntactically invalid .yar file should be skipped gracefully."""
        bad_dir = tmp_path / "invalid"
        bad_dir.mkdir()
        (bad_dir / "invalid.yar").write_text(
            "rule BrokenRule { condition: this_is_not_valid_yara_syntax_xyz }",
            encoding="utf-8",
        )
        # Should not raise — bad files are skipped
        loader = load_rules(bad_dir, strict=False)
        # Either compiled is None or produced a warning
        assert loader.compiled is None or len(loader.errors) > 0 or len(loader.warnings) > 0
