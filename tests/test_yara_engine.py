"""
Tests for yaratrix.yara_engine — file and directory scanning.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yara

from yaratrix.models import RuleMatch, ScanResult, Severity
from yaratrix.yara_engine import scan_directory, scan_file

# Inline YARA rule strings (same as conftest fixtures but usable as module-level constants)
RULE_POWERSHELL = """
rule Suspicious_PowerShell_EncodedCommand {
    meta:
        mitre_technique = "T1059.001"
        mitre_tactic    = "execution"
        severity        = "high"
        description     = "Detects encoded PowerShell commands"
    strings:
        $enc = "EncodedCommand" nocase
        $enc2 = "-EncodedCommand" nocase
    condition:
        any of them
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
        $sekurlsa = "sekurlsa" nocase
    condition:
        any of them
}
"""



# ─────────────────────────────────────────────────────────────────────────────
#  scan_file — basic matching
# ─────────────────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_match_found_for_ps_file(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        assert isinstance(result, ScanResult)
        assert len(result.matches) >= 1

    def test_no_match_for_clean_file(
        self, compiled_ps_rule: yara.Rules, clean_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, clean_sample_file)
        assert result.matches == []

    def test_correct_rule_name_in_match(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        names = {m.rule_name for m in result.matches}
        assert "Suspicious_PowerShell_EncodedCommand" in names

    def test_match_has_correct_technique(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        techniques = {m.mitre_technique for m in result.matches}
        assert "T1059.001" in techniques

    def test_match_has_correct_tactic(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        tactics = {m.mitre_tactic for m in result.matches}
        assert "execution" in tactics

    def test_match_has_correct_severity(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        severities = {m.severity for m in result.matches}
        assert Severity.HIGH in severities

    def test_result_has_duration_ms(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        assert result.duration_ms >= 0.0

    def test_result_has_scan_time(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        assert result.scan_time is not None

    def test_lsass_rule_matches_bat_file(
        self, compiled_lsass_rule: yara.Rules, bat_sample_file: Path
    ):
        result = scan_file(compiled_lsass_rule, bat_sample_file)
        assert len(result.matches) >= 1
        assert any(m.mitre_technique == "T1003.001" for m in result.matches)

    def test_multiple_rules_can_match_same_file(
        self, compiled_multi_rules: yara.Rules, bat_sample_file: Path
    ):
        """LSASS rule should fire on .bat; PS rule should not."""
        result = scan_file(compiled_multi_rules, bat_sample_file)
        names = {m.rule_name for m in result.matches}
        assert "LSASS_Memory_Access" in names

    def test_matched_strings_present(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        assert len(result.matches) > 0
        # At least one match should have captured strings
        total_strings = sum(len(m.matched_strings) for m in result.matches)
        assert total_strings >= 1

    def test_errors_empty_on_clean_scan(
        self, compiled_ps_rule: yara.Rules, clean_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, clean_sample_file)
        assert result.errors == []

    def test_target_file_in_result(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        result = scan_file(compiled_ps_rule, ps_sample_file)
        assert result.target_file.endswith(ps_sample_file.name)

    def test_to_dict_is_serialisable(
        self, compiled_ps_rule: yara.Rules, ps_sample_file: Path
    ):
        import json
        result = scan_file(compiled_ps_rule, ps_sample_file)
        d = result.to_dict()
        serialised = json.dumps(d)  # must not raise
        assert isinstance(serialised, str)


# ─────────────────────────────────────────────────────────────────────────────
#  scan_file — rule_file_map
# ─────────────────────────────────────────────────────────────────────────────

class TestScanFileRuleMap:
    def test_rule_file_map_recorded_in_match(
        self, rule_yar_file: Path, ps_sample_file: Path, tmp_path: Path
    ):
        """When rule_file_map is provided, each match should record its source file."""
        compiled = yara.compile(filepath=str(rule_yar_file))
        rule_file_map = {"ns_test": str(rule_yar_file)}
        result = scan_file(compiled, ps_sample_file, rule_file_map=rule_file_map)
        assert len(result.matches) > 0
        for match in result.matches:
            assert match.rule_file != ""


# ─────────────────────────────────────────────────────────────────────────────
#  scan_directory
# ─────────────────────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_scans_multiple_files(
        self, compiled_multi_rules: yara.Rules, multi_sample_dir: Path
    ):
        summary = scan_directory(compiled_multi_rules, multi_sample_dir)
        assert summary.total_files() >= 2

    def test_files_with_matches_returns_only_hits(
        self, compiled_multi_rules: yara.Rules, multi_sample_dir: Path
    ):
        summary = scan_directory(compiled_multi_rules, multi_sample_dir)
        for result in summary.files_with_matches():
            assert len(result.matches) > 0

    def test_clean_files_have_no_matches(
        self, compiled_ps_rule: yara.Rules, multi_sample_dir: Path
    ):
        summary = scan_directory(compiled_ps_rule, multi_sample_dir)
        clean = [r for r in summary.results if not r.matches]
        # clean.txt should have no matches
        assert any("clean" in r.target_file for r in clean)

    def test_progress_callback_called(
        self, compiled_multi_rules: yara.Rules, multi_sample_dir: Path
    ):
        calls: list[tuple[int, int, str]] = []

        def cb(current: int, total: int, filename: str) -> None:
            calls.append((current, total, filename))

        scan_directory(compiled_multi_rules, multi_sample_dir, on_progress=cb)
        assert len(calls) > 0
        # Current should be monotonically increasing
        for i in range(1, len(calls)):
            assert calls[i][0] >= calls[i - 1][0]

    def test_total_matches_sums_across_files(
        self, compiled_multi_rules: yara.Rules, multi_sample_dir: Path
    ):
        summary = scan_directory(compiled_multi_rules, multi_sample_dir)
        manual_total = sum(len(r.matches) for r in summary.results)
        assert summary.total_matches() == manual_total

    def test_nonexistent_dir_raises(self, compiled_ps_rule: yara.Rules):
        with pytest.raises(FileNotFoundError):
            scan_directory(compiled_ps_rule, Path("/nonexistent/dir/xyz"))

    def test_summary_to_dict_is_serialisable(
        self, compiled_multi_rules: yara.Rules, multi_sample_dir: Path
    ):
        import json
        summary = scan_directory(compiled_multi_rules, multi_sample_dir)
        d = summary.to_dict()
        serialised = json.dumps(d)
        assert isinstance(serialised, str)
