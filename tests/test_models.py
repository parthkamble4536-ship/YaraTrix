"""
Tests for yaratrix.models — core data structures.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from yaratrix.models import (
    DirectoryScanSummary,
    MatchedString,
    RuleMatch,
    ScanResult,
    Severity,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Severity enum
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverity:
    def test_values_are_lowercase_strings(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_all_five_levels_exist(self):
        levels = {s.value for s in Severity}
        assert levels == {"critical", "high", "medium", "low", "info"}

    def test_severity_is_string_subclass(self):
        # Severity(str, Enum) — should compare equal to its string value.
        assert Severity.HIGH == "high"


# ─────────────────────────────────────────────────────────────────────────────
#  MatchedString
# ─────────────────────────────────────────────────────────────────────────────

class TestMatchedString:
    def test_to_dict_encodes_bytes_as_hex(self):
        ms = MatchedString(identifier="$enc", offset=42, data=b"\xde\xad\xbe\xef")
        d = ms.to_dict()
        assert d["identifier"] == "$enc"
        assert d["offset"] == 42
        assert d["data"] == "deadbeef"

    def test_empty_data(self):
        ms = MatchedString(identifier="$s", offset=0, data=b"")
        assert ms.to_dict()["data"] == ""


# ─────────────────────────────────────────────────────────────────────────────
#  RuleMatch
# ─────────────────────────────────────────────────────────────────────────────

def _make_match(**overrides) -> RuleMatch:
    defaults = dict(
        rule_name="Test_Rule",
        rule_file="/rules/test.yar",
        mitre_technique="T1059.001",
        mitre_tactic="execution",
        severity=Severity.HIGH,
        description="Test rule",
    )
    defaults.update(overrides)
    return RuleMatch(**defaults)


class TestRuleMatch:
    def test_technique_ids_single(self):
        m = _make_match(mitre_technique="T1059.001")
        assert m.technique_ids() == ["T1059.001"]

    def test_technique_ids_multiple(self):
        m = _make_match(mitre_technique="T1059.001,T1027")
        assert m.technique_ids() == ["T1059.001", "T1027"]

    def test_technique_ids_with_spaces(self):
        m = _make_match(mitre_technique=" T1059.001 , T1027 ")
        assert m.technique_ids() == ["T1059.001", "T1027"]

    def test_tactic_names_single(self):
        m = _make_match(mitre_tactic="execution")
        assert m.tactic_names() == ["execution"]

    def test_tactic_names_multiple(self):
        m = _make_match(mitre_tactic="execution,defense-evasion")
        assert m.tactic_names() == ["execution", "defense-evasion"]

    def test_tactic_names_normalised_to_lowercase(self):
        m = _make_match(mitre_tactic="Execution,Defense-Evasion")
        assert m.tactic_names() == ["execution", "defense-evasion"]

    def test_to_dict_structure(self):
        ms = MatchedString("$x", 0, b"test")
        m = _make_match(matched_strings=[ms])
        d = m.to_dict()
        assert d["rule_name"] == "Test_Rule"
        assert d["severity"] == "high"
        assert len(d["matched_strings"]) == 1

    def test_empty_technique_ids_on_empty_string(self):
        m = _make_match(mitre_technique="")
        assert m.technique_ids() == []


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult
# ─────────────────────────────────────────────────────────────────────────────

def _make_scan_result(*matches: RuleMatch) -> ScanResult:
    return ScanResult(
        target_file="/tmp/test.ps1",
        scan_time=datetime.now(tz=timezone.utc),
        duration_ms=12.5,
        matches=list(matches),
    )


class TestScanResult:
    def test_matched_techniques_deduped(self):
        m1 = _make_match(mitre_technique="T1059.001")
        m2 = _make_match(mitre_technique="T1059.001")  # duplicate
        m3 = _make_match(mitre_technique="T1027")
        result = _make_scan_result(m1, m2, m3)
        techs = result.matched_techniques()
        assert techs.count("T1059.001") == 1
        assert "T1027" in techs
        assert len(techs) == 2

    def test_matched_tactics_deduped(self):
        m1 = _make_match(mitre_tactic="execution")
        m2 = _make_match(mitre_tactic="execution")
        m3 = _make_match(mitre_tactic="persistence")
        result = _make_scan_result(m1, m2, m3)
        tactics = result.matched_tactics()
        assert tactics.count("execution") == 1
        assert "persistence" in tactics

    def test_severity_counts_all_zero_when_no_matches(self):
        result = _make_scan_result()
        counts = result.severity_counts()
        assert all(v == 0 for v in counts.values())
        assert set(counts.keys()) == {"critical", "high", "medium", "low", "info"}

    def test_severity_counts_correct(self):
        m1 = _make_match(severity=Severity.CRITICAL)
        m2 = _make_match(severity=Severity.HIGH)
        m3 = _make_match(severity=Severity.HIGH)
        result = _make_scan_result(m1, m2, m3)
        counts = result.severity_counts()
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 0

    def test_to_dict_contains_required_keys(self):
        result = _make_scan_result()
        d = result.to_dict()
        required = {"target_file", "scan_time", "duration_ms", "match_count", "techniques", "tactics", "severity_counts", "matches", "errors"}
        assert required.issubset(d.keys())

    def test_match_count_in_dict(self):
        m1 = _make_match()
        m2 = _make_match()
        result = _make_scan_result(m1, m2)
        assert result.to_dict()["match_count"] == 2


# ─────────────────────────────────────────────────────────────────────────────
#  DirectoryScanSummary
# ─────────────────────────────────────────────────────────────────────────────

class TestDirectoryScanSummary:
    def _make_summary(self, *results: ScanResult) -> DirectoryScanSummary:
        return DirectoryScanSummary(
            root_path="/tmp/testdir",
            scan_time=datetime.now(tz=timezone.utc),
            results=list(results),
        )

    def test_total_files(self):
        r1 = _make_scan_result()
        r2 = _make_scan_result()
        summary = self._make_summary(r1, r2)
        assert summary.total_files() == 2

    def test_total_matches(self):
        m = _make_match()
        r1 = _make_scan_result(m, m)
        r2 = _make_scan_result(m)
        summary = self._make_summary(r1, r2)
        assert summary.total_matches() == 3

    def test_files_with_matches_filters_clean(self):
        r_with = _make_scan_result(_make_match())
        r_clean = _make_scan_result()
        summary = self._make_summary(r_with, r_clean)
        assert len(summary.files_with_matches()) == 1
        assert summary.files_with_matches()[0] is r_with

    def test_to_dict_structure(self):
        summary = self._make_summary()
        d = summary.to_dict()
        assert "root_path" in d
        assert "total_files_scanned" in d
        assert "total_matches" in d
