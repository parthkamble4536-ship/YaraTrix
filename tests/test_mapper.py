"""
Tests for yaratrix.mapper — ATT&CK mapping and confidence scoring.

All tests use a MockAttackClient that returns synthetic TechniqueInfo objects
so they run without the 46 MB STIX bundle.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from yaratrix.attack_client import TechniqueInfo, MitigationInfo
from yaratrix.mapper import (
    _compute_confidence,
    _compute_threat_level,
    _build_narrative,
    map_scan_result,
    MappingResult,
)
from yaratrix.models import RuleMatch, ScanResult, Severity


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_technique(technique_id: str, tactics: list[str], name: str = "") -> TechniqueInfo:
    return TechniqueInfo(
        technique_id=technique_id,
        name=name or technique_id,
        tactics=tactics,
        description="Test technique.",
        url=f"https://attack.mitre.org/techniques/{technique_id}/",
        is_subtechnique="." in technique_id,
        parent_technique_id=technique_id.split(".")[0] if "." in technique_id else "",
        sub_techniques=[],
        mitigations=[
            MitigationInfo("M1000", "Test Mitigation", "Some mitigation description.")
        ],
        detection="Monitor for this.",
    )


def _make_rule_match(
    technique: str = "T1059.001",
    tactic: str = "execution",
    severity: Severity = Severity.HIGH,
) -> RuleMatch:
    return RuleMatch(
        rule_name="Test_Rule",
        rule_file="/rules/test.yar",
        mitre_technique=technique,
        mitre_tactic=tactic,
        severity=severity,
        description="Test rule match.",
    )


def _make_scan_result(*matches: RuleMatch, path: str = "/tmp/test.ps1") -> ScanResult:
    return ScanResult(
        target_file=path,
        scan_time=datetime.now(tz=timezone.utc),
        duration_ms=10.0,
        matches=list(matches),
    )


def _make_mock_client(technique_map: dict[str, TechniqueInfo | None]) -> MagicMock:
    """Return a mock AttackClient whose get_technique() uses technique_map."""
    client = MagicMock()
    client.get_technique.side_effect = lambda tid: technique_map.get(tid.upper(), None)
    return client


# ─────────────────────────────────────────────────────────────────────────────
#  _compute_confidence
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeConfidence:
    def test_zero_with_no_matches(self):
        assert _compute_confidence([], []) == 0.0

    def test_higher_score_with_more_tactics(self):
        m_high = _make_rule_match(severity=Severity.HIGH)
        score_one = _compute_confidence(["execution"], [m_high])
        score_two = _compute_confidence(["execution", "persistence"], [m_high])
        assert score_two > score_one

    def test_critical_severity_boosts_score(self):
        m_low = _make_rule_match(severity=Severity.LOW)
        m_crit = _make_rule_match(severity=Severity.CRITICAL)
        score_low = _compute_confidence(["execution"], [m_low])
        score_crit = _compute_confidence(["execution"], [m_crit])
        assert score_crit > score_low

    def test_score_bounded_between_0_and_1(self):
        tactics = ["execution", "persistence", "credential-access", "defense-evasion",
                   "discovery", "lateral-movement", "exfiltration", "impact"]
        matches = [_make_rule_match(severity=Severity.CRITICAL)] * 10
        score = _compute_confidence(tactics, matches)
        assert 0.0 <= score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
#  _compute_threat_level
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeThreatLevel:
    def test_none_for_zero(self):
        assert _compute_threat_level(0.0) == "none"

    def test_low_threshold(self):
        assert _compute_threat_level(0.05) == "low"

    def test_medium_threshold(self):
        assert _compute_threat_level(0.30) == "medium"

    def test_high_threshold(self):
        assert _compute_threat_level(0.50) == "high"

    def test_critical_threshold(self):
        assert _compute_threat_level(0.75) == "critical"


# ─────────────────────────────────────────────────────────────────────────────
#  _build_narrative
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildNarrative:
    def test_no_tactics_returns_clean_message(self):
        n = _build_narrative([], [], "/tmp/test.ps1")
        assert "No suspicious" in n

    def test_narrative_mentions_filename(self):
        n = _build_narrative(["execution"], ["T1059.001"], "/tmp/suspicious.ps1")
        assert "suspicious.ps1" in n

    def test_narrative_mentions_tactic(self):
        n = _build_narrative(["execution"], ["T1059.001"], "/tmp/test.ps1")
        assert "execution" in n.lower() or "command" in n.lower()

    def test_narrative_mentions_technique_count(self):
        n = _build_narrative(["execution", "persistence"], ["T1059.001", "T1547.001"], "/tmp/t.ps1")
        assert "2" in n

    def test_narrative_is_string(self):
        n = _build_narrative(["execution"], ["T1059.001"], "/tmp/test.ps1")
        assert isinstance(n, str)


# ─────────────────────────────────────────────────────────────────────────────
#  map_scan_result — integration with mock client
# ─────────────────────────────────────────────────────────────────────────────

class TestMapScanResult:
    def _client_for(self, *technique_ids: str) -> MagicMock:
        mapping = {
            tid: _make_technique(tid, ["execution"]) for tid in technique_ids
        }
        return _make_mock_client(mapping)

    def test_empty_scan_result_returns_no_mappings(self):
        result = _make_scan_result()
        client = MagicMock()
        mapping = map_scan_result(result, client=client)
        assert isinstance(mapping, MappingResult)
        assert mapping.technique_mappings == []

    def test_matched_technique_appears_in_mapping(self):
        match = _make_rule_match(technique="T1059.001", tactic="execution")
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert "T1059.001" in mapping.unique_techniques

    def test_tactic_appears_in_mapping(self):
        match = _make_rule_match(technique="T1059.001", tactic="execution")
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert "execution" in mapping.unique_tactics

    def test_confidence_score_non_zero_with_match(self):
        match = _make_rule_match(severity=Severity.HIGH)
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert mapping.confidence_score > 0.0

    def test_threat_level_set(self):
        match = _make_rule_match(severity=Severity.CRITICAL)
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert mapping.threat_level in {"none", "low", "medium", "high", "critical"}

    def test_narrative_is_non_empty_string(self):
        match = _make_rule_match()
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert isinstance(mapping.narrative, str)
        assert len(mapping.narrative) > 0

    def test_multi_technique_rule_expands_correctly(self):
        """A rule with 'T1059.001,T1027' in technique field should produce 2 technique mappings."""
        match = _make_rule_match(technique="T1059.001,T1027", tactic="execution,defense-evasion")
        result = _make_scan_result(match)
        technique_map = {
            "T1059.001": _make_technique("T1059.001", ["execution"]),
            "T1027": _make_technique("T1027", ["defense-evasion"]),
        }
        client = _make_mock_client(technique_map)
        mapping = map_scan_result(result, client=client)
        assert "T1059.001" in mapping.unique_techniques
        assert "T1027" in mapping.unique_techniques

    def test_unknown_technique_returns_none_technique_info(self):
        """If technique is not in STIX, technique_info should be None but mapping still valid."""
        match = _make_rule_match(technique="T9999.999")
        result = _make_scan_result(match)
        client = _make_mock_client({})  # returns None for everything
        mapping = map_scan_result(result, client=client)
        assert len(mapping.technique_mappings) > 0
        assert mapping.technique_mappings[0].technique_info is None

    def test_to_dict_is_serialisable(self):
        import json
        match = _make_rule_match()
        result = _make_scan_result(match)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        d = mapping.to_dict()
        serialised = json.dumps(d)
        assert isinstance(serialised, str)

    def test_duplicate_techniques_deduped_in_unique_list(self):
        """Two matches hitting the same technique should appear once in unique_techniques."""
        m1 = _make_rule_match(technique="T1059.001")
        m2 = _make_rule_match(technique="T1059.001", severity=Severity.CRITICAL)
        result = _make_scan_result(m1, m2)
        client = self._client_for("T1059.001")
        mapping = map_scan_result(result, client=client)
        assert mapping.unique_techniques.count("T1059.001") == 1
