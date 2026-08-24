"""
Tests for yaratrix.navigator_export — Navigator layer generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from yaratrix.attack_client import TechniqueInfo, MitigationInfo
from yaratrix.mapper import MappingResult, TechniqueMapping
from yaratrix.models import Severity
from yaratrix.navigator_export import build_navigator_layer, export_navigator_layer


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_technique(technique_id: str, tactics: list[str]) -> TechniqueInfo:
    return TechniqueInfo(
        technique_id=technique_id,
        name=f"Technique {technique_id}",
        tactics=tactics,
        description="",
        url="",
        is_subtechnique="." in technique_id,
        parent_technique_id=technique_id.split(".")[0] if "." in technique_id else "",
        sub_techniques=[],
        mitigations=[],
        detection="",
    )


def _make_mapping(
    technique_ids: list[str],
    severities: list[Severity],
    tactics: list[str],
    file: str = "/tmp/test.ps1",
) -> MappingResult:
    tech_mappings = [
        TechniqueMapping(
            rule_name=f"Rule_{tid}",
            technique_id=tid,
            technique_info=_make_technique(tid, tactics),
            severity=sev,
            match_count=1,
        )
        for tid, sev in zip(technique_ids, severities)
    ]
    return MappingResult(
        target_file=file,
        technique_mappings=tech_mappings,
        unique_techniques=technique_ids,
        unique_tactics=tactics,
        confidence_score=0.5,
        threat_level="high",
        narrative="Test narrative.",
    )


# ─────────────────────────────────────────────────────────────────────────────
#  build_navigator_layer
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildNavigatorLayer:
    def test_returns_dict(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        assert isinstance(layer, dict)

    def test_has_required_top_level_keys(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        for key in ("name", "versions", "domain", "techniques", "gradient", "legendItems"):
            assert key in layer, f"Missing key: {key}"

    def test_domain_is_enterprise_attack(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        assert layer["domain"] == "enterprise-attack"

    def test_technique_appears_in_layer(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        technique_ids = {t["techniqueID"] for t in layer["techniques"]}
        assert "T1059.001" in technique_ids

    def test_score_mapped_from_severity(self):
        mapping = _make_mapping(["T1059.001"], [Severity.CRITICAL], ["execution"])
        layer = build_navigator_layer([mapping])
        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059.001")
        assert entry["score"] == 4  # critical == 4

    def test_color_set_for_critical(self):
        mapping = _make_mapping(["T1059.001"], [Severity.CRITICAL], ["execution"])
        layer = build_navigator_layer([mapping])
        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059.001")
        assert entry["color"] == "#ff0000"

    def test_multiple_techniques_all_present(self):
        mapping = _make_mapping(
            ["T1059.001", "T1547.001", "T1003.001"],
            [Severity.HIGH, Severity.HIGH, Severity.CRITICAL],
            ["execution", "persistence", "credential-access"],
        )
        layer = build_navigator_layer([mapping])
        ids = {t["techniqueID"] for t in layer["techniques"]}
        assert {"T1059.001", "T1547.001", "T1003.001"}.issubset(ids)

    def test_layer_name_custom(self):
        mapping = _make_mapping(["T1059.001"], [Severity.LOW], ["execution"])
        layer = build_navigator_layer([mapping], layer_name="My Custom Layer")
        assert layer["name"] == "My Custom Layer"

    def test_gradient_has_5_colors(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        assert len(layer["gradient"]["colors"]) == 5

    def test_empty_mappings_produces_empty_techniques(self):
        layer = build_navigator_layer([])
        assert layer["techniques"] == []

    def test_layer_is_json_serialisable(self):
        import json
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        serialised = json.dumps(layer)
        assert isinstance(serialised, str)

    def test_versions_present(self):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        layer = build_navigator_layer([mapping])
        assert "attack" in layer["versions"]
        assert "navigator" in layer["versions"]
        assert "layer" in layer["versions"]

    def test_highest_severity_wins_when_aggregating(self):
        """Two mappings hitting the same technique — highest severity should win."""
        m1 = _make_mapping(["T1059.001"], [Severity.LOW], ["execution"], file="/tmp/a.ps1")
        m2 = _make_mapping(["T1059.001"], [Severity.CRITICAL], ["execution"], file="/tmp/b.ps1")
        layer = build_navigator_layer([m1, m2])
        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059.001")
        assert entry["score"] == 4  # critical wins
        assert entry["color"] == "#ff0000"


# ─────────────────────────────────────────────────────────────────────────────
#  export_navigator_layer — file writing
# ─────────────────────────────────────────────────────────────────────────────

class TestExportNavigatorLayer:
    def test_writes_json_file(self, tmp_path):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        out_path = tmp_path / "layer.json"
        result = export_navigator_layer([mapping], out_path)
        assert result.exists()

    def test_written_json_is_valid(self, tmp_path):
        import json
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        out_path = tmp_path / "layer.json"
        export_navigator_layer([mapping], out_path)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert "techniques" in data

    def test_creates_parent_dirs(self, tmp_path):
        mapping = _make_mapping(["T1059.001"], [Severity.HIGH], ["execution"])
        out_path = tmp_path / "nested" / "deep" / "layer.json"
        export_navigator_layer([mapping], out_path)
        assert out_path.exists()
