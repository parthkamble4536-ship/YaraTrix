"""
MITRE ATT&CK Navigator Layer Exporter for YaraTrix.

Generates a Navigator-compatible JSON layer file from a MappingResult or
a list of MappingResults. The layer can be directly imported into:
  https://mitre-attack.github.io/attack-navigator/

Official layer format spec:
  https://github.com/mitre-attack/attack-navigator/blob/master/LAYER_FORMAT.md

Layer format version: 4.5
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from yaratrix.mapper import MappingResult

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Colour palette for severity levels (Navigator hex colors)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff0000",  # Red
    "high": "#ff6600",  # Orange
    "medium": "#ffcc00",  # Yellow
    "low": "#66b3ff",  # Light blue
    "info": "#cccccc",  # Grey
}

# Default color when no severity is available
_DEFAULT_COLOR = "#ffffff"


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _highest_severity(severities: list[str]) -> str:
    """Return the highest severity value from a list."""
    order = ["critical", "high", "medium", "low", "info"]
    for level in order:
        if level in severities:
            return level
    return "info"


def _build_technique_entry(
    technique_id: str,
    severities: list[str],
    rule_names: list[str],
    score: int,
) -> dict[str, Any]:
    """
    Build a single technique entry in the Navigator layer format.

    Args:
        technique_id: ATT&CK technique ID (e.g. "T1059.001").
        severities:   List of severity values from all matching rules.
        rule_names:   Names of matching rules (used as comments).
        score:        Numeric score (used for heatmap intensity, 1–4).
    """
    # Navigator requires technique vs. sub-technique split
    parts = technique_id.split(".")
    base_id = parts[0]
    sub_id = parts[1] if len(parts) > 1 else None

    highest = _highest_severity(severities)
    color = _SEVERITY_COLORS.get(highest, _DEFAULT_COLOR)
    comment = "Rules matched: " + ", ".join(sorted(set(rule_names)))

    entry: dict[str, Any] = {
        "techniqueID": base_id,
        "score": score,
        "color": color,
        "comment": comment[:500],
        "enabled": True,
        "metadata": [
            {"name": "severity", "value": highest},
            {"name": "yaratrix_rules", "value": ", ".join(sorted(set(rule_names)))},
        ],
        "links": [],
        "showSubtechniques": sub_id is not None,
    }

    if sub_id:
        entry["techniqueID"] = f"{base_id}.{sub_id}"

    return entry


def _severity_to_score(severity: str) -> int:
    """Map severity string to a 1–4 integer score for Navigator heatmap."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}.get(severity, 1)


# ─────────────────────────────────────────────────────────────────────────────
#  Layer generator
# ─────────────────────────────────────────────────────────────────────────────


def build_navigator_layer(
    mapping_results: list[MappingResult],
    *,
    layer_name: str = "YaraTrix Scan Results",
    layer_description: str = "",
    domain: str = "enterprise-attack",
    version: str = "4.5",
) -> dict[str, Any]:
    """
    Build a MITRE ATT&CK Navigator layer dict from one or more MappingResults.

    Args:
        mapping_results:  List of MappingResult objects from mapper.py.
        layer_name:       Display name shown in the Navigator header.
        layer_description: Optional description for the layer.
        domain:           ATT&CK domain (enterprise-attack, mobile-attack, etc.).
        version:          Navigator layer format version.

    Returns:
        A dict matching the Navigator layer JSON schema.
    """
    # Aggregate: technique_id → {severities: [...], rules: [...]}
    technique_aggregates: dict[str, dict[str, list[str]]] = {}

    for result in mapping_results:
        for mapping in result.technique_mappings:
            tid = mapping.technique_id
            if tid not in technique_aggregates:
                technique_aggregates[tid] = {"severities": [], "rules": []}
            technique_aggregates[tid]["severities"].append(mapping.severity.value)
            technique_aggregates[tid]["rules"].append(mapping.rule_name)

    # Build technique entries
    techniques: list[dict[str, Any]] = []
    for tid, agg in technique_aggregates.items():
        highest_sev = _highest_severity(agg["severities"])
        score = _severity_to_score(highest_sev)
        entry = _build_technique_entry(
            technique_id=tid,
            severities=agg["severities"],
            rule_names=agg["rules"],
            score=score,
        )
        techniques.append(entry)

    # Build description if not provided
    if not layer_description:
        total_files = len(mapping_results)
        files_with_hits = sum(1 for r in mapping_results if r.technique_mappings)
        unique_techs = len(technique_aggregates)
        layer_description = (
            f"Generated by YaraTrix on {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M UTC')}. "
            f"Scanned {total_files} file(s), {files_with_hits} had matches. "
            f"{unique_techs} unique ATT&CK technique(s) identified."
        )

    layer = {
        "name": layer_name,
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": version,
        },
        "domain": domain,
        "description": layer_description,
        "filters": {
            "platforms": [
                "Windows",
                "Linux",
                "macOS",
            ]
        },
        "sorting": 3,  # Sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [
                "#ffffff",  # 0 — no match
                "#66b3ff",  # 1 — low
                "#ffcc00",  # 2 — medium
                "#ff6600",  # 3 — high
                "#ff0000",  # 4 — critical
            ],
            "minValue": 0,
            "maxValue": 4,
        },
        "legendItems": [
            {"label": "Critical", "color": "#ff0000"},
            {"label": "High", "color": "#ff6600"},
            {"label": "Medium", "color": "#ffcc00"},
            {"label": "Low", "color": "#66b3ff"},
        ],
        "metadata": [
            {"name": "generator", "value": "YaraTrix"},
            {
                "name": "generated_at",
                "value": datetime.now(tz=UTC).isoformat(),
            },
        ],
        "links": [
            {
                "label": "YaraTrix on GitHub",
                "url": "https://github.com/parthkamble4536-ship/YaraTrix",
            }
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    return layer


def export_navigator_layer(
    mapping_results: list[MappingResult],
    output_path: str | Path,
    *,
    layer_name: str = "YaraTrix Scan Results",
    layer_description: str = "",
) -> Path:
    """
    Generate a Navigator layer JSON file from mapping results and write it to disk.

    Args:
        mapping_results: List of MappingResult objects from mapper.py.
        output_path:     Path to write the .json file to.
        layer_name:      Display name shown in the Navigator header.
        layer_description: Optional description for the layer.

    Returns:
        Resolved output Path.
    """
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    layer = build_navigator_layer(
        mapping_results,
        layer_name=layer_name,
        layer_description=layer_description,
    )

    import sys

    out_str = str(out)
    if sys.platform == "win32" and not out_str.startswith("\\\\?\\"):
        out_str = "\\\\?\\" + out_str
    with open(out_str, "w", encoding="utf-8") as f:
        f.write(json.dumps(layer, indent=2, ensure_ascii=False))
    logger.info("Navigator layer written to %s", out)
    return out
