"""
HTML Report Generator for YaraTrix.

Renders a full per-scan HTML report from ScanResult and MappingResult
using Jinja2 templates.  The report includes:
  - Threat level + confidence stats banner
  - Kill-chain heatmap (coloured by highest severity per tactic)
  - MITRE ATT&CK technique breakdown table
  - Rule match cards with metadata
  - Human-readable narrative
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from yaratrix import __version__
from yaratrix.mapper import MappingResult
from yaratrix.models import ScanResult, Severity

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Severity order for determining the "worst" tactic severity
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _worst_severity(severities: list[str]) -> str:
    for sev in _SEV_ORDER:
        if sev in severities:
            return sev
    return "info"


def _build_tactic_severity_map(mapping: MappingResult) -> dict[str, str]:
    """
    Build a dict of tactic → highest_severity for the kill-chain heatmap.
    """
    tactic_sevs: dict[str, list[str]] = {}
    for tm in mapping.technique_mappings:
        # Use STIX-resolved tactics if available, else rule meta
        tactics = (
            tm.technique_info.tactics
            if tm.technique_info
            else [t.strip() for t in tm.severity.value.split(",")]
        )
        # Get tactics from the matched rule itself
        if tm.technique_info:
            for tactic in tm.technique_info.tactics:
                tactic_sevs.setdefault(tactic, []).append(tm.severity.value)
        else:
            # Fall back to rule meta tactic
            pass

    # Also include tactics from rule meta
    for tm in mapping.technique_mappings:
        from yaratrix.models import RuleMatch
        pass

    result = {tactic: _worst_severity(sevs) for tactic, sevs in tactic_sevs.items()}
    return result


def _build_technique_rows(mapping: MappingResult) -> list[dict[str, Any]]:
    """Build deduplicated technique rows for the technique breakdown table."""
    seen: set[str] = set()
    rows = []
    for tm in mapping.technique_mappings:
        if tm.technique_id in seen:
            continue
        seen.add(tm.technique_id)
        info = tm.technique_info
        rows.append({
            "technique_id": tm.technique_id,
            "name": info.name if info else "",
            "description": info.description if info else "",
            "url": info.url if info else "",
            "tactics": info.tactics if info else [],
            "severity": tm.severity.value,
            "mitigation_count": len(info.mitigations) if info else 0,
        })
    return rows


def _build_rule_matches(scan_results: list[ScanResult]) -> list[dict[str, Any]]:
    """Build rule match dicts for the match cards section."""
    rows = []
    for result in scan_results:
        file_name = Path(result.target_file).name
        for match in result.matches:
            rows.append({
                "rule_name": match.rule_name,
                "file_name": file_name,
                "rule_file": Path(match.rule_file).name,
                "mitre_technique": match.mitre_technique,
                "mitre_tactic": match.mitre_tactic,
                "severity": match.severity.value,
                "description": match.description,
                "string_count": len(match.matched_strings),
            })
    return rows


def render_report(
    scan_results: list[ScanResult],
    mappings: list[MappingResult],
    output_path: str | Path,
    *,
    report_title: str = "Scan Report",
) -> Path:
    """
    Render a full HTML scan report to disk.

    Args:
        scan_results:  List of per-file ScanResult objects.
        mappings:      Corresponding MappingResult objects from mapper.py.
        output_path:   Destination path for the HTML file.
        report_title:  Title shown in the report header.

    Returns:
        Resolved output Path.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    # Aggregate across all mappings
    all_techniques: set[str] = set()
    all_tactics: set[str] = set()
    all_narratives: list[str] = []
    total_matches = sum(len(r.matches) for r in scan_results)
    files_with_matches = sum(1 for r in scan_results if r.matches)
    total_files = len(scan_results)

    # Aggregate tactic severity map across all mappings
    combined_tactic_sevs: dict[str, list[str]] = {}
    all_technique_rows: list[dict[str, Any]] = []
    seen_techs: set[str] = set()

    for mapping in mappings:
        all_techniques.update(mapping.unique_techniques)
        all_tactics.update(mapping.unique_tactics)
        if mapping.narrative and mapping.technique_mappings:
            all_narratives.append(mapping.narrative)

        # Tactic severity
        tsmap = _build_tactic_severity_map(mapping)
        for tactic, sev in tsmap.items():
            combined_tactic_sevs.setdefault(tactic, []).append(sev)

        # Technique rows (deduplicated globally)
        for row in _build_technique_rows(mapping):
            if row["technique_id"] not in seen_techs:
                seen_techs.add(row["technique_id"])
                all_technique_rows.append(row)

    tactic_severity_map = {
        t: _worst_severity(sevs) for t, sevs in combined_tactic_sevs.items()
    }

    # Overall confidence and threat level from highest-confidence mapping
    confidence_score = max((m.confidence_score for m in mappings), default=0.0)
    threat_level = max(
        (m.threat_level for m in mappings),
        key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}.get(x, 0),
        default="none",
    )

    rule_matches = _build_rule_matches(scan_results)

    context = {
        "version": __version__,
        "report_title": report_title,
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "threat_level": threat_level,
        "confidence_score": confidence_score,
        "total_matches": total_matches,
        "total_files": total_files,
        "files_with_matches": files_with_matches,
        "unique_techniques": sorted(all_techniques),
        "unique_tactics": sorted(all_tactics),
        "narratives": all_narratives or ["No significant threats detected."],
        "tactic_severity_map": tactic_severity_map,
        "technique_rows": all_technique_rows,
        "rule_matches": rule_matches,
    }

    html = template.render(**context)

    # Write safely (Windows paths with &)
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out_str = str(out)
    if sys.platform == "win32" and not out_str.startswith("\\\\?\\"):
        out_str = "\\\\?\\" + out_str
    with open(out_str, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("HTML report written to %s", out)
    return out
