"""
MITRE ATT&CK Mapping & Aggregation Layer for YaraTrix.

Takes a list of RuleMatch objects from the YARA engine and:
  1. Resolves each technique ID → full TechniqueInfo via AttackClient.
  2. Aggregates per-file: unique tactics, unique techniques, severity counts.
  3. Computes a coverage/confidence score.
  4. Generates a human-readable narrative sentence describing what was found.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from yaratrix.attack_client import AttackClient, TechniqueInfo, get_default_client
from yaratrix.models import RuleMatch, ScanResult, Severity

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Kill-chain order used for confidence calculation
# ─────────────────────────────────────────────────────────────────────────────

# The 14 enterprise tactics ordered by kill-chain position.
# More distinct phases covered → higher confidence the file is truly malicious.
KILL_CHAIN_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Severity weight multipliers for confidence scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.5,
}

# Tactic phrases used to build the narrative sentence
_TACTIC_PHRASES: dict[str, str] = {
    "reconnaissance": "reconnaissance and target profiling",
    "resource-development": "capability staging and infrastructure setup",
    "initial-access": "initial system compromise",
    "execution": "code and command execution",
    "persistence": "persistence establishment",
    "privilege-escalation": "privilege escalation",
    "defense-evasion": "defense evasion and anti-analysis",
    "credential-access": "credential theft",
    "discovery": "environment and host discovery",
    "lateral-movement": "lateral movement within the network",
    "collection": "data collection and staging",
    "command-and-control": "command-and-control communications",
    "exfiltration": "data exfiltration",
    "impact": "destructive or disruptive impact",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class TechniqueMapping:
    """
    An enriched mapping of a matched rule → resolved ATT&CK technique.
    """

    rule_name: str
    technique_id: str
    technique_info: TechniqueInfo | None  # None if ID not found in STIX
    severity: Severity
    match_count: int  # How many rules matched this technique

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "technique_id": self.technique_id,
            "technique_info": self.technique_info.to_dict() if self.technique_info else None,
            "severity": self.severity.value,
            "match_count": self.match_count,
        }


@dataclass
class MappingResult:
    """
    Full mapping result for a single scanned file.

    Contains:
    - Per-technique enriched mappings
    - Aggregated tactic/technique lists
    - Confidence score (0.0–1.0)
    - Human-readable narrative
    """

    target_file: str
    technique_mappings: list[TechniqueMapping] = field(default_factory=list)

    # Aggregated
    unique_techniques: list[str] = field(default_factory=list)  # T-IDs, deduped
    unique_tactics: list[str] = field(default_factory=list)  # tactic names, deduped
    confidence_score: float = 0.0  # 0.0–1.0
    threat_level: str = "none"  # low/medium/high/critical
    narrative: str = ""  # human-readable summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_file": self.target_file,
            "unique_techniques": self.unique_techniques,
            "unique_tactics": self.unique_tactics,
            "confidence_score": round(self.confidence_score, 3),
            "threat_level": self.threat_level,
            "narrative": self.narrative,
            "technique_mappings": [m.to_dict() for m in self.technique_mappings],
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Core mapping functions
# ─────────────────────────────────────────────────────────────────────────────


def _compute_confidence(
    tactics: list[str],
    matches: list[RuleMatch],
) -> float:
    """
    Compute a 0.0–1.0 confidence score.

    Formula:
        tactic_breadth  = (distinct tactics hit) / (total kill-chain phases)  * 0.6
        severity_score  = weighted severity sum / max possible weight          * 0.4

    The idea: spanning more of the kill-chain is a stronger signal of a real
    threat than many matches on a single tactic.
    """
    if not matches:
        return 0.0

    # Tactic breadth contribution (60% weight)
    distinct_tactic_count = sum(1 for t in KILL_CHAIN_ORDER if t in tactics)
    tactic_score = (distinct_tactic_count / len(KILL_CHAIN_ORDER)) * 0.6

    # Severity contribution (40% weight)
    max_weight = _SEVERITY_WEIGHTS["critical"] * len(matches)
    actual_weight = sum(_SEVERITY_WEIGHTS.get(m.severity.value, 1.0) for m in matches)
    severity_score = min(actual_weight / max(max_weight, 1.0), 1.0) * 0.4

    return min(tactic_score + severity_score, 1.0)


def _compute_threat_level(score: float) -> str:
    if score >= 0.70:
        return "critical"
    elif score >= 0.45:
        return "high"
    elif score >= 0.20:
        return "medium"
    elif score > 0.0:
        return "low"
    return "none"


def _build_narrative(tactics: list[str], techniques: list[str], target_file: str) -> str:
    """
    Generate a human-readable narrative sentence describing the threat.
    """
    if not tactics:
        return f"No suspicious behaviors detected in {target_file}."

    # Order tactics by kill-chain position
    ordered = [t for t in KILL_CHAIN_ORDER if t in tactics]
    phrases = [_TACTIC_PHRASES.get(t, t) for t in ordered]

    file_name = target_file.split("\\")[-1].split("/")[-1]
    technique_count = len(techniques)

    if len(phrases) == 1:
        behavior_str = phrases[0]
    elif len(phrases) == 2:
        behavior_str = f"{phrases[0]} and {phrases[1]}"
    else:
        behavior_str = ", ".join(phrases[:-1]) + f", and {phrases[-1]}"

    return (
        f"'{file_name}' exhibits behavior consistent with {behavior_str}. "
        f"{technique_count} distinct ATT&CK technique(s) were matched, "
        f"spanning {len(tactics)} tactic phase(s) of the MITRE ATT&CK kill-chain."
    )


def map_scan_result(
    scan_result: ScanResult,
    client: AttackClient | None = None,
) -> MappingResult:
    """
    Map a ScanResult → MappingResult by enriching each matched rule
    with full ATT&CK technique metadata.

    Args:
        scan_result: Output from yara_engine.scan_file() or scan_directory().
        client:      AttackClient instance; uses module singleton if None.

    Returns:
        MappingResult with enriched mappings, confidence score, and narrative.
    """
    if client is None:
        client = get_default_client()

    if not scan_result.matches:
        return MappingResult(
            target_file=scan_result.target_file,
            narrative=f"No suspicious behaviors detected in {scan_result.target_file}.",
        )

    # Resolve each unique technique ID exactly once
    technique_cache: dict[str, TechniqueInfo | None] = {}

    # Count how many matches hit each technique ID
    technique_match_counts: dict[str, int] = {}
    for match in scan_result.matches:
        for tid in match.technique_ids():
            technique_match_counts[tid] = technique_match_counts.get(tid, 0) + 1

    # Build enriched TechniqueMapping per matched rule
    mappings: list[TechniqueMapping] = []
    for match in scan_result.matches:
        for tid in match.technique_ids():
            if tid not in technique_cache:
                technique_cache[tid] = client.get_technique(tid)

            info = technique_cache[tid]
            mappings.append(
                TechniqueMapping(
                    rule_name=match.rule_name,
                    technique_id=tid,
                    technique_info=info,
                    severity=match.severity,
                    match_count=technique_match_counts[tid],
                )
            )

    # Collect unique techniques (deduplicated)
    seen_techs: set[str] = set()
    unique_techniques: list[str] = []
    for m in mappings:
        if m.technique_id not in seen_techs:
            seen_techs.add(m.technique_id)
            unique_techniques.append(m.technique_id)

    # Collect unique tactics — from both rule meta AND resolved TechniqueInfo
    seen_tactics: set[str] = set()
    unique_tactics: list[str] = []

    for match in scan_result.matches:
        for tactic in match.tactic_names():
            if tactic and tactic not in seen_tactics:
                seen_tactics.add(tactic)
                unique_tactics.append(tactic)

    # Supplement with tactics from STIX (in case rule meta was imprecise)
    for m in mappings:
        if m.technique_info:
            for tactic in m.technique_info.tactics:
                if tactic not in seen_tactics:
                    seen_tactics.add(tactic)
                    unique_tactics.append(tactic)

    # Score and narrative
    confidence = _compute_confidence(unique_tactics, scan_result.matches)
    threat_level = _compute_threat_level(confidence)

    # Production Override: If we have a CRITICAL match, enforce a CRITICAL threat level
    if any(m.severity.value == "critical" for m in scan_result.matches):
        threat_level = "critical"

    narrative = _build_narrative(unique_tactics, unique_techniques, scan_result.target_file)

    return MappingResult(
        target_file=scan_result.target_file,
        technique_mappings=mappings,
        unique_techniques=unique_techniques,
        unique_tactics=unique_tactics,
        confidence_score=confidence,
        threat_level=threat_level,
        narrative=narrative,
    )


def map_scan_results(
    scan_results: list[ScanResult],
    client: AttackClient | None = None,
) -> list[MappingResult]:
    """Map a list of ScanResult objects (from a directory scan)."""
    if client is None:
        client = get_default_client()
    return [map_scan_result(r, client=client) for r in scan_results]
