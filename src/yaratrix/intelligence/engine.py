"""
YaraTrix Intelligence Engine (Phase 2)

Transforms raw YARA match events into enriched threat intelligence:
  - Confidence scoring based on severity weights and tactic coverage
  - Behavioral profiling with human-readable narrative generation
  - Temporal attack chain reconstruction from DB history
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
#  Severity Weights for Confidence Scoring
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 0.80,
    "high": 0.60,
    "medium": 0.40,
    "low": 0.20,
    "informational": 0.05,
}

# Bonus score added per unique MITRE tactic covered
TACTIC_DIVERSITY_BONUS = 0.05

# Maximum possible confidence score
MAX_CONFIDENCE = 1.0


# ──────────────────────────────────────────────────────────────────────────────
#  Tactic → Human-readable label mapping
# ──────────────────────────────────────────────────────────────────────────────

TACTIC_LABELS: dict[str, str] = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "command-and-control": "Command & Control",
    "impact": "Impact",
    # Also handle simplified tactic names from rule metadata
    "initial_access": "Initial Access",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "lateral_movement": "Lateral Movement",
    "command_and_control": "Command & Control",
}


# ──────────────────────────────────────────────────────────────────────────────
#  Data classes for intelligence output
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class RuleMatchInput:
    """Input structure representing a single YARA rule match."""

    rule_name: str
    severity: str = "medium"
    mitre_technique: str = ""
    mitre_tactic: str = ""
    description: str = ""


@dataclass
class IntelligenceReport:
    """
    The enriched intelligence output for a single scanned file.
    Contains confidence score, behavioral narrative, and tactic coverage.
    """

    confidence_score: float = 0.0  # 0.0 - 1.0
    confidence_label: str = "Clean"  # Clean / Low / Medium / High / Critical
    threat_level: str = "none"  # none / low / medium / high / critical
    tactic_coverage: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    behavioral_narrative: str = ""
    rule_count: int = 0
    tactic_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_score": round(self.confidence_score, 3),
            "confidence_label": self.confidence_label,
            "threat_level": self.threat_level,
            "tactic_coverage": self.tactic_coverage,
            "technique_ids": self.technique_ids,
            "behavioral_narrative": self.behavioral_narrative,
            "rule_count": self.rule_count,
            "tactic_count": self.tactic_count,
        }


# ──────────────────────────────────────────────────────────────────────────────
#  Core Intelligence Engine
# ──────────────────────────────────────────────────────────────────────────────


class IntelligenceEngine:
    """
    Transforms raw YARA rule matches into enriched threat intelligence.

    Usage:
        engine = IntelligenceEngine()
        report = engine.analyze(matches)
    """

    def analyze(self, matches: list[RuleMatchInput]) -> IntelligenceReport:
        """
        Run the full intelligence pipeline on a list of YARA rule matches.

        Args:
            matches: List of RuleMatchInput from a single scan.

        Returns:
            An IntelligenceReport with confidence score, narrative, and coverage.
        """
        if not matches:
            return IntelligenceReport(
                confidence_score=0.0,
                confidence_label="Clean",
                threat_level="none",
                behavioral_narrative="No YARA rules matched. File appears clean.",
            )

        confidence = self._calculate_confidence(matches)
        tactics = self._extract_tactics(matches)
        techniques = self._extract_techniques(matches)
        narrative = self._build_narrative(matches, tactics, confidence)
        label, threat = self._classify(confidence)

        return IntelligenceReport(
            confidence_score=confidence,
            confidence_label=label,
            threat_level=threat,
            tactic_coverage=tactics,
            technique_ids=techniques,
            behavioral_narrative=narrative,
            rule_count=len(matches),
            tactic_count=len(tactics),
        )

    # ── Private methods ──────────────────────────────────────────────────────

    def _calculate_confidence(self, matches: list[RuleMatchInput]) -> float:
        """
        Calculate a confidence score (0.0 to 1.0) based on:
          - Severity weights of each matched rule
          - Diversity bonus for each unique MITRE tactic covered
        """
        base_score = sum(
            SEVERITY_WEIGHTS.get(m.severity.lower(), SEVERITY_WEIGHTS["medium"]) for m in matches
        )

        # Add bonus for tactic diversity (attacker using multiple phases)
        unique_tactics = {m.mitre_tactic.lower() for m in matches if m.mitre_tactic}
        diversity_bonus = len(unique_tactics) * TACTIC_DIVERSITY_BONUS

        return min(base_score + diversity_bonus, MAX_CONFIDENCE)

    def _extract_tactics(self, matches: list[RuleMatchInput]) -> list[str]:
        """Return a deduplicated, human-readable list of MITRE tactics detected."""
        seen: dict[str, str] = {}
        for m in matches:
            tactic_key = m.mitre_tactic.lower().strip()
            if tactic_key and tactic_key not in seen:
                label = TACTIC_LABELS.get(tactic_key, tactic_key.replace("_", " ").title())
                seen[tactic_key] = label
        return list(seen.values())

    def _extract_techniques(self, matches: list[RuleMatchInput]) -> list[str]:
        """Return a deduplicated list of MITRE technique IDs."""
        seen: set[str] = set()
        result: list[str] = []
        for m in matches:
            tid = m.mitre_technique.strip().upper()
            if tid and tid not in seen:
                seen.add(tid)
                result.append(tid)
        return result

    def _build_narrative(
        self,
        matches: list[RuleMatchInput],
        tactics: list[str],
        confidence: float,
    ) -> str:
        """
        Generate a human-readable behavioral narrative summarizing the threat.

        Example output:
            "Observed Execution and Credential Access activity. 3 YARA rules
             triggered across 2 MITRE ATT&CK tactics. High-confidence
             suspicious execution chain detected."
        """
        rule_count = len(matches)
        tactic_count = len(tactics)

        if tactic_count == 0:
            return (
                f"{rule_count} YARA rule(s) matched but no MITRE ATT&CK "
                "technique metadata was found in rule definitions."
            )

        tactic_str = self._join_list(tactics)
        _, threat = self._classify(confidence)

        # Build the narrative sentence
        parts: list[str] = [
            f"Observed {tactic_str} activity.",
            f"{rule_count} YARA rule(s) triggered across {tactic_count} MITRE ATT&CK tactic(s).",
        ]

        # Add threat-specific context
        if threat == "critical":
            parts.append(
                "Critical-confidence attack chain detected. "
                "Immediate investigation is strongly recommended."
            )
        elif threat == "high":
            parts.append(
                "High-confidence suspicious behavior detected. Analyst review is recommended."
            )
        elif threat == "medium":
            parts.append(
                "Medium-confidence suspicious indicators found. Further triage is advised."
            )
        else:
            parts.append("Low-confidence indicators detected. May require contextual review.")

        return " ".join(parts)

    @staticmethod
    def _classify(confidence: float) -> tuple[str, str]:
        """
        Map a confidence score to a (label, threat_level) pair.

        Thresholds:
            0.00 - 0.19: Clean / none
            0.20 - 0.39: Low / low
            0.40 - 0.59: Medium / medium
            0.60 - 0.79: High / high
            0.80 - 1.00: Critical / critical
        """
        if confidence < 0.20:
            return "Clean", "none"
        elif confidence < 0.40:
            return "Low", "low"
        elif confidence < 0.60:
            return "Medium", "medium"
        elif confidence < 0.80:
            return "High", "high"
        else:
            return "Critical", "critical"

    @staticmethod
    def _join_list(items: list[str]) -> str:
        """Format a list into a readable English string: 'A, B, and C'."""
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        if len(items) == 2:
            return f"{items[0]} and {items[1]}"
        return ", ".join(items[:-1]) + f", and {items[-1]}"
