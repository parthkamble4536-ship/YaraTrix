"""
YaraTrix Analytics Engine (Phase 4)

Queries the database to compute detection quality metrics:
  - Platform-wide summary stats (total scans, threats found, clean files)
  - Per-rule effectiveness (true positive rate, false positive rate, hit count)
  - MITRE ATT&CK tactic and technique coverage (what we can detect vs. gaps)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from yaratrix.db.models import FileArtifact, MatchEvent, ScanJob

# All 14 MITRE ATT&CK Enterprise tactics in kill-chain order
ALL_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
]


# ─────────────────────────────────────────────────────────────────────────────
#  Data classes for analytics output
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class RuleStats:
    """Statistics for a single YARA rule."""

    rule_name: str
    total_hits: int = 0
    true_positives: int = 0
    false_positives: int = 0
    effectiveness_score: float = 0.0  # TP / (TP + FP), 0 if no feedback

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "total_hits": self.total_hits,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "effectiveness_score": round(self.effectiveness_score, 3),
            "noise_level": "high"
            if self.false_positives > self.true_positives
            else "medium"
            if self.false_positives > 0
            else "low",
        }


@dataclass
class CoverageReport:
    """MITRE ATT&CK coverage report."""

    covered_tactics: list[str] = field(default_factory=list)
    missing_tactics: list[str] = field(default_factory=list)
    covered_techniques: list[str] = field(default_factory=list)
    coverage_percentage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage_percentage": round(self.coverage_percentage, 1),
            "covered_tactics": self.covered_tactics,
            "missing_tactics": self.missing_tactics,
            "covered_techniques": sorted(self.covered_techniques),
            "tactic_count": len(self.covered_tactics),
            "missing_count": len(self.missing_tactics),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Analytics Engine
# ─────────────────────────────────────────────────────────────────────────────


class AnalyticsEngine:
    """
    Reads from the database and computes platform-level threat intelligence
    analytics. All methods accept an active SQLAlchemy Session.
    """

    def get_summary(self, db: Session) -> dict[str, Any]:
        """
        Platform-wide summary statistics.

        Returns totals for scans, threats, false positives, and average
        confidence across all completed scans.
        """
        total_jobs = db.query(func.count(ScanJob.id)).scalar() or 0
        completed_jobs = (
            db.query(func.count(ScanJob.id)).filter(ScanJob.status == "completed").scalar() or 0
        )
        failed_jobs = (
            db.query(func.count(ScanJob.id)).filter(ScanJob.status == "failed").scalar() or 0
        )

        total_artifacts = db.query(func.count(FileArtifact.id)).scalar() or 0
        threat_artifacts = (
            db.query(func.count(FileArtifact.id))
            .filter(FileArtifact.confidence_score > 0.0)
            .scalar()
            or 0
        )
        clean_artifacts = total_artifacts - threat_artifacts

        avg_confidence = (
            db.query(func.avg(FileArtifact.confidence_score))
            .filter(FileArtifact.confidence_score > 0.0)
            .scalar()
            or 0.0
        )

        total_events = db.query(func.count(MatchEvent.id)).scalar() or 0
        false_positives = (
            db.query(func.count(MatchEvent.id))
            .filter(MatchEvent.is_false_positive.is_(True))
            .scalar()
            or 0
        )

        # Top 5 most triggered rules
        top_rules = (
            db.query(MatchEvent.rule_name, func.count(MatchEvent.id).label("hits"))
            .group_by(MatchEvent.rule_name)
            .order_by(func.count(MatchEvent.id).desc())
            .limit(5)
            .all()
        )

        return {
            "scan_jobs": {
                "total": total_jobs,
                "completed": completed_jobs,
                "failed": failed_jobs,
                "pending": total_jobs - completed_jobs - failed_jobs,
            },
            "artifacts": {
                "total_scanned": total_artifacts,
                "threats_detected": threat_artifacts,
                "clean_files": clean_artifacts,
                "average_confidence": round(float(avg_confidence), 3),
            },
            "match_events": {
                "total": total_events,
                "confirmed_false_positives": false_positives,
            },
            "top_triggered_rules": [{"rule": row.rule_name, "hits": row.hits} for row in top_rules],
        }

    def get_rule_effectiveness(self, db: Session) -> list[dict[str, Any]]:
        """
        Per-rule effectiveness metrics sorted by total hit count (descending).

        For each rule seen in MatchEvents, compute:
          - Total hits
          - Analyst-confirmed true positives
          - Analyst-confirmed false positives
          - Effectiveness score (TP rate)
          - Noise level (low/medium/high)
        """
        # Aggregate: total hits per rule
        hits_query = (
            db.query(MatchEvent.rule_name, func.count(MatchEvent.id).label("total"))
            .group_by(MatchEvent.rule_name)
            .all()
        )

        # Aggregate: false positives per rule
        fp_query = (
            db.query(MatchEvent.rule_name, func.count(MatchEvent.id).label("fps"))
            .filter(MatchEvent.is_false_positive.is_(True))
            .group_by(MatchEvent.rule_name)
            .all()
        )
        fp_map: dict[str, int] = {row.rule_name: row.fps for row in fp_query}

        results: list[RuleStats] = []
        for row in hits_query:
            fps = fp_map.get(row.rule_name, 0)
            tps = row.total - fps
            # Effectiveness = TP / total (only if analyst has reviewed any)
            reviewed = tps + fps
            score = (tps / reviewed) if reviewed > 0 else 0.0

            results.append(
                RuleStats(
                    rule_name=row.rule_name,
                    total_hits=row.total,
                    true_positives=tps,
                    false_positives=fps,
                    effectiveness_score=score,
                )
            )

        # Sort by total hits descending
        results.sort(key=lambda r: r.total_hits, reverse=True)
        return [r.to_dict() for r in results]

    def get_coverage(self, db: Session) -> dict[str, Any]:
        """
        MITRE ATT&CK coverage analysis.

        Compares the tactics/techniques seen in loaded rules against the
        complete list of 14 ATT&CK Enterprise tactics to surface gaps.
        """
        # All unique tactics ever triggered
        tactic_rows = (
            db.query(MatchEvent.mitre_tactics)
            .filter(MatchEvent.mitre_tactics != "")
            .distinct()
            .all()
        )

        # All unique technique IDs ever triggered
        technique_rows = (
            db.query(MatchEvent.mitre_techniques)
            .filter(MatchEvent.mitre_techniques != "")
            .distinct()
            .all()
        )

        # Normalize tactic names to match our ALL_TACTICS list
        raw_tactics: set[str] = set()
        for row in tactic_rows:
            for t in row.mitre_tactics.split(","):
                normalized = t.strip().replace("_", " ").replace("-", " ").title()
                raw_tactics.add(normalized)

        covered_tactics = [
            t
            for t in ALL_TACTICS
            if t in raw_tactics
            or t.replace(" ", "_").lower() in {r.replace(" ", "_").lower() for r in raw_tactics}
        ]
        missing_tactics = [t for t in ALL_TACTICS if t not in covered_tactics]

        covered_techniques: list[str] = []
        for row in technique_rows:
            for tid in row.mitre_techniques.split(","):
                tid = tid.strip().upper()
                if tid and tid not in covered_techniques:
                    covered_techniques.append(tid)

        coverage_pct = (len(covered_tactics) / len(ALL_TACTICS)) * 100

        report = CoverageReport(
            covered_tactics=covered_tactics,
            missing_tactics=missing_tactics,
            covered_techniques=covered_techniques,
            coverage_percentage=coverage_pct,
        )

        result = report.to_dict()

        # Enrich with tactic-level technique counts
        tactic_breakdown: dict[str, int] = defaultdict(int)
        for row in technique_rows:
            for tid in row.mitre_techniques.split(","):
                tid = tid.strip()
                if tid:
                    tactic_breakdown["detected"] += 1

        result["detection_gap_advice"] = (
            f"YaraTrix rules currently cover {len(covered_tactics)} of "
            f"{len(ALL_TACTICS)} MITRE ATT&CK tactics. "
            f"Consider adding rules for: {', '.join(missing_tactics) if missing_tactics else 'all tactics covered!'}."
        )

        return result
