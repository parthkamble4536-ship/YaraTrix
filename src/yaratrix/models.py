"""
Data models for YaraTrix.

Defines the core dataclasses that act as clean contracts between
the scanning engine, mapping layer, and reporting/API layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Rule severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MatchedString:
    """A single matched string or pattern offset within a scanned file."""

    identifier: str  # e.g. "$encoded_ps"
    offset: int  # byte offset in the file
    data: bytes  # raw matched bytes (truncated to 128 bytes for safety)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "offset": self.offset,
            "data": self.data.hex(),
        }


@dataclass
class RuleMatch:
    """
    A single YARA rule match against a target file.

    Attributes:
        rule_name:        The YARA rule identifier.
        rule_file:        Path to the .yar file the rule came from.
        mitre_technique:  Technique ID(s), e.g. "T1059.001" or "T1059.001,T1027".
        mitre_tactic:     Tactic name(s), e.g. "execution" or "execution,defense-evasion".
        severity:         Severity level of this rule.
        description:      Human-readable description of what the rule detects.
        tags:             Optional YARA rule tags.
        matched_strings:  List of matched string offsets.
        meta:             Raw rule meta dictionary (for any extra fields).
    """

    rule_name: str
    rule_file: str
    mitre_technique: str
    mitre_tactic: str
    severity: Severity
    description: str
    tags: list[str] = field(default_factory=list)
    matched_strings: list[MatchedString] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def technique_ids(self) -> list[str]:
        """Return individual technique IDs (handles comma-separated values)."""
        return [t.strip() for t in self.mitre_technique.split(",") if t.strip()]

    def tactic_names(self) -> list[str]:
        """Return individual tactic names (handles comma-separated values)."""
        return [t.strip().lower() for t in self.mitre_tactic.split(",") if t.strip()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "rule_file": self.rule_file,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "severity": self.severity.value,
            "description": self.description,
            "tags": self.tags,
            "matched_strings": [s.to_dict() for s in self.matched_strings],
        }


@dataclass
class ScanResult:
    """
    Complete scan result for a single target file.

    Attributes:
        target_file:      Absolute path of the scanned file.
        scan_time:        When the scan started.
        duration_ms:      How long the scan took in milliseconds.
        matches:          List of all rule matches found.
        errors:           Any non-fatal errors encountered during scanning.
    """

    target_file: str
    scan_time: datetime
    duration_ms: float
    matches: list[RuleMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---  Convenience helpers  ---

    def matched_techniques(self) -> list[str]:
        """Unique technique IDs across all matches."""
        seen: set[str] = set()
        result = []
        for m in self.matches:
            for t in m.technique_ids():
                if t not in seen:
                    seen.add(t)
                    result.append(t)
        return result

    def matched_tactics(self) -> list[str]:
        """Unique tactic names across all matches."""
        seen: set[str] = set()
        result = []
        for m in self.matches:
            for t in m.tactic_names():
                if t not in seen:
                    seen.add(t)
                    result.append(t)
        return result

    def severity_counts(self) -> dict[str, int]:
        """Count matches per severity level."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for m in self.matches:
            counts[m.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_file": self.target_file,
            "scan_time": self.scan_time.isoformat(),
            "duration_ms": round(self.duration_ms, 2),
            "match_count": len(self.matches),
            "techniques": self.matched_techniques(),
            "tactics": self.matched_tactics(),
            "severity_counts": self.severity_counts(),
            "matches": [m.to_dict() for m in self.matches],
            "errors": self.errors,
        }


@dataclass
class DirectoryScanSummary:
    """
    Aggregated summary for a directory-wide scan.

    Attributes:
        root_path:    The directory that was scanned.
        scan_time:    When the scan started.
        results:      Per-file ScanResult objects.
    """

    root_path: str
    scan_time: datetime
    results: list[ScanResult] = field(default_factory=list)

    def total_files(self) -> int:
        return len(self.results)

    def total_matches(self) -> int:
        return sum(len(r.matches) for r in self.results)

    def files_with_matches(self) -> list[ScanResult]:
        return [r for r in self.results if r.matches]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_path": self.root_path,
            "scan_time": self.scan_time.isoformat(),
            "total_files_scanned": self.total_files(),
            "files_with_matches": len(self.files_with_matches()),
            "total_matches": self.total_matches(),
            "results": [r.to_dict() for r in self.files_with_matches()],
        }
