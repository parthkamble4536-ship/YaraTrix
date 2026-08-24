"""
MITRE ATT&CK Client for YaraTrix.

Wraps mitreattack-python's MitreAttackData to resolve technique IDs
into full metadata: name, tactic(s), sub-techniques, description,
URL, mitigations, and detection guidance.

Results are cached in-process after the first lookup so repeated
calls for the same technique are free.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)

# Default path to the locally cached STIX bundle (downloaded in Phase 0).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_STIX_PATH = _PROJECT_ROOT / "data" / "enterprise-attack.json"


# ─────────────────────────────────────────────────────────────────────────────
#  Data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class MitigationInfo:
    """A single mitigation linked to a technique."""

    mitigation_id: str  # e.g. "M1038"
    name: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return {
            "mitigation_id": self.mitigation_id,
            "name": self.name,
            "description": self.description[:300],
        }


@dataclass
class TechniqueInfo:
    """Full metadata for a single MITRE ATT&CK technique or sub-technique."""

    technique_id: str  # e.g. "T1059.001"
    name: str  # e.g. "PowerShell"
    tactics: list[str]  # tactic short names e.g. ["execution"]
    description: str
    url: str  # ATT&CK website link
    is_subtechnique: bool
    parent_technique_id: str  # empty if not a sub-technique
    sub_techniques: list[str]  # IDs of sub-techniques (empty for sub-techniques)
    mitigations: list[MitigationInfo] = field(default_factory=list)
    detection: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": self.tactics,
            "description": self.description[:500],
            "url": self.url,
            "is_subtechnique": self.is_subtechnique,
            "parent_technique_id": self.parent_technique_id,
            "sub_techniques": self.sub_techniques,
            "mitigations": [m.to_dict() for m in self.mitigations],
            "detection": self.detection[:300],
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Attack Client
# ─────────────────────────────────────────────────────────────────────────────


class AttackClient:
    """
    Thin wrapper around MitreAttackData for technique lookups.

    Usage:
        client = AttackClient()
        info = client.get_technique("T1059.001")
    """

    def __init__(self, stix_path: str | Path = DEFAULT_STIX_PATH) -> None:
        stix_path = Path(stix_path)
        if not stix_path.exists():
            raise FileNotFoundError(
                f"STIX bundle not found: {stix_path}\n"
                "Run: uv run python scripts/download_mitre_data.py"
            )
        logger.info("Loading MITRE ATT&CK STIX bundle from %s …", stix_path)
        self._data = MitreAttackData(str(stix_path))
        self._technique_cache: dict[str, TechniqueInfo | None] = {}
        logger.info("MITRE ATT&CK data loaded.")

    # ── Public API ─────────────────────────────────────────────────────────

    def get_technique(self, technique_id: str) -> TechniqueInfo | None:
        """
        Resolve a technique ID (e.g. 'T1059', 'T1059.001') to full metadata.

        Returns None if the ID is not found in the local STIX bundle.
        """
        tid = technique_id.strip().upper()
        if tid in self._technique_cache:
            return self._technique_cache[tid]

        result = self._resolve(tid)
        self._technique_cache[tid] = result
        return result

    def get_tactic_name(self, tactic_short: str) -> str:
        """Return the display name for a tactic short name (e.g. 'execution' → 'Execution')."""
        _TACTIC_NAMES = {
            "reconnaissance": "Reconnaissance",
            "resource-development": "Resource Development",
            "initial-access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Access",
            "discovery": "Discovery",
            "lateral-movement": "Lateral Movement",
            "collection": "Collection",
            "command-and-control": "Command and Control",
            "exfiltration": "Exfiltration",
            "impact": "Impact",
        }
        return _TACTIC_NAMES.get(tactic_short.lower(), tactic_short.title())

    def list_techniques(self) -> list[str]:
        """Return all technique IDs available in the local STIX bundle."""
        techniques = self._data.get_techniques(remove_revoked_deprecated=True)
        return [
            t.get("external_references", [{}])[0].get("external_id", "")
            for t in techniques
            if t.get("external_references")
        ]

    # ── Internal resolution ─────────────────────────────────────────────────

    def _resolve(self, technique_id: str) -> TechniqueInfo | None:
        """Internal: perform the actual STIX lookup."""
        try:
            technique = self._data.get_object_by_attack_id(technique_id, "technique")
        except Exception as exc:
            logger.debug("Error looking up technique %s: %s", technique_id, exc)
            technique = None

        if technique is None:
            logger.debug("Technique not found in STIX bundle: %s", technique_id)
            return None

        # STIX2 objects support both attribute access and dict-style access.
        # We normalise to dict via serialise → deserialise for safety.
        try:
            t = dict(technique)
        except Exception:
            try:
                import json as _json

                t = _json.loads(technique.serialize())
            except Exception:
                logger.warning("Could not deserialise STIX object for %s", technique_id)
                return None

        # Extract tactic names from the kill-chain phases
        tactics = [
            phase["phase_name"]
            for phase in t.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # External references (first one is usually ATT&CK URL)
        ext_refs = t.get("external_references", [])
        url = next(
            (r.get("url", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )

        # Parent technique for sub-techniques
        is_subtechnique = t.get("x_mitre_is_subtechnique", False)
        parent_id = ""
        if is_subtechnique and "." in technique_id:
            parent_id = technique_id.split(".")[0]

        # Sub-techniques (only for base techniques)
        sub_technique_ids: list[str] = []
        if not is_subtechnique:
            try:
                sub_techniques = self._data.get_subtechniques_of_technique(t["id"])
                sub_technique_ids = [
                    dict(st).get("external_references", [{}])[0].get("external_id", "")
                    for st in sub_techniques
                    if dict(st).get("external_references")
                ]
            except Exception:
                pass

        # Mitigations
        mitigations: list[MitigationInfo] = []
        try:
            mit_objects = self._data.get_mitigations_mitigating_technique(t["id"])
            for m in mit_objects:
                try:
                    m_obj = dict(m.get("object", m))
                except Exception:
                    m_obj = {}
                ext = m_obj.get("external_references", [{}])
                ext0 = ext[0] if ext else {}
                mitigations.append(
                    MitigationInfo(
                        mitigation_id=ext0.get("external_id", ""),
                        name=m_obj.get("name", ""),
                        description=m_obj.get("description", ""),
                    )
                )
        except Exception:
            pass

        return TechniqueInfo(
            technique_id=technique_id,
            name=t.get("name", ""),
            tactics=tactics,
            description=t.get("description", ""),
            url=url,
            is_subtechnique=is_subtechnique,
            parent_technique_id=parent_id,
            sub_techniques=sub_technique_ids,
            mitigations=mitigations,
            detection=t.get("x_mitre_detection", ""),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level singleton helper
# ─────────────────────────────────────────────────────────────────────────────

_default_client: AttackClient | None = None


def get_default_client(stix_path: str | Path = DEFAULT_STIX_PATH) -> AttackClient:
    """Return a lazily-initialized module-level AttackClient singleton."""
    global _default_client
    if _default_client is None:
        _default_client = AttackClient(stix_path)
    return _default_client
