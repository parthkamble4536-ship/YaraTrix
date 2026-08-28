"""
YaraTrix Celery Tasks (Phase 3)

Defines the async scan task that runs inside a Celery worker.

Workflow:
  1. API endpoint receives file bytes + metadata → writes ScanJob (status=pending) → pushes task to Redis
  2. Celery worker picks up the task from Redis
  3. Worker runs YARA engine + Intelligence Engine
  4. Worker persists FileArtifact + MatchEvents to DB
  5. Worker updates ScanJob status to "completed"
  6. Client polls GET /jobs/{job_id} to retrieve results
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from celery import Task

from yaratrix.worker.celery_app import celery_app
from yaratrix.db.session import SessionLocal
from yaratrix.db.models import ScanJob, FileArtifact, MatchEvent
from yaratrix.intelligence import IntelligenceEngine, RuleMatchInput
from yaratrix.rule_loader import load_rules
from yaratrix.yara_engine import scan_file
from yaratrix.mapper import map_scan_results
from yaratrix.attack_client import get_default_client

logger = logging.getLogger(__name__)

# Default rules directory (relative to project root when running in Docker)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_RULES_DIR = _PROJECT_ROOT / "rules"


class ScanTask(Task):
    """
    Custom Celery Task base class with lazy-loaded shared resources.
    Resources are loaded once per worker process, not once per task.
    """
    _rules = None
    _attack_client = None

    @property
    def rules(self):
        if self._rules is None:
            logger.info("Worker: Loading YARA rules from %s", DEFAULT_RULES_DIR)
            self._rules = load_rules(DEFAULT_RULES_DIR)
        return self._rules

    @property
    def attack_client(self):
        if self._attack_client is None:
            try:
                logger.info("Worker: Loading MITRE ATT&CK STIX bundle")
                self._attack_client = get_default_client()
            except Exception as exc:
                logger.warning("Worker: STIX bundle unavailable: %s", exc)
        return self._attack_client


@celery_app.task(
    bind=True,
    base=ScanTask,
    name="yaratrix.scan_file_async",
    max_retries=3,
    default_retry_delay=10,
)
def scan_file_async(
    self: ScanTask,
    job_id: int,
    file_bytes_hex: str,
    original_filename: str,
) -> dict:
    """
    Async Celery task: Scan a file and persist results to the database.

    Args:
        job_id: The ScanJob ID already written to DB (status=pending).
        file_bytes_hex: Hex-encoded file content (safe for JSON serialization).
        original_filename: The original uploaded filename.

    Returns:
        A dict with job_id, artifact_id, confidence, and tactic_coverage.
    """
    db = SessionLocal()
    tmp_path = None

    try:
        # Update job status to running
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise ValueError(f"ScanJob {job_id} not found in database")

        job.status = "running"
        db.commit()

        # Decode the file bytes
        file_bytes = bytes.fromhex(file_bytes_hex)
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        file_size = len(file_bytes)

        # Write to a temp file so the YARA engine can scan it
        suffix = Path(original_filename).suffix or ".bin"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = Path(tmp.name)

        # Run the YARA scan
        loader = self.rules
        result = scan_file(loader.compiled, tmp_path, rule_file_map=loader.filepaths)
        result.target_file = original_filename

        # Persist FileArtifact
        artifact = FileArtifact(
            job_id=job_id,
            file_path=original_filename,
            file_hash=file_hash,
            file_size=file_size,
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        # Run Intelligence Engine
        intel_engine = IntelligenceEngine()
        match_inputs = [
            RuleMatchInput(
                rule_name=m.rule_name,
                severity=m.meta.get("severity", "medium") if m.meta else "medium",
                mitre_technique=m.meta.get("mitre_technique", "") if m.meta else "",
                mitre_tactic=m.meta.get("mitre_tactic", "") if m.meta else "",
                description=m.meta.get("description", "") if m.meta else "",
            )
            for m in result.matches
        ]
        intel_report = intel_engine.analyze(match_inputs)

        # Update confidence on artifact
        artifact.confidence_score = intel_report.confidence_score
        db.commit()

        # Persist MatchEvents
        for mi in match_inputs:
            event = MatchEvent(
                artifact_id=artifact.id,
                rule_name=mi.rule_name,
                mitre_techniques=mi.mitre_technique,
                mitre_tactics=mi.mitre_tactic,
                severity=mi.severity,
                description=mi.description,
            )
            db.add(event)

        # ATT&CK enrichment
        mitre_mapping = None
        if result.matches and self.attack_client:
            mappings = map_scan_results([result], client=self.attack_client)
            mitre_mapping = mappings[0].to_dict() if mappings else None

        # Mark job complete and store result summary on it
        job.status = "completed"
        job.completed_at = datetime.now(tz=UTC)
        db.commit()

        logger.info(
            "Worker: Scan complete for job=%d artifact=%d confidence=%.2f",
            job_id, artifact.id, intel_report.confidence_score,
        )

        return {
            "job_id": job_id,
            "artifact_id": artifact.id,
            "filename": original_filename,
            "file_hash": file_hash,
            "intelligence": intel_report.to_dict(),
            "scan_result": result.to_dict(),
            "mitre_mapping": mitre_mapping,
        }

    except Exception as exc:
        logger.error("Worker: Scan task failed for job=%d: %s", job_id, exc)
        # Mark job as failed in DB
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = "failed"
                db.commit()
        except Exception:
            pass
        # Retry with exponential backoff
        raise self.retry(exc=exc)

    finally:
        db.close()
        if tmp_path:
            try:
                tmp_path.unlink()
            except Exception:
                pass
