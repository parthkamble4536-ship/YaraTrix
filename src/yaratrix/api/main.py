"""
YaraTrix FastAPI Application.

Endpoints:
  GET  /health               Health check + version info
  POST /scan                 Upload a file and receive a full JSON scan report (synchronous)
  GET  /techniques           List ATT&CK technique IDs supported by the local STIX bundle
  GET  /rules                List all loaded YARA rules
  POST /export/navigator     Upload a file and receive a Navigator layer JSON
  POST /export/report        Upload a file and receive an HTML report

  [Phase 3 - Async Jobs]
  POST /jobs/scan            Submit a file for async scanning; returns job_id immediately
  GET  /jobs/{job_id}        Poll a job's status and retrieve results when complete

  [Phase 4 - Analytics & Feedback]
  PATCH /events/{event_id}/feedback   Mark a MatchEvent as True or False Positive
  GET   /analytics/summary            Platform-wide scan and detection statistics
  GET   /analytics/rules              Per-rule effectiveness metrics (TP/FP rates)
  GET   /analytics/coverage           MITRE ATT&CK tactic and technique coverage gaps

Design principles:
  - File size limit enforced (default 50 MB)
  - Validation errors return 422 with human-readable messages
  - All errors return structured JSON (never raw exceptions)
  - Rules and STIX data are loaded once at startup via lifespan
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from yaratrix import __version__
from yaratrix.attack_client import AttackClient, get_default_client
from yaratrix.mapper import map_scan_result, map_scan_results
from yaratrix.navigator_export import build_navigator_layer
from yaratrix.report_generator import render_report
from yaratrix.rule_loader import RuleLoaderResult, load_rules
from yaratrix.yara_engine import scan_file
from sqlalchemy.orm import Session
from sqlalchemy import text
from yaratrix.db.session import get_db
from yaratrix.db.models import ScanJob, FileArtifact, MatchEvent
from yaratrix.intelligence import IntelligenceEngine, RuleMatchInput
from yaratrix.worker.tasks import scan_file_async
from yaratrix.analytics import AnalyticsEngine

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_RULES_DIR = _PROJECT_ROOT / "rules"
MAX_FILE_SIZE_MB = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


# ─────────────────────────────────────────────────────────────────────────────
#  App state (loaded once at startup)
# ─────────────────────────────────────────────────────────────────────────────


class _AppState:
    loader: RuleLoaderResult | None = None
    attack_client: AttackClient | None = None
    startup_time: str = ""
    rules_dir: str = str(DEFAULT_RULES_DIR)


_state = _AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load rules and STIX data once at startup."""
    logger.info("YaraTrix API starting up…")
    _state.startup_time = datetime.now(tz=UTC).isoformat()

    # Load YARA rules
    try:
        _state.loader = load_rules(DEFAULT_RULES_DIR)
        rule_count = sum(1 for _ in _state.loader.compiled) if _state.loader.compiled else 0
        logger.info("Loaded %d YARA rule(s) from %s", rule_count, DEFAULT_RULES_DIR)
    except Exception as exc:
        logger.error("Failed to load YARA rules: %s", exc)

    # Load STIX bundle
    try:
        _state.attack_client = get_default_client()
        logger.info("MITRE ATT&CK STIX bundle loaded.")
    except Exception as exc:
        logger.warning("STIX bundle not available: %s", exc)

    yield  # Application runs here

    logger.info("YaraTrix API shutting down.")


# ─────────────────────────────────────────────────────────────────────────────
#  FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="YaraTrix API",
    description=(
        "YARA-to-MITRE ATT&CK Mapping Engine REST API.\n\n"
        "Upload files to scan them against custom YARA rules and receive "
        "enriched ATT&CK technique mappings, confidence scores, and "
        "Navigator-compatible heatmap layers."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _require_rules() -> RuleLoaderResult:
    if _state.loader is None or _state.loader.compiled is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="YARA rules are not loaded. Check server logs.",
        )
    return _state.loader


def _validate_file_size(file: UploadFile) -> None:
    """Raise 413 if file exceeds size limit (if content-length header is present)."""
    if file.size and file.size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {MAX_FILE_SIZE_MB} MB.",
        )


async def _read_upload_to_temp(file: UploadFile) -> Path:
    """
    Stream an uploaded file to a secure temp file and return its path.
    Enforces the MAX_FILE_SIZE_BYTES limit during streaming.
    """
    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {MAX_FILE_SIZE_MB} MB.",
        )

    suffix = Path(file.filename or "upload").suffix or ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        return Path(tmp.name)


# ─────────────────────────────────────────────────────────────────────────────
#  Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@app.get(
    "/health",
    summary="Health check",
    tags=["System"],
    response_model=dict,
)
async def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Returns the API health status, version, rule count, STIX availability, and DB connection status.
    """
    rule_count = 0
    if _state.loader and _state.loader.compiled:
        rule_count = sum(1 for _ in _state.loader.compiled)

    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        db_status = "disconnected"

    return {
        "status": "healthy",
        "version": __version__,
        "startup_time": _state.startup_time,
        "rules_loaded": rule_count,
        "stix_available": _state.attack_client is not None,
        "db_status": db_status,
        "rules_dir": _state.rules_dir,
        "max_file_size_mb": MAX_FILE_SIZE_MB,
    }


@app.get(
    "/rules",
    summary="List loaded YARA rules",
    tags=["Rules"],
)
async def list_rules() -> dict[str, Any]:
    """
    Return metadata for all currently loaded YARA rules.
    """
    loader = _require_rules()
    rules = []
    for rule in loader.compiled:
        meta = rule.meta or {}
        rules.append(
            {
                "name": rule.identifier,
                "mitre_technique": meta.get("mitre_technique", ""),
                "mitre_tactic": meta.get("mitre_tactic", ""),
                "severity": meta.get("severity", ""),
                "description": meta.get("description", ""),
                "tags": list(rule.tags),
            }
        )

    return {
        "count": len(rules),
        "rules": rules,
        "validation_issues": len(loader.errors),
    }


@app.get(
    "/techniques",
    summary="List supported ATT&CK techniques",
    tags=["ATT&CK"],
)
async def list_techniques(
    limit: int = Query(100, ge=1, le=1000, description="Max techniques to return"),
) -> dict[str, Any]:
    """
    List ATT&CK technique IDs available in the locally cached STIX bundle.
    """
    if _state.attack_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="STIX bundle not available. Run download_mitre_data.py first.",
        )
    techniques = _state.attack_client.list_techniques()[:limit]
    return {
        "count": len(techniques),
        "techniques": techniques,
    }


@app.post(
    "/scan",
    summary="Scan an uploaded file",
    tags=["Scanning"],
)
async def scan_upload(
    file: UploadFile = File(..., description="File to scan (max 50 MB)"),
    enrich: bool = Query(True, description="Enrich results with ATT&CK technique data"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Upload a file, scan it against loaded YARA rules, and return a structured
    JSON report with optional ATT&CK enrichment.

    **Response includes:**
    - Matched rules with technique/tactic/severity/strings
    - ATT&CK technique metadata (name, description, mitigations, URL)
    - Confidence score and threat level
    - Behavioral narrative (Intelligence Engine)
    - Narrative summary
    """
    loader = _require_rules()
    _validate_file_size(file)

    tmp_path = await _read_upload_to_temp(file)
    original_name = file.filename or "upload"
    file_content = tmp_path.read_bytes()
    file_hash = hashlib.sha256(file_content).hexdigest()
    file_size = len(file_content)

    # Create a ScanJob record in the DB
    job = ScanJob(status="running", target_path=original_name)
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        result = scan_file(loader.compiled, tmp_path, rule_file_map=loader.filepaths)
        result.target_file = original_name

        # Persist the FileArtifact to DB
        artifact = FileArtifact(
            job_id=job.id,
            file_path=original_name,
            file_hash=file_hash,
            file_size=file_size,
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        # Run the Intelligence Engine
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

        # Update confidence score on the artifact
        artifact.confidence_score = intel_report.confidence_score
        db.commit()

        # Persist each MatchEvent
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

        # Mark job complete
        job.status = "completed"
        job.completed_at = datetime.now(tz=UTC)
        db.commit()

        # Build response
        response: dict[str, Any] = result.to_dict()
        response["intelligence"] = intel_report.to_dict()
        response["scan_job_id"] = job.id
        response["artifact_id"] = artifact.id

        if enrich and result.matches and _state.attack_client:
            mapping = map_scan_result(result, client=_state.attack_client)
            response["mitre_mapping"] = mapping.to_dict()

        return response
    except Exception as exc:
        job.status = "failed"
        db.commit()
        logger.error("Scan failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {exc}",
        )
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass


@app.post(
    "/export/navigator",
    summary="Export Navigator layer for an uploaded file",
    tags=["Export"],
)
async def export_navigator(
    file: UploadFile = File(..., description="File to scan (max 50 MB)"),
) -> Response:
    """
    Upload a file and receive a downloadable MITRE ATT&CK Navigator JSON layer.

    Import the returned JSON at https://mitre-attack.github.io/attack-navigator/
    """
    loader = _require_rules()
    _validate_file_size(file)

    if _state.attack_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="STIX bundle not available.",
        )

    tmp_path = await _read_upload_to_temp(file)
    original_name = file.filename or "upload"

    try:
        result = scan_file(loader.compiled, tmp_path, rule_file_map=loader.filepaths)
        result.target_file = original_name

        if not result.matches:
            raise HTTPException(
                status_code=status.HTTP_204_NO_CONTENT,
                detail="No YARA matches found — no layer to export.",
            )

        mappings = map_scan_results([result], client=_state.attack_client)
        layer = build_navigator_layer(
            mappings,
            layer_name=f"YaraTrix — {original_name}",
        )

        import json

        layer_json = json.dumps(layer, indent=2, ensure_ascii=False)
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in original_name)
        filename = f"yaratrix_{safe_name}_navigator.json"

        return Response(
            content=layer_json,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass


@app.post(
    "/export/report",
    summary="Generate HTML report for an uploaded file",
    tags=["Export"],
)
async def export_report(
    file: UploadFile = File(..., description="File to scan (max 50 MB)"),
) -> Response:
    """
    Upload a file and receive a downloadable HTML threat analysis report.

    The report includes:
    - Threat level and confidence score
    - Kill-chain coverage heatmap
    - ATT&CK technique breakdown
    - Rule match cards
    """
    loader = _require_rules()
    _validate_file_size(file)

    tmp_path = await _read_upload_to_temp(file)
    original_name = file.filename or "upload"

    try:
        result = scan_file(loader.compiled, tmp_path, rule_file_map=loader.filepaths)
        result.target_file = original_name

        mappings = []
        if result.matches and _state.attack_client:
            mappings = map_scan_results([result], client=_state.attack_client)

        # Write to a temp HTML file, then read it back for the response
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_html:
            html_path = Path(tmp_html.name)

        render_report(
            [result],
            mappings,
            html_path,
            report_title=original_name,
        )

        html_content = html_path.read_text(encoding="utf-8")
        html_path.unlink(missing_ok=True)

        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in original_name)
        filename = f"yaratrix_{safe_name}_report.html"

        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  Phase 3: Async Job Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@app.post(
    "/jobs/scan",
    summary="Submit a file for async scanning (non-blocking)",
    tags=["Async Jobs"],
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_scan_job(
    file: UploadFile = File(..., description="File to scan (max 50 MB)"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Submit a file for asynchronous scanning.

    This endpoint returns **immediately** with a `job_id`. The actual scan
    runs in a background Celery worker. Poll `GET /jobs/{job_id}` to check
    progress and retrieve results when the job completes.

    **Use this endpoint for large files or batch workflows.**
    """
    _validate_file_size(file)
    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {MAX_FILE_SIZE_MB} MB.",
        )

    original_name = file.filename or "upload"

    # Write a ScanJob record immediately so we have an ID to return
    job = ScanJob(status="pending", target_path=original_name)
    db.add(job)
    db.commit()
    db.refresh(job)

    # Push the scan task to Redis queue (non-blocking)
    scan_file_async.delay(
        job_id=job.id,
        file_bytes_hex=content.hex(),
        original_filename=original_name,
    )

    return {
        "job_id": job.id,
        "status": "pending",
        "filename": original_name,
        "message": f"Scan job submitted. Poll GET /jobs/{job.id} for results.",
    }


@app.get(
    "/jobs/{job_id}",
    summary="Get async scan job status and results",
    tags=["Async Jobs"],
)
async def get_job_status(
    job_id: int,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Retrieve the status and results of an async scan job.

    **Job statuses:**
    - `pending` — Job is queued, waiting for a worker
    - `running` — Worker has picked up the job and is scanning
    - `completed` — Scan is done, results are available
    - `failed` — Something went wrong during scanning
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found.",
        )

    response: dict[str, Any] = {
        "job_id": job.id,
        "status": job.status,
        "target": job.target_path,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

    # If completed, include artifact + match event details
    if job.status == "completed":
        artifacts = db.query(FileArtifact).filter(FileArtifact.job_id == job_id).all()
        artifact_data = []
        for artifact in artifacts:
            events = db.query(MatchEvent).filter(MatchEvent.artifact_id == artifact.id).all()
            artifact_data.append({
                "artifact_id": artifact.id,
                "file_path": artifact.file_path,
                "file_hash": artifact.file_hash,
                "file_size": artifact.file_size,
                "confidence_score": artifact.confidence_score,
                "match_events": [
                    {
                        "rule_name": e.rule_name,
                        "mitre_techniques": e.mitre_techniques,
                        "mitre_tactics": e.mitre_tactics,
                        "severity": e.severity,
                        "is_false_positive": e.is_false_positive,
                    }
                    for e in events
                ],
            })
        response["artifacts"] = artifact_data

    return response


# ─────────────────────────────────────────────────────────────────────────────
#  Phase 4: Analytics & Feedback Loop
# ─────────────────────────────────────────────────────────────────────────────


@app.patch(
    "/events/{event_id}/feedback",
    summary="Submit analyst feedback on a match event (True/False Positive)",
    tags=["Analytics"],
)
async def submit_event_feedback(
    event_id: int,
    is_false_positive: bool,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Mark a specific `MatchEvent` as a True Positive or False Positive.

    This analyst feedback powers the Rule Effectiveness analytics,
    helping identify noisy rules that generate too many false alarms.

    - `is_false_positive=true`  — Analyst says this match is NOT real
    - `is_false_positive=false` — Analyst confirms this IS a real threat
    """
    event = db.query(MatchEvent).filter(MatchEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MatchEvent {event_id} not found.",
        )

    event.is_false_positive = is_false_positive
    db.commit()
    db.refresh(event)

    return {
        "event_id": event.id,
        "rule_name": event.rule_name,
        "is_false_positive": event.is_false_positive,
        "message": "Feedback recorded. Analytics will reflect this update.",
    }


@app.get(
    "/analytics/summary",
    summary="Platform-wide detection statistics",
    tags=["Analytics"],
)
async def analytics_summary(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Returns platform-wide statistics including:
    - Total scan jobs (pending/completed/failed)
    - Files scanned, threats detected, clean files
    - Average confidence score across all threat detections
    - Top 5 most frequently triggered YARA rules
    - Total match events and confirmed false positives
    """
    engine = AnalyticsEngine()
    return engine.get_summary(db)


@app.get(
    "/analytics/rules",
    summary="Per-rule effectiveness metrics",
    tags=["Analytics"],
)
async def analytics_rules(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Returns per-rule detection quality metrics:
    - **Total hits**: How many times each rule has fired
    - **True/False positives**: Based on analyst feedback
    - **Effectiveness score**: TP / (TP + FP)
    - **Noise level**: low / medium / high

    Rules with `noise_level: high` are candidates for tuning or removal.
    """
    engine = AnalyticsEngine()
    rules = engine.get_rule_effectiveness(db)
    return {
        "total_rules_seen": len(rules),
        "rules": rules,
    }


@app.get(
    "/analytics/coverage",
    summary="MITRE ATT&CK tactic and technique coverage analysis",
    tags=["Analytics"],
)
async def analytics_coverage(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Analyses your YARA ruleset's coverage across the MITRE ATT&CK framework.

    Returns:
    - **Coverage %**: Percentage of ATT&CK tactics your rules cover
    - **Covered tactics**: Tactics you can currently detect
    - **Missing tactics**: Blind spots in your detection capability
    - **Covered techniques**: All unique technique IDs seen in rules
    - **Gap advice**: Actionable recommendation on what to add next
    """
    engine = AnalyticsEngine()
    return engine.get_coverage(db)
