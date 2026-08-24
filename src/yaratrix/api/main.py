"""
YaraTrix FastAPI Application.

Endpoints:
  GET  /health               Health check + version info
  POST /scan                 Upload a file and receive a full JSON scan report
  GET  /techniques           List ATT&CK technique IDs supported by the local STIX bundle
  GET  /rules                List all loaded YARA rules
  POST /export/navigator     Upload a file and receive a Navigator layer JSON
  POST /export/report        Upload a file and receive an HTML report

Design principles:
  - File size limit enforced (default 50 MB)
  - Validation errors return 422 with human-readable messages
  - All errors return structured JSON (never raw exceptions)
  - Rules and STIX data are loaded once at startup via lifespan
"""

from __future__ import annotations

import logging
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from yaratrix import __version__
from yaratrix.attack_client import AttackClient, get_default_client
from yaratrix.mapper import map_scan_result, map_scan_results
from yaratrix.navigator_export import build_navigator_layer
from yaratrix.report_generator import render_report
from yaratrix.rule_loader import RuleLoaderResult, load_rules
from yaratrix.yara_engine import scan_file

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
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
async def health() -> dict[str, Any]:
    """
    Returns the API health status, version, rule count, and STIX availability.
    """
    rule_count = 0
    if _state.loader and _state.loader.compiled:
        rule_count = sum(1 for _ in _state.loader.compiled)

    return {
        "status": "healthy",
        "version": __version__,
        "startup_time": _state.startup_time,
        "rules_loaded": rule_count,
        "stix_available": _state.attack_client is not None,
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
) -> dict[str, Any]:
    """
    Upload a file, scan it against loaded YARA rules, and return a structured
    JSON report with optional ATT&CK enrichment.

    **Response includes:**
    - Matched rules with technique/tactic/severity/strings
    - ATT&CK technique metadata (name, description, mitigations, URL)
    - Confidence score and threat level
    - Narrative summary
    """
    loader = _require_rules()
    _validate_file_size(file)

    tmp_path = await _read_upload_to_temp(file)
    original_name = file.filename or "upload"

    try:
        result = scan_file(loader.compiled, tmp_path, rule_file_map=loader.filepaths)
        # Restore the original filename in the result for cleaner reporting
        result.target_file = original_name

        response: dict[str, Any] = result.to_dict()

        if enrich and result.matches and _state.attack_client:
            mapping = map_scan_result(result, client=_state.attack_client)
            response["mitre_mapping"] = mapping.to_dict()

        return response
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
