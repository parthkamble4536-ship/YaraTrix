"""
YARA Scanning Engine for YaraTrix.

Responsibilities:
- Accept compiled YARA rules and scan a single file or recursively scan a directory.
- Return structured ScanResult / DirectoryScanSummary objects.
- Handle common errors gracefully (permission denied, binary files, etc.).
- Report scan timing so the API/CLI can display performance metrics.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import yara

from yaratrix.models import (
    DirectoryScanSummary,
    MatchedString,
    RuleMatch,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)

# Maximum bytes of matched data to store per string (to avoid huge reports).
MAX_MATCH_DATA_BYTES = 128

# File extensions to skip entirely (compiled binaries, archives, media).
# Feel free to tune this set.
SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".rar",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".pdf",
        ".pyc",
        ".pyd",
    }
)


def _build_rule_match(match: yara.Match, rule_file_map: dict[str, str]) -> RuleMatch:
    """
    Convert a raw yara.Match into a structured RuleMatch dataclass.

    Args:
        match:         Raw YARA match object.
        rule_file_map: namespace -> filepath mapping from the loader.

    Returns:
        RuleMatch populated from the match meta and strings.
    """
    meta = match.meta or {}

    # Resolve source file from namespace map.
    rule_file = rule_file_map.get(match.namespace, "unknown")

    # Parse severity with a safe fallback.
    severity_raw = str(meta.get("severity", "medium")).strip().lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.MEDIUM

    matched_strings: list[MatchedString] = []
    for string_match in match.strings:
        for instance in string_match.instances:
            matched_strings.append(
                MatchedString(
                    identifier=string_match.identifier,
                    offset=instance.offset,
                    data=bytes(instance.matched_data)[:MAX_MATCH_DATA_BYTES],
                )
            )

    return RuleMatch(
        rule_name=match.rule,
        rule_file=rule_file,
        mitre_technique=str(meta.get("mitre_technique", "")).strip(),
        mitre_tactic=str(meta.get("mitre_tactic", "")).strip(),
        severity=severity,
        description=str(meta.get("description", "")).strip(),
        tags=list(match.tags),
        matched_strings=matched_strings,
        meta=dict(meta),
    )


def scan_file(
    compiled_rules: yara.Rules,
    target: str | Path,
    rule_file_map: dict[str, str] | None = None,
    *,
    timeout: int = 60,
) -> ScanResult:
    """
    Scan a single file against compiled YARA rules.

    Args:
        compiled_rules: Pre-compiled yara.Rules object.
        target:         Path to the file to scan.
        rule_file_map:  namespace -> filepath mapping (from RuleLoaderResult.filepaths).
        timeout:        Per-file YARA scan timeout in seconds.

    Returns:
        ScanResult for the target file.
    """
    target_path = Path(target).resolve()
    rule_file_map = rule_file_map or {}
    scan_time = datetime.now(tz=UTC)
    errors: list[str] = []
    matches: list[RuleMatch] = []

    start = time.perf_counter()

    if not target_path.exists():
        errors.append(f"File not found: {target_path}")
    elif not target_path.is_file():
        errors.append(f"Not a regular file: {target_path}")
    elif target_path.suffix.lower() in SKIP_EXTENSIONS:
        logger.debug("Skipping excluded extension: %s", target_path)
    else:
        try:
            import sys

            path_str = str(target_path)
            # On Windows, use extended path prefix to handle special chars (e.g. & in dir name)
            if sys.platform == "win32" and not path_str.startswith("\\\\?\\"):
                path_str = "\\\\?\\" + path_str
            with open(path_str, "rb") as fh:
                file_bytes = fh.read()
            raw_matches: list[yara.Match] = compiled_rules.match(data=file_bytes, timeout=timeout)
            for raw_match in raw_matches:
                matches.append(_build_rule_match(raw_match, rule_file_map))
        except yara.TimeoutError:
            errors.append(f"YARA scan timed out after {timeout}s: {target_path}")
            logger.warning("Scan timed out: %s", target_path)
        except PermissionError:
            errors.append(f"Permission denied: {target_path}")
            logger.warning("Permission denied: %s", target_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Unexpected error scanning {target_path}: {exc}")
            logger.error("Error scanning %s: %s", target_path, exc, exc_info=True)

    duration_ms = (time.perf_counter() - start) * 1000

    if matches:
        logger.info(
            "Scanned %s — %d match(es) in %.1fms",
            target_path.name,
            len(matches),
            duration_ms,
        )

    return ScanResult(
        target_file=str(target_path),
        scan_time=scan_time,
        duration_ms=duration_ms,
        matches=matches,
        errors=errors,
    )


def scan_directory(
    compiled_rules: yara.Rules,
    directory: str | Path,
    rule_file_map: dict[str, str] | None = None,
    *,
    recursive: bool = True,
    timeout: int = 60,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> DirectoryScanSummary:
    """
    Recursively scan all files in a directory.

    Args:
        compiled_rules: Pre-compiled yara.Rules object.
        directory:      Root directory to scan.
        rule_file_map:  namespace -> filepath mapping (from RuleLoaderResult.filepaths).
        recursive:      If False, only scan top-level files.
        timeout:        Per-file YARA scan timeout in seconds.
        on_progress:    Optional callback(current, total, filename) for progress reporting.

    Returns:
        DirectoryScanSummary aggregating all per-file ScanResult objects.

    Raises:
        FileNotFoundError: If directory does not exist.
        NotADirectoryError: If path is not a directory.
    """
    root = Path(directory).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Expected a directory, got: {root}")

    # Collect candidate files first so we can report progress.
    if recursive:
        all_files = [
            p
            for p in root.rglob("*")
            if p.is_file()
            and p.suffix.lower() not in SKIP_EXTENSIONS
            and not any(part.startswith(".") for part in p.parts)
        ]
    else:
        all_files = [
            p for p in root.iterdir() if p.is_file() and p.suffix.lower() not in SKIP_EXTENSIONS
        ]

    all_files.sort()
    total = len(all_files)
    scan_time = datetime.now(tz=UTC)
    results: list[ScanResult] = []

    logger.info("Starting directory scan: %s (%d file(s))", root, total)

    for idx, file_path in enumerate(all_files, start=1):
        if on_progress:
            on_progress(idx, total, file_path.name)
        result = scan_file(
            compiled_rules,
            file_path,
            rule_file_map=rule_file_map,
            timeout=timeout,
        )
        results.append(result)

    matched_count = sum(1 for r in results if r.matches)
    logger.info(
        "Directory scan complete: %d/%d file(s) had matches",
        matched_count,
        total,
    )

    return DirectoryScanSummary(
        root_path=str(root),
        scan_time=scan_time,
        results=results,
    )
