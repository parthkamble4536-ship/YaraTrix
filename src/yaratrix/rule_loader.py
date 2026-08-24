"""
YARA Rule Loader for YaraTrix.

Responsibilities:
- Recursively discover .yar / .yara files under a given directory.
- Validate that every rule contains required meta fields:
  mitre_technique, mitre_tactic, severity, description.
- Compile rules using yara.compile() and return a compiled ruleset.
- Report (but never silently swallow) validation errors.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import NamedTuple

import yara

logger = logging.getLogger(__name__)

# Required meta keys that every YaraTrix rule must declare.
REQUIRED_META_FIELDS: frozenset[str] = frozenset(
    {"mitre_technique", "mitre_tactic", "severity", "description"}
)

VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


class RuleValidationError(NamedTuple):
    """Represents a single validation failure for a rule file."""

    rule_file: str
    rule_name: str
    issues: list[str]

    def __str__(self) -> str:
        issue_list = "; ".join(self.issues)
        return f"[{self.rule_file}] Rule '{self.rule_name}': {issue_list}"


class RuleLoaderResult(NamedTuple):
    """Output of load_rules()."""

    compiled: yara.Rules | None  # Compiled YARA rules (None if all fail)
    filepaths: dict[str, str]  # namespace -> filepath mapping used
    errors: list[RuleValidationError]  # Validation failures
    warnings: list[str]  # Non-fatal warnings


def discover_rule_files(rules_dir: str | Path) -> list[Path]:
    """
    Recursively find all .yar and .yara files under rules_dir.

    Args:
        rules_dir: Root directory to search.

    Returns:
        Sorted list of absolute Path objects.

    Raises:
        FileNotFoundError: If rules_dir does not exist.
    """
    root = Path(rules_dir).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Rules directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Expected a directory, got: {root}")

    found = sorted(p for p in root.rglob("*") if p.suffix.lower() in {".yar", ".yara"})
    logger.debug("Discovered %d rule file(s) under %s", len(found), root)
    return found


def _validate_rule_meta(
    rule_file: Path,
    rule_name: str,
    meta: dict,
) -> list[str]:
    """
    Validate the meta block of a single YARA rule.

    Returns a list of human-readable issue strings (empty = valid).
    """
    issues: list[str] = []

    for field in REQUIRED_META_FIELDS:
        if field not in meta:
            issues.append(f"missing required meta field '{field}'")
        elif not str(meta[field]).strip():
            issues.append(f"meta field '{field}' is empty")

    # Validate severity value if present
    if "severity" in meta:
        sev = str(meta["severity"]).strip().lower()
        if sev not in VALID_SEVERITIES:
            issues.append(
                f"invalid severity '{sev}' — must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )

    return issues


def load_rules(
    rules_dir: str | Path,
    *,
    strict: bool = False,
) -> RuleLoaderResult:
    """
    Load, validate, and compile all YARA rules found under rules_dir.

    Args:
        rules_dir: Directory to search for .yar / .yara files.
        strict:    If True, raise ValueError if any validation errors are found.

    Returns:
        RuleLoaderResult with compiled rules, filepaths, errors, and warnings.

    Raises:
        FileNotFoundError: If rules_dir does not exist.
        ValueError:        If strict=True and validation errors are found.
        yara.SyntaxError:  If any YARA file has a syntax error.
    """
    rule_files = discover_rule_files(rules_dir)

    if not rule_files:
        logger.warning("No .yar/.yara files found under %s", rules_dir)
        return RuleLoaderResult(
            compiled=None,
            filepaths={},
            errors=[],
            warnings=[f"No rule files found under {rules_dir}"],
        )

    validation_errors: list[RuleValidationError] = []
    warnings: list[str] = []

    # First pass: parse each file individually to validate meta blocks.
    # We use an external variable matching trick: compile in external mode
    # so we can inspect rules before the full compile.
    valid_files: list[Path] = []

    for rule_file in rule_files:
        try:
            temp_rules = yara.compile(filepath=str(rule_file))
        except yara.SyntaxError as exc:
            logger.error("Syntax error in %s: %s", rule_file, exc)
            warnings.append(f"Skipping {rule_file.name} due to syntax error: {exc}")
            continue

        file_errors: list[RuleValidationError] = []
        for rule in temp_rules:
            issues = _validate_rule_meta(rule_file, rule.identifier, rule.meta)
            if issues:
                file_errors.append(
                    RuleValidationError(
                        rule_file=str(rule_file),
                        rule_name=rule.identifier,
                        issues=issues,
                    )
                )

        if file_errors:
            validation_errors.extend(file_errors)
            for err in file_errors:
                logger.warning("Validation issue: %s", err)

        # Always keep the file — we warn on bad meta but still compile.
        valid_files.append(rule_file)

    if not valid_files:
        msg = "No valid YARA files could be loaded."
        if strict:
            raise ValueError(msg)
        return RuleLoaderResult(
            compiled=None,
            filepaths={},
            errors=validation_errors,
            warnings=warnings + [msg],
        )

    if strict and validation_errors:
        raise ValueError(
            f"{len(validation_errors)} rule(s) failed validation. "
            "Fix the meta fields or run without strict mode."
        )

    # Build namespace -> filepath mapping for yara.compile(filepaths={...}).
    # Namespaces must be unique; use the stem (filename without extension).
    filepaths: dict[str, str] = {}
    for idx, f in enumerate(valid_files):
        # Handle duplicate stems by appending index.
        namespace = f.stem if f.stem not in filepaths else f"{f.stem}_{idx}"
        filepaths[namespace] = str(f)

    compiled = yara.compile(filepaths=filepaths)
    logger.info(
        "Compiled %d rule file(s) from %s (%d validation issue(s))",
        len(valid_files),
        rules_dir,
        len(validation_errors),
    )

    return RuleLoaderResult(
        compiled=compiled,
        filepaths=filepaths,
        errors=validation_errors,
        warnings=warnings,
    )
