"""
YaraTrix test suite — shared fixtures and helpers.

All tests in this package use:
  - In-memory YARA rules (no disk I/O for rule loading)
  - Temporary files with synthetic content (no dependency on STIX bundle)
  - Mocked AttackClient where ATT&CK enrichment is needed

This keeps the tests fast and self-contained.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yara

# ─────────────────────────────────────────────────────────────────────────────
#  Inline YARA rule strings used across tests
# ─────────────────────────────────────────────────────────────────────────────

RULE_POWERSHELL = """
rule Suspicious_PowerShell_EncodedCommand {
    meta:
        mitre_technique = "T1059.001"
        mitre_tactic    = "execution"
        severity        = "high"
        description     = "Detects encoded PowerShell commands"
    strings:
        $enc = "EncodedCommand" nocase
        $enc2 = "-EncodedCommand" nocase
    condition:
        any of them
}
"""

RULE_LSASS = """
rule LSASS_Memory_Access {
    meta:
        mitre_technique = "T1003.001"
        mitre_tactic    = "credential-access"
        severity        = "critical"
        description     = "Detects LSASS memory access"
    strings:
        $lsass = "lsass.exe" nocase
        $sekurlsa = "sekurlsa" nocase
    condition:
        any of them
}
"""

RULE_MULTI_TECHNIQUE = """
rule Multi_Technique_Rule {
    meta:
        mitre_technique = "T1059.001,T1027"
        mitre_tactic    = "execution,defense-evasion"
        severity        = "medium"
        description     = "Rule with multiple techniques"
    strings:
        $s = "multi_marker_12345"
    condition:
        $s
}
"""

RULE_MISSING_META = """
rule Missing_Meta_Rule {
    strings:
        $s = "test_string"
    condition:
        $s
}
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def compiled_ps_rule() -> yara.Rules:
    """Compile and return a single PowerShell detection rule."""
    return yara.compile(source=RULE_POWERSHELL)


@pytest.fixture
def compiled_lsass_rule() -> yara.Rules:
    """Compile and return the LSASS memory access rule."""
    return yara.compile(source=RULE_LSASS)


@pytest.fixture
def compiled_multi_rules() -> yara.Rules:
    """Compile multiple rules from a temp .yar file and return them."""
    combined = RULE_POWERSHELL + "\n" + RULE_LSASS
    return yara.compile(source=combined)


@pytest.fixture
def rule_yar_file(tmp_path: Path) -> Path:
    """Write a valid .yar file to tmp_path and return its path."""
    yar_file = tmp_path / "test_rules.yar"
    yar_file.write_text(RULE_POWERSHELL + "\n" + RULE_LSASS, encoding="utf-8")
    return yar_file


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """
    Create a temporary rules directory with two tactic subdirectories.
    """
    exec_dir = tmp_path / "execution"
    exec_dir.mkdir()
    (exec_dir / "execution_rules.yar").write_text(RULE_POWERSHELL, encoding="utf-8")

    cred_dir = tmp_path / "credential_access"
    cred_dir.mkdir()
    (cred_dir / "cred_rules.yar").write_text(RULE_LSASS, encoding="utf-8")

    return tmp_path


@pytest.fixture
def ps_sample_file(tmp_path: Path) -> Path:
    """Write a synthetic PowerShell file that triggers the PS rule."""
    f = tmp_path / "suspicious.ps1"
    f.write_bytes(b"powershell -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0A")
    return f


@pytest.fixture
def bat_sample_file(tmp_path: Path) -> Path:
    """Write a synthetic .bat file that triggers the LSASS rule."""
    f = tmp_path / "bad.bat"
    f.write_bytes(b"procdump -ma lsass.exe c:\\lsass_dump\nsekurlsa::logonPasswords")
    return f


@pytest.fixture
def clean_sample_file(tmp_path: Path) -> Path:
    """Write a benign file that triggers no rules."""
    f = tmp_path / "clean.txt"
    f.write_bytes(b"Hello world! This is a perfectly clean file.")
    return f


@pytest.fixture
def multi_sample_dir(
    tmp_path: Path, ps_sample_file: Path, bat_sample_file: Path, clean_sample_file: Path
) -> Path:
    """A directory containing three files: one PS, one BAT, one clean."""
    return tmp_path
