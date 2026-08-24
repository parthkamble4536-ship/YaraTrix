# YaraTrix 🛡️

<div align="center">

![YaraTrix Banner](https://img.shields.io/badge/YaraTrix-YARA%20→%20MITRE%20ATT%26CK-blueviolet?style=for-the-badge&logo=shield&logoColor=white)

[![CI](https://github.com/parthkamble4536-ship/YaraTrix/actions/workflows/ci.yml/badge.svg)](https://github.com/parthkamble4536-ship/YaraTrix/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![uv](https://img.shields.io/badge/managed%20by-uv-7C3AED?style=flat)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Scan files with YARA rules → auto-map every hit to MITRE ATT&CK techniques → generate Navigator heatmaps and premium HTML threat reports.**

[Features](#features) · [Quick Start](#quick-start) · [CLI Reference](#cli-reference) · [REST API](#rest-api) · [Architecture](#architecture) · [Contributing](#contributing)

</div>

---

## What is YaraTrix?

YaraTrix is a Python-powered **threat analysis engine** that bridges the gap between raw YARA signature matching and structured threat intelligence. It:

1. **Loads** YARA rules from a directory, compiling them once for speed
2. **Scans** files or entire directory trees, collecting all matches with offsets and strings
3. **Maps** every rule match to one or more MITRE ATT&CK techniques using the live STIX bundle
4. **Exports** results as:
   - A structured **JSON** report (for pipelines)
   - An **ATT&CK Navigator layer** (`.json`) — importable at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
   - A **premium HTML threat report** with kill-chain heatmap, narrative, and technique breakdown
5. **Serves** a **FastAPI REST API** for integration with SIEMs, EDR platforms, or CI/CD pipelines

---

## Features

| Feature | Details |
|---|---|
| 🔍 **YARA Scanning** | Recursive directory scanning with progress callbacks |
| 🗺️ **ATT&CK Mapping** | Auto-maps technique IDs from rule `meta:` fields to live STIX v2.1 data |
| 📊 **Navigator Export** | Heatmaps coloured by severity (low → critical) |
| 📄 **HTML Reports** | Premium dark-mode report with kill-chain heatmap, narratives, mitigations |
| ⚡ **FastAPI Server** | REST API with file upload, JSON/Navigator/HTML export endpoints |
| 🖥️ **Rich CLI** | Beautiful terminal UI with `scan`, `report`, `serve`, and `version` commands |
| ✅ **96 Tests** | Full pytest suite, no STIX bundle required for testing |
| 🔄 **CI/CD** | GitHub Actions: lint + test matrix (Python 3.11/3.12 × Linux/Windows) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`
- On Linux: `sudo apt-get install libyara-dev`

### Install

```bash
# Clone the repo
git clone https://github.com/parthkamble4536-ship/YaraTrix.git
cd YaraTrix

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### Download MITRE ATT&CK data

```bash
uv run python scripts/download_mitre_data.py
```

This downloads the STIX bundle (~46 MB) to `data/enterprise-attack.json`.

### Run your first scan

```bash
# Scan a file
uv run yaratrix scan /path/to/suspicious.ps1

# Scan a directory
uv run yaratrix scan /path/to/samples/

# Generate an HTML report
uv run yaratrix generate-report /path/to/suspicious.ps1 --output report.html

# Export an ATT&CK Navigator layer
uv run yaratrix scan /path/to/samples/ --navigator --output layer.json
```

---

## YARA Rule Format

YaraTrix requires rules to have structured `meta:` fields:

```yara
rule Suspicious_PowerShell_EncodedCommand {
    meta:
        mitre_technique = "T1059.001"        // Required — comma-separated for multi
        mitre_tactic    = "execution"         // Required — comma-separated for multi
        severity        = "high"              // Required: low | medium | high | critical
        description     = "Detects encoded PowerShell execution via -EncodedCommand"

    strings:
        $enc  = "-EncodedCommand" nocase
        $iex  = "IEX(" nocase

    condition:
        any of them
}
```

Place all `.yar` files in the `rules/` directory. YaraTrix will discover and compile them automatically.

---

## CLI Reference

```
Usage: yaratrix [OPTIONS] COMMAND [ARGS]...

  YaraTrix — YARA-to-MITRE ATT&CK Mapping Engine

Options:
  --version   Show version and exit.
  --help      Show this message and exit.

Commands:
  scan             Scan a file or directory with YARA rules.
  generate-report  Generate an HTML threat report for a target.
  serve            Start the FastAPI REST API server.
```

### `scan`

```bash
uv run yaratrix scan TARGET [OPTIONS]

Options:
  --rules-dir PATH      Directory containing .yar rules  [default: rules/]
  --stix-bundle PATH    Path to MITRE ATT&CK STIX bundle
  --navigator           Also export an ATT&CK Navigator layer
  --output PATH         Output path for JSON/Navigator results
  --format [json|table] Output format for terminal  [default: table]
```

### `generate-report`

```bash
uv run yaratrix generate-report TARGET [OPTIONS]

Options:
  --rules-dir PATH   Directory containing .yar rules  [default: rules/]
  --output PATH      Path for HTML report  [default: reports/<target>.html]
```

### `serve`

```bash
uv run yaratrix serve [OPTIONS]

Options:
  --host TEXT     Bind host  [default: 0.0.0.0]
  --port INTEGER  Bind port  [default: 8000]
  --reload        Enable hot-reload (dev mode)
```

---

## REST API

Start the server with `uv run yaratrix serve`, then:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Version, rule count, STIX status |
| `POST` | `/scan` | Upload file → full JSON scan + ATT&CK enrichment |
| `GET` | `/rules` | List all loaded YARA rules |
| `GET` | `/techniques` | List ATT&CK technique IDs from STIX bundle |
| `POST` | `/export/navigator` | Upload file → download Navigator layer JSON |
| `POST` | `/export/report` | Upload file → download HTML threat report |

### Example

```bash
# Health check
curl http://localhost:8000/health

# Scan a file
curl -X POST http://localhost:8000/scan \
  -F "file=@/path/to/suspicious.ps1"

# Get Navigator layer
curl -X POST http://localhost:8000/export/navigator \
  -F "file=@/path/to/suspicious.ps1" \
  -o layer.json
```

Interactive API docs available at **`http://localhost:8000/docs`** (Swagger UI).

---

## Architecture

```
YaraTrix
├── src/yaratrix/
│   ├── rule_loader.py        # YARA rule discovery & compilation
│   ├── yara_engine.py        # File/directory scanning engine
│   ├── attack_client.py      # MITRE ATT&CK STIX client & caching
│   ├── mapper.py             # Rule match → ATT&CK technique mapping
│   ├── navigator_export.py   # ATT&CK Navigator layer generation
│   ├── report_generator.py   # Jinja2 HTML report rendering
│   ├── models.py             # Pydantic-like dataclasses
│   ├── cli/main.py           # Typer CLI entrypoint
│   ├── api/main.py           # FastAPI REST API
│   └── templates/report.html # Premium dark-mode report template
├── rules/                    # YARA rule files (.yar)
├── data/                     # MITRE ATT&CK STIX bundle (cached)
├── reports/                  # Generated HTML reports
├── tests/                    # 96-test pytest suite
└── scripts/                  # Helper scripts (STIX download, etc.)
```

### Data Flow

```
.yar rules ──► rule_loader ──► yara_engine ──► ScanResult
                                                    │
                                               mapper.py
                                                    │
                                          attack_client (STIX)
                                                    │
                                            MappingResult
                                           ┌────────┴────────┐
                                    navigator_export    report_generator
                                           │                  │
                                    layer.json          report.html
```

---

## Running Tests

```bash
# Run full test suite (96 tests, no STIX download needed)
uv run pytest tests/ -v

# With coverage report
uv run pytest tests/ --cov=src/yaratrix --cov-report=term-missing

# Run specific test module
uv run pytest tests/test_yara_engine.py -v
```

---

## Project Structure

```
YaraTrix/
├── .github/
│   └── workflows/ci.yml    # CI: Lint + Test (3.11/3.12 × Linux/Windows) + Build
├── src/yaratrix/           # Main package
├── tests/                  # pytest test suite
├── rules/                  # Sample YARA rules
├── scripts/                # Utility scripts
├── data/                   # STIX bundle (git-ignored)
├── reports/                # Generated reports (git-ignored)
├── pyproject.toml          # Project config + tool settings
└── uv.lock                 # Locked dependency versions
```

---

## Contributing

1. Fork the repo and create a feature branch
2. Install dev dependencies: `uv sync`
3. Make your changes and add tests
4. Run `uv run ruff check src/ tests/` and `uv run pytest tests/`
5. Open a Pull Request — CI will run automatically

---

## License

MIT © 2026 Parth Kamble

---

<div align="center">

Built with ❤️ using [YARA](https://virustotal.github.io/yara/), [MITRE ATT&CK](https://attack.mitre.org/), [FastAPI](https://fastapi.tiangolo.com/), and [uv](https://github.com/astral-sh/uv)

</div>
