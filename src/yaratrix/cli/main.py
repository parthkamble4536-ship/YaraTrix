"""
YaraTrix CLI — Main entry point.

Commands:
  scan              Scan a single file.
  scan-dir          Scan an entire directory recursively.
  export-navigator  Generate a MITRE ATT&CK Navigator layer from scan results.
  generate-report   Generate an HTML threat analysis report.
  serve             Launch the REST API server.
  list-rules        List all loaded YARA rules.

Run:  uv run yaratrix --help
"""

from __future__ import annotations

import json
import os
import sys

# Force UTF-8 output on Windows to support rich's Unicode characters (arrows, etc.)
if sys.platform == "win32":
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from pathlib import Path
from typing import Any, Optional


def _safe_write(path: Path, text: str) -> None:
    """Write text to path safely, handling Windows paths with special chars like &."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path_str = str(path.resolve())
    if sys.platform == "win32" and not path_str.startswith("\\\\?\\"):
        path_str = "\\\\?\\" + path_str
    with open(path_str, "w", encoding="utf-8") as f:
        f.write(text)

import typer
import yara
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from yaratrix import __version__
from yaratrix.attack_client import get_default_client
from yaratrix.mapper import map_scan_result, map_scan_results
from yaratrix.navigator_export import export_navigator_layer
from yaratrix.report_generator import render_report
from yaratrix.rule_loader import load_rules
from yaratrix.yara_engine import scan_directory, scan_file

app = typer.Typer(
    name="yaratrix",
    help="[bold green]YaraTrix[/bold green] — YARA-to-MITRE ATT&CK Mapping Engine",
    rich_markup_mode="rich",
    add_completion=False,
)
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  Default paths
# ─────────────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_RULES_DIR = _HERE / "rules"


def _severity_color(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }.get(severity.lower(), "white")


def _threat_level_color(level: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "none": "dim",
    }.get(level.lower(), "white")


def version_callback(value: bool) -> None:
    if value:
        console.print(
            Panel(
                f"[bold green]YaraTrix[/bold green]  v{__version__}\n"
                "[dim]YARA-to-MITRE ATT&CK Mapping Engine[/dim]",
                border_style="green",
            )
        )
        raise typer.Exit()


# ─────────────────────────────────────────────────────────────────────────────
#  Root callback — --version flag
# ─────────────────────────────────────────────────────────────────────────────
@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """YaraTrix — YARA-to-MITRE ATT&CK Mapping Engine"""


# ─────────────────────────────────────────────────────────────────────────────
#  scan command
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def scan(
    target: Path = typer.Argument(..., help="File to scan.", exists=True),
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR,
        "--rules-dir",
        "-r",
        help="Directory containing .yar rule files.",
    ),
    output_json: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Save JSON results to this file."
    ),
    no_mitre: bool = typer.Option(
        False, "--no-mitre", help="Skip MITRE ATT&CK enrichment (faster)."
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Fail if any rule has missing meta fields."
    ),
) -> None:
    """Scan a [bold]single file[/bold] against loaded YARA rules."""

    console.print(
        Panel(
            f"[bold]Scanning:[/bold] {target}\n[dim]Rules:[/dim] {rules_dir}",
            title="[green]YaraTrix Scan[/green]",
            border_style="green",
        )
    )

    # Load rules
    with console.status("[bold green]Loading rules…"):
        try:
            loader = load_rules(rules_dir, strict=strict)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

    if loader.warnings:
        for w in loader.warnings:
            console.print(f"  [yellow]⚠[/yellow]  {w}")

    if not loader.compiled:
        console.print("[red]No rules compiled. Aborting scan.[/red]")
        raise typer.Exit(1)

    # Run scan
    with console.status("[bold green]Scanning file…"):
        result = scan_file(loader.compiled, target, rule_file_map=loader.filepaths)

    # ── YARA match table ──
    if not result.matches:
        console.print("[bold green]✓ No matches found.[/bold green]")
    else:
        table = Table(
            title=f"YARA Matches — {target.name}",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("Rule", style="bold")
        table.add_column("Technique")
        table.add_column("Tactic")
        table.add_column("Severity")
        table.add_column("Strings Hit", justify="right")
        table.add_column("Description", max_width=50)

        for m in result.matches:
            sev_style = _severity_color(m.severity.value)
            table.add_row(
                m.rule_name,
                m.mitre_technique,
                m.mitre_tactic,
                Text(m.severity.value.upper(), style=sev_style),
                str(len(m.matched_strings)),
                m.description[:80],
            )
        console.print(table)

    # ── Errors ──
    for err in result.errors:
        console.print(f"  [red]✗[/red] {err}")

    # ── MITRE ATT&CK enrichment ──
    mapping = None
    if result.matches and not no_mitre:
        with console.status("[bold green]Resolving MITRE ATT&CK techniques…"):
            try:
                client = get_default_client()
                mapping = map_scan_result(result, client=client)
            except FileNotFoundError as exc:
                console.print(f"[yellow]⚠  ATT&CK enrichment skipped:[/yellow] {exc}")

    if mapping:
        _print_mapping_panel(mapping)

    # ── Summary ──
    threat_color = _threat_level_color(mapping.threat_level if mapping else "none")
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"{len(result.matches)} match(es) | "
        f"Techniques: [cyan]{', '.join(result.matched_techniques()) or 'none'}[/cyan] | "
        f"Tactics: [cyan]{', '.join(result.matched_tactics()) or 'none'}[/cyan] | "
        + (f"Threat Level: [{threat_color}]{mapping.threat_level.upper()}[/{threat_color}] | "
           f"Confidence: {mapping.confidence_score:.0%}" if mapping else "")
        + f" | Duration: {result.duration_ms:.1f}ms"
    )

    # ── JSON output ──
    if output_json:
        combined = result.to_dict()
        if mapping:
            combined["mitre_mapping"] = mapping.to_dict()
        _safe_write(output_json, json.dumps(combined, indent=2))
        console.print(f"\n[dim]JSON saved to: {output_json}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
#  scan-dir command
# ─────────────────────────────────────────────────────────────────────────────
@app.command(name="scan-dir")
def scan_dir(
    directory: Path = typer.Argument(..., help="Directory to scan recursively."),
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR,
        "--rules-dir",
        "-r",
        help="Directory containing .yar rule files.",
    ),
    output_json: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Save JSON results to this file."
    ),
    navigator_out: Optional[Path] = typer.Option(
        None, "--navigator", "-n", help="Save MITRE Navigator layer JSON to this file."
    ),
    no_mitre: bool = typer.Option(
        False, "--no-mitre", help="Skip MITRE ATT&CK enrichment (faster)."
    ),
    strict: bool = typer.Option(False, "--strict"),
    no_recursive: bool = typer.Option(
        False, "--no-recursive", help="Only scan top-level files."
    ),
) -> None:
    """Scan an [bold]entire directory[/bold] recursively against loaded YARA rules."""

    if not directory.is_dir():
        console.print(f"[red]Error:[/red] Not a directory: {directory}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold]Scanning:[/bold] {directory}\n[dim]Rules:[/dim] {rules_dir}",
            title="[green]YaraTrix Directory Scan[/green]",
            border_style="green",
        )
    )

    with console.status("[bold green]Loading rules…"):
        try:
            loader = load_rules(rules_dir, strict=strict)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

    if not loader.compiled:
        console.print("[red]No rules compiled. Aborting.[/red]")
        raise typer.Exit(1)

    files_scanned = 0

    def _progress(current: int, total: int, filename: str) -> None:
        nonlocal files_scanned
        files_scanned = current
        console.print(f"  [{current}/{total}] {filename}", highlight=False)

    summary = scan_directory(
        loader.compiled,
        directory,
        rule_file_map=loader.filepaths,
        recursive=not no_recursive,
        on_progress=_progress,
    )

    hits = summary.files_with_matches()

    # ── MITRE ATT&CK enrichment ──
    mappings = []
    if hits and not no_mitre:
        with console.status("[bold green]Resolving MITRE ATT&CK techniques…"):
            try:
                client = get_default_client()
                mappings = map_scan_results([r for r in hits], client=client)
            except FileNotFoundError as exc:
                console.print(f"[yellow]⚠  ATT&CK enrichment skipped:[/yellow] {exc}")

    if not hits:
        console.print("\n[bold green]✓ No matches found in any scanned file.[/bold green]")
    else:
        for result in hits:
            table = Table(
                title=f"[bold]{Path(result.target_file).name}[/bold]",
                box=box.SIMPLE_HEAVY,
                show_lines=False,
            )
            table.add_column("Rule", style="bold")
            table.add_column("Technique")
            table.add_column("Tactic")
            table.add_column("Severity")

            for m in result.matches:
                sev_style = _severity_color(m.severity.value)
                table.add_row(
                    m.rule_name,
                    m.mitre_technique,
                    m.mitre_tactic,
                    Text(m.severity.value.upper(), style=sev_style),
                )
            console.print(table)

        # Print mapping panels
        for mapping in mappings:
            _print_mapping_panel(mapping)

    console.print(
        f"\n[bold]Summary:[/bold] "
        f"{summary.total_files()} file(s) scanned | "
        f"{len(hits)} file(s) with matches | "
        f"{summary.total_matches()} total match(es)"
    )

    # ── JSON output ──
    if output_json:
        combined = summary.to_dict()
        if mappings:
            combined["mitre_mappings"] = [m.to_dict() for m in mappings]
        _safe_write(output_json, json.dumps(combined, indent=2))
        console.print(f"[dim]JSON saved to: {output_json}[/dim]")

    # ── Navigator export ──
    if navigator_out and mappings:
        export_navigator_layer(mappings, navigator_out)
        console.print(f"[dim]Navigator layer saved to: {navigator_out}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
#  export-navigator command
# ─────────────────────────────────────────────────────────────────────────────
@app.command(name="export-navigator")
def export_navigator(
    target: Path = typer.Argument(
        ..., help="File or directory to scan and export a Navigator layer for."
    ),
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR,
        "--rules-dir",
        "-r",
        help="Directory containing .yar rule files.",
    ),
    output: Path = typer.Option(
        Path("yaratrix_navigator_layer.json"),
        "--output",
        "-o",
        help="Output path for the Navigator JSON layer file.",
    ),
    layer_name: str = typer.Option(
        "YaraTrix Scan Results",
        "--name",
        help="Display name for the Navigator layer.",
    ),
) -> None:
    """
    Scan a file or directory and export a [bold]MITRE ATT&CK Navigator[/bold] layer.

    Import the resulting JSON at:
    [link=https://mitre-attack.github.io/attack-navigator/]https://mitre-attack.github.io/attack-navigator/[/link]
    """

    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Output:[/bold] {output}\n"
            f"[dim]Rules:[/dim] {rules_dir}",
            title="[green]YaraTrix -> Navigator Export[/green]",
            border_style="green",
        )
    )

    with console.status("[bold green]Loading rules…"):
        try:
            loader = load_rules(rules_dir)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

    if not loader.compiled:
        console.print("[red]No rules compiled.[/red]")
        raise typer.Exit(1)

    # Scan
    scan_results = []
    if target.is_dir():
        with console.status("[bold green]Scanning directory…"):
            summary = scan_directory(loader.compiled, target, rule_file_map=loader.filepaths)
            scan_results = summary.results
    elif target.is_file():
        with console.status("[bold green]Scanning file…"):
            scan_results = [scan_file(loader.compiled, target, rule_file_map=loader.filepaths)]
    else:
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(1)

    # Map to ATT&CK
    with console.status("[bold green]Resolving MITRE ATT&CK techniques…"):
        try:
            client = get_default_client()
            mappings = map_scan_results(scan_results, client=client)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

    total_techniques = sum(len(m.unique_techniques) for m in mappings)
    if total_techniques == 0:
        console.print("[yellow]! No techniques found to export.[/yellow]")
        raise typer.Exit(0)

    # Export
    out_path = export_navigator_layer(mappings, output, layer_name=layer_name)
    console.print(
        Panel(
            f"[bold green]Navigator layer exported![/bold green]\n\n"
            f"File: [cyan]{out_path}[/cyan]\n"
            f"Techniques covered: [bold]{total_techniques}[/bold]\n\n"
            f"Import at:\n"
            f"[link=https://mitre-attack.github.io/attack-navigator/]"
            f"https://mitre-attack.github.io/attack-navigator/[/link]",
            border_style="green",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
#  list-rules command
# ─────────────────────────────────────────────────────────────────────────────
@app.command(name="list-rules")
def list_rules(
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR,
        "--rules-dir",
        "-r",
        help="Directory containing .yar rule files.",
    ),
) -> None:
    """List all YARA rules loaded from the rules directory."""

    try:
        loader = load_rules(rules_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if not loader.compiled:
        console.print("[yellow]No rules found.[/yellow]")
        raise typer.Exit(0)

    table = Table(
        title=f"Rules loaded from {rules_dir}",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Rule Name", style="bold")
    table.add_column("Technique")
    table.add_column("Tactic")
    table.add_column("Severity")
    table.add_column("Source File")

    count = 0
    for rule in loader.compiled:
        count += 1
        meta = rule.meta or {}
        sev = str(meta.get("severity", "?")).lower()
        sev_style = _severity_color(sev)

        # Derive source file from filepaths map
        src_file = "unknown"
        for ns, fp in loader.filepaths.items():
            try:
                test_compiled = yara.compile(filepath=fp)
                for r in test_compiled:
                    if r.identifier == rule.identifier:
                        src_file = Path(fp).name
                        break
            except Exception:
                pass
            if src_file != "unknown":
                break

        table.add_row(
            str(count),
            rule.identifier,
            str(meta.get("mitre_technique", "-")),
            str(meta.get("mitre_tactic", "-")),
            Text(sev.upper(), style=sev_style),
            src_file,
        )

    console.print(table)
    console.print(f"\n[bold]{count}[/bold] rule(s) loaded from [dim]{len(loader.filepaths)}[/dim] file(s)")

    if loader.errors:
        console.print(f"\n[yellow]! {len(loader.errors)} rule(s) have meta validation issues:[/yellow]")
        for err in loader.errors:
            console.print(f"  [dim]{err}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
#  Shared display helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_mapping_panel(mapping) -> None:
    """Print a rich panel showing the ATT&CK mapping result for one file."""
    from pathlib import Path as _Path
    file_name = _Path(mapping.target_file).name
    threat_color = _threat_level_color(mapping.threat_level)

    # Build technique enrichment table
    if mapping.technique_mappings:
        tech_table = Table(box=box.MINIMAL, show_header=True, padding=(0, 1))
        tech_table.add_column("Technique ID", style="bold cyan")
        tech_table.add_column("Name")
        tech_table.add_column("Tactic(s)")
        tech_table.add_column("Severity")
        tech_table.add_column("Mitigations", justify="right")

        seen_techs: set[str] = set()
        for m in mapping.technique_mappings:
            if m.technique_id in seen_techs:
                continue
            seen_techs.add(m.technique_id)
            info = m.technique_info
            name = info.name if info else "[dim]unknown[/dim]"
            tactics = ", ".join(info.tactics) if info else m.severity.value
            mitigation_count = str(len(info.mitigations)) if info else "-"
            sev_style = _severity_color(m.severity.value)
            tech_table.add_row(
                m.technique_id,
                name,
                tactics,
                Text(m.severity.value.upper(), style=sev_style),
                mitigation_count,
            )

        console.print(
            Panel(
                f"[bold]File:[/bold] {file_name}\n"
                f"[bold]Threat Level:[/bold] [{threat_color}]{mapping.threat_level.upper()}[/{threat_color}]  "
                f"[bold]Confidence:[/bold] {mapping.confidence_score:.0%}\n"
                f"[bold]Tactics:[/bold] [cyan]{', '.join(mapping.unique_tactics)}[/cyan]\n\n"
                f"[italic]{mapping.narrative}[/italic]",
                title="[bold]ATT&CK Mapping[/bold]",
                border_style="blue",
            )
        )
        console.print(tech_table)


# ─────────────────────────────────────────────────────────────────────────────
#  generate-report command
# ─────────────────────────────────────────────────────────────────────────────

@app.command(name="generate-report")
def generate_report(
    target: Path = typer.Argument(..., help="File or directory to scan."),
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR, "--rules-dir", "-r",
        help="Directory containing .yar rule files.",
    ),
    output: Path = typer.Option(
        Path("yaratrix_report.html"),
        "--output", "-o",
        help="Output path for the HTML report.",
    ),
    no_mitre: bool = typer.Option(False, "--no-mitre", help="Skip ATT&CK enrichment."),
) -> None:
    """Generate a [bold]HTML threat analysis report[/bold] for a file or directory scan."""

    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Output:[/bold] {output}\n"
            f"[dim]Rules:[/dim] {rules_dir}",
            title="[green]YaraTrix -> HTML Report[/green]",
            border_style="green",
        )
    )

    with console.status("[bold green]Loading rules…"):
        try:
            loader = load_rules(rules_dir)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

    if not loader.compiled:
        console.print("[red]No rules compiled.[/red]")
        raise typer.Exit(1)

    # Scan
    scan_results = []
    report_title = target.name
    if target.is_dir():
        with console.status("[bold green]Scanning directory…"):
            from yaratrix.yara_engine import scan_directory as _scan_dir
            summary = _scan_dir(loader.compiled, target, rule_file_map=loader.filepaths)
            scan_results = summary.results
            report_title = target.name
    elif target.is_file():
        with console.status("[bold green]Scanning file…"):
            scan_results = [scan_file(loader.compiled, target, rule_file_map=loader.filepaths)]
    else:
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(1)

    # Map to ATT&CK
    mappings = []
    if not no_mitre:
        with console.status("[bold green]Resolving MITRE ATT&CK techniques…"):
            try:
                client = get_default_client()
                mappings = map_scan_results(scan_results, client=client)
            except FileNotFoundError as exc:
                console.print(f"[yellow]! ATT&CK enrichment skipped:[/yellow] {exc}")

    # Render report
    with console.status("[bold green]Rendering HTML report…"):
        out_path = render_report(scan_results, mappings, output, report_title=report_title)

    console.print(
        Panel(
            f"[bold green]HTML report generated![/bold green]\n\n"
            f"File: [cyan]{out_path}[/cyan]\n"
            f"Open in your browser to view the threat analysis.",
            border_style="green",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
#  serve command
# ─────────────────────────────────────────────────────────────────────────────

@app.command(name="serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on."),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (development)."),
    log_level: str = typer.Option("info", "--log-level", help="Uvicorn log level."),
) -> None:
    """Launch the [bold]YaraTrix REST API[/bold] server."""
    import uvicorn
    console.print(
        Panel(
            f"[bold]YaraTrix API[/bold] starting on [cyan]http://{host}:{port}[/cyan]\n"
            f"[dim]Docs: http://{host}:{port}/docs[/dim]",
            title="[green]YaraTrix API Server[/green]",
            border_style="green",
        )
    )
    uvicorn.run(
        "yaratrix.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
def run_cli() -> None:
    app()


if __name__ == "__main__":
    run_cli()
