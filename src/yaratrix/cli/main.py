"""
YaraTrix CLI — Main entry point.

Commands:
  scan          Scan a single file.
  scan-dir      Scan an entire directory recursively.
  list-rules    List all loaded YARA rules.

Run:  uv run yaratrix --help
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from yaratrix import __version__
from yaratrix.rule_loader import load_rules
from yaratrix.yara_engine import scan_directory, scan_file

app = typer.Typer(
    name="yaratrix",
    help="[bold green]YaraTrix[/bold green] — YARA-to-MITRE ATT&CK Mapping Engine",
    rich_markup_mode="rich",
    add_completion=False,
)
console = Console()

# ─────────────────────────────────────────────
#  Default paths
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
#  Root callback — --version flag
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
#  scan command
# ─────────────────────────────────────────────
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

    # ── Print results ──
    if not result.matches:
        console.print("[bold green]✓ No matches found.[/bold green]")
    else:
        table = Table(
            title=f"Matches in {target.name}",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("Rule", style="bold")
        table.add_column("Technique")
        table.add_column("Tactic")
        table.add_column("Severity")
        table.add_column("Strings Hit")
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

    # ── Summary ──
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"{len(result.matches)} match(es) | "
        f"Techniques: {', '.join(result.matched_techniques()) or 'none'} | "
        f"Tactics: {', '.join(result.matched_tactics()) or 'none'} | "
        f"Duration: {result.duration_ms:.1f}ms"
    )

    # ── JSON output ──
    if output_json:
        output_json.write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n[dim]JSON saved to: {output_json}[/dim]")


# ─────────────────────────────────────────────
#  scan-dir command
# ─────────────────────────────────────────────
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
        console.print(
            f"  [{current}/{total}] {filename}", highlight=False
        )

    summary = scan_directory(
        loader.compiled,
        directory,
        rule_file_map=loader.filepaths,
        recursive=not no_recursive,
        on_progress=_progress,
    )

    hits = summary.files_with_matches()

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

    console.print(
        f"\n[bold]Summary:[/bold] "
        f"{summary.total_files()} file(s) scanned | "
        f"{len(hits)} file(s) with matches | "
        f"{summary.total_matches()} total match(es)"
    )

    if output_json:
        output_json.write_text(json.dumps(summary.to_dict(), indent=2))
        console.print(f"[dim]JSON saved to: {output_json}[/dim]")


# ─────────────────────────────────────────────
#  list-rules command
# ─────────────────────────────────────────────
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
        # yara.Rule doesn't expose namespace directly on iteration;
        # we derive source file from the filepaths map by scanning for the rule identifier.
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

    # Report validation issues
    if loader.errors:
        console.print(f"\n[yellow]⚠  {len(loader.errors)} rule(s) have meta validation issues:[/yellow]")
        for err in loader.errors:
            console.print(f"  [dim]{err}[/dim]")


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def run_cli() -> None:
    app()


if __name__ == "__main__":
    run_cli()
