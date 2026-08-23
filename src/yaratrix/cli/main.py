import typer
from rich.console import Console

from yaratrix import __version__

app = typer.Typer(help="YaraTrix: YARA-to-MITRE ATT&CK Mapping Engine")
console = Console()

def version_callback(value: bool):
    if value:
        console.print(f"[bold green]YaraTrix[/bold green] version: {__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=version_callback,
        is_eager=True,
    )
):
    """
    YaraTrix CLI
    """
    pass

def run_cli():
    app()

if __name__ == "__main__":
    run_cli()
