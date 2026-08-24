"""Narrative and machine-readable CLI for the safe OpenBOLA pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from openbola.pipeline import IdentityInput, PipelineError, PipelineResult, run_pipeline

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


def _assignment(value: str, label: str) -> tuple[str, str]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise typer.BadParameter(f"{label} must use NAME=VALUE")
    return name, path


def _identity_input(name: str, path: str, credential_env: str) -> IdentityInput:
    traffic_path = Path(path)
    if traffic_path.suffix.casefold() == ".har":
        return IdentityInput(name=name, har_path=traffic_path, credential_env=credential_env)
    return IdentityInput(name=name, records_path=traffic_path, credential_env=credential_env)


def _render(result: PipelineResult, *, json_output: bool) -> None:
    summary = result.public_summary()
    if json_output:
        typer.echo(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return
    console.print(
        f"[cyan]>[/cyan] run {result.run_id} voor "
        f"[bold]{result.scope_target_label}[/bold]"
    )
    console.print(f"  [dim]->[/dim] {result.ownership_persisted} ownership-relatie(s) vastgelegd")
    console.print(f"  [dim]->[/dim] {result.pending_count} combinatie(s) beoordeeld")
    for reason, count in sorted(result.skip_reasons.items()):
        console.print(
            f"  [dim]->[/dim] [yellow]{count} candidate(s) overgeslagen"
            f" ({reason.replace('_', ' ')})[/yellow]"
        )
    for verdict, count in summary["outcomes"].items():
        if count:
            colour = "red" if verdict == "bola" else "green" if verdict == "protected" else "yellow"
            console.print(f"  [dim]->[/dim] [{colour}]{count} {verdict}[/{colour}]")
    console.print(
        "  [dim]->[/dim] rapporten atomair geschreven naar "
        f"{result.report_paths['markdown'].parent}"
    )


@app.command()
def scan(
    scope: Annotated[Path, typer.Option("--scope", exists=False, readable=True)],
    base_url: Annotated[str, typer.Option("--base-url")],
    identity: Annotated[
        list[str],
        typer.Option(
            "--identity",
            help="NAME=records.json (ownership evidence) or NAME=traffic.har (discovery only)",
        ),
    ],
    credential: Annotated[
        list[str], typer.Option("--credential", help="NAME=ENVIRONMENT_VARIABLE")
    ],
    db: Annotated[Path, typer.Option("--db")] = Path("bola_state.db"),
    report_dir: Annotated[Path, typer.Option("--report-dir")] = Path("reports"),
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit one machine-readable JSON line")
    ] = False,
) -> None:
    """Run a read-only BOLA assessment against a confirmed, local scope."""

    try:
        traffic = dict(_assignment(item, "--identity") for item in identity)
        credentials = dict(_assignment(item, "--credential") for item in credential)
        if len(traffic) < 2:
            raise typer.BadParameter("at least two --identity values are required")
        missing = sorted(set(traffic) - set(credentials))
        if missing:
            raise typer.BadParameter("missing --credential for: " + ", ".join(missing))
        inputs = [_identity_input(name, path, credentials[name]) for name, path in traffic.items()]
        if not json_output:
            console.print(f"[cyan]>[/cyan] scope laden vanaf {scope}")
        result = run_pipeline(
            scope.absolute(),
            base_url,
            inputs,
            db_path=db.absolute(),
            report_dir=report_dir.absolute(),
        )
        _render(result, json_output=json_output)
    except (PipelineError, OSError, ValueError) as error:
        if json_output:
            typer.echo(json.dumps({"ok": False, "error": "scan_denied"}, separators=(",", ":")))
        else:
            console.print(f"[bold red]geweigerd:[/bold red] {error}")
        raise typer.Exit(code=2) from error


@app.callback()
def main() -> None:
    """OpenBOLA: authorization-first BOLA/IDOR testing."""


if __name__ == "__main__":  # pragma: no cover
    app()


__all__ = ["app"]
