"""Narrative and machine-readable CLI for the safe OpenBOLA pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from openbola import __version__
from openbola.doctor import DiagnosticReport, run_doctor
from openbola.mcp_server import MCPServiceError, create_mcp_server
from openbola.pipeline import IdentityInput, PipelineError, PipelineResult, run_pipeline
from openbola.reports import (
    ARTIFACT_FILENAMES,
    ReportError,
    ReportLocator,
    load_published_report,
)
from openbola.setup import SetupResult, run_setup
from openbola.updates import UpdateResult, apply_update, check_for_update

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
_SAFE_UPDATE_REASONS = frozenset(
    {
        "archive_invalid",
        "archive_members_invalid",
        "archive_too_large",
        "artifact_missing",
        "artifact_too_large",
        "cache_untrusted",
        "checksum_duplicate",
        "checksum_malformed",
        "checksum_missing",
        "checksum_too_large",
        "confirmation_required",
        "data_root_unavailable",
        "digest_mismatch",
        "download_failed",
        "download_malformed",
        "executable_invalid",
        "invalid_version",
        "malformed_release",
        "redirect_denied",
        "release_unavailable",
        "replacement_failed",
        "manifest_mismatch",
        "scope_denied",
        "scope_peer_pinning_unsupported",
        "scope_required",
        "size_mismatch",
        "unsupported_platform",
        "update_failed",
        "url_denied",
    }
)
_SAFE_SETUP_REASONS = frozenset(
    {
        "browser_install_failed",
        "browser_self_test_failed",
        "browser_unavailable",
        "data_root_unavailable",
        "data_root_untrusted",
        "invalid_arguments",
        "marker_write_failed",
        "setup_marker_invalid",
        "setup_marker_missing",
        "setup_marker_untrusted",
        "scope_required",
        "vault_unavailable",
    }
)


@dataclass(frozen=True)
class CommandResult:
    """Bounded result shared by administration command adapters."""

    ok: bool
    code: str
    details: dict[str, str | int | bool]


def _emit_command_error(code: str, *, json_output: bool) -> NoReturn:
    """Emit a stable, secret-free error and terminate with the admin code."""

    result = CommandResult(False, code, {})
    if json_output:
        typer.echo(json.dumps({"ok": result.ok, "error": result.code}, separators=(",", ":")))
    else:
        console.print("[bold red]commando geweigerd[/bold red]")
    raise typer.Exit(code=2)


def _emit_update_result(result: UpdateResult, *, json_output: bool) -> None:
    """Render only the updater protocol and map denied states to exit 2."""

    ok = result.status in {"current", "available", "updated"}
    details: dict[str, str | int | bool] = {
        "ok": ok,
        "status": result.status,
        "current_version": result.current_version,
    }
    if not ok:
        details["error"] = "update_denied"
    if result.candidate_version is not None:
        details["candidate_version"] = result.candidate_version
    if result.reason_code in _SAFE_UPDATE_REASONS:
        details["reason_code"] = result.reason_code
    if json_output:
        typer.echo(json.dumps(details, sort_keys=True, separators=(",", ":")))
    elif ok:
        if result.status == "updated":
            console.print(f"[green]OpenBOLA bijgewerkt naar {result.candidate_version}[/green]")
        elif result.status == "available":
            console.print(f"[yellow]Update beschikbaar: {result.candidate_version}[/yellow]")
        else:
            console.print(f"[green]OpenBOLA is actueel ({result.current_version})[/green]")
    else:
        console.print("[bold red]update geweigerd[/bold red]")
    if not ok:
        raise typer.Exit(code=2)


def _emit_setup_result(result: SetupResult, *, json_output: bool) -> None:
    """Render the setup protocol without exposing adapter or path details."""

    details = result.public_summary()
    reason = details.get("reason_code")
    if reason not in _SAFE_SETUP_REASONS:
        details.pop("reason_code", None)
    if json_output:
        typer.echo(json.dumps(details, sort_keys=True, separators=(",", ":")))
    else:
        if result.ok:
            console.print("[green]OpenBOLA setup voltooid[/green]")
        else:
            console.print("[bold red]setup geweigerd[/bold red]")
        console.print(f"  [dim]->[/dim] browser: {details['browser']}")
        console.print(f"  [dim]->[/dim] vault: {details['vault']}")
        console.print(f"  [dim]->[/dim] self-test: {details['self_test']}")
    if not result.ok:
        raise typer.Exit(code=2)


def _emit_doctor_result(result: DiagnosticReport, *, json_output: bool) -> None:
    """Render bounded local diagnostics and preserve blocked exit semantics."""

    details = result.public_dict()
    if json_output:
        typer.echo(json.dumps(details, sort_keys=True, separators=(",", ":")))
    else:
        heading = (
            "[green]doctor: lokale installatie gereed[/green]"
            if result.ok
            else "[yellow]doctor: aandacht vereist[/yellow]"
        )
        console.print(heading)
        for diagnostic in result.diagnostics:
            colour = (
                "green"
                if diagnostic.status == "ok"
                else "yellow"
                if diagnostic.status == "warning"
                else "red"
            )
            console.print(
                f"  [dim]->[/dim] [{colour}]{diagnostic.name}: {diagnostic.code}[/{colour}]"
            )
        console.print(f"  [dim]->[/dim] recovery: {result.recovery_state}")
    if result.blocked:
        raise typer.Exit(code=2)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


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


@app.command("setup")
def setup_command(
    json_output: Annotated[bool, typer.Option("--json")] = False,
    force_browser: Annotated[bool, typer.Option("--force-browser")] = False,
) -> None:
    """Prepare local browser and vault prerequisites."""

    try:
        result = run_setup(force_browser=force_browser)
    except Exception as error:
        # Adapter details may contain local paths or dependency information.
        del error
        _emit_command_error("setup_unavailable", json_output=json_output)
    _emit_setup_result(result, json_output=json_output)


@app.command("doctor")
def doctor_command(
    db: Annotated[Path | None, typer.Option("--db")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect local installation and recovery state without probing a target."""

    try:
        result = run_doctor(db_path=db, json_output=json_output)
    except Exception as error:
        # Diagnostic adapters are intentionally fail-closed at the CLI boundary.
        del error
        _emit_command_error("diagnostics_blocked", json_output=json_output)
    _emit_doctor_result(result, json_output=json_output)


@app.command("report")
def report_command(
    run: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
    format_name: Annotated[str, typer.Option("--format")] = "json",
    db: Annotated[Path, typer.Option("--db")] = Path("bola_state.db"),
    data_root: Annotated[Path | None, typer.Option("--data-root")] = None,
) -> None:
    """Reopen an existing sanitized report run."""

    normalized_format = format_name.casefold()
    if normalized_format not in ARTIFACT_FILENAMES:
        _emit_command_error("report_denied", json_output=json_output)
    try:
        database_path = db.absolute()
        root = (data_root if data_root is not None else database_path.parent).absolute()
        resolved = ReportLocator().resolve(run, db_path=database_path, data_root=root)
        directory = resolved if resolved.is_dir() else resolved.parent
        artifact = directory / ARTIFACT_FILENAMES[normalized_format]
        loaded = load_published_report(artifact)
        details: dict[str, object] = {
            "artifact": artifact.name,
            "format": normalized_format,
        }
        if isinstance(loaded, dict) and normalized_format == "json":
            summary = loaded.get("summary")
            scope = loaded.get("scope")
            if isinstance(summary, dict):
                details["summary"] = {
                    key: summary[key]
                    for key in ("bola", "executed", "inconclusive", "protected", "skipped")
                    if key in summary and isinstance(summary[key], int)
                }
            if isinstance(scope, dict) and isinstance(scope.get("target_label"), str):
                details["target_label"] = scope["target_label"]
        else:
            details.update(
                {key: value for key, value in loaded.items() if key in {"size", "filename"}}
            )
        if json_output:
            typer.echo(json.dumps({"ok": True, **details}, sort_keys=True, separators=(",", ":")))
            return
        console.print(f"[cyan]>[/cyan] sanitized report: {artifact.name}")
        if "target_label" in details:
            console.print(
                f"  [dim]->[/dim] target: {details['target_label']}", markup=False
            )
        summary = details.get("summary")
        if isinstance(summary, dict):
            for key, value in summary.items():
                console.print(f"  [dim]->[/dim] {key}: {value}")
    except (ReportError, OSError, ValueError, TypeError):
        _emit_command_error("report_denied", json_output=json_output)


@app.command("update")
def update_command(
    json_output: Annotated[bool, typer.Option("--json")] = False,
    check: Annotated[bool, typer.Option("--check")] = False,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    force_check: Annotated[bool, typer.Option("--force-check")] = False,
) -> None:
    """Check for or explicitly apply a verified release update."""
    try:
        result = (
            check_for_update(force_check=force_check)
            if check
            else apply_update(confirm=yes)
        )
    except Exception as error:
        # Never expose transport, filesystem, URL, or release-body details.
        del error
        _emit_command_error("update_denied", json_output=json_output)
    _emit_update_result(result, json_output=json_output)


@app.command("mcp")
def mcp_command(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Start the local read-only MCP server."""

    try:
        create_mcp_server(read_only=True).run(transport="stdio")
    except (ImportError, MCPServiceError, OSError, RuntimeError, ValueError) as error:
        # Optional transport/import failures are intentionally mapped to one
        # bounded code; exception text may contain local paths or dependency
        # details and must never cross the CLI boundary.
        del error
        _emit_command_error("mcp_unavailable", json_output=json_output)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = False,
) -> None:
    """OpenBOLA: authorization-first BOLA/IDOR testing."""

    del version


if __name__ == "__main__":  # pragma: no cover
    app()


__all__ = ["app"]
