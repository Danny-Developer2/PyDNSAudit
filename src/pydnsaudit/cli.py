"""Interfaz de línea de comandos de PyDNSAudit (Typer + Rich)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pydnsaudit import __version__
from pydnsaudit.config import COMMON_DKIM_SELECTORS, AuditConfig
from pydnsaudit.core.auditor import Auditor
from pydnsaudit.exceptions import PyDNSAuditError
from pydnsaudit.export import export_result
from pydnsaudit.models import DNSAuditResult, Severity
from pydnsaudit.utils.logger import setup_logger
from pydnsaudit.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    load_scope_file,
    validate_target,
)

app = typer.Typer(
    name="pydnsaudit",
    help="PyDNSAudit — auditoría de seguridad DNS (solo auditorías autorizadas).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

AVISO_LEGAL = (
    "[yellow]AVISO:[/yellow] esta herramienta está pensada exclusivamente para "
    "auditorías autorizadas. Comprueba que dispones de autorización expresa."
)

SEVERITY_ORDER = [
    Severity.CONFIRMADO,
    Severity.PROBABLE,
    Severity.POTENCIAL,
    Severity.INDICIO,
    Severity.RECOMENDACION,
]


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Dominio autorizado (por ejemplo ejemplo.com)."),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Fichero JSON con el alcance autorizado."
    ),
    confirm_authorized: bool = typer.Option(
        False, "--confirm-authorized", help="Declara que se dispone de autorización expresa."
    ),
    nameserver: str | None = typer.Option(
        None, "--nameserver", help="Resolver DNS concreto (por defecto, el del sistema)."
    ),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Tiempo de espera por consulta."),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Consultas simultáneas."),
    rate_limit: float = typer.Option(20.0, "--rate-limit", help="Consultas por segundo."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Ruta del informe (se añade la extensión)."
    ),
    format: str = typer.Option("json", "--format", "-f", help="Formato: json, csv o html."),
    log_file: Path | None = typer.Option(None, "--log-file", help="Volcar el registro a fichero."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Registro detallado."),
    no_spf: bool = typer.Option(False, "--no-spf", help="No analizar SPF."),
    no_dmarc: bool = typer.Option(False, "--no-dmarc", help="No analizar DMARC."),
    no_subdomains: bool = typer.Option(False, "--no-subdomains", help="No enumerar subdominios."),
    dkim_selectors: str | None = typer.Option(
        None,
        "--dkim-selectors",
        help="Selectores DKIM separados por comas (por defecto, los habituales).",
    ),
) -> None:
    """Ejecuta una auditoría DNS sobre el dominio autorizado."""
    setup_logger("DEBUG" if verbose else "INFO", log_file)
    console.print(AVISO_LEGAL)

    try:
        validated = validate_target(domain)
        scope = load_scope_file(scope_file)
        ensure_authorized(validated, scope, confirm_authorized)
        config = AuditConfig(
            domain=validated,
            nameserver=nameserver,
            timeout=timeout,
            concurrency=concurrency,
            rate_limit=rate_limit,
            check_spf=not no_spf,
            check_dmarc=not no_dmarc,
            check_subdomains=not no_subdomains,
            dkim_selectors=tuple(s.strip() for s in dkim_selectors.split(",") if s.strip())
            if dkim_selectors
            else COMMON_DKIM_SELECTORS,
            scope=scope,
            scope_file=str(scope_file) if scope_file else None,
            confirm_authorized=confirm_authorized,
        )
        if output is not None:
            ensure_path_writable(output)
    except PyDNSAuditError as exc:
        err_console.print(f"[red]Error de validación:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        result = asyncio.run(Auditor(config).run())
    except KeyboardInterrupt:  # pragma: no cover - interrupción manual
        err_console.print("\n[yellow]Ejecución interrumpida por el usuario.[/yellow]")
        raise typer.Exit(code=130) from None
    except PyDNSAuditError as exc:
        err_console.print(f"[red]Error durante la auditoría:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_summary(result)

    if output is not None:
        try:
            written = export_result(result, output, format)
        except PyDNSAuditError as exc:
            err_console.print(f"[red]Error al exportar:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Informe guardado en:[/green] {written}")


def _print_summary(result: DNSAuditResult) -> None:
    """Muestra un resumen en tabla por consola."""
    console.print(f"\n[bold]PyDNSAudit[/bold] — dominio: {result.domain}")
    console.print(
        f"Registros: {len(result.records)} tipos · "
        f"Servidores de nombres: {len(result.nameservers)} · "
        f"Subdominios: {len(result.subdomains)} · "
        f"Duración: {result.duration_seconds:.2f}s"
    )

    if result.spf:
        spf_raw = result.spf.raw if result.spf.present and result.spf.raw else "ausente"
        console.print(f"SPF: {spf_raw}")
    if result.dmarc:
        dmarc_raw = result.dmarc.raw if result.dmarc.present and result.dmarc.raw else "ausente"
        console.print(f"DMARC: {dmarc_raw}")

    table = Table(title="Hallazgos por severidad")
    table.add_column("Severidad", style="cyan")
    table.add_column("Cantidad", justify="right")
    for severity in SEVERITY_ORDER:
        table.add_row(severity.value, str(len(result.findings_by_severity(severity))))
    console.print(table)


@app.command()
def version() -> None:
    """Muestra la versión de PyDNSAudit."""
    console.print(f"PyDNSAudit {__version__}")


def main() -> None:
    """Punto de entrada de la CLI."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
