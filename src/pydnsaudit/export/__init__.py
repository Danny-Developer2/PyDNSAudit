"""Exportación de resultados a JSON, CSV y HTML."""

from pathlib import Path

from pydnsaudit.exceptions import ExportError
from pydnsaudit.export.csv_export import export_csv
from pydnsaudit.export.html_export import export_html
from pydnsaudit.export.json_export import export_json
from pydnsaudit.models import DNSAuditResult

SUPPORTED_FORMATS = ("json", "csv", "html")


def export_result(result: DNSAuditResult, path: Path, fmt: str) -> Path:
    """Exporta un resultado al formato indicado.

    Raises:
        ExportError: Si el formato no está soportado o no se puede escribir.
    """
    normalized = fmt.lower().lstrip(".")
    if normalized not in SUPPORTED_FORMATS:
        raise ExportError(f"formato no soportado: {fmt!r}. Usa: {', '.join(SUPPORTED_FORMATS)}")

    destination = path.with_suffix(f".{normalized}")
    try:
        if normalized == "json":
            return export_json(result, destination)
        if normalized == "csv":
            return export_csv(result, destination)
        return export_html(result, destination)
    except ExportError:
        raise
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el informe en {destination}: {exc}") from exc


__all__ = ["export_result", "SUPPORTED_FORMATS", "export_json", "export_csv", "export_html"]
