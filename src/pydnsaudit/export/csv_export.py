"""Exportación de resultados a CSV."""

from __future__ import annotations

import csv
from pathlib import Path

from pydnsaudit.exceptions import ExportError
from pydnsaudit.models import DNSAuditResult

FIELDNAMES = [
    "id",
    "categoria",
    "severidad",
    "titulo",
    "descripcion",
    "evidencia",
    "recomendacion",
    "referencias",
    "dominio",
    "fecha",
]


def export_csv(result: DNSAuditResult, path: Path) -> Path:
    """Escribe una fila por hallazgo.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()
            for finding in result.findings:
                writer.writerow(
                    {
                        "id": finding.id,
                        "categoria": finding.category.value,
                        "severidad": finding.severity.value,
                        "titulo": finding.title,
                        "descripcion": finding.description,
                        "evidencia": finding.evidence,
                        "recomendacion": finding.recommendation,
                        "referencias": "; ".join(finding.references),
                        "dominio": result.domain,
                        "fecha": result.finished_at.isoformat(),
                    }
                )
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el CSV en {path}: {exc}") from exc
    return path
