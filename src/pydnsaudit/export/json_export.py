"""Exportación de resultados a JSON."""

from __future__ import annotations

import json
from pathlib import Path

from pydnsaudit.exceptions import ExportError
from pydnsaudit.models import DNSAuditResult


def export_json(result: DNSAuditResult, path: Path) -> Path:
    """Escribe el resultado en formato JSON con esquema versionado.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    payload = result.model_dump(mode="json")
    payload["schema"] = "pydnsaudit/audit-result"
    payload["schema_version"] = 1

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el JSON en {path}: {exc}") from exc
    return path
