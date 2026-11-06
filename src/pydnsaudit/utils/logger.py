"""Registro de actividad de PyDNSAudit."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logger(level: str = "INFO", log_file: Path | None = None) -> logging.Logger:
    """Configura el registro global de la herramienta.

    Args:
        level: Nivel mínimo (DEBUG, INFO, WARNING, ERROR).
        log_file: Si se indica, el registro se volcará también al fichero.

    Returns:
        El logger raíz de la aplicación.
    """
    global _configured

    root = logging.getLogger("pydnsaudit")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.propagate = False
    _configured = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Devuelve un logger con el prefijo de la aplicación."""
    if not _configured:
        setup_logger()
    return logging.getLogger(f"pydnsaudit.{name}")
