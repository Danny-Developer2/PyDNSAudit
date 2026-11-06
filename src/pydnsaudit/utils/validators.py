"""Validación de entradas y control de autorización."""

from __future__ import annotations

import json
from pathlib import Path

from pydnsaudit.exceptions import (
    AuthorizationError,
    ScopeError,
    ValidationError,
)
from pydnsaudit.models import Scope
from pydnsaudit.utils.domain import validate_domain


def validate_target(target: str) -> str:
    """Valida y normaliza el dominio objetivo.

    Raises:
        ValidationError: Si el dominio no es válido.
    """
    return validate_domain(target).name


def load_scope_file(path: Path | None) -> Scope | None:
    """Carga el fichero de alcance autorizado.

    Returns:
        El alcance o ``None`` si no se proporcionó fichero.

    Raises:
        ScopeError: Si el fichero no existe o no es JSON válido.
    """
    if path is None:
        return None

    if not path.exists():
        raise ScopeError(f"el fichero de alcance no existe: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"no se pudo leer el fichero de alcance {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ScopeError("el fichero de alcance debe ser un objeto JSON")

    targets = payload.get("authorized_targets")
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise ScopeError("authorized_targets debe ser una lista de cadenas")

    return Scope(
        name=str(payload.get("name", "Auditoría autorizada")),
        authorized_targets=targets,
    )


def is_target_in_scope(domain: str, scope: Scope) -> bool:
    """Indica si un dominio está dentro del alcance autorizado."""
    return scope.matches(domain)


def ensure_authorized(domain: str, scope: Scope | None, confirmed: bool) -> None:
    """Exige autorización expresa o inclusión en el alcance.

    Raises:
        AuthorizationError: Si no hay autorización.
        ValidationError: Si el dominio está fuera del alcance.
    """
    if scope is None and not confirmed:
        raise AuthorizationError(
            "se requiere autorización expresa: usa --confirm-authorized o --scope"
        )

    if scope is not None and not scope.matches(domain):
        raise ValidationError(
            f"el dominio {domain} está fuera del alcance autorizado ({scope.name})"
        )


def ensure_path_writable(path: Path) -> None:
    """Comprueba que se puede escribir un informe en la ruta indicada.

    Raises:
        ValidationError: Si la ruta no es escribible.
    """
    if path.exists() and path.is_dir():
        raise ValidationError(f"la ruta de salida es un directorio: {path}")

    parent = path.parent if str(path.parent) else Path(".")
    if not parent.exists():
        raise ValidationError(f"el directorio de salida no existe: {parent}")
    if not parent.is_dir():
        raise ValidationError(f"el directorio de salida no es un directorio: {parent}")
