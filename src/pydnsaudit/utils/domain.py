"""Utilidades de dominio y red para PyDNSAudit."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from pydnsaudit.exceptions import ValidationError
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("utils.domain")

# Patrón de etiqueta DNS válida.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


@dataclass(frozen=True, slots=True)
class Domain:
    """Dominio normalizado."""

    name: str

    def __str__(self) -> str:
        return self.name


def validate_domain(value: str) -> Domain:
    """Valida y normaliza un nombre de dominio.

    Raises:
        ValidationError: Si el dominio no es válido.
    """
    cleaned = (value or "").strip().lower().rstrip(".")

    if not cleaned:
        raise ValidationError("el dominio no puede estar vacío")

    # Se aceptan URLs completas para facilitar el uso.
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.split(":", 1)[0]

    if len(cleaned) > 253:
        raise ValidationError(f"el dominio {value!r} supera la longitud máxima")

    if not _DOMAIN_RE.match(cleaned):
        raise ValidationError(f"el dominio {value!r} no es válido")

    return Domain(name=cleaned)


def is_domain(value: str) -> bool:
    """Indica si un valor parece un nombre de dominio."""
    try:
        validate_domain(value)
    except ValidationError:
        return False
    return True


def is_ip_address(value: str) -> bool:
    """Indica si un valor es una dirección IP."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parent_domain(domain: str) -> str:
    """Devuelve el dominio de nivel superior (zona) de un nombre.

    ``www.sub.ejemplo.com`` → ``ejemplo.com``. Es una aproximación basada en la
    última etiqueta pública común, suficiente para el ámbito de la herramienta.
    """
    parts = validate_domain(domain).name.split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def build_fqdn(label: str, domain: str) -> str:
    """Concatena una etiqueta con el dominio base."""
    return f"{label}.{domain}" if label else domain


def strip_wildcard(name: str) -> str:
    """Elimina el prefijo comodín de un nombre DNS."""
    return name[2:] if name.startswith("*.") else name


__all__ = [
    "Domain",
    "build_fqdn",
    "is_domain",
    "is_ip_address",
    "parent_domain",
    "strip_wildcard",
    "validate_domain",
]
