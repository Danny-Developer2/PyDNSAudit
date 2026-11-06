"""Análisis de registros DKIM."""

from __future__ import annotations

from pydnsaudit.core.resolver import resolve_record
from pydnsaudit.models import Category, DKIMInfo, DNSRecord, Finding, Severity
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.dkim")


async def analyze_dkim(
    domain: str,
    selector: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> tuple[DKIMInfo, list[Finding]]:
    """Analiza el registro DKIM de un selector concreto.

    Returns:
        Una tupla con la información DKIM y los hallazgos.
    """
    dkim_domain = f"{selector}._domainkey.{domain}"

    try:
        records = await resolve_record(dkim_domain, "TXT", nameserver, timeout)
    except Exception as exc:  # defensivo
        _logger.debug("no se pudo obtener DKIM %s: %s", dkim_domain, exc)
        records = []

    raw = _find_dkim(records)
    if raw is None:
        return DKIMInfo(domain=domain, selector=selector, present=False), []

    info = _parse_dkim(domain, selector, raw)
    return info, _evaluate_dkim(info)


def _find_dkim(records: list[DNSRecord]) -> str | None:
    """Busca el registro TXT con la clave pública DKIM."""
    for record in records:
        for value in record.values:
            if "v=dkim1" in value.lower() or "k=rsa" in value.lower() or "p=" in value:
                return value.strip()
    return None


def _parse_dkim(domain: str, selector: str, raw: str) -> DKIMInfo:
    """Descompone un registro DKIM en sus etiquetas."""
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()

    return DKIMInfo(
        domain=domain,
        selector=selector,
        present=True,
        raw=raw,
        key_type=tags.get("k"),
        key_size=_key_size(tags.get("p")),
    )


def _key_size(public_key: str | None) -> int | None:
    """Estima la longitud de la clave pública a partir de su codificación base64."""
    if not public_key:
        return None
    import base64
    import binascii

    try:
        decoded = base64.b64decode(public_key + "=" * (-len(public_key) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    # Estimación aproximada: la clave DER ocupa ~1.37 veces su tamaño en bits.
    return max(len(decoded) * 8 // 11, 0) if decoded else None


def _evaluate_dkim(info: DKIMInfo) -> list[Finding]:
    """Genera hallazgos a partir del registro DKIM."""
    findings: list[Finding] = []

    if not info.raw:
        return findings

    tags: dict[str, str] = {}
    for part in info.raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()

    if not tags.get("p"):
        findings.append(
            Finding(
                id=f"dkim_empty_key_{_slug(info.selector)}",
                category=Category.DKIM,
                severity=Severity.INDICIO,
                title=f"DKIM con clave pública vacía: {info.selector}",
                description=(
                    "Un registro DKIM sin clave pública (`p=` vacío) invalida la "
                    "verificación, lo que suele indicar que la clave se ha retirado."
                ),
                evidence=f"DKIM {info.selector}: {info.raw}",
                recommendation="Retira el registro o restaura la clave pública.",
                references=["https://datatracker.ietf.org/doc/html/rfc6376"],
            )
        )

    if "s" in tags and "email" not in info.raw.lower():
        findings.append(
            Finding(
                id=f"dkim_service_type_{_slug(info.selector)}",
                category=Category.DKIM,
                severity=Severity.INDICIO,
                title="DKIM restringido a servicios distintos del correo",
                description=(
                    "La etiqueta `s=` limita el uso de la clave a servicios concretos; "
                    "si no incluye `email`, no se aplica al correo electrónico."
                ),
                evidence=f"DKIM {info.selector}: {info.raw}",
                recommendation="Comprueba que la etiqueta `s=` incluye email.",
                references=["https://datatracker.ietf.org/doc/html/rfc6376"],
            )
        )

    if info.key_type and info.key_type.lower() not in {"rsa", "ed25519"}:
        findings.append(
            Finding(
                id=f"dkim_unusual_key_type_{_slug(info.selector)}",
                category=Category.DKIM,
                severity=Severity.POTENCIAL,
                title=f"DKIM con tipo de clave poco habitual: {info.selector}",
                description=(
                    "El tipo de clave declarado no es uno de los habituales, lo que "
                    "puede indicar una configuración errónea."
                ),
                evidence=f"k={info.key_type}",
                recommendation="Usa claves RSA o Ed25519.",
                references=["https://datatracker.ietf.org/doc/html/rfc6376"],
            )
        )

    if info.key_size is not None and info.key_size < 1024:
        findings.append(
            Finding(
                id=f"dkim_short_key_{_slug(info.selector)}",
                category=Category.DKIM,
                severity=Severity.PROBABLE,
                title=f"DKIM con clave de longitud insuficiente: {info.selector}",
                description=(
                    "Las claves DKIM cortas pueden verificarse de forma débil y son "
                    "rechazadas por algunos servicios de correo."
                ),
                evidence=f"Longitud estimada: {info.key_size} bits",
                recommendation="Usa claves RSA de al menos 2048 bits.",
                references=["https://datatracker.ietf.org/doc/html/rfc6376"],
            )
        )

    return findings


def _slug(value: str) -> str:
    """Genera un identificador estable."""
    return "".join(ch if ch.isalnum() else "_" for ch in value.lower())[:30]


__all__ = ["analyze_dkim"]
