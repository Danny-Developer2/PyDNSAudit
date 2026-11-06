"""Análisis de políticas DMARC."""

from __future__ import annotations

from pydnsaudit.core.resolver import resolve_record
from pydnsaudit.models import Category, DMARCInfo, DNSRecord, Finding, Severity
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.dmarc")


async def analyze_dmarc(
    domain: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> tuple[DMARCInfo, list[Finding]]:
    """Analiza la política DMARC del dominio.

    Returns:
        Una tupla con la información DMARC y los hallazgos.
    """
    dmarc_domain = f"_dmarc.{domain}"

    try:
        records = await resolve_record(dmarc_domain, "TXT", nameserver, timeout)
    except Exception as exc:  # defensivo
        _logger.debug("no se pudo obtener DMARC de %s: %s", domain, exc)
        records = []

    raw = _find_dmarc(records)
    if raw is None:
        return (
            DMARCInfo(domain=domain, present=False),
            [
                Finding(
                    id="dmarc_missing",
                    category=Category.DMARC,
                    severity=Severity.PROBABLE,
                    title="Política DMARC ausente",
                    description=(
                        "Sin DMARC, el dominio no indica cómo actuar ante mensajes que "
                        "superan o fallan SPF y DKIM, lo que facilita la suplantación."
                    ),
                    evidence=f"No se ha encontrado un registro TXT en {dmarc_domain}.",
                    recommendation=(
                        "Publica una política DMARC; empieza con p=none y evoluciona "
                        "hacia p=quarantine y p=reject."
                    ),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc7489",
                        "https://dmarc.org/",
                    ],
                )
            ],
        )

    info = _parse_dmarc(domain, raw)
    return info, _evaluate_dmarc(info)


def _find_dmarc(records: list[DNSRecord]) -> str | None:
    """Busca el registro TXT que contiene la política DMARC."""
    for record in records:
        for value in record.values:
            if value.strip().lower().startswith("v=dmarc1"):
                return value.strip()
    return None


def _parse_dmarc(domain: str, raw: str) -> DMARCInfo:
    """Descompone una política DMARC en sus etiquetas."""
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()

    return DMARCInfo(
        domain=domain,
        present=True,
        raw=raw,
        policy=tags.get("p"),
        subdomain_policy=tags.get("sp"),
        percentage=_parse_percentage(tags.get("pct")),
        aggregate_reports=[v for v in tags.get("rua", "").split(",") if v],
        forensic_reports=[v for v in tags.get("ruf", "").split(",") if v],
    )


def _parse_percentage(value: str | None) -> int | None:
    """Convierte la etiqueta pct a un entero."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _evaluate_dmarc(info: DMARCInfo) -> list[Finding]:
    """Genera hallazgos a partir de la política DMARC."""
    findings: list[Finding] = []

    if info.policy == "none":
        findings.append(
            Finding(
                id="dmarc_policy_none",
                category=Category.DMARC,
                severity=Severity.PROBABLE,
                title="DMARC sin acción de aplicación",
                description=(
                    "La política `p=none` solo pide informes, por lo que los mensajes "
                    "suplantados siguen entregándose con normalidad."
                ),
                evidence=f"DMARC: {info.raw}",
                recommendation=("Evoluciona a p=quarantine y, cuando sea viable, a p=reject."),
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        )
    elif info.policy is None:
        findings.append(
            Finding(
                id="dmarc_policy_missing",
                category=Category.DMARC,
                severity=Severity.PROBABLE,
                title="DMARC sin etiqueta p",
                description=(
                    "La política no define la etiqueta `p`, por lo que no hay una "
                    "postura de aplicación declarada."
                ),
                evidence=f"DMARC: {info.raw}",
                recommendation="Define p=none como punto de partida y evoluciona la política.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        )

    if info.subdomain_policy == "none" or (
        info.subdomain_policy is None and info.policy != "reject"
    ):
        findings.append(
            Finding(
                id="dmarc_subdomain_policy",
                category=Category.DMARC,
                severity=Severity.POTENCIAL,
                title="DMARC sin protección explícita de subdominios",
                description=(
                    "Sin `sp=` los subdominios pueden quedar fuera de la política "
                    "principal, lo que deja vías de suplantación abiertas."
                ),
                evidence=(
                    f"sp={info.subdomain_policy or 'ausente'} · p={info.policy or 'ausente'}"
                ),
                recommendation="Declara sp=reject o sp=quarantine para los subdominios.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        )

    if info.percentage is not None and info.percentage < 100:
        findings.append(
            Finding(
                id="dmarc_partial_percentage",
                category=Category.DMARC,
                severity=Severity.RECOMENDACION,
                title="DMARC aplica la política de forma parcial",
                description=(
                    "La etiqueta `pct` reduce el porcentaje de mensajes a los que se "
                    "aplica la política, lo que deja una parte sin proteger."
                ),
                evidence=f"pct={info.percentage}",
                recommendation="Usa pct=100 cuando la política esté consolidada.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        )

    if not info.aggregate_reports:
        findings.append(
            Finding(
                id="dmarc_without_reports",
                category=Category.DMARC,
                severity=Severity.RECOMENDACION,
                title="DMARC sin informes agregados",
                description=(
                    "Sin la etiqueta `rua` no se reciben informes de resultados, lo que "
                    "dificulta detectar intentos de suplantación."
                ),
                evidence=f"DMARC: {info.raw}",
                recommendation="Configura una dirección rua para recibir informes.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        )

    return findings


__all__ = ["analyze_dmarc"]
