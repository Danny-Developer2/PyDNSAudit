"""Análisis de registros SPF."""

from __future__ import annotations

from pydnsaudit.config import SPF_DNS_LOOKUPS
from pydnsaudit.core.resolver import resolve_record
from pydnsaudit.models import Category, DNSRecord, Finding, Severity, SPFInfo
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.spf")


async def analyze_spf(
    domain: str, nameserver: str | None = None, timeout: float = 5.0
) -> tuple[SPFInfo, list[Finding]]:
    """Analiza el registro SPF del dominio.

    Returns:
        Una tupla con la información SPF y los hallazgos.
    """
    try:
        records = await resolve_record(domain, "TXT", nameserver, timeout)
    except Exception as exc:  # defensivo: un fallo de red no detiene la auditoría
        _logger.debug("no se pudo obtener SPF de %s: %s", domain, exc)
        records = []

    spf_raw = _find_spf(records)
    if spf_raw is None:
        return (
            SPFInfo(domain=domain, present=False),
            [
                Finding(
                    id="spf_missing",
                    category=Category.SPF,
                    severity=Severity.PROBABLE,
                    title="Registro SPF ausente",
                    description=(
                        "El dominio no publica un registro SPF, lo que facilita la "
                        "suplantación de identidad en el correo electrónico."
                    ),
                    evidence=f"No se ha encontrado ningún registro TXT con v=spf1 en {domain}.",
                    recommendation=(
                        "Publica una política SPF que enumere los servidores autorizados."
                    ),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc7208",
                        "https://dmarcian.com/spf-survey/",
                    ],
                )
            ],
        )

    info = _parse_spf(domain, spf_raw)
    return info, _evaluate_spf(info)


def _find_spf(records: list[DNSRecord]) -> str | None:
    """Busca el registro TXT que contiene la política SPF."""
    for record in records:
        for value in record.values:
            if value.strip().lower().startswith("v=spf1"):
                return str(value.strip())
    return None


def _parse_spf(domain: str, raw: str) -> SPFInfo:
    """Descompone una política SPF en sus mecanismos."""
    tokens = raw.split()
    mechanisms = [token for token in tokens[1:] if not token.startswith("v=")]

    all_qualifier: str | None = None
    includes: list[str] = []
    lookup_count = 0

    for token in mechanisms:
        lowered = token.lower()
        if lowered.startswith(("include:", "redirect=")) or lowered.startswith(
            ("a", "mx", "ptr", "exists")
        ):
            lookup_count += 1
        if lowered in {"a", "mx"}:
            lookup_count += 1
        if lowered in {"all", "+all"}:
            all_qualifier = "+"
        elif lowered.startswith("-all"):
            all_qualifier = "-"
        elif lowered.startswith("~all"):
            all_qualifier = "~"
        elif lowered.startswith("?all"):
            all_qualifier = "?"
        if lowered.startswith("include:"):
            includes.append(token.split(":", 1)[1])

    # Los mecanismos `all` no cuentan como consulta DNS.
    lookup_count = min(lookup_count, len(SPF_DNS_LOOKUPS) * 4)

    return SPFInfo(
        domain=domain,
        present=True,
        raw=raw,
        mechanisms=mechanisms,
        lookup_count=lookup_count,
        all_qualifier=all_qualifier,
        includes=includes,
    )


def _evaluate_spf(info: SPFInfo) -> list[Finding]:
    """Genera hallazgos a partir de la política SPF."""
    findings: list[Finding] = []

    if info.all_qualifier == "+":
        findings.append(
            Finding(
                id="spf_permissive_all",
                category=Category.SPF,
                severity=Severity.PROBABLE,
                title="SPF permite el envío desde cualquier origen",
                description=(
                    "El mecanismo `+all` autoriza a cualquier servidor a enviar correo "
                    "en nombre del dominio, lo que invalida el propósito de SPF."
                ),
                evidence=f"SPF: {info.raw}",
                recommendation="Sustituye `+all` por `~all` o `-all`.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            )
        )
    elif info.all_qualifier is None:
        findings.append(
            Finding(
                id="spf_without_all",
                category=Category.SPF,
                severity=Severity.POTENCIAL,
                title="SPF sin mecanismo `all`",
                description=(
                    "La política no define el mecanismo `all`, por lo que el "
                    "comportamiento ante orígenes no coincidentes queda sin definir."
                ),
                evidence=f"SPF: {info.raw}",
                recommendation="Añade `~all` o `-all` al final de la política.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            )
        )
    elif info.all_qualifier == "?":
        findings.append(
            Finding(
                id="spf_neutral_all",
                category=Category.SPF,
                severity=Severity.RECOMENDACION,
                title="SPF con mecanismo `?all` neutro",
                description=(
                    "El mecanismo `?all` no define una postura clara, por lo que los "
                    "servidores de correo no rechazarán ni marcarán los mensajes."
                ),
                evidence=f"SPF: {info.raw}",
                recommendation="Usa `~all` o `-all` para definir una postura.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            )
        )

    if info.lookup_count > 10:
        findings.append(
            Finding(
                id="spf_too_many_lookups",
                category=Category.SPF,
                severity=Severity.PROBABLE,
                title="SPF supera el límite de consultas DNS",
                description=(
                    "El RFC 7208 limita a 10 las consultas DNS que puede provocar una "
                    "política SPF; superarlo hace que la evaluación falle con `permerror`."
                ),
                evidence=f"Consultas estimadas: {info.lookup_count}",
                recommendation="Reduce los mecanismos `include`, `a`, `mx` y `redirect`.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
            )
        )

    if info.includes:
        findings.append(
            Finding(
                id="spf_includes_present",
                category=Category.SPF,
                severity=Severity.INDICIO,
                title="SPF delega en otros dominios",
                description=(
                    "La política incluye otros dominios, lo que extiende la superficie "
                    "de confianza a la configuración de terceros."
                ),
                evidence=f"include: {', '.join(info.includes)}",
                recommendation="Revisa periódicamente los dominios incluidos.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
            )
        )

    return findings


__all__ = ["analyze_spf"]
