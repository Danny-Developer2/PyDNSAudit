"""Enumeración de subdominios y análisis de exposición.

Solo se realizan consultas DNS individuales contra una lista reducida de nombres
habituales. No se intenta transferencia de zona ni fuerza bruta.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable

from pydnsaudit.config import COMMON_SUBDOMAINS
from pydnsaudit.core.resolver import resolve_record
from pydnsaudit.models import Category, DNSRecord, Finding, Severity, SubdomainInfo
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.subdomains")

# Prefijos que suelen indicar entornos no productivos.
NON_PRODUCTION_PREFIXES: tuple[str, ...] = (
    "dev",
    "test",
    "stage",
    "staging",
    "demo",
    "sandbox",
    "lab",
    "uat",
    "qa",
    "pre",
    "preprod",
)

# Prefijos que suelen alojar servicios de administración.
ADMIN_PREFIXES: tuple[str, ...] = (
    "admin",
    "administrator",
    "panel",
    "cpanel",
    "whm",
    "manage",
    "management",
    "portal",
    "intranet",
    "extranet",
    "vpn",
    "remote",
)


async def enumerate_subdomains(
    domain: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
    max_names: int = 60,
    concurrency: int = 10,
) -> list[SubdomainInfo]:
    """Busca subdominios habituales resolviendo cada nombre.

    Returns:
        Subdominios que existen, con sus direcciones y tipos de registro.
    """
    candidates = [f"{name}.{domain}" for name in COMMON_SUBDOMAINS[:max_names]]
    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(name: str) -> SubdomainInfo | None:
        async with semaphore:
            return await _resolve_subdomain(name, nameserver, timeout)

    results = await asyncio.gather(*(_probe(name) for name in candidates))
    found = [r for r in results if r is not None]
    found.sort(key=lambda info: info.name)
    _logger.info("subdominios identificados: %d", len(found))
    return found


async def _resolve_subdomain(
    name: str,
    nameserver: str | None,
    timeout: float,
) -> SubdomainInfo | None:
    """Resuelve un único nombre de subdominio."""
    types: list[str] = []
    addresses: list[str] = []

    for rdtype in ("A", "AAAA", "CNAME"):
        try:
            records = await resolve_record(name, rdtype, nameserver, timeout)
        except Exception:  # defensivo: un fallo no detiene el resto
            continue
        if records:
            types.append(rdtype)
            for record in records:
                for value in record.values:
                    if value not in addresses:
                        addresses.append(value)

    if not types:
        return None
    return SubdomainInfo(name=name, record_types=types, addresses=addresses)


def analyze_exposure(
    domain: str,
    subdomains: list[SubdomainInfo],
    records: dict[str, list[DNSRecord]],
) -> list[Finding]:
    """Identifica información expuesta en los registros públicos.

    Args:
        domain: Dominio auditado.
        subdomains: Subdominios identificados.
        records: Registros del dominio base.

    Returns:
        Hallazgos de exposición.
    """
    findings: list[Finding] = []

    findings.extend(_check_non_production(domain, subdomains))
    findings.extend(_check_admin_services(subdomains))
    findings.extend(_check_internal_addresses(records))
    findings.extend(_check_mail_exposure(records))
    findings.extend(_check_wildcard(domain))

    return findings


def _check_non_production(domain: str, subdomains: list[SubdomainInfo]) -> list[Finding]:
    """Detecta subdominios que parecen entornos de desarrollo o pruebas."""
    found = [
        info.name
        for info in subdomains
        if info.name.split(".", 1)[0].lower() in NON_PRODUCTION_PREFIXES
    ]
    if not found:
        return []
    return [
        Finding(
            id="exposed_non_production_subdomains",
            category=Category.EXPOSURE,
            severity=Severity.INDICIO,
            title="Subdominios de entornos no productivos expuestos",
            description=(
                "Se han identificado subdominios asociados a desarrollo, pruebas o "
                "preproducción, que suelen tener controles más débiles que producción."
            ),
            evidence=", ".join(found),
            recommendation=(
                "Restringe el acceso a estos entornos o retíralos de la resolución pública."
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )
    ]


def _check_admin_services(subdomains: list[SubdomainInfo]) -> list[Finding]:
    """Detecta subdominios con servicios de administración."""
    found = [
        info.name for info in subdomains if info.name.split(".", 1)[0].lower() in ADMIN_PREFIXES
    ]
    if not found:
        return []
    return [
        Finding(
            id="exposed_administrative_subdomains",
            category=Category.EXPOSURE,
            severity=Severity.POTENCIAL,
            title="Subdominios de administración expuestos",
            description=(
                "Los nombres identificados suelen alojar paneles de administración o "
                "accesos remotos, que son objetivos habituales de ataque."
            ),
            evidence=", ".join(found),
            recommendation=(
                "Limita el acceso a estos servicios mediante red o autenticación fuerte."
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )
    ]


def _check_internal_addresses(records: dict[str, list[DNSRecord]]) -> list[Finding]:
    """Detecta direcciones IP privadas o reservadas en registros públicos."""
    leaked: list[str] = []
    for rdtype, entries in records.items():
        if rdtype not in {"A", "AAAA"}:
            continue
        for record in entries:
            for value in record.values:
                if _is_internal(value) and value not in leaked:
                    leaked.append(value)

    if not leaked:
        return []
    return [
        Finding(
            id="internal_addresses_exposed",
            category=Category.EXPOSURE,
            severity=Severity.PROBABLE,
            title="Direcciones IP internas expuestas en DNS público",
            description=(
                "Los registros DNS públicos revelan direcciones de la red interna, lo "
                "que facilita el reconocimiento de la infraestructura."
            ),
            evidence=", ".join(leaked),
            recommendation="Elimina los registros que expongan direcciones internas.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )
    ]


def _check_mail_exposure(records: dict[str, list[DNSRecord]]) -> list[Finding]:
    """Informa sobre los servidores de correo configurados."""
    mx_records = records.get("MX", [])
    if not mx_records:
        return []

    values: list[str] = []
    for record in mx_records:
        values.extend(record.values)

    return [
        Finding(
            id="mail_servers_exposed",
            category=Category.EXPOSURE,
            severity=Severity.INDICIO,
            title="Servidores de correo identificables",
            description=(
                "Los registros MX revelan los servidores de correo del dominio, lo que "
                "es información útil para dirigir ataques contra el correo."
            ),
            evidence=", ".join(values),
            recommendation=(
                "Considera servidores antiabuso y revisa la configuración SPF/DKIM/DMARC."
            ),
            references=["https://www.rfc-editor.org/rfc/rfc5321"],
        )
    ]


def _check_wildcard(domain: str) -> list[Finding]:
    """Comprueba si el dominio tiene un registro comodín activo."""
    probe = f"pydnsaudit-{_random_token()}.{domain}"
    try:
        # La comprobación se realiza de forma síncrona para mantener la firma simple.
        import asyncio

        records = asyncio.run(resolve_record(probe, "A", None, 3.0))
    except Exception:  # defensivo
        return []

    if not records:
        return []

    return [
        Finding(
            id="wildcard_dns_active",
            category=Category.EXPOSURE,
            severity=Severity.POTENCIAL,
            title="DNS comodín activo",
            description=(
                "El dominio resuelve nombres inexistentes mediante un registro comodín, "
                "lo que invalida la enumeración por resolución y puede exponer servicios."
            ),
            evidence=f"{probe} resolvió a: {', '.join(records[0].values)}",
            recommendation="Sustituye el comodín por registros explícitos.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )
    ]


def _is_internal(value: str) -> bool:
    """Indica si una dirección es privada, de bucle local o reservada."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved


def _random_token() -> str:
    """Genera un token impredecible para la sonda de comodín."""
    import secrets

    return secrets.token_hex(6)


__all__ = ["enumerate_subdomains", "analyze_exposure", "COMMON_SUBDOMAINS", "Iterable"]
