"""Resolución DNS asíncrona con dnspython."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from pydnsaudit.exceptions import DNSQueryError
from pydnsaudit.models import DNSRecord
from pydnsaudit.utils.domain import validate_domain
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.resolver")


async def resolve_record(
    domain: str,
    rdtype: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> list[DNSRecord]:
    """Resuelve un único tipo de registro.

    Args:
        domain: Nombre de dominio a consultar.
        rdtype: Tipo de registro (A, AAAA, MX, ...).
        nameserver: Resolver concreto o ``None`` para el del sistema.
        timeout: Tiempo de espera por consulta.

    Returns:
        Registros encontrados (lista vacía si no existen).

    Raises:
        DNSQueryError: Si la consulta falla de forma no recuperable.
    """
    name = validate_domain(domain).name
    record_type = dns.rdatatype.from_text(rdtype)

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    if nameserver:
        resolver.nameservers = [nameserver]

    try:
        answer = await resolver.resolve(name, record_type)
    except dns.resolver.NXDOMAIN:
        _logger.debug("el dominio %s no existe", name)
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NoNameservers as exc:
        raise DNSQueryError(f"no hay servidores DNS disponibles: {exc}") from exc
    except dns.exception.Timeout as exc:
        raise DNSQueryError(f"tiempo de espera agotado consultando {rdtype} de {name}") from exc
    except dns.exception.DNSException as exc:
        raise DNSQueryError(f"error al consultar {rdtype} de {name}: {exc}") from exc

    return _to_records(answer, name, rdtype)


async def resolve_many(
    domain: str,
    rdtpyes: Iterable[str],
    nameserver: str | None = None,
    timeout: float = 5.0,
    concurrency: int = 10,
) -> dict[str, list[DNSRecord]]:
    """Resuelve varios tipos de registro de forma concurrente.

    Los fallos de un tipo no impiden resolver los demás.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _guarded(rdtype: str) -> tuple[str, list[DNSRecord]]:
        async with semaphore:
            try:
                records = await resolve_record(domain, rdtype, nameserver, timeout)
            except DNSQueryError as exc:
                _logger.debug("no se pudo resolver %s de %s: %s", rdtype, domain, exc)
                return rdtype, []
            return rdtype, records

    results = await asyncio.gather(*(_guarded(rdtype) for rdtype in rdtpyes))
    return dict(results)


def _to_records(answer: dns.resolver.Answer, name: str, rdtype: str) -> list[DNSRecord]:
    """Convierte una respuesta DNS en modelos de la aplicación."""
    ttl = getattr(answer, "ttl", None)
    values: list[str] = []
    for entry in answer:
        values.append(_format_value(rdtype, entry))
    if not values:
        return []
    return [DNSRecord(name=name, type=rdtype, values=values, ttl=ttl)]


def _format_value(rdtype: str, entry: Any) -> str:
    """Serializa el valor de un registro de forma legible."""
    if rdtype == "MX":
        preference = getattr(entry, "preference", 0)
        exchange = getattr(entry, "exchange", entry)
        return f"{preference} {str(exchange).rstrip('.')}"
    if rdtype == "SOA":
        return (
            f"{str(entry.mname).rstrip('.')} {str(entry.rname).rstrip('.')} "
            f"{entry.serial} {entry.refresh} {entry.retry} {entry.expire} {entry.minimum}"
        )
    if rdtype == "SRV":
        return f"{entry.priority} {entry.weight} {entry.port} {str(entry.target).rstrip('.')}"
    return str(entry).strip('"')


async def resolve_nameservers(
    domain: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> list[str]:
    """Devuelve los servidores de nombres autoritativos del dominio."""
    try:
        records = await resolve_record(domain, "NS", nameserver, timeout)
    except DNSQueryError:
        return []
    servers: list[str] = []
    for record in records:
        for value in record.values:
            if value not in servers:
                servers.append(value)
    return servers


async def resolve_address(
    name: str, nameserver: str | None = None, timeout: float = 5.0
) -> list[str]:
    """Resuelve un nombre a direcciones IPv4 e IPv6."""
    addresses: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            records = await resolve_record(name, rdtype, nameserver, timeout)
        except DNSQueryError:
            continue
        for record in records:
            for value in record.values:
                if value not in addresses:
                    addresses.append(value)
    return addresses


__all__ = [
    "resolve_address",
    "resolve_many",
    "resolve_nameservers",
    "resolve_record",
]
