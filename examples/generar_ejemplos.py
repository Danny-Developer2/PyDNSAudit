"""Genera informes de ejemplo de PyDNSAudit con datos simulados.

Utiliza un resolvedor sintético para que el ejemplo sea reproducible sin
necesidad de red ni de un dominio real, y exporta los informes en JSON, CSV y
HTML dentro de ``examples/``.

Uso:
    python examples/generar_ejemplos.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Añade el directorio src al path cuando se ejecuta desde el repositorio.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pydnsaudit import core  # noqa: E402
from pydnsaudit.config import AuditConfig  # noqa: E402
from pydnsaudit.core.auditor import Auditor  # noqa: E402
from pydnsaudit.export import export_result  # noqa: E402
from pydnsaudit.models import DNSRecord  # noqa: E402

DESTINO = ROOT / "examples"
DOMAIN = "ejemplo.com"

# Datos DNS simulados que imitan un dominio con configuraciones mejorables.
SYNTHETIC_ZONE: dict[str, list[DNSRecord]] = {
    "A": [DNSRecord(name=DOMAIN, type="A", values=["203.0.113.10"], ttl=300)],
    "AAAA": [DNSRecord(name=DOMAIN, type="AAAA", values=["2001:db8::10"], ttl=300)],
    "MX": [DNSRecord(name=DOMAIN, type="MX", values=["10 mail.ejemplo.com"], ttl=300)],
    "NS": [
        DNSRecord(name=DOMAIN, type="NS", values=["ns1.ejemplo.com", "ns2.ejemplo.com"], ttl=3600)
    ],
    "TXT": [
        DNSRecord(
            name=DOMAIN,
            type="TXT",
            values=["v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all"],
            ttl=300,
        )
    ],
    "CNAME": [DNSRecord(name="www.ejemplo.com", type="CNAME", values=[DOMAIN], ttl=300)],
    "SOA": [
        DNSRecord(
            name=DOMAIN,
            type="SOA",
            values=["ns1.ejemplo.com admin.ejemplo.com 2024010101 7200 3600 1209600 3600"],
            ttl=3600,
        )
    ],
}


def _install_synthetic_resolver() -> None:
    """Sustituye la resolución DNS por los datos sintéticos."""

    async def _resolve_record(domain: str, rdtype: str, *args, **kwargs):
        if rdtype == "TXT" and domain.startswith("_dmarc."):
            return [
                DNSRecord(
                    name=domain,
                    type="TXT",
                    values=["v=DMARC1; p=none; rua=mailto:dmarc@ejemplo.com"],
                    ttl=300,
                )
            ]
        if rdtype == "TXT" and "._domainkey." in domain:
            return [
                DNSRecord(
                    name=domain,
                    type="TXT",
                    values=["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"],
                    ttl=300,
                )
            ]
        if rdtype == "TXT" and domain == DOMAIN:
            return SYNTHETIC_ZONE.get("TXT", [])
        if domain.startswith("dev.") or domain.startswith("staging."):
            return [DNSRecord(name=domain, type="A", values=["10.10.0.5"], ttl=300)]
        if domain.startswith("admin."):
            return [DNSRecord(name=domain, type="A", values=["203.0.113.20"], ttl=300)]
        return SYNTHETIC_ZONE.get(rdtype, [])

    async def _resolve_many(domain: str, rdtpyes, *args, **kwargs):
        return {rdtype: await _resolve_record(domain, rdtype) for rdtype in rdtpyes}

    async def _resolve_nameservers(domain: str, *args, **kwargs):
        return ["ns1.ejemplo.com", "ns2.ejemplo.com"]

    for module in (
        core.resolver,
        core.spf,
        core.dmarc,
        core.dkim,
        core.subdomains,
        core.auditor,
    ):
        if hasattr(module, "resolve_record"):
            module.resolve_record = _resolve_record  # type: ignore[attr-defined]
        if hasattr(module, "resolve_many"):
            module.resolve_many = _resolve_many  # type: ignore[attr-defined]
        if hasattr(module, "resolve_nameservers"):
            module.resolve_nameservers = _resolve_nameservers  # type: ignore[attr-defined]


async def main() -> int:
    """Ejecuta la auditoría de ejemplo y escribe los informes."""
    _install_synthetic_resolver()

    config = AuditConfig(domain=DOMAIN, confirm_authorized=True)
    result = await Auditor(config).run()

    DESTINO.mkdir(parents=True, exist_ok=True)
    for fmt in ("json", "csv", "html"):
        written = export_result(result, DESTINO / "informe-ejemplo", fmt)
        print(f"  {fmt.upper():4} -> {written.relative_to(ROOT)}")

    print(
        f"\nAuditoría completada: {len(result.findings)} hallazgos "
        f"en {result.duration_seconds:.2f} s"
    )
    if result.spf:
        print(f"SPF: {result.spf.raw or 'ausente'}")
    if result.dmarc:
        print(f"DMARC: {result.dmarc.raw or 'ausente'}")
    print(f"Subdominios identificados: {len(result.subdomains)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
