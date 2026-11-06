"""Configuración común de las pruebas de PyDNSAudit.

Las pruebas unitarias no requieren red: se prueban los analizadores con datos
sintéticos. Las de integración usan el resolvedor del sistema, que en el entorno
de CI puede no estar disponible, por lo que se comprueba de forma tolerante.
"""

from __future__ import annotations

import pytest

from pydnsaudit.models import DNSRecord, SPFInfo


@pytest.fixture()
def spf_permissive() -> SPFInfo:
    """Política SPF muy permisiva."""
    return SPFInfo(
        domain="ejemplo.com",
        present=True,
        raw="v=spf1 +all",
        mechanisms=["+all"],
        all_qualifier="+",
        lookup_count=0,
    )


@pytest.fixture()
def spf_restrictive() -> SPFInfo:
    """Política SPF correcta."""
    return SPFInfo(
        domain="ejemplo.com",
        present=True,
        raw="v=spf1 ip4:192.0.2.0/24 -all",
        mechanisms=["ip4:192.0.2.0/24", "-all"],
        all_qualifier="-",
        lookup_count=0,
    )


@pytest.fixture()
def txt_records() -> list[DNSRecord]:
    """Registros TXT de ejemplo."""
    return [
        DNSRecord(
            name="ejemplo.com",
            type="TXT",
            values=["v=spf1 ip4:192.0.2.0/24 -all"],
            ttl=300,
        )
    ]


@pytest.fixture()
def dmarc_records() -> list[DNSRecord]:
    """Registros TXT de DMARC de ejemplo."""
    return [
        DNSRecord(
            name="_dmarc.ejemplo.com",
            type="TXT",
            values=["v=DMARC1; p=reject; rua=mailto:dmarc@ejemplo.com"],
            ttl=300,
        )
    ]
