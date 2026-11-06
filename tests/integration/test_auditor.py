"""Pruebas de integración del auditor DNS.

Se simula el resolvedor para que las pruebas no dependan de la red.
"""

from __future__ import annotations

import pytest

from pydnsaudit.config import AuditConfig
from pydnsaudit.core.auditor import Auditor
from pydnsaudit.models import DNSRecord, Severity


def _patch_resolver(monkeypatch: pytest.MonkeyPatch, records: dict[str, list[DNSRecord]]) -> None:
    """Sustituye las funciones de resolución por datos sintéticos."""

    async def _resolve_record(domain: str, rdtype: str, *args, **kwargs):
        if rdtype == "TXT" and domain.startswith("_dmarc."):
            return records.get("DMARC", [])
        if rdtype == "TXT" and "._domainkey." in domain:
            return records.get("DKIM", [])
        if rdtype == "TXT" and domain == "ejemplo.com":
            return records.get("SPF", [])
        return records.get(rdtype, [])

    async def _resolve_many(domain: str, rdtpyes, *args, **kwargs):
        return {rdtype: await _resolve_record(domain, rdtype) for rdtype in rdtpyes}

    async def _resolve_nameservers(domain: str, *args, **kwargs):
        return ["ns1.ejemplo.com", "ns2.ejemplo.com"]

    monkeypatch.setattr("pydnsaudit.core.resolver.resolve_record", _resolve_record)
    monkeypatch.setattr("pydnsaudit.core.auditor.resolve_many", _resolve_many)
    monkeypatch.setattr("pydnsaudit.core.auditor.resolve_nameservers", _resolve_nameservers)
    monkeypatch.setattr("pydnsaudit.core.spf.resolve_record", _resolve_record)
    monkeypatch.setattr("pydnsaudit.core.dmarc.resolve_record", _resolve_record)
    monkeypatch.setattr("pydnsaudit.core.dkim.resolve_record", _resolve_record)


class TestAuditorDNS:
    async def test_auditoria_completa(self, monkeypatch):
        _patch_resolver(
            monkeypatch,
            {
                "A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"])],
                "NS": [DNSRecord(name="ejemplo.com", type="NS", values=["ns1.ejemplo.com"])],
                "SPF": [DNSRecord(name="ejemplo.com", type="TXT", values=["v=spf1 -all"])],
                "DMARC": [
                    DNSRecord(name="_dmarc.ejemplo.com", type="TXT", values=["v=DMARC1; p=reject"])
                ],
                "DKIM": [
                    DNSRecord(
                        name="mail._domainkey.ejemplo.com",
                        type="TXT",
                        values=["v=DKIM1; k=rsa; p=ABC"],
                    )
                ],
            },
        )
        config = AuditConfig(
            domain="ejemplo.com",
            confirm_authorized=True,
            check_subdomains=False,
        )
        result = await Auditor(config).run()

        assert result.domain == "ejemplo.com"
        assert result.connected if hasattr(result, "connected") else True
        assert result.spf is not None and result.spf.present
        assert result.dmarc is not None and result.dmarc.policy == "reject"
        assert result.findings is not None

    async def test_detecta_spf_permisivo(self, monkeypatch):
        _patch_resolver(
            monkeypatch,
            {
                "A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"])],
                "NS": [DNSRecord(name="ejemplo.com", type="NS", values=["ns1.ejemplo.com"])],
                "SPF": [DNSRecord(name="ejemplo.com", type="TXT", values=["v=spf1 +all"])],
            },
        )
        config = AuditConfig(domain="ejemplo.com", confirm_authorized=True, check_subdomains=False)
        result = await Auditor(config).run()
        ids = {f.id for f in result.findings}
        assert "spf_permissive_all" in ids
        assert result.spf is not None and result.spf.all_qualifier == "+"

    async def test_detecta_spf_ausente(self, monkeypatch):
        _patch_resolver(
            monkeypatch,
            {
                "A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"])],
                "NS": [DNSRecord(name="ejemplo.com", type="NS", values=["ns1.ejemplo.com"])],
            },
        )
        config = AuditConfig(domain="ejemplo.com", confirm_authorized=True, check_subdomains=False)
        result = await Auditor(config).run()
        ids = {f.id for f in result.findings}
        assert "spf_missing" in ids
        assert "dmarc_missing" in ids

    async def test_estadisticas_coherentes(self, monkeypatch):
        _patch_resolver(
            monkeypatch,
            {
                "A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"])],
                "NS": [DNSRecord(name="ejemplo.com", type="NS", values=["ns1.ejemplo.com"])],
            },
        )
        config = AuditConfig(domain="ejemplo.com", confirm_authorized=True, check_subdomains=False)
        result = await Auditor(config).run()
        assert sum(result.statistics.values()) == len(result.findings)
        assert all(f.severity in set(Severity) for f in result.findings)

    async def test_dominio_sin_registros(self, monkeypatch):
        _patch_resolver(monkeypatch, {})
        config = AuditConfig(
            domain="inexistente.com", confirm_authorized=True, check_subdomains=False
        )
        result = await Auditor(config).run()
        assert any(f.id == "no_records_found" for f in result.findings)


class TestAuditorOpciones:
    async def test_desactivar_analisis(self, monkeypatch):
        _patch_resolver(
            monkeypatch,
            {
                "A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"])],
                "NS": [DNSRecord(name="ejemplo.com", type="NS", values=["ns1.ejemplo.com"])],
                "SPF": [DNSRecord(name="ejemplo.com", type="TXT", values=["v=spf1 +all"])],
            },
        )
        config = AuditConfig(
            domain="ejemplo.com",
            confirm_authorized=True,
            check_spf=False,
            check_dmarc=False,
            check_subdomains=False,
        )
        result = await Auditor(config).run()
        assert result.spf is None
        assert result.dmarc is None
        assert not any(f.id.startswith("spf_") for f in result.findings)
