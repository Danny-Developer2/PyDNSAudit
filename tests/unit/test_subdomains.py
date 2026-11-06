"""Pruebas unitarias de la enumeración de subdominios y la exposición."""

from __future__ import annotations

from pydnsaudit.core.subdomains import (
    _check_internal_addresses,
    _check_non_production,
    _is_internal,
    analyze_exposure,
)
from pydnsaudit.models import DNSRecord, Severity, SubdomainInfo


def _subdomain(name: str) -> SubdomainInfo:
    return SubdomainInfo(name=name, record_types=["A"], addresses=["192.0.2.1"])


class TestInternalAddresses:
    def test_ip_privada(self):
        assert _is_internal("10.0.0.1") is True
        assert _is_internal("192.168.1.1") is True
        assert _is_internal("172.16.0.1") is True

    def test_ip_publica(self):
        assert _is_internal("8.8.8.8") is False

    def test_ip_de_bucle(self):
        assert _is_internal("127.0.0.1") is True

    def test_valor_no_ip(self):
        assert _is_internal("ejemplo.com") is False


class TestNonProduction:
    def test_detecta_entornos(self):
        findings = _check_non_production(
            "ejemplo.com", [_subdomain("dev.ejemplo.com"), _subdomain("www.ejemplo.com")]
        )
        assert len(findings) == 1
        assert findings[0].severity is Severity.INDICIO

    def test_sin_entornos(self):
        assert _check_non_production("ejemplo.com", [_subdomain("www.ejemplo.com")]) == []


class TestExposure:
    def test_sin_datos(self):
        assert analyze_exposure("ejemplo.com", [], {}) == []

    def test_ip_interna_en_registros(self):
        records = {"A": [DNSRecord(name="ejemplo.com", type="A", values=["10.1.2.3"])]}
        findings = _check_internal_addresses(records)
        assert findings
        assert findings[0].severity is Severity.PROBABLE

    def test_sin_ip_interna(self):
        records = {"A": [DNSRecord(name="ejemplo.com", type="A", values=["8.8.8.8"])]}
        assert _check_internal_addresses(records) == []

    def test_subdominios_administrativos(self):
        findings = analyze_exposure("ejemplo.com", [_subdomain("admin.ejemplo.com")], {})
        assert any(f.id == "exposed_administrative_subdomains" for f in findings)

    def test_registros_vacios(self):
        assert analyze_exposure("ejemplo.com", [], {"A": []}) == []
