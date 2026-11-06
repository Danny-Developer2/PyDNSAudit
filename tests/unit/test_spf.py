"""Pruebas unitarias del análisis SPF."""

from __future__ import annotations

import pytest

from pydnsaudit.core.spf import _evaluate_spf, _parse_spf, analyze_spf
from pydnsaudit.models import Severity


class TestParseSPF:
    def test_spf_simple(self):
        info = _parse_spf("ejemplo.com", "v=spf1 ip4:192.0.2.1 -all")
        assert info.present is True
        assert info.all_qualifier == "-"
        assert info.lookup_count == 0

    def test_spf_permisivo(self):
        info = _parse_spf("ejemplo.com", "v=spf1 +all")
        assert info.all_qualifier == "+"

    def test_spf_neutro(self):
        info = _parse_spf("ejemplo.com", "v=spf1 ?all")
        assert info.all_qualifier == "?"

    def test_spf_fallo_suave(self):
        info = _parse_spf("ejemplo.com", "v=spf1 ~all")
        assert info.all_qualifier == "~"

    def test_spf_con_include(self):
        info = _parse_spf("ejemplo.com", "v=spf1 include:_spf.google.com -all")
        assert info.includes == ["_spf.google.com"]
        assert info.lookup_count == 1

    def test_spf_sin_all(self):
        info = _parse_spf("ejemplo.com", "v=spf1 ip4:192.0.2.1")
        assert info.all_qualifier is None


class TestEvaluateSPF:
    def test_spf_permisivo_genera_hallazgo(self, spf_permissive):
        findings = _evaluate_spf(spf_permissive)
        assert any(f.id == "spf_permissive_all" for f in findings)
        assert any(f.severity is Severity.PROBABLE for f in findings)

    def test_spf_restrictive_sin_hallazgos(self, spf_restrictive):
        assert _evaluate_spf(spf_restrictive) == []

    def test_spf_sin_all(self):
        info = _parse_spf("ejemplo.com", "v=spf1 ip4:192.0.2.1")
        findings = _evaluate_spf(info)
        assert any(f.id == "spf_without_all" for f in findings)

    def test_spf_con_muchas_consultas(self):
        raw = "v=spf1 " + " ".join(f"include:d{i}.ejemplo.com" for i in range(12)) + " -all"
        info = _parse_spf("ejemplo.com", raw)
        findings = _evaluate_spf(info)
        assert any(f.id == "spf_too_many_lookups" for f in findings)


class TestAnalyzeSPF:
    async def test_spf_presente(self):
        info, findings = await analyze_spf("example.com")
        # Sin red no se garantiza resultado; se comprueba que no se rompe.
        assert info is not None
        assert isinstance(findings, list)

    async def test_spf_con_resolver_inalcanzable(self, monkeypatch):
        async def _fail(*args, **kwargs):
            from pydnsaudit.exceptions import DNSQueryError

            raise DNSQueryError("sin red")

        monkeypatch.setattr("pydnsaudit.core.spf.resolve_record", _fail)
        info, findings = await analyze_spf("ejemplo.com")
        assert info.present is False
        assert any(f.id == "spf_missing" for f in findings)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("v=spf1 +all", "+"),
        ("v=spf1 -all", "-"),
        ("v=spf1 ~all", "~"),
        ("v=spf1 ?all", "?"),
    ],
)
def test_calificadores(raw, expected):
    assert _parse_spf("ejemplo.com", raw).all_qualifier == expected
