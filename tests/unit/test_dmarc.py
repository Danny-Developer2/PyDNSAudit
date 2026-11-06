"""Pruebas unitarias del análisis DMARC."""

from __future__ import annotations

from pydnsaudit.core.dmarc import _evaluate_dmarc, _parse_dmarc
from pydnsaudit.models import DMARCInfo, Severity


class TestParseDMARC:
    def test_dmarc_completo(self):
        raw = "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:a@ejemplo.com"
        info = _parse_dmarc("ejemplo.com", raw)
        assert info.present is True
        assert info.policy == "reject"
        assert info.subdomain_policy == "quarantine"
        assert info.percentage == 100
        assert info.aggregate_reports == ["mailto:a@ejemplo.com"]

    def test_dmarc_minimo(self):
        info = _parse_dmarc("ejemplo.com", "v=DMARC1; p=none")
        assert info.policy == "none"
        assert info.percentage is None
        assert info.subdomain_policy is None

    def test_dmarc_pct_no_numerico(self):
        info = _parse_dmarc("ejemplo.com", "v=DMARC1; p=reject; pct=abc")
        assert info.percentage is None

    def test_dmarc_varias_direcciones(self):
        raw = "v=DMARC1; p=reject; rua=mailto:a@ejemplo.com,mailto:b@ejemplo.com"
        info = _parse_dmarc("ejemplo.com", raw)
        assert len(info.aggregate_reports) == 2


class TestEvaluateDMARC:
    def _info(self, **kwargs) -> DMARCInfo:
        base = {"domain": "ejemplo.com", "present": True, "raw": "v=DMARC1; p=reject"}
        base.update(kwargs)
        return DMARCInfo(**base)

    def test_politica_reject_sin_hallazgos(self):
        info = self._info(
            policy="reject",
            subdomain_policy="reject",
            percentage=100,
            aggregate_reports=["mailto:a@ejemplo.com"],
        )
        assert _evaluate_dmarc(info) == []

    def test_politica_none(self):
        findings = _evaluate_dmarc(self._info(policy="none"))
        assert any(f.id == "dmarc_policy_none" for f in findings)

    def test_sin_etiqueta_p(self):
        findings = _evaluate_dmarc(self._info(p=None))
        assert any(f.id == "dmarc_policy_missing" for f in findings)

    def test_subdominios_sin_proteccion(self):
        findings = _evaluate_dmarc(self._info(policy="quarantine", subdomain_policy=None))
        assert any(f.id == "dmarc_subdomain_policy" for f in findings)

    def test_porcentaje_parcial(self):
        findings = _evaluate_dmarc(
            self._info(policy="reject", subdomain_policy="reject", percentage=50)
        )
        assert any(f.id == "dmarc_partial_percentage" for f in findings)

    def test_sin_informes(self):
        findings = _evaluate_dmarc(self._info(policy="reject", subdomain_policy="reject"))
        assert any(f.id == "dmarc_without_reports" for f in findings)
        assert all(f.severity is not Severity.CONFIRMADO for f in findings)
