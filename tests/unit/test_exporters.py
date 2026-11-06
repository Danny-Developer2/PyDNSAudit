"""Pruebas unitarias de los exportadores de PyDNSAudit."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pydnsaudit.exceptions import ExportError
from pydnsaudit.export import export_result
from pydnsaudit.export.csv_export import export_csv
from pydnsaudit.export.html_export import export_html
from pydnsaudit.export.json_export import export_json
from pydnsaudit.models import (
    Category,
    DKIMInfo,
    DMARCInfo,
    DNSAuditResult,
    DNSRecord,
    Finding,
    Severity,
    SPFInfo,
    SubdomainInfo,
)


def _sample_result() -> DNSAuditResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return DNSAuditResult(
        domain="ejemplo.com",
        authorized=True,
        started_at=now,
        finished_at=now + timedelta(seconds=3),
        duration_seconds=3.0,
        nameservers=["ns1.ejemplo.com"],
        records={"A": [DNSRecord(name="ejemplo.com", type="A", values=["192.0.2.1"], ttl=300)]},
        spf=SPFInfo(domain="ejemplo.com", present=True, raw="v=spf1 -all", all_qualifier="-"),
        dmarc=DMARCInfo(
            domain="ejemplo.com", present=True, raw="v=DMARC1; p=reject", policy="reject"
        ),
        dkim=[DKIMInfo(domain="ejemplo.com", selector="mail", present=True, key_type="rsa")],
        subdomains=[
            SubdomainInfo(name="www.ejemplo.com", record_types=["A"], addresses=["192.0.2.1"])
        ],
        findings=[
            Finding(
                id="ejemplo_1",
                category=Category.SPF,
                severity=Severity.PROBABLE,
                title="SPF permisivo",
                description="Descripción de ejemplo",
                evidence="v=spf1 +all",
                recommendation="Usa -all.",
                references=["https://ejemplo.test/ref"],
            )
        ],
        statistics={
            "confirmado": 0,
            "probable": 1,
            "potencial": 0,
            "indicio": 0,
            "recomendacion": 0,
        },
    )


class TestJsonExport:
    def test_genera_json_valido(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "resultado.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "PyDNSAudit"
        assert data["schema"] == "pydnsaudit/audit-result"
        assert data["findings"][0]["id"] == "ejemplo_1"

    def test_incluye_spf_y_dmarc(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "resultado.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["spf"]["raw"] == "v=spf1 -all"
        assert data["dmarc"]["policy"] == "reject"


class TestCsvExport:
    def test_una_fila_por_hallazgo(self, tmp_path: Path):
        path = export_csv(_sample_result(), tmp_path / "resultado.csv")
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == 1
        assert rows[0]["severidad"] == "probable"
        assert rows[0]["dominio"] == "ejemplo.com"


class TestHtmlExport:
    def test_genera_html_completo(self, tmp_path: Path):
        path = export_html(_sample_result(), tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "Informe de auditoría DNS" in html
        assert "SPF permisivo" in html
        assert "v=spf1 -all" in html
        assert "www.ejemplo.com" in html

    def test_escapa_contenido_malicioso(self, tmp_path: Path):
        result = _sample_result()
        original = result.findings[0]
        result.findings[0] = Finding(
            id=original.id,
            category=original.category,
            severity=original.severity,
            title=original.title,
            description="<script>alert(1)</script>",
            evidence=original.evidence,
            recommendation=original.recommendation,
            references=original.references,
        )
        path = export_html(result, tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestExportResult:
    @pytest.mark.parametrize("fmt", ["json", "csv", "html"])
    def test_formatos_soportados(self, tmp_path: Path, fmt: str):
        written = export_result(_sample_result(), tmp_path / "salida", fmt)
        assert written.exists()
        assert written.suffix == f".{fmt}"

    def test_formato_no_soportado(self, tmp_path: Path):
        with pytest.raises(ExportError):
            export_result(_sample_result(), tmp_path / "salida", "pdf")
