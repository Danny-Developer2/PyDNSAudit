"""Pruebas de integración de la interfaz de línea de comandos."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pydnsaudit.cli import app

runner = CliRunner()


class TestComandoVersion:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "PyDNSAudit" in result.output


class TestControlAutorizacion:
    def test_sin_autorizacion_sale_con_error(self):
        result = runner.invoke(app, ["scan", "ejemplo.com"])
        assert result.exit_code == 2

    def test_dominio_invalido(self):
        result = runner.invoke(app, ["scan", "no valido", "--confirm-authorized"])
        assert result.exit_code == 2


class TestComandoScan:
    def test_scan_json(self, monkeypatch, tmp_path: Path):
        async def _resolve_record(domain, rdtype, *args, **kwargs):
            from pydnsaudit.models import DNSRecord

            if rdtype == "TXT":
                return [DNSRecord(name=domain, type="TXT", values=["v=spf1 -all"])]
            if rdtype == "NS":
                return [DNSRecord(name=domain, type="NS", values=["ns1.ejemplo.com"])]
            return []

        async def _resolve_many(domain, rdtpyes, *args, **kwargs):
            return {rdtype: await _resolve_record(domain, rdtype) for rdtype in rdtpyes}

        async def _resolve_nameservers(domain, *args, **kwargs):
            return ["ns1.ejemplo.com"]

        monkeypatch.setattr("pydnsaudit.core.resolver.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_many", _resolve_many)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_nameservers", _resolve_nameservers)
        monkeypatch.setattr("pydnsaudit.core.spf.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dmarc.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dkim.resolve_record", _resolve_record)

        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "ejemplo.com",
                "--confirm-authorized",
                "--no-subdomains",
                "--output",
                str(salida),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        datos = json.loads((tmp_path / "informe.json").read_text(encoding="utf-8"))
        assert datos["schema"] == "pydnsaudit/audit-result"
        assert datos["domain"] == "ejemplo.com"

    def test_scan_html(self, monkeypatch, tmp_path: Path):
        async def _resolve_record(domain, rdtype, *args, **kwargs):
            from pydnsaudit.models import DNSRecord

            if rdtype == "TXT":
                return [DNSRecord(name=domain, type="TXT", values=["v=spf1 -all"])]
            if rdtype == "NS":
                return [DNSRecord(name=domain, type="NS", values=["ns1.ejemplo.com"])]
            return []

        async def _resolve_many(domain, rdtpyes, *args, **kwargs):
            return {rdtype: await _resolve_record(domain, rdtype) for rdtype in rdtpyes}

        async def _resolve_nameservers(domain, *args, **kwargs):
            return ["ns1.ejemplo.com"]

        monkeypatch.setattr("pydnsaudit.core.resolver.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_many", _resolve_many)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_nameservers", _resolve_nameservers)
        monkeypatch.setattr("pydnsaudit.core.spf.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dmarc.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dkim.resolve_record", _resolve_record)

        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "ejemplo.com",
                "--confirm-authorized",
                "--no-subdomains",
                "--output",
                str(salida),
                "--format",
                "html",
            ],
        )
        assert result.exit_code == 0, result.output
        html = (tmp_path / "informe.html").read_text(encoding="utf-8")
        assert "Informe de auditoría DNS" in html

    def test_scan_con_scope_fuera_de_alcance(self, tmp_path: Path):
        scope = tmp_path / "scope.json"
        scope.write_text(
            json.dumps({"name": "Otro", "authorized_targets": ["otro.com"]}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["scan", "ejemplo.com", "--scope", str(scope)],
        )
        assert result.exit_code == 2

    def test_scan_csv(self, monkeypatch, tmp_path: Path):
        async def _resolve_record(domain, rdtype, *args, **kwargs):
            return []

        async def _resolve_many(domain, rdtpyes, *args, **kwargs):
            return {rdtype: [] for rdtype in rdtpyes}

        async def _resolve_nameservers(domain, *args, **kwargs):
            return []

        monkeypatch.setattr("pydnsaudit.core.resolver.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_many", _resolve_many)
        monkeypatch.setattr("pydnsaudit.core.auditor.resolve_nameservers", _resolve_nameservers)
        monkeypatch.setattr("pydnsaudit.core.spf.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dmarc.resolve_record", _resolve_record)
        monkeypatch.setattr("pydnsaudit.core.dkim.resolve_record", _resolve_record)

        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "ejemplo.com",
                "--confirm-authorized",
                "--no-subdomains",
                "--output",
                str(salida),
                "--format",
                "csv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "informe.csv").exists()
