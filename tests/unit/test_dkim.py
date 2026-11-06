"""Pruebas unitarias del análisis DKIM."""

from __future__ import annotations

import base64

from pydnsaudit.core.dkim import _evaluate_dkim, _key_size, _parse_dkim
from pydnsaudit.models import DKIMInfo


def _key(bits: int) -> str:
    """Genera una clave ficticia de la longitud indicada, en base64."""
    return base64.b64encode(b"\x30" * (bits // 8)).decode()


class TestParseDKIM:
    def test_dkim_completo(self):
        raw = f"v=DKIM1; k=rsa; p={_key(2048)}"
        info = _parse_dkim("ejemplo.com", "selector1", raw)
        assert info.present is True
        assert info.key_type == "rsa"
        assert info.key_size is not None

    def test_dkim_sin_clave(self):
        info = _parse_dkim("ejemplo.com", "selector1", "v=DKIM1; k=rsa; p=")
        assert info.key_size is None

    def test_dkim_etiquetas(self):
        info = _parse_dkim("ejemplo.com", "mail", "v=DKIM1; k=ed25519; p=ABC")
        assert info.key_type == "ed25519"


class TestKeySize:
    def test_clave_vacia(self):
        assert _key_size(None) is None
        assert _key_size("") is None

    def test_clave_valida(self):
        assert _key_size(_key(2048)) is not None

    def test_clave_invalida(self):
        assert _key_size("!!!no-base64!!!") is None


class TestEvaluateDKIM:
    def test_dkim_correcto_sin_hallazgos(self):
        info = DKIMInfo(
            domain="ejemplo.com",
            selector="selector1",
            present=True,
            raw=f"v=DKIM1; k=rsa; p={_key(2048)}",
            key_type="rsa",
            key_size=2048,
        )
        assert _evaluate_dkim(info) == []

    def test_clave_vacia(self):
        info = DKIMInfo(
            domain="ejemplo.com",
            selector="selector1",
            present=True,
            raw="v=DKIM1; k=rsa; p=",
            key_type="rsa",
            key_size=None,
        )
        findings = _evaluate_dkim(info)
        assert any(f.id == "dkim_empty_key_selector1" for f in findings)

    def test_tipo_de_clave_inusual(self):
        info = DKIMInfo(
            domain="ejemplo.com",
            selector="selector1",
            present=True,
            raw=f"v=DKIM1; k=dsa; p={_key(2048)}",
            key_type="dsa",
            key_size=2048,
        )
        assert any(f.id == "dkim_unusual_key_type_selector1" for f in _evaluate_dkim(info))

    def test_clave_corta(self):
        info = DKIMInfo(
            domain="ejemplo.com",
            selector="selector1",
            present=True,
            raw=f"v=DKIM1; k=rsa; p={_key(512)}",
            key_type="rsa",
            key_size=512,
        )
        assert any(f.id == "dkim_short_key_selector1" for f in _evaluate_dkim(info))
