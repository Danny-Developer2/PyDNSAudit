"""Pruebas unitarias de validadores y control de autorización."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pydnsaudit.exceptions import AuthorizationError, ScopeError, ValidationError
from pydnsaudit.models import Scope
from pydnsaudit.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    is_target_in_scope,
    load_scope_file,
    validate_target,
)


class TestValidateTarget:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("ejemplo.com", "ejemplo.com"),
            ("  EJEMPLO.COM.  ", "ejemplo.com"),
            ("https://ejemplo.com/ruta", "ejemplo.com"),
            ("ejemplo.com:8443", "ejemplo.com"),
            ("sub.ejemplo.com", "sub.ejemplo.com"),
        ],
    )
    def test_dominios_validos(self, value, expected):
        assert validate_target(value) == expected

    @pytest.mark.parametrize("value", ["", "   ", "no valido", "-ejemplo.com", "ejemplo..com"])
    def test_dominios_invalidos(self, value):
        with pytest.raises(ValidationError):
            validate_target(value)


class TestScope:
    @pytest.fixture()
    def scope(self) -> Scope:
        return Scope(name="Lab", authorized_targets=["ejemplo.com"])

    def test_dominio_exacto(self, scope):
        assert is_target_in_scope("ejemplo.com", scope)

    def test_subdominio_dentro_del_scope(self, scope):
        assert is_target_in_scope("sub.ejemplo.com", scope)

    def test_otro_dominio_fuera(self, scope):
        assert not is_target_in_scope("otro.com", scope)

    def test_prefijo_parecido_fuera(self, scope):
        assert not is_target_in_scope("ejemplo.com.evil.net", scope)


class TestEnsureAuthorized:
    def test_sin_scope_ni_confirmacion(self):
        with pytest.raises(AuthorizationError):
            ensure_authorized("ejemplo.com", None, False)

    def test_confirmacion_directa(self):
        ensure_authorized("ejemplo.com", None, True)

    def test_fuera_de_alcance(self):
        scope = Scope(name="Lab", authorized_targets=["otro.com"])
        with pytest.raises(ValidationError):
            ensure_authorized("ejemplo.com", scope, True)


class TestLoadScopeFile:
    def test_scope_valido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(
            json.dumps({"name": "Lab", "authorized_targets": ["ejemplo.com"]}),
            encoding="utf-8",
        )
        scope = load_scope_file(path)
        assert scope is not None
        assert scope.name == "Lab"

    def test_sin_fichero_devuelve_none(self):
        assert load_scope_file(None) is None

    def test_scope_invalido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text("{ no valido", encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope_file(path)

    def test_scope_sin_authorized_targets(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(json.dumps({"name": "Lab"}), encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope_file(path)


class TestEnsurePathWritable:
    def test_ruta_valida(self, tmp_path: Path):
        ensure_path_writable(tmp_path / "salida.json")

    def test_carpeta_como_fichero(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            ensure_path_writable(tmp_path)

    def test_directorio_inexistente(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            ensure_path_writable(tmp_path / "inexistente" / "salida.json")
