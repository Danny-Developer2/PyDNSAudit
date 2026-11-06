"""Pruebas unitarias de las utilidades de dominio."""

from __future__ import annotations

import pytest

from pydnsaudit.exceptions import ValidationError
from pydnsaudit.utils.domain import (
    build_fqdn,
    is_domain,
    is_ip_address,
    parent_domain,
    strip_wildcard,
    validate_domain,
)


class TestValidateDomain:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("ejemplo.com", "ejemplo.com"),
            ("EJEMPLO.COM", "ejemplo.com"),
            ("ejemplo.com.", "ejemplo.com"),
            ("https://ejemplo.com/", "ejemplo.com"),
        ],
    )
    def test_validos(self, value, expected):
        assert validate_domain(value).name == expected

    @pytest.mark.parametrize("value", ["", "no valido", "ejemplo..com", "-a.com"])
    def test_invalidos(self, value):
        with pytest.raises(ValidationError):
            validate_domain(value)


class TestHelpers:
    def test_is_domain(self):
        assert is_domain("ejemplo.com") is True
        assert is_domain("no valido") is False

    def test_is_ip_address(self):
        assert is_ip_address("127.0.0.1") is True
        assert is_ip_address("ejemplo.com") is False

    def test_parent_domain(self):
        assert parent_domain("www.ejemplo.com") == "ejemplo.com"
        assert parent_domain("ejemplo.com") == "ejemplo.com"

    def test_build_fqdn(self):
        assert build_fqdn("www", "ejemplo.com") == "www.ejemplo.com"
        assert build_fqdn("", "ejemplo.com") == "ejemplo.com"

    def test_strip_wildcard(self):
        assert strip_wildcard("*.ejemplo.com") == "ejemplo.com"
        assert strip_wildcard("ejemplo.com") == "ejemplo.com"
