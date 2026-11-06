"""Excepciones propias de PyDNSAudit."""

from __future__ import annotations


class PyDNSAuditError(Exception):
    """Excepción base de PyDNSAudit."""


class ValidationError(PyDNSAuditError):
    """Entrada no válida (dominio, selector o parámetro incorrecto)."""


class AuthorizationError(PyDNSAuditError):
    """El dominio no está dentro del alcance autorizado."""


class ScopeError(PyDNSAuditError):
    """El fichero de alcance está ausente o es incorrecto."""


class DNSQueryError(PyDNSAuditError):
    """No se pudo completar la consulta DNS."""


class ExportError(PyDNSAuditError):
    """No se pudo escribir el informe."""
