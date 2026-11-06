"""Configuración de PyDNSAudit y catálogos de trabajo."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydnsaudit.models import Scope

# Tipos de registro que se enumeran de forma predeterminada.
DEFAULT_RECORD_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
)

# Selectores DKIM habituales que se prueban cuando no se indica uno concreto.
COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "smtp",
    "dkim",
    "mimecast",
    "zoho",
)

# Subdominios habituales para la enumeración pasiva local.
COMMON_SUBDOMAINS: tuple[str, ...] = (
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "ns1",
    "ns2",
    "mx",
    "mx1",
    "mx2",
    "email",
    "remote",
    "blog",
    "wiki",
    "portal",
    "vpn",
    "api",
    "dev",
    "test",
    "stage",
    "staging",
    "demo",
    "admin",
    "secure",
    "app",
    "cloud",
    "cdn",
    "static",
    "assets",
    "docs",
    "support",
    "help",
    "news",
    "status",
    "monitor",
    "git",
    "gitlab",
    "github",
    "jenkins",
    "jira",
    "confluence",
    "crm",
    "erp",
    "intranet",
    "extranet",
    "partners",
    "shop",
    "store",
    "pay",
    "billing",
    "auth",
    "login",
    "sso",
    "owa",
    "autodiscover",
    "autoconfig",
    "m",
    "mobile",
    "es",
    "en",
)

# Mecanismos SPF que cuentan como consultas DNS (RFC 7208, límite de 10).
SPF_DNS_LOOKUPS: tuple[str, ...] = ("include", "a", "mx", "ptr", "exists", "redirect")

# Calificadores del mecanismo `all` y su significado.
SPF_ALL_QUALIFIERS: dict[str, str] = {
    "+": "permitir todo (muy permisivo)",
    "-": "rechazar todo (restrictivo)",
    "~": "marcar como fallo suave (recomendado)",
    "?": "neutro (sin política)",
}

# Políticas DMARC y su nivel de protección.
DMARC_POLICIES: dict[str, str] = {
    "reject": "rechazo total (recomendado)",
    "quarantine": "cuarentena",
    "none": "sin acción (solo monitorización)",
}


@dataclass(slots=True)
class AuditConfig:
    """Configuración de una auditoría DNS."""

    domain: str
    timeout: float = 5.0
    nameserver: str | None = None
    record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES
    check_spf: bool = True
    check_dmarc: bool = True
    dkim_selectors: tuple[str, ...] = ()
    check_subdomains: bool = True
    max_subdomains: int = 60
    concurrency: int = 10
    rate_limit: float = 20.0
    scope: Scope | None = None
    scope_file: str | None = None
    confirm_authorized: bool = False


@dataclass(slots=True)
class DNSDefaults:
    """Valores por defecto reutilizables."""

    timeout: float = 5.0
    concurrency: int = 10
    rate_limit: float = 20.0
    max_subdomains: int = 60


# Referencias técnicas.
REFERENCES: dict[str, list[str]] = {
    "spf": [
        "https://datatracker.ietf.org/doc/html/rfc7208",
        "https://dmarcian.com/spf-survey/",
    ],
    "dmarc": [
        "https://datatracker.ietf.org/doc/html/rfc7489",
        "https://dmarc.org/",
    ],
    "dkim": ["https://datatracker.ietf.org/doc/html/rfc6376"],
    "registros": ["https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml"],
    "subdominios": ["https://owasp.org/www-project-web-security-testing-guide/"],
    "exposicion": ["https://owasp.org/www-project-web-security-testing-guide/"],
}

__all__ = [
    "AuditConfig",
    "COMMON_DKIM_SELECTORS",
    "COMMON_SUBDOMAINS",
    "DEFAULT_RECORD_TYPES",
    "DMARC_POLICIES",
    "DNSDefaults",
    "REFERENCES",
    "SPF_ALL_QUALIFIERS",
    "SPF_DNS_LOOKUPS",
    "field",
]
