"""Modelos de datos de PyDNSAudit (Pydantic)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Niveles de severidad, de mayor a menor impacto."""

    CONFIRMADO = "confirmado"
    PROBABLE = "probable"
    POTENCIAL = "potencial"
    INDICIO = "indicio"
    RECOMENDACION = "recomendacion"


class Category(StrEnum):
    """Áreas de análisis de la auditoría DNS."""

    RECORDS = "registros"
    SPF = "spf"
    DMARC = "dmarc"
    DKIM = "dkim"
    SUBDOMAINS = "subdominios"
    EXPOSURE = "exposicion"
    GENERAL = "general"


class Scope(BaseModel):
    """Alcance autorizado de la auditoría."""

    model_config = ConfigDict(frozen=True)

    name: str = "Auditoría autorizada"
    authorized_targets: list[str] = Field(default_factory=list)

    def matches(self, domain: str) -> bool:
        """Indica si un dominio está dentro del alcance.

        Se acepta el dominio exacto o cualquier subdominio de los objetivos
        declarados, para poder analizar subdominios sin salir del alcance.
        """
        candidate = _normalise(domain)
        for target in self.authorized_targets:
            normalised = _normalise(target)
            if candidate == normalised or candidate.endswith(f".{normalised}"):
                return True
        return False


class DNSRecord(BaseModel):
    """Registro DNS observado."""

    model_config = ConfigDict(frozen=True)

    name: str
    type: str
    values: list[str] = Field(default_factory=list)
    ttl: int | None = None

    @property
    def value(self) -> str:
        """Primer valor del registro, o cadena vacía."""
        return self.values[0] if self.values else ""


class SPFInfo(BaseModel):
    """Resultado del análisis SPF."""

    model_config = ConfigDict(frozen=True)

    domain: str
    present: bool = False
    raw: str | None = None
    mechanisms: list[str] = Field(default_factory=list)
    lookup_count: int = 0
    all_qualifier: str | None = None
    includes: list[str] = Field(default_factory=list)
    error: str | None = None


class DMARCInfo(BaseModel):
    """Resultado del análisis DMARC."""

    model_config = ConfigDict(frozen=True)

    domain: str
    present: bool = False
    raw: str | None = None
    policy: str | None = None
    subdomain_policy: str | None = None
    percentage: int | None = None
    aggregate_reports: list[str] = Field(default_factory=list)
    forensic_reports: list[str] = Field(default_factory=list)
    error: str | None = None


class DKIMInfo(BaseModel):
    """Resultado del análisis DKIM."""

    model_config = ConfigDict(frozen=True)

    domain: str
    selector: str
    present: bool = False
    raw: str | None = None
    key_type: str | None = None
    key_size: int | None = None
    error: str | None = None


class SubdomainInfo(BaseModel):
    """Subdominio identificado."""

    model_config = ConfigDict(frozen=True)

    name: str
    record_types: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Hallazgo de seguridad."""

    model_config = ConfigDict(frozen=True)

    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    references: list[str] = Field(default_factory=list)


class DNSAuditResult(BaseModel):
    """Resultado consolidado de una auditoría DNS."""

    model_config = ConfigDict(frozen=True)

    tool: str = "PyDNSAudit"
    version: str = "1.0.0"
    domain: str
    scope: str | None = None
    authorized: bool = False
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = 0.0
    nameservers: list[str] = Field(default_factory=list)
    records: dict[str, list[DNSRecord]] = Field(default_factory=dict)
    spf: SPFInfo | None = None
    dmarc: DMARCInfo | None = None
    dkim: list[DKIMInfo] = Field(default_factory=list)
    subdomains: list[SubdomainInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    statistics: dict[str, int] = Field(default_factory=dict)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Devuelve los hallazgos de una severidad concreta."""
        return [f for f in self.findings if f.severity is severity]

    @property
    def confirmed_count(self) -> int:
        """Número de hallazgos confirmados."""
        return len(self.findings_by_severity(Severity.CONFIRMADO))

    def summary(self) -> dict[str, Any]:
        """Resumen apto para registros y depuración."""
        return {
            "domain": self.domain,
            "nameservers": len(self.nameservers),
            "record_types": sorted(self.records),
            "subdomains": len(self.subdomains),
            "findings": len(self.findings),
            "statistics": self.statistics,
        }


def _normalise(value: str) -> str:
    """Normaliza un dominio para compararlo sin distinguir mayúsculas."""
    return value.strip().lower().rstrip(".")


__all__ = [
    "Category",
    "DKIMInfo",
    "DMARCInfo",
    "DNSAuditResult",
    "DNSRecord",
    "Finding",
    "Scope",
    "SPFInfo",
    "Severity",
    "SubdomainInfo",
    "timezone",
]
