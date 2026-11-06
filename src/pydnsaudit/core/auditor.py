"""Orquestador principal de la auditoría DNS de PyDNSAudit."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from pydnsaudit.config import COMMON_DKIM_SELECTORS, AuditConfig
from pydnsaudit.core.dkim import analyze_dkim
from pydnsaudit.core.dmarc import analyze_dmarc
from pydnsaudit.core.resolver import resolve_many, resolve_nameservers
from pydnsaudit.core.spf import analyze_spf
from pydnsaudit.core.subdomains import analyze_exposure, enumerate_subdomains
from pydnsaudit.models import (
    Category,
    DKIMInfo,
    DNSAuditResult,
    DNSRecord,
    Finding,
    Severity,
    SubdomainInfo,
)
from pydnsaudit.utils.logger import get_logger

_logger = get_logger("core.auditor")


class Auditor:
    """Ejecuta una auditoría DNS completa sobre un dominio autorizado."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self.logger = get_logger("core.auditor")

    async def run(self) -> DNSAuditResult:
        """Ejecuta el análisis y devuelve el resultado consolidado."""
        started = datetime.now(UTC)
        self.logger.info("auditoría DNS iniciada contra %s", self.config.domain)

        findings: list[Finding] = []
        records: dict[str, list[DNSRecord]] = {}
        nameservers: list[str] = []
        spf = None
        dmarc = None
        dkim: list[DKIMInfo] = []
        subdomains: list[SubdomainInfo] = []

        try:
            records = await resolve_many(
                self.config.domain,
                self.config.record_types,
                self.config.nameserver,
                self.config.timeout,
                self.config.concurrency,
            )

            nameservers = await resolve_nameservers(
                self.config.domain, self.config.nameserver, self.config.timeout
            )
            if not nameservers:
                findings.append(
                    _finding(
                        id="nameservers_unavailable",
                        category=Category.GENERAL,
                        severity=Severity.INDICIO,
                        title="No se pudieron obtener los servidores de nombres",
                        description=(
                            "No se ha podido resolver la zona del dominio, por lo que "
                            "parte del análisis puede estar incompleto."
                        ),
                        evidence=f"Dominio: {self.config.domain}",
                        recommendation="Comprueba que el dominio existe y que es resoluble.",
                    )
                )

            findings.extend(_analyze_records(self.config.domain, records))

            if self.config.check_spf:
                spf, spf_findings = await analyze_spf(
                    self.config.domain, self.config.nameserver, self.config.timeout
                )
                findings.extend(spf_findings)

            if self.config.check_dmarc:
                dmarc, dmarc_findings = await analyze_dmarc(
                    self.config.domain, self.config.nameserver, self.config.timeout
                )
                findings.extend(dmarc_findings)

            selectors = self.config.dkim_selectors or COMMON_DKIM_SELECTORS
            dkim, dkim_findings = await self._analyze_dkim(selectors)
            findings.extend(dkim_findings)

            if self.config.check_subdomains:
                subdomains = await enumerate_subdomains(
                    self.config.domain,
                    self.config.nameserver,
                    self.config.timeout,
                    self.config.max_subdomains,
                    self.config.concurrency,
                )
                findings.extend(analyze_exposure(self.config.domain, subdomains, records))

        except Exception as exc:  # defensivo: nunca se debe perder el resultado parcial
            self.logger.error("error durante la auditoría: %s", exc)
            findings.append(
                _finding(
                    id="audit_error",
                    category=Category.GENERAL,
                    severity=Severity.INDICIO,
                    title="Error durante la auditoría",
                    description="Se ha producido un error que ha interrumpido parte del análisis.",
                    evidence=str(exc),
                    recommendation="Revisa el registro para obtener más detalle.",
                )
            )

        finished = datetime.now(UTC)
        result = DNSAuditResult(
            domain=self.config.domain,
            scope=self.config.scope.name if self.config.scope else None,
            authorized=self.config.confirm_authorized or self.config.scope is not None,
            started_at=started,
            finished_at=finished,
            duration_seconds=round((finished - started).total_seconds(), 3),
            nameservers=nameservers,
            records=records,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            subdomains=subdomains,
            findings=findings,
            statistics=_statistics(findings),
        )
        self.logger.info(
            "auditoría finalizada en %.2f s: %d hallazgos",
            result.duration_seconds,
            len(findings),
        )
        return result

    async def _analyze_dkim(
        self, selectors: tuple[str, ...]
    ) -> tuple[list[DKIMInfo], list[Finding]]:
        """Analiza varios selectores DKIM de forma concurrente."""
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def _guarded(selector: str) -> tuple[DKIMInfo | None, list[Finding]]:
            async with semaphore:
                return await analyze_dkim(
                    self.config.domain, selector, self.config.nameserver, self.config.timeout
                )

        results = await asyncio.gather(*(_guarded(selector) for selector in selectors))
        infos: list[DKIMInfo] = []
        findings: list[Finding] = []
        for info, selector_findings in results:
            if info is not None:
                infos.append(info)
            findings.extend(selector_findings)

        if not any(info.present for info in infos):
            findings.append(
                _finding(
                    id="dkim_not_found",
                    category=Category.DKIM,
                    severity=Severity.INDICIO,
                    title="No se han encontrado registros DKIM habituales",
                    description=(
                        "No se ha localizado DKIM para los selectores habituales. Si el "
                        "dominio usa un selector distinto, indícalo con --dkim-selector."
                    ),
                    evidence=f"Selectores probados: {', '.join(selectors[:5])}…",
                    recommendation="Publica un registro DKIM y revísalo periódicamente.",
                )
            )

        return infos, findings


def _analyze_records(domain: str, records: dict[str, list[DNSRecord]]) -> list[Finding]:
    """Genera hallazgos a partir de los registros del dominio base."""
    findings: list[Finding] = []

    # Un diccionario con claves pero sin valores equivale a "sin registros".
    has_records = any(entries for entries in records.values())
    if not has_records:
        findings.append(
            _finding(
                id="no_records_found",
                category=Category.RECORDS,
                severity=Severity.INDICIO,
                title="No se han obtenido registros del dominio",
                description=(
                    "El dominio no devolvió registros para los tipos consultados, lo que "
                    "puede indicar que no existe o que no está publicado."
                ),
                evidence=f"Dominio: {domain}",
                recommendation="Comprueba que el dominio está dado de alta y propagado.",
            )
        )
        return findings

    ns_records = records.get("NS", [])
    if not ns_records:
        findings.append(
            _finding(
                id="no_ns_records",
                category=Category.RECORDS,
                severity=Severity.POTENCIAL,
                title="Sin registros NS visibles",
                description=(
                    "No se han obtenido servidores de nombres autoritativos, lo que puede "
                    "indicar una delegación incorrecta."
                ),
                evidence=f"Dominio: {domain}",
                recommendation="Revisa la delegación del dominio en el registrador.",
            )
        )

    txt_values: list[str] = []
    for record in records.get("TXT", []):
        txt_values.extend(record.values)

    if txt_values and not any(value.lower().startswith("v=spf1") for value in txt_values):
        # SPF ausente ya se reporta en su propio análisis; no se duplica aquí.
        pass

    return findings


def _finding(
    *,
    id: str,
    category: Category,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    references: list[str] | None = None,
) -> Finding:
    """Construye un hallazgo con los campos normalizados."""
    return Finding(
        id=id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        references=references or [],
    )


def _statistics(findings: list[Finding]) -> dict[str, int]:
    """Cuenta los hallazgos por severidad."""
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


__all__ = ["Auditor"]
