"""Núcleo de PyDNSAudit."""

from pydnsaudit.core.auditor import Auditor
from pydnsaudit.core.dkim import analyze_dkim
from pydnsaudit.core.dmarc import analyze_dmarc
from pydnsaudit.core.resolver import (
    resolve_address,
    resolve_many,
    resolve_nameservers,
    resolve_record,
)
from pydnsaudit.core.spf import analyze_spf
from pydnsaudit.core.subdomains import analyze_exposure, enumerate_subdomains

__all__ = [
    "Auditor",
    "analyze_dkim",
    "analyze_dmarc",
    "analyze_exposure",
    "analyze_spf",
    "enumerate_subdomains",
    "resolve_address",
    "resolve_many",
    "resolve_nameservers",
    "resolve_record",
]
