"""Utilidades compartidas de PyDNSAudit."""

from pydnsaudit.utils.domain import (
    Domain,
    build_fqdn,
    is_domain,
    is_ip_address,
    parent_domain,
    strip_wildcard,
    validate_domain,
)
from pydnsaudit.utils.logger import get_logger, setup_logger
from pydnsaudit.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    is_target_in_scope,
    load_scope_file,
    validate_target,
)

__all__ = [
    "Domain",
    "build_fqdn",
    "ensure_authorized",
    "ensure_path_writable",
    "get_logger",
    "is_domain",
    "is_ip_address",
    "is_target_in_scope",
    "load_scope_file",
    "parent_domain",
    "setup_logger",
    "strip_wildcard",
    "validate_domain",
    "validate_target",
]
