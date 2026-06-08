"""GHAUDIT - audit a GitHub org's security posture from an export.

Defensive / forensics tooling: analyzes an organization export (members,
repositories, branch protection, secrets metadata) you already own and
reports hardening gaps. No network access, no attack capability.
"""
from .core import (
    Finding,
    AuditReport,
    audit_org,
    load_export,
    SEVERITY_ORDER,
)

TOOL_NAME = "ghaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "AuditReport",
    "audit_org",
    "load_export",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
