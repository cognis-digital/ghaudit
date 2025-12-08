"""GHAUDIT — Audit a GitHub org's security posture (branch rules, 2FA, secrets) from an export."""
from ghaudit.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
