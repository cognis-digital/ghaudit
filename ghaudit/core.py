"""Core audit engine for GHAUDIT.

Consumes a GitHub org export (JSON) and evaluates it against a set of
security-posture checks inspired by org-hardening guidance (legitify-style):
2FA enforcement, branch protection, secret hygiene, member/admin sprawl,
repository visibility and forking policy.

Pure standard library. Deterministic. No network.
"""
from __future__ import annotations

import json
import html
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Severity -> hex color for HTML report
_SEV_COLOR = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#558b2f",
    "INFO": "#1565c0",
}

# Exit codes treat these severities as "failing".
_FAILING = {"CRITICAL", "HIGH"}

# Age in days after which a secret is considered stale / should be rotated.
_SECRET_STALE_DAYS = 365


@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    resource: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditReport:
    org: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def failing(self) -> bool:
        return any(f.severity in _FAILING for f in self.findings)

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "tool": "ghaudit",
            "org": self.org,
            "generated_at": self.generated_at,
            "stats": self.stats,
            "counts": self.counts(),
            "failing": self.failing,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_export(path: str) -> dict:
    """Load and minimally validate a GitHub org export JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("export root must be a JSON object")
    if "organization" not in data:
        raise ValueError("export missing required 'organization' key")
    return data


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    txt = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Individual checks. Each appends Finding objects to `out`.
# --------------------------------------------------------------------------

def _check_org_2fa(org: dict, out: list[Finding]) -> None:
    if not org.get("two_factor_requirement_enabled", False):
        out.append(Finding(
            check_id="ORG_2FA_DISABLED",
            severity="CRITICAL",
            title="Organization does not require two-factor authentication",
            resource=f"org/{org.get('login', '?')}",
            detail="Members can authenticate without 2FA, exposing the org to "
                   "credential-stuffing and phishing account takeover.",
            remediation="Enable 'Require two-factor authentication' in "
                        "Org Settings > Authentication security.",
        ))


def _check_default_perm(org: dict, out: list[Finding]) -> None:
    perm = (org.get("default_repository_permission") or "read").lower()
    if perm in ("write", "admin"):
        out.append(Finding(
            check_id="ORG_BASE_PERMISSION_BROAD",
            severity="HIGH",
            title=f"Org base repository permission is '{perm}'",
            resource=f"org/{org.get('login', '?')}",
            detail="Every member gets this permission on all repos by default, "
                   "violating least-privilege.",
            remediation="Set default repository permission to 'read' (or 'none') "
                        "and grant write/admin per-team.",
        ))


def _check_member_can_create_public(org: dict, out: list[Finding]) -> None:
    if org.get("members_can_create_public_repositories", False):
        out.append(Finding(
            check_id="ORG_MEMBERS_CREATE_PUBLIC",
            severity="MEDIUM",
            title="Members can create public repositories",
            resource=f"org/{org.get('login', '?')}",
            detail="Any member can publish a public repo, risking inadvertent "
                   "disclosure of internal code.",
            remediation="Restrict repository creation to owners, or disallow "
                        "public repos in member privileges.",
        ))


def _check_admins(members: list[dict], out: list[Finding]) -> None:
    admins = [m for m in members if (m.get("role") or "").lower() == "admin"]
    total = len(members)
    if total and len(admins) / total > 0.25 and len(admins) > 2:
        out.append(Finding(
            check_id="ORG_ADMIN_SPRAWL",
            severity="HIGH",
            title=f"Excessive org owners: {len(admins)} of {total} members",
            resource=f"members ({len(admins)} owners)",
            detail="More than 25% of members hold owner/admin role. Owner "
                   "accounts are high-value targets.",
            remediation="Reduce org owners to the minimum (typically 2-3) and "
                        "use teams for delegated access.",
        ))
    for m in members:
        if (m.get("role") or "").lower() == "admin" and not m.get("two_factor_enabled", True):
            out.append(Finding(
                check_id="ADMIN_NO_2FA",
                severity="CRITICAL",
                title="Org owner without two-factor authentication",
                resource=f"user/{m.get('login', '?')}",
                detail="An account with org-owner privileges has 2FA disabled.",
                remediation="Require this owner to enable 2FA immediately or "
                            "revoke their owner role.",
            ))


def _check_repo(repo: dict, out: list[Finding]) -> None:
    name = repo.get("full_name") or repo.get("name") or "?"
    archived = repo.get("archived", False)

    # Branch protection on the default branch.
    if not archived:
        bp = repo.get("branch_protection") or {}
        default_branch = repo.get("default_branch", "main")
        if not bp.get("enabled", False):
            out.append(Finding(
                check_id="REPO_NO_BRANCH_PROTECTION",
                severity="HIGH",
                title="Default branch is not protected",
                resource=f"repo/{name}@{default_branch}",
                detail="The default branch has no protection rule; direct pushes "
                       "and force-pushes are possible.",
                remediation="Add a branch protection rule requiring PR review "
                            "and status checks on the default branch.",
            ))
        else:
            if (bp.get("required_approving_review_count") or 0) < 1:
                out.append(Finding(
                    check_id="REPO_NO_REQUIRED_REVIEW",
                    severity="MEDIUM",
                    title="Branch protection does not require PR review",
                    resource=f"repo/{name}@{default_branch}",
                    detail="Changes can merge without an approving review.",
                    remediation="Require at least one approving review before "
                                "merge.",
                ))
            if bp.get("allow_force_pushes", False):
                out.append(Finding(
                    check_id="REPO_ALLOW_FORCE_PUSH",
                    severity="HIGH",
                    title="Branch protection allows force pushes",
                    resource=f"repo/{name}@{default_branch}",
                    detail="Force pushes can rewrite history, enabling tampering "
                           "and audit-trail loss.",
                    remediation="Disable 'Allow force pushes' on the protected "
                                "branch.",
                ))
            if not bp.get("enforce_admins", False):
                out.append(Finding(
                    check_id="REPO_ADMINS_BYPASS",
                    severity="MEDIUM",
                    title="Administrators can bypass branch protection",
                    resource=f"repo/{name}@{default_branch}",
                    detail="Admins are not subject to protection rules, weakening "
                           "the control.",
                    remediation="Enable 'Include administrators' on the branch "
                                "protection rule.",
                ))

    # Visibility.
    if repo.get("visibility") == "public" and repo.get("contains_internal_marker"):
        out.append(Finding(
            check_id="REPO_PUBLIC_INTERNAL",
            severity="CRITICAL",
            title="Public repo flagged as containing internal material",
            resource=f"repo/{name}",
            detail="A repo marked internal-only is exposed publicly.",
            remediation="Make the repository private and rotate any leaked "
                        "credentials.",
        ))

    # Secret scanning / push protection.
    if not archived and repo.get("visibility") != "public":
        if not repo.get("secret_scanning_enabled", False):
            out.append(Finding(
                check_id="REPO_NO_SECRET_SCANNING",
                severity="MEDIUM",
                title="Secret scanning is disabled",
                resource=f"repo/{name}",
                detail="Committed credentials will not be detected automatically.",
                remediation="Enable secret scanning (and push protection) on the "
                            "repository.",
            ))


def _check_secrets(repo: dict, out: list[Finding], now: datetime) -> None:
    name = repo.get("full_name") or repo.get("name") or "?"
    for sec in repo.get("secrets") or []:
        sname = sec.get("name", "?")
        updated = _parse_date(sec.get("updated_at"))
        if updated is not None:
            age = (now - updated).days
            if age > _SECRET_STALE_DAYS:
                out.append(Finding(
                    check_id="SECRET_STALE",
                    severity="MEDIUM",
                    title=f"Actions secret not rotated in {age} days",
                    resource=f"repo/{name}#{sname}",
                    detail="Long-lived secrets increase blast radius if leaked.",
                    remediation="Rotate the secret and adopt a rotation schedule "
                                "(<= 1 year).",
                ))
        # Plaintext leakage: an export should never contain a value.
        if "value" in sec or "plaintext" in sec:
            out.append(Finding(
                check_id="SECRET_VALUE_IN_EXPORT",
                severity="CRITICAL",
                title=f"Secret value present in export for '{sname}'",
                resource=f"repo/{name}#{sname}",
                detail="The export file contains a cleartext secret value; the "
                       "export itself is now sensitive.",
                remediation="Rotate this secret, purge the export, and ensure "
                            "exports never include secret values.",
            ))


def audit_org(export: dict, now: Optional[datetime] = None) -> AuditReport:
    """Run all checks against an export dict and return an AuditReport."""
    now = now or _now()
    org = export.get("organization") or {}
    members = export.get("members") or []
    repos = export.get("repositories") or []

    findings: list[Finding] = []

    _check_org_2fa(org, findings)
    _check_default_perm(org, findings)
    _check_member_can_create_public(org, findings)
    _check_admins(members, findings)

    for repo in repos:
        _check_repo(repo, findings)
        _check_secrets(repo, findings, now)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.check_id, f.resource))

    stats = {
        "members": len(members),
        "repositories": len(repos),
        "public_repositories": sum(1 for r in repos if r.get("visibility") == "public"),
        "archived_repositories": sum(1 for r in repos if r.get("archived")),
        "total_findings": len(findings),
    }

    return AuditReport(
        org=org.get("login", "unknown"),
        generated_at=now.replace(microsecond=0).isoformat(),
        findings=findings,
        stats=stats,
    )


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

def render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_table(report: AuditReport) -> str:
    counts = report.counts()
    lines = []
    lines.append(f"GHAUDIT report for org: {report.org}")
    lines.append(f"Generated: {report.generated_at}")
    lines.append("")
    lines.append("Summary: " + "  ".join(
        f"{s}={counts[s]}" for s in SEVERITY_ORDER if counts[s]
    ) or "Summary: no findings")
    lines.append(
        f"Inventory: {report.stats.get('members', 0)} members, "
        f"{report.stats.get('repositories', 0)} repos "
        f"({report.stats.get('public_repositories', 0)} public)"
    )
    lines.append("")

    if not report.findings:
        lines.append("No findings. Posture checks passed.")
        return "\n".join(lines)

    sev_w, id_w = 8, 26
    lines.append(f"{'SEVERITY':<{sev_w}} {'CHECK':<{id_w}} RESOURCE / TITLE")
    lines.append("-" * 78)
    for f in report.findings:
        lines.append(f"{f.severity:<{sev_w}} {f.check_id:<{id_w}} {f.resource}")
        lines.append(f"{'':<{sev_w}} {'':<{id_w}} {f.title}")
        lines.append(f"{'':<{sev_w}} {'':<{id_w}} fix: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def render_html(report: AuditReport) -> str:
    counts = report.counts()
    esc = html.escape
    pills = "".join(
        f'<span class="pill" style="background:{_SEV_COLOR[s]}">{s}: {counts[s]}</span>'
        for s in SEVERITY_ORDER if counts[s]
    ) or '<span class="pill" style="background:#1565c0">No findings</span>'

    rows = []
    for f in report.findings:
        color = _SEV_COLOR.get(f.severity, "#555")
        rows.append(f"""    <tr>
      <td><span class=\"sev\" style=\"background:{color}\">{esc(f.severity)}</span></td>
      <td class=\"mono\">{esc(f.check_id)}</td>
      <td class=\"mono\">{esc(f.resource)}</td>
      <td><strong>{esc(f.title)}</strong><br><span class=\"detail\">{esc(f.detail)}</span>
          <br><span class=\"fix\">Fix: {esc(f.remediation)}</span></td>
    </tr>""")
    rows_html = "\n".join(rows) if rows else (
        '    <tr><td colspan="4" class="ok">No findings — posture checks passed.</td></tr>'
    )

    s = report.stats
    return f"""<!DOCTYPE html>
<html lang=\"en\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>GHAUDIT report — {esc(report.org)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background:#0f1115; color:#e6e6e6; }}
  header {{ padding:24px 32px; background:#161a22; border-bottom:1px solid #262b36; }}
  h1 {{ margin:0 0 4px; font-size:22px; }}
  .meta {{ color:#9aa4b2; font-size:13px; }}
  .pills {{ margin:14px 0; }}
  .pill {{ color:#fff; padding:4px 10px; border-radius:12px; font-size:12px;
          margin-right:6px; font-weight:600; }}
  .inv {{ display:flex; gap:24px; padding:16px 32px; color:#cfd6df; font-size:13px;
         background:#12151c; border-bottom:1px solid #262b36; }}
  .inv b {{ color:#fff; font-size:18px; display:block; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:10px 14px; vertical-align:top;
           border-bottom:1px solid #20242e; font-size:13px; }}
  th {{ background:#1b1f29; color:#9aa4b2; position:sticky; top:0; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px;
         font-weight:700; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; color:#bcd; }}
  .detail {{ color:#9aa4b2; }}
  .fix {{ color:#8fce8f; }}
  .ok {{ color:#8fce8f; text-align:center; padding:24px; }}
  footer {{ padding:14px 32px; color:#5c6573; font-size:12px; }}
</style></head>
<body>
<header>
  <h1>GHAUDIT — security posture report</h1>
  <div class=\"meta\">Organization <strong>{esc(report.org)}</strong> &middot;
       generated {esc(report.generated_at)}</div>
  <div class=\"pills\">{pills}</div>
</header>
<div class=\"inv\">
  <div><b>{s.get('members', 0)}</b>members</div>
  <div><b>{s.get('repositories', 0)}</b>repositories</div>
  <div><b>{s.get('public_repositories', 0)}</b>public</div>
  <div><b>{s.get('archived_repositories', 0)}</b>archived</div>
  <div><b>{s.get('total_findings', 0)}</b>findings</div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Check</th><th>Resource</th><th>Finding</th></tr></thead>
  <tbody>
{rows_html}
  </tbody>
</table>
<footer>Generated by ghaudit — defensive org-hardening audit. No data leaves this machine.</footer>
</body></html>"""
