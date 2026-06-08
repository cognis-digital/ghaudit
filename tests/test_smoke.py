"""Smoke tests for GHAUDIT. Standard library only, no network."""
import json
import os
import unittest
from datetime import datetime, timezone

from ghaudit import audit_org, load_export, TOOL_NAME, TOOL_VERSION
from ghaudit.core import render_json, render_table, render_html
from ghaudit.cli import main


DEMO = os.path.join(
    os.path.dirname(__file__), "..", "demos", "01-basic", "org-export.json"
)
FIXED_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


def _ids(report):
    return {f.check_id for f in report.findings}


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.export = load_export(DEMO)
        self.report = audit_org(self.export, now=FIXED_NOW)

    def test_meta(self):
        self.assertEqual(TOOL_NAME, "ghaudit")
        self.assertTrue(TOOL_VERSION)

    def test_demo_is_failing(self):
        self.assertTrue(self.report.failing)

    def test_expected_critical_findings(self):
        ids = _ids(self.report)
        for cid in ("ORG_2FA_DISABLED", "ADMIN_NO_2FA",
                    "REPO_PUBLIC_INTERNAL", "SECRET_VALUE_IN_EXPORT"):
            self.assertIn(cid, ids)

    def test_expected_high_findings(self):
        ids = _ids(self.report)
        for cid in ("ORG_BASE_PERMISSION_BROAD", "ORG_ADMIN_SPRAWL",
                    "REPO_NO_BRANCH_PROTECTION", "REPO_ALLOW_FORCE_PUSH"):
            self.assertIn(cid, ids)

    def test_stale_secret_detected(self):
        # DEPLOY_KEY from 2023 should be stale relative to FIXED_NOW.
        self.assertIn("SECRET_STALE", _ids(self.report))

    def test_archived_repo_skipped(self):
        # legacy-archive is archived; it must not raise branch-protection findings.
        for f in self.report.findings:
            self.assertNotIn("legacy-archive", f.resource)

    def test_findings_sorted_by_severity(self):
        from ghaudit.core import SEVERITY_ORDER
        ranks = [SEVERITY_ORDER[f.severity] for f in self.report.findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_clean_org_passes(self):
        clean = {
            "organization": {
                "login": "secure-co",
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
                "members_can_create_public_repositories": False,
            },
            "members": [
                {"login": "a", "role": "admin", "two_factor_enabled": True},
                {"login": "b", "role": "member", "two_factor_enabled": True},
            ],
            "repositories": [{
                "full_name": "secure-co/app",
                "default_branch": "main",
                "visibility": "private",
                "archived": False,
                "secret_scanning_enabled": True,
                "branch_protection": {
                    "enabled": True,
                    "required_approving_review_count": 2,
                    "allow_force_pushes": False,
                    "enforce_admins": True,
                },
                "secrets": [],
            }],
        }
        report = audit_org(clean, now=FIXED_NOW)
        self.assertFalse(report.failing)
        self.assertEqual(report.findings, [])


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.report = audit_org(load_export(DEMO), now=FIXED_NOW)

    def test_json_roundtrip(self):
        data = json.loads(render_json(self.report))
        self.assertEqual(data["tool"], "ghaudit")
        self.assertEqual(data["org"], "acme-labs")
        self.assertTrue(data["failing"])
        self.assertEqual(len(data["findings"]), data["counts"]["CRITICAL"]
                         + data["counts"]["HIGH"] + data["counts"]["MEDIUM"]
                         + data["counts"]["LOW"] + data["counts"]["INFO"])

    def test_table_contains_summary(self):
        out = render_table(self.report)
        self.assertIn("GHAUDIT report", out)
        self.assertIn("acme-labs", out)

    def test_html_is_self_contained(self):
        out = render_html(self.report)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", out)
        self.assertNotIn("http://", out)
        self.assertIn("acme-labs", out)


class TestLoadErrors(unittest.TestCase):
    def test_missing_org_key(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            json.dump({"members": []}, tf)
            path = tf.name
        try:
            with self.assertRaises(ValueError):
                load_export(path)
        finally:
            os.unlink(path)


class TestCli(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_audit_exit_code_nonzero_on_findings(self):
        rc = main(["audit", os.path.abspath(DEMO), "--format", "json"])
        self.assertEqual(rc, 1)

    def test_missing_file_exit_2(self):
        rc = main(["audit", "does-not-exist.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
