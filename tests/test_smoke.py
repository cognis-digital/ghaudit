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

    def test_empty_file_raises_value_error(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            tf.write("   ")
            path = tf.name
        try:
            with self.assertRaises(ValueError, msg="empty file should raise ValueError"):
                load_export(path)
        finally:
            os.unlink(path)

    def test_invalid_json_raises_value_error(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            tf.write("{bad json")
            path = tf.name
        try:
            with self.assertRaises(ValueError, msg="malformed JSON should raise ValueError"):
                load_export(path)
        finally:
            os.unlink(path)

    def test_json_array_raises_value_error(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            json.dump([1, 2, 3], tf)
            path = tf.name
        try:
            with self.assertRaises(ValueError, msg="JSON array root should raise ValueError"):
                load_export(path)
        finally:
            os.unlink(path)


class TestAuditEdgeCases(unittest.TestCase):
    """Hardening tests: malformed / adversarial export data must not crash."""

    def test_none_member_entries_ignored(self):
        """A None entry in the members list must be skipped gracefully."""
        export = {
            "organization": {"login": "test-org", "two_factor_requirement_enabled": True,
                             "default_repository_permission": "read"},
            "members": [None, {"login": "alice", "role": "admin", "two_factor_enabled": True}],
            "repositories": [],
        }
        report = audit_org(export, now=FIXED_NOW)
        # Should complete without exception; findings may or may not exist.
        self.assertIsNotNone(report)

    def test_non_dict_repo_entries_ignored(self):
        """Non-dict entries in repositories must be skipped without crashing."""
        export = {
            "organization": {"login": "test-org", "two_factor_requirement_enabled": True},
            "members": [],
            "repositories": ["not-a-repo", 42, None],
        }
        report = audit_org(export, now=FIXED_NOW)
        self.assertIsNotNone(report)

    def test_branch_protection_non_dict_treated_as_absent(self):
        """branch_protection set to a non-dict value should trigger REPO_NO_BRANCH_PROTECTION."""
        export = {
            "organization": {"login": "test-org"},
            "members": [],
            "repositories": [{
                "full_name": "test-org/repo",
                "default_branch": "main",
                "archived": False,
                "branch_protection": "enabled",  # wrong type
            }],
        }
        report = audit_org(export, now=FIXED_NOW)
        ids = {f.check_id for f in report.findings}
        self.assertIn("REPO_NO_BRANCH_PROTECTION", ids)

    def test_none_secret_entries_ignored(self):
        """A None entry in a repo's secrets list must be skipped without crashing."""
        export = {
            "organization": {"login": "test-org"},
            "members": [],
            "repositories": [{
                "full_name": "test-org/repo",
                "default_branch": "main",
                "archived": False,
                "secrets": [None, {"name": "KEY", "updated_at": "2023-01-01T00:00:00Z"}],
            }],
        }
        report = audit_org(export, now=FIXED_NOW)
        # The valid stale secret should still be detected.
        ids = {f.check_id for f in report.findings}
        self.assertIn("SECRET_STALE", ids)

    def test_empty_export_no_crash(self):
        """Minimal export with only the required 'organization' key produces a report."""
        export = {"organization": {}}
        report = audit_org(export, now=FIXED_NOW)
        self.assertEqual(report.org, "unknown")
        self.assertEqual(report.stats["members"], 0)
        self.assertEqual(report.stats["repositories"], 0)


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

    def test_empty_json_file_exit_2(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            tf.write("")
            path = tf.name
        try:
            rc = main(["audit", path])
            self.assertEqual(rc, 2, "empty file should exit 2")
        finally:
            os.unlink(path)

    def test_malformed_json_exit_2(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as tf:
            tf.write("{this is not json")
            path = tf.name
        try:
            rc = main(["audit", path])
            self.assertEqual(rc, 2, "invalid JSON should exit 2")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
