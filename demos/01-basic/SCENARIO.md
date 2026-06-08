# Demo 01 — basic org audit

`org-export.json` is a realistic export of a fictional GitHub organization
(`acme-labs`) that you own. It deliberately contains common hardening gaps so
you can see GHAUDIT's full range of findings.

## What's in the export

- **Org settings**: 2FA *not* required, base permission `write`, members may
  create public repos.
- **Members**: 3 of 5 are owners (admin sprawl); owner `bob` has 2FA disabled.
- **`payments-api`** (private): protected branch but no required reviews,
  force-pushes allowed, admins can bypass, secret scanning off, and a
  `DEPLOY_KEY` secret last rotated in 2023 (stale).
- **`website`** (public): no branch protection and flagged as containing
  internal material — a public exposure.
- **`internal-tools`** (private): well-configured branch protection, *but* its
  export accidentally includes a cleartext secret `value` — the export file is
  now itself sensitive.
- **`legacy-archive`** (archived): skipped for branch/secret checks.

## Run it

```bash
# Human-readable table (default)
python -m ghaudit audit demos/01-basic/org-export.json

# Machine-readable for pipelines
python -m ghaudit audit demos/01-basic/org-export.json --format json

# Self-contained HTML report (the shareable UI)
python -m ghaudit audit demos/01-basic/org-export.json --format html -o report.html
```

The process exits non-zero (1) because CRITICAL/HIGH findings are present,
so it can gate CI. A clean org would exit 0.

## Expected highlights

- `ORG_2FA_DISABLED` (CRITICAL)
- `ADMIN_NO_2FA` for `bob` (CRITICAL)
- `REPO_PUBLIC_INTERNAL` for `website` (CRITICAL)
- `SECRET_VALUE_IN_EXPORT` for `internal-tools#NPM_TOKEN` (CRITICAL)
- `ORG_BASE_PERMISSION_BROAD`, `ORG_ADMIN_SPRAWL`,
  `REPO_NO_BRANCH_PROTECTION`, `REPO_ALLOW_FORCE_PUSH` (HIGH)
