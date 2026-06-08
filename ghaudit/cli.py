"""Command-line interface for GHAUDIT."""
from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    load_export,
    audit_org,
    render_json,
    render_table,
    render_html,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Audit a GitHub org's security posture from an export "
                    "(branch rules, 2FA, secrets). Defensive analysis only.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="audit an org export file")
    audit.add_argument("export", help="path to the org export JSON file")
    audit.add_argument("--format", choices=["table", "json", "html"],
                       default="table", help="output format (default: table)")
    audit.add_argument("-o", "--output",
                       help="write report to this file instead of stdout")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "audit":
        parser.print_help()
        return 2

    try:
        export = load_export(args.export)
    except FileNotFoundError:
        print(f"error: export file not found: {args.export}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: could not load export: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # malformed JSON, etc.
        print(f"error: invalid export: {exc}", file=sys.stderr)
        return 2

    report = audit_org(export)

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "html":
        rendered = render_html(report)
    else:
        rendered = render_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        except OSError as exc:
            print(f"error: could not write output: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # Non-zero exit when failing (CRITICAL/HIGH) findings exist.
    return 1 if report.failing else 0


if __name__ == "__main__":
    raise SystemExit(main())
