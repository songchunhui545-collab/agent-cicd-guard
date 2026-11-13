"""Command-line interface for agent-cicd-guard."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_cicd_guard import __version__
from agent_cicd_guard.reporters import render_json, render_sarif, render_text
from agent_cicd_guard.scanner import ScanError, scan_path, should_fail

FORMATS = ("text", "json", "sarif")
FAIL_ON = ("high", "medium", "low", "info", "never")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-cicd-guard",
        description=(
            "Scan GitHub Actions workflows for security risks when AI agents "
            "are wired into CI/CD."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"agent-cicd-guard {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a repository or workflow file")
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root, .github/workflows directory, or a single workflow file",
    )
    scan.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="Output format (default: text)",
    )
    scan.add_argument(
        "-o",
        "--output",
        help="Write the report to this file instead of stdout",
    )
    scan.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default="high",
        help="Exit 1 when a finding of this severity or higher is present (default: high)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    if args.command == "scan":
        return _cmd_scan(args)
    parser.error(f"Unknown command: {args.command}")
    return 2


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        workflows, findings = scan_path(args.path)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = render_json(workflows, findings)
    elif args.format == "sarif":
        report = render_sarif(workflows, findings)
    else:
        report = render_text(workflows, findings)

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        if args.format == "text":
            # Still echo a short note so CI logs show the path.
            print(f"Wrote {path}", file=sys.stderr)
        else:
            print(f"Wrote {path}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on == "never":
        return 0
    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
