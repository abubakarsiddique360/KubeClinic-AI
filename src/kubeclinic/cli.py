"""Command-line interface for KubeClinic."""

from __future__ import annotations

import argparse
import json
import sys

from kubeclinic import __version__
from kubeclinic.loader import ManifestError, load_path
from kubeclinic.report import ScanReport
from kubeclinic.rules import RULES, SEVERITY_ORDER, run_rules


def _scan(args: argparse.Namespace) -> int:
    resources = load_path(args.path)
    findings = run_rules(resources)
    if args.min_severity:
        threshold = SEVERITY_ORDER[args.min_severity]
        findings = [finding for finding in findings if SEVERITY_ORDER[finding.severity] <= threshold]
    report = ScanReport(path=str(args.path), resources=resources, findings=findings)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(report.render())
    return report.exit_code


def _rules(args: argparse.Namespace) -> int:
    for rule in RULES:
        print(f"{rule.severity:<8} {rule.id:<28} {rule.summary}")
    print(f"\n{len(RULES)} rule(s)")
    return 0


def _explain(args: argparse.Namespace) -> int:
    rule = next((candidate for candidate in RULES if candidate.id == args.rule), None)
    if rule is None:
        print(f"unknown rule: {args.rule}", file=sys.stderr)
        return 2
    print(f"rule     : {rule.id}")
    print(f"severity : {rule.severity}")
    print(f"summary  : {rule.summary}")
    print(f"check    : {rule.check.__module__}.{rule.check.__name__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubeclinic",
        description="Diagnose Kubernetes manifests for security and reliability problems.",
    )
    parser.add_argument("--version", action="version", version=f"kubeclinic {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory of manifests")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--min-severity", choices=("error", "warning", "info"), default=None)
    scan.set_defaults(func=_scan)

    rules = sub.add_parser("rules", help="list every rule")
    rules.set_defaults(func=_rules)

    explain = sub.add_parser("explain", help="describe one rule")
    explain.add_argument("rule")
    explain.set_defaults(func=_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
