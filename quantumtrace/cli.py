"""Command-line entry point."""

import argparse
import json
import sys

from . import __version__
from .inventory import scan_path
from .report import write_reports
from .runtime import diagnostics
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description="QuantumTrace: local cryptographic inventory with evidence")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Passively inspect local files; never execute scanned code")
    scan.add_argument("input", help="File or directory containing input data")
    scan.add_argument("--out", default="reports", help="Output directory (default: reports)")
    scan.add_argument("--strict", action="store_true", help="Return exit code 2 if any file has errors or incomplete analysis")
    scan.add_argument("--fail-on-critical", action="store_true", help="Return exit code 1 when a non-offered critical primitive is found")
    commands.add_parser("doctor", help="Check optional local dependencies")
    serve = commands.add_parser("serve", help="Open the local app with upload, analysis and history")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-browser", action="store_true")
    serve.add_argument("--state-dir", type=Path, help="Optional location for analysis history")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        print(json.dumps(diagnostics(), indent=2))
        return 0
    if args.command == "serve":
        from .app import serve as run_server
        try:
            return run_server(Path(__file__).resolve().parents[1], args.port, not args.no_browser, args.state_dir)
        except (OSError, ValueError) as exc:
            print(f"Could not start local app: {exc}", file=sys.stderr)
            return 2
    try:
        report = scan_path(args.input)
        html, inventory = write_reports(report, args.out)
    except (OSError, ValueError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f"QuantumTrace {__version__}: {summary['analysed_files']} analysed files, {summary['total_findings']} findings")
    print("Risk tiers: " + json.dumps(summary["risk_counts"], sort_keys=True))
    print(f"Counted in cards: {summary['non_offered_findings']}; offered separately: {summary['offered_findings']}")
    print(f"Review reasons: {json.dumps(summary['review_counts'], sort_keys=True)}")
    print(f"Partial: {summary['partial_files']}; errors: {summary['error_files']}; unsupported: {summary['unsupported_files']}")
    print(f"HTML report: {html.resolve()}")
    print(f"Inventory JSON: {inventory.resolve()}")
    if args.strict and (summary["error_files"] or summary["partial_files"]):
        return 2
    if args.fail_on_critical and summary["risk_counts"].get("critical", 0):
        return 1
    return 0
