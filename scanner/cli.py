"""Command-line interface and multi-source scan pipeline orchestrator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from scanner.cbom import CBOMSerializer
from scanner.models import CryptoFinding
from scanner.report import (
    build_report_summary,
    calculate_hygiene_score,
    calculate_posture_status,
    calculate_quantum_risk_score,
    generate_summary_counts,
)
from scanner.risk import enrich_finding_risk


def build_cli_parser() -> argparse.ArgumentParser:
    """Construct argument parser for the CLI interface."""
    parser = argparse.ArgumentParser(
        prog="quantumtrace",
        description="Automated Post-Quantum Cryptographic Discovery & Risk Analysis",
    )
    parser.add_argument(
        "--source",
        type=str,
        default=None,
        help="Path to source code directory or file to scan",
    )
    parser.add_argument(
        "--cloud",
        type=str,
        default=None,
        help="Path to cloud posture JSON inventory directory or file",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Path to PCAP/PCAPNG network capture directory or file",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all supported input vectors using default paths in support-materials/",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="File path to write the CycloneDX 1.6 CBOM JSON",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="QuantumTrace 1.0.0",
    )
    return parser


def render_terminal_summary(
    findings: list[Any],
    report_summary: dict[str, Any],
) -> None:
    """Print an executive cryptographic posture summary table to stdout."""
    counts = report_summary.get("counts", generate_summary_counts(findings))
    risk_score = report_summary.get("risk_score", calculate_quantum_risk_score(findings))
    hygiene = report_summary.get("hygiene_score", calculate_hygiene_score(findings))
    posture = report_summary.get("posture_status", calculate_posture_status(findings))

    posture_icon = {
        "FAILING": "🚨",
        "AT_RISK": "⚠️",
        "SECURE": "✅",
        "NO_DATA": "ℹ️",
    }.get(posture, "•")

    print("\n" + "=" * 60)
    print("        QuantumTrace Post-Quantum Cryptographic Posture")
    print("=" * 60)
    print(f"Posture Status:      {posture_icon} {posture}")
    print(f"Crypto Hygiene:      {hygiene}/100")
    print(f"Quantum Risk Score:  {risk_score}/100.0 (Exposure)")
    print("-" * 60)
    print(f"Total Findings:      {counts.get('Total', 0)}")
    print(f"  Critical:          {counts.get('Critical', 0)}")
    print(f"  Medium:            {counts.get('Medium', 0)}")
    print(f"  Safe:              {counts.get('Safe', 0)}")
    print(f"  Unknown:           {counts.get('Unknown', 0)}")
    print("=" * 60 + "\n")


def execute_pipeline(args: argparse.Namespace) -> int:
    """Execute end-to-end multi-vector scan and return process exit code."""
    findings: list[CryptoFinding] = []

    # Source code scanning
    source_target = args.source
    if args.all and not source_target:
        candidate = Path("support-materials/source-code")
        if candidate.exists():
            source_target = str(candidate)

    if source_target:
        src_path = Path(source_target)
        if src_path.exists():
            try:
                from scanner.source_scanner import scan_file, scan_source_directory
                if src_path.is_dir():
                    findings.extend(scan_source_directory(src_path))
                else:
                    findings.extend(scan_file(src_path))
            except Exception as exc:  # noqa: BLE001 - isolate optional source scan failure
                if args.verbose:
                    print(f"[WARN] Source scan error on {src_path}: {exc}", file=sys.stderr)
        elif args.verbose:
            print(f"[WARN] Source path not found: {source_target}", file=sys.stderr)

    # Enrich findings with centralized risk engine
    enriched_findings: list[CryptoFinding] = []
    for f in findings:
        enriched_findings.append(enrich_finding_risk(f))

    # Generate aggregate metrics
    report = build_report_summary(enriched_findings)
    render_terminal_summary(enriched_findings, report)

    # Persist CBOM if requested
    if args.output:
        serializer = CBOMSerializer(
            scanner_name="OSPF-DR QuantumTrace",
            version="1.0.0",
        )
        for finding in enriched_findings:
            serializer.add_finding(finding)
        cbom_doc = serializer.document
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(cbom_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if args.verbose:
            print(f"[INFO] Exported CBOM to {out_path}", file=sys.stderr)

    # Critical findings indicate risk but do not cause scanner process crash
    return 0


def main(argv: list[str] | None = None) -> int:
    """Primary CLI entrypoint for QuantumTrace scanner."""
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    try:
        return execute_pipeline(args)
    except KeyboardInterrupt:
        print("\n[INFO] Scan aborted by user.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level CLI error boundary
        print(f"[ERROR] Operational error: {exc}", file=sys.stderr)
        return 1
