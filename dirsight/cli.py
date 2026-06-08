"""Command-line interface for DIRSIGHT.

Usage:
    dirsight analyze <file> [--source auto|ffuf|gobuster] [--base-url URL]
                            [--format table|json] [--min-score N]
    dirsight --version

Exit codes:
    0  ran successfully, no high-interest findings
    1  internal error / bad input
    2  high-interest findings present (intended for CI gating)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze, parse_auto, parse_ffuf_json, parse_gobuster_text, summarize


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _render_table(findings, summary, min_score: float) -> str:
    lines = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - signal from dirbusting noise")
    lines.append(
        "total={total} signal={signal} noise={noise} "
        "high_interest={high_interest}".format(**summary)
    )
    lines.append("")
    header = f"{'SCORE':>6}  {'STATUS':>6}  {'LEN':>8}  PATH"
    lines.append(header)
    lines.append("-" * max(len(header), 40))
    shown = 0
    for f in findings:
        if f.score < min_score:
            continue
        shown += 1
        flag = " [noise]" if f.noise else ""
        length = f.length if f.length >= 0 else "-"
        lines.append(f"{f.score:>6.1f}  {f.status:>6}  {str(length):>8}  {f.path}{flag}")
        if f.reasons:
            lines.append(f"        -> {'; '.join(f.reasons)}")
    if shown == 0:
        lines.append("(no findings at or above min-score)")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Analyze ffuf/gobuster content-discovery output into "
                    "ranked endpoints (defensive / authorized testing only).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    an = sub.add_parser("analyze", help="parse and rank a results file")
    an.add_argument("file", help="results file (or '-' for stdin)")
    an.add_argument("--source", choices=("auto", "ffuf", "gobuster"),
                    default="auto", help="input format (default: auto-detect)")
    an.add_argument("--base-url", default="",
                    help="base URL to prefix gobuster paths")
    an.add_argument("--format", choices=("table", "json"), default="table",
                    help="output format")
    an.add_argument("--min-score", type=float, default=0.0,
                    help="only show findings with score >= N")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":
        parser.print_help()
        return 1

    try:
        text = _read(args.file)
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1

    try:
        if args.source == "ffuf":
            findings = parse_ffuf_json(text)
        elif args.source == "gobuster":
            findings = parse_gobuster_text(text, base_url=args.base_url)
        else:
            findings = parse_auto(text, base_url=args.base_url)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: failed to parse input: {exc}", file=sys.stderr)
        return 1

    ranked = analyze(findings)
    summary = summarize(ranked)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "findings": [
                f.to_dict() for f in ranked if f.score >= args.min_score
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(_render_table(ranked, summary, args.min_score))

    # CI-friendly: non-zero exit when high-interest findings exist.
    return 2 if summary["high_interest"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
