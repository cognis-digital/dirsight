"""DIRSIGHT - signal from dirbusting noise.

Defensive / authorized-testing analysis tool. Parses web content-discovery
output (ffuf JSON, gobuster text) and ranks endpoints so an analyst can
triage the interesting findings out of the noise. Analysis only -- it never
makes any network requests of its own.
"""
from .core import (
    Finding,
    parse_ffuf_json,
    parse_gobuster_text,
    parse_auto,
    score_finding,
    analyze,
    summarize,
)

TOOL_NAME = "dirsight"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "parse_ffuf_json",
    "parse_gobuster_text",
    "parse_auto",
    "score_finding",
    "analyze",
    "summarize",
]
