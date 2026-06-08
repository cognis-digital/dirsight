"""Core engine for DIRSIGHT.

Real logic: parse content-discovery output, normalize into Finding records,
score each for analyst interest, detect soft-404 / wildcard noise, and rank.

No network access -- this module only reads tool output that already exists.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable
from urllib.parse import urlsplit

# --- Heuristics ------------------------------------------------------------

# Path tokens that frequently indicate sensitive / high-value endpoints.
_INTERESTING_TOKENS = {
    "admin": 40, "administrator": 40, "login": 25, "logout": 8,
    "config": 35, "configuration": 35, "settings": 20,
    "backup": 45, "bak": 30, "old": 18, "dump": 40, "sql": 35,
    "db": 25, "database": 30, ".git": 50, ".svn": 45, ".env": 55,
    "secret": 45, "secrets": 45, "key": 30, "keys": 30, "token": 30,
    "password": 45, "passwd": 45, "credential": 40, "private": 30,
    "api": 22, "graphql": 28, "swagger": 30, "openapi": 30,
    "debug": 35, "test": 15, "staging": 20, "dev": 15, "internal": 25,
    "upload": 28, "uploads": 28, "phpinfo": 45, "console": 30,
    "actuator": 35, "wp-admin": 35, "wp-config": 50, "server-status": 35,
    "jenkins": 30, "manager": 25, "shell": 35, "cmd": 30,
}

# File extensions worth a closer look.
_INTERESTING_EXTS = {
    ".sql": 35, ".bak": 35, ".zip": 25, ".tar": 25, ".gz": 20,
    ".log": 25, ".env": 50, ".json": 12, ".xml": 12, ".yml": 18,
    ".yaml": 18, ".config": 30, ".conf": 28, ".ini": 25, ".pem": 45,
    ".key": 45, ".p12": 40, ".pfx": 40, ".db": 30, ".sqlite": 30,
    ".old": 22, ".swp": 30, ".orig": 25,
}

# How much each HTTP status contributes to interest.
_STATUS_WEIGHT = {
    200: 18, 201: 18, 204: 8,
    301: 6, 302: 6, 307: 6, 308: 6,
    401: 30, 403: 28,  # auth-gated -> something is there
    405: 14, 500: 22, 501: 16, 503: 10,
}


@dataclass
class Finding:
    """A single normalized content-discovery result."""
    url: str
    path: str
    status: int
    length: int = -1
    words: int = -1
    lines: int = -1
    redirect: str = ""
    source: str = ""
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    noise: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _path_of(url_or_path: str) -> str:
    if "://" in url_or_path:
        sp = urlsplit(url_or_path)
        p = sp.path or "/"
        if sp.query:
            p += "?" + sp.query
        return p
    return url_or_path if url_or_path.startswith("/") else "/" + url_or_path


def _ext_of(path: str) -> str:
    base = path.split("?", 1)[0].rstrip("/")
    _, ext = os.path.splitext(base)
    return ext.lower()


# --- Parsers ---------------------------------------------------------------

def parse_ffuf_json(text: str) -> list[Finding]:
    """Parse ffuf's `-o out.json -of json` output."""
    data = json.loads(text)
    results = data.get("results", []) if isinstance(data, dict) else data
    findings: list[Finding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("input", {}).get("FUZZ", "") if isinstance(r.get("input"), dict) else r.get("url", "")
        url = r.get("url", url) or ""
        findings.append(
            Finding(
                url=url,
                path=_path_of(url) if url else "/",
                status=int(r.get("status", 0) or 0),
                length=int(r.get("length", -1) if r.get("length") is not None else -1),
                words=int(r.get("words", -1) if r.get("words") is not None else -1),
                lines=int(r.get("lines", -1) if r.get("lines") is not None else -1),
                redirect=str(r.get("redirectlocation", "") or ""),
                source="ffuf",
            )
        )
    return findings


_GOBUSTER_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s*(?P<redir>[^\]]+)\])?",
    re.IGNORECASE,
)


def parse_gobuster_text(text: str, base_url: str = "") -> list[Finding]:
    """Parse gobuster dir plain-text output lines."""
    findings: list[Finding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("=") or line.startswith("["):
            continue
        m = _GOBUSTER_RE.match(line)
        if not m:
            continue
        path = m.group("path")
        status = int(m.group("status"))
        size = int(m.group("size")) if m.group("size") else -1
        redir = (m.group("redir") or "").strip()
        url = base_url.rstrip("/") + path if base_url else path
        findings.append(
            Finding(
                url=url,
                path=_path_of(path),
                status=status,
                length=size,
                redirect=redir,
                source="gobuster",
            )
        )
    return findings


def parse_auto(text: str, base_url: str = "") -> list[Finding]:
    """Detect format and parse. Falls back to gobuster text."""
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return parse_ffuf_json(text)
        except (json.JSONDecodeError, ValueError):
            pass
    return parse_gobuster_text(text, base_url=base_url)


# --- Scoring & noise detection ---------------------------------------------

def _detect_noise(findings: list[Finding]) -> None:
    """Flag likely soft-404 / wildcard noise via response-size clustering.

    If many 200-status responses share an identical body length, that length
    is almost certainly a catch-all/soft-404 page rather than real content.
    """
    lengths = Counter(
        f.length for f in findings
        if f.status in (200, 201) and f.length >= 0
    )
    if not lengths:
        return
    total = sum(lengths.values())
    noisy_lengths = set()
    for length, count in lengths.items():
        # A length shared by >40% of 200s and appearing >=4 times = wildcard.
        if count >= 4 and count / total > 0.40:
            noisy_lengths.add(length)
    for f in findings:
        if f.status in (200, 201) and f.length in noisy_lengths:
            f.noise = True


def score_finding(f: Finding) -> Finding:
    """Compute interest score + human-readable reasons for one finding."""
    score = 0.0
    reasons: list[str] = []

    sw = _STATUS_WEIGHT.get(f.status, 0)
    if sw:
        score += sw
        reasons.append(f"status {f.status} (+{sw})")

    low = f.path.lower()
    matched_tokens = []
    for token, weight in _INTERESTING_TOKENS.items():
        # word-ish boundary match against path segments
        if token in low:
            score += weight
            matched_tokens.append(token)
    if matched_tokens:
        reasons.append("keyword: " + ", ".join(sorted(set(matched_tokens))))

    ext = _ext_of(f.path)
    ew = _INTERESTING_EXTS.get(ext, 0)
    if ew:
        score += ew
        reasons.append(f"extension {ext} (+{ew})")

    # Directory depth: deeper hidden paths are mildly more interesting.
    depth = f.path.strip("/").count("/")
    if depth >= 2:
        score += min(depth * 2, 8)
        reasons.append(f"depth {depth}")

    # Redirect to a login/auth page is a strong tell.
    if f.redirect:
        rl = f.redirect.lower()
        if any(t in rl for t in ("login", "signin", "auth", "sso")):
            score += 15
            reasons.append("redirects to auth")

    if f.noise:
        score *= 0.15
        reasons.append("likely soft-404/wildcard noise")

    f.score = round(score, 2)
    f.reasons = reasons
    return f


def analyze(findings: Iterable[Finding]) -> list[Finding]:
    """Detect noise, score, and rank findings high-to-low."""
    items = list(findings)
    _detect_noise(items)
    for f in items:
        score_finding(f)
    items.sort(key=lambda x: (x.score, x.status == 200), reverse=True)
    return items


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Build an aggregate summary of analyzed findings."""
    by_status = Counter(f.status for f in findings)
    noise = sum(1 for f in findings if f.noise)
    high = [f for f in findings if f.score >= 40 and not f.noise]
    return {
        "total": len(findings),
        "noise": noise,
        "signal": len(findings) - noise,
        "high_interest": len(high),
        "by_status": dict(sorted(by_status.items())),
        "top_score": findings[0].score if findings else 0.0,
    }
