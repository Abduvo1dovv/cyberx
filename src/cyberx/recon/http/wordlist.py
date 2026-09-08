"""Fixed v1 directory wordlist. Closed, depth-1, ≤ 50 names. No operator expansion."""

from __future__ import annotations

from cyberx.domain.identity import parse_http_url
from cyberx.recon.http.safety import canonical_url

# SPEC §5.6.8 plus a few conservative depth-1 names. Order is coverage-stable.
DEFAULT_DIRECTORY_LABELS: tuple[str, ...] = (
    "admin",
    "login",
    "robots.txt",
    "sitemap.xml",
    ".git",
    "backup",
    "api",
    "uploads",
    "images",
    "css",
    "js",
    "server-status",
    ".well-known",
    "console",
    "actuator",
    "phpmyadmin",
    "wp-admin",
    "wp-login.php",
    "config",
    "backup.zip",
    "admin.php",
    "static",
    "assets",
    "files",
    "tmp",
    "test",
    "dev",
    "hidden",
    "private",
    "secret",
    "data",
    "db",
    "sql",
    "dump",
    "old",
    "new",
    "portal",
    "manager",
    "status",
    "health",
    "metrics",
    "debug",
    "trace",
    "cgi-bin",
    "includes",
    "vendor",
    "node_modules",
    "env",
    ".env",
    "README.md",
)

assert len(DEFAULT_DIRECTORY_LABELS) <= 50
assert len(set(DEFAULT_DIRECTORY_LABELS)) == len(DEFAULT_DIRECTORY_LABELS)

MAX_DIRECTORY_CANDIDATES = 50
_FORBIDDEN_SCHEMES = ("http://", "https://", "javascript:", "data:", "mailto:", "file:")


def normalize_label(raw: str) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    lowered = text.lower()
    if any(lowered.startswith(scheme) for scheme in _FORBIDDEN_SCHEMES):
        return None
    if any(ch in text for ch in " \t\n\r;|`$(){}<>\\\"'"):
        return None
    if "\\" in text or "://" in text:
        return None
    if text.startswith("//"):
        return None
    trimmed = text.lstrip("/")
    if not trimmed or trimmed in {".", ".."}:
        return None
    if ".." in trimmed.split("/"):
        return None
    parts = [p for p in trimmed.split("/") if p]
    if len(parts) != 1:
        return None
    label = parts[0]
    if len(label) > 64:
        return None
    return label


def default_labels(*, limit: int = MAX_DIRECTORY_CANDIDATES) -> tuple[str, ...]:
    cap = max(1, min(int(limit), MAX_DIRECTORY_CANDIDATES))
    return DEFAULT_DIRECTORY_LABELS[:cap]


def candidate_urls(
    base_url: str, *, limit: int = MAX_DIRECTORY_CANDIDATES
) -> list[tuple[str, str]]:
    """Return (path, absolute_url) pairs, depth 1 off the base URL."""
    scheme, host, port, path = parse_http_url(base_url)
    parent = path.rstrip("/")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label in default_labels(limit=limit):
        cleaned = normalize_label(label)
        if cleaned is None:
            continue
        npath = f"{parent}/{cleaned}" if parent else f"/{cleaned}"
        if npath in seen:
            continue
        seen.add(npath)
        url = canonical_url(f"{scheme}://{host}:{port}{npath}")
        out.append((npath, url))
        if len(out) >= limit:
            break
    return out


def canary_urls(base_url: str) -> list[tuple[str, str]]:
    scheme, host, port, path = parse_http_url(base_url)
    parent = path.rstrip("/")
    tokens = ("a9f3e1", "b7c2d0", "c1e4aa")
    rows: list[tuple[str, str]] = []
    for token in tokens:
        npath = f"{parent}/__cx_no_such_{token}" if parent else f"/__cx_no_such_{token}"
        url = canonical_url(f"{scheme}://{host}:{port}{npath}")
        rows.append((npath, url))
    return rows
