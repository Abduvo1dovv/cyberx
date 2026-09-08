"""Conservative recon-signal classification. Signals are not vulnerabilities."""

from __future__ import annotations

from cyberx.domain.identity import parse_http_url

# Investigation-priority weights. Unknown labels fall back to SIGNAL_WEIGHT_DEFAULT.
SIGNAL_WEIGHT: dict[str, float] = {
    "admin_surface": 0.95,
    "management_surface": 0.92,
    "auth_surface": 0.90,
    "backup_looking_path": 0.88,
    "api_surface": 0.82,
    "upload_surface": 0.80,
    "debug_surface": 0.78,
    "internal_surface": 0.75,
    "directory_listing": 0.72,
    "unusual_service": 0.70,
    "interesting_endpoint": 0.65,
    "version_disclosure": 0.60,
    "unusual_status": 0.55,
    "unusual_redirect": 0.50,
    "exposed_service": 0.45,
    "tech_observed": 0.35,
    "open_port": 0.40,
    "interesting_path": 0.55,
    "technology": 0.40,
    "anomaly": 0.50,
}
SIGNAL_WEIGHT_DEFAULT = 0.40

_SIGNAL_TITLE: dict[str, str] = {
    "admin_surface": "Admin surface discovered",
    "management_surface": "Management surface discovered",
    "auth_surface": "Authentication surface discovered",
    "backup_looking_path": "Backup-looking path discovered",
    "api_surface": "API surface discovered",
    "upload_surface": "Upload surface discovered",
    "debug_surface": "Debug surface discovered",
    "internal_surface": "Internal surface discovered",
    "directory_listing": "Directory listing discovered",
    "unusual_service": "Unusual service discovered",
    "interesting_endpoint": "Interesting endpoint discovered",
    "version_disclosure": "Version disclosure observed",
    "unusual_status": "Unusual status observed",
    "unusual_redirect": "Unusual redirect observed",
    "exposed_service": "Exposed service discovered",
    "tech_observed": "Technology observed",
}

# First-path-segment tokens only. Intentionally small and conservative.
_PATH_TOKENS: dict[str, str] = {
    "admin": "admin_surface",
    "administrator": "admin_surface",
    "wp-admin": "admin_surface",
    "phpmyadmin": "admin_surface",
    "login": "auth_surface",
    "signin": "auth_surface",
    "sign-in": "auth_surface",
    "auth": "auth_surface",
    "oauth": "auth_surface",
    "sso": "auth_surface",
    "api": "api_surface",
    "graphql": "api_surface",
    "swagger": "api_surface",
    "openapi": "api_surface",
    "backup": "backup_looking_path",
    "backups": "backup_looking_path",
    "dump": "backup_looking_path",
    "upload": "upload_surface",
    "uploads": "upload_surface",
    "debug": "debug_surface",
    "test": "debug_surface",
    "testing": "debug_surface",
    "phpinfo": "debug_surface",
    "internal": "internal_surface",
    "private": "internal_surface",
    "management": "management_surface",
    "manager": "management_surface",
    "dashboard": "management_surface",
    "panel": "management_surface",
    "cpanel": "management_surface",
}

_BACKUP_SUFFIXES = (
    ".bak",
    ".old",
    ".sql",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".dump",
)

# Open ports that are ordinary internet-facing services, not "unusual".
_COMMON_PORTS = frozenset({21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995})
_UNUSUAL_PORTS = frozenset(
    {
        23,
        161,
        445,
        1433,
        1521,
        2049,
        2375,
        2376,
        3306,
        3389,
        5432,
        5900,
        6379,
        6443,
        9200,
        11211,
        27017,
    }
)

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


def signal_weight(signal: str) -> float:
    if not signal:
        return SIGNAL_WEIGHT_DEFAULT
    return SIGNAL_WEIGHT.get(signal, SIGNAL_WEIGHT_DEFAULT)


def signal_title(signal: str, detail: str = "") -> str:
    base = _SIGNAL_TITLE.get(signal, "Reconnaissance signal observed")
    if detail:
        title = f"{base}: {detail}"
    else:
        title = base
    return title[:200]


def classify_path(path: str | None) -> str | None:
    if not path:
        return None
    token = _first_segment(path)
    if not token:
        return None
    if token in _PATH_TOKENS:
        return _PATH_TOKENS[token]
    last = _last_segment(path)
    lowered = last.lower()
    if any(lowered.endswith(suffix) for suffix in _BACKUP_SUFFIXES):
        return "backup_looking_path"
    return None


def classify_http_status(status: int | None, path: str = "/") -> str | None:
    if status is None:
        return None
    if 500 <= int(status) <= 599:
        return "unusual_status"
    if int(status) in _REDIRECT_STATUS:
        return "unusual_redirect"
    return classify_path(path)


def classify_port(number: int) -> str:
    if int(number) in _UNUSUAL_PORTS:
        return "unusual_service"
    if int(number) in _COMMON_PORTS:
        return "exposed_service"
    return "exposed_service"


def classify_title(title: str | None) -> str | None:
    if not title:
        return None
    lowered = title.lower()
    if "index of" in lowered or "directory listing" in lowered:
        return "directory_listing"
    return None


def path_from_locator(locator: str) -> str:
    text = locator.strip()
    if text.startswith("url:"):
        text = text[4:]
    if text.startswith("ep:"):
        _, _, rest = text.partition(":")
        _, _, rest = rest.partition(":")
        text = rest
    try:
        return parse_http_url(text)[3]
    except Exception:
        if "/" in text:
            idx = text.find("/", text.find("://") + 3) if "://" in text else text.find("/")
            if idx >= 0:
                return text[idx:] or "/"
        return "/"


def _first_segment(path: str) -> str:
    text = path.strip().split("?", 1)[0].split("#", 1)[0]
    parts = [part for part in text.split("/") if part]
    if not parts:
        return ""
    return parts[0].lower()


def _last_segment(path: str) -> str:
    text = path.strip().split("?", 1)[0].split("#", 1)[0]
    parts = [part for part in text.split("/") if part]
    if not parts:
        return ""
    return parts[-1]
