"""Conservative technology fingerprints from headers/body. No network, no AI."""

from __future__ import annotations

import re
from typing import Any

from cyberx.domain.identity import product_slug

_SERVER_VER = re.compile(r"^([A-Za-z0-9._-]+)(?:/([A-Za-z0-9._-]+))?")
_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_GENERATOR_REV = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
    re.IGNORECASE,
)

_BODY_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("wp-content/", "wordpress", "body"),
    ("wp-includes/", "wordpress", "body"),
    ("wp-json", "wordpress", "body"),
    ("xmlrpc.php", "wordpress", "body"),
    ("csrfmiddlewaretoken", "django", "body"),
    ("__VIEWSTATE", "asp-net", "body"),
    ("drupal-settings-json", "drupal", "body"),
    ("sites/default/files", "drupal", "body"),
    ("laravel_session", "laravel", "cookie"),
    ("joomla", "joomla", "body"),
)

_COOKIE_MARKERS: tuple[tuple[str, str], ...] = (
    ("phpsessid", "php"),
    ("jsessionid", "java"),
    ("wordpress_", "wordpress"),
    ("django", "django"),
    ("laravel_session", "laravel"),
)


def detect_technologies(headers: dict[str, Any], body: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(product: str, source: str, version: str | None = None) -> None:
        try:
            slug = product_slug(product)
        except Exception:
            return
        key = (slug, source)
        if key in seen:
            return
        seen.add(key)
        item: dict[str, str] = {"product": slug, "source": source}
        if version:
            item["version"] = version[:32]
        found.append(item)

    server = str((headers or {}).get("server") or "")
    match = _SERVER_VER.match(server.strip())
    if match and match.group(1):
        add(match.group(1), "header", match.group(2))

    powered = str((headers or {}).get("x-powered-by") or "")
    match = _SERVER_VER.match(powered.strip())
    if match and match.group(1):
        add(match.group(1), "header", match.group(2))

    generator = str((headers or {}).get("x-generator") or "")
    if generator.strip():
        parts = generator.strip().split()
        add(parts[0], "header", parts[1] if len(parts) > 1 else None)

    text = body or ""
    gen_match = _GENERATOR.search(text) or _GENERATOR_REV.search(text)
    if gen_match:
        raw = gen_match.group(1).strip()
        parts = raw.split()
        version = None
        if len(parts) >= 2 and any(ch.isdigit() for ch in parts[-1]):
            version = parts[-1]
            product = " ".join(parts[:-1])
        else:
            product = raw
        add(product, "body", version)

    lowered = text.lower()
    for marker, product, source in _BODY_MARKERS:
        if marker.lower() in lowered:
            add(product, source)

    cookie = str((headers or {}).get("set-cookie") or "")
    cookie_l = cookie.lower()
    for marker, product in _COOKIE_MARKERS:
        if marker in cookie_l:
            add(product, "cookie")
    return found
