"""Redact secret-shaped values before they become Observations."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from cyberx.domain.identity import is_secret_shaped_name, is_secret_shaped_value
from cyberx.domain.models.common import DomainModel

REDACTED = "[REDACTED]"

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)(\b(?:bearer|basic)\s+)(\S+)")

_ALWAYS_REDACT_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
)


class SecretRef(DomainModel):
    """Metadata only — never stores the secret value (SPEC §10.3)."""

    kind: str
    location_hint: str
    sha256: str


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class Redactor:
    def redact_text(self, text: str, *, location: str = "text") -> tuple[str, list[SecretRef]]:
        refs: list[SecretRef] = []
        out = text

        def _sub_pem(pattern: re.Pattern[str], kind: str, current: str) -> str:
            def repl(match: re.Match[str]) -> str:
                refs.append(
                    SecretRef(kind=kind, location_hint=location, sha256=_digest(match.group(0)))
                )
                return REDACTED

            return pattern.sub(repl, current)

        out = _sub_pem(_PEM, "pem", out)
        out = _sub_pem(_PEM_CERT, "pem", out)

        def jwt_repl(match: re.Match[str]) -> str:
            refs.append(
                SecretRef(kind="jwt", location_hint=location, sha256=_digest(match.group(0)))
            )
            return REDACTED

        out = _JWT.sub(jwt_repl, out)

        def bearer_repl(match: re.Match[str]) -> str:
            refs.append(
                SecretRef(kind="token", location_hint=location, sha256=_digest(match.group(2)))
            )
            return match.group(1) + REDACTED

        out = _BEARER.sub(bearer_repl, out)
        return out, refs

    def redact_header(self, name: str, value: str) -> tuple[str, list[SecretRef]]:
        key = name.lower()
        if (
            key in _ALWAYS_REDACT_HEADERS
            or is_secret_shaped_name(name)
            or is_secret_shaped_value(value)
        ):
            return REDACTED, [
                SecretRef(kind="header", location_hint=f"header:{key}", sha256=_digest(value))
            ]
        return self.redact_text(value, location=f"header:{key}")

    def redact(self, value: Any, *, location: str = "object") -> Any:
        if value is None or isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, str):
            redacted, _refs = self.redact_text(value, location=location)
            return redacted
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                key_s = str(key)
                if is_secret_shaped_name(key_s) or (
                    isinstance(item, str) and is_secret_shaped_value(item)
                ):
                    out[key_s] = REDACTED
                else:
                    out[key_s] = self.redact(item, location=f"{location}.{key_s}")
            return out
        if isinstance(value, list):
            return [self.redact(item, location=f"{location}[]") for item in value]
        return value


DEFAULT_REDACTOR = Redactor()
