"""Injectable chat transport. Does not launch processes. API keys are request headers only."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class TransportResult:
    status: int
    body: bytes
    timed_out: bool = False
    error: str | None = None


class ChatTransport(Protocol):
    def complete(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        timeout_s: float,
        max_bytes: int,
    ) -> TransportResult: ...


class UrllibChatTransport:
    """Stdlib POST JSON. Never logs Authorization."""

    def complete(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        timeout_s: float,
        max_bytes: int,
    ) -> TransportResult:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=max(1.0, float(timeout_s))) as resp:
                body = resp.read(max(1, int(max_bytes)) + 1)
                status = getattr(resp, "status", 200) or 200
                if len(body) > max_bytes:
                    return TransportResult(status=int(status), body=body[:max_bytes])
                return TransportResult(status=int(status), body=body)
        except TimeoutError:
            return TransportResult(status=0, body=b"", timed_out=True, error="timeout")
        except urllib.error.HTTPError as exc:
            snippet = b""
            try:
                snippet = exc.read(1024)
            except Exception:
                snippet = b""
            if exc.code == 429:
                return TransportResult(status=429, body=snippet, error="rate_limit")
            return TransportResult(status=int(exc.code), body=snippet, error="unavailable")
        except urllib.error.URLError:
            return TransportResult(status=0, body=b"", error="unavailable")
        except OSError:
            return TransportResult(status=0, body=b"", error="unavailable")
