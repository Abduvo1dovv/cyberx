"""HTTP transport. Stdlib http.client only. Never follows redirects."""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass
class HttpRawResponse:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    timed_out: bool = False
    error: str | None = None
    tls_enabled: bool = False
    tls_version: str | None = None


@dataclass
class PreparedRequest:
    method: str
    scheme: str
    host: str
    port: int
    path: str
    url: str
    timeout_s: int
    max_body: int
    tls_verify: bool
    user_agent: str


class StdlibTransport:
    """One GET/HEAD. Redirects are the adapter's job."""

    def request(self, spec: PreparedRequest) -> HttpRawResponse:
        headers = {
            "User-Agent": spec.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        conn: http.client.HTTPConnection | None = None
        try:
            if spec.scheme == "https":
                context = ssl.create_default_context()
                if not spec.tls_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    spec.host,
                    spec.port,
                    timeout=spec.timeout_s,
                    context=context,
                )
            else:
                conn = http.client.HTTPConnection(spec.host, spec.port, timeout=spec.timeout_s)
            conn.request(spec.method, spec.path or "/", headers=headers)
            resp = conn.getresponse()
            body, truncated = _read_capped(resp, spec.max_body)
            raw_headers = {k.lower(): v for k, v in resp.getheaders()}
            tls_version = None
            if spec.scheme == "https" and getattr(conn, "sock", None) is not None:
                tls_obj = getattr(conn.sock, "version", None)
                if callable(tls_obj):
                    tls_version = tls_obj()
            return HttpRawResponse(
                url=spec.url,
                status=int(resp.status),
                headers=raw_headers,
                body=body,
                truncated=truncated,
                tls_enabled=spec.scheme == "https",
                tls_version=tls_version,
            )
        except TimeoutError:
            return HttpRawResponse(url=spec.url, timed_out=True, error="timeout")
        except ssl.SSLError:
            return HttpRawResponse(url=spec.url, error="tls_failure")
        except OSError as exc:
            name = type(exc).__name__
            if name in {"timeout", "TimeoutError"} or "timed out" in str(exc).lower():
                return HttpRawResponse(url=spec.url, timed_out=True, error="timeout")
            if name == "gaierror" or "name or service not known" in str(exc).lower():
                return HttpRawResponse(url=spec.url, error="dns_failure")
            return HttpRawResponse(url=spec.url, error="connect_failure")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass


class FixtureTransport:
    """Test double. Maps canonical URL → canned response. No network."""

    def __init__(self, responses: Mapping[str, HttpRawResponse] | HttpRawResponse) -> None:
        if isinstance(responses, HttpRawResponse):
            self._responses: dict[str, HttpRawResponse] = {"*": responses}
        else:
            self._responses = dict(responses)
        self.calls: list[PreparedRequest] = []

    def request(self, spec: PreparedRequest) -> HttpRawResponse:
        self.calls.append(spec)
        hit = self._responses.get(spec.url) or self._responses.get("*")
        if hit is None:
            for key, value in self._responses.items():
                if key.rstrip("/") == spec.url.rstrip("/"):
                    hit = value
                    break
        if hit is None:
            return HttpRawResponse(url=spec.url, error="connect_failure")
        return HttpRawResponse(
            url=spec.url,
            status=hit.status,
            headers=dict(hit.headers),
            body=hit.body,
            truncated=hit.truncated,
            timed_out=hit.timed_out,
            error=hit.error,
            tls_enabled=hit.tls_enabled or spec.scheme == "https",
            tls_version=hit.tls_version,
        )


def _read_capped(resp: http.client.HTTPResponse, max_body: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    remaining = max(0, int(max_body))
    truncated = False
    while True:
        chunk = resp.read(65536 if remaining > 65536 else remaining + 1)
        if not chunk:
            break
        if len(chunk) > remaining:
            if remaining:
                chunks.append(chunk[:remaining])
            truncated = True
            break
        chunks.append(chunk)
        remaining -= len(chunk)
        if remaining <= 0:
            extra = resp.read(1)
            if extra:
                truncated = True
            break
    return b"".join(chunks), truncated
