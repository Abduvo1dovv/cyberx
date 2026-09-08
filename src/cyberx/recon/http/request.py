"""Build a deterministic GET request from a validated Action. No I/O."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from pydantic import ValidationError

from cyberx.actions.params import (
    DirectoryEnumerationParams,
    HttpProbeParams,
    TechnologyDetectionParams,
)
from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import parse_http_url
from cyberx.domain.models.actions import Action
from cyberx.recon.http.safety import canonical_url, validate_http_url
from cyberx.recon.http.transport import PreparedRequest

ALLOWED_METHODS = ("GET",)
HTTP_ACTION_TYPES = ("http_probe", "technology_detection")


def url_from_action(action: Action) -> str:
    if action.action_type == "http_probe":
        try:
            params = HttpProbeParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid http_probe parameters") from exc
        if params.url:
            return validate_http_url(params.url)
        locator = action.target.canonical_locator or ""
        if locator.startswith("http://") or locator.startswith("https://"):
            return validate_http_url(locator)
        if not params.scheme or not params.port:
            raise DomainValidationError("http_probe requires url or host+port+scheme")
        host = locator or ""
        if not host:
            raise DomainValidationError("http_probe missing host")
        return validate_http_url(f"{params.scheme}://{host}:{params.port}/")
    if action.action_type == "technology_detection":
        try:
            params = TechnologyDetectionParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid technology_detection parameters") from exc
        if params.url:
            return validate_http_url(params.url)
        locator = action.target.canonical_locator or ""
        if locator.startswith("http://") or locator.startswith("https://"):
            return validate_http_url(locator)
        raise DomainValidationError("technology_detection requires a url")
    if action.action_type == "endpoint_discovery":
        locator = action.target.canonical_locator or ""
        if locator.startswith("http://") or locator.startswith("https://"):
            return validate_http_url(locator)
        raw = action.parameters.get("url")
        if isinstance(raw, str) and raw:
            return validate_http_url(raw)
        raise DomainValidationError("endpoint_discovery requires a url")
    if action.action_type == "directory_enumeration":
        try:
            params = DirectoryEnumerationParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid directory_enumeration parameters") from exc
        if params.url:
            return validate_http_url(params.url)
        locator = action.target.canonical_locator or ""
        if locator.startswith("http://") or locator.startswith("https://"):
            return validate_http_url(locator)
        raise DomainValidationError("directory_enumeration requires a url")
    raise DomainValidationError(f"http adapter does not run {action.action_type}")


def prepare_get(
    url: str,
    *,
    timeout_s: int,
    max_body: int,
    tls_verify: bool,
    user_agent: str,
) -> PreparedRequest:
    cleaned = validate_http_url(url)
    scheme, host, port, path = parse_http_url(cleaned)
    parts = urlsplit(cleaned)
    request_path = parts.path or "/"
    if parts.query:
        request_path = f"{request_path}?{parts.query}"
    return PreparedRequest(
        method="GET",
        scheme=scheme,
        host=host,
        port=port,
        path=request_path,
        url=cleaned,
        timeout_s=max(1, int(timeout_s)),
        max_body=max_body,
        tls_verify=tls_verify,
        user_agent=user_agent,
    )


def resolve_redirect(current_url: str, location: str) -> str:
    if not location or not location.strip():
        raise DomainValidationError("empty redirect location")
    joined = urljoin(current_url, location.strip())
    try:
        return canonical_url(joined)
    except IdentityError as exc:
        raise DomainValidationError("redirect location is not a valid http url") from exc


def build_http_argv(action: Action) -> list[str]:
    url = url_from_action(action)
    return ["GET", url]
