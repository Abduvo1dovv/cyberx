"""endpoint_discovery adapter. Parses stored HTTP artifacts. No network."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from cyberx.actions.params import EndpointDiscoveryParams
from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import parse_http_url
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.http.safety import canonical_url, validate_http_url


class HtmlArtifactSource(Protocol):
    def load(self, *, mission_id: str, url: str) -> dict[str, Any] | None: ...


class FixtureHtmlSource:
    """Test double. Maps canonical URL → stored probe JSON or HTML string."""

    def __init__(self, pages: dict[str, dict[str, Any] | str | bytes]) -> None:
        self._pages = dict(pages)

    def load(self, *, mission_id: str, url: str) -> dict[str, Any] | None:
        del mission_id
        hit = self._pages.get(url)
        if hit is None:
            for key, value in self._pages.items():
                if _same_page(key, url):
                    hit = value
                    break
        if hit is None:
            return None
        if isinstance(hit, dict):
            return dict(hit)
        if isinstance(hit, bytes):
            text = hit.decode("utf-8", errors="replace")
        else:
            text = str(hit)
        return {"url": url, "html": text}


class EndpointAdapter:
    name = "endpoint_adapter"
    action_types: tuple[str, ...] = ("endpoint_discovery",)

    def __init__(
        self,
        *,
        source: HtmlArtifactSource | None = None,
        available: bool | None = True,
    ) -> None:
        self._source = source
        self._forced_available = available
        self._last_argv: list[str] = []
        self._last_result: Any = None

    def is_available(self) -> bool:
        if self._forced_available is not None:
            return self._forced_available
        return True

    def build_argv(self, action: Action) -> list[str]:
        url = _url_from_endpoint_action(action)
        argv = ["parse-artifact", url]
        self._last_argv = argv
        return argv

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        if action.action_type != "endpoint_discovery":
            raise DomainValidationError("endpoint adapter only runs endpoint_discovery")
        url = _url_from_endpoint_action(action)
        payload = None
        if self._source is not None:
            payload = self._source.load(mission_id=action.mission_id, url=url)
        if payload is None:
            payload = _load_from_workdir(ctx.workdir, url)
        if payload is None:
            payload = {"url": url, "endpoints": []}
        if "url" not in payload:
            payload["url"] = url
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._last_argv = ["parse-artifact", url]
        self._last_result = type("Meta", (), {"timed_out": False, "error": None, "status": 0})()
        path = None
        if ctx.workdir:
            dest = Path(ctx.workdir) / "artifacts" / "endpoint.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            path = str(dest)
        return RawArtifact(
            artifact_id=new_id(PREFIX_ARTIFACT),
            tool_run_id=new_id(PREFIX_TOOL_RUN),
            adapter_name=self.name,
            media_type="application/json",
            sha256=hashlib.sha256(raw).hexdigest(),
            byte_size=len(raw),
            body=raw,
            path=path,
            mission_id=action.mission_id,
            source_locator=url,
        )


def _url_from_endpoint_action(action: Action) -> str:
    params = EndpointDiscoveryParams.model_validate(action.parameters)
    raw = params.url or action.target.canonical_locator
    if not raw:
        raise DomainValidationError("endpoint_discovery requires a url")
    return validate_http_url(raw)


def _load_from_workdir(workdir: str | None, url: str) -> dict[str, Any] | None:
    if not workdir:
        return None
    root = Path(workdir)
    candidates = list(root.glob("artifacts/*/response.meta.json"))
    candidates.extend(root.glob("artifacts/*.bin"))
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        stored = data.get("final_url") or data.get("url") or data.get("target")
        if isinstance(stored, str) and _same_page(stored, url):
            return data
        if data.get("html") or data.get("body") or data.get("endpoints"):
            if not stored:
                continue
    return None


def _same_page(left: str, right: str) -> bool:
    try:
        return parse_http_url(left) == parse_http_url(right)
    except IdentityError:
        try:
            return canonical_url(left) == canonical_url(right)
        except Exception:
            return left.rstrip("/") == right.rstrip("/")
