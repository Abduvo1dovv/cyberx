"""HTTP adapter: request construction, scope/redirect, timeout, TLS, no extra flags."""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURES

from cyberx.domain.enums import ActionResultStatus, ActionStatus, PolicyVerdict, Risk
from cyberx.domain.errors import DomainValidationError, ExecutionBypassError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget, PolicyDecision
from cyberx.domain.time import utcnow
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.ports.execution import AuthorizedAction, ExecutionContext
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.request import build_http_argv, url_from_action
from cyberx.recon.http.safety import is_blocked_ssrf, validate_http_url
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse


def _action(url: str = "http://10.10.11.23/", action_type: str = "http_probe") -> Action:
    params = {"url": url} if action_type == "http_probe" else {"url": url}
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type=action_type,
        target=ActionTarget(canonical_locator=url),
        parameters=params,
        reason="probe",
        expected_information_gain=0.8,
        risk=Risk.INFO,
        timeout_s=15,
        status=ActionStatus.AUTHORIZED,
        coverage_key=f"{action_type}:{url}",
        created_at=utcnow(),
    )


def _authorized(action: Action | None = None) -> AuthorizedAction:
    item = action or _action()
    return AuthorizedAction(
        action=item,
        decision=PolicyDecision(verdict=PolicyVerdict.ALLOW, reason_code="allow"),
    )


def _ctx(action: Action, tmp_path, **kwargs) -> ExecutionContext:
    data = {
        "mission_id": action.mission_id,
        "action_id": action.action_id,
        "timeout_s": 15,
        "workdir": str(tmp_path),
        "stub": False,
        "allowed_targets": ["10.10.11.23"],
        "allowed_protocols": ["http", "https"],
    }
    data.update(kwargs)
    return ExecutionContext(**data)


def test_argv_is_get_and_url_only() -> None:
    action = _action()
    argv = build_http_argv(action)
    assert argv == ["GET", "http://10.10.11.23/"]
    assert "User-Agent" not in argv
    assert "--proxy" not in argv


def test_invalid_urls_rejected() -> None:
    with pytest.raises(DomainValidationError):
        validate_http_url("ftp://10.10.11.23/")
    with pytest.raises(DomainValidationError):
        validate_http_url("http://10.10.11.23/;curl evil")
    with pytest.raises(DomainValidationError):
        validate_http_url("http://user:pass@10.10.11.23/")
    with pytest.raises(DomainValidationError):
        validate_http_url("http://169.254.169.254/")
    assert is_blocked_ssrf("169.254.169.254")


def test_arbitrary_headers_rejected() -> None:
    action = _action()
    action = action.model_copy(
        update={"parameters": {"url": "http://10.10.11.23/", "headers": {"X-Evil": "1"}}}
    )
    with pytest.raises(DomainValidationError):
        url_from_action(action)


def test_fixture_get_records_status_and_title(tmp_path) -> None:
    html = (FIXTURES / "http" / "html_200.html").read_text(encoding="utf-8")
    transport = FixtureTransport(
        HttpRawResponse(
            url="http://10.10.11.23/",
            status=200,
            headers={"content-type": "text/html"},
            body=html.encode("utf-8"),
        )
    )
    sink = InMemoryEventSink()
    adapter = HttpAdapter(transport=transport, events=sink)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert artifact.media_type == "application/json"
    assert b'"status":200' in (artifact.body or b"")
    assert b"Box Portal" in (artifact.body or b"")
    types = {e.event_type for e in sink.events}
    assert EventType.HTTP_STARTED in types
    assert EventType.HTTP_COMPLETED in types
    assert all("<?xml" not in str(e.payload) for e in sink.events)
    assert all("<html" not in str(e.payload) for e in sink.events)


def test_in_scope_redirect_followed(tmp_path) -> None:
    transport = FixtureTransport(
        {
            "http://10.10.11.23/": HttpRawResponse(
                url="http://10.10.11.23/",
                status=302,
                headers={"location": "http://10.10.11.23/login"},
            ),
            "http://10.10.11.23/login": HttpRawResponse(
                url="http://10.10.11.23/login",
                status=200,
                headers={"content-type": "text/html"},
                body=b"<html><title>Login</title></html>",
            ),
        }
    )
    adapter = HttpAdapter(transport=transport)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert b'"status":200' in (artifact.body or b"")
    assert b"/login" in (artifact.body or b"")
    assert len(transport.calls) == 2


def test_out_of_scope_redirect_not_followed(tmp_path) -> None:
    transport = FixtureTransport(
        {
            "http://10.10.11.23/": HttpRawResponse(
                url="http://10.10.11.23/",
                status=302,
                headers={"location": "http://evil.example/phish"},
            )
        }
    )
    sink = InMemoryEventSink()
    adapter = HttpAdapter(transport=transport, events=sink)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert len(transport.calls) == 1
    assert EventType.HTTP_REDIRECT_BLOCKED in {e.event_type for e in sink.events}
    assert b"evil.example" in (artifact.body or b"")
    assert b'"followed":false' in (artifact.body or b"") or b'"followed": false' in (
        artifact.body or b""
    )


def test_metadata_redirect_blocked(tmp_path) -> None:
    transport = FixtureTransport(
        HttpRawResponse(
            url="http://10.10.11.23/",
            status=302,
            headers={"location": "http://169.254.169.254/latest/meta-data"},
        )
    )
    adapter = HttpAdapter(transport=transport)
    action = _action()
    adapter.run(action, _ctx(action, tmp_path))
    assert len(transport.calls) == 1


def test_timeout_is_timeout_result(tmp_path) -> None:
    transport = FixtureTransport(
        HttpRawResponse(url="http://10.10.11.23/", timed_out=True, error="timeout")
    )
    adapter = HttpAdapter(transport=transport)
    executor = ReconExecutor(http=adapter, http_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), _ctx(_action(), tmp_path))
    assert outcome.result.status is ActionResultStatus.TIMEOUT
    assert outcome.result.error_code == "timeout"


def test_tls_failure(tmp_path) -> None:
    transport = FixtureTransport(HttpRawResponse(url="https://10.10.11.23/", error="tls_failure"))
    adapter = HttpAdapter(transport=transport)
    action = _action("https://10.10.11.23/")
    executor = ReconExecutor(http=adapter, http_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(action), _ctx(action, tmp_path))
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "tls_failure"


def test_dns_and_connect_failure(tmp_path) -> None:
    adapter = HttpAdapter(
        transport=FixtureTransport(HttpRawResponse(url="http://10.10.11.23/", error="dns_failure"))
    )
    executor = ReconExecutor(http=adapter, http_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), _ctx(_action(), tmp_path))
    assert outcome.result.error_code == "dns_failure"
    adapter = HttpAdapter(
        transport=FixtureTransport(
            HttpRawResponse(url="http://10.10.11.23/", error="connect_failure")
        )
    )
    executor = ReconExecutor(http=adapter, http_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), _ctx(_action(), tmp_path))
    assert outcome.result.error_code == "connect_failure"


def test_executor_rejects_raw_action(tmp_path) -> None:
    executor = ReconExecutor(
        http=HttpAdapter(transport=FixtureTransport(HttpRawResponse(url="x", status=200))),
        http_enabled=True,
        data_dir=str(tmp_path),
    )
    with pytest.raises(ExecutionBypassError):
        executor.execute(_action())  # type: ignore[arg-type]


def test_tech_adapter_fingerprints_from_body(tmp_path) -> None:
    html = (FIXTURES / "http" / "html_200.html").read_bytes()
    transport = FixtureTransport(
        HttpRawResponse(
            url="http://10.10.11.23/",
            status=200,
            headers={"content-type": "text/html"},
            body=html,
        )
    )
    adapter = TechAdapter(transport=transport)
    action = _action(action_type="technology_detection")
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert artifact.adapter_name == "tech_adapter"
    from cyberx.evidence.pipeline import EvidencePipeline

    _obs, evidence = EvidencePipeline().normalize(artifact)
    products = [
        item.claim_preview["object"]["product"]
        for item in evidence
        if item.claim_preview.get("predicate") == "http.tech"
    ]
    assert "wordpress" in products
