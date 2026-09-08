"""Endpoint discovery parser: links, forms, auth, oos, idempotency."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture, shapes

from cyberx.domain.identity import parse_http_url, url_key, url_key_from_string
from cyberx.evidence.parsers.endpoint import EndpointParser
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.model import InMemoryWorldModel


def _html(name: str, locator: str = "http://10.10.11.23/"):
    return artifact_from_fixture(
        f"endpoint/{name}",
        adapter_name="endpoint_adapter",
        media_type="text/html",
        source_locator=locator,
    )


def test_mixed_links_same_scope_only() -> None:
    obs = EndpointParser().parse(_html("links_mixed.html"))
    urls = {o.object for o in obs if o.predicate == "url.seen"}
    assert "url:http://10.10.11.23:80/admin" in urls
    assert "url:http://10.10.11.23:80/api" in urls
    assert "url:http://10.10.11.23:80/profile" in urls
    assert "url:http://10.10.11.23:80/login" in urls
    assert not any("outside.example" in str(u) for u in urls)
    assert not any("javascript" in str(o.object).lower() for o in obs)
    assert not any("mailto" in str(o.object).lower() for o in obs)


def test_query_and_fragment_do_not_change_url_identity() -> None:
    a = url_key_from_string("http://10.10.11.23/profile?ref=home#x")
    b = url_key_from_string("http://10.10.11.23/profile")
    assert a == b
    scheme, host, port, path = parse_http_url("https://Box.HTB:443/login?x=1#y")
    assert url_key(scheme, host, port, path) == "url:https://box.htb:443/login"


def test_duplicate_links_deduped() -> None:
    obs = EndpointParser().parse(_html("links_mixed.html"))
    login = [o for o in obs if o.predicate == "endpoint.seen" and "login" in str(o.object)]
    assert len(login) == 1


def test_get_and_post_forms() -> None:
    obs = EndpointParser().parse(_html("forms.html"))
    methods = [
        o.object["method"]
        for o in obs
        if o.predicate == "endpoint.seen" and isinstance(o.object, dict)
    ]
    assert "GET" in methods
    assert "POST" in methods
    params = {
        o.object["name"] for o in obs if o.predicate == "param.seen" and isinstance(o.object, dict)
    }
    assert {"q", "username", "password", "email", "message"} <= params
    password = next(
        o.object for o in obs if o.predicate == "param.seen" and o.object["name"] == "password"
    )
    assert password["redacted"] is True
    auth = [o.object for o in obs if o.predicate == "auth.seen"]
    assert "http_form" in auth
    contact_auth = [o for o in obs if o.predicate == "auth.seen" and "contact" in o.subject_hint]
    assert contact_auth == []


def test_stored_http_probe_json_with_body() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200_html.json",
        adapter_name="endpoint_adapter",
        media_type="application/json",
        source_locator="http://10.10.11.23/",
    )
    obs = EndpointParser().parse(artifact)
    assert any(o.predicate == "endpoint.seen" for o in obs)
    assert any("login" in str(o.object) for o in obs)


def test_evidence_traceable_to_artifact() -> None:
    artifact = _html("login.html")
    _obs, evidence = EvidencePipeline().normalize(artifact)
    assert evidence
    for ev in evidence:
        assert ev.artifact_id == artifact.artifact_id
        assert ev.tool_run_id == artifact.tool_run_id
        assert ev.parser_id == "endpoint"


def test_world_idempotent_on_replay() -> None:
    from cyberx.domain.ids import PREFIX_MISSION, new_id

    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    artifact = artifact_from_fixture(
        "endpoint/forms.html",
        adapter_name="endpoint_adapter",
        media_type="text/html",
        source_locator="http://10.10.11.23/",
        mission_id=mid,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)
    urls = {u.canonical_key for u in world.get_web_surfaces()}
    endpoints = {e.canonical_key for e in world.get_endpoints()}
    params = {p.canonical_key for p in world.get_parameters()}
    auths = {a.canonical_key for a in world.get_auth_surfaces()}
    for item in evidence:
        world.apply_evidence(item)
    assert {u.canonical_key for u in world.get_web_surfaces()} == urls
    assert {e.canonical_key for e in world.get_endpoints()} == endpoints
    assert {p.canonical_key for p in world.get_parameters()} == params
    assert {a.canonical_key for a in world.get_auth_surfaces()} == auths


def test_parser_shapes_stable() -> None:
    artifact = _html("login.html")
    assert shapes(EndpointParser().parse(artifact)) == shapes(EndpointParser().parse(artifact))
