from __future__ import annotations

import pytest
from tests.conftest import artifact_from_fixture, load_golden, shapes

from cyberx.domain.enums import V1_ACTION_TYPES
from cyberx.domain.errors import ParseError
from cyberx.evidence.parsers.directory import DirectoryParser
from cyberx.evidence.parsers.dns import DnsParser
from cyberx.evidence.parsers.endpoint import EndpointParser
from cyberx.evidence.parsers.http_probe import HttpProbeParser
from cyberx.evidence.parsers.stub import StubParser
from cyberx.evidence.parsers.tech import TechnologyParser
from cyberx.evidence.redactor import REDACTED


def test_http_probe_200_golden() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
        source_locator="http://10.10.11.23/",
    )
    got = shapes(HttpProbeParser().parse(artifact))
    assert got == load_golden("http/probe_200.golden.json")
    assert shapes(HttpProbeParser().parse(artifact)) == got


def test_http_redirect_recorded_not_followed() -> None:
    artifact = artifact_from_fixture(
        "http/probe_redirect.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    got = shapes(HttpProbeParser().parse(artifact))
    ukey = "url:http://10.10.11.23:80/"
    assert {
        "predicate": "http.redirect",
        "subject_hint": ukey,
        "object": "http://10.10.11.23/login",
    } in got
    assert not any(
        item["predicate"] == "url.seen" and "login" in str(item["object"]) for item in got
    )


def test_http_secrets_redacted() -> None:
    artifact = artifact_from_fixture(
        "http/probe_with_secrets.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    headers = [
        item["object"]
        for item in shapes(HttpProbeParser().parse(artifact))
        if item["predicate"] == "http.header"
    ]
    values = {item["name"]: item["value"] for item in headers}
    assert values["authorization"] == REDACTED
    assert values["set-cookie"] == REDACTED
    assert values["server"] == "nginx"
    blob = str(shapes(HttpProbeParser().parse(artifact)))
    assert "eyJ" not in blob
    assert "super-secret-value" not in blob


def test_http_malformed_json_fails_closed() -> None:
    from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_MISSION, PREFIX_TOOL_RUN, new_id
    from cyberx.ports.execution import RawArtifact

    artifact = RawArtifact(
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        adapter_name="http_adapter",
        media_type="application/json",
        sha256="0" * 64,
        byte_size=4,
        body=b"{no",
        mission_id=new_id(PREFIX_MISSION),
    )
    with pytest.raises(ParseError) as err:
        HttpProbeParser().parse(artifact)
    assert err.value.code == "invalid_json"


def test_dns_a_aaaa_golden() -> None:
    artifact = artifact_from_fixture(
        "dns/a_record.json",
        adapter_name="dns_adapter",
        media_type="application/json",
        source_locator="box.htb",
    )
    got = shapes(DnsParser().parse(artifact))
    assert got == load_golden("dns/a_record.golden.json")


def test_dns_empty_is_completed_empty() -> None:
    artifact = artifact_from_fixture(
        "dns/empty.json",
        adapter_name="dns_adapter",
        media_type="application/json",
    )
    assert DnsParser().parse(artifact) == []


def test_dns_subdomains() -> None:
    artifact = artifact_from_fixture(
        "dns/subdomains.json",
        adapter_name="subdomain_adapter",
        media_type="application/json",
    )
    got = shapes(DnsParser().parse(artifact))
    assert {
        "predicate": "dns.subdomain",
        "subject_hint": "subdomain:www.box.htb",
        "object": "www.box.htb",
    } in got
    assert {
        "predicate": "dns.subdomain",
        "subject_hint": "subdomain:admin.box.htb",
        "object": "admin.box.htb",
    } in got


def test_directory_paths_and_404() -> None:
    artifact = artifact_from_fixture(
        "directory/paths.json",
        adapter_name="directory_adapter",
        media_type="application/json",
    )
    observations = DirectoryParser().parse(artifact)
    got = shapes(observations)
    admin = "url:http://10.10.11.23:80/admin"
    nope = "url:http://10.10.11.23:80/nope"
    assert {"predicate": "url.seen", "subject_hint": admin, "object": admin} in got
    assert {"predicate": "http.status", "subject_hint": admin, "object": 401} in got
    assert {"predicate": "http.status", "subject_hint": nope, "object": 404} in got
    four_oh_four = next(
        o for o in observations if o.subject_hint == nope and o.predicate == "url.seen"
    )
    assert four_oh_four.extra["status"] == 404


def test_technology_parser() -> None:
    artifact = artifact_from_fixture(
        "tech/nginx.json",
        adapter_name="tech_adapter",
        media_type="application/json",
    )
    got = shapes(TechnologyParser().parse(artifact))
    ukey = "url:http://10.10.11.23:80/"
    assert {
        "predicate": "http.tech",
        "subject_hint": ukey,
        "object": {"product": "nginx", "version": "1.24.0", "source": "header"},
    } in got
    assert {
        "predicate": "http.tech",
        "subject_hint": ukey,
        "object": {"product": "php", "version": "8.1", "source": "body"},
    } in got


def test_endpoint_json() -> None:
    artifact = artifact_from_fixture(
        "endpoint/login.json",
        adapter_name="endpoint_adapter",
        media_type="application/json",
    )
    got = shapes(EndpointParser().parse(artifact))
    login = "url:http://10.10.11.23:80/login"
    assert {"predicate": "url.seen", "subject_hint": login, "object": login} in got
    assert {
        "predicate": "endpoint.seen",
        "subject_hint": f"ep:POST:{login}",
        "object": {"method": "POST", "url": login},
    } in got
    password = next(
        item
        for item in got
        if item["predicate"] == "param.seen" and item["object"]["name"] == "password"
    )
    assert password["object"]["redacted"] is True


def test_endpoint_html_same_host_cap() -> None:
    artifact = artifact_from_fixture(
        "endpoint/login.html",
        adapter_name="endpoint_adapter",
        media_type="text/html",
        source_locator="http://10.10.11.23/",
    )
    got = shapes(EndpointParser().parse(artifact))
    objects = [item["object"] for item in got]
    assert "url:http://10.10.11.23:80/admin" in objects
    assert not any("evil.example" in str(item) for item in got)
    assert any(item["predicate"] == "auth.seen" and item["object"] == "http_form" for item in got)
    assert any(
        item["predicate"] == "param.seen"
        and item["object"]["name"] == "password"
        and item["object"]["redacted"]
        for item in got
    )


def test_stub_parser_covers_catalog_types() -> None:
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
    )
    got = shapes(StubParser().parse(artifact))
    assert {
        "predicate": "port.state",
        "subject_hint": "port:host:ipv4:10.10.11.23:tcp:80",
        "object": "open",
    } in got
    assert StubParser().parse(artifact)[0].parser_id == "stub"
    assert set(V1_ACTION_TYPES)


def test_stub_parser_deterministic() -> None:
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
    )
    assert shapes(StubParser().parse(artifact)) == shapes(StubParser().parse(artifact))
