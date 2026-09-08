"""Additional HTTP parser fixtures for M11A."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture, shapes

from cyberx.evidence.factory import reliability_for
from cyberx.evidence.parsers.fingerprints import detect_technologies
from cyberx.evidence.parsers.http_probe import HttpProbeParser
from cyberx.evidence.pipeline import EvidencePipeline


def _art(name: str):
    return artifact_from_fixture(
        f"http/{name}",
        adapter_name="http_adapter",
        media_type="application/json",
        source_locator="http://10.10.11.23/",
    )


def test_html_title_and_same_host_links() -> None:
    obs = HttpProbeParser().parse(_art("probe_200_html.json"))
    titles = [o.object for o in obs if o.predicate == "http.title"]
    assert "Box Portal" in titles
    urls = {o.object for o in obs if o.predicate == "url.seen"}
    assert any("login" in str(u) for u in urls)
    methods = [
        o.object.get("method")
        for o in obs
        if o.predicate == "endpoint.seen" and isinstance(o.object, dict)
    ]
    assert "POST" in methods
    assert not any("evil.example" in str(o.object) for o in obs)


def test_status_codes() -> None:
    for name, code in (
        ("probe_301.json", 301),
        ("probe_redirect.json", 302),
        ("probe_401.json", 401),
        ("probe_403.json", 403),
        ("probe_404.json", 404),
        ("probe_500.json", 500),
    ):
        obs = HttpProbeParser().parse(_art(name))
        statuses = [o.object for o in obs if o.predicate == "http.status"]
        assert code in statuses


def test_401_records_auth_surface() -> None:
    obs = HttpProbeParser().parse(_art("probe_401.json"))
    kinds = [o.object for o in obs if o.predicate == "auth.seen"]
    assert "http_basic" in kinds


def test_https_metadata_on_url() -> None:
    artifact = artifact_from_fixture(
        "http/probe_https.json",
        adapter_name="http_adapter",
        media_type="application/json",
        source_locator="https://10.10.11.23/",
    )
    obs = HttpProbeParser().parse(artifact)
    seen = next(o for o in obs if o.predicate == "url.seen")
    assert seen.extra.get("tls") is True


def test_missing_server_header_has_no_tech() -> None:
    obs = HttpProbeParser().parse(_art("probe_no_server.json"))
    assert not any(o.predicate == "http.tech" for o in obs)
    assert any(o.predicate == "http.title" for o in obs)


def test_malformed_html_does_not_crash() -> None:
    obs = HttpProbeParser().parse(_art("probe_malformed_html.json"))
    assert any(o.predicate == "http.status" for o in obs)


def test_empty_body_ok() -> None:
    obs = HttpProbeParser().parse(_art("probe_empty.json"))
    assert any(o.object == 200 for o in obs if o.predicate == "http.status")
    assert not any(o.predicate == "http.title" for o in obs)


def test_oversized_truncated_still_parses() -> None:
    obs = HttpProbeParser().parse(_art("probe_oversized.json"))
    assert any(o.object == "Huge" for o in obs if o.predicate == "http.title")


def test_http_evidence_traceable() -> None:
    artifact = _art("probe_200.json")
    obs, evidence = EvidencePipeline().normalize(artifact)
    assert obs
    for ev in evidence:
        assert ev.artifact_id == artifact.artifact_id
        assert ev.tool_run_id == artifact.tool_run_id
        assert ev.parser_id == "http_probe"
    port_like = next(e for e in evidence if e.claim_preview["predicate"] == "http.status")
    assert port_like.reliability == 0.90


def test_fingerprint_header_and_body_markers() -> None:
    techs = detect_technologies(
        {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1"},
        "<html>wp-content/themes/x csrfmiddlewaretoken</html>",
    )
    products = {t["product"] for t in techs}
    assert "nginx" in products
    assert "php" in products
    assert "wordpress" in products
    assert "django" in products
    nginx = next(t for t in techs if t["product"] == "nginx")
    assert nginx["version"] == "1.24.0"
    assert nginx["source"] == "header"


def test_weak_markers_are_not_invented() -> None:
    techs = detect_technologies({"content-type": "text/html"}, "<html><p>jquery is mentioned</p>")
    assert techs == []


def test_header_tech_reliability_is_conservative() -> None:
    obs = HttpProbeParser().parse(_art("probe_200.json"))
    tech = next(o for o in obs if o.predicate == "http.tech")
    assert reliability_for(tech) == 0.55
    assert shapes(obs)
