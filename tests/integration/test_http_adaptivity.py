"""Golden adaptive path: nmap 80/tcp → http_probe → technology_detection."""

from __future__ import annotations

import os

import pytest
from tests.conftest import FIXTURES, create_cmd

from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.engine.stub_executor import StubExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner


def _wired(tmp_path, html: bytes, xml_name: str = "host_22_80.xml"):
    xml = (FIXTURES / "nmap" / xml_name).read_bytes()
    sink = InMemoryEventSink()
    nmap = NmapAdapter(runner=FixtureProcessRunner(xml), available=True, events=sink)
    page = HttpRawResponse(
        url="http://10.10.11.23:80/",
        status=200,
        headers={"content-type": "text/html"},
        body=html,
    )
    transport = FixtureTransport(
        {
            "http://10.10.11.23:80/": page,
            "http://10.10.11.23/": page,
            "http://10.10.11.23:80": page,
        }
    )
    http = HttpAdapter(transport=transport, events=sink)
    tech = TechAdapter(transport=transport, events=sink)
    executor = ReconExecutor(
        nmap=nmap,
        http=http,
        tech=tech,
        nmap_enabled=True,
        http_enabled=True,
        data_dir=str(tmp_path),
    )
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    boundary = ExecutionBoundary(executor=executor, events=sink)
    engine = MissionEngine(service, boundary=boundary, events=sink)
    return service, mission.mission_id, engine, sink


def test_nmap_http_probe_then_technology_detection(tmp_path) -> None:
    html = (FIXTURES / "http" / "html_200.html").read_bytes()
    _service, mid, engine, sink = _wired(tmp_path, html)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    assert first.execution_status == "completed"
    world = engine.world(mid)
    assert {p.number for p in world.get_open_ports()} >= {22, 80}
    second = engine.run_one_cycle(mid)
    assert second.selected_action_type == "http_probe"
    assert second.execution_status == "completed"
    assert second.evidence_added > 0
    assert second.coverage_key != first.coverage_key
    surfaces = engine.world(mid).get_web_surfaces()
    assert surfaces
    assert any(s.status_code == 200 for s in surfaces)
    titles = [s.title for s in surfaces if s.title]
    assert any(titles)
    third = engine.run_one_cycle(mid)
    assert third.selected_action_type == "technology_detection"
    assert third.selected_action_type != "port_scan"
    assert third.coverage_key != second.coverage_key
    techs = engine.world(mid).get_technologies()
    assert techs
    products = {t.product for t in techs}
    assert "wordpress" in products or "nginx" in products
    kinds = {e.event_type for e in sink.events}
    assert EventType.HTTP_STARTED in kinds
    assert EventType.PARSE_COMPLETED in kinds


def test_http_world_model_has_url_and_title(tmp_path) -> None:
    html = b"<html><title>Only Title</title><body>hi</body></html>"
    _service, mid, engine, _sink = _wired(tmp_path, html)
    engine.run_one_cycle(mid)
    engine.run_one_cycle(mid)
    world = engine.world(mid)
    urls = world.get_web_surfaces()
    assert urls
    assert any(u.title == "Only Title" for u in urls)
    claims = [c.predicate for c in world.get_claims()]
    assert "http.status" in claims
    assert "http.title" in claims


def test_stub_path_still_reaches_http_probe() -> None:
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(service)
    first = engine.run_one_cycle(mission.mission_id)
    second = engine.run_one_cycle(mission.mission_id)
    assert first.selected_action_type == "port_scan"
    assert second.selected_action_type == "http_probe"
    assert isinstance(engine._boundary._executor, StubExecutor)


@pytest.mark.requires_http
def test_live_http_optional() -> None:
    if os.environ.get("CYBERX_LIVE_HTTP") != "1":
        pytest.skip("set CYBERX_LIVE_HTTP=1 to run live HTTP")
    pytest.skip("live HTTP requires an operator-provided in-scope listener")
