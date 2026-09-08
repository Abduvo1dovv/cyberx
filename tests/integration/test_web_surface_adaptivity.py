"""Golden: nmap → http_probe → endpoint_discovery → web surface in Brain context."""

from __future__ import annotations

from tests.conftest import FIXTURES, create_cmd

from cyberx.brain.context import BrainContextBuilder
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.endpoint import EndpointAdapter
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner


def _engine(tmp_path):
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    html = (FIXTURES / "http" / "surface.html").read_bytes()
    page = HttpRawResponse(
        url="http://10.10.11.23/",
        status=200,
        headers={"content-type": "text/html", "server": "nginx"},
        body=html,
    )
    transport = FixtureTransport(
        {
            "http://10.10.11.23/": page,
            "http://10.10.11.23:80/": page,
        }
    )
    nmap = NmapAdapter(runner=FixtureProcessRunner(xml), available=True)
    http = HttpAdapter(transport=transport)
    tech = TechAdapter(transport=transport)
    endpoint = EndpointAdapter()
    executor = ReconExecutor(
        nmap=nmap,
        http=http,
        tech=tech,
        endpoint=endpoint,
        nmap_enabled=True,
        http_enabled=True,
        data_dir=str(tmp_path),
    )
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    sink = InMemoryEventSink()
    boundary = ExecutionBoundary(executor=executor, events=sink)
    engine = MissionEngine(service, boundary=boundary, events=sink)
    return service, mission.mission_id, engine


def test_four_cycle_web_surface(tmp_path) -> None:
    service, mid, engine = _engine(tmp_path)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    second = engine.run_one_cycle(mid)
    assert second.selected_action_type == "http_probe"
    assert second.coverage_key != first.coverage_key
    world2 = engine.world(mid)
    assert world2.get_web_surfaces()
    third = engine.run_one_cycle(mid)
    assert third.selected_action_type == "endpoint_discovery"
    assert third.coverage_key != second.coverage_key
    world3 = engine.world(mid)
    snap = world3.snapshot()
    paths = {u.path for u in world3.get_web_surfaces()}
    assert {"/login", "/api", "/admin"} <= paths
    methods = {(e.method.value, e.url_canonical) for e in world3.get_endpoints()}
    assert any(m == "POST" and "login" in u for m, u in methods)
    assert world3.get_auth_surfaces()
    params = {p.name for p in world3.get_parameters()}
    assert "password" in params
    assert any(p.redacted for p in world3.get_parameters() if p.name == "password")
    assert not any("outside.example" in u.canonical_key for u in world3.get_web_surfaces())
    ctx = BrainContextBuilder().build(
        snap,
        service.get(mid),
        scope=service.get_bundle(mid).scope,
    )
    kinds = {row.get("kind") for row in ctx.top_assets}
    assert "endpoint" in kinds
    assert "auth_surface" in kinds
    assert any("login" in (row.get("url") or row.get("key") or "") for row in ctx.top_assets)
    fourth = engine.run_one_cycle(mid)
    assert fourth.selected_action_type != "endpoint_discovery"
    assert fourth.coverage_key != third.coverage_key or fourth.completed


def test_endpoint_discovery_not_repeated(tmp_path) -> None:
    _service, mid, engine = _engine(tmp_path)
    types = []
    for _ in range(6):
        report = engine.run_one_cycle(mid)
        if report.completed:
            break
        types.append(report.selected_action_type)
    assert types.count("endpoint_discovery") == 1
    assert types[0] == "port_scan"
    assert "http_probe" in types
