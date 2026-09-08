"""Golden: nmap 80 → http_probe → later directory_enumeration from gaps, not a pipeline."""

from __future__ import annotations

from tests.conftest import FIXTURES, create_cmd

from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.directory import DirectoryAdapter
from cyberx.recon.http.endpoint import EndpointAdapter
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner


def _transport() -> FixtureTransport:
    html = b"<html><head><title>Box</title></head><body>ok</body></html>"
    root = HttpRawResponse(
        url="http://10.10.11.23/",
        status=200,
        headers={"content-type": "text/html", "server": "nginx"},
        body=html,
    )
    return FixtureTransport(
        {
            "http://10.10.11.23:80/": root,
            "http://10.10.11.23/": root,
            "http://10.10.11.23:80": root,
            "http://10.10.11.23/admin": HttpRawResponse(
                url="http://10.10.11.23/admin", status=200, body=b"<title>Admin</title>"
            ),
            "http://10.10.11.23/api": HttpRawResponse(
                url="http://10.10.11.23/api", status=200, body=b"{}"
            ),
            "http://10.10.11.23/backup": HttpRawResponse(
                url="http://10.10.11.23/backup", status=403, body=b"no"
            ),
            "http://10.10.11.23/uploads": HttpRawResponse(
                url="http://10.10.11.23/uploads",
                status=301,
                headers={"location": "/login"},
                body=b"",
            ),
            "*": HttpRawResponse(url="*", status=404, body=b"missing"),
        }
    )


def test_directory_enumeration_emerges_from_gaps(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    sink = InMemoryEventSink()
    transport = _transport()
    executor = ReconExecutor(
        nmap=NmapAdapter(runner=FixtureProcessRunner(xml), available=True, events=sink),
        http=HttpAdapter(transport=transport, events=sink),
        tech=TechAdapter(transport=transport, events=sink),
        endpoint=EndpointAdapter(),
        directory=DirectoryAdapter(transport=transport, events=sink, max_candidates=12),
        nmap_enabled=True,
        http_enabled=True,
        data_dir=str(tmp_path),
    )
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(
        service, boundary=ExecutionBoundary(executor=executor, events=sink), events=sink
    )
    types: list[str] = []
    keys: list[str] = []
    dir_index = None
    for _ in range(6):
        report = engine.run_one_cycle(mission.mission_id)
        if report.completed or not report.selected_action_type:
            break
        types.append(report.selected_action_type)
        keys.append(report.coverage_key or "")
        if report.selected_action_type == "directory_enumeration":
            dir_index = len(types) - 1
            break
    assert types[0] == "port_scan"
    assert "http_probe" in types
    assert "directory_enumeration" in types
    assert dir_index is not None
    world = engine.world(mission.mission_id)
    paths = {u.path for u in world.get_web_surfaces()}
    assert {"/admin", "/api", "/backup", "/uploads"} <= paths
    nxt = engine.run_one_cycle(mission.mission_id)
    if nxt.selected_action_type:
        assert nxt.coverage_key != keys[dir_index]
    assert types.count("directory_enumeration") == 1
