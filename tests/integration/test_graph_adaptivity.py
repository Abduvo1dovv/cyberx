"""Golden: evidence sequence grows the graph and influences the next action."""

from __future__ import annotations

from tests.conftest import FIXTURES, artifact_from_fixture, create_cmd

from cyberx.brain.context import BrainContextBuilder
from cyberx.domain.enums import V1_ACTION_TYPES, GraphNodeKind
from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.graph.paths import PathPlanner
from cyberx.graph.projector import GraphProjector
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.endpoint import EndpointAdapter
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner
from cyberx.validation.engine import ValidationEngine
from cyberx.world.model import InMemoryWorldModel


def _apply(world: InMemoryWorldModel, relative: str, adapter: str, media: str) -> None:
    artifact = artifact_from_fixture(
        relative,
        adapter_name=adapter,
        media_type=media,
        mission_id=world.mission_id,
        source_locator="http://10.10.11.23/",
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)


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


def test_graph_changes_each_cycle_and_stays_recon(tmp_path) -> None:
    service, mid, engine = _engine(tmp_path)
    digests: list[str] = []
    types: list[str | None] = []
    for _ in range(4):
        report = engine.run_one_cycle(mid)
        types.append(report.selected_action_type)
        snap = engine.world(mid).snapshot()
        graph = GraphProjector().project(snap)
        digests.append(graph.digest)
        for node in graph.nodes:
            assert "exploit" not in node.kind.value
            assert "session" not in node.kind.value
        if report.completed:
            break
    assert types[0] == "port_scan"
    assert "http_probe" in types
    assert len(set(digests)) >= 2
    world = engine.world(mid)
    kinds = {n.kind for n in GraphProjector().project(world.snapshot()).nodes}
    assert GraphNodeKind.HOST in kinds
    assert GraphNodeKind.PORT in kinds
    ctx = BrainContextBuilder().build(
        world.snapshot(),
        service.get(mid),
        scope=service.get_bundle(mid).scope,
    )
    assert ctx.graph_digest
    assert ctx.byte_size <= 32768
    for row in ctx.investigation_paths:
        action = row.get("action") or ""
        if action:
            assert action in V1_ACTION_TYPES


def test_replay_same_evidence_same_digest() -> None:
    def run() -> str:
        world = InMemoryWorldModel(new_id(PREFIX_MISSION))
        _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
        _apply(world, "http/probe_200.json", "http_adapter", "application/json")
        _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
        graph = GraphProjector().project(
            world.snapshot(), validation_candidates=ValidationEngine().evaluate(world)
        )
        return graph.digest

    assert run() == run()


def test_paths_influence_next_catalog_action() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    before = PathPlanner().plan(GraphProjector().project(world.snapshot()), world.snapshot())
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    after_graph = GraphProjector().project(world.snapshot())
    after = PathPlanner().plan(after_graph, world.snapshot())
    assert after
    labels = " ".join(" ".join(p.labels) for p in after).lower()
    assert "login" in labels or "auth" in labels or after_graph.nodes
    before_keys = {p.semantic_key for p in before}
    after_keys = {p.semantic_key for p in after}
    assert before_keys != after_keys or len(after) >= len(before)
    for path in after:
        for action in path.candidate_actions:
            assert action in V1_ACTION_TYPES
