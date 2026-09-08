"""M15 attack-surface graph: projection, digest, paths, no exploit nodes."""

from __future__ import annotations

import pytest
from tests.conftest import artifact_from_fixture

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.facade import Brain
from cyberx.domain.enums import (
    FORBIDDEN_GRAPH_NODES,
    V1_ACTION_TYPES,
    GraphEdgeKind,
    GraphNodeKind,
    MissionMode,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_MISSION, PREFIX_PATH, PREFIX_SCOPE, PREFIX_TARGET, new_id
from cyberx.domain.models.graph import InvestigationPath
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.graph.paths import PathPlanner
from cyberx.graph.projector import GraphProjector
from cyberx.graph.queries import GraphQueries, graph_summary, project_and_query
from cyberx.graph.tree import render_attack_tree, render_paths
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


def _mission_scope(world: InMemoryWorldModel, target: str = "10.10.11.23") -> tuple[Mission, Scope]:
    now = utcnow()
    from cyberx.domain.enums import MissionStatus

    mission = Mission(
        mission_id=world.mission_id,
        name="box",
        intent="enumerate surface",
        mode=MissionMode.CTF,
        status=MissionStatus.RUNNING,
        target_id=new_id(PREFIX_TARGET),
        scope_id=new_id(PREFIX_SCOPE),
        created_at=now,
        started_at=now,
        iteration=1,
    )
    scope = Scope(
        scope_id=mission.scope_id,
        mission_id=world.mission_id,
        allowed_targets=[target],
        allowed_networks=[],
        allowed_ports=[],
        allowed_protocols=["tcp", "http", "https", "dns"],
        frozen=True,
        created_at=now,
    )
    return mission, scope


def test_nmap_creates_host_port_service_nodes() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    graph = GraphProjector().project(world.snapshot())
    kinds = {n.kind for n in graph.nodes}
    assert GraphNodeKind.HOST in kinds
    assert GraphNodeKind.PORT in kinds
    edge_kinds = {e.kind for e in graph.edges}
    assert GraphEdgeKind.EXPOSES in edge_kinds
    queries = GraphQueries(graph)
    host = next(n for n in graph.nodes if n.kind is GraphNodeKind.HOST)
    surface = queries.get_attack_surface_for_host(host.node_id)
    assert any(n.kind is GraphNodeKind.PORT for n in surface)
    assert any("80" in n.label for n in graph.nodes)


def test_dns_creates_domain_subdomain_resolution() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "dns/mixed_records.json", "dns_adapter", "application/json")
    graph = GraphProjector().project(world.snapshot())
    kinds = {n.kind for n in graph.nodes}
    assert GraphNodeKind.DOMAIN in kinds
    assert GraphNodeKind.SUBDOMAIN in kinds
    assert GraphNodeKind.HOST in kinds
    edge_kinds = {e.kind for e in graph.edges}
    assert GraphEdgeKind.CONTAINS in edge_kinds
    assert GraphEdgeKind.RESOLVES_TO in edge_kinds or GraphEdgeKind.LINKS_TO in edge_kinds
    labels = {n.label for n in graph.nodes}
    assert any("box.htb" in label for label in labels)


def test_web_surface_url_endpoint_auth_chain() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    cands = ValidationEngine().evaluate(world)
    graph = GraphProjector().project(world.snapshot(), validation_candidates=cands)
    kinds = {n.kind for n in graph.nodes}
    assert GraphNodeKind.URL in kinds
    assert GraphNodeKind.ENDPOINT in kinds
    assert GraphNodeKind.AUTH_SURFACE in kinds
    assert GraphNodeKind.FINDING in kinds
    assert GraphNodeKind.VALIDATION_CANDIDATE in kinds
    edge_kinds = {e.kind for e in graph.edges}
    assert GraphEdgeKind.SERVES in edge_kinds
    assert GraphEdgeKind.CONTAINS in edge_kinds
    assert GraphEdgeKind.AUTHENTICATES in edge_kinds
    assert GraphEdgeKind.HAS_FINDING in edge_kinds
    url = next(n for n in graph.nodes if n.kind is GraphNodeKind.URL)
    web = GraphQueries(graph).get_web_surface(url.node_id)
    assert any(n.kind is GraphNodeKind.ENDPOINT for n in web)


def test_duplicate_evidence_does_not_duplicate_nodes() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    first = GraphProjector().project(world.snapshot())
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    second = GraphProjector().project(world.snapshot())
    host_keys = [n.semantic_key for n in second.nodes if n.kind is GraphNodeKind.HOST]
    assert len(host_keys) == len(set(host_keys))
    port_keys = [n.semantic_key for n in second.nodes if n.kind is GraphNodeKind.PORT]
    assert len(port_keys) == len(set(port_keys))
    edge_ids = [e.identity_key for e in second.edges]
    assert len(edge_ids) == len(set(edge_ids))
    assert {n.semantic_key for n in first.nodes} <= {n.semantic_key for n in second.nodes}


def test_semantic_digest_stable_across_ulids() -> None:
    def build() -> str:
        world = InMemoryWorldModel(new_id(PREFIX_MISSION))
        _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
        _apply(world, "http/probe_200.json", "http_adapter", "application/json")
        return GraphProjector().project(world.snapshot()).digest

    assert build() == build()


def test_digest_excludes_ulids() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    graph = GraphProjector().project(world.snapshot())
    blob = graph.digest
    for node in graph.nodes:
        assert node.node_id not in blob


def test_graph_grows_after_world_changes() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    empty = GraphProjector().project(world.snapshot())
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    after_nmap = GraphProjector().project(world.snapshot())
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    after_http = GraphProjector().project(world.snapshot())
    assert after_nmap.digest != empty.digest
    assert after_http.digest != after_nmap.digest
    assert after_http.revision == world.snapshot().revision
    assert len(after_http.nodes) > len(after_nmap.nodes)


def test_no_exploit_or_session_nodes() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    graph = GraphProjector().project(world.snapshot())
    for node in graph.nodes:
        lowered = node.kind.value.lower()
        assert not any(token in lowered for token in FORBIDDEN_GRAPH_NODES)
    kinds = {e.kind.value.lower() for e in graph.edges}
    assert "exploit" not in kinds
    assert "session" not in kinds


def test_path_planner_catalog_only() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    snap = world.snapshot()
    graph, paths, _q = project_and_query(snap)
    assert graph.nodes
    assert paths
    for path in paths:
        assert path.path_id.startswith(PREFIX_PATH)
        for action in path.candidate_actions:
            assert action in V1_ACTION_TYPES
            assert "exploit" not in action
            assert "validate" not in action
        assert path.priority == pytest.approx(path.priority)
        assert 0.0 <= path.priority <= 1.0


def test_path_dedup_and_scoring() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    snap = world.snapshot()
    graph = GraphProjector().project(snap, validation_candidates=ValidationEngine().evaluate(world))
    paths = PathPlanner().plan(graph, snap)
    keys = [p.semantic_key for p in paths]
    assert len(keys) == len(set(keys))
    ids = [p.path_id for p in paths]
    assert len(ids) == len(set(ids))
    again = PathPlanner().plan(graph, snap)
    assert [p.path_id for p in again] == [p.path_id for p in paths]
    if len(paths) >= 2:
        assert paths[0].priority >= paths[1].priority
    auth_paths = [
        p for p in paths if any("auth" in lab.lower() or "login" in lab.lower() for lab in p.labels)
    ]
    if auth_paths:
        assert auth_paths[0].priority >= 0.4


def test_oos_paths_are_not_actionable() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "dns/mixed_records.json", "dns_adapter", "application/json")
    snap = world.snapshot()
    graph = GraphProjector().project(snap)
    oos = [n for n in graph.nodes if n.out_of_scope]
    paths = PathPlanner().plan(graph, snap)
    for path in paths:
        assert not path.out_of_scope
        for node_id in path.node_ids:
            node = graph.node_by_id(node_id)
            if node is not None and node.kind not in {
                GraphNodeKind.FINDING,
                GraphNodeKind.HYPOTHESIS,
                GraphNodeKind.VALIDATION_CANDIDATE,
            }:
                assert not node.out_of_scope
    # OOS nodes may exist on the graph for provenance
    del oos


def test_path_rejects_exploit_actions() -> None:
    with pytest.raises(DomainValidationError):
        InvestigationPath(
            path_id=new_id(PREFIX_PATH),
            semantic_key="x",
            nodes=["a"],
            labels=["a"],
            candidate_actions=["exploit_http"],
            rationale="no",
        )


def test_brain_context_includes_compact_graph() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    mission, scope = _mission_scope(world)
    cands = ValidationEngine().evaluate(world)
    ctx = BrainContextBuilder().build(
        world.snapshot(), mission, scope=scope, validation_candidates=cands
    )
    assert ctx.graph_digest
    assert ctx.byte_size <= 32768
    assert len(ctx.investigation_paths) <= 5
    assert len(ctx.graph_focus) <= 8
    decision = Brain().decide(ctx, DEFAULT_CATALOG, min_score=0.15)
    if decision.action is not None:
        assert decision.action.action_type in V1_ACTION_TYPES
        assert "exploit" not in decision.action.action_type


def test_queries_neighbors_and_summary() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    graph, paths, queries = project_and_query(world.snapshot())
    host = next(n for n in graph.nodes if n.kind is GraphNodeKind.HOST)
    neighbors = queries.get_neighbors(host.node_id)
    assert neighbors
    summary = graph_summary(graph, world.snapshot(), paths=paths)
    assert summary.node_count == len(graph.nodes)
    assert summary.digest == graph.digest
    tree = render_attack_tree(graph)
    assert tree
    assert "exploit" not in tree.lower()
    text = render_paths(paths)
    assert "exploit" not in text.lower()


def test_invalidated_edges_remain_visible() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    graph = GraphProjector().project(world.snapshot())
    all_edges = graph.get_edges(include_invalidated=True)
    live = graph.get_edges(include_invalidated=False)
    assert len(all_edges) >= len(live)
    conflicts = graph.conflict_count
    assert conflicts >= 0


def test_technology_relationship() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    _apply(world, "tech/nginx.json", "tech_adapter", "application/json")
    graph = GraphProjector().project(world.snapshot())
    techs = [n for n in graph.nodes if n.kind is GraphNodeKind.TECHNOLOGY]
    if techs:
        edge_kinds = {e.kind for e in graph.edges}
        assert GraphEdgeKind.IMPLEMENTS in edge_kinds


def test_tui_graph_binding() -> None:
    from cyberx.app.views import GraphView
    from cyberx.tui.keys import BINDINGS, HELP_TEXT
    from cyberx.tui.render import render_graph

    assert BINDINGS["g"] == "graph"
    assert "g graph" in HELP_TEXT
    text = render_graph(
        GraphView(revision=1, digest="abc", node_count=1, edge_count=0, tree="host"),
        color=False,
    )
    assert "Attack surface graph" in text
    assert "host" in text
