"""Read-only graph queries. No mutation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cyberx.domain.enums import GraphEdgeKind, GraphNodeKind
from cyberx.domain.models.graph import (
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    GraphSummary,
    InvestigationPath,
)
from cyberx.graph.paths import PathPlanner
from cyberx.world.snapshot import WorldSnapshot


class GraphQueries:
    def __init__(self, graph: GraphSnapshot) -> None:
        self._graph = graph

    def get_nodes(self) -> tuple[GraphNode, ...]:
        return self._graph.get_nodes()

    def get_edges(self, *, include_invalidated: bool = True) -> tuple[GraphEdge, ...]:
        return self._graph.get_edges(include_invalidated=include_invalidated)

    def get_neighbors(
        self,
        node: str,
        *,
        include_invalidated: bool = False,
    ) -> tuple[GraphNode, ...]:
        seed = self._graph.node_by_id(node) or self._graph.node_by_key(node)
        if seed is None:
            return ()
        found: dict[str, GraphNode] = {}
        for edge in self._graph.get_edges(include_invalidated=include_invalidated):
            other = None
            if edge.src_key == seed.semantic_key:
                other = self._graph.node_by_key(edge.dst_key)
            elif edge.dst_key == seed.semantic_key:
                other = self._graph.node_by_key(edge.src_key)
            if other is not None and other.semantic_key not in found:
                found[other.semantic_key] = other
        items = list(found.values())
        items.sort(key=lambda n: (n.kind.value, n.semantic_key))
        return tuple(items)

    def get_related_assets(self, node: str) -> tuple[GraphNode, ...]:
        neighbors = self.get_neighbors(node)
        return tuple(
            n
            for n in neighbors
            if n.kind
            not in {
                GraphNodeKind.FINDING,
                GraphNodeKind.HYPOTHESIS,
                GraphNodeKind.VALIDATION_CANDIDATE,
            }
        )

    def get_attack_surface_for_host(self, host: str) -> tuple[GraphNode, ...]:
        seed = self._graph.node_by_id(host) or self._graph.node_by_key(host)
        if seed is None:
            return ()
        out: dict[str, GraphNode] = {seed.semantic_key: seed}
        frontier = [seed.semantic_key]
        allowed = {
            GraphEdgeKind.HOSTS,
            GraphEdgeKind.EXPOSES,
            GraphEdgeKind.RUNS,
            GraphEdgeKind.SERVES,
            GraphEdgeKind.IMPLEMENTS,
            GraphEdgeKind.CONTAINS,
            GraphEdgeKind.AUTHENTICATES,
        }
        seen = set(frontier)
        while frontier:
            current = frontier.pop()
            for edge in self._graph.get_edges(include_invalidated=False):
                if edge.kind not in allowed:
                    continue
                nxt = None
                if edge.src_key == current:
                    nxt = edge.dst_key
                if nxt is None or nxt in seen:
                    continue
                node = self._graph.node_by_key(nxt)
                if node is None or node.out_of_scope:
                    continue
                seen.add(nxt)
                out[nxt] = node
                frontier.append(nxt)
        items = list(out.values())
        items.sort(key=lambda n: (n.kind.value, n.semantic_key))
        return tuple(items)

    def get_web_surface(self, url: str) -> tuple[GraphNode, ...]:
        seed = self._graph.node_by_id(url) or self._graph.node_by_key(url)
        if seed is None:
            return ()
        out = [seed]
        for edge in self._graph.get_edges(include_invalidated=False):
            if edge.src_key != seed.semantic_key:
                continue
            if edge.kind in {
                GraphEdgeKind.CONTAINS,
                GraphEdgeKind.AUTHENTICATES,
                GraphEdgeKind.IMPLEMENTS,
                GraphEdgeKind.HAS_FINDING,
            }:
                node = self._graph.node_by_key(edge.dst_key)
                if node is not None:
                    out.append(node)
        out.sort(key=lambda n: (n.kind.value, n.semantic_key))
        return tuple(out)

    def get_services(self, host: str) -> tuple[GraphNode, ...]:
        surface = self.get_attack_surface_for_host(host)
        return tuple(n for n in surface if n.kind is GraphNodeKind.SERVICE)

    def get_endpoints(self, url: str) -> tuple[GraphNode, ...]:
        return tuple(n for n in self.get_web_surface(url) if n.kind is GraphNodeKind.ENDPOINT)

    def get_findings_for_asset(self, asset: str) -> tuple[GraphNode, ...]:
        return self._typed_neighbors(asset, GraphEdgeKind.HAS_FINDING)

    def get_hypotheses_for_asset(self, asset: str) -> tuple[GraphNode, ...]:
        return self._typed_neighbors(asset, GraphEdgeKind.HAS_HYPOTHESIS)

    def get_validation_candidates_for_asset(self, asset: str) -> tuple[GraphNode, ...]:
        return self._typed_neighbors(asset, GraphEdgeKind.HAS_VALIDATION)

    def _typed_neighbors(self, asset: str, kind: GraphEdgeKind) -> tuple[GraphNode, ...]:
        seed = self._graph.node_by_id(asset) or self._graph.node_by_key(asset)
        if seed is None:
            return ()
        out: list[GraphNode] = []
        for edge in self._graph.get_edges(include_invalidated=True):
            if edge.kind is not kind or edge.src_key != seed.semantic_key:
                continue
            node = self._graph.node_by_key(edge.dst_key)
            if node is not None:
                out.append(node)
        out.sort(key=lambda n: n.semantic_key)
        return tuple(out)


def graph_summary(
    graph: GraphSnapshot,
    snapshot: WorldSnapshot | None = None,
    *,
    paths: Sequence[InvestigationPath] | None = None,
) -> GraphSummary:
    del snapshot
    counts: dict[str, int] = {}
    for node in graph.nodes:
        counts[node.kind.value] = counts.get(node.kind.value, 0) + 1
    top = [
        n.label
        for n in graph.nodes
        if n.kind
        in {
            GraphNodeKind.HOST,
            GraphNodeKind.URL,
            GraphNodeKind.AUTH_SURFACE,
            GraphNodeKind.SERVICE,
        }
        and not n.out_of_scope
    ][:12]
    planned = list(paths or ())
    important = [item.semantic_key for item in planned[:8]]
    unresolved: list[str] = []
    for item in planned[:8]:
        unresolved.extend(item.unresolved_questions)
    return GraphSummary(
        revision=graph.revision,
        digest=graph.digest,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        node_counts=counts,
        top_assets=top,
        important_paths=important[:8],
        unresolved_branches=list(dict.fromkeys(unresolved))[:8],
        conflict_count=graph.conflict_count,
        out_of_scope_count=sum(1 for n in graph.nodes if n.out_of_scope),
    )


def project_and_query(snapshot: WorldSnapshot, *, validation_candidates: Any = None):
    from cyberx.graph.projector import GraphProjector

    graph = GraphProjector().project(snapshot, validation_candidates=validation_candidates)
    paths = PathPlanner().plan(graph, snapshot, validation_candidates=validation_candidates or ())
    return graph, paths, GraphQueries(graph)
