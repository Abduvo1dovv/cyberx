"""Compact textual attack-surface tree. No visualization framework."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.domain.enums import GraphEdgeKind, GraphNodeKind
from cyberx.domain.models.graph import GraphNode, GraphSnapshot, InvestigationPath

_CHILD_EDGES = frozenset(
    {
        GraphEdgeKind.CONTAINS,
        GraphEdgeKind.EXPOSES,
        GraphEdgeKind.RUNS,
        GraphEdgeKind.SERVES,
        GraphEdgeKind.IMPLEMENTS,
        GraphEdgeKind.AUTHENTICATES,
        GraphEdgeKind.HOSTS,
        GraphEdgeKind.RESOLVES_TO,
        GraphEdgeKind.LINKS_TO,
    }
)
_ROOT_ORDER = (
    GraphNodeKind.DOMAIN,
    GraphNodeKind.SUBDOMAIN,
    GraphNodeKind.HOST,
    GraphNodeKind.URL,
)
_SKIP_ROOT = {
    GraphNodeKind.FINDING,
    GraphNodeKind.HYPOTHESIS,
    GraphNodeKind.VALIDATION_CANDIDATE,
    GraphNodeKind.PARAMETER,
    GraphNodeKind.INTERFACE,
    GraphNodeKind.TECHNOLOGY,
}


def render_attack_tree(graph: GraphSnapshot, *, max_lines: int = 40) -> str:
    children = _children(graph)
    child_keys = {n.semantic_key for kids in children.values() for n in kids}
    roots = [
        n
        for n in graph.nodes
        if n.semantic_key not in child_keys and n.kind not in _SKIP_ROOT and not n.out_of_scope
    ]
    if not roots:
        roots = [n for n in graph.nodes if n.kind in _ROOT_ORDER]
    roots.sort(key=lambda n: (_ROOT_ORDER.index(n.kind) if n.kind in _ROOT_ORDER else 9, n.label))
    lines: list[str] = []
    seen: set[str] = set()
    for root in roots:
        _walk(root, children, lines, seen, indent=0, max_lines=max_lines)
        if len(lines) >= max_lines:
            break
    if not lines:
        return "(empty graph)"
    return "\n".join(lines[:max_lines])


def render_path_line(path: InvestigationPath) -> str:
    trail = " → ".join(path.labels[:8]) or path.semantic_key
    extra = f"  p={path.priority:.2f}"
    if path.action_type:
        extra += f"  next={path.action_type}"
    return (trail + extra)[:200]


def render_paths(paths: Sequence[InvestigationPath], *, limit: int = 8) -> str:
    if not paths:
        return "(no investigation paths)"
    rows = [f"{idx}. {render_path_line(path)}" for idx, path in enumerate(paths[:limit], start=1)]
    return "\n".join(rows)


def _children(graph: GraphSnapshot) -> dict[str, list[GraphNode]]:
    out: dict[str, list[GraphNode]] = {}
    for edge in graph.get_edges(include_invalidated=False):
        if edge.kind not in _CHILD_EDGES:
            continue
        src = graph.node_by_key(edge.src_key)
        dst = graph.node_by_key(edge.dst_key)
        if src is None or dst is None or dst.out_of_scope:
            continue
        bucket = out.setdefault(src.semantic_key, [])
        if all(existing.semantic_key != dst.semantic_key for existing in bucket):
            bucket.append(dst)
    for kids in out.values():
        kids.sort(key=lambda n: (n.kind.value, n.label))
    return out


def _walk(
    node: GraphNode,
    children: dict[str, list[GraphNode]],
    lines: list[str],
    seen: set[str],
    *,
    indent: int,
    max_lines: int,
) -> None:
    if len(lines) >= max_lines:
        return
    if node.semantic_key in seen:
        return
    seen.add(node.semantic_key)
    mark = " [oos]" if node.out_of_scope else ""
    lines.append(f"{'  ' * indent}{node.label}{mark}")
    for child in children.get(node.semantic_key, ()):
        if child.kind in {
            GraphNodeKind.FINDING,
            GraphNodeKind.HYPOTHESIS,
            GraphNodeKind.VALIDATION_CANDIDATE,
        }:
            continue
        _walk(child, children, lines, seen, indent=indent + 1, max_lines=max_lines)
