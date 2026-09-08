"""Investigation path planner. Catalog-only; never exploit paths."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from cyberx.domain.confidence import clamp01
from cyberx.domain.enums import (
    FORBIDDEN_ACTION_MARKERS,
    V1_ACTION_TYPES,
    GraphEdgeKind,
    GraphNodeKind,
    PortState,
)
from cyberx.domain.ids import PREFIX_PATH, generate_ulid
from cyberx.domain.models.assets import (
    AuthenticationSurface,
    Domain,
    Endpoint,
    Host,
    Port,
    Service,
    Subdomain,
    UrlAsset,
)
from cyberx.domain.models.graph import GraphEdge, GraphNode, GraphSnapshot, InvestigationPath
from cyberx.world.importance import asset_importance
from cyberx.world.signals import classify_path, path_from_locator
from cyberx.world.snapshot import WorldSnapshot

# Maps v1 gap kinds onto existing catalog actions. Not an ActionScorer.
_GAP_ACTIONS: dict[str, str] = {
    "host.unresolved": "dns_enumeration",
    "host.ports_unknown": "port_scan",
    "port.service_unknown": "service_enumeration",
    "service.http_unprobed": "http_probe",
    "url.tech_unknown": "technology_detection",
    "domain.subdomains_unknown": "subdomain_enumeration",
    "service.directories_unknown": "directory_enumeration",
    "endpoint.params_unknown": "endpoint_discovery",
}

_HTTP_PORTS = frozenset({80, 443, 8080, 8443})
_HTTPS_PORTS = frozenset({443, 8443})
_HTTP_NAMES = frozenset({"http", "https", "http-alt", "ssl/http", "https-alt"})
_MAX_PATHS = 16
_MAX_DEPTH = 8
_PARENT_EDGE = frozenset(
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
_PARENT_KIND_SCORE = {
    GraphNodeKind.ENDPOINT: 90,
    GraphNodeKind.URL: 80,
    GraphNodeKind.PORT: 70,
    GraphNodeKind.SERVICE: 65,
    GraphNodeKind.AUTH_SURFACE: 60,
    GraphNodeKind.HOST: 50,
    GraphNodeKind.SUBDOMAIN: 40,
    GraphNodeKind.DOMAIN: 30,
    GraphNodeKind.INTERFACE: 20,
    GraphNodeKind.TECHNOLOGY: 15,
}
_STAGE_ORDER = (
    "dns_enumeration",
    "network_discovery",
    "subdomain_enumeration",
    "port_scan",
    "service_enumeration",
    "http_probe",
    "technology_detection",
    "directory_enumeration",
    "endpoint_discovery",
)
_INTEL_KINDS = {
    GraphNodeKind.FINDING,
    GraphNodeKind.HYPOTHESIS,
    GraphNodeKind.VALIDATION_CANDIDATE,
}


class PathPlanner:
    """Deterministic investigation paths. ActionScorer remains authoritative."""

    def plan(
        self,
        graph: GraphSnapshot,
        snapshot: WorldSnapshot,
        *,
        validation_candidates: Sequence[Any] = (),
    ) -> tuple[InvestigationPath, ...]:
        del validation_candidates
        parents, children = _adjacencies(graph)
        seeds = _seeds(graph, snapshot)
        seen: dict[str, InvestigationPath] = {}
        for seed in seeds:
            chain = _walk_up(seed, graph, parents, children)
            if not chain:
                continue
            if any(node.out_of_scope for node in chain if node.kind not in _INTEL_KINDS):
                continue
            path = _build_path(chain, graph, snapshot)
            if path.out_of_scope:
                continue
            prev = seen.get(path.semantic_key)
            if prev is None or path.priority > prev.priority:
                seen[path.semantic_key] = path
        items = list(seen.values())
        items.sort(key=lambda p: (-p.priority, p.semantic_key))
        return tuple(items[:_MAX_PATHS])


def _adjacencies(
    graph: GraphSnapshot,
) -> tuple[dict[str, list[tuple[GraphEdge, GraphNode]]], dict[str, list[GraphNode]]]:
    parents: dict[str, list[tuple[GraphEdge, GraphNode]]] = {}
    children: dict[str, list[GraphNode]] = {}
    for edge in graph.get_edges(include_invalidated=False):
        if edge.kind not in _PARENT_EDGE:
            continue
        src = graph.node_by_key(edge.src_key)
        dst = graph.node_by_key(edge.dst_key)
        if src is None or dst is None:
            continue
        parents.setdefault(dst.semantic_key, []).append((edge, src))
        children.setdefault(src.semantic_key, []).append(dst)
    return parents, children


def _seeds(graph: GraphSnapshot, snapshot: WorldSnapshot) -> list[GraphNode]:
    out: list[GraphNode] = []
    seen: set[str] = set()

    def add(node: GraphNode | None) -> None:
        if node is None or node.semantic_key in seen:
            return
        if node.out_of_scope and node.kind not in _INTEL_KINDS:
            return
        seen.add(node.semantic_key)
        out.append(node)

    for node in graph.nodes:
        if node.kind is GraphNodeKind.AUTH_SURFACE and not node.out_of_scope:
            add(node)
    for finding in snapshot.findings:
        if finding.kind.value == "out_of_scope_observation":
            continue
        node = graph.node_by_id(finding.finding_id)
        add(node)
    for hyp in snapshot.hypotheses:
        add(graph.node_by_id(hyp.hypothesis_id))
    for gap in snapshot.gaps:
        if gap.closed or not gap.subject_id:
            continue
        add(graph.node_by_id(gap.subject_id))
    for node in graph.nodes:
        if node.kind is GraphNodeKind.URL and not node.out_of_scope:
            path = path_from_locator(node.label)
            if classify_path(path):
                add(node)
        if node.kind is GraphNodeKind.PORT and not node.out_of_scope:
            asset = snapshot.peek_asset_by_id(node.ref_id)
            if isinstance(asset, Port) and asset.state is PortState.OPEN:
                if asset.number in _HTTP_PORTS:
                    add(node)
        if node.kind in {GraphNodeKind.HOST, GraphNodeKind.DOMAIN, GraphNodeKind.SUBDOMAIN}:
            if not node.out_of_scope:
                add(node)
        if node.kind is GraphNodeKind.VALIDATION_CANDIDATE and not node.out_of_scope:
            add(node)
    return out


def _walk_up(
    seed: GraphNode,
    graph: GraphSnapshot,
    parents: dict[str, list[tuple[GraphEdge, GraphNode]]],
    children: dict[str, list[GraphNode]],
) -> list[GraphNode]:
    del children
    start = seed
    if seed.kind in _INTEL_KINDS:
        related = _related_asset(seed, graph)
        start = related or seed
    chain = [start]
    seen = {start.semantic_key}
    current = start
    for _ in range(_MAX_DEPTH):
        parent = _best_parent(current, parents)
        if parent is None or parent.semantic_key in seen:
            break
        if parent.out_of_scope:
            break
        chain.append(parent)
        seen.add(parent.semantic_key)
        current = parent
    chain.reverse()
    if seed.kind in _INTEL_KINDS and seed.semantic_key not in seen:
        chain.append(seed)
    return chain


def _related_asset(node: GraphNode, graph: GraphSnapshot) -> GraphNode | None:
    for edge in graph.get_edges(include_invalidated=False):
        if edge.dst_key != node.semantic_key:
            continue
        if edge.kind in {
            GraphEdgeKind.HAS_FINDING,
            GraphEdgeKind.HAS_HYPOTHESIS,
            GraphEdgeKind.HAS_VALIDATION,
        }:
            src = graph.node_by_key(edge.src_key)
            if src is not None and src.kind not in _INTEL_KINDS:
                return src
    return None


def _best_parent(
    node: GraphNode, parents: dict[str, list[tuple[GraphEdge, GraphNode]]]
) -> GraphNode | None:
    options = parents.get(node.semantic_key) or []
    ranked: list[tuple[int, str, GraphNode]] = []
    for _edge, parent in options:
        if parent.out_of_scope:
            continue
        score = _PARENT_KIND_SCORE.get(parent.kind, 0)
        ranked.append((score, parent.semantic_key, parent))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[0][2]


def _build_path(
    chain: list[GraphNode],
    graph: GraphSnapshot,
    snapshot: WorldSnapshot,
) -> InvestigationPath:
    labels = [node.label for node in chain]
    keys = [node.semantic_key for node in chain]
    ids = [node.node_id for node in chain]
    edge_ids: list[str] = []
    evidence: list[str] = []
    for left, right in zip(chain, chain[1:]):
        for edge in graph.get_edges(include_invalidated=False):
            if {edge.src_key, edge.dst_key} == {left.semantic_key, right.semantic_key}:
                edge_ids.append(edge.identity_key)
                evidence.extend(edge.evidence_ids)
                break
    kinds = {n.kind for n in chain}
    oos = any(n.out_of_scope for n in chain if n.kind not in _INTEL_KINDS)
    questions, actions = _questions_and_actions(chain, snapshot)
    actions = [a for a in actions if a in V1_ACTION_TYPES]
    actions = [a for a in actions if not any(m in a for m in FORBIDDEN_ACTION_MARKERS)]
    locator, action_type, params = _action_payload(actions[0] if actions else "", chain, snapshot)
    relevance = _relevance(chain, kinds)
    confidence = _avg([n.confidence for n in chain if n.confidence > 0] or [0.4])
    completeness = _completeness(kinds)
    information = 0.9 if actions else 0.35
    if questions:
        information = max(information, min(1.0, 0.4 + 0.15 * len(questions)))
    importance = _importance(chain, snapshot)
    evidence_quality = min(1.0, len(set(evidence)) / 3.0) if evidence else 0.35
    novelty = 1.0 if actions else 0.35
    priority = clamp01(
        0.25 * relevance
        + 0.20 * information
        + 0.15 * (1.0 - completeness)
        + 0.15 * importance
        + 0.10 * confidence
        + 0.10 * evidence_quality
        + 0.05 * novelty
    )
    semantic = ">".join(keys)
    return InvestigationPath(
        path_id=_path_id(semantic),
        semantic_key=semantic[:800],
        nodes=keys,
        node_ids=ids,
        labels=labels,
        edges=edge_ids,
        relevance=relevance,
        confidence=confidence,
        information_value=information,
        completeness=completeness,
        priority=priority,
        unresolved_questions=questions[:6],
        candidate_actions=actions[:4],
        rationale=_rationale(labels, questions, actions),
        locator=locator,
        action_type=action_type,
        parameters=params,
        out_of_scope=oos,
    )


def _questions_and_actions(
    chain: list[GraphNode], snapshot: WorldSnapshot
) -> tuple[list[str], list[str]]:
    kinds = {n.kind for n in chain}
    ids = {n.ref_id for n in chain} | {n.node_id for n in chain}
    questions: list[str] = []
    actions: list[str] = []
    for gap in snapshot.gaps:
        if gap.closed:
            continue
        if gap.subject_id and gap.subject_id in ids:
            questions.append(gap.detail or gap.kind)
            mapped = _GAP_ACTIONS.get(gap.kind)
            if mapped:
                actions.append(mapped)
    host = _asset(chain, snapshot, Host)
    unresolved_host = (
        isinstance(host, Host) and bool(host.hostname) and not host.ipv4 and not host.ipv6
    )
    if unresolved_host:
        if "dns_enumeration" not in actions:
            questions.append("hostname unresolved")
            actions.append("dns_enumeration")
        actions = [a for a in actions if a == "dns_enumeration"]
        uniq_q = list(dict.fromkeys(questions))
        return uniq_q, list(dict.fromkeys(actions))
    if GraphNodeKind.DOMAIN in kinds and GraphNodeKind.SUBDOMAIN not in kinds:
        if "subdomain_enumeration" not in actions:
            questions.append("subdomains unknown")
            actions.append("subdomain_enumeration")
    if GraphNodeKind.HOST in kinds and GraphNodeKind.PORT not in kinds:
        if "port_scan" not in actions:
            questions.append("host ports unknown")
            actions.append("port_scan")
    if GraphNodeKind.PORT in kinds and GraphNodeKind.URL not in kinds:
        port = _asset(chain, snapshot, Port)
        if isinstance(port, Port) and port.number in _HTTP_PORTS and port.state is PortState.OPEN:
            if "http_probe" not in actions:
                questions.append("http surface unprobed")
                actions.append("http_probe")
    if GraphNodeKind.SERVICE in kinds and GraphNodeKind.URL not in kinds:
        svc = _asset(chain, snapshot, Service)
        if isinstance(svc, Service) and (svc.name or "") in _HTTP_NAMES:
            if "http_probe" not in actions:
                questions.append("http service unprobed")
                actions.append("http_probe")
    if GraphNodeKind.URL in kinds and GraphNodeKind.ENDPOINT not in kinds:
        if "endpoint_discovery" not in actions:
            questions.append("endpoints unknown")
            actions.append("endpoint_discovery")
    if GraphNodeKind.URL in kinds and GraphNodeKind.TECHNOLOGY not in kinds:
        if "technology_detection" not in actions:
            questions.append("technology unknown")
            actions.append("technology_detection")
    if snapshot.urls and "http_probe" in actions:
        actions = [a for a in actions if a != "http_probe"]
        questions = [q for q in questions if "unprobed" not in q]
    if snapshot.endpoints and "endpoint_discovery" in actions:
        url = _asset(chain, snapshot, UrlAsset)
        if isinstance(url, UrlAsset):
            owned = [e for e in snapshot.endpoints if e.url_id == url.asset_id]
            if owned:
                actions = [a for a in actions if a != "endpoint_discovery"]
                questions = [q for q in questions if q != "endpoints unknown"]
        else:
            actions = [a for a in actions if a != "endpoint_discovery"]
    if snapshot.technologies and "technology_detection" in actions:
        url = _asset(chain, snapshot, UrlAsset)
        if url is None or any(
            getattr(t, "parent_asset_id", None) == url.asset_id for t in snapshot.technologies
        ):
            actions = [a for a in actions if a != "technology_detection"]
            questions = [q for q in questions if q != "technology unknown"]
    uniq_q = list(dict.fromkeys(questions))
    uniq_a = [a for a in _STAGE_ORDER if a in actions]
    for extra in actions:
        if extra not in uniq_a:
            uniq_a.append(extra)
    return uniq_q, uniq_a


def _action_payload(
    action_type: str, chain: list[GraphNode], snapshot: WorldSnapshot
) -> tuple[str, str, dict[str, str]]:
    if not action_type:
        host = _asset(chain, snapshot, Host)
        url = _asset(chain, snapshot, UrlAsset)
        domain = _asset(chain, snapshot, Domain)
        if url is not None:
            return _url_locator(url), "", {"url": _url_locator(url), "url_id": url.asset_id}
        if domain is not None:
            return domain.fqdn, "", {"fqdn": domain.fqdn, "domain_id": domain.asset_id}
        if host is not None:
            address = host.ipv4 or host.ipv6 or host.hostname or ""
            return address, "", {"host_id": host.asset_id, "address": address}
        return chain[-1].label if chain else "", "", {}
    host = _asset(chain, snapshot, Host)
    port = _asset(chain, snapshot, Port)
    url = _asset(chain, snapshot, UrlAsset)
    domain = _asset(chain, snapshot, Domain)
    sub = _asset(chain, snapshot, Subdomain)
    auth = _asset(chain, snapshot, AuthenticationSurface)
    endpoint = _asset(chain, snapshot, Endpoint)
    if action_type == "port_scan" and host is not None:
        address = host.ipv4 or host.ipv6 or host.hostname or ""
        return (
            address,
            action_type,
            {"host_id": host.asset_id, "address": address, "ports": "top1000", "protocol": "tcp"},
        )
    if action_type == "http_probe":
        if url is not None:
            loc = _url_locator(url)
            return loc, action_type, {"url": loc}
        if host is not None and port is not None:
            address = host.ipv4 or host.ipv6 or host.hostname or ""
            scheme = "https" if port.number in _HTTPS_PORTS else "http"
            loc = f"{scheme}://{address}:{port.number}/"
            return (
                loc,
                action_type,
                {
                    "host_id": host.asset_id,
                    "port": str(port.number),
                    "scheme": scheme,
                    "url": loc,
                },
            )
    if action_type in {"technology_detection", "endpoint_discovery", "directory_enumeration"}:
        target = url
        if target is None and endpoint is not None:
            loc = endpoint.url_canonical
            loc = loc[4:] if loc.startswith("url:") else loc
            params = {"url": loc}
            if endpoint.url_id:
                params["url_id"] = endpoint.url_id
            if action_type == "directory_enumeration":
                params["wordlist"] = "small"
            return loc, action_type, params
        if target is not None:
            loc = _url_locator(target)
            params = {"url": loc, "url_id": target.asset_id}
            if action_type == "directory_enumeration":
                params["wordlist"] = "small"
            return loc, action_type, params
        if auth is not None:
            loc = auth.endpoint_canonical
            if loc.startswith("url:"):
                loc = loc[4:]
            elif "url:" in loc:
                loc = loc.split("url:", 1)[1]
            return loc, action_type, {"url": loc}
    if action_type == "dns_enumeration":
        fqdn = (domain.fqdn if domain else None) or (sub.fqdn if sub else None)
        if not fqdn and host is not None:
            fqdn = host.hostname
        if fqdn:
            params = {"fqdn": fqdn}
            if domain is not None:
                params["domain_id"] = domain.asset_id
            return fqdn, action_type, params
    if action_type == "subdomain_enumeration" and domain is not None:
        return (
            domain.fqdn,
            action_type,
            {"domain_id": domain.asset_id, "fqdn": domain.fqdn, "wordlist": "default"},
        )
    if action_type == "service_enumeration" and host is not None:
        address = host.ipv4 or host.ipv6 or host.hostname or ""
        params = {"host_id": host.asset_id}
        if port is not None:
            params["port"] = str(port.number)
        return address, action_type, params
    locator = chain[-1].label if chain else ""
    return locator, action_type, {}


def _asset(chain: list[GraphNode], snapshot: WorldSnapshot, cls: type) -> Any:
    for node in reversed(chain):
        asset = snapshot.peek_asset_by_id(node.ref_id)
        if isinstance(asset, cls):
            return asset
    return None


def _url_locator(url: UrlAsset) -> str:
    return f"{url.scheme}://{url.host}:{url.port}{url.path or '/'}"


def _relevance(chain: list[GraphNode], kinds: set[GraphNodeKind]) -> float:
    blob = " ".join(n.label.lower() for n in chain)
    if GraphNodeKind.AUTH_SURFACE in kinds or "login" in blob:
        return 1.0
    if any(token in blob for token in ("admin", "/api", "auth")):
        return 0.92
    if GraphNodeKind.FINDING in kinds or GraphNodeKind.VALIDATION_CANDIDATE in kinds:
        return 0.85
    if GraphNodeKind.URL in kinds or GraphNodeKind.SERVICE in kinds:
        return 0.72
    if GraphNodeKind.HOST in kinds or GraphNodeKind.DOMAIN in kinds:
        return 0.55
    return 0.40


def _completeness(kinds: set[GraphNodeKind]) -> float:
    expected: list[GraphNodeKind] = []
    if GraphNodeKind.DOMAIN in kinds or GraphNodeKind.SUBDOMAIN in kinds:
        expected.extend([GraphNodeKind.DOMAIN, GraphNodeKind.HOST])
    if GraphNodeKind.HOST in kinds or GraphNodeKind.PORT in kinds:
        expected.extend([GraphNodeKind.HOST, GraphNodeKind.PORT])
    if GraphNodeKind.URL in kinds or GraphNodeKind.ENDPOINT in kinds:
        expected.extend([GraphNodeKind.URL, GraphNodeKind.ENDPOINT])
    if GraphNodeKind.AUTH_SURFACE in kinds:
        expected.append(GraphNodeKind.AUTH_SURFACE)
    if not expected:
        expected = [GraphNodeKind.HOST]
    unique = list(dict.fromkeys(expected))
    have = sum(1 for kind in unique if kind in kinds)
    return clamp01(have / max(1, len(unique)))


def _importance(chain: list[GraphNode], snapshot: WorldSnapshot) -> float:
    best = 0.4
    for node in chain:
        asset = snapshot.peek_asset_by_id(node.ref_id)
        if asset is not None:
            best = max(best, asset_importance(asset, snapshot))
        elif node.kind is GraphNodeKind.AUTH_SURFACE:
            best = max(best, 0.88)
        elif node.kind is GraphNodeKind.FINDING:
            best = max(best, 0.7)
    return clamp01(best)


def _rationale(labels: list[str], questions: list[str], actions: list[str]) -> str:
    trail = " → ".join(labels[:8])
    if actions:
        return f"{trail}; next={actions[0]}"[:500]
    if questions:
        return f"{trail}; {questions[0]}"[:500]
    return trail[:500]


def _path_id(semantic: str) -> str:
    digest = hashlib.sha256(semantic.encode("utf-8")).digest()[:10]
    return PREFIX_PATH + generate_ulid(timestamp_ms=0, randomness=digest)


def _avg(values: list[float]) -> float:
    return clamp01(sum(values) / len(values)) if values else 0.0
