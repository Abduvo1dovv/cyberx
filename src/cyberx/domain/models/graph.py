"""Attack-surface graph projection. Not a source of truth; World Model is."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import V1_ACTION_TYPES, GraphEdgeKind, GraphNodeKind
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_PATH, require_id
from cyberx.domain.models.common import DomainModel

_FORBIDDEN_NODE = ("exploit", "payload", "shell", "session", "persist", "foothold")


class GraphNode(DomainModel):
    node_id: str
    kind: GraphNodeKind
    semantic_key: str = Field(min_length=1, max_length=400)
    label: str = Field(min_length=1, max_length=200)
    ref_id: str = ""
    epistemic_status: str = ""
    out_of_scope: bool = False
    confidence: float = 0.0
    evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def _conf(cls, value: float) -> float:
        return validate_confidence(value)

    @model_validator(mode="after")
    def _safety(self) -> GraphNode:
        if not self.ref_id:
            self.ref_id = self.node_id
        lowered = self.kind.value.lower()
        if any(token in lowered for token in _FORBIDDEN_NODE):
            raise DomainValidationError("graph node kind is not allowed in v1")
        return self


class GraphEdge(DomainModel):
    kind: GraphEdgeKind
    src_key: str = Field(min_length=1, max_length=400)
    dst_key: str = Field(min_length=1, max_length=400)
    src_id: str = ""
    dst_id: str = ""
    rule: str = Field(min_length=1, max_length=80)
    epistemic_status: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    invalidated: bool = False

    @property
    def identity_key(self) -> str:
        return f"{self.kind.value}|{self.src_key}|{self.dst_key}"


class InvestigationPath(DomainModel):
    path_id: str
    semantic_key: str = Field(min_length=1, max_length=800)
    nodes: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    edges: list[str] = Field(default_factory=list)
    relevance: float = 0.0
    confidence: float = 0.0
    information_value: float = 0.0
    completeness: float = 0.0
    priority: float = 0.0
    unresolved_questions: list[str] = Field(default_factory=list)
    candidate_actions: list[str] = Field(default_factory=list)
    rationale: str = Field(default="", max_length=500)
    locator: str = ""
    action_type: str = ""
    parameters: dict[str, str] = Field(default_factory=dict)
    out_of_scope: bool = False

    @field_validator("path_id")
    @classmethod
    def _pid(cls, value: str) -> str:
        return require_id(value, PREFIX_PATH)

    @field_validator(
        "relevance",
        "confidence",
        "information_value",
        "completeness",
        "priority",
    )
    @classmethod
    def _unit(cls, value: float) -> float:
        return validate_confidence(value, field="path score")

    @model_validator(mode="after")
    def _no_exploit(self) -> InvestigationPath:
        blob = " ".join(self.candidate_actions).lower()
        if any(token in blob for token in ("exploit", "payload", "shell", "brute")):
            raise DomainValidationError("investigation paths cannot name exploit actions")
        for action in self.candidate_actions:
            if action not in V1_ACTION_TYPES:
                raise DomainValidationError(
                    f"investigation path action {action!r} is not a v1 catalog type"
                )
        return self


class GraphSnapshot(DomainModel):
    mission_id: str
    revision: int
    digest: str
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    conflict_count: int = 0

    def get_nodes(self) -> tuple[GraphNode, ...]:
        return self.nodes

    def get_edges(self, *, include_invalidated: bool = True) -> tuple[GraphEdge, ...]:
        if include_invalidated:
            return self.edges
        return tuple(e for e in self.edges if not e.invalidated)

    def node_by_key(self, semantic_key: str) -> GraphNode | None:
        for node in self.nodes:
            if node.semantic_key == semantic_key:
                return node
        return None

    def node_by_id(self, node_id: str) -> GraphNode | None:
        for node in self.nodes:
            if node.node_id == node_id or node.ref_id == node_id:
                return node
        return None

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for node in self.nodes:
            counts[node.kind.value] = counts.get(node.kind.value, 0) + 1
        return {
            "mission_id": self.mission_id,
            "revision": self.revision,
            "digest": self.digest,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_counts": counts,
            "conflict_count": self.conflict_count,
            "out_of_scope_count": sum(1 for n in self.nodes if n.out_of_scope),
        }


class GraphSummary(DomainModel):
    revision: int
    digest: str
    node_count: int = 0
    edge_count: int = 0
    node_counts: dict[str, int] = Field(default_factory=dict)
    top_assets: list[str] = Field(default_factory=list)
    important_paths: list[str] = Field(default_factory=list)
    unresolved_branches: list[str] = Field(default_factory=list)
    conflict_count: int = 0
    out_of_scope_count: int = 0
