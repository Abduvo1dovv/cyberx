"""Closed v1 enumerations (SPEC Appendix A)."""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """3.10-compatible str enum (stdlib StrEnum is 3.11+)."""

    def __str__(self) -> str:
        return str(self.value)


class MissionMode(StrEnum):
    CTF = "ctf"
    LAB = "lab"
    AUTHORIZED_ASSESSMENT = "authorized_assessment"


class MissionStatus(StrEnum):
    CREATED = "CREATED"
    CONFIRMED = "CONFIRMED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class StopReason(StrEnum):
    OPERATOR = "operator"
    NO_ACTIONS = "no_actions"
    OBJECTIVES_MET = "objectives_met"
    MAX_ITERATIONS = "max_iterations"
    MAX_RUNTIME = "max_runtime"
    STALLED = "stalled"
    TOO_MANY_FAILURES = "too_many_failures"
    ERROR = "error"


class EpistemicStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    KNOWN = "KNOWN"
    SUSPECTED = "SUSPECTED"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    INVALIDATED = "INVALIDATED"


class ActionStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    QUEUED = "QUEUED"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class Risk(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"


class TargetKind(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    URL = "url"


class LocatorStatus(StrEnum):
    CURRENT = "current"
    HISTORICAL = "historical"
    OBSERVED = "observed"
    UNREACHABLE = "unreachable"


class AssetKind(StrEnum):
    HOST = "host"
    INTERFACE = "interface"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_SURFACE = "auth_surface"


class PolicyVerdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"


class FindingKind(StrEnum):
    OPEN_PORT = "open_port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    URL = "url"
    INTERESTING_PATH = "interesting_path"
    AUTH_SURFACE = "auth_surface"
    DNS = "dns"
    ANOMALY = "anomaly"
    OUT_OF_SCOPE_OBSERVATION = "out_of_scope_observation"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"
    SUPERSEDED = "superseded"
    INVALIDATED = "invalidated"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    RETIRED = "retired"
    PROMOTED = "promoted"


class HypothesisSource(StrEnum):
    HEURISTIC = "heuristic"
    AI = "ai"


class ValidationStatus(StrEnum):
    PROPOSED = "proposed"
    QUEUED = "queued"
    TESTING = "testing"
    SUPPORTED = "supported"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
    EXPIRED = "expired"


class GraphNodeKind(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    INTERFACE = "interface"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_SURFACE = "auth_surface"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    VALIDATION_CANDIDATE = "validation_candidate"


class GraphEdgeKind(StrEnum):
    RESOLVES_TO = "RESOLVES_TO"
    HOSTS = "HOSTS"
    EXPOSES = "EXPOSES"
    RUNS = "RUNS"
    IMPLEMENTS = "IMPLEMENTS"
    SERVES = "SERVES"
    CONTAINS = "CONTAINS"
    LINKS_TO = "LINKS_TO"
    USES = "USES"
    AUTHENTICATES = "AUTHENTICATES"
    SUPPORTED_BY = "SUPPORTED_BY"
    RELATED_TO = "RELATED_TO"
    DERIVED_FROM = "DERIVED_FROM"
    HAS_FINDING = "HAS_FINDING"
    HAS_HYPOTHESIS = "HAS_HYPOTHESIS"
    HAS_VALIDATION = "HAS_VALIDATION"


FORBIDDEN_GRAPH_NODES = (
    "exploit",
    "payload",
    "shell",
    "session",
    "persistence",
    "foothold",
)


class TimelineKind(StrEnum):
    MISSION_STATUS = "mission_status"
    DECISION = "decision"
    POLICY = "policy"
    ACTION = "action"
    EVIDENCE = "evidence"
    WORLD = "world"
    HYPOTHESIS = "hypothesis"
    AI = "ai"
    ERROR = "error"
    OPERATOR = "operator"
    NETWORK = "network"


class ReachabilityStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    ROUTE_MISSING = "ROUTE_MISSING"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"


BLOCKING_REACHABILITY = frozenset(
    {
        ReachabilityStatus.ROUTE_MISSING,
        ReachabilityStatus.UNREACHABLE,
        ReachabilityStatus.BLOCKED,
    }
)


class AddressType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    NAME = "name"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    OPTIONS = "OPTIONS"


class ParamLocation(StrEnum):
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"


class AuthSurfaceKind(StrEnum):
    HTTP_BASIC = "http_basic"
    HTTP_FORM = "http_form"
    HTTP_BEARER_CHALLENGE = "http_bearer_challenge"
    UNKNOWN = "unknown"


class TechSource(StrEnum):
    HEADER = "header"
    BODY = "body"
    BANNER = "banner"
    TLS = "tls"
    BEHAVIOR = "behavior"


class SubdomainSource(StrEnum):
    ENUM = "enum"
    BRUTE = "brute"
    CERT = "cert"
    TRANSFER = "transfer"


REGISTERED_AI_PROVIDERS = frozenset(
    {"none", "grok", "gemini", "claude", "openai", "deepseek", "local", "custom"}
)

ALLOWED_PROTOCOLS = frozenset({"tcp", "udp", "http", "https", "dns"})

V1_POLICY_PROFILE = "recon_default"

OBSERVATION_PREDICATES = frozenset(
    {
        "host.alive",
        "host.address",
        "host.hostname",
        "port.state",
        "service.name",
        "service.product",
        "service.version",
        "service.banner",
        "http.status",
        "http.title",
        "http.header",
        "http.redirect",
        "http.body_hash",
        "http.tech",
        "dns.record",
        "dns.subdomain",
        "url.seen",
        "endpoint.seen",
        "param.seen",
        "auth.seen",
    }
)

GAP_KINDS = frozenset(
    {
        "host.unresolved",
        "host.ports_unknown",
        "port.service_unknown",
        "service.http_unprobed",
        "url.tech_unknown",
        "domain.subdomains_unknown",
        "service.directories_unknown",
        "endpoint.params_unknown",
    }
)

FORBIDDEN_ACTION_MARKERS = ("exploit", "validate", "privesc", "persist", "shell")

V1_ACTION_TYPES = (
    "network_discovery",
    "port_scan",
    "service_enumeration",
    "http_probe",
    "technology_detection",
    "dns_enumeration",
    "subdomain_enumeration",
    "directory_enumeration",
    "endpoint_discovery",
)
