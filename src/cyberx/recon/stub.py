"""Deterministic stub adapter. Never launches processes or opens sockets."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cyberx.domain.enums import V1_ACTION_TYPES
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.execution import ExecutionContext, RawArtifact, ToolAdapter

# Closed synthetic fixtures. Same inputs → same payload bytes.
_SYNTHETIC: dict[str, dict[str, Any]] = {
    "network_discovery": {
        "hosts": [{"ip": "10.10.11.1", "alive": True}, {"ip": "10.10.11.23", "alive": True}],
    },
    "port_scan": {
        "ports": [
            {"number": 22, "protocol": "tcp", "state": "open"},
            {"number": 80, "protocol": "tcp", "state": "open"},
            {"number": 443, "protocol": "tcp", "state": "open"},
        ],
    },
    "service_enumeration": {
        "services": [
            {"port": 22, "name": "ssh", "product": "OpenSSH"},
            {"port": 80, "name": "http", "product": "nginx"},
        ],
    },
    "http_probe": {
        "status": 200,
        "title": "Stub Host",
        "headers": {"server": "nginx"},
    },
    "technology_detection": {
        "technologies": [{"product": "nginx", "version": "1.24.0", "source": "header"}],
    },
    "dns_enumeration": {
        "records": [{"type": "A", "name": "box.htb", "value": "10.10.11.23"}],
    },
    "subdomain_enumeration": {
        "subdomains": ["www.box.htb", "admin.box.htb"],
    },
    "directory_enumeration": {
        "paths": [
            {"path": "/admin", "status": 401},
            {"path": "/login", "status": 200},
            {"path": "/robots.txt", "status": 200},
        ],
    },
    "endpoint_discovery": {
        "endpoints": [
            {"method": "GET", "path": "/login"},
            {"method": "POST", "path": "/login"},
        ],
    },
}


def synthetic_payload(action: Action) -> dict[str, Any]:
    body = dict(_SYNTHETIC[action.action_type])
    body["action_type"] = action.action_type
    body["coverage_key"] = action.coverage_key
    body["target"] = action.target.canonical_locator or action.target.asset_id
    return body


def payload_bytes(action: Action) -> bytes:
    dumped = json.dumps(synthetic_payload(action), sort_keys=True, separators=(",", ":"))
    return dumped.encode("utf-8")


class StubAdapter:
    """Always available. argv is a list of strings. No shell."""

    name = "stub_adapter"
    action_types: tuple[str, ...] = V1_ACTION_TYPES

    def is_available(self) -> bool:
        return True

    def build_argv(self, action: Action) -> list[str]:
        locator = action.target.canonical_locator or action.target.asset_id or ""
        return ["stub", action.action_type, locator]

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        raw = payload_bytes(action)
        digest = hashlib.sha256(raw).hexdigest()
        locator = action.target.canonical_locator or action.target.asset_id or ""
        return RawArtifact(
            artifact_id=new_id(PREFIX_ARTIFACT),
            tool_run_id=new_id(PREFIX_TOOL_RUN),
            adapter_name=self.name,
            media_type="application/json",
            sha256=digest,
            byte_size=len(raw),
            truncated=False,
            body=raw,
            path=None,
            mission_id=action.mission_id,
            source_locator=locator or None,
        )


def default_stub_adapter() -> ToolAdapter:
    return StubAdapter()
