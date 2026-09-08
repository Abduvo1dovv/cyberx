"""dns_enumeration and subdomain_enumeration adapters. No World Model. No shell."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberx.actions.params import DnsEnumerationParams, SubdomainEnumerationParams
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.identity import is_subdomain_of, normalize_fqdn, validate_fqdn
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.dns.resolver import (
    DnsAnswer,
    DnsResolver,
    UdpDnsResolver,
    query_records,
)
from cyberx.recon.dns.wordlist import candidates_for

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
SUBDOMAIN_RECORD_TYPES = ("A", "AAAA", "CNAME")
MAX_CANDIDATES = 100


@dataclass
class DnsCallMeta:
    timed_out: bool = False
    error: str | None = None
    status: int | None = 0
    exit_code: int = 0


def _name_allowed(name: str, ctx: ExecutionContext) -> bool:
    if not ctx.allowed_targets:
        return True
    try:
        cleaned = normalize_fqdn(name)
    except Exception:
        return False
    allowed: list[str] = []
    for raw in ctx.allowed_targets:
        try:
            allowed.append(normalize_fqdn(raw))
        except Exception:
            continue
    if cleaned in allowed:
        return True
    if ctx.allow_subdomains and any(is_subdomain_of(cleaned, parent) for parent in allowed):
        return True
    return False


class DnsAdapter:
    name = "dns_adapter"
    action_types: tuple[str, ...] = ("dns_enumeration",)

    def __init__(
        self,
        *,
        resolver: DnsResolver | None = None,
        events: EventSink | None = None,
        available: bool | None = True,
    ) -> None:
        self._resolver = resolver or UdpDnsResolver()
        self._events = events or NullEventSink()
        self._forced_available = available
        self._last_argv: list[str] = []
        self._last_result: DnsCallMeta | None = None

    def is_available(self) -> bool:
        if self._forced_available is not None:
            return self._forced_available
        return True

    def build_argv(self, action: Action) -> list[str]:
        params = DnsEnumerationParams.model_validate(action.parameters)
        argv = ["dns-query", params.fqdn, ",".join(DNS_RECORD_TYPES)]
        self._last_argv = argv
        return argv

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        if action.action_type != "dns_enumeration":
            raise DomainValidationError("dns adapter only runs dns_enumeration")
        params = DnsEnumerationParams.model_validate(action.parameters)
        fqdn = params.fqdn
        self._last_argv = ["dns-query", fqdn, ",".join(DNS_RECORD_TYPES)]
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.DNS_STARTED,
                mission_id=action.mission_id,
                payload={"action_id": action.action_id, "fqdn": fqdn},
            ),
        )
        if not _name_allowed(fqdn, ctx):
            self._last_result = DnsCallMeta(error="out_of_scope", exit_code=1, status=None)
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.DNS_FAILED,
                    mission_id=action.mission_id,
                    payload={"reason": "out_of_scope", "fqdn": fqdn},
                ),
            )
            return self._artifact(
                action, ctx, {"fqdn": fqdn, "status": "out_of_scope", "records": []}
            )
        answers = query_records(self._resolver, fqdn, DNS_RECORD_TYPES, float(ctx.timeout_s))
        payload = _records_payload(fqdn, answers)
        meta = _meta_from_answers(answers)
        self._last_result = meta
        kind = EventType.DNS_FAILED if meta.error else EventType.DNS_COMPLETED
        emit_safe(
            self._events,
            DomainEvent(
                event_type=kind,
                mission_id=action.mission_id,
                payload={
                    "fqdn": fqdn,
                    "record_count": len(payload["records"]),
                    "error": meta.error,
                },
            ),
        )
        return self._artifact(action, ctx, payload)

    def _artifact(
        self, action: Action, ctx: ExecutionContext, payload: dict[str, Any]
    ) -> RawArtifact:
        return _json_artifact(self.name, action, ctx, payload)


class SubdomainAdapter:
    name = "subdomain_adapter"
    action_types: tuple[str, ...] = ("subdomain_enumeration",)

    def __init__(
        self,
        *,
        resolver: DnsResolver | None = None,
        events: EventSink | None = None,
        max_candidates: int = MAX_CANDIDATES,
        available: bool | None = True,
    ) -> None:
        self._resolver = resolver or UdpDnsResolver()
        self._events = events or NullEventSink()
        self._max = max(1, min(int(max_candidates), MAX_CANDIDATES))
        self._forced_available = available
        self._last_argv: list[str] = []
        self._last_result: DnsCallMeta | None = None

    def is_available(self) -> bool:
        if self._forced_available is not None:
            return self._forced_available
        return True

    def build_argv(self, action: Action) -> list[str]:
        params = SubdomainEnumerationParams.model_validate(action.parameters)
        zone = params.fqdn or ""
        argv = ["dns-query", f"*.{zone}", "A,AAAA,CNAME", f"limit={self._max}"]
        self._last_argv = argv
        return argv

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        if action.action_type != "subdomain_enumeration":
            raise DomainValidationError("subdomain adapter only runs subdomain_enumeration")
        params = SubdomainEnumerationParams.model_validate(action.parameters)
        zone = params.fqdn
        if not zone:
            raise DomainValidationError("subdomain_enumeration requires fqdn")
        zone = validate_fqdn(zone, allow_single_label=False)
        names = candidates_for(zone, limit=self._max)
        self._last_argv = ["dns-query", f"*.{zone}", "A,AAAA,CNAME", f"limit={len(names)}"]
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.DNS_STARTED,
                mission_id=action.mission_id,
                payload={
                    "action_id": action.action_id,
                    "fqdn": zone,
                    "candidates": len(names),
                },
            ),
        )
        if not _name_allowed(zone, ctx):
            self._last_result = DnsCallMeta(error="out_of_scope", exit_code=1, status=None)
            return self._artifact(
                action, ctx, {"fqdn": zone, "status": "out_of_scope", "subdomains": []}
            )
        remaining = float(ctx.timeout_s)
        discovered: list[dict[str, Any]] = []
        negative: list[dict[str, Any]] = []
        seen: set[str] = set()
        timed_out = False
        per = max(0.2, remaining / max(1, len(names)))
        for candidate in names:
            if remaining <= 0.2:
                timed_out = True
                break
            if not _name_allowed(candidate, ctx):
                negative.append({"fqdn": candidate, "status": "out_of_scope"})
                continue
            answers = query_records(self._resolver, candidate, SUBDOMAIN_RECORD_TYPES, per)
            remaining -= per
            if any(a.timed_out for a in answers):
                timed_out = True
                negative.append({"fqdn": candidate, "status": "timeout"})
                break
            if any(a.rcode == "NXDOMAIN" for a in answers) and not any(a.values for a in answers):
                negative.append({"fqdn": candidate, "status": "nxdomain"})
                continue
            if any(a.rcode == "SERVFAIL" for a in answers) and not any(a.values for a in answers):
                negative.append({"fqdn": candidate, "status": "servfail"})
                continue
            records = _flatten_records(candidate, answers)
            if not records:
                negative.append({"fqdn": candidate, "status": "empty"})
                continue
            key = normalize_fqdn(candidate)
            if key in seen:
                continue
            seen.add(key)
            discovered.append({"fqdn": key, "records": records})
        payload = {
            "fqdn": zone,
            "status": "timeout" if timed_out and not discovered else "ok",
            "subdomains": [row["fqdn"] for row in discovered],
            "details": discovered,
            "negative": negative,
            "candidate_count": len(names),
        }
        self._last_result = DnsCallMeta(timed_out=timed_out and not discovered)
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.DNS_COMPLETED,
                mission_id=action.mission_id,
                payload={"fqdn": zone, "discovered": len(discovered)},
            ),
        )
        return self._artifact(action, ctx, payload)

    def _artifact(
        self, action: Action, ctx: ExecutionContext, payload: dict[str, Any]
    ) -> RawArtifact:
        return _json_artifact(self.name, action, ctx, payload)


def _records_payload(fqdn: str, answers: list[DnsAnswer]) -> dict[str, Any]:
    records = _flatten_records(fqdn, answers)
    status = "ok"
    if answers and all(a.timed_out for a in answers):
        status = "timeout"
    elif answers and answers[0].rcode == "NXDOMAIN" and not records:
        status = "nxdomain"
    elif answers and not records and any(a.rcode == "SERVFAIL" for a in answers):
        status = "servfail"
    return {
        "fqdn": fqdn,
        "status": status,
        "records": records,
        "answers": [
            {"type": a.rtype, "rcode": a.rcode, "values": a.values, "error": a.error}
            for a in answers
        ],
    }


def _flatten_records(owner: str, answers: list[DnsAnswer]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for answer in answers:
        for value in answer.values:
            if not value:
                continue
            item = {"type": answer.rtype, "name": owner, "value": value}
            if answer.rtype == "MX" and " " in value:
                pref, _, exchange = value.partition(" ")
                item["value"] = exchange
                item["preference"] = pref
            rows.append(item)
    return rows


def _meta_from_answers(answers: list[DnsAnswer]) -> DnsCallMeta:
    if any(a.timed_out for a in answers) and not any(a.values for a in answers):
        return DnsCallMeta(timed_out=True, error="timeout", status=None, exit_code=-1)
    if any(a.error == "out_of_scope" for a in answers):
        return DnsCallMeta(error="out_of_scope", status=None, exit_code=1)
    return DnsCallMeta()


def _json_artifact(
    adapter_name: str, action: Action, ctx: ExecutionContext, payload: dict[str, Any]
) -> RawArtifact:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = None
    if ctx.workdir:
        dest = Path(ctx.workdir) / "artifacts" / f"{adapter_name}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        path = str(dest)
    locator = ""
    try:
        locator = str(action.parameters.get("fqdn") or action.target.canonical_locator or "")
    except Exception:
        locator = action.target.canonical_locator or ""
    return RawArtifact(
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        adapter_name=adapter_name,
        media_type="application/json",
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
        body=raw,
        path=path,
        mission_id=action.mission_id,
        source_locator=locator,
    )
