"""DNS / subdomain adapters: closed argv, fixture resolver, limits, no World Model."""

from __future__ import annotations

import json

import pytest

from cyberx.domain.enums import ActionStatus, Risk
from cyberx.domain.errors import ExecutionBypassError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget
from cyberx.domain.time import utcnow
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.ports.execution import ExecutionContext
from cyberx.recon.dns.adapter import DnsAdapter, SubdomainAdapter
from cyberx.recon.dns.resolver import FixtureDnsResolver
from cyberx.recon.dns.wordlist import DEFAULT_LABELS, candidates_for


def _action(action_type: str, fqdn: str = "box.htb") -> Action:
    params = {"fqdn": fqdn}
    if action_type == "subdomain_enumeration":
        params["wordlist"] = "default"
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type=action_type,
        target=ActionTarget(canonical_locator=fqdn),
        parameters=params,
        reason="dns",
        expected_information_gain=0.8,
        risk=Risk.INFO if action_type == "dns_enumeration" else Risk.LOW,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key="dns",
        created_at=utcnow(),
    )


def test_wordlist_is_closed_and_capped() -> None:
    assert len(DEFAULT_LABELS) <= 100
    assert {"www", "mail", "dev", "admin", "api", "staging", "test", "vpn"} <= set(DEFAULT_LABELS)
    names = candidates_for("box.htb", limit=100)
    assert len(names) <= 100
    assert names[0] == "www.box.htb"
    assert len(candidates_for("box.htb", limit=8)) == 8


def test_dns_adapter_argv_is_closed(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    resolver.add("box.htb", "A", "10.10.10.10")
    adapter = DnsAdapter(resolver=resolver)
    action = _action("dns_enumeration")
    argv = adapter.build_argv(action)
    assert argv[0] == "dns-query"
    assert "box.htb" in argv
    assert not any(item.startswith("-") for item in argv[1:])
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=30,
        workdir=str(tmp_path),
        allowed_targets=["box.htb"],
        allow_subdomains=True,
    )
    artifact = adapter.run(action, ctx)
    body = json.loads(artifact.body or b"{}")
    assert body["fqdn"] == "box.htb"
    assert any(r["type"] == "A" and r["value"] == "10.10.10.10" for r in body["records"])


def test_nxdomain_and_timeout_payloads(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    adapter = DnsAdapter(resolver=resolver)
    action = _action("dns_enumeration", "missing.box.htb")
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=5,
        workdir=str(tmp_path),
        allowed_targets=["box.htb", "missing.box.htb"],
        allow_subdomains=True,
    )
    artifact = adapter.run(action, ctx)
    body = json.loads(artifact.body or b"{}")
    assert body["status"] == "nxdomain"
    assert body["records"] == []

    timed = FixtureDnsResolver()
    from cyberx.recon.dns.resolver import DnsAnswer

    timed._answers[("slow.box.htb", "A")] = DnsAnswer(
        name="slow.box.htb", rtype="A", rcode="TIMEOUT", timed_out=True, error="timeout"
    )
    adapter = DnsAdapter(resolver=timed)
    action = _action("dns_enumeration", "slow.box.htb")
    ctx = ctx.model_copy(update={"action_id": action.action_id})
    artifact = adapter.run(action, ctx)
    assert json.loads(artifact.body or b"{}")["status"] == "timeout"
    assert adapter._last_result is not None
    assert adapter._last_result.timed_out is True


def test_subdomain_adapter_respects_limit_and_scope(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    resolver.add("www.box.htb", "A", "10.10.10.10")
    resolver.add("mail.box.htb", "A", "10.10.10.12")
    resolver.add("mail.box.htb", "CNAME", "box.htb")
    adapter = SubdomainAdapter(resolver=resolver, max_candidates=8)
    action = _action("subdomain_enumeration")
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=30,
        workdir=str(tmp_path),
        allowed_targets=["box.htb"],
        allow_subdomains=True,
    )
    artifact = adapter.run(action, ctx)
    body = json.loads(artifact.body or b"{}")
    assert body["candidate_count"] == 8
    assert "www.box.htb" in body["subdomains"]
    assert "mail.box.htb" in body["subdomains"]
    assert "dev.box.htb" not in body["subdomains"]
    assert any(row["status"] == "nxdomain" for row in body["negative"])
    queried = {name for name, _rtype in resolver.queries}
    assert "evil.example" not in queried


def test_out_of_scope_name_not_queried(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    adapter = DnsAdapter(resolver=resolver)
    action = _action("dns_enumeration", "evil.example")
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=10,
        workdir=str(tmp_path),
        allowed_targets=["box.htb"],
        allow_subdomains=True,
    )
    artifact = adapter.run(action, ctx)
    assert json.loads(artifact.body or b"{}")["status"] == "out_of_scope"
    assert resolver.queries == []


def test_executor_requires_authorized() -> None:
    executor = ReconExecutor(dns=DnsAdapter(), dns_enabled=True)
    with pytest.raises(ExecutionBypassError):
        executor.execute(_action("dns_enumeration"))  # type: ignore[arg-type]


def test_codec_round_trip_a_record() -> None:
    from cyberx.recon.dns.resolver import decode_response, encode_query

    query = encode_query("box.htb", "A", 7)
    # Build a minimal NOERROR A response using the same question + one uncompressed answer
    import struct

    header = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0)
    qname = query[12:]
    # owner pointer to question name at offset 12
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes((10, 10, 10, 10))
    packet = header + qname + answer
    decoded = decode_response(packet, "box.htb", "A", 7)
    assert decoded.rcode == "NOERROR"
    assert decoded.values == ["10.10.10.10"]
