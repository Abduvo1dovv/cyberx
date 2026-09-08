"""Golden: hostname → dns_enumeration → world change → different next action."""

from __future__ import annotations

from tests.conftest import create_cmd

from cyberx.brain.context import BrainContextBuilder
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.recon.dns.adapter import DnsAdapter, SubdomainAdapter
from cyberx.recon.dns.resolver import FixtureDnsResolver
from cyberx.recon.stub import StubAdapter


def _engine(tmp_path, resolver: FixtureDnsResolver):
    dns = DnsAdapter(resolver=resolver)
    sub = SubdomainAdapter(resolver=resolver, max_candidates=8)
    executor = ReconExecutor(
        dns=dns,
        subdomain=sub,
        stub=StubAdapter(),
        dns_enabled=True,
        data_dir=str(tmp_path),
    )
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd(raw_target="box.htb"))
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    sink = InMemoryEventSink()
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor, events=sink),
        events=sink,
    )
    return service, mission.mission_id, engine


def test_dns_then_adaptive_replan(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    resolver.add("box.htb", "A", "10.10.10.10")
    resolver.add("www.box.htb", "A", "10.10.10.10")
    resolver.add("mail.box.htb", "A", "10.10.10.12")
    service, mid, engine = _engine(tmp_path, resolver)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "dns_enumeration"
    world = engine.world(mid)
    assert any(h.ipv4 == "10.10.10.10" for h in world.get_hosts())
    # Apex A does not expand scope to the resolved IP and does not
    # invent subdomains, so domain.subdomains_unknown remains.
    second = engine.run_one_cycle(mid)
    assert second.selected_action_type == "subdomain_enumeration"
    assert second.coverage_key != first.coverage_key
    names = {s.fqdn for s in engine.world(mid).get_subdomains()}
    assert "www.box.htb" in names
    assert "mail.box.htb" in names
    ctx = BrainContextBuilder().build(
        engine.world(mid).snapshot(),
        service.get(mid),
        scope=service.get_bundle(mid).scope,
    )
    assert any(c.get("predicate") == "dns.record" for c in ctx.claims)
    kinds = {row.get("kind") for row in ctx.top_assets}
    assert "host" in kinds
    assert "subdomain" in kinds or "www.box.htb" in names
    oos_ips = [h for h in engine.world(mid).get_hosts() if h.ipv4 and h.out_of_scope]
    assert oos_ips
    third = engine.run_one_cycle(mid)
    assert third.selected_action_type != "subdomain_enumeration"


def test_subdomain_enum_discovers_www(tmp_path) -> None:
    resolver = FixtureDnsResolver()
    resolver.add("box.htb", "A", "10.10.10.10")
    resolver.add("www.box.htb", "A", "10.10.10.10")
    resolver.add("admin.box.htb", "A", "10.10.10.13")
    service, mid, engine = _engine(tmp_path, resolver)
    types = []
    for _ in range(4):
        report = engine.run_one_cycle(mid)
        if report.completed:
            break
        types.append(report.selected_action_type)
        if report.selected_action_type == "subdomain_enumeration":
            break
    world = engine.world(mid)
    names = {s.fqdn for s in world.get_subdomains()}
    if "subdomain_enumeration" in types:
        assert "www.box.htb" in names or any(h.hostname == "www.box.htb" for h in world.get_hosts())
    assert types[0] == "dns_enumeration"
    assert types.count("dns_enumeration") == 1
