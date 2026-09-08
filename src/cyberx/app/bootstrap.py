"""Composition root. The only place that selects concrete infrastructure."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyberx.actions.catalog import ActionCatalog
from cyberx.actions.validator import ActionValidator
from cyberx.ai.factory import build_provider
from cyberx.app.facade import OperatorFacade
from cyberx.brain.facade import Brain
from cyberx.config import AppConfig
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.engine.stub_executor import StubExecutor
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.policy.engine import PolicyEngine
from cyberx.ports.events import EventSink
from cyberx.recon.dns.adapter import DnsAdapter, SubdomainAdapter
from cyberx.recon.dns.resolver import UdpDnsResolver
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.directory import DirectoryAdapter
from cyberx.recon.http.endpoint import EndpointAdapter
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.stub import StubAdapter
from cyberx.scope.checker import ScopeChecker
from cyberx.storage.sqlite import SqliteStore


class Application:
    """Wired CyberX process. Call close() when the process exits."""

    def __init__(
        self,
        config: AppConfig,
        store: Any,
        events: EventSink,
        service: MissionService,
        engine: MissionEngine,
        facade: OperatorFacade,
        catalog: ActionCatalog,
        policy: PolicyEngine,
        executor: Any,
    ) -> None:
        self.config = config
        self.store = store
        self.events = events
        self.service = service
        self.engine = engine
        self.facade = facade
        self.catalog = catalog
        self.policy = policy
        self.executor = executor

    def close(self) -> None:
        closer = getattr(self.store, "close", None)
        if callable(closer):
            closer()


def bootstrap(
    config: AppConfig | None = None,
    *,
    store: Any | None = None,
    events: EventSink | None = None,
) -> Application:
    """Assemble the running process. Inject store/events in tests."""
    cfg = config or AppConfig.from_env()
    sink: EventSink = events or InMemoryEventSink()
    if store is None:
        data_dir = Path(cfg.runtime.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        store = SqliteStore(data_dir / "cyberx.db", data_dir=data_dir)
    catalog = ActionCatalog()
    validator = ActionValidator(catalog)
    policy = PolicyEngine(catalog, validator=validator, scope_checker=ScopeChecker())
    if cfg.runtime.stub_mode:
        executor: Any = StubExecutor()
    else:
        nmap = NmapAdapter(
            binary=cfg.nmap.binary,
            events=sink,
            max_bytes=cfg.actions.max_artifact_bytes,
            max_retries=cfg.nmap.max_retries,
        )
        http = HttpAdapter(
            events=sink,
            max_body_bytes=cfg.http.max_body_bytes,
            max_redirects=cfg.http.max_redirects,
            tls_verify=cfg.http.tls_verify,
            user_agent=cfg.http.user_agent,
        )
        tech = TechAdapter(
            events=sink,
            max_body_bytes=cfg.http.max_body_bytes,
            max_redirects=cfg.http.max_redirects,
            tls_verify=cfg.http.tls_verify,
            user_agent=cfg.http.user_agent,
        )
        endpoint = EndpointAdapter()
        directory = DirectoryAdapter(
            events=sink,
            max_body_bytes=min(65536, cfg.http.max_body_bytes),
            max_candidates=cfg.http.directory_max_candidates,
            tls_verify=cfg.http.tls_verify,
            user_agent=cfg.http.user_agent,
        )
        resolver = UdpDnsResolver(nameserver=cfg.dns.nameserver)
        dns = DnsAdapter(resolver=resolver, events=sink)
        subdomain = SubdomainAdapter(
            resolver=resolver,
            events=sink,
            max_candidates=cfg.dns.subdomain_max_candidates,
        )
        executor = ReconExecutor(
            nmap=nmap,
            http=http,
            tech=tech,
            endpoint=endpoint,
            directory=directory,
            dns=dns,
            subdomain=subdomain,
            stub=StubAdapter(),
            nmap_enabled=True,
            http_enabled=True,
            dns_enabled=True,
            catalog=catalog,
            events=sink,
            data_dir=cfg.runtime.data_dir,
        )
    pipeline = EvidencePipeline()
    provider = build_provider(cfg, events=sink)
    brain = Brain(catalog=catalog, provider=provider)
    service = MissionService(store, events=sink)
    boundary = ExecutionBoundary(
        validator=validator,
        policy=policy,
        executor=executor,
        events=sink,
    )
    engine = MissionEngine(
        service,
        brain=brain,
        boundary=boundary,
        pipeline=pipeline,
        store=store,
        events=sink,
    )
    facade = OperatorFacade(cfg, service, engine, sink, stub_mode=cfg.runtime.stub_mode)
    return Application(
        config=cfg,
        store=store,
        events=sink,
        service=service,
        engine=engine,
        facade=facade,
        catalog=catalog,
        policy=policy,
        executor=executor,
    )
