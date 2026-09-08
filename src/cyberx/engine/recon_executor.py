"""Authorized-only executor. Routes nmap actions to NmapAdapter, others to stub."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.domain.enums import ActionResultStatus, ActionStatus
from cyberx.domain.errors import AdapterUnavailable, ExecutionBypassError
from cyberx.domain.ids import PREFIX_RESULT, new_id
from cyberx.domain.models.actions import ActionResult, ToolRun
from cyberx.domain.time import utcnow
from cyberx.engine.results import ExecutionOutcome
from cyberx.engine.stub_executor import _count_obs
from cyberx.ports.events import EventSink, NullEventSink
from cyberx.ports.execution import AuthorizedAction, ExecutionContext, RawArtifact
from cyberx.recon.dns.adapter import DnsAdapter, SubdomainAdapter
from cyberx.recon.http.adapter import HttpAdapter
from cyberx.recon.http.directory import DirectoryAdapter
from cyberx.recon.http.endpoint import EndpointAdapter
from cyberx.recon.http.request import HTTP_ACTION_TYPES
from cyberx.recon.http.tech import TechAdapter
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.argv import NMAP_ACTION_TYPES
from cyberx.recon.stub import StubAdapter, synthetic_payload


class ReconExecutor:
    """The only production path from AuthorizedAction to a tool adapter."""

    def __init__(
        self,
        *,
        nmap: NmapAdapter | None = None,
        http: HttpAdapter | None = None,
        tech: TechAdapter | None = None,
        endpoint: EndpointAdapter | None = None,
        directory: DirectoryAdapter | None = None,
        dns: DnsAdapter | None = None,
        subdomain: SubdomainAdapter | None = None,
        stub: StubAdapter | None = None,
        nmap_enabled: bool = False,
        http_enabled: bool = False,
        dns_enabled: bool = False,
        catalog: ActionCatalog | None = None,
        events: EventSink | None = None,
        data_dir: str = "data",
    ) -> None:
        self._nmap = nmap
        self._http = http
        self._tech = tech
        self._endpoint = endpoint
        self._directory = directory
        self._dns = dns
        self._subdomain = subdomain
        self._stub = stub or StubAdapter()
        self._nmap_enabled = nmap_enabled
        self._http_enabled = http_enabled
        self._dns_enabled = dns_enabled
        self._catalog = catalog or DEFAULT_CATALOG
        self._events = events or NullEventSink()
        self._data_dir = data_dir

    def execute(
        self, authorized: AuthorizedAction, ctx: ExecutionContext | None = None
    ) -> ExecutionOutcome:
        if not isinstance(authorized, AuthorizedAction):
            raise ExecutionBypassError()
        if not authorized.decision.allowed:
            raise ExecutionBypassError("policy did not allow this action")
        action = authorized.action
        adapter = self._adapter_for(action.action_type)
        workdir = Path(self._data_dir) / "missions" / action.mission_id
        workdir.mkdir(parents=True, exist_ok=True)
        context = ctx or ExecutionContext(
            mission_id=action.mission_id,
            action_id=action.action_id,
            timeout_s=action.timeout_s,
            stub=adapter is self._stub,
            workdir=str(workdir),
        )
        if context.workdir is None:
            context = context.model_copy(update={"workdir": str(workdir)})
        started = utcnow()
        if not adapter.is_available():
            raise AdapterUnavailable(getattr(adapter, "name", "nmap_adapter"))
        artifact = adapter.run(action, context)
        ended = utcnow()
        argv = list(getattr(adapter, "_last_argv", None) or adapter.build_argv(action))
        status, error_code, unavailable, timed_out, exit_code = _status_for(adapter, artifact)
        if unavailable or status is ActionResultStatus.UNAVAILABLE:
            raise AdapterUnavailable(getattr(adapter, "name", "nmap_adapter"))
        tool_run = ToolRun(
            tool_run_id=artifact.tool_run_id,
            action_id=action.action_id,
            adapter_name=adapter.name,
            argv=argv,
            started_at=started,
            ended_at=ended,
            status=status.value,
            exit_code=exit_code,
            artifact_id=artifact.artifact_id,
            timed_out=timed_out,
            unavailable=unavailable,
        )
        result = ActionResult(
            result_id=new_id(PREFIX_RESULT),
            action_id=action.action_id,
            tool_run_id=artifact.tool_run_id,
            status=status,
            started_at=started,
            ended_at=ended,
            error_code=error_code,
            observation_count=_count_obs(artifact.body)
            if adapter is self._stub
            else (1 if artifact.byte_size else 0),
        )
        action_status = (
            ActionStatus.COMPLETED
            if status is ActionResultStatus.COMPLETED
            else ActionStatus.FAILED
        )
        observations: dict[str, Any] = {}
        if adapter is self._stub and status is ActionResultStatus.COMPLETED:
            observations = synthetic_payload(action)
        return ExecutionOutcome(
            action=action.model_copy(update={"status": action_status}),
            result=result,
            tool_run=tool_run,
            artifact=artifact,
            observations=observations,
        )

    def _adapter_for(self, action_type: str):
        spec = self._catalog.get(action_type)
        name = spec.adapter_name if spec is not None else ""
        if self._nmap_enabled and name == "nmap_adapter" and action_type in NMAP_ACTION_TYPES:
            if self._nmap is None:
                raise AdapterUnavailable("nmap_adapter")
            return self._nmap
        if self._http_enabled and name == "http_adapter" and action_type in HTTP_ACTION_TYPES:
            if self._http is None:
                raise AdapterUnavailable("http_adapter")
            return self._http
        if self._http_enabled and name == "tech_adapter":
            if self._tech is None:
                raise AdapterUnavailable("tech_adapter")
            return self._tech
        if self._http_enabled and name == "endpoint_adapter":
            if self._endpoint is None:
                raise AdapterUnavailable("endpoint_adapter")
            return self._endpoint
        if self._http_enabled and name == "directory_adapter":
            if self._directory is None:
                raise AdapterUnavailable("directory_adapter")
            return self._directory
        if self._dns_enabled and name == "dns_adapter":
            if self._dns is None:
                raise AdapterUnavailable("dns_adapter")
            return self._dns
        if self._dns_enabled and name == "subdomain_adapter":
            if self._subdomain is None:
                raise AdapterUnavailable("subdomain_adapter")
            return self._subdomain
        return self._stub


def _status_for(
    adapter: Any, artifact: RawArtifact
) -> tuple[ActionResultStatus, str | None, bool, bool, int | None]:
    meta = getattr(adapter, "_last_result", None)
    timed_out = bool(getattr(meta, "timed_out", False)) if meta is not None else False
    exit_code = int(getattr(meta, "exit_code", 0) or 0) if meta is not None else 0
    if timed_out:
        return ActionResultStatus.TIMEOUT, "timeout", False, True, -1
    if adapter.name in {
        "http_adapter",
        "tech_adapter",
        "endpoint_adapter",
        "directory_adapter",
        "dns_adapter",
        "subdomain_adapter",
    }:
        error = getattr(meta, "error", None) if meta is not None else None
        status_code = getattr(meta, "status", None) if meta is not None else None
        if error == "timeout":
            return ActionResultStatus.TIMEOUT, "timeout", False, True, -1
        if error in {"connect_failure", "dns_failure", "tls_failure", "out_of_scope"}:
            return ActionResultStatus.FAILED, error, False, False, 1
        if status_code is None and error:
            return ActionResultStatus.FAILED, str(error), False, False, 1
        return ActionResultStatus.COMPLETED, None, False, False, 0
    if adapter.name == "nmap_adapter":
        parseable = bool(artifact.body) and b"<nmaprun" in artifact.body
        if parseable:
            return ActionResultStatus.COMPLETED, None, False, False, exit_code
        if exit_code == 127:
            return ActionResultStatus.UNAVAILABLE, "adapter_unavailable", True, False, 127
        if artifact.byte_size == 0:
            return ActionResultStatus.FAILED, "empty_output", False, False, exit_code
        return ActionResultStatus.FAILED, "invalid_output", False, False, exit_code
    return ActionResultStatus.COMPLETED, None, False, False, 0
