"""Single configuration boundary. Secrets come from the environment, never source."""

from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict, Field

from cyberx.domain.enums import FORBIDDEN_ACTION_MARKERS, V1_ACTION_TYPES, V1_POLICY_PROFILE
from cyberx.domain.errors import ConfigurationError


class MissionDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(default=50, ge=1, le=500)
    max_runtime_s: int = Field(default=3600, ge=1, le=14400)
    min_action_score: float = Field(default=0.15, ge=0.0, le=1.0)
    policy_profile: str = V1_POLICY_PROFILE
    ai_provider: str = "none"


class PolicyProfileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = V1_POLICY_PROFILE
    deny_markers: tuple[str, ...] = FORBIDDEN_ACTION_MARKERS
    v1_action_types: tuple[str, ...] = V1_ACTION_TYPES


class ActionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    concurrency: int = Field(default=1, ge=1, le=1)
    max_artifact_bytes: int = Field(default=5_000_000, ge=1)
    max_attempts: int = Field(default=2, ge=1, le=5)


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stub_mode: bool = True
    data_dir: str = "data"
    log_level: str = "WARNING"


class ProviderConfig(BaseModel):
    """AI provider selection. API keys are read from env, never hardcoded."""

    model_config = ConfigDict(extra="forbid")

    name: str = "none"
    api_key: str | None = None
    model: str = "grok-4.5"
    timeout_s: int = Field(default=8, ge=1, le=30)
    max_calls_per_mission: int = Field(default=20, ge=0, le=100)
    max_calls_per_cycle: int = Field(default=2, ge=0, le=4)
    max_prompt_bytes: int = Field(default=32768, ge=256, le=32768)
    max_response_bytes: int = Field(default=8192, ge=256, le=32768)
    max_output_tokens: int = Field(default=800, ge=64, le=4096)
    reasoning: str = "low"
    enabled: bool = False
    base_url: str = "https://api.x.ai/v1"


class NmapSettings(BaseModel):
    """v1 Nmap adapter settings. Profile is always 'safe' (no NSE, no -A, no -O)."""

    model_config = ConfigDict(extra="forbid")

    binary: str = "nmap"
    timeout_s: int = Field(default=180, ge=1, le=300)
    profile: str = "safe"
    max_retries: int = Field(default=1, ge=0, le=2)


class HttpSettings(BaseModel):
    """v1 HTTP adapter settings. GET only. No arbitrary headers or proxies."""

    model_config = ConfigDict(extra="forbid")

    timeout_s: int = Field(default=30, ge=1, le=60)
    connect_timeout_s: int = Field(default=10, ge=1, le=30)
    read_timeout_s: int = Field(default=20, ge=1, le=60)
    max_redirects: int = Field(default=3, ge=0, le=3)
    max_body_bytes: int = Field(default=524288, ge=1, le=5_000_000)
    tls_verify: bool = True
    user_agent: str = "CyberX/1.0"
    directory_max_candidates: int = Field(default=50, ge=1, le=50)


class DnsSettings(BaseModel):
    """v1 DNS adapter settings. Closed record types. Wordlist is fixed."""

    model_config = ConfigDict(extra="forbid")

    timeout_s: int = Field(default=30, ge=1, le=60)
    subdomain_max_candidates: int = Field(default=100, ge=1, le=100)
    nameserver: str | None = None


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mission: MissionDefaults = Field(default_factory=MissionDefaults)
    policy: PolicyProfileConfig = Field(default_factory=PolicyProfileConfig)
    actions: ActionLimits = Field(default_factory=ActionLimits)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    nmap: NmapSettings = Field(default_factory=NmapSettings)
    http: HttpSettings = Field(default_factory=HttpSettings)
    dns: DnsSettings = Field(default_factory=DnsSettings)

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> AppConfig:
        env = environ if environ is not None else os.environ
        stub_raw = env.get("CYBERX_STUB", "1").strip().lower()
        stub_mode = stub_raw not in {"0", "false", "no"}
        provider = env.get("CYBERX_AI_PROVIDER", "none").strip() or "none"
        api_key = env.get("CYBERX_AI_API_KEY") or env.get("XAI_API_KEY") or None
        model = env.get("CYBERX_AI_MODEL", "").strip() or "grok-4.5"
        timeout_ai_raw = env.get("CYBERX_AI_TIMEOUT", "").strip()
        max_calls_raw = env.get("CYBERX_AI_MAX_CALLS", "").strip()
        cycle_calls_raw = env.get("CYBERX_AI_MAX_CALLS_CYCLE", "").strip()
        timeout_raw = env.get("CYBERX_NMAP_TIMEOUT", "").strip()
        http_timeout_raw = env.get("CYBERX_HTTP_TIMEOUT", "").strip()
        dns_timeout_raw = env.get("CYBERX_DNS_TIMEOUT", "").strip()
        tls_raw = env.get("CYBERX_HTTP_TLS_VERIFY", "1").strip().lower()
        try:
            nmap_timeout = int(timeout_raw) if timeout_raw else 180
            http_timeout = int(http_timeout_raw) if http_timeout_raw else 30
            dns_timeout = int(dns_timeout_raw) if dns_timeout_raw else 30
            ai_timeout = int(timeout_ai_raw) if timeout_ai_raw else 8
            max_calls = int(max_calls_raw) if max_calls_raw else 20
            cycle_calls = int(cycle_calls_raw) if cycle_calls_raw else 2
            enabled = provider not in {"", "none"} and bool(api_key)
            max_iter_raw = env.get("CYBERX_MAX_ITERATIONS", "").strip()
            max_runtime_raw = env.get("CYBERX_MAX_RUNTIME", "").strip()
            max_iterations = int(max_iter_raw) if max_iter_raw else 50
            max_runtime_s = int(max_runtime_raw) if max_runtime_raw else 3600
            log_level = (env.get("CYBERX_LOG_LEVEL") or "WARNING").strip().upper() or "WARNING"
            return cls(
                runtime=RuntimeSettings(
                    stub_mode=stub_mode,
                    data_dir=env.get("CYBERX_DATA_DIR", "data"),
                    log_level=log_level,
                ),
                provider=ProviderConfig(
                    name=provider,
                    api_key=api_key,
                    model=model,
                    timeout_s=ai_timeout,
                    max_calls_per_mission=max_calls,
                    max_calls_per_cycle=cycle_calls,
                    enabled=enabled,
                ),
                mission=MissionDefaults(
                    ai_provider=provider if provider else "none",
                    max_iterations=max_iterations,
                    max_runtime_s=max_runtime_s,
                ),
                nmap=NmapSettings(
                    binary=env.get("CYBERX_NMAP_BIN", "nmap") or "nmap",
                    timeout_s=nmap_timeout,
                ),
                http=HttpSettings(
                    timeout_s=http_timeout,
                    tls_verify=tls_raw not in {"0", "false", "no"},
                ),
                dns=DnsSettings(
                    timeout_s=dns_timeout,
                    nameserver=env.get("CYBERX_DNS_NS") or None,
                ),
            )
        except Exception as exc:
            raise ConfigurationError(str(exc), code="invalid_config") from exc


def default_config() -> AppConfig:
    return AppConfig()
