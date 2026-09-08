from __future__ import annotations

from cyberx.config import AppConfig
from cyberx.domain.enums import V1_POLICY_PROFILE


def test_defaults_match_spec() -> None:
    cfg = AppConfig()
    assert cfg.mission.max_iterations == 50
    assert cfg.mission.max_runtime_s == 3600
    assert cfg.mission.min_action_score == 0.15
    assert cfg.mission.policy_profile == V1_POLICY_PROFILE
    assert cfg.runtime.stub_mode is True
    assert cfg.provider.name == "none"
    assert cfg.provider.api_key is None
    assert cfg.provider.enabled is False
    assert cfg.provider.timeout_s == 8
    assert cfg.provider.max_calls_per_mission == 20
    assert cfg.provider.max_calls_per_cycle == 2
    assert cfg.provider.max_prompt_bytes == 32768
    assert cfg.provider.max_output_tokens == 800
    assert cfg.actions.concurrency == 1
    assert cfg.nmap.binary == "nmap"
    assert cfg.nmap.timeout_s == 180
    assert cfg.nmap.profile == "safe"
    assert cfg.http.max_redirects == 3
    assert cfg.http.max_body_bytes == 524288
    assert cfg.http.tls_verify is True
    assert cfg.http.directory_max_candidates == 50
    assert cfg.dns.timeout_s == 30
    assert cfg.dns.subdomain_max_candidates == 100


def test_from_env_reads_stub_and_provider_without_hardcoded_secrets() -> None:
    cfg = AppConfig.from_env(
        {
            "CYBERX_STUB": "0",
            "CYBERX_AI_PROVIDER": "grok",
            "CYBERX_AI_API_KEY": "from-env-only",
            "CYBERX_AI_MODEL": "test-model",
            "CYBERX_AI_TIMEOUT": "6",
            "CYBERX_AI_MAX_CALLS": "12",
            "CYBERX_AI_MAX_CALLS_CYCLE": "1",
            "CYBERX_DATA_DIR": "/tmp/cx",
            "CYBERX_NMAP_BIN": "/usr/bin/nmap",
            "CYBERX_NMAP_TIMEOUT": "90",
            "CYBERX_LOG_LEVEL": "INFO",
            "CYBERX_MAX_ITERATIONS": "12",
            "CYBERX_MAX_RUNTIME": "600",
        }
    )
    assert cfg.runtime.stub_mode is False
    assert cfg.provider.name == "grok"
    assert cfg.provider.api_key == "from-env-only"
    assert cfg.provider.model == "test-model"
    assert cfg.provider.timeout_s == 6
    assert cfg.provider.max_calls_per_mission == 12
    assert cfg.provider.max_calls_per_cycle == 1
    assert cfg.provider.enabled is True
    assert cfg.runtime.data_dir == "/tmp/cx"
    assert cfg.nmap.binary == "/usr/bin/nmap"
    assert cfg.nmap.timeout_s == 90
    assert cfg.runtime.log_level == "INFO"
    assert cfg.mission.max_iterations == 12
    assert cfg.mission.max_runtime_s == 600


def test_from_env_accepts_xai_api_key_alias() -> None:
    cfg = AppConfig.from_env(
        {
            "CYBERX_AI_PROVIDER": "grok",
            "XAI_API_KEY": "alias-only",
        }
    )
    assert cfg.provider.api_key == "alias-only"
    assert cfg.provider.enabled is True


def test_from_env_does_not_invent_api_keys() -> None:
    cfg = AppConfig.from_env({"CYBERX_AI_PROVIDER": "none"})
    assert cfg.provider.api_key is None
    assert cfg.provider.enabled is False


def test_grok_without_key_is_disabled() -> None:
    cfg = AppConfig.from_env({"CYBERX_AI_PROVIDER": "grok"})
    assert cfg.provider.name == "grok"
    assert cfg.provider.api_key is None
    assert cfg.provider.enabled is False
