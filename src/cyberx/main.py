"""Process entry: python -m cyberx  /  python main.py  /  cyberx."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys

from cyberx import __release__, __version__
from cyberx.app.bootstrap import bootstrap
from cyberx.config import AppConfig
from cyberx.domain.errors import ConfigurationError
from cyberx.tui.app import ConsoleApp
from cyberx.tui.io import StdIO


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberx",
        description=(
            f"{__release__}. Reconnaissance and intelligence only. "
            "No exploitation. Scope and policy stay fail-closed."
        ),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="print version and exit",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="check local configuration and tool availability (no scan)",
    )
    parser.add_argument(
        "--network",
        metavar="TARGET",
        help="observe local routing for TARGET (no scan, no VPN control)",
    )
    parser.add_argument(
        "--diagnose",
        metavar="TARGET",
        help="safe diagnostic for TARGET (no scan, no secrets)",
    )
    return parser


def configure_logging(level: str) -> None:
    name = (level or "WARNING").upper()
    numeric = getattr(logging, name, logging.WARNING)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def run_doctor(config: AppConfig) -> int:
    nmap = shutil.which(config.nmap.binary)
    print(__release__)
    print(f"version: {__version__}")
    print(f"python: {sys.version.split()[0]}")
    print(f"stub_mode: {config.runtime.stub_mode}")
    print(f"data_dir: {config.runtime.data_dir}")
    if nmap:
        print(f"nmap: {nmap}")
    else:
        print("nmap unavailable")
    ai = config.provider.name if config.provider.name != "none" else "none"
    if config.provider.enabled:
        print(f"ai_provider: {ai} (configured)")
    else:
        print(f"ai_provider: {ai} (inactive)")
    print("CyberX is not a VPN client. Connect OpenVPN/WireGuard outside this process.")
    print("Authorized CTF/lab targets only. Policy and Scope remain authoritative.")
    return 0


def run_network_check(target: str) -> int:
    from cyberx.network.resolver import NetworkResolver

    ctx = NetworkResolver().resolve(target)
    compact = ctx.compact()
    print("NETWORK (informational — not authorization)")
    print(f"Target: {compact.get('target') or target}")
    print(f"Target IP: {compact.get('target_ip') or '-'}")
    print(f"Reachability: {compact.get('reachability')}")
    print(f"Interface: {compact.get('interface') or '-'}")
    print(f"Source: {compact.get('source') or '-'}")
    print(f"Route: {compact.get('route') or '-'}")
    print(f"Tunnel: {compact.get('tunnel') or 'none'} (heuristic, unverified)")
    if compact.get("diagnostic"):
        print(f"Diagnostic: {compact['diagnostic']}")
    print("No routes, iptables, or VPN state were modified.")
    return 0


def run_diagnose(target: str, config: AppConfig) -> int:
    from cyberx.domain.enums import MissionMode
    from cyberx.domain.errors import TargetValidationError
    from cyberx.mission.target_parse import parse_target

    print("DIAGNOSE (no scan)")
    run_doctor(config)
    print("--- target ---")
    try:
        parsed = parse_target(target, mode=MissionMode.CTF)
        print(f"raw: {target}")
        print(f"kind: {parsed.kind.value}")
        print(f"normalized: {parsed.normalized}")
        print(f"host: {parsed.host or parsed.normalized}")
        print("current_locator: (mission not started — equals normalized after confirm)")
    except TargetValidationError as exc:
        print(f"target invalid: {exc}")
        return 2
    print("--- timeouts ---")
    print(f"nmap_timeout_s: {config.nmap.timeout_s}")
    print(f"http_timeout_s: {config.http.timeout_s}")
    print(f"dns_timeout_s: {config.dns.timeout_s}")
    print(f"ai_timeout_s: {config.provider.timeout_s}")
    print(f"max_action_attempts: {config.actions.max_attempts}")
    print("--- network ---")
    run_network_check(target)
    print("Scope is not expanded here. Confirm a mission to freeze scope.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.version:
        sys.stdout.write(f"{__version__}\n")
        return 0
    try:
        config = AppConfig.from_env()
    except ConfigurationError as exc:
        sys.stderr.write(f"configuration error: {exc.message}\n")
        return 2
    configure_logging(config.runtime.log_level)
    if args.doctor:
        return run_doctor(config)
    if args.diagnose:
        return run_diagnose(args.diagnose, config)
    if args.network:
        return run_network_check(args.network)
    try:
        application = bootstrap(config)
    except ConfigurationError as exc:
        sys.stderr.write(f"configuration error: {exc.message}\n")
        return 2
    try:
        return ConsoleApp(application.facade, io=StdIO()).run()
    except KeyboardInterrupt:
        sys.stdout.write("\nInterrupted.\n")
        return 0
    finally:
        application.close()


if __name__ == "__main__":
    raise SystemExit(main())
