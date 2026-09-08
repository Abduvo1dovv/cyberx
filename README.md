# CyberX v1 CTF Edition — Recon/Intelligence Release

CyberX is a **mission-driven reconnaissance and intelligence** console for
authorized CTFs, Hack The Box / TryHackMe-style labs, and authorized
assessments.

It is **not** an exploit framework, **not** a scanner wrapper, and **not** an
LLM with a shell.

**Label:** CyberX v1 CTF Edition — Recon/Intelligence Release
**Version:** `1.0.0-ctf`
**Runtime:** Python 3.10+
**Contract:** [`docs/SPEC.md`](docs/SPEC.md)

v1 = reconnaissance + adaptive intelligence + safe validation questions.

It is **not** production-ready and **not** fully autonomous.

## What it does

- Creates a Mission with a frozen Scope
- Distinguishes **target identity** from a **locator** (IP/hostname can change)
- Observes local routing (`tun0` / `wg0`-like) without becoming a VPN client
- Plans the next cheapest in-scope recon action (Brain never executes)
- Runs a closed catalog: port scan, service enum, HTTP, tech, DNS, subdomain,
  bounded directory enum, endpoint discovery
- Turns tool output into Evidence → World Model facts
- Projects an attack-surface graph and investigation paths
- Optionally asks Grok for structured advice (AI never executes)
- Writes `report.json` + `report.md` with FACT / HYPOTHESIS / UNKNOWN labels

## What it will not do

- exploitation, payloads, shells, sessions, persistence
- privilege escalation, credential attacks, password spraying, brute force
- authentication bypass, arbitrary command execution
- arbitrary AI-generated commands or scope expansion
- start/stop VPNs, modify routes, or touch iptables

Policy and Scope are fail-closed. Out-of-scope observations never become
follow-up actions.

## Requirements

- Python 3.10 or newer
- `pydantic` v2
- Optional for real tool mode: `nmap` on `PATH`
- Optional AI: an xAI API key (`CYBERX_AI_API_KEY` or `XAI_API_KEY`)
- Linux is the intended operator environment (Kali/Parrot/lab VM)

CI and first-run use **stub mode** (`CYBERX_STUB=1`). Stub mode does not need
nmap, a VPN, Internet, or an API key.

## Install (Kali / Linux)

```bash
git clone <this-repo>
cd <repo>
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # edit locally; never commit
```

Runnable entrypoints (all equivalent):

```bash
python main.py
python -m cyberx
cyberx
```

## Configure

See [`.env.example`](.env.example). Important variables:

| Variable | Default | Meaning |
|---|---|---|
| `CYBERX_STUB` | `1` | `1` stub adapters; `0` real nmap/http/dns |
| `CYBERX_DATA_DIR` | `data` | SQLite + artifacts + reports |
| `CYBERX_LOG_LEVEL` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `CYBERX_MAX_ITERATIONS` | `50` | mission brake |
| `CYBERX_MAX_RUNTIME` | `3600` | mission brake (seconds) |
| `CYBERX_AI_PROVIDER` | `none` | `none` or `grok` |
| `CYBERX_AI_API_KEY` | unset | never printed; never committed |
| `CYBERX_NMAP_BIN` | `nmap` | nmap executable |

Secrets never live in source. Doctor mode will say `configured` / `no API key`
and will not print the key.

## First run

```bash
python main.py --version
python main.py --doctor
python main.py
```

Operator flow:

1. Target (authorized CTF/lab host only)
2. Mission name + intent
3. Mode: `ctf` / `lab` / `authorized_assessment`
4. AI provider: `none` (fully usable) or `grok`
5. Review scope → confirm (scope freezes)
6. Dashboard: start / pause / resume / one cycle / inspect / export

Dashboard keys: `s` start, `p` pause, `r` resume, `x` stop, `c` one cycle,
`f` findings, `i` investigations, `g` graph, `n` network, `t` target/locator,
`w` world, `h` hypotheses, `l` logs, `o` report, `q` quit.

## Real tools vs stub

```bash
# CI / no tools
CYBERX_STUB=1 python main.py

# Authorized lab with nmap installed
CYBERX_STUB=0 python main.py --doctor
CYBERX_STUB=0 python main.py
```

If nmap is missing in real mode the operator sees **`nmap unavailable`**.
HTTP/DNS adapters still run. The mission does not fail solely because nmap is
absent.

## Network / VPN

CyberX is **not a VPN client**. Connect OpenVPN or WireGuard **outside**
CyberX, then let CyberX observe `tun0` / `tun1` / `wg0`-like interfaces.

HTB Machines/private lab IPs expect the tunnel to be up first. Official
guidance: [HTB lab access](https://help.hackthebox.com/en/articles/5185687-introduction-to-lab-access)
and [Understanding the HTB VPN](https://help.hackthebox.com/en/articles/8602725-understanding-the-hack-the-box-vpn).

```bash
python main.py --network 10.10.11.23
```

That command does **not** scan. It only reports interface, source, route, and
reachability. Tunnel labels are `DETECTED_UNVERIFIED` heuristics.

A new in-scope locator becomes **current** only after the operator confirms it
(`t` on the dashboard). AI cannot retarget. DNS cannot expand scope.

## Reports

From the dashboard press `o`, or call `export_report` via the facade.
Files:

```
$CYBERX_DATA_DIR/missions/<mission_id>/report.json
$CYBERX_DATA_DIR/missions/<mission_id>/report.md
```

Labels: **FACT**, **HYPOTHESIS / NOT CONFIRMED**, **UNKNOWN**, **INVALIDATED**.
Reports never include exploit instructions.

## Tests

```bash
pytest
ruff check src tests
```

Live optional markers (off by default): `requires_nmap`, `requires_http`,
`requires_dns`, `requires_network`, `requires_grok`.

## Docs

- [`docs/SPEC.md`](docs/SPEC.md) — binding contract
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — historical proposal
- [`docs/CTF_RUNBOOK.md`](docs/CTF_RUNBOOK.md) — operator runbook
- [`docs/CTF_TEST_PLAN.md`](docs/CTF_TEST_PLAN.md) — authorized-lab test plan

## Troubleshooting

| Symptom | What to do |
|---|---|
| `nmap unavailable` | install nmap, or keep `CYBERX_STUB=1` |
| target unreachable | check VPN **outside** CyberX; `--network TARGET` |
| AI does nothing | expected without a key; deterministic Brain still plans |
| process killed mid-run | restart, resume the mission from the TUI |
| `database_corrupt` | do not reuse a damaged `data/cyberx.db`; start a new data dir |
| locator looks wrong | identity survives IP change; confirm the new locator with `t` |

## License / authorization

Use only on systems you are authorized to test. CyberX will not help you
expand past confirmed scope.
