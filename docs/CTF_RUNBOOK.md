# CyberX v1 CTF Runbook

Operator guide for authorized CTF / HTB / THM / lab use.
**CyberX v1.0.0-ctf — CTF Enumeration / Reconnaissance Release.**

CyberX is reconnaissance and intelligence only. It is not a VPN client and
not an exploit framework. It is not fully autonomous and not production-ready.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for failure diagnostics.

## 1. Prerequisites

- Linux VM (Kali, Parrot, or similar)
- Python **3.10+**
- Authorized target (your HTB/THM/CTF machine, not the public Internet)
- Optional: `nmap` for real port scans
- Optional: xAI API key for Grok advice
- Optional: OpenVPN/WireGuard **already connected** if the target is on a lab VPN

## 2. Installation (clean virtual environment)

From a clone of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
cp .env.example .env
python main.py --version          # 1.0.0-ctf
python main.py --doctor
```

Do not paste VPN credentials, `.ovpn` files, or API keys into the repo.
`.env` may contain `CYBERX_AI_API_KEY`; `--doctor` never prints it.

Equivalent entrypoints: `python -m cyberx` or `cyberx`.

## 3. Nmap requirement

Real `port_scan` / `service_enumeration` need `nmap` on PATH.

```bash
which nmap
python main.py --doctor           # prints nmap: <path> or nmap unavailable
```

Missing nmap: stay in stub mode (`CYBERX_STUB=1`) or install nmap. HTTP, DNS,
and directory enumeration do not require nmap.

IPv4 CTF scans use `-4 -Pn` and a validated `-e <interface>` when the target
is REACHABLE via that interface. CyberX does **not** automatically add
`-S <source>` (that plus dual-stack `tun0` binds `fe80::` and fails with
NSOCK). See TROUBLESHOOTING §5.

## 4. Operator workflow (authorized lab)

**STEP 1.** Connect the authorized CTF/HTB VPN **outside CyberX**.

```bash
sudo openvpn /path/to/your.ovpn
# wait for: Initialization Sequence Completed
```

CyberX never starts, stops, or configures a VPN.

**STEP 2.** Verify the tunnel and routes on the operator machine.

```bash
ip addr show tun0
ip route
```

`tun0` is an example. `tun1` / `wg0` are equally valid if that is the route.

**STEP 3.** Verify CyberX itself (no scan).

```bash
python main.py --doctor
```

Reports version, Python, platform, stub mode, database, artifact store, nmap,
AI provider (no secrets), and timeouts.

**STEP 4.** Verify the target network (no scan).

```bash
python main.py --network <AUTHORIZED_TARGET>
python main.py --diagnose <AUTHORIZED_TARGET>
```

`--network` reports target, address family, interface, source, route,
reachability, tunnel heuristic (unverified), and digest. It does not claim a
VPN provider.

**STEP 5.** Run the console.

```bash
# stub (no nmap required)
CYBERX_STUB=1 python main.py

# real tools after nmap is installed and VPN is up
CYBERX_STUB=0 python main.py
```

**STEP 6.** Create a mission: Target, name/intent, Mode = **CTF**,
AI = **none** (or Grok optional).

**STEP 7.** Review scope (targets, networks, ports, protocols, exclusions).

**STEP 8.** Confirm. **Scope freezes.** AI cannot mutate it.

**STEP 9.** Start (`s`).

**STEP 10.** Observe the real enumeration flow when tools are enabled:

```text
Nmap (port_scan) → World Model ports
  → HTTP / service_enumeration (if 80/443 or a named service)
  → DNS / subdomain (if a domain is in scope)
  → bounded directory enumeration (max 50, depth 1)
  → Brain re-plans from evidence
```

The sequence is scored, not hardcoded. A failed nmap does **not** mean the
host is fully enumerated: `host.ports_unknown` remains.

**STEP 11.** Keys (match the implemented TUI):

| Key | Action |
|---|---|
| `s` | start |
| `p` | pause |
| `r` | resume |
| `x` | stop |
| `c` | one cycle |
| `f` | findings |
| `i` | investigations |
| `g` | graph |
| `n` | network |
| `t` | target |
| `w` | world |
| `h` | hypotheses |
| `l` | logs |
| `o` | report |
| `q` | quit |

## 5. How scope works

- Scope is proposed at create time from the target
- After confirm it is immutable
- AI cannot modify it
- DNS, redirects, and discovered routes cannot expand it
- A newly observed address is only **current** after operator confirmation
  and only if it is already in scope

IP is a locator, not a permanent identity, unless the operator supplied only
an IP.

## 6. AI / none

`ai_provider=none` is a first-class mode. The deterministic Brain still
plans. Grok is advisory: timeouts, bad JSON, missing keys, and budget
exhaustion fall back to Brain. AI cannot execute, retarget, or write facts.

## 7. Dashboard

| Question | Where |
|---|---|
| What target am I working on? | header + `t` |
| Family / interface / source / route? | `n` and FAILED action block |
| What has been discovered? | `w` |
| What is CyberX doing now / why? | current action + rationale |
| Failure reason / attempt / retryable? | FAILED block |
| Top investigations / findings / gaps? | `i` / `f` / `w` |
| Is AI active? Remaining calls? | AI line |
| Recent events? | `l` |

Do not paste giant raw tool output into notes; use World Model + evidence ids.
Full nmap stderr lives in the artifact, not the TUI.

## 8. Pause / resume

- `p` pause (cycle boundary)
- `q` while running pauses then quits
- Restart the process and choose **resume**
- `r` resume

Resume must not replay completed coverage keys and must not silently switch
to an obsolete locator.

## 9. Findings / World Model / paths

- `f` — recon signals, not vulnerability names with exploit steps
- `w` — current belief. Facts enter only via Evidence. TIMEOUT is not a
  World Model reachability fact
- `i` / `g` — catalog-only next observations. Not exploit chains

## 10. Network state

`n` — informational. Policy and Scope remain authoritative.
VPN source IPs are discovered from NetworkContext (they change). Never
hardcoded.

If nmap retries without `-e`, that is **OS routing** with `-4` still set. It
is not a silent move to `eth0`.

## 11. Target locator change

After a machine reset the IP may change. Confirm the new in-scope locator.
Brain, DNS, and NetworkContext cannot silently retarget.

## 12. Export reports

`o` writes:

```
$CYBERX_DATA_DIR/missions/<id>/report.json
$CYBERX_DATA_DIR/missions/<id>/report.md
```

## 13. Recover after interruption

1. Confirm `data/cyberx.db` opens (`python main.py --doctor`)
2. Start CyberX, pick the resumable mission
3. Check current locator (`t`) and network (`n`)
4. Resume

If SQLite reports `database_corrupt`, do not keep writing to that file. Use a
fresh `CYBERX_DATA_DIR`.

## 14. Common failures

| Failure | Fix |
|---|---|
| `nmap unavailable` | install nmap or stay in stub mode |
| NSOCK / `fe80` / `mksock_bind_addr` | IPv4 now uses `-4` without automatic `-S`; see TROUBLESHOOTING §5 |
| `port_scan FAILED` then still `host.ports_unknown` | expected: failed ≠ completed coverage |
| HTTP/DNS still work when nmap is missing | expected |
| Route missing / TIMEOUT | VPN/routing outside CyberX; not a host-down fact |
| Grok timeout / no key | Brain continues |
| Locator rejected | out of scope or non-operator actor |
| Scope frozen | create a new mission; do not expect mutation |

Full list: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 15. Tests

CI must not require Internet, HTB, VPN, nmap, or a Grok key:

```bash
pytest
ruff check src tests
```

Optional live nmap (authorized localhost / configured target only):

```bash
CYBERX_LIVE_NMAP=1 pytest -m requires_nmap
```

Do not point the automated suite at arbitrary Internet hosts.

## 16. Optional real-tool smoke (manual, authorized lab only)

```bash
python main.py --diagnose <AUTHORIZED_TARGET>
# IPv4-safe contrast on the operator machine:
nmap -4 -Pn -e tun0 --top-ports 100 <AUTHORIZED_TARGET>
# OS routing (no -e) also works when the route is correct:
nmap -Pn -sV --top-ports 100 <AUTHORIZED_TARGET>
curl -I --max-time 10 http://<AUTHORIZED_TARGET>/
CYBERX_STUB=0 python main.py
```

If CyberX `port_scan` fails, the dashboard shows FAILED / reason / attempt /
family / interface. That is not mission success. Ports remain UNKNOWN.
