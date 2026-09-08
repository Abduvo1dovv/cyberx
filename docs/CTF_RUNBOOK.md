# CyberX v1 CTF Runbook

Operator guide for authorized CTF / HTB / THM / lab use.
**CyberX v1 CTF Edition — Recon/Intelligence Release** (`1.0.0-ctf`).

CyberX is reconnaissance and intelligence only. It is not a VPN client and
not an exploit framework.

## 1. Prerequisites

- Linux VM (Kali, Parrot, or similar) with Python 3.10+
- Authorized target (your HTB/THM/CTF machine, not the public Internet)
- Optional: `nmap` for real port scans
- Optional: xAI API key for Grok advice
- Optional: OpenVPN/WireGuard **already connected** if the target is on a lab VPN

## 2. Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Do not paste VPN credentials, `.ovpn` files, or API keys into the repo.

## 3. Tool verification

```bash
python main.py --version          # 1.0.0-ctf
python main.py --doctor           # stub/nmap/AI status, no scan
which nmap || true
```

`--doctor` never prints API keys. Missing nmap prints `nmap unavailable`.

## 4. Optional HTB / THM VPN (outside CyberX)

CyberX does **not** start, stop, or configure a VPN.

Hack The Box Machines and private lab IPs live on a private subnet. HTB's
current guidance uses OpenVPN for those targets and expects the tunnel to be
established **before** you work with them.

Official HTB instructions:

- [Introduction to Lab Access](https://help.hackthebox.com/en/articles/5185687-introduction-to-lab-access)
- [Understanding the Hack The Box VPN](https://help.hackthebox.com/en/articles/8602725-understanding-the-hack-the-box-vpn)

Typical Linux flow (operator machine, not CyberX):

```bash
sudo openvpn /path/to/your.ovpn
# wait for: Initialization Sequence Completed
ip addr show tun0
```

Never store the `.ovpn` inside the CyberX data directory.

## 5. Verify tun0 (or similar)

```bash
ip addr show tun0 || ip addr show tun1 || ip addr show wg0
python main.py --network <AUTHORIZED_TARGET>
```

`--network` reports interface, source address, route, reachability, and a
tunnel heuristic labeled **unverified**. It does not scan, and it does not
change routing.

`tun0` is **not** assumed to be HTB. Tunnel-like interfaces are
`DETECTED_UNVERIFIED`.

## 6. Launch CyberX

```bash
# stub (no nmap required)
CYBERX_STUB=1 python main.py

# real tools after nmap is installed and VPN is up
CYBERX_STUB=0 python main.py
```

Equivalent: `python -m cyberx` or `cyberx`.

## 7. Create a mission

1. Target: the authorized locator (IP or hostname)
2. Name / intent
3. Mode: `1` CTF (default), `2` lab, `3` authorized assessment
4. AI: `1` none (fully usable) or `2` grok
5. Review the scope
6. Confirm — **scope freezes**

CTF mode favors faster recon and compact context. It does **not** weaken
Scope, Policy, fail-closed behavior, or the action catalog.

## 8. How scope works

- Scope is proposed at create time from the target
- After confirm it is immutable
- AI cannot modify it
- DNS, redirects, and discovered routes cannot expand it
- A newly observed address is only **current** after operator confirmation
  and only if it is already in scope

IP is a locator, not a permanent identity, unless the operator supplied only
an IP.

## 9. AI / none

`ai_provider=none` is a first-class mode. The deterministic Brain still
plans. Grok is advisory: timeouts, bad JSON, missing keys, and budget
exhaustion fall back to Brain. AI cannot execute, retarget, or write facts.

## 10. Dashboard

| Question | Where |
|---|---|
| What target am I working on? | header + `t` |
| Is it reachable? Through which interface? | `n` |
| What has been discovered? | `w` |
| What is CyberX doing now / why? | current action + rationale |
| Top investigations / findings / gaps? | `i` / `f` / `w` |
| Is AI active? Remaining calls? | AI line |
| Recent events? | `l` |

Do not paste giant raw tool output into notes; use World Model + evidence ids.

## 11. Pause / resume

- `p` pause (cycle boundary)
- `q` while running pauses then quits
- Restart the process and choose **resume**
- `r` resume

Resume must not replay completed coverage keys and must not silently switch
to an obsolete locator.

## 12. Findings

`f` — recon signals, not vulnerability names with exploit steps.
FACT vs HYPOTHESIS are separate lists.

## 13. World Model

`w` — current belief. Facts enter only via Evidence. TIMEOUT is not a World
Model reachability fact.

## 14. Investigation paths

`i` / `g` — catalog-only next observations (e.g. probe HTTP on an open port).
Not exploit chains.

## 15. Network state

`n` — informational. Policy and Scope remain authoritative.

## 16. Export reports

`o` writes:

```
$CYBERX_DATA_DIR/missions/<id>/report.json
$CYBERX_DATA_DIR/missions/<id>/report.md
```

## 17. Recover after interruption

1. Confirm `data/cyberx.db` opens (`python main.py --doctor`)
2. Start CyberX, pick the resumable mission
3. Check current locator (`t`) and network (`n`)
4. Resume

If SQLite reports `database_corrupt`, do not keep writing to that file. Use a
fresh `CYBERX_DATA_DIR`.

## 18. Common failures

| Failure | Fix |
|---|---|
| `nmap unavailable` | install nmap or stay in stub mode |
| HTTP/DNS still work when nmap is missing | expected |
| Route missing / TIMEOUT | VPN/routing outside CyberX; not a host-down fact |
| Grok timeout / no key | Brain continues |
| Locator rejected | out of scope or non-operator actor |
| Scope frozen | create a new mission; do not expect mutation |

## 19. Test suite

```bash
pytest
ruff check src tests
```

Do not point the automated suite at arbitrary Internet hosts.
