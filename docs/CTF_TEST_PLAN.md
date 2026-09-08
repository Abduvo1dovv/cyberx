# CyberX v1 CTF Test Plan

Repeatable **authorized-lab** reconnaissance benchmark.
No exploitation. No arbitrary Internet targets in CI.

**Release:** CyberX v1 CTF Edition — Recon/Intelligence Release (`1.0.0-ctf`)

## Automated CI (required)

Must pass without VPN, Internet, nmap, or a Grok key:

```bash
pytest
ruff check src tests
```

Covered by the suite:

- architecture / import boundaries
- parser fixtures (nmap xml, http, dns, directory, endpoint)
- stub end-to-end
- storage / replay
- network mock fixtures (tun0 source change, gone, reappear)
- locator identity vs IP
- AI fallback (no live key)
- tool unavailable → structured result, operator text `nmap unavailable`
- report.json / report.md
- `--version` / `--doctor`

## Manual authorized-lab sequence

Use **your** authorized target. Do not hardcode a lab IP in this repo.

1. Connect the Linux VM to the authorized lab VPN **manually**
   (HTB: OpenVPN outside CyberX — see `CTF_RUNBOOK.md`).
2. Verify the tunnel (`ip addr show tun0` or equivalent).
3. Select an authorized target locator (IP or hostname).
4. Start CyberX: `CYBERX_STUB=0 python main.py`
5. Create a mission (mode `ctf`, AI `none` first).
6. Confirm scope. Verify it is frozen.
7. Run reconnaissance (`s` or several `c` cycles).
8. Monitor network context (`n`): interface, source, route, reachability.
9. Monitor Brain decisions (rationale / current action).
10. Verify Nmap (or confirm `nmap unavailable` and that the mission continues).
11. Verify HTTP probe if a web port is in-scope.
12. Verify DNS if the target is a hostname.
13. Verify subdomain enumeration stays in-scope.
14. Verify bounded directory discovery (no wildcard flood).
15. Inspect World Model (`w`).
16. Inspect graph (`g`).
17. Inspect findings (`f`) — recon signals only.
18. Inspect investigation paths (`i`).
19. Pause (`p`).
20. Quit, restart, resume. Coverage keys must not blindly repeat.
21. Export report (`o`). Open `report.json` and `report.md`.

Optional second pass: enable Grok with a key. Confirm advice is advisory and
the catalog still gates every action.

## Manual smoke checklist

Record pass/fail. Never paste VPN configs or API keys into the notes.

| Check | Pass? |
|---|---|
| Route exists for the authorized target | |
| Target reachable (or TIMEOUT recorded as transient, not a World fact) | |
| Nmap result **or** `nmap unavailable` | |
| HTTP result (if web in-scope) | |
| DNS result (if hostname) | |
| Directory result (if web in-scope) | |
| Evidence ids present | |
| World Model grew | |
| Brain adapted (cycle 2 ≠ cycle 1 when new evidence exists) | |
| Report created with FACT / HYPOTHESIS / UNKNOWN | |
| Report has no exploit instructions | |
| AI disabled still usable | |

## Non-goals for this plan

- exploitation, shells, privesc, credential attacks
- scanning hosts you do not own or are not authorized to test
- treating CyberX as production-ready or fully autonomous
