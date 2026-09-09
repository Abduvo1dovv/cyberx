# CyberX v1 Troubleshooting

Authorized CTF/lab reconnaissance only. CyberX does **not** change routes,
iptables, VPN state, or credentials. Connect the lab VPN **outside** CyberX.

Do not paste API keys, `.ovpn` files, or session cookies into tickets.

---

## 1. tun0 missing

**Symptom:** `--network` shows no tunnel interface; reachability `ROUTE_MISSING`
or default `eth0`.

**Likely cause:** OpenVPN/WireGuard is not connected, or the tunnel has a
different name (`tun1`, `wg0`).

**Diagnostic:**

```bash
ip addr show
ip route
python main.py --network <AUTHORIZED_TARGET>
python main.py --doctor
```

**CyberX response:** NetworkContext is informational. It never starts a VPN.

**Operator action:** Connect the authorized VPN outside CyberX, then re-run
`--network`. Do not invent interface names.

---

## 2. No route to target

**Symptom:** Reachability `ROUTE_MISSING`. Dashboard shows no matching route.

**Likely cause:** VPN connected to the wrong lab, or the machine reset onto a
different subnet.

**Diagnostic:** `ip route get <AUTHORIZED_TARGET>` and `python main.py --network <AUTHORIZED_TARGET>`.

**CyberX response:** Planner may skip nmap rather than scan an unroutable host.
TIMEOUT is not recorded as a World Model fact.

**Operator action:** Confirm the current locator (`t`) and that the VPN is for
this lab. Do not add routes unless your lab documentation requires it, and
never from inside CyberX.

---

## 3. Target unreachable

**Symptom:** Reachability `UNREACHABLE` or `BLOCKED`. Interface may be down.

**Likely cause:** Host down, interface `operstate=down`, or ICMP blocked.

**Diagnostic:** `--network`, `ip link show <iface>`.

**CyberX response:** Marks the locator unreachable for diagnostics. Does not
invent port facts.

**Operator action:** Check the machine is spawned. Confirm the locator. Resume
when routing returns.

---

## 4. Nmap missing

**Symptom:** `nmap unavailable` on `--doctor` or action `UNAVAILABLE`.

**Likely cause:** `nmap` is not on PATH.

**Diagnostic:** `which nmap`; `python main.py --doctor`.

**CyberX response:** `port_scan` is unavailable. HTTP/DNS/directory still run
if those adapters are enabled. Stub mode works without nmap.

**Operator action:** Install nmap, or stay in `CYBERX_STUB=1`.

---

## 5. Nmap interface failure (NSOCK / fe80)

**Symptom:**

```
port_scan FAILED
reason=process_error
NSOCK ERROR
mksock_bind_addr()
Bind to fe80::... failed
Invalid argument
```

**Likely cause:** Dual-stack tunnel (`tun0` has IPv4 **and** IPv6 link-local).
Nmap `-e tun0` without `-4` binds `fe80::`.

**Diagnostic:** `python main.py --diagnose <AUTHORIZED_TARGET>` and the
dashboard FAILED block (family/interface/source). Full stderr is in the
artifact `stderr.txt`, not the TUI.

**CyberX response:** IPv4 scans use `-4 -Pn -e <iface>` and **do not** add
`-S`. If NSOCK still fires, one intra-run retry drops `-e` and keeps `-4`
(OS routing — not a silent switch to `eth0`). Failed scans are
`process_error`, not `empty_output`, and do **not** complete coverage.

**Operator action:** Confirm family is IPv4 and the interface is the tunnel.
Do not run nmap yourself with `-e tun0` and no `-4`. Resume after the retry
policy (`attempt 1/2`).

---

## 6. IPv4 / IPv6 mismatch

**Symptom:** IPv6 target with IPv4 flags, or IPv4 target attempting `fe80`.

**Likely cause:** Dual-stack interface plus missing family flag (fixed in
v1.0.0-ctf). IPv6 is conservative in v1.

**Diagnostic:** `--network` Family line; dashboard `family=`.

**CyberX response:** IPv4 → `-4`. IPv6 → `-6`. Hostnames default to `-4`.
Link-local is never used as `-S`.

**Operator action:** Prefer the IPv4 locator for CTF boxes. v1 does not fully
support IPv6 enumeration.

---

## 7. HTTP timeout

**Symptom:** `http_probe` TIMEOUT / `connect_failure`.

**Likely cause:** Port closed, host filtered, or HTTP not yet discovered.

**Diagnostic:** World Model ports (`w`); `--diagnose` HTTP timeout.

**CyberX response:** Timeout is not a technology fact. Retryable once.

**Operator action:** Confirm 80/tcp (or 443) is actually open before expecting
HTTP follow-up.

---

## 8. DNS failure

**Symptom:** `dns_lookup` / subdomain `dns_failure` or NXDOMAIN.

**Likely cause:** No DNS name, lab DNS not reachable, or out-of-scope name.

**Diagnostic:** `--diagnose`; World Model hosts.

**CyberX response:** DNS cannot expand Scope. Observed names stay historical
until the operator confirms an in-scope locator.

**Operator action:** Confirm the domain is in scope. Do not point CyberX at
public Internet resolvers for out-of-scope names.

---

## 9. Directory enumeration wildcard

**Symptom:** Many 200s on random paths; wildcard finding.

**Likely cause:** The server answers 200 for unknown paths.

**Diagnostic:** `f` findings; directory artifact.

**CyberX response:** Bounded wordlist (max 50, depth 1, no recursion). Wildcard
responses are recorded, not treated as real endpoints.

**Operator action:** Inspect findings. Do not add custom wordlists.

---

## 10. Database corruption

**Symptom:** `database_corrupt` on start; `--doctor` `database: ... (corrupt)`.

**Likely cause:** Incomplete write, disk full, or copied a truncated db.

**Diagnostic:** `python main.py --doctor`.

**CyberX response:** Fail closed. Do not keep writing to a malformed SQLite
file.

**Operator action:** Use a fresh `CYBERX_DATA_DIR`. Do not repair by hand
unless you know SQLite recovery.

---

## 11. Stale target locator

**Symptom:** Mission identity unchanged but IP changed after a machine reset.

**Likely cause:** HTB/THM respawn assigned a new IP.

**Diagnostic:** Target screen `t`; current vs previous locator.

**CyberX response:** DNS/Brain/AI cannot retarget. Only an operator-confirmed
in-scope locator becomes current. Historical locators stay labeled.

**Operator action:** Confirm the new in-scope locator. Do not edit the
database.

---

## 12. Grok unavailable

**Symptom:** AI DISABLED / timeout / missing key.

**Likely cause:** No `CYBERX_AI_API_KEY`, provider `none`, or network to xAI.

**Diagnostic:** `--doctor` `ai_provider:` line (never prints the key).

**CyberX response:** Deterministic Brain continues. AI cannot execute.

**Operator action:** Use AI `none`, or set the key in the environment — not
in source.

---

## 13. Mission resume

**Symptom:** Process restart; last action unknown; duplicate scans feared.

**Likely cause:** Normal pause/crash.

**Diagnostic:** Resume the mission; check coverage on `w` and last ACTION
timeline on `l`.

**CyberX response:** Hydrates World Model from evidence; blocking coverage
is not replayed. `attempted` failures may retry once.

**Operator action:** `r` resume. Confirm locator (`t`) and network (`n`)
first if the VPN changed.

---

## 14. Permissions

**Symptom:** Nmap `permission denied` / `need to be root`; cannot write
`data/`.

**Likely cause:** Connect-scan vs SYN-scan (CyberX uses `-sT`, not `-sS`),
or data directory not writable.

**Diagnostic:** `--doctor`; action reason `process_error`.

**CyberX response:** Fail closed with `process_error`. Does not escalate
privileges and does not switch to `-sS`.

**Operator action:** Ensure `data/` is writable. Do not run CyberX as a
generic root workflow unless your lab policy requires it.

---

## Nmap IPv4 invocation (v1)

Preferred IPv4 argv (closed list, no shell):

```text
nmap -4 -e <validated_interface> -n -Pn --max-retries 1 -sT ... -oX <path> --host-timeout <Ns> <ipv4>
```

- No automatic `-S <source>`
- Never bind `fe80::` for an IPv4 target
- If `-e` still NSOCK-fails: retry **without** `-e`, keep `-4` (OS routing)
- That fallback is **not** a named switch to `eth0`

Manual contrast that fails on dual-stack tun0:

```bash
# fails (binds fe80)
sudo nmap -Pn -e tun0 -sV -p- <IPV4>
# works (OS routing)
nmap -Pn -sV -p- <IPV4>
```

CyberX prefers the IPv4-safe form (`-4` plus validated `-e`) so the operator
does not have to bypass the tool.

IPv6 in v1 is conservative (`-6`, optional `-e`, no automatic `-S`) and is
not a complete IPv6 enumeration product.
