# CyberX v1 Engineering Specification

**Status:** Binding implementation contract — CyberX v1 CTF Edition (recon/intelligence)
**Runtime:** Python 3.10+
**Supersedes assumptions in:** `docs/ARCHITECTURE.md` where they differ
**Product:** CyberX v1 — Strategic Recon Brain
**Contracts:** Pydantic v2 models; `Protocol` interfaces
**Out of scope:** exploitation, persistence, destructive actions, credential brute force, DoS, C2, arbitrary command execution

This document is precise enough to implement without architectural invention. If a behavior is not specified here, it is **not** a v1 feature.

---

# 1. Executive Architecture

CyberX v1 is a mission-driven adaptive reconnaissance and analysis platform for authorized CTFs, HTB/THM-style labs, and authorized assessments.

It is **not** a scanner pipeline, **not** an exploit framework, and **not** an LLM with a shell.

## 1.1 Control loop

```text
Mission
  → Observe (World Model snapshot)
  → Enumerate (knowledge gaps)
  → Parse (only after a tool run)
  → Evidence
  → World Model update
  → Graph projection (attack-surface relationships; not a second source of truth)
  → NetworkContext (read-only local routing; not authorization)
  → Findings / recon signals
  → Validation candidates (safe questions → existing catalog actions)
  → Investigation paths (catalog-only; not exploit chains)
  → Hypothesis revise
  → Score candidate actions
  → Select next best action
  → Deterministic validation + scope + catalog + policy
  → Execute allowed action
  → Observe result
  → Update World Model
  → Rebuild graph
  → Re-plan
```

## 1.2 Non-negotiable rules

| ID | Rule |
|---|---|
| R1 | No action exists outside a `Mission` with status `RUNNING` and a frozen `Scope`. |
| R2 | Only catalogued `action_type` values may execute. Unknown types are denied. |
| R3 | AI never executes, never writes DB/scope/mission state, never bypasses catalog or policy. |
| R4 | Facts enter the World Model only via Evidence. Hypotheses are not facts. |
| R5 | v1 action types are recon-only. `VALIDATE` / `EXPLOIT` / `POST_EXPLOIT` are denied even if instantiated. `ValidationCandidate` is not an action type. |
| R6 | Tool adapters receive argv-list parameters. `shell=True` is forbidden. |
| R7 | Mission Engine is the only sequencer. Brain cannot call executors. |
| R8 | A mission must run with `ai_provider = none`. |
| R9 | Every World Model claim traces to ≥1 `evidence_id`. |
| R10 | Scope is immutable after `CONFIRMED`. AI cannot modify it. |

## 1.3 Runtime components

| Component | Kind | Privilege |
|---|---|---|
| Operator TUI / CLI | Interface | Creates missions, pause/stop, views state |
| Mission Engine | Application | Sole owner of the loop |
| Brain | Domain service | Reads `BrainContext`, returns `Decision` |
| Policy Engine | Domain service | Hard gate |
| Action Catalog | Domain | Declares legal actions |
| Evidence Pipeline | Domain service | Raw → Observation → Evidence → Delta |
| World Model | Domain | Current belief graph |
| GraphProjector | Domain service | World snapshot → attack-surface graph (projection only) |
| PathPlanner | Domain service | Investigation paths over the graph; never executes |
| ValidationEngine | Domain service | Safe investigation questions; never executes |
| NetworkResolver | Domain service | Read-only local routing/interface observation; never authorizes |
| Recon adapters | Infrastructure | Run tools |
| Storage | Infrastructure | System of record |
| AI providers | Infrastructure | Optional structured advice |
| Audit/Timeline | Infrastructure | Append-only history |

## 1.4 Identifiers, time, enums

- All IDs: prefix + Crockford ULID, ASCII, example `mis_01J6Q...`
- Timestamps: timezone-aware UTC `datetime`
- Enums: `StrEnum`
- Confidence: `float` in `[0.0, 1.0]`
- Money/cost: dimensionless `float` in `[0.0, 1.0]` (1 = expensive)
- Canonicalization functions live in `cyberx.domain.identity` and are the **only** legal way to build asset keys

ID prefixes:

| Prefix | Entity |
|---|---|
| `mis_` | Mission |
| `tgt_` | Target |
| `scp_` | Scope |
| `ast_` | Asset (base) |
| `hst_` | Host |
| `nif_` | NetworkInterface |
| `prt_` | Port |
| `svc_` | Service |
| `tec_` | Technology |
| `dom_` | Domain |
| `sub_` | Subdomain |
| `url_` | URL |
| `ep_` | Endpoint |
| `prm_` | Parameter |
| `aut_` | AuthenticationSurface |
| `fnd_` | Finding |
| `hyp_` | Hypothesis |
| `evd_` | Evidence |
| `obs_` | Observation |
| `act_` | Action (instance) |
| `run_` | ToolRun |
| `res_` | ActionResult |
| `tl_` | TimelineEvent |
| `clm_` | Claim |
| `gap_` | KnowledgeGap |
| `dec_` | Decision |
| `art_` | RawArtifact |
| `val_` | ValidationCandidate |
| `pth_` | InvestigationPath |

---

# 2. Domain Model

All entities are immutable in storage except where a lifecycle field is specified. Updates create a new `updated_at` and, for claims, an audit timeline event. Do not add fields beyond this spec in v1.

Shared conventions:

- `created_at` required on every persisted entity
- `updated_at` required if the entity is mutable
- `mission_id` required on every mission-scoped entity
- Deletion is not allowed; use status `INVALIDATED` / `CANCELLED` / `SUPERSEDED`

---

## 2.1 Mission

**Purpose:** Unit of work. All recon happens inside one mission.

**Identity:** `mission_id`

**Required fields**

| Field | Type | Notes |
|---|---|---|
| `mission_id` | `str` | `mis_` |
| `name` | `str` | 1–80 chars |
| `intent` | `str` | Operator natural language, 1–4000 chars |
| `mode` | `MissionMode` | `ctf` \| `lab` \| `authorized_assessment` |
| `status` | `MissionStatus` | see §4 |
| `target_id` | `str` | |
| `scope_id` | `str` | |
| `policy_profile` | `str` | v1: `recon_default` |
| `ai_provider` | `str` | default `none` |
| `max_iterations` | `int` | default `50`, min 1, max 500 |
| `max_runtime_s` | `int` | default `3600`, max `14400` |
| `min_action_score` | `float` | default `0.15` |
| `created_at` | `datetime` | |

**Optional fields**

| Field | Type | Notes |
|---|---|---|
| `authorized_by` | `str` | Operator name; required if mode=`authorized_assessment` |
| `authorization_note` | `str` | Ticket/CTF name |
| `started_at` | `datetime` | |
| `ended_at` | `datetime` | |
| `stop_reason` | `StopReason` | |
| `iteration` | `int` | default 0 |
| `updated_at` | `datetime` | |

**Lifecycle:** `CREATED → CONFIRMED → RUNNING ⇄ PAUSED → COMPLETED | STOPPED | FAILED` (§4)

**Relationships:** 1 Target, 1 Scope, 0..1 World Model, N Actions, N Evidence, N TimelineEvents

**Validation**

- `intent` and `name` non-empty
- `mode=authorized_assessment` requires `authorized_by`
- `max_iterations`, `max_runtime_s` within bounds
- Cannot enter `CONFIRMED` unless Target and Scope validate
- `ai_provider` must be a registered provider name or `none`

**Confidence:** n/a

---

## 2.2 Target

**Purpose:** What the operator pointed at, before and after normalization.

**Identity:** `target_id`

**Required**

| Field | Type | Notes |
|---|---|---|
| `target_id` | `str` | `tgt_` |
| `mission_id` | `str` | |
| `raw_input` | `str` | Exactly as typed |
| `kind` | `TargetKind` | `ipv4` \| `ipv6` \| `cidr` \| `hostname` \| `domain` \| `url` |
| `normalized` | `str` | Canonical form |
| `created_at` | `datetime` | |

**Optional**

| Field | Type | Notes |
|---|---|---|
| `resolved_ipv4` | `list[str]` | Filled by recon, not by operator guess |
| `resolved_ipv6` | `list[str]` | |
| `url_scheme` | `str` | if kind=url |
| `url_port` | `int` | |
| `url_path` | `str` | |

**Lifecycle:** immutable except resolution fields (`UNKNOWN` → populated via Evidence)

**Relationships:** Mission 1–1; seeds Host/Domain/URL assets

**Validation**

- Parse `raw_input`; reject empty, whitespace-only, credentials-in-URL (`user:pass@`)
- Reject loopback, link-local, multicast unless `mode=ctf|lab` **and** operator confirms (TUI prompt). Default deny: `127.0.0.0/8`, `::1`, `169.254.0.0/16`, `10.0.0.0/8` is **allowed** for CTF/lab, **denied** for `authorized_assessment` unless inside explicit Scope
- Hostname: LDH + dots, max 253 chars
- URL: `http` or `https` only in v1

**Confidence:** resolution IPs are Claims on Host, not trusted from `raw_input`

### 2.2.1 Target identity vs locators (M18)

An IP address is a **locator**, not necessarily the permanent identity of a target.

```text
Mission → TargetIdentity → ObservedLocators → CurrentReachability
```

**Identity** is stable for the mission (`canonical_identity`). It is:

- `identity:name:{fqdn}` when the operator supplied a hostname/domain (or a URL whose host is a name)
- `identity:ipv4:{ip}` / `identity:ipv6:{ip}` only when the operator supplied an IP (or IP URL) and no stronger name is available
- never rewritten when a locator changes

**Locator** (`current_locator` + `locator_history`) is observed addressing. History is append-only. Statuses: `current` | `historical` | `observed` | `unreachable`.

Rules:

- Recon/DNS may **observe** a new address. Observation does not retarget the mission.
- Promoting a new locator to `current` is an **operator-only** command (`ConfirmLocatorCmd`). AI cannot do it.
- The new locator must already sit inside the frozen Scope. Out of scope → `LocatorRejected`. Scope is never expanded.
- Unreachable old locators are not `TARGET_IDENTITY_INVALID`.
- `TIMEOUT` is transient NetworkContext state and must not be persisted as a World Model fact.
- Coverage keys include the action's canonical locator: scanning a new IP is new work; repeating the same locator+params is suppressed.
- World Model keeps historical host entities. Graph may `RELATED_TO` hosts that share the same target-identity label; it does not merge unrelated IPs.

**NetworkContext digest:** sha256 of `{target, target_ip, reachability, interface, source, route, tunnel, tunnel_present, available}` truncated to 16 hex chars. Source-IP change, route change, and interface disappearance/reappearance are distinct revisions.

---

## 2.3 Scope

**Purpose:** Deterministic allow/deny envelope. Frozen at confirm.

**Identity:** `scope_id`

**Required**

| Field | Type | Notes |
|---|---|---|
| `scope_id` | `str` | `scp_` |
| `mission_id` | `str` | |
| `allowed_targets` | `list[str]` | Hosts, FQDNs, URLs |
| `allowed_networks` | `list[str]` | CIDRs; may be empty if hosts listed |
| `allowed_ports` | `PortSet` | default `all` represented as empty list meaning all ports **in v1 CTF/lab**; assessment default `{80,443,8080,8443}` if operator does not specify |
| `allowed_protocols` | `list[str]` | subset of `tcp,udp,http,https,dns` |
| `version` | `int` | always `1` after confirm; never increment in v1 (immutable) |
| `frozen` | `bool` | `true` after CONFIRMED |
| `created_at` | `datetime` | |

**Optional**

| Field | Type | Notes |
|---|---|---|
| `excluded_targets` | `list[str]` | |
| `excluded_networks` | `list[str]` | |
| `excluded_ports` | `list[int]` | |
| `time_window_start` | `datetime` | |
| `time_window_end` | `datetime` | |
| `allow_subdomains` | `bool` | default `true` for listed domains |
| `follow_redirects_in_scope_only` | `bool` | default `true` |

**Lifecycle:** mutable only while Mission is `CREATED`. After `CONFIRMED`, all writes except via a **new mission** are rejected.

**Relationships:** Mission 1–1

**Validation**

- At least one of `allowed_targets` or `allowed_networks` non-empty
- Every allowed host/network must include the Target (Target is auto-inserted at confirm if missing)
- CIDRs max `/16` in `authorized_assessment`; max `/8` in ctf/lab
- `time_window_end` > start if both set
- Protocols non-empty
- No overlapping allow/exclude that would make Target itself excluded

**Confidence:** n/a — Scope is authority, not a belief

---

## 2.4 Asset

**Purpose:** Polymorphic discovered entity. Concrete kinds below inherit Asset.

**Identity:** `asset_id` (also kind-specific ID; they are equal, e.g. host uses `hst_` as `asset_id`)

**Required:** `asset_id`, `mission_id`, `kind`, `canonical_key`, `display_name`, `first_seen_at`, `last_seen_at`, `epistemic_status`

**Optional:** `parent_asset_id`, `labels: list[str]`

**Kinds (v1):** `host`, `interface`, `port`, `service`, `technology`, `domain`, `subdomain`, `url`, `endpoint`, `parameter`, `auth_surface`

**Lifecycle of an asset:** created when first Claim/Evidence requires it; never deleted; may become `INVALIDATED`

**Dedup:** unique `(mission_id, canonical_key)`

**Validation:** `canonical_key` produced only by identity helpers; callers cannot pass arbitrary keys

---

## 2.5 Host

**Purpose:** A machine / addressable node.

**Identity:** `hst_`  
**Canonical key:** `host:ipv4:{ip}` | `host:ipv6:{ip}` | `host:name:{fqdn}` (name-only until resolved)

**Required:** Asset fields + `address_type` (`ipv4`\|`ipv6`\|`name`)

**Optional:** `ipv4`, `ipv6`, `hostname`, `os_family`, `os_hint`

**Relationships:** 0..N NetworkInterfaces, Ports, Technologies; 0..N hostnames via Domain/Subdomain resolution claims

**Confidence:** address identity CONFIRMED when seen in tool output; OS fields start SUSPECTED/SUPPORTED from fingerprints

**Validation:** if `address_type=ipv4`, `ipv4` required and valid

---

## 2.6 NetworkInterface

**Purpose:** An address bound to a host (v1: one interface per known IP).

**Identity:** `nif_`  
**Canonical key:** `iface:{host_canonical}:{ip}`

**Required:** `host_id`, `ip`, `family` (`4`\|`6`)

**Optional:** `mac`, `iface_name`, `rdns`

**Relationships:** belongs to Host

**Validation:** `ip` in Scope allow and not excluded, else asset may be recorded as `out_of_scope=true` and **must not** be targeted by later actions

**Extra field:** `out_of_scope: bool` default false

---

## 2.7 Port

**Purpose:** Transport port on a host.

**Identity:** `prt_`  
**Canonical key:** `port:{host_canonical}:{protocol}:{number}`

**Required:** `host_id`, `protocol` (`tcp`\|`udp`), `number` (1–65535), `state` (`open`\|`closed`\|`filtered`\|`unknown`)

**Optional:** `reason` (nmap reason string, truncated 64)

**Relationships:** 0..1 Service; belongs to Host

**Confidence:** nmap `open` → Claim CONFIRMED reliability 0.95; `filtered` → KNOWN 0.7

**Validation:** protocol in scope; port in allowed_ports / not excluded

---

## 2.8 Service

**Purpose:** Application-layer identity on a port.

**Identity:** `svc_`  
**Canonical key:** `svc:{port_canonical}` (v1 1:1 with Port)

**Required:** `port_id`, `name` (lowercase, e.g. `http`)

**Optional:** `product`, `version`, `banner` (truncated 256, redacted), `tunnel` (`ssl`\|`none`)

**Relationships:** Port 1–1; 0..N Technology; may spawn URL if http/https

**Confidence:** name from nmap well-known port = SUPPORTED 0.6; from probe/banner = CONFIRMED 0.85

---

## 2.9 Technology

**Purpose:** Fingerprinted product on an asset (host, service, or URL).

**Identity:** `tec_`  
**Canonical key:** `tech:{parent_canonical}:{product_slug}:{version or '-'}`

**Required:** `parent_asset_id`, `product` (slug, e.g. `nginx`)

**Optional:** `version`, `cpe`, `source` (`header`\|`body`\|`banner`\|`tls`\|`behavior`)

**Relationships:** parent Asset; 0..N Findings

**Confidence:** header Server = SUPPORTED 0.55; body generator + header agreement = CONFIRMED 0.8; AI-only = SUSPECTED max 0.2

---

## 2.10 Domain

**Purpose:** DNS zone / registered-style name in scope (`box.htb`).

**Identity:** `dom_`  
**Canonical key:** `domain:{fqdn_lower}`

**Required:** `fqdn`

**Optional:** `whois_stub` unused in v1 — **do not implement**

**Relationships:** 0..N Subdomains; resolution Claims to Hosts

**Validation:** fqdn lowercase, no trailing dot stored

---

## 2.11 Subdomain

**Purpose:** FQDN under a Domain.

**Identity:** `sub_`  
**Canonical key:** `subdomain:{fqdn_lower}`

**Required:** `fqdn`, `domain_id`

**Optional:** `source` (`enum`\|`brute`\|`cert`\|`transfer`)

**Relationships:** Domain; resolution to Hosts

**Validation:** `fqdn` endswith `.` + parent fqdn; must pass Scope (`allow_subdomains`)

---

## 2.12 URL

**Purpose:** Normalized locator.

**Identity:** `url_`  
**Canonical key:** `url:{scheme}://{host}:{port}{path}` with default ports omitted in **display**, included in key always (`http`→80, `https`→443)

**Required:** `scheme` (`http`\|`https`), `host`, `port`, `path` (must start `/`, no query)

**Optional:** `query_template` (sorted keys only, values stripped), `status_code`, `title` (128), `content_type`

**Normalization:** lowercase scheme/host; decode `%2e` / dot-dot rejected; strip fragment; path collapse `//`; no credentials

**Relationships:** 0..N Endpoints; may link Host + Domain

**Validation:** in-scope host/domain/port/scheme

---

## 2.13 Endpoint

**Purpose:** HTTP method + URL as a probed surface.

**Identity:** `ep_`  
**Canonical key:** `ep:{method}:{url_canonical}`

**Required:** `url_id`, `method` (`GET`\|`HEAD`\|`POST`\|`OPTIONS` — v1 probe methods)

**Optional:** `last_status`, `content_length`, `auth_required: bool`

**Relationships:** URL; 0..N Parameters; 0..1 AuthenticationSurface

---

## 2.14 Parameter

**Purpose:** Observed request parameter name (not a playground for injection).

**Identity:** `prm_`  
**Canonical key:** `param:{endpoint_canonical}:{location}:{name_lower}`

**Required:** `endpoint_id`, `name`, `location` (`query`\|`path`\|`body`\|`header`\|`cookie`)

**Optional:** `example_seen` — **store only if not secret-shaped**; else `redacted=true`

**Secret-shaped:** name matches `(pass|pwd|secret|token|key|session|cookie|auth|jwt)` case-insensitive, or value looks like JWT/PEM. Values never stored; `redacted=true`

**v1 does not fuzz parameters.**

---

## 2.15 AuthenticationSurface

**Purpose:** Discovered auth presentation. **Not** an invite to attack.

**Identity:** `aut_`  
**Canonical key:** `auth:{endpoint_canonical}:{kind}`

**Required:** `kind` (`http_basic`\|`http_form`\|`http_bearer_challenge`\|`unknown`), `endpoint_id` or `url_id`

**Optional:** `form_fields` (names only), `realm`

**Forbidden:** passwords, cookies, tokens

**Lifecycle:** discovered → reported as Finding `auth_surface`; no brute-force action exists in catalog

---

## 2.16 Finding

**Purpose:** Operator-facing noteworthy recon item. Not an exploit proof.

**Identity:** `fnd_`

**Required:** `mission_id`, `kind`, `title`, `summary`, `severity`, `epistemic_status`, `evidence_ids` (min 1), `asset_ids` (min 1), `created_at`

**Kind (v1):** `open_port` \| `service` \| `technology` \| `url` \| `interesting_path` \| `auth_surface` \| `dns` \| `anomaly` \| `out_of_scope_observation`

**Severity (v1):** `info` \| `low` \| `medium` — no `high`/`critical` (those imply exploit impact; v1 recon does not assign them)

**Optional:** `hypothesis_id` if derived from a supported hypothesis; `recommendation` (investigation only); `signal`; `identity_key`; `validation_state`; `validation_count`; `last_validation_result`

**Lifecycle:** `open` \| `accepted` \| `superseded` \| `invalidated`

**Validation:** `evidence_ids` non-empty; cannot have `epistemic_status=CONFIRMED` if all supporting claims are SUSPECTED; cannot exist without World Model claims. Findings are recon signals, never `VULNERABILITY_CONFIRMED`.

**Confidence:** equals `min(supporting claim confidences)`

---

## 2.17 Hypothesis

**Purpose:** Testable explanatory claim. **Never a fact.**

**Identity:** `hyp_`

**Required:** `mission_id`, `statement` (≤500 chars), `status`, `confidence`, `created_at`

**Status:** `open` \| `supported` \| `contradicted` \| `retired` \| `promoted`

**Optional:** `rationale`, `related_asset_ids`, `related_gap_ids`, `suggested_action_types`, `source` (`heuristic`\|`ai`), `promoted_claim_id`

**Lifecycle**

```text
open → supported → promoted     # promotion creates/upgrades a Claim; hypothesis not deleted
open → contradicted
* → retired                     # planner dropped as irrelevant
```

**Validation**

- `source=ai` ⇒ confidence capped at `0.4` and status cannot be `promoted` without subsequent **non-AI** evidence
- `promoted` requires ≥1 non-AI Evidence and Claim status ≥ `SUPPORTED`
- Statement cannot contain shell commands

**Confidence rules:** start 0.3 heuristic / 0.2 AI; +0.15 per independent supporting evidence; −0.3 on contradiction; promote only if ≥0.7 **and** non-AI evidence exists

---

## 2.18 Evidence

**Purpose:** The only legal writer-input to World Model. Traceable normalized statement.

**Identity:** `evd_`

**Required:** `mission_id`, `observation_id`, `artifact_id`, `tool_run_id`, `parser_id`, `claim_preview` (predicate+object), `reliability`, `created_at`

**Optional:** `parent_evidence_id` (if derived), `hash` (sha256 of normalized JSON)

**Lifecycle:** immutable once written

**Relationships:** 1 Observation, 1 RawArtifact, 1 ToolRun, N Claims

**Validation:** `reliability` in `[0,1]`; parser_id in registry; cannot be created by AI providers

---

## 2.19 Observation

**Purpose:** Atomic structured parser output.

**Identity:** `obs_`

**Required:** `mission_id`, `parser_id`, `predicate`, `object` (JSON-serializable, size ≤ 8KiB), `subject_hint` (canonical key or raw), `created_at`

**Optional:** `extra: dict` ≤ 2KiB

**Lifecycle:** immutable

**Validation:** unknown predicate is stored but **not** applied to World Model (logged as `unmapped_observation`)

**v1 predicates (closed set):**

```
host.alive, host.address, host.hostname,
port.state, service.name, service.product, service.version, service.banner,
http.status, http.title, http.header, http.redirect, http.body_hash, http.tech,
dns.record, dns.subdomain,
url.seen, endpoint.seen, param.seen, auth.seen
```

---

## 2.20 Action

**Purpose:** One planned or in-flight catalogued operation (instance, not spec).

**Identity:** `action_id` (`act_`)

**Required**

| Field | Type |
|---|---|
| `action_id` | `str` |
| `mission_id` | `str` |
| `action_type` | `str` (catalog key) |
| `target` | `ActionTarget` (asset_id and/or canonical locator) |
| `parameters` | `dict` validated by catalog schema |
| `reason` | `str` ≤ 500 |
| `expected_information_gain` | `float` 0–1 |
| `risk` | `Risk` `info`\|`low`\|`medium` |
| `timeout_s` | `int` |
| `prerequisites` | `list[str]` (gap ids or claim ids) |
| `evidence_expected` | `list[str]` (predicate names) |
| `status` | `ActionStatus` |
| `coverage_key` | `str` |
| `created_at` | `datetime` |

**Optional:** `score`, `decision_id`, `attempt`, `parent_action_id` (retry)

**Lifecycle:** §5.3

**Validation:** `action_type` in catalog; params schema; timeout ≤ spec max; risk ≤ spec risk; target in scope (engine still re-checks)

---

## 2.21 ActionResult

**Purpose:** Outcome of one Action / ToolRun pair.

**Identity:** `res_`

**Required:** `action_id`, `tool_run_id`, `status` (`completed`\|`failed`\|`timeout`\|`cancelled`\|`unavailable`\|`denied`), `started_at`, `ended_at`

**Optional:** `error_code`, `error_message` (truncated 300, no secrets), `observation_count`, `evidence_ids`

---

## 2.22 ToolRun

**Purpose:** One adapter invocation.

**Identity:** `run_`

**Required:** `action_id`, `adapter_name`, `argv` (`list[str]`, **not** a joined string), `started_at`, `status`

**Optional:** `exit_code`, `ended_at`, `artifact_id`, `timed_out: bool`, `unavailable: bool`

**Validation:** `argv` has no `shell=True` equivalent; no `|`, `&&`, `;` as injected operator tokens; hostname/path are single argv slots

---

## 2.23 TimelineEvent

**Purpose:** Append-only mission history for operator + audit.

**Identity:** `tl_`

**Required:** `mission_id`, `kind`, `message`, `at`

**Kind:** `mission_status` \| `decision` \| `policy` \| `action` \| `evidence` \| `world` \| `hypothesis` \| `ai` \| `error` \| `operator` \| `network`

**Optional:** `ref_id`, `payload_digest` (hash of structured payload; do not dump raw tool output here)

---

## 2.24 WorldModel

**Purpose:** Current understanding of the target for this mission. Not the database.

**Identity:** `mission_id` (one world per mission)

**Required contents:** entities index, claims index, gaps index, coverage index, `revision` (monotonic int), `updated_at`

**Not stored as a blob-only object:** it is a projection. A serialized snapshot **may** be cached in storage as `world_snapshots(revision, json, created_at)` for fast load.

Details: §3

---

## 2.25 BrainContext

**Purpose:** Size-capped, read-only projection of World Model + mission for planning and optional AI.

**Required**

| Field | Notes |
|---|---|
| `mission_id` | |
| `intent` | |
| `mode` | |
| `iteration` | |
| `scope_digest` | hash + human summary, not full mutate-capable object |
| `asset_counts` | by kind |
| `top_assets` | max 50 typed `AssetContext` rows |
| `claims` | non-INVALIDATED, max 200, values truncated 200 chars (`ClaimContext`) |
| `gaps` | max 50, priority desc (`GapContext`) |
| `hypotheses` | open+supported, max 20 (`HypothesisContext`) |
| `coverage_keys` | list of completed coverage_keys |
| `recent_results` | last 5 ActionResults (`ResultContext`) |
| `recent_events` | last 10 TimelineEvents (messages only) |
| `revision` | World Model revision used |
| `byte_size` | |
| `top_findings` | max 8 compact recon findings (`FindingContext`) |
| `investigations` | max 8 ranked investigation items (`InvestigationContext`) |
| `validation_candidates` | max 8 compact ValidationCandidate rows (`ValidationContext`) |
| `graph_digest` | semantic graph digest (ULID-independent) |
| `investigation_paths` | max 5 compact InvestigationPath rows (`PathContext`) |
| `graph_focus` | max 8 compact edges related to top paths / current target |
| `network` | compact `NetworkContextSummary`: reachability, interface, source, route, tunnel, diagnostic, digest, current locator |
| `target_identity` | compact `TargetIdentityContext`: identity, current, previous, historical |

Rows are read-only DTOs (attribute access is canonical). They are **not** domain entities.

**Hard cap:** serialized JSON ≤ 32 KiB. Truncate `top_assets` then `claims` then events to fit. Then hypotheses, investigations, findings, validation candidates, graph_focus, investigation_paths. Keep `network` compact (selected route only). Empty fields are omitted from the serialized form.

**Forbidden in BrainContext:** raw artifacts, argv, secrets, full Scope object (digest only), AI chain-of-thought dumps, the full attack-surface graph

**Lifecycle:** ephemeral per cycle; one coherent snapshot per MissionEngine decision phase. Hypothesis revisions persist to the World Model for the **next** cycle — do not rebuild BrainContext from partially changed state in the same decision phase. May be persisted as an audit blob hashed; not required for v1 resume.

---

## 2.26 ValidationCandidate

**Purpose:** A safe investigation question about a recon signal. **Not** a vulnerability, **not** an exploit plan, **not** an action type.

**Identity:** `val_`

**Required:** `validation_id`, `mission_id`, `candidate_type`, `identity_key`, `status`, `reason`, `created_at`

**Optional:** `finding_id`, `asset_ids`, `hypothesis_id`, `mapped_action_type`, `coverage_key`, `locator`, `parameters`, `expected_predicates`, `evidence_ids`, `current_confidence`, `priority`, `updated_at`, `source`

**Statuses (v1):** `proposed` \| `queued` \| `testing` \| `supported` \| `inconclusive` \| `rejected` \| `expired`

v1 uses `proposed`, `supported`, `inconclusive`, `rejected`, `expired`. `queued` / `testing` are reserved for v2 protocol-specific validation and must not mean "exploit in progress".

**Candidate types (v1, closed, recon-adjacent):**

```
http_surface, interesting_path, unusual_http, redirect_behavior,
technology_fingerprint, authentication_surface, service_fingerprint, unsupported
```

**Mapping law:** `mapped_action_type` is empty **or** a v1 catalog action. There is no `validate` action. Unknown / exploit-like types are `rejected`.

**Safety:** AI cannot create candidates (`source=ai` is invalid). Parameters cannot contain credentials or unsafe HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`). Candidates never execute.

**Coverage:** identical observation (`coverage_key`) is suppressed (`supported` if expected evidence is present, else `inconclusive`). New expected evidence can change status without inventing a new action type.

**Epistemic output:** `supported` / `inconclusive` / `rejected` refer to the **investigation question**, never to a confirmed vulnerability.

---

## 2.27 GraphSnapshot

**Purpose:** Read-only projection of World Model relationships for investigation. **Not** a source of truth. Evidence → World Model remains authoritative. The graph is rebuilt from a `WorldSnapshot` (+ current ValidationCandidates). Callers cannot inject arbitrary nodes or edges.

**Identity:** `mission_id` + `revision` (matches World Model revision). Semantic identity is `digest` (sha256 of sorted `(kind, semantic_key, out_of_scope, epistemic_status)` nodes and `(kind, src_key, dst_key, invalidated, rule)` edges). ULIDs are excluded from the digest.

**Node kinds (closed v1):** `domain`, `subdomain`, `host`, `interface`, `port`, `service`, `technology`, `url`, `endpoint`, `parameter`, `auth_surface`, `finding`, `hypothesis`, `validation_candidate`

Forbidden node kinds: `exploit`, `payload`, `shell`, `session`, `persistence`, `foothold`

Every node references the underlying World Model / finding / hypothesis / validation entity (`ref_id`). `semantic_key` is the canonical key (or `finding:{identity_key}`, `hyp:{statement}`, `val:{identity_key}`).

**Edge kinds (closed v1):** `RESOLVES_TO`, `HOSTS`, `EXPOSES`, `RUNS`, `IMPLEMENTS`, `SERVES`, `CONTAINS`, `LINKS_TO`, `USES`, `AUTHENTICATES`, `SUPPORTED_BY`, `RELATED_TO`, `DERIVED_FROM`, `HAS_FINDING`, `HAS_HYPOTHESIS`, `HAS_VALIDATION`

Edges exist only with a documented rule (`identity:*` foreign keys, `claim:dns.record`, `claim:host.hostname`, `match:url.host`). Invalidated relationships are retained (`invalidated=true`); they are not rewritten silently.

Out-of-scope nodes may appear for provenance. They must not seed executable actions or active investigation paths.

The graph is not persisted as a second database. It is rebuilt deterministically from World Model + evidence history.

---

## 2.28 InvestigationPath

**Purpose:** A sequence of observed graph relationships plus legal investigation opportunities. **Not** an exploit chain, **not** an attack path, **not** an action type.

**Identity:** `pth_` (deterministic ULID from the path semantic key; timestamp=0)

**Required:** `path_id`, `semantic_key`, `nodes`, `labels`, `priority`

**Optional:** `node_ids`, `edges`, `relevance`, `confidence`, `information_value`, `completeness`, `unresolved_questions`, `candidate_actions`, `rationale`, `locator`, `action_type`, `parameters`, `out_of_scope`

**Path score (deterministic, 0..1):**

```
priority = clamp01(
    0.25 * relevance
  + 0.20 * information_value
  + 0.15 * (1 - completeness)
  + 0.15 * asset_importance
  + 0.10 * confidence
  + 0.10 * evidence_quality
  + 0.05 * novelty
)
```

`candidate_actions` may only name existing v1 catalog types. ActionScorer remains authoritative for executable actions. Out-of-scope branches produce no candidate actions and are not emitted as active paths.

---

## 2.29 NetworkContext

**Purpose:** Read-only observation of the local network environment for one mission target. **Not** a VPN client, **not** authorization, **not** World Model evidence, **not** a reason to mutate Scope.

**Required:** `target`, `reachability`

**Optional:** `target_ip`, `selected_interface`, `source_address`, `selected_route`, `default_route`, `likely_tunnel`, `tunnel_unverified`, `tunnel_hint`, `tunnel_present`, `diagnostic`, `platform`, `available`, `route_in_scope`, `oos_routes`, `interfaces`, `routes`

**ReachabilityStatus (closed):** `UNKNOWN` \| `REACHABLE` \| `UNREACHABLE` \| `ROUTE_MISSING` \| `BLOCKED` \| `TIMEOUT`

- `ROUTE_MISSING` is not “host is down”.
- `TIMEOUT` is transient and **must not** be persisted as a World Model fact or `GAP_KINDS` entry.
- Tunnel labels are heuristic (`tun`/`tap`/`wg`/`utun` + ARPHRD). Never claim a VPN provider (e.g. “HTB VPN”) without direct evidence.
- A discovered route CIDR is diagnostic only. It never expands Scope.
- Adapters consume bind hints only via `ExecutionContext` (`source_interface`, `source_address`, `address_family`) after validation. IPv4 Nmap receives modeled `-4` and optional `-e <interface>`. Explicit `-S` is **not** added automatically (dual-stack tunnels otherwise bind IPv6 link-local `fe80::`). IPv6 is conservative (`-6`, optional `-e`). If `-e` still NSOCK-fails, the adapter retries without `-e` (OS routing; not a silent switch to another named interface). HTTP/DNS must not take arbitrary bind/resolver overrides from AI or the operator.

Compact form for BrainContext (selected route/interface only; no full table dump).

---

# 3. World Model

The World Model is the **current belief graph** of one mission. Storage is the **history**. Brain reads a snapshot; only the Evidence projector writes.

## 3.1 Epistemic status

Every Claim and Asset carries `epistemic_status`:

| Status | Meaning | Typical origin |
|---|---|---|
| `UNKNOWN` | Gap exists; no claim yet | KnowledgeGap only (not stored as Claim) |
| `KNOWN` | Directly observed once, not corroborated | Single parser observation |
| `SUSPECTED` | Weak inference or hypothesis bleed | Heuristic/AI, low reliability |
| `SUPPORTED` | Independent or reasonably strong support | 2nd source or reliability ≥ 0.7 |
| `CONFIRMED` | Sufficient evidence; reportable as fact | Direct high-reliability observation or 2 independent + conf ≥ 0.8 |
| `INVALIDATED` | Contradicted; **retained** | Stronger or equal contrary evidence |

**Law:** a Hypothesis is never written as `CONFIRMED` Claim in the same step it was created, and never without non-AI Evidence.

## 3.2 Graph contents

```text
Asset nodes
Claim edges/records: (subject_asset_id, predicate, object)
KnowledgeGap nodes
Coverage map: coverage_key → ActionResult status
Hypothesis index (references, not facts)
out_of_scope flags
revision
```

Claim record:

| Field | Type |
|---|---|
| `claim_id` | `clm_` |
| `subject_id` | asset id |
| `predicate` | str |
| `object` | JSON scalar/object small |
| `epistemic_status` | enum |
| `confidence` | 0–1 |
| `evidence_ids` | list, min 1 except never — **min 1 always** |
| `contradiction_ids` | list of evidence_id |
| `created_at` `updated_at` | |

A Claim **without evidence is invalid** and the projector must reject it.

## 3.3 How facts enter

```text
ToolRun → RawArtifact
        → Parser → Observation[]
        → EvidencePipeline.normalize → Evidence[]
        → CorrelationEngine.match → existing assets / new assets
        → WorldProjector.apply → WorldDelta[]
        → WorldModel.apply(deltas) → revision++
```

No other writer exists. TUI cannot edit claims. AI cannot insert claims. Brain cannot insert claims.

## 3.4 How evidence supports a fact

Each Evidence has `reliability` from parser tables:

| Source | Predicate examples | Reliability |
|---|---|---|
| nmap port state open/closed | `port.state` | 0.95 |
| nmap service tunnel/ssl | `service.name` | 0.85 |
| nmap version guess | `service.product` | 0.60 |
| HTTP status from probe | `http.status` | 0.90 |
| HTTP title | `http.title` | 0.85 |
| HTTP Server header | `http.tech` | 0.55 |
| Body generator / cookie names | `http.tech` | 0.50 |
| DNS A/AAAA | `dns.record` | 0.90 |
| Subdomain brute hit (resolves) | `dns.subdomain` | 0.80 |
| Directory enum HTTP 200/401/403 | `url.seen` | 0.85 |
| Directory enum 404 wildcard-unverified | `url.seen` | 0.40 |
| Heuristic inference (no tool) | any | **forbidden** — not Evidence |
| AI | any | **forbidden as Evidence** |

AI may create Hypotheses only.

## 3.5 Confidence update (mandatory formula)

Let `c` be current confidence, `r` evidence reliability.

**Supporting evidence (same subject+predicate+object):**

```
c := 1 - (1 - c) * (1 - r)
```

**Contradicting evidence (same subject+predicate, different object):**

```
if r >= c:
    status := INVALIDATED
    confidence := r
    # old object retained on the INVALIDATED claim
    # new claim created for new object with status from §3.6 using this evidence only
else:
    c := c * (1 - 0.5 * r)
    if c < 0.30: status := SUSPECTED
```

Clamp `c` to `[0,1]`.

## 3.6 Status upgrade/downgrade

After confidence update, set status from evidence class (do not skip ranks except as noted):

| Condition | Resulting status |
|---|---|
| Single direct observation, `r ≥ 0.90`, predicate in `{port.state, http.status, dns.record, url.seen, host.alive}` | `CONFIRMED` |
| Single direct observation, `0.70 ≤ r < 0.90` | `KNOWN` |
| Single observation, `0.40 ≤ r < 0.70` | `SUPPORTED` if parser-declared “fingerprint”; else `SUSPECTED` |
| `r < 0.40` | `SUSPECTED` |
| Two independent evidence_ids (different `tool_run_id`), same object, `c ≥ 0.70` | max(current, `SUPPORTED`) |
| Two independent, `c ≥ 0.80`, no open contradiction | `CONFIRMED` |
| Hypothesis-sourced, no tool evidence | **not a Claim** |
| After contradiction handled as above | `INVALIDATED` or `SUSPECTED` |

Independent = different `tool_run_id` and different `parser_id` **or** different `action_type`.

## 3.7 Conflicting evidence

1. Keep the original Claim row; mark `INVALIDATED` when rule says so.
2. Insert a new Claim for the new object.
3. TimelineEvent `world` with both evidence ids.
4. If both objects are still weakly supported, both may exist: one `INVALIDATED` or both `SUSPECTED` with contradiction_ids set. Reports must show conflict, not pick silently.
5. Operator does not manually merge in v1.

## 3.8 Deduplication

| Entity | Canonical key function |
|---|---|
| Host IP | `ip_address` normalized (IPv4 no leading zeros; IPv6 compressed) |
| Host name | FQDN lower, no trailing dot |
| Merge host | when `dns.record` A/AAAA links name-host to ip-host: keep IP host as primary, name as alias Claim `host.hostname` |
| Port | host primary + proto + number |
| URL | scheme lower, host lower, explicit port, path RFC3986, no fragment, query keys sorted excluded from identity unless path is `/` and query is the resource — v1 identity **ignores query** |
| Subdomain | FQDN lower |
| Technology | parent + product slug (`re.sub(r'[^a-z0-9]+','-', product.lower())`) + version or `-` |

Insert path: `get_or_create(canonical_key)` inside CorrelationEngine under the mission lock.

## 3.9 Invalidated retention

INVALIDATED claims:

- remain queryable
- are excluded from BrainContext `claims` **except** they appear in a `conflicts[]` array (max 20)
- never deleted from DB
- Findings derived solely from them become `invalidated`

## 3.10 Knowledge gaps

Gap record: `gap_id`, `kind`, `subject_id?`, `detail`, `priority` 0–1, `closed: bool`

v1 gap kinds (closed set):

```
host.unresolved
host.ports_unknown
port.service_unknown
service.http_unprobed
url.tech_unknown
domain.subdomains_unknown
service.directories_unknown
endpoint.params_unknown
```

Gaps are (re)computed by `GapDetector` after every WorldModel.apply. Brain does not invent gap kinds.

Close a gap when a Claim exists that answers it at status ≥ `KNOWN`.

## 3.11 Compact BrainContext generation

Function: `BrainContextBuilder.build(snapshot: WorldSnapshot, mission: Mission, network_context: NetworkContext | None = None) -> BrainContext`

Algorithm:

1. Copy mission id, intent, mode, iteration
2. `scope_digest = sha256(frozen scope json)[:16]` + string like `hosts=1 nets=0 ports=all proto=tcp,http,https`
3. Count assets by kind
4. Select assets: hosts, then services, then urls, cap 50
5. Claims status not INVALIDATED, sort by confidence desc, cap 200
6. Open gaps sort by priority desc, cap 50
7. Hypotheses status in `{open,supported}`, cap 20
8. Coverage keys all (they are short); if over budget, keep those matching open gap action types
9. Last 5 results, last 10 events
10. Serialize; while `> 32768` bytes drop: events → claims 200→50 → top_assets 50→20
11. Set `byte_size`, `revision`

## 3.12 Snapshot vs live model

- `WorldModel` is in-memory, mutex per mission
- `snapshot()` copies dataclasses/pydantic models (deep, immutable)
- Resume: load latest snapshot row, replay Evidence with `id > snapshot.last_evidence_id`

---

# 4. Mission & Scope

## 4.1 Mission lifecycle

```text
CREATED ──confirm──► CONFIRMED ──start──► RUNNING ⇄ PAUSED
                                             │
                        ┌────────────────────┼────────────────────┐
                        ▼                    ▼                    ▼
                   COMPLETED              STOPPED               FAILED
```

| Status | Meaning | Allowed operator commands |
|---|---|---|
| `CREATED` | Draft, scope still mutable | edit, confirm, stop (abandon) |
| `CONFIRMED` | Scope frozen, not looping | start, stop |
| `RUNNING` | Engine looping | pause, stop |
| `PAUSED` | Loop halted between cycles | resume, stop |
| `COMPLETED` | Terminal success | view/report only |
| `STOPPED` | Terminal operator halt | view/report only |
| `FAILED` | Terminal unrecoverable error | view/report only |

Illegal transitions raise `IllegalMissionTransition`. No skips.

## 4.2 Creation

Input: `name`, `intent`, `raw_target`, `mode`, optional scope overrides, optional `ai_provider`, optional limits.

Steps:

1. Parse and validate Target
2. Build default Scope from Target + mode defaults
3. Merge operator overrides; validate Scope includes Target
4. Persist Mission `CREATED`, Target, Scope `frozen=false`
5. Timeline `mission_status`

Does **not** create World Model entities yet except empty world revision 0.

## 4.3 Confirm (target + scope validation)

`confirm(mission_id)`:

1. Re-validate Target
2. Ensure Scope contains Target
3. Assessment mode: `authorized_by` present
4. Freeze Scope (`frozen=true`, `version=1`)
5. Seed World Model:
   - If target IP → Host `SUSPECTED`/`KNOWN`? **Seed as Claim `host.address` with synthetic Evidence `parser_id=seed` reliability 0.99** (operator assertion is evidence class `seed`)
   - If hostname/domain → Domain + optional Subdomain + gap `host.unresolved` and/or `host.ports_unknown`
   - If URL → URL + Host/Domain + gaps `service.http_unprobed` / `url.tech_unknown`
6. Status `CONFIRMED`

`parser_id=seed` is the **only** non-tool Evidence allowed, and only at confirm.

## 4.4 Start / pause / resume / stop

| Command | From | To | Behavior |
|---|---|---|---|
| `start` | CONFIRMED | RUNNING | `started_at=now`, spawn engine loop |
| `pause` | RUNNING | PAUSED | finish current ToolRun or cancel on timeout; **do not** start next action; set flag checked at cycle boundary |
| `resume` | PAUSED | RUNNING | continue with new snapshot |
| `stop` | CREATED/CONFIRMED/RUNNING/PAUSED | STOPPED | cancel in-flight with `cancelled`; `stop_reason=operator` |

Pause is **between cycles** plus cooperative cancel of ToolRun (kill process group on SIGTERM, then SIGKILL after 5s). Partial output still parsed.

## 4.5 Completion conditions

Engine sets `COMPLETED` when any:

1. No candidate action with `score ≥ min_action_score` after policy filter
2. All gaps closed **and** at least one of: a port Claim exists, or mission intent satisfied heuristic (v1 default objective: see §4.7)
3. `iteration >= max_iterations`
4. `now - started_at >= max_runtime_s` (after current action)

`stop_reason` set to `no_actions` | `objectives_met` | `max_iterations` | `max_runtime`

## 4.6 Failure conditions → `FAILED`

- Storage write failure after retry 3
- Policy engine exception (fail closed, then FAILED if repeated)
- World Model apply exception (bug) after 1 retry
- Scope unfrozen while RUNNING (integrity error)

Tool missing / tool crash is **not** mission failure: ActionResult `unavailable`/`failed`, loop continues.

## 4.7 Default mission objectives (v1)

If `intent` is unstructured, objectives are:

1. Resolve target to host(s) in scope
2. Discover TCP ports on those hosts (and UDP only if operator enabled protocol)
3. Enumerate services on open ports
4. If HTTP(S) present: probe, tech detect, limited directory enum
5. If domain: DNS + subdomain enum (cap listed in catalog)

## 4.8 Scope enforcement algorithm

Function `ScopeChecker.check(action: Action, scope: Scope, now) -> PolicyDecision`

1. If `scope.frozen` is false → DENY `scope_not_frozen`
2. If time window set and `now` outside → DENY `out_of_time_window`
3. Resolve action target to a `ScopeSubject`: `{ips, fqdns, cidrs, port, protocol, url}`
4. **Allow test:** each IP in some `allowed_networks` OR exact `allowed_targets`; each FQDN exact match or (if `allow_subdomains`) under allowed domain; URL host+port+scheme similarly
5. **Exclude test:** any match on excluded_* → DENY `excluded`
6. Port: if `allowed_ports` non-empty, port must be in set; excluded_ports deny
7. Protocol mapping: `http_probe` requires `http` or `https` in `allowed_protocols`; `port_scan` requires `tcp`/`udp` as parameterized
8. DNS answers / HTTP redirects: adapter must filter. Out-of-scope observations stored with `out_of_scope=true` and **must not** generate follow-up Actions
9. DENY codes are closed: `not_in_allowlist`, `excluded`, `port_not_allowed`, `protocol_not_allowed`, `out_of_time_window`, `scope_not_frozen`, `redirect_out_of_scope` (if action attempted to follow)

AI has no function to mutate Scope. Repository `update_scope` raises if mission status ≠ `CREATED`.

---

# 5. Action System

## 5.1 Action contract (instance)

See §2.20. Catalog spec is `ActionSpec`:

| Field | Type |
|---|---|
| `action_type` | str stable key |
| `summary` | str |
| `parameter_schema` | Pydantic model class |
| `prerequisites_gap_kinds` | list[str] |
| `produces_predicates` | list[str] |
| `risk` | `info`\|`low`\|`medium` |
| `cost` | float 0–1 |
| `default_timeout_s` | int |
| `max_timeout_s` | int |
| `max_attempts` | int default 2 |
| `allowed_modes` | list[MissionMode] |
| `adapter_name` | str |
| `enabled` | bool — v1 all catalog entries true; exploit types not present |

## 5.2 Candidate creation

Planner (not AI, not adapter):

1. Read BrainContext gaps + assets
2. For each ActionSpec, for each matching subject, if prerequisites satisfied, instantiate `Action` with params from asset fields
3. Compute `coverage_key = sha256(action_type + canonical_target + canonical_json(params))`
4. Drop if coverage_key in completed/failed-nonretryable/in-flight
5. Attach `reason` string from gap kind templates (deterministic)
6. Optional AI may **reorder or annotate** but may only reference existing candidate `action_id`s after they are created. If AI proposes a new type or params that fail schema, drop.

## 5.3 Instance lifecycle

```text
PROPOSED → VALIDATED → QUEUED → AUTHORIZED → RUNNING → COMPLETED
                         │           │            └→ FAILED → (retry) → QUEUED
                         │           └→ DENIED
                         └→ REJECTED
CANCELLED from QUEUED/RUNNING
```

| Status | Who sets | Meaning |
|---|---|---|
| `PROPOSED` | Planner | Exists only in Decision payload |
| `VALIDATED` | ActionValidator | schema + catalog + types |
| `QUEUED` | Engine | Selected next action |
| `AUTHORIZED` | Policy | Scope + kind + rate |
| `RUNNING` | Executor | ToolRun started |
| `COMPLETED` | Engine | Parsed, world updated |
| `FAILED` | Executor/Engine | Retryable or not |
| `DENIED` | Policy | Terminal for this instance |
| `REJECTED` | Validator | Unknown type / bad params |
| `CANCELLED` | Operator/Engine | Pause/stop/timeout kill |

Unknown `action_type` → `REJECTED` immediately. Never queued.

## 5.4 Retry

Retry if `error_code` in `{timeout, adapter_crash, empty_output}` AND `attempt < max_attempts` AND mission still RUNNING.

Non-retryable: `denied`, `out_of_scope`, `wildcard_detected`, `invalid_params`, `unavailable` (tool missing — do not hammer).

Backoff: immediate once in v1 (no sleep beyond tool timeout).

## 5.5 Dedup / cancel

- One RUNNING action per mission in v1 (`concurrency=1`)
- Identical coverage_key cannot be queued twice
- `cancel` sets CANCELLED and kills ToolRun

## 5.6 v1 Action Catalog

No other types may be registered in v1. Risk never above `medium`.

### 5.6.1 `network_discovery`

| | |
|---|---|
| Purpose | Identify live hosts in an in-scope network |
| Input | `network: CIDR` (must equal an allowed_network) |
| Output predicates | `host.alive`, `host.address` |
| Prerequisites | Scope has CIDR; skip if Target is a single host/URL and no extra nets |
| Risk | `low` |
| Cost | 0.4 |
| Modes | all |
| Timeout | default 120, max 180 |
| Restrictions | `/16` max assessment; ping/syn only via adapter profile `safe` |

### 5.6.2 `port_scan`

| | |
|---|---|
| Purpose | Discover port states on a host |
| Input | `host_id` or `address`, `ports`: `top100`\|`top1000`\|`specified` + optional list |
| Output | `port.state` |
| Prerequisites | Host in world, in scope; gap `host.ports_unknown` |
| Risk | `low` |
| Cost | 0.5 |
| Modes | all |
| Timeout | default 180, max 300 |
| Restrictions | UDP scan only if `udp` in allowed_protocols (separate param `protocol=tcp\|udp`, default tcp) |

### 5.6.3 `service_enumeration`

| | |
|---|---|
| Purpose | Fingerprint services on open ports |
| Input | `host_id`, optional `port` |
| Output | `service.name`, `service.product`, `service.version`, `service.banner` |
| Prerequisites | ≥1 Port `state=open` |
| Risk | `low` |
| Cost | 0.5 |
| Modes | all |
| Timeout | default 180, max 300 |

### 5.6.4 `http_probe`

| | |
|---|---|
| Purpose | Request HTTP(S) root and record status/title/redirects |
| Input | `url` or (`host_id` + `port` + `scheme`) |
| Output | `http.status`, `http.title`, `http.redirect`, `url.seen`, `endpoint.seen` |
| Prerequisites | Service name http/https **or** port 80/443/8080/8443 open |
| Risk | `info` |
| Cost | 0.2 |
| Modes | all |
| Timeout | default 30, max 60 |
| Restrictions | Do not follow out-of-scope redirects; max 3 in-scope redirects |

### 5.6.5 `technology_detection`

| | |
|---|---|
| Purpose | Fingerprint web/app technologies |
| Input | `url_id` or `service_id` |
| Output | `http.tech`, `http.header` |
| Prerequisites | Successful `http_probe` with status ≠ 0 |
| Risk | `info` |
| Cost | 0.2 |
| Modes | all |
| Timeout | default 45, max 90 |

### 5.6.6 `dns_enumeration`

| | |
|---|---|
| Purpose | Resolve and collect A/AAAA/CNAME/TXT/MX/NS in scope |
| Input | `fqdn` |
| Output | `dns.record`, `host.address`, `host.hostname` |
| Prerequisites | Domain or hostname target |
| Risk | `info` |
| Cost | 0.2 |
| Modes | all |
| Timeout | default 30, max 60 |
| Restrictions | Do not query names out of scope; drop out-of-scope answers as `out_of_scope` observations |

### 5.6.7 `subdomain_enumeration`

| | |
|---|---|
| Purpose | Discover in-scope subdomains |
| Input | `domain_id`, `wordlist: default` (v1 fixed small list ≤ 100 names + `www,mail,dev,admin,api,staging,test,vpn`) |
| Output | `dns.subdomain` |
| Prerequisites | Domain in world; `allow_subdomains`; gap `domain.subdomains_unknown` |
| Risk | `low` |
| Cost | 0.4 |
| Modes | all |
| Timeout | default 120, max 180 |
| Restrictions | No zone-transfer attempt that writes; if AXFR offered, record Finding `dns` only — **do not** dump full out-of-scope records into follow-up actions |

### 5.6.8 `directory_enumeration`

| | |
|---|---|
| Purpose | Discover paths on an HTTP service |
| Input | `url_id` (base), `wordlist: small` (v1 ≤ 50 entries: `admin,login,robots.txt,sitemap.xml,.git,backup,api,uploads,images,css,js,server-status`) |
| Output | `url.seen`, `http.status` |
| Prerequisites | `http_probe` completed; gap `service.directories_unknown` |
| Risk | `medium` |
| Cost | 0.6 |
| Modes | all; assessment: require status still RUNNING and rate 1 req / 200ms in adapter |
| Timeout | default 120, max 180 |
| Restrictions | Stop if wildcard 200 detected (`wildcard_detected`); no recursive deep busting in v1 (depth=1) |

### 5.6.9 `endpoint_discovery`

| | |
|---|---|
| Purpose | Extract links/forms/parameters from probed pages |
| Input | `url_id` |
| Output | `endpoint.seen`, `param.seen`, `auth.seen`, `url.seen` |
| Prerequisites | Body artifact from `http_probe` or directory hit with content-type html |
| Risk | `info` |
| Cost | 0.3 |
| Modes | all |
| Timeout | default 30, max 60 |
| Restrictions | Only parse stored artifacts; no extra crawling beyond same-host in-scope links, cap 25 new URLs per run |

---

# 6. Recon Architecture

Domain never imports tool libraries. Adapters live in `cyberx.recon`.

## 6.1 Adapter interface

```python
class ExecutionContext(BaseModel):
    mission_id: str
    action_id: str
    workdir: Path          # mission artifact dir
    timeout_s: int
    rate_limit_hz: float | None
    scope_digest: str      # for logging, not mutation

class RawArtifact(BaseModel):
    artifact_id: str
    tool_run_id: str
    adapter_name: str
    media_type: str        # text/plain, application/xml, application/json
    path: Path             # on disk
    sha256: str
    byte_size: int         # hard cap 5_000_000; truncated flag
    truncated: bool
    stdout_path: Path | None
    stderr_path: Path | None

class ToolAdapter(Protocol):
    name: str
    action_types: tuple[str, ...]
    def is_available(self) -> bool: ...
    def build_argv(self, action: Action) -> list[str]: ...
    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact: ...
```

`run` must:

- return `ActionResult.status=unavailable` path by raising `AdapterUnavailable` if binary missing (Engine maps this; **does not fail mission**)
- enforce timeout
- write files under `workdir/artifacts/{tool_run_id}/`
- never use `shell=True`
- never follow out-of-scope redirects / scan out-of-scope IPs (pre-filter argv targets using ScopeChecker results already applied; double-check host argument)

## 6.2 Executor

`ActionExecutor.execute(action, ctx)`:

1. Load adapter by `ActionSpec.adapter_name`
2. `build_argv` → persist on ToolRun
3. `run`
4. Return RawArtifact + exit metadata

## 6.3 Per-adapter contracts

| Adapter | Binary (preferred) | Input | Output file | Timeout | Error behavior | Parser |
|---|---|---|---|---|---|---|
| `nmap_adapter` | `nmap` | hosts/cidr, ports, profile | `scan.xml` | from action | non-zero → failed unless xml partial parseable | `NmapXmlParser` |
| `http_adapter` | stdlib/`httpx` | url, method GET/HEAD | `response.meta.json` + `body.bin` (cap 512KiB) | from action | connect fail → failed | `HttpProbeParser` |
| `dns_adapter` | `dns.resolver` or `dig` | fqdn, record types | `dns.json` | from action | NXDOMAIN is **completed** with empty records | `DnsParser` |
| `subdomain_adapter` | dns + wordlist | domain | `subs.json` | from action | each miss is normal | `SubdomainParser` |
| `directory_adapter` | httpx | base url + wordlist | `paths.json` | from action | wildcard abort | `DirectoryParser` |
| `tech_adapter` | http headers/body already fetched **or** one GET | url | `tech.json` | from action | reuse artifact if present | `TechParser` |
| `endpoint_adapter` | HTML parser (stdlib/html.parser) | artifact body | `endpoints.json` | from action | non-HTML → completed empty | `EndpointParser` |
| `stub_adapter` | none | any | synthetic fixture | 0 | always available in tests / `--stub` | matching parser on fixtures |

v1 HTTP stack: **httpx** (or stdlib if httpx not desired — implementers pick **one** and stay). Nmap is optional at runtime.

## 6.4 Stub mode

If binary missing: action `unavailable`, TimelineEvent `error` at info, Planner will pick another action. `--stub` uses fixtures so E2E works without nmap.

## 6.5 Raw output handling

- Store on disk, hash, size
- Truncate > 5MB
- Redact secret-shaped lines before any copy into DB/timeline/AI (`Redactor`)
- DB holds path + hash + size, not full blob

---

# 7. Evidence Pipeline

```text
Tool Output
  → RawArtifact (disk)
  → Parser.parse(artifact) → Observation[]
  → EvidenceFactory.wrap(observation) → Evidence[]
  → CorrelationEngine.correlate(evidence, world) → BoundEvidence[]
  → WorldProjector.project(bound) → WorldDelta[]
  → WorldModel.apply
  → FindingFactory.maybe_emit
  → GapDetector.recompute
```

## 7.1 Parser interface

```python
class EvidenceParser(Protocol):
    parser_id: str
    produces: tuple[str, ...]
    def parse(self, artifact: RawArtifact) -> list[Observation]: ...
```

Parsers are pure: no I/O except reading the artifact path; no network; deterministic given bytes.

## 7.2 Traceability

Every Claim stores `evidence_ids`. Every Evidence stores `observation_id`, `artifact_id`, `tool_run_id`, `parser_id`. Every ToolRun stores `action_id`. Every Action stores `decision_id`.  

Trace: `Claim → Evidence → Observation → Artifact → ToolRun → Action → Decision → BrainContext revision`.

UI “why is this port open?” walks that chain.

## 7.3 Correlation

`CorrelationEngine`:

- map `subject_hint` to canonical_key
- get_or_create Asset
- mark `out_of_scope` via ScopeChecker without creating follow-up gaps for those assets
- drop unmapped predicates to `unmapped_observations` table (still persisted)

## 7.4 World deltas

`WorldDelta` kinds: `upsert_asset`, `upsert_claim`, `invalidate_claim`, `close_gap`, `open_gap`, `coverage_add`

Apply is transactional in-memory then persisted.

---

# 8. Brain Architecture

Brain **does not** execute tools, write World Model facts, or touch Scope.

## 8.1 Components

| Component | Package | Responsibility |
|---|---|---|
| `Brain` | `brain.facade` | `decide(context) -> Decision` |
| `BrainContextBuilder` | `brain.context` | snapshot → BrainContext |
| `HypothesisEngine` | `brain.hypotheses` | create/update/retire hypotheses |
| `ValidationEngine` | `validation.engine` | recon findings → safe ValidationCandidate[] (does not execute) |
| `GraphProjector` | `graph.projector` | WorldSnapshot → GraphSnapshot (does not write World Model) |
| `PathPlanner` | `graph.paths` | GraphSnapshot → InvestigationPath[] (catalog actions only) |
| `Planner` | `brain.planner` | gaps + catalog + validation candidates + investigation paths → CandidateAction[] |
| `NetworkResolver` | `network.resolver` | target → NetworkContext (read-only; not authorization) |
| `ActionScorer` | `brain.scorer` | scores |
| `DecisionEngine` | `brain.decision` | pick top legal candidate or STOP |
| `CorrelationEngine` | `world.correlation` | **not** inside Brain; Brain only reads results |

Optional: `IntelligenceProvider` is called from Brain **after** deterministic hypothesis revision and **after** deterministic scoring. Grok is advisory. Planner/Scorer remain authoritative.

## 8.2 Interfaces

```python
class Brain(Protocol):
    def decide(self, ctx: BrainContext, catalog: ActionCatalogView) -> Decision: ...

class Planner(Protocol):
    def propose(self, ctx: BrainContext, catalog: ActionCatalogView) -> list[CandidateAction]: ...

class ActionScorer(Protocol):
    def score(self, candidates: list[CandidateAction], ctx: BrainContext) -> list[ScoredAction]: ...

class HypothesisEngine(Protocol):
    def revise(self, ctx: BrainContext) -> list[HypothesisDelta]: ...

class DecisionEngine(Protocol):
    def select(self, scored: list[ScoredAction], ctx: BrainContext) -> Decision: ...
```

`Decision` fields: `decision_id`, `kind` (`act`\|`stop`), `action?`, `rejected: list[{action_type, coverage_key, reason}]`, `rationale: str`, `scores: list`, `context_revision`, `created_at`

Rationale is deterministic template, e.g.  
`gap=host.ports_unknown host=10.10.11.23 score=0.72 gain=0.8 novelty=1.0`

## 8.3 Cycle position

Engine order per iteration:

1. Snapshot world (after network observe + validation evaluate/sync)
2. `ValidationEngine.evaluate` → candidates (no execution)
3. `GraphProjector.project` → GraphSnapshot; `PathPlanner.plan` → InvestigationPath[] (inside BrainContextBuilder)
4. Build **one** BrainContext (includes top findings + validation candidates + compact paths / graph focus + compact network + target identity)
5. `HypothesisEngine.revise` (persist hypotheses onto World Model for the **next** cycle; **no claims**; do not rebuild this cycle's BrainContext)
6. `Planner.propose` (existing catalog actions only, including mapped validation follow-ups and path follow-ups; IP-gated recon is suppressed on `ROUTE_MISSING` / `UNREACHABLE` / `BLOCKED`; historical locators are not action targets)
7. Candidate merge by `coverage_key` (one executable candidate; merged reasons; highest gain; `ActionScorer` remains the scoring authority)
8. `ActionScorer.score` (heuristics, then optional AI advice merge)
9. `DecisionEngine.select`
10. Return to Engine (catalog/policy/execute happen **outside** Brain)

## 8.4 AI inside Brain

If provider ≠ `none` and the provider is available:

- Call Grok only when the decision is non-trivial (not first-cycle IP + `ports_unknown` only). Typical triggers: similarly ranked actions, remaining gaps after discovery, investigation paths, or correlated findings.
- `hypothesize(ctx)` → validate `HypothesisDraft` schema → Brain may accept with `source=ai`. **AI hypothesis confidence is capped at 0.4.** This is an epistemic safety boundary, not a scoring knob: AI proposals are advisory and must not become high-confidence facts without later **non-AI** evidence. Claims may later exceed 0.4 through normal `apply_supporting` updates. AI hypotheses cannot be promoted without that later non-AI evidence.
- `advise_scores(candidates, ctx)` → map by existing `coverage_key` only; additive delta in `[-0.1, +0.1]`; cannot revive rejected types; cannot create candidates.
- Timeout default 8s; max 20 calls/mission and 2/cycle; identical fingerprints are not re-sent.
- On timeout / 429 / invalid JSON / invalid schema / missing credentials / budget exhaustion: discard Grok output and continue with deterministic Brain. **Never stop recon because AI failed.**
- TimelineEvent `ai` plus DomainEvents `ai.requested` / `ai.completed` / `ai.failed` / `ai.rejected` / `ai.fallback`. Events carry mission_id, task_type, provider, model, latency, validation — never API keys or full prompts.

---

# 9. Adaptive Loop

Owned by `MissionEngine` in `cyberx.engine.loop`.

## 9.1 Cycle

```text
while mission.status == RUNNING:
    1. CHECK pause/stop flags; CHECK iteration/runtime budgets
    2. OBSERVE NETWORK: NetworkResolver.resolve(target) (read-only; not World Model)
    3. UPDATE GAPS: GapDetector.recompute (cheap if revision unchanged skip)
    4. VALIDATE QUESTIONS: ValidationEngine.evaluate (no execution)
    5. SNAPSHOT WorldModel (one coherent snapshot for this decision phase)
    6. PROJECT GRAPH + BUILD BrainContext (once)
    7. REASON: HypothesisEngine.revise → persist hyps for next cycle
    8. PLAN: Planner (dedup by coverage_key) → Scorer → DecisionEngine
       using the same BrainContext (no second build from partial state)
    9. IF decision.kind == stop: COMPLETED (no_actions or objectives_met)
   10. CATALOG/POLICY: catalog + pydantic params + unknown deny
   11. SCOPE CHECK + policy allowlist + rate limit
   12. EXECUTE: adapter
   13. OBSERVE RESULT: verify artifact integrity → parse → evidence → correlate → apply world
   14. COVERAGE: add coverage_key
   15. TIMELINE + persist (SQLite transaction: world snapshot + runtime)
   16. iteration += 1
   17. RE-PLAN (loop)
```

## 9.2 Limits (defaults)

| Knob | Default | Prevents |
|---|---|---|
| `max_iterations` | 50 | infinite loop |
| `max_runtime_s` | 3600 | runaway |
| `min_action_score` | 0.15 | low-value thrash |
| `max_attempts` per coverage_key | 2 | retry storms |
| `max_consecutive_action_failures` | 5 | then STOPPED/FAILED? → **COMPLETED** with `stop_reason=too_many_failures` (not FAILED) |
| `progress_stall_cycles` | 3 | if revision and evidence count unchanged 3 cycles → stop `stalled` |
| `concurrency` | 1 | overlapping mutation |

## 9.3 Dedup

Skip candidate if coverage_key in `{COMPLETED, RUNNING, DENIED, REJECTED}` or `FAILED` / `UNAVAILABLE` after retries are exhausted.

A failed attempt is **not** completed coverage. First retryable failure is stored as `attempted` and may be proposed again (max 2 attempts per coverage_key). Non-retryable failures and exhausted retries are `failed` and are skipped.

If planner, path, and validation sources propose the same executable `coverage_key`, the final candidate set contains **one** executable candidate: merged reasons, preserved source metadata (`planner` / `path` / `validation`), highest valid expected information gain. `ActionScorer` remains the only scorer.

New host/url from evidence creates **new** coverage keys → allows follow-up. That is intended adaptivity.

Historical / obsolete locators are never active action targets. Current locator may be targeted. New locators require operator confirmation. Out-of-scope locators are denied. AI cannot retarget.

TIMEOUT reachability is transient and is not persisted as a World Model fact.

## 9.4 Pause handling

Flag `pause_requested` checked at step 1 and after step 12. In-flight ToolRun: cooperative timeout kill if pause wait > 2s after request — still parse partial.

## 9.5 Preventing infinite loops

1. Coverage keys
2. Stall detector
3. Iteration/runtime caps
4. Planner must not propose directory_enum more than once per `url_id` unless wildcard was false and new base path discovered (new url_id)
5. Blacklist coverage_key after 2 proposals denied for same reason
6. Unit test: fixture world with all gaps closed ⇒ Decision `stop` on first cycle

---

# 10. Storage Architecture

SQLite v1 (SQLAlchemy 2). Path: `data/cyberx.db`. Artifacts: `data/missions/{mission_id}/`.

## 10.1 Four stores

| Store | Contents | Retention |
|---|---|---|
| 1 Structured DB | missions, scope, assets, claims, gaps, hypotheses, findings, actions, results, evidence metadata, snapshots | forever for the mission |
| 2 Raw artifacts | files on disk, hashed | forever; not copied into logs |
| 3 Audit/timeline | `timeline_events`, `decision_traces`, `policy_decisions` | append-only |
| 4 Secrets metadata | `secret_refs(id, kind, location_hint, sha256, created_at)` — **no secret values** | forever; values discarded at redaction |

## 10.2 History vs world

- Evidence, observations, timeline, actions: insert-only
- Claims: updated in place **plus** `claim_history` row per change (`old_status`, `new_status`, `evidence_id`)
- World snapshot every cycle (can prune to last 5 + every 10th in a later patch; v1 keep all ≤ max_iterations)

## 10.3 Secrets

Redactor runs on parser input and argv display. Patterns: password/token/jwt/pem/htpasswd. Timeline and BrainContext never receive raw matches. If a tool prints a secret, store `SecretRef` only.

## 10.4 Repositories (ports)

`MissionRepo`, `EvidenceRepo`, `WorldRepo`, `ActionRepo`, `ArtifactStore`, `AuditRepo`, `EnginePersistence`

Application code depends on these Protocols. `storage.sqlite` implements them. `EnginePersistence` is the capability set MissionEngine requires when a store is attached (world snapshot, runtime, actions, artifacts, evidence, timeline, decision traces). In-memory missions pass `None`. Duck-typing (`hasattr` / `store_has`) is forbidden in the engine.

Event history uses `EventSink.emit` plus `EventReader.iter_recent` / `emitted_count` (`EventLog`). The engine must not read `InMemoryEventSink.events` internals.

Artifacts are integrity-checked (sha256, size bound, missing/truncated file) before parse. Corruption fails closed and does not create World Model facts. Evidence/history remains the source of truth; World Model and graph are rebuildable projections.

Interrupted persist is recovered by replaying evidence. Meaningful crash boundaries:

- **A** before action persistence — resume has history empty; world rebuilds from existing evidence only
- **B** after action persistence — actions exist; world does not invent facts from an action row
- **C** after result persistence — results exist; world still requires evidence
- **D** after evidence persistence — missing snapshot → `rebuild_from_evidence`
- **E** after World Model snapshot — hydrate snapshot, then apply tail evidence
- **F** after decision trace — traces are append-only audit; they are not required to rebuild the world

Action + tool_run + result are written in one SQLite transaction. Evidence (artifact + observations + evidence) is a separate transaction. Snapshot + runtime is a third. Timeline and decision traces are append-only. Duck-typing (`hasattr` / `store_has`) is forbidden in the engine.

---

# 11. AI Provider Architecture

Grok is an optional advisory plugin. The deterministic Brain remains the planner. Policy, catalog, and scope remain hard gates. Evidence remains the only writer of World Model facts.

## 11.1 Protocol

```python
class HypothesisDraft(BaseModel):
    statement: str
    rationale: str
    related_canonical_keys: list[str] = []
    suggested_action_types: list[str] = []  # must ⊆ catalog
    confidence: float = 0.2
    evidence_ids: list[str] = []  # must be empty in v1 (BrainContext has no evidence ids)

class ScoreAdvice(BaseModel):
    coverage_key: str
    delta: float  # [-0.1, 0.1]
    comment: str = ""

class IntelligenceProvider(Protocol):
    name: str
    def hypothesize(self, ctx: BrainContext) -> list[HypothesisDraft]: ...
    def advise_scores(self, candidates: list[CandidateAction], ctx: BrainContext) -> list[ScoreAdvice]: ...
    def explain_finding(self, finding: Finding, ctx: BrainContext) -> str: ...
    def draft_report_section(self, report: ReportModel) -> str: ...
```

Registered names: `none`, `grok`, `gemini`, `claude`, `openai`, `deepseek`, `local`, `custom`.

v1 implemented providers: `none` (default), `grok` (advisory). Other names are reserved and do not change Brain contracts.

## 11.2 Validation

Every Grok response must pass transport, JSON, schema, allowed-value, coverage, range, evidence-reference, and policy checks.

- Pydantic parse; on error return empty list
- `suggested_action_types` filtered to the closed v1 catalog; forbidden markers (`exploit`, `validate`, `privesc`, `persist`, `shell`) drop the draft
- `related_canonical_keys` must exist in ctx or the draft is dropped
- Non-empty `evidence_ids` are treated as invalid evidence references and dropped (AI cannot mint evidence)
- `|delta| > 0.1` is **rejected** (not applied). Applied deltas are also clamped to `[-0.1, +0.1]`
- Unknown `coverage_key` is dropped. Grok cannot create candidates or action types
- `explain_finding` / report prose is **display only**, never parsed as commands, never written as facts
- Max 8 drafts per cycle
- Invalid output: discard, emit `ai.rejected` / `ai.failed`, continue deterministic Brain

## 11.3 Failure / fallback

If Grok times out, rate-limits (429), returns invalid JSON/schema, is unavailable, is disabled, has missing credentials, or exhausts budget:

- emit `ai.failed` and `ai.fallback`
- use deterministic Brain heuristics
- **Never stop recon solely because AI is unavailable**

Default remains `none`. Credentials come from `CYBERX_AI_API_KEY` or `XAI_API_KEY`. Keys are never stored in the database, never logged, never placed in prompts, and never hardcoded.

## 11.4 Isolation

- Implementations in `cyberx.ai.providers.*` (`GrokProvider` in `cyberx.ai.providers.grok`)
- Brain depends on `IntelligenceProvider` only (plus `NoneProvider` default)
- Engine and TUI must not import `cyberx.ai.providers`
- Provider receives BrainContext (already compact, ≤32KiB) plus optional candidate coverage keys / one finding
- No DB session, repository, ToolAdapter, executor, subprocess, mutable Scope, credentials, or raw artifacts
- No function-calling tools except returning the schemas above
- Transport is injectable (`urllib` in production). Tests use a mocked transport and do not require a live key

## 11.5 Prompt construction and injection defense

A deterministic serializer builds the user payload from BrainContext only (mission intent, assets, findings, hypotheses, graph/path summary, validation candidates, compact network, gaps, recent results, existing coverage keys).

- Deterministic JSON key order
- Redactor runs before send (JWT/PEM/secret-shaped keys)
- Hard cap 32KiB
- System policy is separate from untrusted target data
- All target-derived text is wrapped in `<untrusted_target_data>` and must never override CyberX policy
- Compact network only (`interface`, `route`, `reachability`, `tunnel=detected_unverified`) — no VPN client identity

## 11.6 Budget, cache, observability

| Knob | Default |
|---|---|
| timeout | 8s |
| max calls / mission | 20 |
| max calls / cycle | 2 |
| max prompt | 32KiB |
| max response | 8KiB |
| max output tokens | 800 |
| reasoning | `low` (config only; not required by the transport) |

Request fingerprint = sha256(provider \| model \| task \| prompt). Cache hits do not consume an additional provider call.

Do not call Grok after every trivial port discovery. Call when actions are close, hypotheses/gaps are informative, or paths/findings exist.

## 11.7 Prohibited AI capabilities

Grok must never: execute tools, create action types, change scope, write Evidence, write Findings as facts, invent hosts/ports, bypass catalog/policy, invent exploits, request a shell, or expand scope.

Score advice cannot override novelty hard-zero, readiness hard-zero, policy, scope, risk, or the catalog.

## 11.8 Operator console

Compact dashboard line:

```text
AI: GROK
Status: AVAILABLE
Calls: 3 / 20
```

or:

```text
AI: DISABLED
Reason: provider not configured
```

Operator may choose `none` or `grok`. Default is `none`. Grok remains advisory; the deterministic Brain still plans.

---

# 12. Operator Console

v1 primary UI is a **TUI**, process entry `python main.py` (setuptools entry `cyberx`).

UI package `cyberx.tui` may import `engine`, `mission.service`, repositories. It may **not** import `recon.*` adapters, parsers, or `ai.providers` implementations (only provider **names**).

## 12.1 Startup flow

```text
python main.py
  1. Prompt target
  2. Prompt mission name + intent
  3. Prompt mode: ctf | lab | authorized_assessment
  4. Prompt AI provider: none | grok | ...
  5. Show derived Scope; operator may edit allow/exclude/ports
  6. Confirm → CONFIRMED
  7. Key: [s]tart [q]uit
```

## 12.2 Running view (single screen, refresh each cycle)

Panels:

- Header: mission name, status, iteration, elapsed, provider
- Scope summary (read-only after confirm)
- Current action: type, target, reason, score
- Known assets: hosts / ports / services counts + last 8 lines
- Findings: last 5 titles
- Hypotheses: open list (mark `HYPOTHESIS`, never as fact)
- Recent events: last 8 timeline messages
- Progress: gaps closed / remaining, bar

## 12.3 Controls

| Key | Command |
|---|---|
| `s` | start |
| `p` | pause |
| `r` | resume |
| `x` | stop (confirm) |
| `f` | findings page |
| `i` | investigations page |
| `g` | attack-surface graph (compact tree) |
| `n` | network context (interfaces/route/reachability; unverified tunnel label) |
| `w` | world model page (assets + claims + status) |
| `h` | hypotheses page |
| `l` | logs/timeline page |
| `t` | target identity + locator confirm (operator only) |
| `c` | run one cycle |
| `o` | report preview/export |
| `q` | quit (if RUNNING, equivalent to pause then quit) |

## 12.4 Rules

- Status colors: facts vs `hypothesis` vs `unknown` gaps must be visually distinct
- Do not show raw nmap XML in the main view
- Export report to `data/missions/{id}/report.json` + `.md`

---

# 13. Reporting

`ReportBuilder.build(mission_id) -> ReportModel` then render JSON and Markdown.

## 13.1 ReportModel sections (required, this order)

1. `mission` — id, name, intent, mode, status, stop_reason, dates, iteration
2. `target` — raw + normalized
3. `scope` — frozen snapshot
4. `assets` — counts + list
5. `hosts`
6. `services` (join ports)
7. `technologies`
8. `urls`
9. `endpoints`
10. `findings` — facts only at ≥ `SUPPORTED`
11. `hypotheses` — clearly labeled **HYPOTHESIS / NOT CONFIRMED**
12. `evidence` — index id, parser, tool, reliability, claim_preview
13. `actions_performed` — type, target, status, timestamps
14. `timeline`
15. `unresolved_knowledge_gaps`
16. `recommended_next_investigation` — from remaining gaps + open hypotheses (**investigation**, not exploit steps)

v1 CTF edition also includes (after `target`, before `assets`): target identity, current locator, locator history, network context summary; plus domains, subdomains, ports, validation candidates, investigation paths, and invalidated claims. Reports remain investigation-only.

## 13.2 Labeling rules

- CONFIRMED/KNOWN/SUPPORTED claims: “Fact (status=…)”
- SUSPECTED: “Unconfirmed”
- Hypotheses: never mixed into findings list
- UNKNOWN gaps: “Unknown”
- INVALIDATED: appendix “Invalidated claims”
- AI prose appendix optional; cannot replace structured sections

---

# 14. Package Structure

```text
src/cyberx/
  domain/              # entities, enums, identity, errors
  mission/             # service, state machine
  scope/               # checker (or mission/scope)
  world/               # model, snapshot, projector, correlation, gaps
  evidence/            # pipeline, parsers/, redactor, factory
  actions/             # catalog, specs/, validator, coverage
  policy/              # engine, allowlist, rate_limit
  brain/               # facade, context, planner, scorer, decision, hypotheses
  validation/          # candidates, engine, rules, mappings, status (no execute)
  graph/               # projector, queries, paths, tree (projection only; no execute)
  network/             # read-only local routing/interface observation (not a VPN client)
  engine/              # loop, cycle
  recon/               # adapters only
  ai/                  # protocol, schemas, providers/, none.py
  storage/             # models, repos, sqlite, artifact_fs
  reporting/           # builder, markdown, json
  tui/                 # textual/rich screens
  observability/       # timeline helpers
  config.py
  main.py              # or cli.py + main.py at repo root
tests/
  unit/
  contract/
  fixtures/
  integration/
  e2e/
```

## 14.1 Dependency rules

| Package | May import | Must not import |
|---|---|---|
| `domain` | stdlib, pydantic | everything else in cyberx |
| `mission` | domain, storage **protocols** | recon, ai providers, tui, brain |
| `world` | domain | recon, ai, tui, engine, graph |
| `evidence` | domain, world protocols | recon adapters, tui, ai |
| `evidence.parsers` | domain, artifact types | recon, brain, tui |
| `actions` | domain | recon, ai, tui |
| `policy` | domain, scope checker | recon, ai, tui, brain |
| `brain` | domain, actions catalog view, ai **protocol**, validation, graph (read) | recon, storage engines, tui, engine |
| `validation` | domain, actions catalog/coverage, world (read) | recon, engine, tui, ai, storage |
| `graph` | domain, world (read), validation (read), actions types | recon, engine, tui, ai, storage, brain |
| `engine` | mission, world, brain, policy, actions, evidence, validation, graph (read), storage protocols, recon **executor protocol** | tui, ai providers |
| `recon` | domain action types, policy ScopeSubject optional | brain, tui, world internals |
| `ai.providers` | ai.protocol, schemas | engine, recon, storage, world |
| `storage` | domain | brain, tui, recon |
| `reporting` | domain, storage protocols | recon, brain internals, tui |
| `tui` | mission service, engine API, reporting, storage repos | recon, parsers, ai providers |
| `observability` | domain | recon, ai |

**No circular imports.** Engine is the hub. Tests that import across layers are allowed.

Forbidden globally: `subprocess` with `shell=True`; `eval`; dynamic `import` of unregistered adapters.

---

# 15. Interfaces & Contracts

Implement these Protocols/Pydantic models before adapters.

## 15.1 MissionService

```python
class MissionService(Protocol):
    def create(self, cmd: CreateMissionCmd) -> Mission: ...
    def confirm(self, mission_id: str) -> Mission: ...
    def start(self, mission_id: str) -> None: ...
    def pause(self, mission_id: str) -> None: ...
    def resume(self, mission_id: str) -> None: ...
    def stop(self, mission_id: str, reason: StopReason) -> None: ...
    def get(self, mission_id: str) -> Mission: ...
```

## 15.2 PolicyEngine

```python
class PolicyEngine(Protocol):
    def authorize(self, action: Action, mission: Mission, scope: Scope) -> PolicyDecision: ...
```

Always deny if `action_type` not in v1 catalog or kind would be `exploit`/`validate`.

## 15.3 WorldModel

```python
class WorldModel(Protocol):
    def snapshot(self) -> WorldSnapshot: ...
    def apply(self, deltas: list[WorldDelta]) -> int: ...  # returns revision
    def get_gaps(self) -> list[KnowledgeGap]: ...
```

## 15.4 Engine

```python
class MissionEngine(Protocol):
    def run_forever(self, mission_id: str) -> None: ...  # until terminal status
    def run_one_cycle(self, mission_id: str) -> CycleReport: ...
```

## 15.5 Catalog

`ActionCatalog.get(action_type) -> ActionSpec | None`  
`ActionCatalog.all() -> list[ActionSpec]`  
Unknown → None → validator REJECTED.

## 15.6 Scoring contract

See §8 ActionScorer. Formula in Implementation notes below (also §19 uses it). **This is mandatory v1:**

All inputs in `[0,1]`:

```
mission_relevance      # 1 if action produces predicates closing an open gap matching default objectives
information_gain       # spec-defined base gain × (1 if gap open else 0.1)
evidence_strength      # 1 if prerequisites claims ≥ KNOWN else 0
p_useful               # 0.7 default; 0.3 if last similar action on sibling asset failed
novelty                # 1 if coverage_key unseen else 0
dependency_readiness   # 1 if prereqs met else 0  (0 ⇒ Planner should not emit; Scorer forces 0)
cost                   # from spec
risk                   # info=0.1, low=0.3, medium=0.6
```

```
score = (
    0.25 * mission_relevance +
    0.25 * information_gain +
    0.10 * evidence_strength +
    0.10 * p_useful +
    0.10 * novelty +
    0.10 * dependency_readiness +
    0.05 * (1 - cost) +
    0.05 * (1 - risk)
)
```

Optional AI: `score = clamp(score + delta, 0, 1)` with `|delta|≤0.1`.

If `dependency_readiness==0` or `novelty==0`: `score=0` (hard).

Tie-break: lower risk, lower cost, catalog registration order.

DecisionEngine picks max score among `score ≥ min_action_score`. Else `kind=stop`.

---

# 16. Testing Strategy

Tools must **not** be required to run the test suite.

| Layer | What | How |
|---|---|---|
| Unit | identity keys, scope checker, state machine, scoring formula, confidence update, redactor | no I/O |
| Contract | each Protocol dummy satisfies methods; catalog every action_type has spec+parser+adapter name | |
| Parser fixtures | committed XML/JSON/HTML under `tests/fixtures/` | bytes → Observation exact equals golden |
| World Model | merge two hosts, conflict invalidation, gap close, snapshot replay | |
| Brain | given fixture BrainContext, expected action_type (golden) | stub provider |
| Action validation | unknown type denied; bad params rejected; exploit type denied | |
| Mission lifecycle | illegal transitions raise; confirm freezes scope | |
| Mocked tools | stub adapter returns fixture artifact | |
| Integration | engine 3 cycles with stubs: cycle2 action ≠ cycle1; world grows | tmp sqlite |
| E2E | `run_one_cycle` × N CLI/TUI headless (`CYBERX_STUB=1`) | no nmap |
| Optional live | mark `@pytest.mark.requires_nmap` skipped by default | |

**Golden Brain tests (minimum):**

1. Only unresolved hostname → `dns_enumeration` or `network_discovery` not dir enum
2. Host alive, ports unknown → `port_scan`
3. Port 80 open, no http_probe → `http_probe` not subdomain
4. HTTP probed, directories unknown → `directory_enumeration` **or** `technology_detection` (score decides; assert not `port_scan` again)
5. All gaps closed → `Decision.kind==stop`

Coverage target: domain/policy/brain/engine ≥ 80% lines in tests.

---

# 17. V2 / V3 / V4 Extension Points

Do not implement. Keep stable:

| Hook | v2 Validation & Attack Planning | v3 Controlled Exploitation | v4 Adaptive Pentest Agent |
|---|---|---|---|
| `ActionKind` / catalog | add `validate.*` specs | add `exploit.*` | add chaining meta-actions |
| `ValidationEngine` / `ValidationRule` | protocol-specific + vuln validation behind the same interface | still no engine execute | |
| `PolicyProfile` | new profile `validate_lab` | `exploit_lab` + operator approval | risk budgets |
| `Planner` protocol | attack-graph view of claims | exploit candidate gen | learned planner impl |
| `GraphProjector` / `PathPlanner` | exploit/attack paths remain v2+; v1 paths are investigation-only | session/foothold nodes | |
| `WorldProjector` | vuln/CVE mapping claims | session/foothold nodes | multi-host graph |
| `IntelligenceProvider` | same schemas + optional `plan_advice` | still no shell | still no shell |
| `MissionEngine` loop | unchanged | insert approval wait state | parallel actions maybe |
| Findings severity | may add `high` when **validated** | exploit proofs | |
| TUI | extra pages | approval modal | |

v1 Policy **hard-denies** `action_type` containing `exploit`, `validate`, `privesc`, `persist`, `shell`.

v1 `ValidationEngine` is recon-adjacent only: it asks safe questions and maps them onto the existing closed catalog. It must not grow a generic `validate` action. v2 adds capabilities behind `ValidationRule` / catalog specs rather than rewriting M14.

v1 `GraphProjector` / `PathPlanner` produce an attack-**surface** graph and investigation paths. They must not grow exploit/session/payload nodes or non-catalog actions. v2 may add an attack-graph view of claims behind the same projection interface.

---

# 18. Architectural Risks

| Risk | Mitigation |
|---|---|
| AI overreach | No execute path; schema validation; delta cap; `none` default; AI cannot write repos |
| Scope bypass | Frozen scope; checker on every action; adapters cannot add targets; out-of-scope assets flagged and not planned |
| Arbitrary command execution | Catalog only; argv list; unknown type REJECTED; no AI argv |
| Circular dependencies | Layer table §14.1; engine is hub; CI import-linter (`import-linter` contract) |
| Giant classes | Brain split into 5 modules; Engine cycle steps as functions; parsers one file each |
| Giant files | Soft cap 400 lines/module; catalog specs one module per action_type |
| State corruption | Single mutex per mission; concurrency=1; snapshot+replay; insert-only evidence |
| Duplicate entities | Canonical keys + get_or_create under lock |
| Infinite planner loops | coverage_key, stall detector, budgets, novelty hard-zero |
| Coupling to one AI provider | Protocol + registry; tests use `none` |
| Coupling to one tool | Adapter protocol; stub adapter; httpx and nmap independently skippable |
| Facts without evidence | Projector rejects claims with empty evidence_ids; unit test |
| Hypothesis as fact | Separate tables; report labeling; promotion rules |
| Prompt injection from tool output | BrainContext only; redaction; no command parse of LLM text |
| Secret leakage | Redactor; SecretRef; artifact not in timeline |
| Pause ignored | Cycle-boundary flags + process kill |
| Assessment against unauthorized net | mode defaults; confirm step; CIDR size cap |

---

# 19. Implementation Order

Do not skip. Each milestone has a test gate.

| M | Deliverable | Gate |
|---|---|---|
| M0 | `domain` models + enums + identity | import, model validation tests |
| M1 | Mission state machine + ScopeChecker | illegal transition tests; target in/out of scope |
| M2 | PolicyEngine + catalog registry with 9 specs (no adapters) | unknown/exploit denied |
| M3 | ActionValidator + coverage_key | param schema tests |
| M4 | Stub adapter + Executor | argv is `list[str]` |
| M5 | Parsers + fixtures for nmap xml, http json, dns json | golden observations |
| M6 | Evidence pipeline + Correlation + WorldModel | merge/conflict/gap tests |
| M7 | SQLite repos + snapshot replay | kill/reopen equality |
| M8 | Heuristic Brain + MissionEngine `run_one_cycle` | cycle2 ≠ cycle1 on stub world |
| M9 | `main.py` TUI/CLI stub mode | create, start, 5 cycles, dump world json |
| M10 | Real http + dns adapters | skip if no net; still policy gated |
| M11 | nmap adapter optional | `@requires_nmap` |
| M12 | directory/tech/endpoint adapters + wordlists | wildcard stop test |
| M13 | `IntelligenceProvider` none + one live provider | recon works if AI down |
| M14 | Report JSON/MD | facts ≠ hypotheses |
| M15 | Redactor, rate limits, audit completeness | secret not in timeline test |
| M16 | Network awareness (VPN/tunnel context, read-only) | tun0 route fixture; ROUTE_MISSING ≠ host down; no VPN client |
| M17 | Grok IntelligenceProvider (advisory, fail-closed) | mocked transport; fallback to deterministic Brain; no live key in CI |
| M18 | Target identity / locator resilience | hostname identity survives IP change; operator confirm; TIMEOUT is not a World Model fact |

v1 CTF release hardening follows M18. Do not start exploitation (v2/v3/v4).

**First runnable product:** M9.

---

## Appendix A — Closed enums (v1)

```text
MissionMode: ctf, lab, authorized_assessment
MissionStatus: CREATED, CONFIRMED, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED
StopReason: operator, no_actions, objectives_met, max_iterations, max_runtime, stalled, too_many_failures, error
EpistemicStatus: UNKNOWN, KNOWN, SUSPECTED, SUPPORTED, CONFIRMED, INVALIDATED
ActionStatus: PROPOSED, VALIDATED, QUEUED, AUTHORIZED, RUNNING, COMPLETED, FAILED, DENIED, REJECTED, CANCELLED
ValidationStatus: proposed, queued, testing, supported, inconclusive, rejected, expired
Risk: info, low, medium
TargetKind: ipv4, ipv6, cidr, hostname, domain, url
GraphNodeKind: domain, subdomain, host, interface, port, service, technology, url, endpoint, parameter, auth_surface, finding, hypothesis, validation_candidate
GraphEdgeKind: RESOLVES_TO, HOSTS, EXPOSES, RUNS, IMPLEMENTS, SERVES, CONTAINS, LINKS_TO, USES, AUTHENTICATES, SUPPORTED_BY, RELATED_TO, DERIVED_FROM, HAS_FINDING, HAS_HYPOTHESIS, HAS_VALIDATION
ReachabilityStatus: UNKNOWN, REACHABLE, UNREACHABLE, ROUTE_MISSING, BLOCKED, TIMEOUT
TimelineKind: mission_status, decision, policy, action, evidence, world, hypothesis, ai, error, operator, network
```

## Appendix B — What v1 will refuse to implement

- Any payload, exploit module, brute force, DOS
- `shell=True`, operator-supplied extra argv, AI-supplied argv
- Auto-expanding Scope
- Multi-agent debate
- Nuclei/Metasploit/SQLMap adapters
- Mutating World Model from TUI
- Storing secret values in SQLite

If a future implementer needs a behavior not in this document, they must update this spec first.
