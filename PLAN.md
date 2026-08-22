# Nexus — MISP / OpenCTI → Zeek `intel.dat` Builder for Security Onion

**Status:** phases 0–6, 8 and 9 built and tested — two IOC sources (MISP, OpenCTI), one per run, plus feed selection, plus offline build and airgapped import; phase 7 (systemd timer, install docs) is all that remains
**Target host:** Security Onion 3.2 manager node, or — for an offline build — any host with Python 3.6+ and nothing else installed
**Form:** a single Python 3 script, `nexus.py`, stdlib only — no pip, no venv, no packaging

```
nexus.py        the tool          python3 nexus.py
test_nexus.py   525 tests         python3 -m unittest test_nexus
```

**New assistant picking this up: read `HANDOFF.md` first.**

Working today: the full interview end-to-end against either platform, including apply, and unattended replay from a profile. Modes: `--check-env`, `--seed`, `--apply`, `--probe`, `--lint`, `--explain`, `--profile`, `--yes`, `--dry-run --diff`, `--offline`, `--import PATH`. `--source {misp,opencti}` and `--host` select the platform; `--misp` remains as a deprecated alias for `--host --source misp`.

---

## 1. What Nexus does

Nexus is an interactive script that runs on a Security Onion 3.2 manager, against **one IOC source per run — MISP or OpenCTI**, chosen in the interview or via `--source`. It:

1. Prompts for which platform, then that platform's address and API token.
2. Connects and *interrogates* the instance to discover what's actually there — for MISP: attribute types in use, tags, taxonomies, organisations, sharing groups, live counts; for OpenCTI: labels, marking definitions, organisations, and exact per-type indicator counts.
3. Walks the operator through a full interview: which IOC classes, which specific attribute/observable types, which tags or labels to include/exclude, what time window, what quality filters, what metadata to embed. Stages 2, 2b, 3, 4 and 5 branch by source; the rest of the interview and everything downstream of it is shared.
4. Pulls matching records — MISP via `/attributes/restSearch` (paginated), OpenCTI via `POST /graphql` (cursor-paginated), reading indicators and the observables linked to them.
5. Normalises, validates, deduplicates and maps them to Zeek Intel framework types through the same table-driven pipeline regardless of source.
6. Preserves every existing indicator, appends newly discovered IOCs from
   whichever source was queried, and atomically publishes the resulting `intel.dat`.
7. Optionally backs up, validates, and applies it out to the grid.

Interview answers can be saved as a **profile** so later runs are non-interactive (systemd timer friendly). A MISP profile and an OpenCTI profile run as two separate scheduled jobs; both converge into the same append-only `intel.dat` with no merge step of their own — see `HANDOFF.md` §5 (Decisions already made).

---

## 2. Ground truth (verified against SO 3.x docs)

### Security Onion 3.2

- Custom intel file: `/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat` on the **manager**.
- **The local intel directory may be empty on a fresh install.** Defaults live at `/opt/so/saltstack/default/salt/zeek/policy/intel/` and contain **two** files — `intel.dat` *and* `__load__.Zeek`. Both must be present locally:
  ```
  sudo cp /opt/so/saltstack/default/salt/zeek/policy/intel/* \
          /opt/so/saltstack/local/salt/zeek/policy/intel/
  ```
  Writing `intel.dat` without `__load__.Zeek` present produces a file Zeek never loads — silent, total failure. **Nexus must check for and seed this.**
- **Intel files are not picked up by Auto State Apply.** The sync is manual and mandatory:
  ```
  sudo salt -C 'I@zeek:enabled:true' state.apply zeek
  ```
- That syncs `/opt/so/saltstack/local/salt/zeek/policy/intel/` → `/opt/so/conf/zeek/policy/intel/` on each node. That destination is the runtime path to verify against.
- Format is strict: single-tab separated, **no leading/trailing spaces, no trailing blank lines**.
- Verify hits in `/nsm/zeek/logs/current/intel.log`; parse errors in `/nsm/zeek/logs/current/reporter.log`. Restart with `sudo so-zeek-restart`.

> **Changed from 2.4** — the apply command is now the `-C 'I@zeek:enabled:true'` compound target running `state.apply zeek`, not a per-minion `state.highstate`; the docs now explicitly call out the empty-local-dir / `__load__.Zeek` trap; and the `/opt/so/conf/...` runtime destination is now documented. The `local/salt/...` source path itself is unchanged.

> **Pre-flight to confirm on the actual box** (do not assume): exact 3.2.x point release, that both paths exist, the current file's owner/mode, and whether anything else already manages that file.

### Zeek Intel framework file format

```
#fields<TAB>indicator<TAB>indicator_type<TAB>meta.source<TAB>meta.desc<TAB>meta.url
```

- Single tab between fields. A field containing only `-` is a null value.
- Valid `Intel::Type` values — the complete set:
  `Intel::ADDR`, `Intel::SUBNET`, `Intel::URL`, `Intel::SOFTWARE`, `Intel::EMAIL`,
  `Intel::DOMAIN`, `Intel::USER_NAME`, `Intel::CERT_HASH`, `Intel::PUBKEY_HASH`,
  `Intel::FILE_HASH`, `Intel::FILE_NAME`
- `meta.do_notice` only works if `policy/frameworks/intel/do_notice.zeek` is loaded — opt-in, verify on the target first.

**Gotchas that silently break matching:**

| Gotcha | Handling |
|---|---|
| `__load__.Zeek` missing from the local intel dir | Detect and offer to seed from defaults |
| `Intel::URL` must have the `http://` / `https://` scheme **stripped** | Strip scheme before writing |
| `Intel::DOMAIN` matches the exact host only — no implicit subdomain matching | Note in summary; optionally emit known subdomains too |
| `Intel::CERT_HASH` is SHA-1 only | Drop `x509-fingerprint-md5` / `-sha256`, count and report |
| `Intel::PUBKEY_HASH` is colon-delimited hex MD5 | Reformat or skip |
| `Intel::FILE_HASH` only fires if Zeek file hashing is enabled for that algorithm | Warn in summary |
| Every indicator is resident in **every** Zeek worker's memory | Size guardrail (§8) |

### MISP API

- `POST /attributes/restSearch` — headers `Authorization: <token>`, `Accept: application/json`, `Content-Type: application/json`. JSON body.
- Body params used: `value`, `type`, `category`, `org`, `tags` (`OR` / `NOT` lists), `from`, `to`, `last`, `timestamp`, `publish_timestamp`, `published`, `eventid`, `uuid`, `to_ids`, `deleted`, `enforceWarninglist`, `includeEventUuid`, `includeEventTags`, `limit`, `page`, `returnFormat`.
- Discovery: `GET /servers/getVersion`, `GET /attributes/describeTypes`, `GET /tags`, `GET /organisations`, `GET /sharing_groups`.

### OpenCTI API

- Single endpoint: `POST /graphql` — header `Authorization: Bearer <token>`. Version probe, discovery, counts and the indicator search are all one query shape over this one path.
- **GraphQL answers HTTP 200 even on a rejected token.** Errors arrive as a 200 response carrying an `errors` array in the body, never a 401/403. `_check_errors` reads that array before any caller touches `data`, so an auth failure raises `SourceAuthError` instead of silently looking like an empty result set.
- Pagination is cursor-based — `first` / `after` / `pageInfo.{endCursor,hasNextPage}` — not page-numbered. A cursor that fails to advance (a proxy or endpoint ignoring `after`) stops the walk with a warning rather than looping forever.
- Filters use **OpenCTI 6.x `FilterGroup` syntax only** — nested `{mode, filters, filterGroups}` objects — not the flat 5.x filter shape. `build_opencti_filters(config)` is the pure builder, the OpenCTI counterpart to `build_search_params(config)`.
- **Filters take entity ids, not names.** Labels, marking definitions and organisations are resolved `name -> id` during discovery; a name with no discovered id is dropped with a warning rather than passed through as a guess.
- Discovery: one GraphQL query each for labels, marking definitions and organisations.
- Counts: `pageInfo.globalCount` is an exact total, permission-dependent; `count_type` falls back to a `first: 1` probe's `len(nodes)` when it's absent, which is still exact for that fallback shape (see `HANDOFF.md` §3).
- Body/entity: only **Indicators** are queried, not raw Observables — see §2 (Decisions taken) in the OpenCTI design spec, `docs/superpowers/specs/2026-08-17-opencti-source-design.md`. An indicator's linked observables (`observables(first: 50) { edges { node { ... } } }`) supply the actual IOC values; `parse_stix_pattern` is a fallback for indicators with no linked observables, and only for `pattern_type == "stix"` — YARA/Sigma pattern bodies are never mined for values.

---

## 3. Script structure

One file: `nexus.py`. Executable, `#!/usr/bin/env python3`, stdlib only (`urllib.request`, `ssl`, `json`, `ipaddress`, `getpass`, `argparse`, `os`, `tempfile`, `shutil`, `subprocess`, `datetime`, `re`, `logging`). Drops onto an air-gapped manager and runs.

Internally organised into banner-delimited sections, in dependency order so the file reads top to bottom:

```
#!/usr/bin/env python3
"""nexus.py — build a Zeek intel.dat from MISP or OpenCTI, for Security Onion 3.2."""

# ── CONSTANTS ──────────────────────────────────────────────
#   SO paths, Zeek type set, MISP→Zeek and OpenCTI→Zeek mapping tables, defaults

# ── LOGGING ────────────────────────────────────────────────
#   setup_logging(), a redacting Filter that scrubs the API token

# ── CLIENT ─────────────────────────────────────────────────
#   class _HttpTransport:  shared urllib/TLS/retry base
#   class MispClient(_HttpTransport):  get_version, describe_types,
#                      get_tags, get_orgs, get_sharing_groups,
#                      count_type, search_attributes (generator, paginated)
#   class OpenctiClient(_HttpTransport):  _graphql, _check_errors,
#                      get_version, get_labels, get_markings,
#                      get_organizations, count_type, search_indicators
#                      (cursor-paginated generator)
#   flatten_attribute(attr) → one record; flatten_indicator(node,
#   stats=None) → a *list*, one record per extracted observable value
#   (an indicator carrying both an MD5 and a SHA-256 yields two rows).
#   Both emit the same record shape (below), so everything downstream
#   of this seam is source-agnostic
#   parse_stix_pattern(pattern) — fallback for OpenCTI indicators with no
#   linked observables; only for pattern_type == "stix"

# ── FEEDS ──────────────────────────────────────────────────
#   feed_provenance(), feed_is_selectable(), apply_feed_to_params()
#   (MISP only — OpenCTI has no feed concept)

# ── MAPPING ────────────────────────────────────────────────
#   map_attribute(record, table=MISP_TO_ZEEK or OPENCTI_TO_ZEEK)
#     -> [(indicator, intel_type), ...]
#   handles composite splitting: domain|ip, ip-src|port, filename|md5
#   (OpenCTI observables carry no composite types of their own)

# ── NORMALISE / VALIDATE ───────────────────────────────────
#   norm_addr, norm_subnet, norm_domain, norm_url, norm_hash,
#   norm_email, norm_cert_hash, sanitize_meta
#   NORMALISERS = {Intel::TYPE: fn}

# ── FILTERS ────────────────────────────────────────────────
#   ExclusionSet: RFC1918, own CIDRs, own domain suffixes, allowlist file

# ── INTEL FILE ─────────────────────────────────────────────
#   header_line(), render_meta(), render_line(), build_indicators()
#   (dedup by (indicator, Intel::Type) happens inline here — there is no
#   separate dedupe function), rows_to_lines(), lint_lines(), lint_file(),
#   read_existing(), merge_additive(), backup_file(), write_atomic()

# ── ENVIRONMENT CHECK ──────────────────────────────────────
#   detect_so_version(), notice_policy_loaded(), check_env()  — stage 0

# ── GUARDRAILS ─────────────────────────────────────────────
#   check_size(), check_not_empty(), check_delta(), check_load_file(),
#   check_broad_indicators(), run_guardrails()   (§8)

# ── INTERVIEW ──────────────────────────────────────────────
#   ask(), ask_yes_no(), ask_int(), ask_choice(), ask_multi(),
#   discover() (MISP) / discover_opencti(),
#   build_search_params() (MISP) / build_opencti_filters() (OpenCTI),
#   then run_interview() -> Config, one stage per §4 heading,
#   stages 2/2b/3/4/5 branching by source

# ── PROFILES ───────────────────────────────────────────────
#   load_profile(), save_profile()   (JSON, v2 schema with a v1 reader
#   that migrates old MISP-only key names forward in memory)

# ── DIFF ───────────────────────────────────────────────────
#   indicator_delta(), summarise_delta(), unified_intel_diff()

# ── APPLY ──────────────────────────────────────────────────
#   seed_load_file(), salt_apply(), log_offset(), log_errors_since(),
#   verify_runtime(), apply_to_grid()

# ── MAIN ───────────────────────────────────────────────────
#   argparse (--source/--host/--misp), client factory picking
#   MispClient or OpenctiClient from config["source"],
#   mode dispatch, summary printing
```

**Design rules that survive the single-file form:**

- The mapping / normalise / filter / intel-file sections must not touch the network or the filesystem — pure functions over plain dicts, so they're testable by importing `nexus.py` from a test script.
- Only `write_atomic()` may write to the live intel path.
- `_HttpTransport` is the only thing that speaks HTTP; `MispClient` and `OpenctiClient` both subclass it and are the only things that call it.

Internal record shape after fetch — produced by both `flatten_attribute(attr)` (MISP, one record per attribute) and `flatten_indicator(node, stats=None)` (OpenCTI, a *list* of records — one per observable value extracted from the indicator, so a file indicator carrying an MD5 and a SHA-256 fans out to two). The shape is identical either way, so mapping, normalisation and everything after it runs unchanged regardless of source:

```python
{
  "value": str, "type": str, "category": str, "to_ids": bool,
  "uuid": str, "timestamp": int, "comment": str,
  "event_id": str, "event_uuid": str, "event_info": str,
  "event_tags": [str], "org": str,
}
```

Deploy: copy to `/usr/local/bin/nexus`, `chmod 750`, root-owned. Working state (profiles, backups, logs) under `/opt/nexus/`, created on first run.

---

## 4. The interview

The heart of the tool. Every question has a default in `[brackets]`; Enter accepts it. Every list-select is populated **live from the connected instance**, never hardcoded. Answers are echoed as a summary for confirmation before anything is fetched or written.

Stages 0, 6, 7 and 8 below call the same code regardless of source. Stages 1, 2, 2b, 3, 4 and 5 branch by source — MISP and OpenCTI variants are described side by side within each. (Stage 7's question wording is a partial exception — see the note under item 31.)

### Stage 0 — Environment check (no questions)

Detects SO version, verifies `/opt/so/saltstack/local/salt/zeek/policy/intel/` exists, and checks for `__load__.Zeek`. If the directory is empty or the load file is missing, offers to seed it from `/opt/so/saltstack/default/salt/zeek/policy/intel/` before going any further.

### Stage 1 — Connection

0. Threat intel platform `[misp / opencti]` — asked whenever `--source` was not already supplied on the command line; a caller that already knows skips the question.
1. Platform address (IP or hostname) — prompt text is `MISP address` or `OpenCTI address` depending on the answer above.
2. Scheme + port `[https / 443]` for either source; the http default is `[80]` for MISP and `[4000]` for OpenCTI (OpenCTI's conventional plaintext port).
3. Verify TLS certificate? `[yes]` — `no` warns and requires typed confirmation (`INSECURE`), identical for both sources.
4. HTTP proxy? `[none]`
5. API token — `getpass`, never echoed, never logged; prompt text is `MISP API token` or `OpenCTI API token`.
6. Timeout / retries `[30s / 3]`

→ MISP: `GET /servers/getVersion`, showing MISP version and the token's owning org. OpenCTI: a `{ about { version } }` GraphQL query. Both abort cleanly on an authentication failure — for OpenCTI that means reading the `errors` array out of a 200 response, since GraphQL never uses 401/403 (see §2, OpenCTI API).

### Stage 2 — Discovery (no questions)

MISP: fetches `describeTypes`, `tags`, `organisations`, `sharing_groups`, then a cheap count per candidate attribute type so the operator sees **how many of each actually exist** before choosing.

OpenCTI: fetches labels, marking definitions, organisations, then an exact per-type indicator count from `pageInfo.globalCount`. Prints `N labels, N markings, N organisations` in the same shape as the MISP discovery line.

### Stage 2b — Feeds

MISP only. `GET /feeds` and the feed-selection flow described in §4b below. On an OpenCTI run this stage prints one line and moves straight to stage 3 — skipping it silently would look like a bug to an operator used to the MISP flow:

```
-- Stage 2b: feeds
  Not applicable to OpenCTI; provenance is filtered by author and label in stage 5.
```

### Stage 3 — What IOCs do you want?

7. IOC classes (multi-select): Network (IP/subnet/domain/URL) · File (hashes/filenames) · Email · TLS certs · Host (user agents/usernames)
8. Within each class, the specific MISP attribute types — live list, annotated with count and target Zeek type:
   ```
   [x] ip-dst           4,182   → Intel::ADDR
   [x] domain           1,905   → Intel::DOMAIN
   [ ] hostname           612   → Intel::DOMAIN
   [x] url                833   → Intel::URL
   [ ] filename         2,441   → Intel::FILE_NAME   (noisy)
   ```
9. Composite types (`domain|ip`, `ip-src|port`, `filename|md5`) — emit both halves or one? `[both]`
10. Treat `hostname` as `Intel::DOMAIN`? `[yes]` — the prompt text is identical on both sources; what branches is the type literal used to act on a `no`. MISP drops types starting `"hostname"`, OpenCTI drops `"Hostname"`, since the two platforms spell the type differently and a shared literal would silently do nothing on one of them.
11. Emit `Intel::SUBNET` for CIDR values in IP attributes? `[yes]`

**OpenCTI variant of stage 3.** Driven by `OPENCTI_IOC_CLASSES` instead of MISP's attribute-type table, annotated with live counts the same way, with `OPENCTI_OFF_BY_DEFAULT` (`User-Account`, `Software`) left unselected. The composite-type question (item 9) is skipped — no `OPENCTI_TO_ZEEK` entry has more than one target Zeek type, so it would be pure noise. The result populates the `x_opencti_main_observable_type` filter.

### Stage 4 — Quality filters

12. `to_ids` flagged only? `[yes]` — the biggest signal/noise lever
13. Published events only? `[yes]`
14. `enforceWarninglist`? `[yes]` — strips known-good (top sites, cloud ranges, root servers)
15. Exclude deleted attributes? `[yes]`
16. Minimum event threat level? `[any]`
17. Event analysis state? `[any / initial / ongoing / completed]`

**Stage 4, OpenCTI variant** — MISP's `to_ids`/warninglist/threat-level questions have no OpenCTI counterpart, so this variant asks different questions entirely rather than a subset of the above:

| Question | Default |
|---|---|
| Minimum `x_opencti_score` (0 = no filter) | 50 |
| Minimum `confidence` (0 = no filter) | 0 |
| Exclude revoked indicators? | yes |
| Only indicators flagged for detection? | no |
| Exclude indicators past their `valid_until`? | yes |

`valid_until` is compared against the run's own UTC timestamp, resolved at query-build time; `build_opencti_filters(config, now=None)` takes an optional fixed `now` so tests stay deterministic.

### Stage 5 — Scope

18. Time window: `last N days` / explicit `from`–`to` / `all` `[last 90d]`
19. Which timestamp — attribute `timestamp` or event `publish_timestamp`? `[timestamp]`
20. Include tags (multi-select, live list, OR semantics) `[none = all]`
21. Exclude tags (multi-select, `NOT` semantics) — pre-suggests `false-positive`, `type:OSINT`
22. Restrict to organisations? `[all]`
23. Restrict to sharing groups / distribution level? `[all]`
24. Restrict to specific event IDs/UUIDs? `[none]`

**Stage 5, OpenCTI variant** — the MISP questions with no OpenCTI counterpart (sharing groups, event ids, threat level, analysis state) are simply not asked:

| Question | Notes |
|---|---|
| Include labels | multi-select from discovery, translated name→id; an unresolvable name is dropped with a warning, never guessed at |
| Exclude labels | same, as a nested "not" filter group |
| TLP markings | multi-select from discovery, translated name→id |
| Created by (organisations) | multi-select from discovery, translated name→id |
| Time window | `all` / `last N days` / explicit range `[all]` |
| Timestamp field | `created_at` or `valid_from` `[created_at]` |

### Stage 6 — Local exclusions

25. Exclude RFC1918 / loopback / link-local / multicast? `[yes]`
26. Exclude your own networks — CIDR list `[none]`
27. Exclude your own domains — suffix list `[none]`
28. Extra allowlist file to subtract `[none]`

*Prevents Nexus arming Zeek against your own infrastructure — a real risk when MISP holds sinkhole and sandbox artefacts.*

### Stage 7 — Metadata

29. `meta.source` format: fixed string / `MISP` / `MISP-<org>` / `MISP-event-<id>` `[MISP-event-<id>]`
30. `meta.desc` template over `{event_info}`, `{category}`, `{tags}`, `{comment}`, `{type}`, `{org}`, `{uuid}` `[{event_info} | {category}]`
31. `meta.url` — link back to the source event/indicator? `[yes]`. The question wording and the `meta.source` preset choices (item 29) are still MISP-flavored on an OpenCTI run — a cosmetic gap, not a functional one, since "fixed string" is always available. The computed URL itself is correct either way: `[https://<misp>/events/view/<id>]` for MISP, `[https://<opencti>/dashboard/observations/indicators/<id>]` for OpenCTI — `render_meta` branches on `config["source"]`.
32. Emit `meta.do_notice`? `[no]` — detects whether `do_notice.zeek` is loaded
33. Max metadata field length `[200]`

### Stage 8 — Output & apply

34. Output path `[/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat]`
35. Existing file behavior: **append-only** (all existing indicators retained)
36. Back up first? `[yes]`
37. Optional hard cap on indicator count `[none / unlimited]`
38. Dry run — write to temp and show a diff instead? `[no]`
39. Save answers as a profile? `[yes → /opt/nexus/profiles/<name>.json]`
40. Apply now? `[no]` — if yes: backup → write → `salt -C 'I@zeek:enabled:true' state.apply zeek` → tail `reporter.log`

### Pre-flight summary

Before fetching: prints the resolved query for whichever source was chosen — the MISP restSearch parameters or the OpenCTI `FilterGroup` from `build_opencti_filters` — plus estimated result count and every filter in effect, then one final confirmation. Before writing: prints a per-type breakdown (kept / dropped / deduped / excluded) and asks again. `summarise_config` leads with a `source` line so a saved profile or `--explain` output is unambiguous about which platform it targets.

---

## 4b. Feed selection

Stage 2b, between discovery and IOC selection. `GET /feeds` lists what's configured; the operator picks which to pull from. **MISP only** — OpenCTI has no post-ingest feed concept to trace; on an OpenCTI run this stage prints one line and moves on, and the equivalent provenance narrowing (author, label) happens in stage 5 instead (see §4 above).

**The constraint that shapes everything here:** `/attributes/restSearch` has **no `feed_id` filter**. Once a feed's data is ingested it is just attributes. A feed is only recoverable through the trace it leaves, and Nexus uses the most precise one available:

| Provenance | Feed field | restSearch filter | Precision |
|---|---|---|---|
| Fixed event | `fixed_event=1` + `event_id` | `eventid` | exact |
| Default tag | `tag_id` → tag name | `tags.OR` | exact unless the tag is used elsewhere |
| Creator org | `orgc_id` | `org` | exact unless the org posts non-feed events |

A feed with none of the three is **untraceable after ingest** — its attributes are indistinguishable from the rest of MISP. Nexus lists those separately and refuses to select them, with the reason shown, rather than silently returning everything.

**One query per feed.** Two feeds identified by different mechanisms (one by event, one by tag) cannot be expressed in a single restSearch body, so each gets its own query and results merge. `build_indicators` dedupes across them, so an indicator carried by two feeds is written once — first feed wins.

**Tag-feed caveat.** `tags.OR` is a disjunction, so a feed's tag and the operator's include-tags cannot both be *required* in one body. The feed tag goes to MISP (narrower selector) and the include-tags are applied client-side in `_fetch_records`. Feeds identified by event or org keep include-tags server-side.

**Output.** All selected feeds land in the one `intel.dat` Security Onion already loads — no `__load__.Zeek` edits. `meta.source` becomes `MISP-feed-<name>` (slugged to stay tab-safe), so an `intel.log` hit names the feed that supplied it.

Feed choice ANDs with every existing filter — `to_ids`, warninglist, time window and type selection all still apply.

---

## 5. Type mapping

This table is `MISP_TO_ZEEK`. The OpenCTI equivalent, `OPENCTI_TO_ZEEK`, is a separate, smaller table keyed on OpenCTI observable entity types (`IPv4-Addr`, `Domain-Name`, `X509-SHA-1`, …) — see `HANDOFF.md` §4 (Architecture) for where it lives, and §6 for the certificate-hash gotcha specific to it. `map_attribute` takes either table as its `table=` argument, so the splitting/dedup logic below is shared, not duplicated.

| MISP attribute type | Zeek `Intel::Type` | Notes |
|---|---|---|
| `ip-src`, `ip-dst` | `ADDR` or `SUBNET` | CIDR detected by `/` |
| `ip-src\|port`, `ip-dst\|port` | `ADDR` | split, port discarded |
| `domain` | `DOMAIN` | |
| `hostname` | `DOMAIN` | optional |
| `domain\|ip` | `DOMAIN` + `ADDR` | split |
| `url`, `uri` | `URL` | **scheme stripped** |
| `link` | `URL` | off by default — usually a report link, not an IOC |
| `md5`, `sha1`, `sha256`, `sha224`, `sha384`, `sha512` | `FILE_HASH` | |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, … | `FILE_NAME` + `FILE_HASH` | split |
| `filename` | `FILE_NAME` | high noise — off by default |
| `email`, `email-src`, `email-dst`, `email-reply-to`, `target-email`, `whois-registrant-email` | `EMAIL` | |
| `x509-fingerprint-sha1` | `CERT_HASH` | |
| `x509-fingerprint-md5`, `x509-fingerprint-sha256` | — | dropped, counted, reported |
| `user-agent` | `SOFTWARE` | |
| `target-user`, `github-username`, `whois-registrant-name` | `USER_NAME` | off by default |
| `ssdeep`, `imphash`, `authentihash`, `vhash`, `tlsh` | — | no Zeek equivalent; dropped with count |

Anything unmapped is dropped and tallied in a "skipped types" report — nothing disappears silently.

---

## 6. Normalisation & validation

Per Intel type, before an indicator enters the file:

- **ADDR** — parse with `ipaddress`; reject invalid, unspecified, loopback, multicast, and (by default) private.
- **SUBNET** — parse as network; reject `/0`; warn below `/16`.
- **DOMAIN** — lowercase, strip trailing dot, IDNA-encode, reject bare TLDs and anything without a dot.
- **URL** — strip `scheme://`, strip leading `//`, keep path + query, drop fragment; reject empty remainder.
- **FILE_HASH** — lowercase, hex only, length in {32, 40, 64, 96, 128}.
- **EMAIL** — lowercase, exactly one `@`, valid domain part.
- **CERT_HASH** — 40 hex chars.
- **All types** — reject values containing tab, CR or LF (they would corrupt the file); strip surrounding whitespace; refuse zero-length.
- **Metadata** — replace tab/CR/LF with a space, collapse whitespace runs, truncate to the configured max, substitute `-` when empty.

**Deduplication** — key `(indicator, indicator_type)`. First wins; repeats optionally append `(+N more events)` to `meta.desc`.

---

## 7. Writing `intel.dat`

1. Render all lines in memory; run the internal linter (column count, no stray whitespace, valid type token, exact header).
2. Write to a temp file **in the same directory** (same filesystem — required for atomic replace).
3. `flush()` + `os.fsync()`.
4. Copy owner/group/mode from the existing file (else `root:root 0644`).
5. `os.replace()` — atomic; Zeek never sees a half-written file.
6. Exactly one `\n` after the last record, no trailing blank line.
7. Confirm `__load__.Zeek` is still present alongside it.

**Merge mode**: append-only. `cmd_build` calls `merge_additive()`, which keeps *every* existing line verbatim and in its original order — hand-maintained and Nexus-written alike — and appends only rows whose `(indicator, Intel::Type)` key is not already present. Where the source returns changed metadata for an IOC already in the file, the existing line wins. (`merge_preserved()`, a selective retain-by-`meta.source` variant, exists in the file but has no callers.)

**Backup**: previous file copied to `/opt/nexus/backups/intel.dat.<ISO8601>` before replacement, with a retention count.

---

## 8. Guardrails

- **Size** — retrieval is unlimited by default, warns at 100k indicators, and
  optionally hard-stops at an operator-selected cap. Every indicator sits in
  every Zeek worker's memory, so actual capacity depends on the target nodes.
- **Overly broad indicators** — reject wide subnets, single-label domains, and known CDN/cloud domains unless explicitly allowed.
- **Empty result set** — refuse to write an empty or near-empty file over a populated one without explicit confirmation. A MISP outage must not silently wipe intel.
- **Append-only invariant** — diff by `(indicator, indicator_type)` and add only
  new keys. Existing rows, including their metadata, are never deleted or
  rewritten by a MISP refresh.
- **Missing `__load__.Zeek`** — refuse to apply; a written-but-unloaded intel file looks like success and isn't.

---

## 9. Applying to the grid

Gated behind explicit confirmation, never automatic:

1. Verify `__load__.Zeek` present (offers to seed from defaults if not).
2. Backup.
3. Atomic write.
4. Record the reporter log's byte offset, so only errors from *this* run are read.
5. Print the exact command; run only if confirmed:
   ```
   sudo salt -C 'I@zeek:enabled:true' state.apply zeek
   ```
6. Confirm the file landed at `/opt/so/conf/zeek/policy/intel/intel.dat` with the expected indicator count.
7. Read `reporter.log` from the recorded offset for intel errors; surface them.
8. Point the operator at `/nsm/zeek/logs/current/intel.log` to confirm hits.

Default posture is **print the command, don't run it** — interview Q40 defaults to no.

**A clean `state.apply` proves nothing.** Zeek rejects a malformed intel file through `reporter.log`, not by failing the salt run, so the reporter check is the real verdict. Nexus records the log's byte offset *before* applying so a pre-existing error from last week can't fail today's run, and today's error can't hide in the noise.

Salt is invoked as an **argv list, never a shell string** — nothing needs a shell, and the `-C 'I@zeek:enabled:true'` compound target contains quotes a shell would have to be trusted with. Missing salt degrades to printing the command.

---

## 10. Non-interactive mode

```
nexus                                  # full interview
nexus --profile daily.json             # replay answers, prompt only for token
nexus --profile daily.json --yes       # fully unattended
nexus --profile daily.json --dry-run --diff
nexus --lint /path/to/intel.dat        # validate a file, no MISP needed
nexus --explain --profile daily.json   # print the resolved platform query, fetch nothing
nexus --check-env                      # stage 0 only: paths, __load__.Zeek, SO version
```

Token resolution order: `--token-file` → env (`NEXUS_TOKEN`, then the deprecated `NEXUS_MISP_TOKEN` for back-compat) → `/opt/nexus/credentials.json` (0600) → interactive prompt. Under `--yes` the prompt is skipped and the run fails loudly instead — an unattended job must never block forever on a `getpass` nobody will answer.

**Profiles never store the token**, and never store the `discovery` cache either (live MISP lists are stale the moment they're written). Written `0600`, and an existing looser file is re-tightened on overwrite. A token hand-added to a profile is dropped on load rather than honoured.

**Two kinds of diff, deliberately.** `--dry-run` reports an *indicator* delta keyed on `(indicator, type)`, so a changed description is not reported as a delete plus an add. `--diff` adds the full line diff, which does show metadata churn. The first answers "what will Zeek match differently?", the second "what changed in the file?".

Scheduled runs via a systemd timer (`nexus.service` + `nexus.timer`), not cron, so failures land in the journal.

---

## 11. Security

- Token read with `getpass`; never printed, never written to the run log, redacted from tracebacks and HTTP debug output by a logging filter.
- Stored credentials only on explicit opt-in: `0600`, root-owned, path shown to the operator.
- TLS verification on by default; `--insecure` demands typed confirmation and stamps a warning into the run log.
- Nexus writes to exactly two places: `/opt/nexus/` and the configured intel path.
- Run log records what was queried and how many indicators were written — the audit trail for "why is Zeek alerting on this?"

---

## 12. Testing

A sibling `test_nexus.py` that imports `nexus.py` — same stdlib-only constraint, runnable with `python3 -m unittest`.

- **Unit** — mapping, normalisation, filters, rendering against fixture attribute/indicator dicts. Table-driven, one case per MISP type and per OpenCTI observable type, including every malformed variant.
- **Golden file** — fixture MISP response → expected `intel.dat`, byte-for-byte. Catches the whitespace regressions the SO docs explicitly warn about. A parallel OpenCTI fixture exercises the same golden-file path through `flatten_indicator` and the STIX pattern fallback.
- **Fake MISP** — `http.server` responder (`FakeMisp`/`FakeMispHandler`) replaying canned `restSearch` pages; exercises pagination, 401, 403, 429, timeout, malformed JSON, mid-pagination failure.
- **Fake OpenCTI** — the GraphQL counterpart (`FakeOpencti`/`FakeOpenctiHandler`), replaying canned query responses; exercises cursor pagination, a 200-with-`errors` auth rejection, and a cursor that fails to advance.
- **Linter self-test** — writer output must always pass `--lint`, for either source.
- **Integration** — against a MISP training VM or `demo.misp-project.org`, and an OpenCTI instance, then a lab SO 3.2 grid: seed `__load__.Zeek`, apply, confirm the file reaches `/opt/so/conf/zeek/policy/intel/`, clean `reporter.log`, generate a hit, confirm it lands in `intel.log`. Not yet done against a real OpenCTI — see `HANDOFF.md` §7.

---

## 13. Build phases

| Phase | Deliverable | Verifiable by |
|---|---|---|
| 0 ✅ | Script skeleton, argparse, redacting logger, `--check-env` | `nexus --check-env` on the manager |
| 1 ✅ | `MispClient` — auth, version check, restSearch, pagination, retry | connects to demo MISP, prints counts |
| 2 ✅ | Mapping + normalisation + writer + `--lint` | unit + golden tests pass offline |
| 3 ✅ | The interview end-to-end → writes a file | full manual run against demo MISP |
| 4 ✅ | Profiles, `--yes`, `--dry-run`, `--diff`, `--explain` | unattended run reproduces phase-3 output |
| 5 ✅ | Local exclusions + all §8 guardrails | a test per refusal path |
| 6 ✅ | Apply — `__load__.Zeek` seeding, salt apply, reporter check | lab grid: apply → hit in `intel.log` |
| 7 | systemd timer, install steps, operator README | fresh-manager install works |
| 8 ✅ | OpenCTI as a second, independently selectable IOC source — client, mapping, interview branching, config/profile/CLI | offline test suite (525 tests); unverified against a live OpenCTI instance, see `HANDOFF.md` §7 |
| 9 ✅ | Offline build (`--offline`) — build a transfer-ready `intel.dat` on a host with no Security Onion installed, plus `--import PATH` to merge one back into a manager's live file, append-only | offline test suite (525 tests, includes a poison-path assertion that an offline build never touches the real `SO_*` paths, and a byte-identity assertion that import never rewrites an existing row) |

Phases 1–2 are independently useful and fully testable without a Security Onion box. Phase 3 is where the tool becomes what was asked for. Phases 8 and 9 were both taken out of numeric order — they landed after phase 6 while phase 7 (systemd timer, install docs) was still outstanding, since both are source-neutral/deployment-neutral to what phase 7 covers.

---

## 14. Later (out of scope for v1)

- Indicator **aging** — expire entries older than N days, or honour MISP `first_seen` / `last_seen` and decay scores.
- Multiple MISP instances merged into one file.
- Generating **Suricata** rules from MISP alongside the Zeek intel.
- Feedback loop: query Elastic for `intel.log` hits to find which indicators actually fire, and prune the dead weight.
- MISP **event**-level pull (`/events/restSearch`) for richer `meta.desc` context.
- PyMISP as an optional backend where it's already installed.
- Specific to OpenCTI (spec §13): querying MISP and OpenCTI in the same run; OpenCTI Observables as a source (Indicators only, per the decision in `HANDOFF.md` §5); OpenCTI 5.x flat-filter syntax; writing anything back to OpenCTI (no sightings, no hit feedback — Nexus stays read-only against both platforms); OpenCTI connectors, streams and the live-stream API (this is a polled pull, the same shape as the MISP path); relationship traversal (indicator → intrusion set → campaign) for richer `meta.desc`.
- Specific to offline build / import (`docs/superpowers/specs/2026-08-21-offline-build-design.md` §3, §8): a checksum or signature sidecar for the transferred file, and a second file format or archive/package wrapping `intel.dat` for the trip across the airgap. Both were considered and rejected — exactly one file crosses the airgap, `intel.dat` itself, no new dependency and no new format to keep in sync. The reasoning for the checksum specifically: import is additive and lints what arrives, so a truncated copy can only contribute fewer rows, never remove one, and a corrupt line fails lint before anything is written. A checksum would detect a condition the existing checks already render harmless.

---

## 15. Open questions

1. Exact 3.2.x point release on the target manager, and whether the local intel dir is currently populated (does `__load__.Zeek` exist there today?).
2. Does that grid already have an intel feed or anything else managing that file? Merge mode depends on the answer.
3. Expected indicator volume from your MISP — drives the cap, and whether aging moves up from §14.
4. Unattended on a schedule from day one, or interactive-only until it's trusted?

---

## Sources

- [Zeek — Security Onion 3 Documentation](https://docs.securityonion.net/en/3/main/zeek/)
- [Zeek Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html)
- [Zeek `Intel::Type`](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html)
- [MISP Automation / RestSearch API](https://www.circl.lu/doc/misp/automation/)
- [Security Onion 3.2.0 release announcement](https://blog.securityonion.net/2026/07/security-onion-320-now-available-with.html)
