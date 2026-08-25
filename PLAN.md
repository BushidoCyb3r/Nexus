# Nexus — MISP / OpenCTI / TAXII → Zeek `intel.dat` Builder for Security Onion

**Status:** every phase built and tested — three IOC sources (MISP, OpenCTI, TAXII), one per run, plus feed selection, offline build and airgapped import, and the opt-in systemd timer. What remains is live validation against a real MISP, OpenCTI or TAXII server and a real Security Onion manager — see `HANDOFF.md` §7.
**Target host:** Security Onion 3.2 manager node, or — for an offline build — any host with Python 3.6+ and nothing else installed
**Form:** a single Python 3 script, `nexus.py`, stdlib only — no pip, no venv, no packaging

```
nexus.py        the tool          python3 nexus.py
test_nexus.py   742 tests         python3 -m unittest test_nexus
```

**New assistant picking this up: read `HANDOFF.md` first.**

Working today: the full interview end-to-end against any of the three platforms, including apply, and unattended replay from a profile. Modes: `--check-env`, `--seed`, `--apply`, `--probe`, `--lint`, `--explain`, `--profile`, `--yes`, `--dry-run`, `--diff` (implies `--dry-run`), `--do-notice`, `--offline`, `--import PATH`, `--install-timer`. `--source {misp,opencti,taxii}` and `--host` select the platform; `--misp` remains as a deprecated alias for `--host --source misp`.

---

## 1. What Nexus does

Nexus is an interactive script that runs on a Security Onion 3.2 manager, against **one IOC source per run — MISP, OpenCTI or TAXII**, chosen in the interview or via `--source`. It:

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

### TAXII API

- Two protocol versions, negotiated per connection. 2.1 discovers at `GET /taxii2/` and sends `Accept: application/taxii+json;version=2.1`; 2.0 discovers at `GET /taxii/` and sends `Accept: application/vnd.oasis.taxii+json; version=2.0`. `detect_version()` probes 2.1 then 2.0. The question is still asked, defaulted to 2.1: stage 1 collects the credential and so has no client to detect with. `run_interview` runs the detection when it connects, at stage 2, and corrects the answer out loud if the server disagrees — without that, a 2.0 server simply fails to answer `/taxii2/` and the whole interview reads it as an unreachable host.
- Unlike GraphQL, TAXII uses ordinary status codes, so the transport's existing 401/403 handling already covers authentication failure. Auth is **Bearer or Basic**; the Basic username is half a credential and is excluded from profiles exactly like the password (`NEXUS_TAXII_USERNAME` supplies it unattended).
- Discovery names its own **API roots**, and the spec makes them absolute URLs. `TaxiiClient._same_host` refuses one that is not on the authenticated scheme, host and port (compared through `_origin()`, which normalises a default port away so `https://h` and `https://h:443` are one origin), on both routes an API root becomes a request — `get_collections` skips it with a warning, `fetch_objects` raises. Otherwise the discovery document could redirect the `Authorization` header to a third party without ever issuing a 3xx.
- Collections live under an API root: `GET <root>collections/`, then `GET <root>collections/<id>/objects/`.
- Pagination differs by version. 2.1 sends `limit` and follows the envelope's `more`/`next`; 2.0 has no such parameter and walks a `Range: items N-M` window, reading `Content-Range` back. Both stop on a cursor or window that fails to advance, on an empty page, and — for 2.0 — on the total reported by the *first* page, so a server whose total outruns its window cannot be pulled forever.
- **The query syntax reaches `match[type]` and `added_after`, nothing else.** `match[type]` is fixed to `indicator`; `added_after` carries the days-back answer. Labels, markings, confidence, `valid_until` and author all live inside the STIX object, so `taxii_object_allowed` applies them **after download** and every prompt that collects one says so.
- Only `type == "indicator"` objects are read, and only `pattern_type == "stix"` patterns are parsed — `parse_stix_pattern` is shared with the OpenCTI fallback and emits `OPENCTI_TO_ZEEK` keys, so TAXII reuses that mapping table wholesale. The pattern's *structure* is not honoured: every `=` comparison in it becomes an indicator, so `AND`- and `OR`-composed observation expressions and qualifiers (`REPEATS`, `WITHIN`, `START`/`STOP`) all flatten to the same independent values. For an `AND` that over-matches, deliberately — Zeek's Intel framework is a flat list with no way to express "only when both are seen", and the alternative is dropping the pattern and losing two real indicators to a structure Zeek could not have used. Only `!=` is genuinely dropped, structurally: the regex's property class excludes `!`, so a negation never reaches the `=`.
- **STIX 2.0 has no `confidence` property.** `flatten_taxii_object` carries an absent value through as `None`, never 0 — 0 is a real (low) confidence in 2.1, and treating absent as zero would let a minimum-confidence filter silently drop every object from a 2.0 feed.

---

## 3. Script structure

One file: `nexus.py`. Executable, `#!/usr/bin/env python3`, stdlib only (`urllib.request`, `ssl`, `json`, `ipaddress`, `getpass`, `argparse`, `os`, `tempfile`, `shutil`, `subprocess`, `datetime`, `re`, `logging`). Drops onto an air-gapped manager and runs.

Internally organised into banner-delimited sections, in dependency order so the file reads top to bottom:

```
#!/usr/bin/env python3
"""nexus.py — build a Zeek intel.dat from MISP, OpenCTI or TAXII, for Security Onion 3.2."""

# ── CONSTANTS ──────────────────────────────────────────────
#   SO paths, Zeek type set, MISP→Zeek and OpenCTI→Zeek mapping tables
#   (TAXII reuses OPENCTI_TO_ZEEK), TAXII_VERSIONS / _ACCEPT / _DISCOVERY,
#   defaults

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
#   class TaxiiClient(_HttpTransport):  detect_version, get_version,
#                      get_collections, fetch_objects (2.1 envelope
#                      pagination) / _fetch_objects_20 (Range windows),
#                      _same_host — refuses an API root off the
#                      authenticated origin
#   NoCrossHostRedirect — refuses a 3xx that would carry the Authorization
#   header to another host, or down from https to http on the same one
#   _origin(url) — (scheme, host, port) with a default port normalised
#   away; the one comparison both refusals are built on
#   flatten_attribute(attr) → one record; flatten_indicator(node,
#   stats=None) and flatten_taxii_object(obj, collection_title, stats=None)
#   → a *list*, one record per extracted value (an indicator carrying both
#   an MD5 and a SHA-256 yields two rows).  All three emit the same record
#   shape (below), so everything downstream of this seam is source-agnostic
#   parse_stix_pattern(pattern) — the value source for TAXII, and the
#   fallback for OpenCTI indicators with no linked observables; only for
#   pattern_type == "stix"

# ── FEEDS ──────────────────────────────────────────────────
#   feed_provenance(), feed_is_selectable(), apply_feed_to_params()
#   (MISP only — neither OpenCTI nor TAXII has a feed concept)

# ── MAPPING ────────────────────────────────────────────────
#   map_attribute(record, table=MISP_TO_ZEEK or OPENCTI_TO_ZEEK)
#     -> [(indicator, intel_type), ...]
#   handles composite splitting: domain|ip, ip-src|port, filename|md5
#   (OpenCTI observables carry no composite types of their own)

# ── NORMALISE / VALIDATE ───────────────────────────────────
#   norm_addr, norm_subnet, norm_domain, norm_url, norm_hash,
#   norm_email, norm_cert_hash, sanitize_meta
#   _prepare() — the shared funnel; carries the guards that are about the
#   line format rather than the value: _reject_control (tabs/newlines) and
#   _reject_comment (a leading "#", which Zeek reads as a comment line)
#   NORMALISERS = {Intel::TYPE: fn}

# ── FILTERS ────────────────────────────────────────────────
#   ExclusionSet: RFC1918, own CIDRs, own domain suffixes, allowlist file
#   taxii_object_allowed(record, config): the six filters TAXII's query
#   syntax cannot express, applied after download

# ── INTEL FILE ─────────────────────────────────────────────
#   header_line(), render_meta(), render_line(), build_indicators()
#   (dedup by (indicator, Intel::Type) happens inline here — there is no
#   separate dedupe function), rows_to_lines(), lint_lines(), lint_file(),
#   read_existing(), merge_additive(), backup_file(), write_atomic()

# ── ENVIRONMENT CHECK ──────────────────────────────────────
#   detect_so_version(), notice_policy_loaded(), check_env()  — stage 0
#   check_output_target() — the off-box counterpart for --offline

# ── GUARDRAILS ─────────────────────────────────────────────
#   check_size(), check_not_empty(), check_delta(), check_load_file(),
#   check_broad_indicators(), check_built_anything(), run_guardrails()  (§8)

# ── INTERVIEW ──────────────────────────────────────────────
#   ask(), ask_yes_no(), ask_int(), ask_choice(), ask_multi(),
#   discover() (MISP) / discover_opencti() / discover_taxii(),
#   build_search_params() (MISP) / build_opencti_filters() (OpenCTI) /
#   taxii_added_after() (TAXII's one server-side filter),
#   connection_defaults() — the CLI connection flags, seeding stage 1's
#     answers when there is no live client to read defaults off,
#   resolve_build_target() — offline vs. manager, asked before check_env(),
#   then run_interview() -> Config, one stage per §4 heading,
#   stages 2/2b/3/4/5 branching by source

# ── PROFILES ───────────────────────────────────────────────
#   load_profile(), save_profile()   (JSON, v2 schema with a v1 reader
#   that migrates old MISP-only key names forward in memory)

# ── DIFF ───────────────────────────────────────────────────
#   indicator_delta(), summarise_delta(), unified_intel_diff()

# ── APPLY ──────────────────────────────────────────────────
#   seed_load_file(), salt_apply(), log_offset(), log_errors_since(),
#   verify_runtime(), apply_to_grid(), print_transfer_instructions()

# ── SCHEDULE ───────────────────────────────────────────────
#   render_unit_files(), describe_calendar(), env_file_names() — which
#   variables the unit's EnvironmentFile supplies, since a terminal cannot
#   see them, check_timer_preconditions(), cmd_install_timer()
#   — --install-timer only; nothing else in the file may reach
#   render_unit_files()

# ── MAIN ───────────────────────────────────────────────────
#   argparse (--source/--host/--misp), client factory picking
#   MispClient, OpenctiClient or TaxiiClient from config["source"],
#   mode dispatch, cmd_build / cmd_import orchestration,
#   summary printing
```

**Design rules that survive the single-file form:**

- The mapping / normalise / filter / intel-file sections must not touch the network or the filesystem — pure functions over plain dicts, so they're testable by importing `nexus.py` from a test script.
- Only `write_atomic()` may write to the live intel path.
- `_HttpTransport` is the only thing that speaks HTTP; `MispClient`, `OpenctiClient` and `TaxiiClient` all subclass it and are the only things that call it.

Internal record shape after fetch — produced by `flatten_attribute(attr)` (MISP, one record per attribute), `flatten_indicator(node, stats=None)` (OpenCTI) and `flatten_taxii_object(obj, collection_title, stats=None)` (TAXII). The latter two return a *list* — one record per value extracted, so a file indicator carrying an MD5 and a SHA-256 fans out to two. The shape is identical whichever produced it, so mapping, normalisation and everything after it runs unchanged regardless of source:

```python
{
  "value": str, "type": str, "category": str,
  "uuid": str, "timestamp": int, "comment": str,
  "event_id": str, "event_uuid": str, "event_info": str,
  "event_tags": [str], "org": str,
}
```

`to_ids` is deliberately **not** in that shape: it is a MISP-only query filter (`build_search_params`), applied server-side, so no record ever needs to carry it. `flatten_taxii_object` adds six TAXII-only keys on top of the shared ones — `collection`, `labels`, `confidence`, `valid_until`, `created_by_ref`, `object_marking_refs` — read by `taxii_object_allowed` and by `render_meta`'s `{collection}` placeholder. Nothing source-agnostic reads them, and `TestFlattenTaxii` pins the *shared* key set equal to `flatten_indicator`'s so a future divergence fails loudly.

Deploy: copy to `/opt/nexus/nexus.py`, `chmod 750`, root-owned (`README.md` — Install). Working state (profiles, backups, logs) under `/opt/nexus/`, created on first run.

---

## 4. The interview

The heart of the tool. Every question has a default in `[brackets]`; Enter accepts it. Every list-select is populated **live from the connected instance**, never hardcoded. Answers are echoed as a summary for confirmation before anything is fetched or written.

Stages 0, 6, 7 and 8 below call the same code regardless of source. Stages 1, 2, 2b, 3, 4 and 5 branch by source — the MISP, OpenCTI and TAXII variants are described side by side within each. TAXII branches hardest: it has no type menu (stage 3 asks which *collection* instead) and no quality stage at all, because everything that would live there is one of the post-download filters stage 5 asks.

### Stage 0 — Environment check (no questions)

Detects SO version, verifies `/opt/so/saltstack/local/salt/zeek/policy/intel/` exists, and checks for `__load__.Zeek`. If the directory is empty or the load file is missing, offers to seed it from `/opt/so/saltstack/default/salt/zeek/policy/intel/` before going any further.

### Stage 1 — Connection

0. Threat intel platform `[misp / opencti / taxii]` — asked whenever `--source` was not already supplied on the command line; a caller that already knows skips the question.
1. Platform address (IP or hostname) — prompt text is `MISP address` or `OpenCTI address` depending on the answer above. Every connection flag (`--host`, `--scheme`, `--port`, `--insecure`, `--proxy`, `--timeout`, `--retries`) seeds the corresponding default here. None of them skips its question.
2. Scheme + port `[https / 443]` for either source; the http default is `[80]` for MISP and `[4000]` for OpenCTI (OpenCTI's conventional plaintext port).
3. Verify TLS certificate? `[yes]` — `no` warns and requires typed confirmation (`INSECURE`), identical for both sources. `--insecure` on the command line seeds the answer *and* stands in for the typed confirmation: it is already the deliberate act, and asking twice made the flag impossible to act on.
4. HTTP proxy? `[none]`
5. API token — `getpass`, never echoed, never logged; prompt text is `MISP API token` or `OpenCTI API token`.

**TAXII variant of stage 1.** Two extra questions before the credential, because TAXII carries its own protocol version and can authenticate two ways: TAXII version `[2.1 / 2.0]`, always asked and defaulted to 2.1 — detection needs a client, and this stage is what builds the credential one, so `run_interview` detects at the stage 2 connect and corrects the answer there; and authentication `[bearer / basic]`. Basic collects an echoed username plus a silent password; both are excluded from a saved profile, so an unattended replay reads the username from `NEXUS_TAXII_USERNAME`.
6. Timeout / retries `[30s / 3]`

→ MISP: `GET /servers/getVersion`, showing MISP version and the token's owning org. OpenCTI: a `{ about { version } }` GraphQL query. Both abort cleanly on an authentication failure — for OpenCTI that means reading the `errors` array out of a 200 response, since GraphQL never uses 401/403 (see §2, OpenCTI API).

### Stage 2 — Discovery (no questions)

MISP: fetches `describeTypes`, `tags`, `organisations`, `sharing_groups`, then a cheap count per candidate attribute type so the operator sees **how many of each actually exist** before choosing.

OpenCTI: fetches labels, marking definitions, organisations, then an exact per-type indicator count from `pageInfo.globalCount`. Prints `N labels, N markings, N organisations` in the same shape as the MISP discovery line.

TAXII: walks every API root in the discovery document (skipping any that is not on the authenticated host and scheme) and lists the collections the credential can actually read. Prints `N collections`. There is nothing to count here — TAXII cannot count a filtered subset, so a per-type count would be a number for a query Nexus never sends.

### Stage 2b — Feeds

MISP only. `GET /feeds` and the feed-selection flow described in §4b below. On an OpenCTI run this stage prints one line and moves straight to stage 3 — skipping it silently would look like a bug to an operator used to the MISP flow. On a TAXII run the stage does not run at all: a collection *is* the feed, and stage 3 asks for it directly.

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

**TAXII variant of stage 3** (`_stage3_collections_taxii`). There is no type menu: `match[type]=indicator` already narrows every collection on the wire, and the values themselves come out of `parse_stix_pattern`, which cannot be asked for a subset. So items 7–9 become one question — which collections to pull from, multi-select, all preselected — and items 10 and 11 are asked unchanged. A `no` to item 10 has no type menu to prune, so it is turned into an explicit allow-list of every `OPENCTI_TO_ZEEK` key except `Hostname`; otherwise the answer would be collected and then quietly do nothing.

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

**There is no stage 4 on TAXII.** Every filter that would belong here is one TAXII's query syntax cannot express, so it is asked in stage 5 and applied after download.

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

**Stage 5, TAXII variant** — one question the server acts on, and six it does not. The stage opens by saying so, and every one of the six repeats it in its own prompt text, because a filter the operator believes is cutting transfer volume when it is not is the defect this project has fixed three times:

| Question | Where it is applied |
|---|---|
| Days back (0 = no time filter) `[90]` | **server-side**, as `added_after` |
| Include labels `[none = all]` | after download |
| Exclude labels `[none]` | after download |
| Include marking-definition refs `[none = all]` | after download |
| Include `created_by_ref` authors `[none = all]` | after download |
| Minimum confidence `[0]` | after download — and on a 2.0 feed the stage warns that STIX 2.0 carries no `confidence` at all, so it will exclude nothing |
| Drop indicators past `valid_until`? `[yes]` | after download |

`taxii_added_after(config, now=None)` turns the days-back answer into the query parameter, and the pre-flight summary calls the *same* function rather than recomputing it — a summary that described a window the query did not have would be worse than no summary.

### Stage 6 — Local exclusions

25. Exclude RFC1918 / loopback / link-local / multicast? `[yes]`
26. Exclude your own networks — CIDR list `[none]`
27. Exclude your own domains — suffix list `[none]`
28. Extra allowlist file to subtract `[none]`

*Prevents Nexus arming Zeek against your own infrastructure — a real risk when MISP holds sinkhole and sandbox artefacts.*

### Stage 7 — Metadata

29. `meta.source` format — the preset list is per source: `SOURCE_FORMATS` for MISP (`MISP-event-{event_id}` / `MISP-{org}` / `MISP` / fixed string), `OPENCTI_SOURCE_FORMATS`, `TAXII_SOURCE_FORMATS` (`TAXII-{collection}` first, since a collection is the only identity a TAXII object has). If stage 2b already chose one — it sets `MISP-feed-{feed}` when feeds were selected — that value leads the list and is the default, rather than being silently overwritten by the menu's own first entry.
30. `meta.desc` template over `{event_info}`, `{category}`, `{tags}`, `{comment}`, `{type}`, `{org}`, `{uuid}`, `{feed}` `[{event_info} | {category}]`
31. `meta.url` — link back to the source event/indicator? `[yes]`. `render_meta` branches on `config["source"]`: `[https://<misp>/events/view/<id>]` for MISP, `[https://<opencti>/dashboard/observations/indicators/<id>]` for OpenCTI. On TAXII the question is **not asked** — a TAXII object has no browsable page, and the MISP-shaped URL would send an analyst to a server with no such event — so the stage says `meta.url is left empty` and moves on.
32. Emit `meta.do_notice`? `[no]` — detects whether `do_notice.zeek` is loaded
33. Max metadata field length `[200]`

### Stage 8 — Output & apply

34. Output path `[/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat]`
35. Existing file behavior: **append-only** (all existing indicators retained)
36. Back up first? `[yes]`
37. Optional hard cap on indicator count `[none / unlimited]`
38. Dry run — build, run every check, report the indicator delta, write nothing? `[no]`. `--diff` adds the full line diff and implies `--dry-run`, so asking to *see* a diff can never write one.
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
- **SUBNET** — parse as network; reject `/0`; **reject** anything broader than `MIN_PREFIX_V4`/`MIN_PREFIX_V6` (/16, /32), and reject loopback, multicast and link-local ranges the way ADDR does. A prefix exactly *at* the floor is admitted here and warned about by `check_broad_indicators` — see §8.
- **DOMAIN** — lowercase, strip trailing dot, strip a leading `*.`, IDNA-encode, reject bare TLDs, numeric TLDs, and an IP address wearing a domain's clothes.
- **URL** — strip `scheme://`, strip leading `//`, drop the fragment, keep path + query, drop `user:pass@` (Zeek never sees credentials in the host header it matches against). A URL with a query but no path gets the `/` it elided — `evil.com?a=1` → `evil.com/?a=1` — and a pathless URL gets a bare one, because Zeek builds its match candidate as host+uri and a uri always starts with `/`. Reject an empty remainder, whitespace, or a host that is neither a valid domain nor a valid address.
- **FILE_HASH** — lowercase, hex only, length in {32, 40, 56, 64, 96, 128} — md5, sha1, **sha224**, sha256, sha384, sha512. There is a `hashlib` round-trip test over all six; sha224 was missing once and silently dropped every sha224 IOC.
- **EMAIL** — lowercase, exactly one `@`, valid domain part.
- **CERT_HASH** — 40 hex chars.
- **All types** — reject values containing tab, CR or LF (they would corrupt the file); strip surrounding whitespace; refuse zero-length.
- **Metadata** — replace tab/CR/LF with a space, collapse whitespace runs, truncate to the configured max, substitute `-` when empty.

**Deduplication** — key `(indicator, indicator_type)`, inline in `build_indicators`. First wins; repeats are counted into `BuildStats.duplicates` and reported, and the later row's metadata is discarded rather than merged into the first — an indicator carried by two events keeps the first event's `meta.desc`.

---

## 7. Writing `intel.dat`

1. Render all lines in memory; run the internal linter (column count, no stray whitespace, valid type token, exact header).
2. Write to a temp file **in the same directory** (same filesystem — required for atomic replace).
3. `flush()` + `os.fsync()`.
4. Copy owner/group/mode from the existing file (else `root:root 0644`).
5. `os.replace()` — atomic; Zeek never sees a half-written file.
6. Exactly one `\n` after the last record, no trailing blank line.
7. Confirm `__load__.Zeek` is still present alongside it.

**Merge mode**: append-only. `cmd_build` and `cmd_import` both call `merge_additive()`, which keeps every existing *indicator* line verbatim and in its original order — hand-maintained and Nexus-written alike — and appends only rows whose `(indicator, Intel::Type)` key is not already present. Operator `#` comment lines are the one thing this does not cover: `read_existing()` filters them out, so they do not survive a merge on either path — see the "Append-only does not currently cover operator comment lines" entry in `HANDOFF.md` §6. Where the source returns changed metadata for an IOC already in the file, the existing line wins. (`merge_preserved()`, a selective retain-by-`meta.source` variant, was deleted once append-only landed — `merge_additive()` retains *every* existing row, hand-added or not, so there was nothing left for it to preserve.)

**Backup**: previous file copied to `/opt/nexus/backups/intel.dat.<ISO8601>` before replacement, with a retention count. Under `--offline`, `/opt/nexus` does not exist on that host and is not writable, so the backup instead goes to `nexus-backups/intel.dat.<ISO8601>` beside the output path, same retention count.

---

## 8. Guardrails

- **Size** — retrieval is unlimited by default, warns at 100k indicators, and
  optionally hard-stops at an operator-selected cap. Every indicator sits in
  every Zeek worker's memory, so actual capacity depends on the target nodes.
- **Overly broad indicators** — `norm_subnet` *rejects* a prefix broader than `MIN_PREFIX_V4`/`V6` (/16, /32) outright; `check_broad_indicators` then *warns* on anything that survived at or broader than the floor, plus single-label domains and hostless URLs. The two deliberately disagree at the boundary: a /16 is a real IOC, but the operator should see it named before it arms every sensor. There is **no built-in CDN/cloud domain list** — that is what `enforceWarninglist` (MISP-side), the allowlist file and the own-domains list are for; a hardcoded list inside Nexus would be stale the week after it shipped.
- **Empty result set** and **large drop** — `check_not_empty` and `check_delta` refuse to write an empty, near-empty or sharply shrunken file over a populated one. Both are **skipped under the append-only merge**, which is every path that ships today: the merge cannot remove a row, so a MISP outage produces a file identical to yesterday's rather than an empty one. They are kept, and tested, for the replace-mode path in §14 — not dead, but not reachable from any answer the interview currently offers either.
- **A run that builds nothing** — `check_built_anything` is the append-only branch's replacement for those two, and it counts `rows` (what *this* run built), not the merged total. Skipping the pair left the zero-result case with no guard at all: a token whose permissions return nothing, a filter that matches nothing, no IOC types or no TAXII collections selected all fetch, build nothing, merge nothing and report success — writing a header-only `intel.dat` on a fresh manager, or printing "added 0 new indicators" and applying it on a populated one. It blocks rather than warns, because a warning still writes that file; the merge is append-only, so refusing loses nothing and the non-zero exit shows up in a timer's journal.
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
nexus --profile daily.json --diff      # show the line diff; implies --dry-run
nexus --lint /path/to/intel.dat        # validate a file, no platform needed
nexus --explain --profile daily.json   # print the resolved platform query, fetch nothing
nexus --check-env                      # stage 0 only: paths, __load__.Zeek, SO version
nexus --offline                        # build for transfer, no Security Onion needed
nexus --import /media/usb/intel.dat    # merge one back in, append-only
nexus --install-timer                  # write nexus.service + nexus.timer, on request only
```

`--do-notice` widens the schema to six columns wherever it applies: it forces `config["do_notice"]` on a build, and forces the six-column expectation on `--lint` (which otherwise reads the schema off the file's own `#fields` header). Forcing it onto a file built without it is caught by the header check and blocked, not written.

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
- **Fake TAXII** — `FakeTaxii`/`FakeTaxiiHandler`, serving *both* protocol versions off one socket: 2.1 discovery and envelope pagination, 2.0 discovery and `Range`/`Content-Range` windows, per-API-root collection listings, a root that answers 500, Basic and Bearer auth, and a server that cannot end its own pagination (so the client's stop conditions are what end it).
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
| 7 ✅ | systemd timer, install steps, operator README — `--install-timer` renders and writes `nexus.service`/`nexus.timer` on request only, after pre-flighting the failures that would otherwise surface unattended; enables nothing | offline test suite (701 tests, including that a build never reaches the unit renderer); unverified on a fresh manager |
| 8 ✅ | OpenCTI as a second, independently selectable IOC source — client, mapping, interview branching, config/profile/CLI | offline test suite (537 tests); unverified against a live OpenCTI instance, see `HANDOFF.md` §7 |
| 9 ✅ | Offline build (`--offline`) — build a transfer-ready `intel.dat` on a host with no Security Onion installed, plus `--import PATH` to merge one back into a manager's live file, append-only | offline test suite (537 tests, includes a poison-path assertion that an offline build never touches the real `SO_*` paths, and a byte-identity assertion that import never rewrites an existing row) |
| 10 ✅ | TAXII as a third, independently selectable IOC source — `TaxiiClient` (2.0/2.1, Basic or Bearer), version detection with an asked-not-skipped default, per-API-root collection discovery, pagination for both protocol versions, a STIX indicator flattener, six client-side filters for what TAXII's query syntax cannot express, source-aware interview stages, full wiring, `--probe` | offline test suite (701 tests, includes a fake server serving both protocol versions); unverified against a live TAXII server, see `HANDOFF.md` §7 |

Phases 1–2 are independently useful and fully testable without a Security Onion box. Phase 3 is where the tool becomes what was asked for. Phases 8, 9 and 10 were taken out of numeric order — they landed after phase 6 while phase 7 was still outstanding, since all three are source-neutral and deployment-neutral to what phase 7 covers. Phase 7 closed last, which is why the timer knows about all three sources and about offline profiles.

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
- Specific to TAXII (`docs/superpowers/specs/2026-08-22-taxii-source-design.md` §3, §7): TAXII 1.x, non-indicator STIX objects, and remembered incremental state were all considered and rejected. TAXII 1.x is a different protocol — XML over a different transport, not a version of this one — so supporting it would mean a second client sharing nothing with `TaxiiClient`, not a branch on the existing one. Non-indicator STIX objects (malware, campaigns, relationships, bare observables arriving outside an indicator's pattern) were rejected as a source for the same reason OpenCTI's raw Observables were: they are artifacts someone collected, not verdicts — `flatten_taxii_object` reads only `obj.get("type") == "indicator"` and returns `[]` for everything else. A remembered cursor (the last object seen per collection, so a repeat run pulls only what's new) would trim bandwidth on a slow link, but it introduces persistent run state Nexus has nowhere else to keep, plus recovery behavior for state that goes missing (re-pull everything, the same as not having it), goes stale, or gets corrupted (silently skip a window and never notice) — and the append-only merge already makes a repeated pull harmless, since a re-imported row collapses to nothing under the `(indicator, Intel::Type)` key. `added_after` is instead computed fresh each run from the same days-back answer that already drives MISP's `--days`. This can be revisited if an operator with a genuinely large collection over a genuinely slow link asks for it; it was not needed to ship.

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
