# Nexus — Handoff

Written for a fresh assistant with no prior context. Read this, then `PLAN.md` for the full design.

**Last updated:** 2026-08-22
**State:** phases 0–6 and 8–10 complete, phase 7 remaining. 650 offline tests passing.
**Never yet run against a real MISP, a real OpenCTI, a real TAXII server, or a real Security Onion box.** Everything below was verified against fakes (or, for TAXII, against the specification documents and a fake server -- see §7).

---

## 1. What this is

`nexus.py` is an interactive CLI for a **Security Onion 3.x manager**. It asks which platform to pull from — **MISP, OpenCTI or TAXII, one source per run** — plus that platform's address and credentials, interrogates it for what's actually in it (MISP: attribute types, tags, orgs, feeds; OpenCTI: labels, marking definitions, organisations; TAXII: collections, discovered per API root), walks the operator through a staged interview, pulls matching IOCs from the platform's API, maps them to Zeek Intel framework types, diffs them against the existing `intel.dat`, and appends only genuinely new indicators. It can then apply the result to either a standalone node or a distributed sensor grid via salt and verify Zeek accepted it.

Not a library. Not a package. **One script**, standard library only, so it drops onto an air-gapped manager with no pip install.

### Files

```
nexus.py        5532 lines   the tool
test_nexus.py   6850 lines   650 tests, no MISP, OpenCTI, TAXII or SO required
PLAN.md          ~580 lines  full design doc, section numbers referenced below
HANDOFF.md       ~400 lines  this file (self-referential count omitted -- drifts every time this file is edited)
```

A git repository, currently on branch `taxii-source`. There is no CI — `python3 -m unittest test_nexus` is the only gate.

---

## 2. Run it

```bash
python3 -m unittest test_nexus        # 650 tests, ~40s, needs nothing external
python3 nexus.py --help

python3 nexus.py                      # default: full interview -> writes intel.dat
python3 nexus.py --check-env          # verify SO paths, __load__.Zeek, do_notice
python3 nexus.py --seed               # copy SO default intel files into the local dir
python3 nexus.py --probe --source misp --host HOST      # MISP: per-type IOC counts, write nothing
python3 nexus.py --probe --source opencti --host HOST   # OpenCTI: per-type IOC counts, write nothing
python3 nexus.py --probe --source taxii --host HOST     # TAXII: per-collection object counts (pre-filter), write nothing
python3 nexus.py --lint PATH          # validate an intel.dat
python3 nexus.py --apply              # push existing intel.dat to the grid
python3 nexus.py --explain --profile daily          # show the resolved platform query
python3 nexus.py --profile daily --yes              # unattended
python3 nexus.py --profile daily --dry-run --diff   # build and compare, write nothing
python3 nexus.py --offline --profile ./laptop.json --yes  # build for transfer, on a host with no SO installed
python3 nexus.py --import /media/usb/intel.dat      # merge a transferred file into this manager's intel.dat
python3 nexus.py --import /media/usb/intel.dat --yes  # merge unattended; also applies to the grid
```

`--source {misp,opencti,taxii}` picks the platform; if omitted, the interview asks (stage 1). `--host` is the source-neutral form of the old `--misp` flag, which still works as a **deprecated alias for `--host --source misp`** — existing MISP-only invocations and profiles keep working unchanged.

`--probe` is the cheapest way to test credentials — it needs a token but skips the interview.

**On a workstation, a flagless build now asks instead of bailing.** `cmd_build` first decides offline-vs-manager through `resolve_build_target()` (or a profile's saved `offline` answer) before it looks at the filesystem at all. Only a manager build then calls `ensure_intel_env()` / `check_env()`, which is what bails when `/opt/so/saltstack/local/salt/zeek/policy/intel` is absent. On a machine with no Security Onion, `resolve_build_target()`'s derived default is "offline", so the question can just be answered with Enter; `--offline` skips the question outright and always means "offline" regardless of what's detected. Use `--probe` or `--lint` for something that touches neither the interview nor the filesystem.

---

## 3. Verified ground truth

Do not re-derive these from memory. They were checked against live documentation and several are counter-intuitive.

### Security Onion 3.x

| Fact | Value |
|---|---|
| Manager-side intel file | `/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat` |
| Defaults to seed from | `/opt/so/saltstack/default/salt/zeek/policy/intel/` |
| Runtime path after sync | `/opt/so/conf/zeek/policy/intel/` |
| Apply command | `sudo salt -C 'I@zeek:enabled:true' state.apply zeek` |
| Parse errors | `/nsm/zeek/logs/current/reporter.log` |
| Hits | `/nsm/zeek/logs/current/intel.log` |

Three things that differ from Security Onion 2.4, so 2.4-era answers are wrong:

1. The apply command is the `-C 'I@zeek:enabled:true'` compound target running `state.apply zeek`, **not** a per-minion `state.highstate`.
2. **Intel files are not picked up by Auto State Apply.** The manual apply is mandatory.
3. The local intel directory can be **empty on a fresh install**, and it needs **two** files: `intel.dat` *and* `__load__.Zeek`. Writing `intel.dat` without `__load__.Zeek` produces a file Zeek never reads. The failure looks exactly like success. This is why `check_load_file` is a hard block, not a warning.

### Zeek intel format

```
#fields<TAB>indicator<TAB>indicator_type<TAB>meta.source<TAB>meta.desc<TAB>meta.url
```

Single tab between fields. `-` is the null value. No leading/trailing whitespace, no trailing blank line. The complete `Intel::Type` set is the 11 values in `ZEEK_TYPES`.

Gotchas that silently break matching:

- `Intel::URL` must have the scheme stripped, and Zeek matches host+uri where the uri always starts with `/` — so a pathless indicator can never fire. `norm_url` appends the root slash.
- `Intel::DOMAIN` matches the exact host only. No implicit subdomain coverage.
- `Intel::CERT_HASH` is SHA-1 only. `x509-fingerprint-md5` and `-sha256` are dropped and counted.
- Every indicator is resident in **every** Zeek worker's memory. Retrieval has
  no built-in ceiling, but Nexus warns at high volume and supports an optional
  operator-selected cap; real capacity is bounded by node memory.

### MISP API

`POST /attributes/restSearch` with headers `Authorization: <token>`, `Accept: application/json`, `Content-Type: application/json`.

**`/attributes/restSearch` has no `feed_id` filter.** This single fact shapes the entire feed feature — see §5.

Some endpoints return a bare JSON list, others an envelope. `get_feeds` and `get_sharing_groups` handle both; a bug where they didn't was caught by tests.

### OpenCTI API

Single endpoint: `POST /graphql`, header `Authorization: Bearer <token>`. Everything — version probe, discovery, counts, the indicator search — is one query shape spoken over that one path.

**GraphQL answers HTTP 200 even when it refuses you.** A rejected token comes back as a 200 with an `errors` array in the body, not a 401/403. `OpenctiClient._check_errors` reads that array before any caller touches `data`, and raises `SourceAuthError` when the error carries an auth-shaped code (`AUTH_REQUIRED`, `FORBIDDEN_ACCESS`, `AUTH_FAILURE`, `UNAUTHORIZED`) or an auth-shaped message, `SourceError` otherwise. Skip this check and a bad token looks exactly like an empty result set.

Pagination is cursor-based (`after` / `pageInfo.endCursor` / `hasNextPage`), not page-numbered like MISP. `search_indicators` guards against a proxy or endpoint that ignores `after` and replays the same page: if the returned cursor doesn't advance, it stops and warns instead of looping forever.

Filters use OpenCTI **6.x `FilterGroup` syntax only** — nested `{mode, filters, filterGroups}` — not the flat 5.x filter shape. `build_opencti_filters` is the pure builder for it, the OpenCTI counterpart to `build_search_params`.

**Filters take entity ids, not names.** A label or marking-definition name in the interview has to be resolved to its OpenCTI id before it can go in a filter; discovery builds `name -> id` maps for this. A name with no discovered id is dropped with a `log.warning`, never guessed at or passed through as text.

Counts come from `pageInfo.globalCount`, which — unlike MISP's bounded probe — is an exact total when present. `count_type` falls back to `len(nodes)` from a `first: 1` probe when `globalCount` is absent, and that fallback is still exact (a closed page at `first: 1` has already seen the whole result), which the code documents since it's easy to mistake for a lower bound.

### TAXII API

Everything below is sourced from the TAXII 2.0/2.1 specification documents, not from a live server — nothing in this project has ever exchanged a packet with a real TAXII implementation. See §7 for the full unverified list and first-contact checklist.

`TaxiiClient(host, token, ..., version="2.1", username=None)`. `username` set means Basic (`Authorization: Basic base64(username:token)`); `username` absent means Bearer (`Authorization: Bearer <token>`). **Both** the username and the token/password are secrets — Basic is TAXII's only source needing two — and both are in `PROFILE_EXCLUDED_KEYS`, so neither ever reaches disk. Both are also handed to the redactor, but registration is best-effort for the username: `RedactingFilter.add_secret` ignores anything shorter than 8 characters, so `admin` or `svc` is silently not registered. That floor is deliberate and stays where it is — lowering it globally would scrub common words out of every log line. Nothing puts the username into a log message anyway, and on the wire it is base64-encoded inside the header the redactor covers through the token.

Because `taxii_username` is excluded from profiles, replaying a Basic profile has to find it elsewhere: `cmd_build` reads **`NEXUS_TAXII_USERNAME`**, prompts when interactive, and fails with exit 2 otherwise (`resolve_taxii_username`). It never falls through to Bearer — that downgrade surfaces as a 401 blaming the token, which is the wrong thing to debug. `--profile --yes` against a Basic server therefore needs `NEXUS_TAXII_USERNAME` set in the environment, next to whatever supplies `NEXUS_TOKEN`.

`detect_version()` probes `/taxii2/` (2.1) then `/taxii/` (2.0) and returns whichever answers first; the result becomes the interview's **default** answer, it does not skip the question — the standing no-implicit-default rule applies here too. An auth error during detection propagates as `SourceAuthError` rather than being read as "wrong version, try the other discovery path."

Errors use ordinary HTTP status codes — 401/403 map directly to `TaxiiAuthError`/`TaxiiError`, unlike OpenCTI's GraphQL, which answers 200 even on a rejected token.

Pagination is completely different between versions, and `fetch_objects(collection, added_after=None, max_results=None, page_size=100)` dispatches accordingly:

- **2.1**: an envelope response (`objects`, `more`, `next`), `limit` as a query parameter, cursor-paginated like OpenCTI. A cursor that repeats or goes missing stops the walk with a warning, the same single-cursor guard `OpenctiClient.search_indicators` already carries.
- **2.0**: a STIX bundle response, paged via the `Range` request header / `Content-Range` response header — **there is no `limit` query parameter on this path**; page size only reaches the server through the width of the `Range` window. `_fetch_objects_20` carries six termination guards, not the four originally planned: `Content-Range` absent, a `*` (unknown) total, the last index reaching the total, an empty page, the window failing to advance, and a **pinned first-page total** — a server whose reported total keeps outrunning `last` (items 0-0/2, then 1-1/3, then 2-2/4) would otherwise satisfy every other guard forever. The next window resumes from the server's reported `last + 1`, not from `start + page_size`.

TAXII defines exactly two server-side filters, both always sent: `match[type]=indicator` and `added_after` (computed per run from the interview's days-back answer — see the honesty item in §6). Everything else the interview asks about — labels, markings, confidence, `valid_until`, `created_by_ref` — is applied client-side, after download, by `taxii_object_allowed()`.

`flatten_taxii_object(obj, collection_title=None, stats=None)` is 1:N like `flatten_indicator`, not 1:1 like `flatten_attribute`. Only `type == "indicator"` objects are read; malware, campaigns, relationships and bare observables are context, not verdicts, and are skipped. It unions `labels` and `indicator_types` — STIX 2.1 moved the indicator open-vocabulary to `indicator_types` and made `labels` optional, so reading only `labels` would silently exclude everything on a 2.1 feed that only populates the newer field. **STIX 2.0 has no `confidence` property at all** (added in 2.1); an absent value is carried through as `None`, never coerced to `0` — a real (low) confidence in 2.1 is a legitimate `0`, and treating "absent" the same way would let a minimum-confidence filter silently drop every object from a 2.0 feed. `taxii_object_allowed()` only compares confidence when both the filter's minimum and the record's value are not `None`.

`render_meta` takes a `{collection}` placeholder; `TAXII_SOURCE_FORMATS` makes `TAXII-{collection}` the stage-7 default `meta.source` for a TAXII run, mirroring `MISP-feed-<slug>`.

---

## 4. Architecture

One file, banner-delimited sections in dependency order (line numbers omitted
-- they drift every time a section above them grows; regenerate on demand
with `grep -n '^# [A-Z]' nexus.py`):

```
CONSTANTS   SO paths, ZEEK_TYPES, MISP_TO_ZEEK / OPENCTI_TO_ZEEK mapping,
            TAXII_VERSIONS / TAXII_DISCOVERY / TAXII_ACCEPT, thresholds
LOGGING     RedactingFilter + RedactingFormatter (token scrubbing)
CLIENT      _HttpTransport (shared base; _request takes extra_headers=None,
            used by TAXII 2.0's Range pagination), MispClient, OpenctiClient,
            TaxiiClient (2.0/2.1, Basic or Bearer), NoCrossHostRedirect,
            SourceError/SourceAuthError (MispError/MispAuthError are
            aliases; TaxiiError/TaxiiAuthError are TAXII's own subclasses),
            flatten_attribute, flatten_indicator, flatten_taxii_object,
            parse_stix_pattern
FEEDS       feed_provenance, apply_feed_to_params  (MISP only — OpenCTI and
            TAXII have no feed concept)
MAPPING     map_attribute — source type -> Zeek type, composite splitting;
            table-driven over MISP_TO_ZEEK or OPENCTI_TO_ZEEK (TAXII reuses
            OPENCTI_TO_ZEEK — parse_stix_pattern already emits its keys)
NORMALISE   norm_addr/subnet/domain/url/hash/email/..., sanitize_meta
FILTERS     ExclusionSet — private IPs, own networks/domains, allowlist;
            taxii_object_allowed — the six client-side filters for what
            TAXII's query syntax cannot express (include/exclude labels,
            markings, authors, min confidence, valid_until)
INTEL       build/render/lint/read/merge_additive/backup/write_atomic;
            render_meta's source_fmt template also takes {collection} for
            TAXII (TAXII_SOURCE_FORMATS defaults meta.source to
            TAXII-{collection})
CHECKENV    check_env + notice_policy_loaded — stage 0 on a manager;
            check_output_target — the off-box counterpart for an offline
            build, same (ok, findings) shape, no Security Onion question
GUARDRAILS  check_size/not_empty/delta/load_file/broad, run_guardrails
INTERVIEW   ask* primitives, discover (MISP) / discover_opencti /
            discover_taxii, build_search_params (MISP) /
            build_opencti_filters (OpenCTI), _stage1_connection (branches
            on source for TAXII's version-detection and Basic/Bearer
            questions), _stage_feeds, _stage3_iocs shared across MISP and
            OpenCTI; _stage3_collections_taxii stands in for it on TAXII
            (collection choice, not a type menu — match[type]=indicator
            already narrows every collection); _stage4_quality/_stage5_scope
            have an `_opencti` sibling each, _stage5_scope_taxii stands in
            for both on TAXII (the one server-side time filter plus the six
            client-side-and-said-so-in-the-prompt filters), and
            run_interview picks by source; taxii_added_after turns the
            days-back answer into the added_after query param;
            run_interview ties the stages together; resolve_build_target
            decides offline-vs-manager, asked before check_env() so it
            also governs whether check_env() runs at all
PROFILES    save_profile, load_profile (JSON, 0600, profile v2 with a v1
            reader that migrates the old MISP-only keys forward in memory)
DIFF        indicator_delta, summarise_delta, unified_intel_diff
APPLY       seed_load_file, salt_apply, log_errors_since, apply_to_grid,
            print_transfer_instructions — the two manager-side routes
            (--import vs. hand-placing the file) for an offline build
MAIN        argparse (--import's dest is "import_file", since import is a
            Python keyword; --source now accepts "taxii"), cmd_* dispatch
            (client factory picks Misp/Opencti/TaxiiClient from
            config["source"]), cmd_probe branches per source
            (_cmd_probe_misp/_opencti/_taxii — TAXII's reports per-collection
            object counts, explicitly pre-filter), ensure_intel_env — the
            check_env()-plus-seed shared by cmd_build and cmd_import,
            _report_guardrails/_report_lint/_report_dry_run — the
            print-and-block ceremonies extracted out of cmd_build and
            cmd_import once they'd copy-pasted them (the lint message had
            already drifted between the two, "rendered" vs "merged" file),
            cmd_build orchestration, cmd_import (merge into a manager's
            live intel.dat, append-only)
```

The `CLIENT` section holds all three clients and all three flatteners; its banner was renamed from `# MISP CLIENT` when `OpenctiClient` landed, and stayed `CLIENT` when `TaxiiClient` did.

### Rules the code holds to — preserve these

- **Stdlib only.** No pip, no venv, no new dependencies. Ever.
- **Python 3.6+ syntax.** No f-strings, no type hints, no dataclasses, no walrus. `%`-formatting throughout. The manager's Python version is unconfirmed, so the floor stays low.
- **Purity where it matters.** `mapping`, `normalise`, `filters`, `intel`, `guardrails`, `diff`, `build_search_params`, `build_opencti_filters` touch no network and no filesystem. That is what makes 650 tests runnable with nothing installed. Do not put I/O in them.
- **Every prompt takes `input_fn`** (and `getpass_fn` for the token), defaulting to the real thing. No test may block on a TTY.
- **Only `write_atomic` writes the intel file.** Same-directory temp, fsync, `os.replace`.
- **Updates are append-only by indicator key.** Every existing `(indicator,
  Intel::Type)` row is retained byte-for-byte; Nexus appends only keys not
  already present. Atomic replacement is an implementation detail for crash
  safety and must never become logical replacement/deletion behavior.
- **Comments explain WHY, not what.** Match the surrounding density.

---

## 5. Decisions already made — do not relitigate without asking

These were explicitly chosen by the user (2026-08-16) after being presented with alternatives.

**Feed selection** (`PLAN.md` §4b). Since restSearch has no `feed_id`, a feed is only recoverable through the trace it leaves once ingested, most precise first:

| Provenance | Feed field | Filter used |
|---|---|---|
| Fixed event | `fixed_event=1` + `event_id` | `eventid` |
| Default tag | `tag_id` → tag name | `tags.OR` |
| Creator org | `orgc_id` | `org` |

- A feed with **none** of the three is untraceable after ingest. It is **listed but blocked**, with the reason printed. Chosen over hiding it or silently falling back.
- **One restSearch query per feed**, results merged. Two feeds identified by different mechanisms cannot share one query body. `build_indicators` dedupes across them; first feed wins.
- **One combined `intel.dat`**, not one file per feed — SO's `__load__.Zeek` loads `intel.dat` specifically. `meta.source` becomes `MISP-feed-<slug>` so an `intel.log` hit names its origin.
- Feed choice **ANDs** with all other filters.
- **Tag-feed caveat:** `tags.OR` is a disjunction, so a feed's tag and the operator's include-tags cannot both be *required* in one body. The feed tag goes to MISP; include-tags are applied client-side in `_fetch_records`. Feeds identified by event or org keep include-tags server-side. Both paths tested.

**OpenCTI as a second source** (spec §2, chosen by the operator 2026-08-17):

| Decision | Chosen | Rejected |
|---|---|---|
| Source model | One source per run | Both merged in one run; OpenCTI replacing MISP |
| OpenCTI entities | Indicators only, values from their linked observables | Observables only; both with an interview toggle |
| Filter depth | Full parity with the MISP interview | Core filters only; types plus score only |
| OpenCTI version | 6.x `FilterGroup` syntax only | 5.x flat filters; runtime detection of both |
| Naming | Neutral shared spine, source-specific edges, profile v1 migrated forward | Parallel per-source keys; neutral rename with no back-compat |

`intel.dat` is already append-only by `(indicator, Intel::Type)`, so a MISP profile and an OpenCTI profile run as two separate timer units converge into one file with no new merge code, no cross-source dedupe path and no combined query planner — that is why one-source-per-run cost nothing to choose. Indicators-only was chosen because OpenCTI observables are artifacts anyone enriched, not verdicts, and routinely include benign infrastructure; indicators carry the quality signals (`x_opencti_score`, `confidence`, `x_opencti_detection`, `revoked`, `valid_until`) that keep `intel.dat` from arming Zeek against the operator's own resolvers.

**Other standing decisions**

- Default posture for applying is **print the command, don't run it**. The apply prompt defaults to no.
- `--yes` seeds `__load__.Zeek` without asking, because the alternative is an unattended run writing a file Zeek never loads. If the user wants it to refuse and alert instead, that is a one-line change.
- Guardrail `.ok` is `False` only on `block`. A `warn` verdict stays truthy.
- IOC retrieval is unlimited by default. If the operator sets a cap,
  `check_size` blocks at `count > cap`; exactly-at-cap warns.
- Pagination has no built-in page ceiling. A repeated-page signature stops a
  MISP or proxy that ignores `page` from looping forever.
- `check_env()` checks both `__load__.Zeek` and whether an active policy loads
  `policy/frameworks/intel/do_notice.zeek`. Missing `__load__.Zeek` blocks;
  missing `do_notice.zeek` warns because the metadata column would have no effect.
- The interview records `deployment=standalone|distributed`; apply prompts and
  output use the selected topology. Older profiles default to distributed.
- `intel.dat` is append-only by `(indicator, Intel::Type)`. Existing rows and
  metadata win, only new keys are added, and any computed removal is a hard
  invariant failure. There is no replace mode.
- **`--import --yes` applies to the grid; a default build's `--yes` does not**,
  unless the replayed profile itself set `apply`. This is deliberate, not an
  inconsistency: an import has no profile to consult, so `--yes` alone is the
  only signal available, and an operator running it unattended from a USB
  stick wants the merged file live. `cmd_build`'s `--yes` only replays what
  the profile already decided (`config["apply"] = config.get("apply", False)`).
  No `--no-apply` flag was added to make the two symmetrical; the asymmetry
  is documented in `--help` on `--import` instead.

---

## 6. Non-obvious things that will bite you

- **`ipaddress.is_private` is broader than RFC1918.** It includes the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`. Correct to exclude from threat intel, but it means example addresses get dropped — tests must use genuinely routable addresses like `45.33.32.0/24`. This already cost one debugging round.
- **Logging filters run before formatting**, so `record.exc_text` is `None` at filter time. Token redaction therefore lives in `RedactingFormatter`, not only in `RedactingFilter`. Do not "simplify" it back.
- **urllib forwards all headers across redirects**, including `Authorization`. `NoCrossHostRedirect` blocks cross-host 3xx. Do not remove it.
- **A clean `salt state.apply` proves nothing.** Zeek rejects a bad intel file through `reporter.log`, not by failing the salt run. `apply_to_grid` records the log's byte offset *before* applying, so old errors can't fail today's run and today's can't hide in noise.
- **`sha224` is 56 hex chars.** It was missing from `VALID_HASH_LENGTHS`, silently dropping every sha224 IOC. There is now a `hashlib` round-trip test over all six hash algorithms — keep it.
- **`old[:-0]` is `[]`**, so a naive retention-0 backup prune deletes nothing. Guarded.
- Salt is invoked as an **argv list, never a shell string**. The compound target contains quotes.
- Append-only still uses `os.replace()` to publish the complete combined file
  atomically. That filesystem operation is crash protection, not permission to
  remove or rewrite existing indicator rows.
- Changing the `meta.do_notice` schema of an existing file would require
  rewriting old rows. Nexus blocks that mismatch to preserve append-only behavior.
- **Hand-placing an offline-built file replaces rather than merges.** Copying
  an offline-built `intel.dat` into place by hand (`sudo cp ... /opt/so/.../intel/`)
  is a deliberately supported route, with no guardrails and no merge: on a
  manager that has been running, it drops every indicator not in the
  transferred file. `--import` merges; `cp` does not. Both routes are printed
  by `print_transfer_instructions`, and the hand-copy route says so at the
  point of use. It stays supported anyway, because an operator who cannot run
  Python on the manager has no other route in.
- **Offline builds keep their backups and their profile beside the output
  file, not under `/opt/nexus`.** `/opt/nexus` is a manager-only directory; it
  does not exist and is not writable on an arbitrary offline host. Under
  `--offline` the interview defaults the profile to the output directory and
  `cmd_build` backs up to `nexus-backups/` next to the output file, same
  retention count. Without this, a second offline build over the same output
  path used to crash in `os.makedirs` and the default profile save died the
  same way. Because an offline profile is a path rather than a bare name,
  replay it as `--profile ./laptop.json`, not `--profile laptop` (a bare name
  always resolves under `/opt/nexus/profiles`). `cmd_import` (which only ever
  runs on a manager) still uses `/opt/nexus/backups`.
- **"Append-only" does not currently cover operator comment lines.** `read_existing`
  filters out any line in the live `intel.dat` that starts with `#` (other than
  the `#fields` header), so a hand-written `#` comment does not survive a
  merge in `cmd_build` or `cmd_import`. This is pre-existing behavior, not
  something offline build or `--import` introduced, but it is a real limit on
  the append-only guarantee stated elsewhere in this document.
- **GraphQL answers HTTP 200 on auth failure.** A rejected OpenCTI token arrives as a 200 with an `errors` array, not a 401/403. Unhandled, that is indistinguishable from an empty result set, and a scheduled run would report "0 new indicators" forever instead of failing loudly. `_check_errors` runs before any caller reads `data`.
- **`strptime`'s `%z` didn't accept a colon in the UTC offset until Python 3.7.** This project's floor is 3.6, so OpenCTI's `...Z` timestamps are normalised to `+0000` (colon-free) before parsing. Without this, every OpenCTI timestamp would silently parse to `""` on 3.6 while a 3.9-or-later test run stayed green and never caught it.
- **OpenCTI 6.x filters take entity ids, not names.** Discovery builds `name -> id` maps for labels, marking definitions and organisations; a name with no discovered id is dropped with a warning, never guessed at or passed through as text.
- **Certificate hashes need their own `X509-` mapping keys.** `OPENCTI_TO_ZEEK["X509-SHA-1"]` is a separate key from `["SHA-1"]` — without the prefix a certificate SHA-1 would land in `Intel::FILE_HASH` instead of `Intel::CERT_HASH`.
- **Non-STIX pattern types are never mined for values.** `parse_stix_pattern` only runs for `pattern_type == "stix"`; a YARA or Sigma rule's string literals are not treated as indicators.
- **The interview's hostname question is type-name-sensitive per source.** It drops the literal `"Hostname"` on OpenCTI but `"hostname"` on MISP — the two platforms spell the type differently. Before this was fixed, an OpenCTI operator answering "no" to "treat hostnames as domains" still got hostname indicators, silently, because the MISP-only literal never matched.
- **`meta.url` is source-aware.** OpenCTI indicators link to `{base}/dashboard/observations/indicators/{id}`; the MISP event URL shape (`{base}/events/view/{id}`) is unchanged. `render_meta` branches on the record's source rather than assuming one URL template — though the stage 7 *question wording* ("Link meta.url back to the MISP event?") and the `meta.source` presets (`SOURCE_FORMATS`, defaulting to `MISP-event-{event_id}`) are still MISP-labelled on an OpenCTI run, a known cosmetic gap recorded at `PLAN.md` §4 item 31.
- **TAXII filters most scoping AFTER download, not on the server.** TAXII's query syntax reaches exactly two things: `match[type]=indicator` and `added_after`. Nexus pushes fifteen filter parameters into a MISP `restSearch` body or an OpenCTI `FilterGroup`; against TAXII, `include_labels`, `exclude_labels`, `include_markings`, `include_authors`, `min_confidence` and `drop_expired` are all applied client-side in `taxii_object_allowed()`, after every object in the time window has already been downloaded. An operator used to MISP will expect `include_labels` to reduce transfer volume the way `tags.OR` does. **It does not.** Stage 5 says so in its own prompt text ("applied after download") so an interactive operator sees it live; this entry is the same fact for whoever is reading code instead of prompts.
- **`--probe`'s TAXII counts are pre-filter.** The server cannot count a filtered subset — TAXII has no query for labels, markings, confidence, validity or author — so a probe number means "objects in this collection" (bounded by `--probe-limit`, default 5000, marked with a trailing `+` when the cap was hit), not "indicators you will actually get" once stage 5's client-side filters run. `_cmd_probe_taxii` prints this caveat directly under its table.
- **STIX 2.0 has no `confidence` property at all.** It arrived in STIX 2.1. `flatten_taxii_object` carries an absent confidence through as `obj.get("confidence")` — `None`, never coerced to `0` — because `0` is a real, valid (low) confidence value in 2.1, and treating "absent" the same way would let a minimum-confidence filter silently drop every object from a 2.0 feed. `taxii_object_allowed()` only compares confidence when both the configured minimum and the record's value are not `None`, and stage 5 warns explicitly in its own text when the detected TAXII version is 2.0.

---

## 7. What is left

### Phase 7 — the only incomplete phase

- A systemd `nexus.service` + `nexus.timer` (not cron — failures should land in the journal).
- Install steps: place at `/usr/local/bin/nexus`, `chmod 750`, root-owned; create `/opt/nexus/{profiles,backups,logs}`.
- An operator README distinct from `PLAN.md`.

### Open questions for the user — none are blocking, all affect phase 7

1. Run `python3 nexus.py --check-env` on the real manager to confirm the local
   `__load__.Zeek`, runtime paths, and `do_notice.zeek` policy state. The code
   performs these checks, but the target box has not been observed yet.
2. Exact 3.x point release, and whether anything else already manages that file.
3. Expected indicator volume and available RAM per Zeek worker. Nexus imposes
   no default ceiling, but Zeek's in-memory Intel framework remains the real limit.

### Flagged as version-dependent, unverified

`threat_level_id` and `analysis` are emitted into the restSearch body by `build_search_params`, but support for them on `/attributes/restSearch` is MISP-version-dependent and was **not** in the verified parameter list. If those interview answers appear to do nothing, this is why. Confirm against the live instance.

### Flagged as unverified, OpenCTI

> **Status: live validation deferred.** As of 2026-08-21 the operator has no OpenCTI
> instance available to test against, and has deliberately postponed this. The OpenCTI
> code path is complete, unit-tested (650 tests, all sources) and reviewed, but **no part
> of it has ever exchanged a packet with a real OpenCTI server.** Treat it as untested in
> production until the checklist below has been run. This is a known, accepted gap — not
> an oversight to re-flag.

Nothing in this project has ever run against a real OpenCTI instance. None of these six block what has already shipped, and each is a contained fix — a few lines in one function, not a redesign.

1. **`x_opencti_detection` as a filter key.** The field exists on Indicator; whether it is filterable is the open question. If not, the detection requirement moves to a client-side filter in the fetch loop.
2. **`objectLabel` / `objectMarking` return shape.** The flattener assumes bare lists, which is 6.x behaviour. 5.x returned `edges { node { ... } }`; if some 6.x point release differs, the flattener needs the edges walk added back.
3. **Label filtering by id versus value.** The interview translates label/marking names to ids via discovery. Some builds may accept values directly, in which case the discovery id map becomes optional rather than required.
4. **`globalCount` under the operator's auth level.** `count_type` falls back to a bounded, still-exact count when `globalCount` is absent (see §3), but the interview's count annotations get less useful without it.
5. **Rate limiting on a large paginated pull.** The existing retry/backoff handles 429, but OpenCTI's actual ceiling and page-size sweet spot are unknown. Default page size is 100 (smaller than MISP's) and is tunable via `page_size`.
6. **OpenCTI version and reachability from the manager.** Same pre-flight class as the outstanding `--check-env` run against the real Security Onion box — nobody has pointed this code at a live OpenCTI yet.

#### First-contact checklist — run this when an OpenCTI instance becomes available

Do these in order. Each step is designed to fail cheaply and locally, before anything
writes an `intel.dat`. Nothing here needs a Security Onion box.

1. `python3 nexus.py --probe --source opencti --host <HOST>` — proves reachability, auth,
   the `Authorization: Bearer` header, and `get_version()`. A wrong token returns HTTP
   200 with the error in the body, so confirm it reports an auth failure rather than
   succeeding emptily. Deliberately try a bad token once to check that.
2. Confirm the probe's per-type counts are non-zero and plausible. Zero everywhere with a
   successful connection points at item 1 above (`x_opencti_detection` not filterable) or
   item 3 (label ids versus values).
3. Check whether the counts are reported as exact. If `globalCount` is unavailable at the
   operator's auth level (item 4), the annotations degrade but the fetch still works.
4. Run a full interview and let it complete to a `--dry-run` build. Watch stage 2's
   discovery lists — empty label, marking or organization lists mean discovery is not
   returning what the filter builder expects (items 2 and 3).
5. Inspect the dry-run's unmapped/skipped counters in the run report. A large
   `pattern unparseable` count means real-world patterns differ from the STIX shapes
   `parse_stix_pattern` handles; capture a few offending patterns verbatim before changing
   anything.
6. Only then do a real build, against a scratch output path first (`--offline` with an
   explicit output path), and diff it by hand before it goes near a manager.

Record what each step actually returned. Several items above become moot the moment real
responses are observed, and the list should shrink rather than be carried forward intact.

### Flagged as unverified, TAXII

> **Status: never run against a real server.** Every protocol claim below comes from the
> TAXII 2.0 and 2.1 specification documents, not from a server this project has exchanged
> a packet with. The TAXII code path is complete, unit-tested (650 tests, all three
> sources) and reviewed against a fake server implementing both protocol versions, but
> **no part of it has ever talked to a real TAXII implementation.** Treat it as untested
> in production until the checklist below has been run. This is a known, accepted gap —
> not an oversight to re-flag.

Six items come from the design spec's own §12; two more surfaced during implementation and are not
in the spec. None block what has already shipped, and each is a contained fix.

1. **The `/taxii2/` then `/taxii/` probe order**, and whether servers reliably answer the
   version they actually implement.
2. **TAXII 2.0's `Range`/`Content-Range` pagination** — materially different from 2.1's
   `more`/`next`, and the most likely place the client is wrong. Six termination guards
   protect it (§3), all unverified against a real response.
3. **Whether real servers honour `match[type]=indicator`**, or return every object type
   and expect the client to filter.
4. **Whether `added_after` is inclusive or exclusive at the boundary.**
5. **The 2.0 confidence gap** — that absent `confidence` is genuinely absent on the wire,
   rather than defaulted by some server to a value Nexus would need to treat differently.
6. **Basic auth in practice**, including whether servers challenge with `WWW-Authenticate`
   before accepting a pre-emptive `Authorization: Basic` header.
7. **Found during implementation, not in the spec:** the 2.0 path's next window resumes
   from the server's reported `last + 1`, not from `start + page_size`. If a server's
   `Content-Range` disagrees with what it actually sent, the next request's window could
   be wrong in a way the fake server cannot expose.
8. **Found during implementation, not in the spec:** `page_size` only reaches a TAXII 2.0
   server through the width of the `Range` header's window — there is no `limit` query
   parameter on that path (2.1's `fetch_objects` does send one). A server that ignores
   `Range` gets no page-size hint at all, and how such a server behaves is unknown.

#### First-contact checklist — run this when a TAXII server becomes available

1. `python3 nexus.py --probe --source taxii --host <HOST>` — proves reachability, version
   detection, and whichever auth scheme was configured. Try a bad token or password once
   to confirm it reports an authentication failure (401/403) rather than an empty
   collection list succeeding quietly.
2. Confirm the collections list is non-empty and the printed object counts look plausible.
   Zero everywhere with a successful connection points at item 3 above (`match[type]` not
   honoured) or an API-root permission problem that discovery is silently swallowing.
3. Run a full interview through to a `--dry-run` build. Confirm the TAXII-version
   question's *default* matches what step 1 detected — the default should be right even
   though the question is still asked.
4. If the server turns out to speak TAXII 2.0, confirm stage 5's "no confidence property"
   warning appears, and that answering a minimum-confidence question does not drop
   everything (item 5).
5. Inspect the dry-run's unmapped/skipped counters in the run report. A large "pattern
   unparseable" count means real-world STIX patterns differ from what `parse_stix_pattern`
   handles; capture a few offending patterns verbatim before changing anything.
6. Let a pull run past one page, on a 2.0 collection and a 2.1 collection if both are
   reachable, to exercise items 2, 7 and 8 for real rather than only against the fake
   server.
7. Only then do a real build, against a scratch output path first (`--offline` with an
   explicit output path), and diff it by hand before it goes near a manager.

**Accepted risk: an uncooperative TAXII 2.1 server could pull forever.** If a server
issues a fresh cursor on every page, keeps setting `more: true`, and keeps returning
*non-empty* pages, `fetch_objects`'s single-cursor-repeat guard never fires and the pull
continues until `max_indicators` stops it — unbounded by default. TAXII 2.1 carries no
`total` to pin the way the 2.0 path pins `first_total` (§3), and `more: false` is the
protocol's own termination signal, so the only additional honest protection would be a
page cap. It was deliberately not added: this project has already removed dead parameters
for being unused, and the `max_pages` argument that exists on both `search_attributes`
and `search_indicators` is exercised only by tests today, never by a real caller. If an
operator hits this in practice, `max_indicators` is the immediate mitigation; a real page
cap is the fix, added then rather than speculatively now.

The *empty*-page variant of that shape is not an accepted risk and is now guarded. A
server answering `{"objects": [], "more": true, "next": "<fresh cursor>"}` yields no
record, so `max_indicators` — which counts records — is never consulted and cannot bound
anything (measured: 828,493 requests in three seconds with a cap of five set). `if not
objects: return` in the 2.1 loop ends it on the first empty page, exactly as
`_fetch_objects_20` has always done.

### Explicitly out of scope (`PLAN.md` §14)

Indicator aging/expiry, multiple MISP instances, Suricata rule generation, an Elastic feedback loop to prune indicators that never fire, event-level pull for richer descriptions, PyMISP as an optional backend. Specific to OpenCTI: dual-source runs, OpenCTI observables as a source, 5.x filter syntax, writing anything back to OpenCTI, connectors/streams/live-stream API, relationship traversal for richer descriptions. Specific to TAXII: TAXII 1.x (a different protocol, not a version of this one), non-indicator STIX objects (malware, campaigns, relationships, bare observables — context, not verdicts), and remembered incremental state (a per-collection last-cursor) — see `PLAN.md` §14 for the reasoning behind each.

---

## 8. Working style the user expects

- Verify claims by running code, not by asserting them. Several real bugs in this codebase were found by executing the suspect case before trusting a review.
- Report failures plainly with the output. Do not claim something works that has not been run.
- Prefer the smallest change that actually fixes the root cause, but never trade away input validation, error handling that prevents data loss, or security measures for brevity.
- Every non-trivial change lands with a test that fails without it.
- The user runs subagents when they ask for them, with this session as orchestrator. Do not spawn them unprompted.
