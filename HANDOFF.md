# Nexus — Handoff

Written for a fresh assistant with no prior context. Read this, then `PLAN.md` for the full design.

**Last updated:** 2026-08-22
**State:** phases 0–6, 8 and 9 complete, phase 7 remaining. 537 offline tests passing.
**Never yet run against a real MISP, a real OpenCTI, or a real Security Onion box.** Everything below was verified against fakes.

---

## 1. What this is

`nexus.py` is an interactive CLI for a **Security Onion 3.x manager**. It asks which platform to pull from — **MISP or OpenCTI, one source per run** — plus that platform's address and API token, interrogates it for what's actually in it (MISP: attribute types, tags, orgs, feeds; OpenCTI: labels, marking definitions, organisations), walks the operator through a staged interview, pulls matching IOCs from the platform's API, maps them to Zeek Intel framework types, diffs them against the existing `intel.dat`, and appends only genuinely new indicators. It can then apply the result to either a standalone node or a distributed sensor grid via salt and verify Zeek accepted it.

Not a library. Not a package. **One script**, standard library only, so it drops onto an air-gapped manager with no pip install.

### Files

```
nexus.py        4781 lines   the tool
test_nexus.py   5302 lines   537 tests, no MISP, OpenCTI or SO required
PLAN.md          555 lines   full design doc, section numbers referenced below
HANDOFF.md       ~350 lines   this file (self-referential count omitted -- drifts every time this file is edited)
```

A git repository, currently on branch `offline-build`. There is no CI — `python3 -m unittest test_nexus` is the only gate.

---

## 2. Run it

```bash
python3 -m unittest test_nexus        # 537 tests, ~20s, needs nothing external
python3 nexus.py --help

python3 nexus.py                      # default: full interview -> writes intel.dat
python3 nexus.py --check-env          # verify SO paths, __load__.Zeek, do_notice
python3 nexus.py --seed               # copy SO default intel files into the local dir
python3 nexus.py --probe --source misp --host HOST      # MISP: per-type IOC counts, write nothing
python3 nexus.py --probe --source opencti --host HOST   # OpenCTI: per-type IOC counts, write nothing
python3 nexus.py --lint PATH          # validate an intel.dat
python3 nexus.py --apply              # push existing intel.dat to the grid
python3 nexus.py --explain --profile daily          # show the resolved platform query
python3 nexus.py --profile daily --yes              # unattended
python3 nexus.py --profile daily --dry-run --diff   # build and compare, write nothing
python3 nexus.py --offline --profile ./laptop.json --yes  # build for transfer, on a host with no SO installed
python3 nexus.py --import /media/usb/intel.dat      # merge a transferred file into this manager's intel.dat
python3 nexus.py --import /media/usb/intel.dat --yes  # merge unattended; also applies to the grid
```

`--source {misp,opencti}` picks the platform; if omitted, the interview asks (stage 1). `--host` is the source-neutral form of the old `--misp` flag, which still works as a **deprecated alias for `--host --source misp`** — existing MISP-only invocations and profiles keep working unchanged.

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

---

## 4. Architecture

One file, banner-delimited sections in dependency order (line numbers omitted
-- they drift every time a section above them grows; regenerate on demand
with `grep -n '^# [A-Z]' nexus.py`):

```
CONSTANTS   SO paths, ZEEK_TYPES, MISP_TO_ZEEK / OPENCTI_TO_ZEEK mapping, thresholds
LOGGING     RedactingFilter + RedactingFormatter (token scrubbing)
CLIENT      _HttpTransport (shared base), MispClient, OpenctiClient,
            NoCrossHostRedirect, SourceError/SourceAuthError (MispError/
            MispAuthError are aliases), flatten_attribute, flatten_indicator,
            parse_stix_pattern
FEEDS       feed_provenance, apply_feed_to_params  (MISP only — OpenCTI has
            no feed concept)
MAPPING     map_attribute — source type -> Zeek type, composite splitting;
            table-driven over MISP_TO_ZEEK or OPENCTI_TO_ZEEK
NORMALISE   norm_addr/subnet/domain/url/hash/email/..., sanitize_meta
FILTERS     ExclusionSet — private IPs, own networks/domains, allowlist
INTEL       build/render/lint/read/merge_additive/backup/write_atomic
CHECKENV    check_env + notice_policy_loaded — stage 0 on a manager;
            check_output_target — the off-box counterpart for an offline
            build, same (ok, findings) shape, no Security Onion question
GUARDRAILS  check_size/not_empty/delta/load_file/broad, run_guardrails
INTERVIEW   ask* primitives, discover (MISP) / discover_opencti,
            build_search_params (MISP) / build_opencti_filters (OpenCTI),
            _stage1_connection, _stage_feeds, _stage3_iocs shared across
            sources; _stage4_quality/_stage5_scope have an `_opencti`
            sibling each and run_interview picks the pair by source;
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
            Python keyword), cmd_* dispatch (client factory picks Misp/
            OpenctiClient from config["source"]), ensure_intel_env — the
            check_env()-plus-seed shared by cmd_build and cmd_import,
            _report_guardrails/_report_lint/_report_dry_run — the
            print-and-block ceremonies extracted out of cmd_build and
            cmd_import once they'd copy-pasted them (the lint message had
            already drifted between the two, "rendered" vs "merged" file),
            cmd_build orchestration, cmd_import (merge into a manager's
            live intel.dat, append-only)
```

The `CLIENT` section holds both clients and both flatteners; its banner was renamed from `# MISP CLIENT` when `OpenctiClient` landed.

### Rules the code holds to — preserve these

- **Stdlib only.** No pip, no venv, no new dependencies. Ever.
- **Python 3.6+ syntax.** No f-strings, no type hints, no dataclasses, no walrus. `%`-formatting throughout. The manager's Python version is unconfirmed, so the floor stays low.
- **Purity where it matters.** `mapping`, `normalise`, `filters`, `intel`, `guardrails`, `diff`, `build_search_params`, `build_opencti_filters` touch no network and no filesystem. That is what makes 537 tests runnable with nothing installed. Do not put I/O in them.
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
> code path is complete, unit-tested (537 tests, all sources) and reviewed, but **no part
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

### Explicitly out of scope (`PLAN.md` §14)

Indicator aging/expiry, multiple MISP instances, Suricata rule generation, an Elastic feedback loop to prune indicators that never fire, event-level pull for richer descriptions, PyMISP as an optional backend. Specific to OpenCTI: dual-source runs, OpenCTI observables as a source, 5.x filter syntax, writing anything back to OpenCTI, connectors/streams/live-stream API, relationship traversal for richer descriptions.

---

## 8. Working style the user expects

- Verify claims by running code, not by asserting them. Several real bugs in this codebase were found by executing the suspect case before trusting a review.
- Report failures plainly with the output. Do not claim something works that has not been run.
- Prefer the smallest change that actually fixes the root cause, but never trade away input validation, error handling that prevents data loss, or security measures for brevity.
- Every non-trivial change lands with a test that fails without it.
- The user runs subagents when they ask for them, with this session as orchestrator. Do not spawn them unprompted.
