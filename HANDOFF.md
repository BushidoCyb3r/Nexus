# Nexus — Handoff

Written for a fresh assistant with no prior context. Read this, then `PLAN.md` for the full design.

**Last updated:** 2026-08-24
**State:** all phases complete (0–10). 742 offline tests passing. Five whole-repo audits run, the latest 2026-08-25 (§7).
**Never yet run against a real MISP, a real OpenCTI, a real TAXII server, or a real Security Onion box.** Everything below was verified against fakes (or, for TAXII, against the specification documents and a fake server -- see §7).

---

## 1. What this is

`nexus.py` is an interactive CLI for a **Security Onion 3.x manager**. It asks which platform to pull from — **MISP, OpenCTI or TAXII, one source per run** — plus that platform's address and credentials, interrogates it for what's actually in it (MISP: attribute types, tags, orgs, feeds; OpenCTI: labels, marking definitions, organisations; TAXII: collections, discovered per API root), walks the operator through a staged interview, pulls matching IOCs from the platform's API, maps them to Zeek Intel framework types, diffs them against the existing `intel.dat`, and appends only genuinely new indicators. It can then apply the result to either a standalone node or a distributed sensor grid via salt and verify Zeek accepted it.

Not a library. Not a package. **One script**, standard library only, so it drops onto an air-gapped manager with no pip install.

### Files

```
nexus.py        ~6210 lines  the tool
test_nexus.py   ~7835 lines  742 tests, no MISP, OpenCTI, TAXII or SO required
PLAN.md          ~630 lines  full design doc, section numbers referenced below
README.md        ~250 lines  the operator-facing doc; PLAN.md is the designer-facing one
HANDOFF.md        ~980 lines  this file (self-referential count omitted -- drifts every time this file is edited)
```

A git repository, currently on `main`. There is no CI — `python3 -m unittest test_nexus` is the only gate.

---

## 2. Run it

```bash
python3 -m unittest test_nexus        # 742 tests, ~45s, needs nothing external
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
python3 nexus.py --install-timer      # write a systemd service + timer for a saved profile, on request only
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

`detect_version()` probes `/taxii2/` (2.1) then `/taxii/` (2.0) and returns whichever answers first, leaving `self.version` set to it. The question in stage 1 is still asked and defaults to 2.1, because stage 1 is what collects the credential and has no client to detect with yet; `run_interview` detects at the stage 2 connect instead, and says so on stdout when the server disagrees with the answer (see §6). An auth error during detection propagates as `SourceAuthError` rather than being read as "wrong version, try the other discovery path."

Errors use ordinary HTTP status codes — the transport's own 401/403 handling raises `SourceAuthError` before any TAXII code runs, unlike OpenCTI's GraphQL, which answers 200 even on a rejected token. `TaxiiError` covers the protocol-level failures the client raises itself (an unsupported version, no discovery endpoint); there is no TAXII-specific auth exception, because nothing would ever raise one.

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
            aliases; TaxiiError is TAXII's own subclass),
            flatten_attribute, flatten_indicator, flatten_taxii_object,
            parse_stix_pattern
FEEDS       feed_provenance, apply_feed_to_params  (MISP only — OpenCTI and
            TAXII have no feed concept)
MAPPING     map_attribute — source type -> Zeek type, composite splitting;
            table-driven over MISP_TO_ZEEK or OPENCTI_TO_ZEEK (TAXII reuses
            OPENCTI_TO_ZEEK — parse_stix_pattern already emits its keys)
NORMALISE   norm_addr/subnet/domain/url/hash/email/..., sanitize_meta;
            _prepare() is the shared funnel and holds the two guards
            that are about the file format rather than the value --
            _reject_control and _reject_comment (a leading "#")
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
GUARDRAILS  check_size/not_empty/delta/load_file/broad, run_guardrails;
            check_built_anything is the append-only branch's stand-in for
            not_empty/delta, which cannot fire against a merge that only
            grows -- it blocks a run that built zero indicators
INTERVIEW   ask* primitives, discover (MISP) / discover_opencti /
            discover_taxii, build_search_params (MISP) /
            build_opencti_filters (OpenCTI), _stage1_connection (branches
            on source for TAXII's version-detection and Basic/Bearer
            questions, and seeds its defaults from connection_defaults(args)
            -- the CLI connection flags -- when there is no live client to
            read them off), _stage_feeds, _stage3_iocs shared across MISP and
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
SCHEDULE    render_unit_files (the two unit bodies as text, so the exact
            bytes can be shown before anything lands in /etc and asserted
            on without root), describe_calendar (systemd-analyze, when it
            is there), env_file_names (which variables the unit's
            EnvironmentFile supplies -- names only, never values -- since
            an install run from a terminal cannot see them),
            check_timer_preconditions (the failures that would
            otherwise surface at 02:00 with nobody watching: no systemd,
            unwritable unit dir, an offline profile, no credential
            reachable without a terminal, a profile that never applies),
            cmd_install_timer.  --install-timer is the only caller, and a
            test pins render_unit_files to exactly two mentions in the
            file -- the def and that one caller -- so a build can never
            write a unit
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
- **Purity where it matters.** `mapping`, `normalise`, `filters`, `intel`, `guardrails`, `diff`, `build_search_params`, `build_opencti_filters` touch no network and no filesystem. That is what makes 742 tests runnable with nothing installed. Do not put I/O in them.
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
  `check_size` blocks at `count > cap`; exactly at the cap passes, and the
  separate 100,000 `warn_at` threshold is what produces a warning.
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
  the profile already decided — it reads `config.get("apply")` and never sets
  it, so an unattended build applies exactly when the saved profile said to.
  No `--no-apply` flag was added to make the two symmetrical; the asymmetry
  is documented in `--help` on `--import` instead.

---

## 6. Non-obvious things that will bite you

- **`ipaddress.is_private` is broader than RFC1918.** It includes the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`. Correct to exclude from threat intel, but it means example addresses get dropped — tests must use genuinely routable addresses like `45.33.32.0/24`. This already cost one debugging round.
- **Logging filters run before formatting**, so `record.exc_text` is `None` at filter time. Token redaction therefore lives in `RedactingFormatter`, not only in `RedactingFilter`. Do not "simplify" it back.
- **urllib forwards all headers across redirects**, including `Authorization`. `NoCrossHostRedirect` blocks cross-host 3xx. Do not remove it.
- **A TAXII discovery document names its own API roots, and the spec makes them absolute URLs.** `urljoin` will follow one to whatever host it names, and the transport puts the `Authorization` header on every request — so a server (or anything that can answer as one) could redirect the credential to a third party without ever issuing a 3xx. `TaxiiClient._same_host` gates both routes an API root becomes a request: `get_collections` skips a foreign root with a warning, and `fetch_objects` raises `TaxiiError` on one, because a collection can also arrive from a saved profile without passing through discovery. A relative root has no netloc and is trivially same-host; an absolute one must match scheme, host *and* port, since a downgrade to `http://` on the same name still puts the credential on the wire in cleartext. The fake server in the test suite serves relative roots, which is why this went unnoticed until the audit — a real server will not.
- **`verify_runtime`'s verdict is `apply_to_grid`'s return value.** It is not an advisory warning: an `expected` count that disagrees with the file salt synced makes the whole apply, and therefore the whole run, exit 1. `cmd_build` must pass `len(combined)` (the merged file) and not `len(rows)` (what this run built) — it passed the latter until 2026-08-23, which failed every apply on a manager that already had indicators. `cmd_apply` and `cmd_import` always counted the whole file.
- **`--lint` and `check_env` read the `do_notice` schema off the file's `#fields` header.** `lint_file(path, do_notice=None)` detects; `True`/`False` overrides. Before that, linting a `do_notice`-built file without `--do-notice` reported "expected 5 tab-separated fields, got 6" on every line of a perfectly good file, and `check_env` surfaced the same thing as "existing intel.dat has N lint problem(s)".
- **`--diff` implies `--dry-run`.** `main()` sets it. On its own, `--diff` used to fall through `_report_dry_run`'s `if not dry_run: return False` and *write* the file, having printed no diff at all — the opposite of what asking for a diff means.
- **A URL with a query but no path used to lose its host.** `norm_url` partitions on the first `/` to find the host, so `evil.com?a=1` put the entire query string inside the host, failed every host check, and was tallied as `url_no_host` -- a rejection reason that named the wrong problem, on a URL shape MISP `url` attributes really do carry. The repair inserts the `/` the URL elided (`evil.com/?a=1`) before the partition; a URL that already has a path is untouched. Zeek matches host+uri and a uri always starts with `/`, so this is also the shape Zeek would have to see for the indicator to fire at all.
- **A URL indicator's host is parsed in one place, `url_host()`.** Three
  functions pull a host out of a URL: `norm_url` (from the raw value, to
  validate it), `ExclusionSet._reason` and `check_broad_indicators` (from the
  already-normalised indicator). All three used to carry their own copy of
  `split("/", 1)[0].split(":", 1)[0]`, and when the 2026-08-24 audit taught
  `norm_url` that an IPv6 literal is bracketed -- so that split cuts
  `[2606:4700::1111]` down to `[2606` -- the other two were left behind.
  `check_broad_indicators` therefore reported every IPv6-literal URL as
  "URL host has no dot", warning about the narrowest indicator there is.
  `url_host()` is now the single parser, and the dotless-host test also asks
  for the absence of a colon, because an IPv6 address has no dot and is
  exactly one address. `ExclusionSet` had no observable defect from its copy
  (an operator's own-domain list never contains `[2606`), but it shared the
  parser and now shares the fix.
- **Same-origin is compared through `_origin()`, not through raw netlocs.**
  `NoCrossHostRedirect` and `TaxiiClient._same_host` are the two places a URL
  is checked against the one we authenticated to, and both used to compare
  `urlparse(...).netloc` directly. That calls `https://h` and `https://h:443`
  different hosts — and both spellings are routine here, because stage 1
  always answers the port question (so every client's `base_url` carries an
  explicit port) while the URLs a server names for *itself* — a TAXII
  `api_root`, a `Location` header — normally leave a default port off. The
  effect on TAXII was total: against a real server publishing absolute API
  roots, every root was refused with `ignoring API root ... it is not on ...`
  and the interview offered **zero collections**, which reads as a permissions
  problem rather than a bug. `_origin()` returns `(scheme, host, port)` with a
  default port normalised to `None`, so `http:80` and `https:443` compare
  equal on the port and the *scheme* stays a separate element each caller
  judges for itself: the redirect handler allows the `http` → `https` upgrade
  and refuses the downgrade, `_same_host` requires an exact scheme match. The
  downgrade branch is checked *first* in the redirect handler, because a
  downgrade is also a port change (443 → 80) and "cross-host" would be a true
  but far less useful name for a cleartext credential. An unparseable port
  returns an origin nothing else equals rather than raising.
- **The TAXII version question is answered before anything can detect it.**
  `detect_version()` exists to supply that answer's default, but stage 1 is
  also what collects the credential, so at the moment the question is asked
  there is no client to detect with — `run_interview` always passes
  `client=None`. Detection therefore happens at the stage 2 connect instead,
  and it has to happen *somewhere*: a 2.0 server does not answer `/taxii2/`,
  so honouring a wrong stage 1 answer made the connect fail, which the
  interview reports as an unreachable host and continues offline — leaving
  the operator at stage 3 with no collections and a build that fetches
  nothing. `run_interview` now calls `detect_version()` in place of
  `get_version()` on the TAXII path, prints a line when the server disagrees
  with the answer, and carries the detected version into `config`.
- **`_stage1_connection`'s live-client branches are not reachable from
  `cmd_build`.** Its `client is not None` paths — seeding connection defaults
  off a working client, reusing its token, detecting the TAXII version —
  exist for a re-run against an established connection that no production
  call site performs: `cmd_build` passes `None` and lets `connect` build the
  client at stage 2. They are exercised by tests only. Not dead code exactly,
  but do not reason about interview behaviour from them.
- **A `max_indicators` cap is measured against the *merged* file, not against
  what this run fetched.** `_fetch_records` spends the same number as a fetch
  budget (records, not rows), while `run_guardrails` passes it to
  `check_size` as `cap` against `total_count = len(combined)` — every
  indicator already in `intel.dat` included. Because the merge is
  append-only, a manager whose file has grown to the cap will block every
  subsequent run and write nothing. That is the honest reading of "hard cap
  on indicator count", and blocking loses no data, but it is a permanent
  failure state rather than a one-off warning: raise the cap or narrow the
  query, and expect a scheduled run to start failing when the file catches
  up with it.
- **Nothing guarded the zero-indicator build until 2026-08-23.**
  `check_not_empty` and `check_delta` are both skipped under append-only, and
  the reasoning for skipping them ("the merge cannot remove a row, so there is
  nothing left to protect") is true only of a *populated* file. It said
  nothing about a run that builds nothing at all — a token whose permissions
  return an empty result, a filter that matches nothing, an interview where
  every IOC type was deselected, a TAXII profile with no collection selected.
  Every one of those fetched, built zero rows, merged zero rows, passed every
  guardrail, and exited 0: on a fresh manager it wrote a header-only
  `intel.dat` that Zeek loads and never matches; on a populated one it printed
  "added 0 new indicators" and, if the profile said so, applied it. README
  promised the opposite ("it will not let a filter silently match nothing").
  `check_built_anything(len(rows))` now runs on the append-only branch and
  **blocks**. Note what it counts: `rows`, this run's build — not
  `total_count`, which stays large on a populated manager precisely when the
  run fetched nothing. A warning would not have done: the file still gets
  written. Blocking loses nothing under append-only, and the non-zero exit is
  what a timer's journal shows.
- **`--install-timer` could not see the credential it told you to create.**
  `check_timer_preconditions` probed for a token through `resolve_token`,
  which reads `--token-file`, the environment and `credentials.json` — but
  never `/opt/nexus/nexus.env`, the `EnvironmentFile` the unit itself reads.
  Under the timer that file *is* the environment, so `resolve_token` is right
  not to read it; at install time it is not, and the check concluded "no API
  token reachable without a terminal" and then advised putting the token in
  `nexus.env` — the one file it had just ignored. Following the instruction
  could never clear the error it came with, which is a dead end, not a
  message. `env_file_names()` parses that file for variable *names* with a
  non-empty value (never the values — they are secrets and nothing here needs
  them) and both the token check and the TAXII Basic username check consult
  it. It is deliberately consulted *first*, so its answer short-circuits
  `resolve_token`, which logs an error of its own on the way to returning "".
- **A same-host redirect can still leak the token.** `NoCrossHostRedirect` compared host only, so an `https` -> `http` 3xx on the *same* name passed straight through with the `Authorization` header attached, in cleartext. It now compares scheme as well -- the same rule `TaxiiClient._same_host` already applied to API roots. The `http` -> `https` direction is the safe one and is still allowed; do not "simplify" the two branches back into one host comparison.
- **`--do-notice` used to do nothing on a build.** Only `cmd_lint` read it; `cmd_build` took `do_notice` from the interview or the profile and never looked at the flag, so a run that asked for the six-column schema quietly wrote five. It is now applied in `cmd_build` alongside `--dry-run`, under the same "CLI flags win over whatever the profile recorded" rule. Forcing it onto a file built without it is caught by the existing header check and blocked.
- **Stage 7 used to overwrite the `meta.source` stage 2b had just chosen.** Selecting MISP feeds sets `source_fmt` to `MISP-feed-{feed}`; stage 7 then offered its menu with `SOURCE_FORMATS[0]` as the default and silently replaced it, after which `run_interview` logged "feeds selected but meta.source has no {feed} placeholder" -- a warning about a choice the interview had made on the operator's behalf. Stage 7 now leads the menu with whatever is already in `config["source_fmt"]` and defaults to it.
- **`--probe --source taxii` could never authenticate with Basic.** A probe runs no interview and a profile never stores the username, so `make_client` always built a Bearer client and a Basic-auth server's 401 was reported as a rejected *token*. `cmd_probe` now reads `NEXUS_TAXII_USERNAME` -- environment only, and the same variable the systemd timer reads, because there is no way to know in advance that a server wants Basic and prompting for it would be a question every MISP probe had to decline.
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
- **An indicator starting with `#` is a comment, not an indicator.** Zeek's
  ASCII input reader treats a `#` line as a header or a comment and never
  loads it, and `read_existing` drops it for exactly the same reason — so a
  MISP `filename` attribute like `#readme.txt` used to be written to
  `intel.dat`, ignored by every sensor, and then quietly dropped from the next
  merge despite append-only, with `lint_file` reporting the file clean
  throughout. The guard lives in `_prepare()`, the one funnel every normaliser
  routes through, alongside `_reject_control` which exists for the identical
  reason (a value that would corrupt the line format is not a valid
  indicator). Only the free-text normalisers — `norm_filename`,
  `norm_freeform` — can produce one; the others cannot, and the shared guard
  covers all of them at once. Rejections tally as `leading_comment_char`.
- **The CLI connection flags seed stage 1; they used to be ignored entirely.**
  `--scheme`, `--port`, `--insecure`, `--proxy`, `--timeout` and `--retries`
  reached `cmd_probe` and nothing else: a build's stage 1 read its defaults
  off a live `client`, and on the interview path there is no client yet, so
  every one of those flags was silently discarded. `connection_defaults(args)`
  is now that bag, passed through `run_interview` into `_stage1_connection`,
  where `_seeded()` resolves client-then-flag-then-built-in. They remain
  defaults, not answers — every question is still asked, per the standing rule
  that flags skip questions only for an unattended replay.
- **`--insecure` is its own typed confirmation.** Declining TLS verification
  normally requires typing `INSECURE`, so nobody turns it off by
  fat-fingering one prompt. Seeding that answer from `--insecure` and then
  asking again made the flag unactionable: an operator taking the seeded
  default with Enter handed verification straight back. The typed step is now
  skipped when, and only when, `--insecure` was given — the flag is already
  the deliberate act, spelled out on the command line.
- **`--probe --yes` was refused by a gate meant for builds.** The `--yes
  requires --profile` check sat above the probe dispatch, so a fully specified
  `--probe --host H --source S --yes` exited 2. A probe runs no interview;
  it now sits above the gate like `--import` and `--install-timer`, and
  refuses only when `--yes` is given with no `--host`/`--source` to work from.
- **`meta.do_notice` has no per-indicator setting.** `build_indicators` takes
  one `do_notice` value for the whole run and `rows_to_lines` writes it on
  every row, so turning the column on means `T` everywhere — an alert per
  match, not a formatting detail. The stage 7 prompt and `--help` both say so
  now. Making it per-indicator would need a source-side signal to derive it
  from; none of MISP, OpenCTI or TAXII carries one that maps cleanly, which is
  why it is one answer for the run.
- **`merge_preserved` was deleted, not overlooked.** It kept lines whose
  `meta.source` was not ours, from the era when a build replaced the file.
  Append-only made it dead the day it landed: `merge_additive` retains *every*
  existing row, hand-added or not, so there was nothing left for it to
  preserve. It had a passing test and no caller, which is the shape dead code
  usually arrives in.
- **GraphQL answers HTTP 200 on auth failure.** A rejected OpenCTI token arrives as a 200 with an `errors` array, not a 401/403. Unhandled, that is indistinguishable from an empty result set, and a scheduled run would report "0 new indicators" forever instead of failing loudly. `_check_errors` runs before any caller reads `data`.
- **`strptime`'s `%z` didn't accept a colon in the UTC offset until Python 3.7.** This project's floor is 3.6, so OpenCTI's `...Z` timestamps are normalised to `+0000` (colon-free) before parsing. Without this, every OpenCTI timestamp would silently parse to `""` on 3.6 while a 3.9-or-later test run stayed green and never caught it.
- **OpenCTI 6.x filters take entity ids, not names.** Discovery builds `name -> id` maps for labels, marking definitions and organisations; a name with no discovered id is dropped with a warning, never guessed at or passed through as text.
- **Certificate hashes need their own `X509-` mapping keys.** `OPENCTI_TO_ZEEK["X509-SHA-1"]` is a separate key from `["SHA-1"]` — without the prefix a certificate SHA-1 would land in `Intel::FILE_HASH` instead of `Intel::CERT_HASH`.
- **Non-STIX pattern types are never mined for values.** `parse_stix_pattern` only runs for `pattern_type == "stix"`; a YARA or Sigma rule's string literals are not treated as indicators.
- **The interview's hostname question is type-name-sensitive per source.** It drops the literal `"Hostname"` on OpenCTI but `"hostname"` on MISP — the two platforms spell the type differently. Before this was fixed, an OpenCTI operator answering "no" to "treat hostnames as domains" still got hostname indicators, silently, because the MISP-only literal never matched.
- **`meta.url` is source-aware.** OpenCTI indicators link to `{base}/dashboard/observations/indicators/{id}`; the MISP event URL shape (`{base}/events/view/{id}`) is unchanged. `render_meta` branches on the record's source rather than assuming one URL template — though the stage 7 *question wording* ("Link meta.url back to the MISP event?") and the `meta.source` presets (`SOURCE_FORMATS`, defaulting to `MISP-event-{event_id}`) are still MISP-labelled on an OpenCTI run, a known cosmetic gap recorded at `PLAN.md` §4 item 31.
- **TAXII filters most scoping AFTER download, not on the server.** TAXII's query syntax reaches exactly two things: `match[type]=indicator` and `added_after`. Nexus pushes fifteen filter parameters into a MISP `restSearch` body or an OpenCTI `FilterGroup`; against TAXII, `include_labels`, `exclude_labels`, `include_markings`, `include_authors`, `min_confidence` and `drop_expired` are all applied client-side in `taxii_object_allowed()`, after every object in the time window has already been downloaded. An operator used to MISP will expect `include_labels` to reduce transfer volume the way `tags.OR` does. **It does not.** Stage 5 says so in its own prompt text ("applied after download") so an interactive operator sees it live; this entry is the same fact for whoever is reading code instead of prompts.
- **`--probe`'s TAXII counts are pre-filter.** The server cannot count a filtered subset — TAXII has no query for labels, markings, confidence, validity or author — so a probe number means "objects in this collection" (bounded by `--probe-limit`, default 5000, marked with a trailing `+` when the cap was hit), not "indicators you will actually get" once stage 5's client-side filters run. `_cmd_probe_taxii` prints this caveat directly under its table.
- **A platform failure part-way through the fetch used to be a traceback.**
  `_fetch_records` is a generator, so the network work does not happen at the
  `client.get_version()` call `cmd_build` wraps in a `try` — it happens inside
  `build_indicators`, several lines later, where nothing caught it. A token
  that expires mid-pull, a 500 that outlasts the retries, or a page of
  malformed JSON therefore left a Python traceback where a timer's journal
  should show one line. Two things follow from that being uncaught. The
  partial fetch: it would have merged cleanly, added a fraction of the
  indicators and reported success, so the build now discards it and writes
  nothing (exit 2, matching the connection-failure exit above it). And the
  message: a `SourceError` carries the request URL and up to 500 bytes of the
  response body, and only the *logging* path redacts on its own — a traceback
  printed by Python bypasses `RedactingFormatter` entirely, so the handler
  scrubs through `REDACTOR.scrub()` explicitly.
- **A URL with an IPv6 literal host was rejected as `url_no_host`.** `norm_url`
  finds the host by splitting the authority on the first `:` to drop a port,
  which cuts `[2606:4700::1111]` down to `[2606`; both `norm_domain` and
  `norm_addr` then failed it and the tally named the wrong problem — the host
  was right there. A bracketed authority is now partitioned on `]` instead.
  The brackets stay on the emitted indicator: that is the form a `Host` header
  carries and Zeek matches host+uri. `ExclusionSet._reason` splits the same
  way for `Intel::URL`, but only ever feeds the result to a domain-suffix
  comparison an IP could not match anyway, so that copy is inert and was left
  alone.
- **`parse_stix_pattern` does not honour the pattern's structure, and used to
  claim it did.** Its docstring said negations *and qualifiers* were "skipped
  rather than approximated". Only the negation is: the property character
  class excludes `!`, so a `!=` never reaches the `=` and the regex simply
  fails to match. Everything else — `AND` and `OR` between observation
  expressions, `REPEATS`, `WITHIN`, `START`/`STOP` — is ignored as structure
  and every `=` comparison in the pattern still yields an indicator. For an
  `AND`-composed pattern that over-matches: Zeek's Intel framework is a flat
  list of values with no way to express "only when both are seen", so the
  choice is between two indicators that each fire alone and dropping the
  pattern entirely. The former is the honest trade and is now what the
  docstring says, with `test_and_composed_observations_become_independent_indicators`
  pinning it.
- **STIX 2.0 has no `confidence` property at all.** It arrived in STIX 2.1. `flatten_taxii_object` carries an absent confidence through as `obj.get("confidence")` — `None`, never coerced to `0` — because `0` is a real, valid (low) confidence value in 2.1, and treating "absent" the same way would let a minimum-confidence filter silently drop every object from a 2.0 feed. `taxii_object_allowed()` only compares confidence when both the configured minimum and the record's value are not `None`, and stage 5 warns explicitly in its own text when the detected TAXII version is 2.0.

---

## 7. What is left

### Every phase is now built. What is left is live validation.

Phase 7 closed on 2026-08-23: `--install-timer` renders and writes
`nexus.service` and `nexus.timer`, and `README.md` is the operator doc. The
timer is **never installed as a side effect of anything** — the user asked for
it to be opt-in explicitly, and `TestInstallTimerCli` asserts that nothing
outside `cmd_install_timer` reaches the unit renderer.

### Audit, 2026-08-23

A full read of `nexus.py`, `PLAN.md`, `README.md` and this file, looking for
logic errors, architectural drift and claims the code does not honour. The
architecture held: the layering (transport → flatten → map → normalise →
filter → build → guardrail → write) is intact, no dead functions, one unused
constant (`FEED_PROVENANCE_ORDER`, kept because a test pins it as the
documented order), and the purity rule still holds everywhere §4 claims it
does.

Two real defects came out of it, both of the same class this project cares
most about — **failure that looks like success** — and both on TAXII paths the
fake server structurally cannot expose. Both are fixed, both have regression
tests that fail without the fix, and both are written up in §6:

1. **Same-origin was compared as raw netlocs**, so `https://h` and
   `https://h:443` were different hosts. Stage 1 always answers the port
   question and a server's own URLs normally omit a default port, so against a
   real TAXII server publishing absolute API roots *every* root was refused and
   the interview offered zero collections. The same comparison sat in
   `NoCrossHostRedirect`, where it refused any redirect that merely normalised
   a path. One helper, `_origin()`, now backs both.
2. **The TAXII version was never actually detected.** `detect_version()` was
   written to default the stage 1 question, but stage 1 is what collects the
   credential, so there is no client to detect with and `run_interview` always
   passes `client=None`. Against a 2.0 server the 2.1 default made the connect
   fail, which the interview reports as an unreachable host: no collections, no
   indicators, no error. Detection now runs at the stage 2 connect.

Corrected in the docs at the same time: this file claimed `check_size` warns at
exactly the cap (it passes), and this file and `PLAN.md` both claimed
`detect_version()` supplied the interview's default (it could not). The
`max_indicators` cap's real semantics — measured against the merged file, so a
grown `intel.dat` blocks every later run — were undocumented and are now in §6
and in `README.md`.

Reported and deliberately **not** changed:

- `apply_feed_to_params` raises an uncaught `ValueError` if a hand-edited
  profile names a feed with no provenance. A traceback rather than a message,
  but the profile is written by Nexus itself at 0600 on a root-owned manager.
- The MISP per-feed budget is spent on records `search_attributes` returns,
  while `seen` counts what survives the client-side include-tags filter, so a
  tag-identified feed can under-deliver its share of `max_indicators`.
- `MispError` / `MispAuthError` have no remaining caller in `nexus.py`; they
  stay as aliases for out-of-tree callers, and the comment above them now says
  so rather than claiming call sites that no longer exist.

### Audit, second pass, 2026-08-23

A re-read of the whole repository after the pass above, looking specifically
for logic gaps, architectural drift and documented claims the code does not
honour. The architecture held again: layering intact, purity rule intact, no
new dead functions. Three things came out of it.

Two real defects, both fixed, both with regression tests that fail without the
fix, both written up in §6:

1. **A build that produced zero indicators was written and reported as
   success.** `check_not_empty` and `check_delta` are skipped under
   append-only and nothing replaced them, so the zero-result case had no
   guard. `check_built_anything` now blocks it.
2. **`--install-timer`'s credential check could not read
   `/opt/nexus/nexus.env`**, the file its own fix message tells the operator
   to create. `env_file_names()` closes the loop.

One documentation defect: `PLAN.md` §7 still described `merge_preserved()` as
"exists in the file but has no callers" — it was deleted when append-only
landed, and §6 of this file already said so. Corrected.

Reported and deliberately **not** changed:

- **MISP stage 2 discovery is expensive, and it is unverified how expensive.**
  `discover()` calls `count_type()` once per mappable attribute type — around
  forty POSTs to `/attributes/restSearch`, each with `limit=probe_limit`
  (5000). `count_type` prefers the `X-Result-Count` header, but the *body* has
  already crossed the wire by the time it reads it, so a large MISP could ship
  on the order of 200,000 attributes to populate the interview's count
  annotations. Asking with `limit=1` first would make it nearly free — but
  only if that header really is the search total rather than the page's own
  count, which nobody has observed on a live instance. The current code
  already trusts it as a total, so `limit=1` would not add an assumption, only
  raise the cost of that assumption being wrong (a type with 100k attributes
  would be annotated "1"). Left alone until a real MISP can answer it; added
  to the checklist below.
- **`check_output_target` reports a schema mismatch as a lint failure.** An
  offline rebuild over a file built with the other `meta.do_notice` setting
  fails with "existing file has N lint problem(s)" rather than the clear
  "schema differs" message `cmd_build`'s header check would have produced,
  because `check_output_target` runs first and passes `config["do_notice"]`
  explicitly instead of letting `lint_file` read the header. The refusal is
  correct; only the wording is poor.
- **`cmd_build` prints the pre-flight summary twice** on the interview path —
  once from `run_interview` for approval, once from `cmd_build` for the log.
- **`--import` cannot honour a `max_indicators` cap**, because an import has
  no profile to read one from. `run_guardrails` is called with no `cap`, so a
  transferred file can push the manager past a cap a build would have blocked
  at.

### Audit, third pass, 2026-08-24

A third whole-repo read — logic, architecture, documentation — looking for
gaps the two passes above did not reach. The architecture held for a third
time: layering intact, purity rule intact, and a mechanical sweep for
functions and constants with no in-file reference found exactly one,
`FEED_PROVENANCE_ORDER`, which the previous audit already recorded as kept
on purpose.

Three defects, all fixed, all with regression tests that fail without the fix,
all written up in §6:

1. **A platform failure mid-fetch escaped as a traceback.** The fetch is a
   generator, so it fails inside `build_indicators`, past the `try` around
   `get_version()`. This is the likeliest runtime failure the tool has, it
   left a traceback in a timer's journal, and the exception text — URL plus
   up to 500 bytes of response body — never reached the redactor, because
   only the logging path scrubs on its own. Now reported and exited 2, with
   the partial fetch discarded rather than written.
2. **IPv6-literal URLs were rejected as `url_no_host`.** The port split cut
   the bracketed address in half. A wrong rejection, and a rejection reason
   that named the wrong problem.
3. **`parse_stix_pattern`'s docstring claimed qualifiers were skipped.** They
   are not; only `!=` is. The `AND`-composed over-match that follows was
   undocumented and is now stated plainly, and pinned by a test.

Reported and deliberately **not** changed:

- **`record["timestamp"]` is written by all three flatteners and read by
  nothing.** `flatten_attribute` copies MISP's epoch straight through;
  `flatten_indicator` and `flatten_taxii_object` each spend two regex
  substitutions and a `strptime` per record (`_opencti_epoch`) to fill it. It
  is part of the documented source-agnostic record shape in `PLAN.md` §3, three
  tests pin its behaviour, and indicator aging — the one feature that would
  consume it — is explicitly out of scope (§14). Deleting it is a clean
  three-line removal whenever that stops being true.
- **`make_client` raises `TaxiiError` on a hand-edited `taxii_version`**, and
  `cmd_build` calls it outside any handler, so that is a traceback. Same class
  as the `apply_feed_to_params` `ValueError` the first audit left alone, for
  the same reason: the profile is written by Nexus itself at 0600 on a
  root-owned manager.
- **A profile freezes each selected feed's provenance at interview time.**
  `config["feeds"]` stores the whole feed dict, so a feed that is later
  retagged, or switched to a fixed event, in MISP replays with the selector it
  had on the day the profile was saved. Re-running the interview is the fix;
  nothing detects the drift.
- **MISP and OpenCTI page walks have no ceiling**, exactly like the TAXII 2.1
  walk whose accepted risk is written up at the end of §7. The repeated-page
  signature and the non-advancing-cursor guards cover the common server bug;
  a server that keeps returning fresh, non-empty pages is bounded only by
  `max_indicators`. `max_pages` exists on both methods and is used by tests
  only.

### Audit, fourth pass, 2026-08-24

A fourth whole-repo read — logic, architecture, documentation. The
architecture held again: layering intact, purity rule intact, the three
earlier passes' fixes all still in place, and `python3 -m unittest test_nexus`
green at 741. This pass deliberately looked for *siblings of already-fixed
bugs* rather than for new ones, on the theory that a fix applied at one call
site is the shape of defect three passes can walk past.

One real defect, fixed, with a regression test that fails without the fix, and
written up in §6:

1. **The third pass fixed IPv6-literal URL hosts in `norm_url` and nowhere
   else.** Two other functions parse a host out of a URL indicator —
   `ExclusionSet._reason` and `check_broad_indicators` — and each carried its
   own copy of the same broken `split(":", 1)` . The visible cost was in
   `check_broad_indicators`: `[2606:4700::1111]/a` became `[2606`, which has
   no dot, so every IPv6-literal URL was reported as an overly broad
   indicator — a warning about the narrowest indicator the tool can emit.
   `url_host()` is now the one parser all three call, and the dotless test
   also requires the absence of a colon. `ExclusionSet` had no observable
   defect (an own-domain list never contains `[2606`); it shared the broken
   parser and now shares the fixed one.

One robustness gap, fixed, no test (a three-line `except` in `__main__`):

2. **Ctrl-C outside a prompt was a traceback.** The interview funnels
   `EOFError`/`KeyboardInterrupt` into `InterviewAborted` at every `_read`,
   but a fetch runs for minutes with no prompt in sight, and `--probe`'s
   `getpass` sits outside the funnel too. `__main__` now exits 130 with
   "Aborted." The guard is in `__main__` rather than in `main()` so nothing
   about `main()` under test changes.

Reported and deliberately **not** changed:

- **`check_not_empty` and `check_delta` are unreachable in production.** Both
  live on `run_guardrails`' `append_only=False` branch, and every production
  caller — `cmd_build`, `cmd_import` — passes `append_only=True`;
  `config["merge_mode"]` is a constant `"append-only"`. So are the two
  functions, their `total_count is None` fallback, and about 17 tests. They
  are correct, cheap, and the only thing that would cover a non-append mode if
  one ever returns. Deleting them is a scope decision, not an audit finding.
- **The MISP fetch budget is spent in records, and a composite attribute is
  two indicators.** `_fetch_records` passes `max_indicators` to
  `search_attributes` as `max_results`, which counts records; a `domain|ip`
  or `filename|md5` record yields two rows. So a cap of N can build up to 2N
  indicators, and `check_size` then **blocks** — a failed build and no file,
  which is the safe direction but a confusing one. The TAXII path already
  reasons about exactly this (see the comment in `_fetch_records`) and counts
  its budget in records post-flattening; MISP and OpenCTI do not. Left alone
  because the failure is loud and the cap is documented as a hard stop.
- **`read_existing` silently drops operator comment lines.** A `#` line in
  `intel.dat` is skipped on read and therefore absent from the merge that is
  written back, so a comment an operator added by hand disappears on the next
  build. `lint_lines` explicitly tolerates such lines, which reads as a
  promise they survive. They are not indicators and the append-only claim is
  about indicators, so this is a documentation gap rather than a defect —
  recorded here rather than fixed, because preserving them means deciding
  where in the merged file they go.
- **`cmd_explain` prints `?match[type]=indicator` unencoded** while
  `fetch_objects` sends `urlencode`'s `match%5Btype%5D=indicator`. Same
  request, different spelling; the printed form is the one the TAXII spec
  uses and the more readable of the two.
- Everything the first three passes recorded as deliberately unchanged still
  stands, and was re-checked rather than assumed: the hand-edited-profile
  traceback class (`apply_feed_to_params`, `make_client`), the frozen feed
  provenance in a profile, the uncapped page walks, the double pre-flight
  summary, `--import` having no cap to honour, and the write-only
  `record["timestamp"]`.

### Audit, fifth pass, 2026-08-25

Live bug, hit by the operator running the interview against a real MISP
host, not found by re-reading: a plain-HTTP MISP server 301-redirected
`/servers/getVersion` with a Location header missing the slash between host
and path (`https://10.10.40.17servers/getVersion` — the server's own
misconfiguration). `NoCrossHostRedirect` parsed that as a different host
(`10.10.40.17servers` != `10.10.40.17`) and correctly refused it — the guard
did its job, stopping the API token from following a redirect to a host that
was never vouched for.

But the refusal reason never reached the operator. `redirect_request` raised
its refusal as `urllib.error.HTTPError`, carrying the real reason in
`.msg`/`.reason`; `_HttpTransport._request`'s generic `HTTPError` handler
ignores both and instead reads the *original* response's body for `detail`
(`exc.read()`), which — mid-redirect — is the original server's 301
boilerplate HTML, not our refusal. The operator saw MISP's "Moved
Permanently" page as if it were an ordinary connection failure, with no hint
that the tool had, correctly, stopped on purpose.

Fixed by raising `SourceError` directly from `NoCrossHostRedirect` instead of
`HTTPError`. It is not one of the exception types `_request` catches, so it
skips that handler's body-reading and retry logic entirely (retrying a
security refusal cannot help) and the actual refusal string reaches the
operator unchanged. Regression test added for the malformed-Location-header
shape specifically, alongside the five redirect tests updated to expect
`SourceError`.

Not a nexus defect, and unchanged: the MISP server's own Location header is
still malformed. Nothing in nexus can repair another host's redirect; the fix
here is only that the tool now says why it stopped instead of showing the
wrong thing.

### Open questions for the user — none are blocking

1. Run `python3 nexus.py --check-env` on the real manager to confirm the local
   `__load__.Zeek`, runtime paths, and `do_notice.zeek` policy state. The code
   performs these checks, but the target box has not been observed yet.
2. Exact 3.x point release, and whether anything else already manages that file.
3. Expected indicator volume and available RAM per Zeek worker. Nexus imposes
   no default ceiling, but Zeek's in-memory Intel framework remains the real limit.

### Flagged as unverified, systemd

Written from the unit-file documentation, never installed on a real manager.

1. That `--install-timer` run under `sudo` finds `/etc/systemd/system` writable
   and `/run/systemd/system` present — both are checked, neither is observed.
2. That the rendered `ExecStart` path is right on the manager. It is
   `sys.executable` plus `os.path.abspath(__file__)` at render time, so
   installing from a copy in `/tmp` bakes `/tmp` into the unit. Install from
   the path the tool will live at.
3. That `EnvironmentFile=-/opt/nexus/nexus.env` reaches `resolve_token`. The
   precedence is env before `credentials.json`, so a stale value in the env
   file wins over a fresh one in `credentials.json`.
4. That `Persistent=true` behaves as intended here — a manager down across
   several periods gets **one** catch-up run, not one per missed period.
5. That the salt apply works from inside a unit. `User=root` is set so no sudo
   is involved, but `SO_APPLY_ARGV` still starts with `sudo`, which is a no-op
   as root on most managers and is not something this project has watched.

### Flagged as version-dependent, unverified

`threat_level_id` and `analysis` are emitted into the restSearch body by `build_search_params`, but support for them on `/attributes/restSearch` is MISP-version-dependent and was **not** in the verified parameter list. If those interview answers appear to do nothing, this is why. Confirm against the live instance.

**Also confirm what `X-Result-Count` counts.** `count_type` treats it as the total for the search and reports the count as exact; if it is really the returned page's own size, every annotation is silently capped at `probe_limit`. Two things ride on the answer. First, whether the counts the interview shows are true. Second, whether stage 2 can be made cheap: it currently issues ~40 `restSearch` POSTs at `limit=5000`, so a large MISP ships a great deal of data just to annotate a menu, and `limit=1` would make it nearly free — but only if the header is the search total. Check it directly: run the same search at `limit=1` and at `limit=5000` on a type with more than 5000 attributes and compare the header both times.

### Flagged as unverified, OpenCTI

> **Status: live validation deferred.** As of 2026-08-21 the operator has no OpenCTI
> instance available to test against, and has deliberately postponed this. The OpenCTI
> code path is complete, unit-tested (741 tests, all sources) and reviewed, but **no part
> of it has ever exchanged a packet with a real OpenCTI server.** Treat it as untested in
> production until the checklist below has been run. This is a known, accepted gap — not
> an oversight to re-flag.

Nothing in this project has ever run against a real OpenCTI instance. None of these seven block what has already shipped, and each is a contained fix — a few lines in one function, not a redesign.

1. **`x_opencti_detection` as a filter key.** The field exists on Indicator; whether it is filterable is the open question. If not, the detection requirement moves to a client-side filter in the fetch loop.
2. **`objectLabel` / `objectMarking` return shape.** The flattener assumes bare lists, which is 6.x behaviour. 5.x returned `edges { node { ... } }`; if some 6.x point release differs, the flattener needs the edges walk added back.
3. **Label filtering by id versus value.** The interview translates label/marking names to ids via discovery. Some builds may accept values directly, in which case the discovery id map becomes optional rather than required.
4. **`globalCount` under the operator's auth level.** `count_type` falls back to a bounded, still-exact count when `globalCount` is absent (see §3), but the interview's count annotations get less useful without it.
5. **Rate limiting on a large paginated pull.** The existing retry/backoff handles 429, but OpenCTI's actual ceiling and page-size sweet spot are unknown. Default page size is 100 (smaller than MISP's) and is tunable via `page_size`.
6. **`exclude_expired` also drops indicators with no `valid_until`.** The
   filter is `valid_until > now`, and a null does not satisfy a `gt`
   comparison, so an indicator that never had an expiry is excluded along
   with the expired ones. OpenCTI normally populates `valid_until` from its
   decay rules, so this is expected to be a no-op — but it has never been
   observed, and if an instance leaves the field null the interview's
   default answer (yes, exclude) would quietly return nothing. Check the
   count with the answer both ways on the first live run.
7. **OpenCTI version and reachability from the manager.** Same pre-flight class as the outstanding `--check-env` run against the real Security Onion box — nobody has pointed this code at a live OpenCTI yet.

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
> a packet with. The TAXII code path is complete, unit-tested (741 tests, all three
> sources) and reviewed against a fake server implementing both protocol versions, but
> **no part of it has ever talked to a real TAXII implementation.** Treat it as untested
> in production until the checklist below has been run. This is a known, accepted gap —
> not an oversight to re-flag.

Six items come from the design spec's own §12; two more surfaced during implementation and are not
in the spec, and a ninth came out of the 2026-08-23 audit. None block what has already shipped, and
each is a contained fix.

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
9. **Found by the audit, and the reason the fake server cannot answer it:** the fake TAXII
   server publishes *relative* API roots (`/api1/`), which `_same_host` accepts without
   reaching the origin comparison at all. The spec makes real roots absolute URLs, and the
   port-normalisation bug the audit fixed lived entirely on that untested branch. Whether a
   real server's roots also agree on scheme and host with the address the operator typed —
   a server behind a reverse proxy may well publish its internal name — is still unobserved.
   If a root is refused, it logs `ignoring API root ... it is not on ...`; that message is now
   the diagnostic, not a symptom of the bug.

#### First-contact checklist — run this when a TAXII server becomes available

1. `python3 nexus.py --probe --source taxii --host <HOST>` — proves reachability, version
   detection, and whichever auth scheme was configured. Try a bad token or password once
   to confirm it reports an authentication failure (401/403) rather than an empty
   collection list succeeding quietly.
2. Confirm the collections list is non-empty and the printed object counts look plausible.
   Zero everywhere with a successful connection points at item 3 above (`match[type]` not
   honoured), an API-root permission problem that discovery is silently swallowing, or a
   root that `_same_host` refused — that one logs `ignoring API root ... it is not on ...`,
   so run with `-v` if the collection list comes back short.
3. Run a full interview through to a `--dry-run` build. The version question defaults
   to 2.1 and is asked before anything can detect; if the server speaks 2.0, confirm that
   stage 2 prints `this server answers TAXII 2.0 ... continuing as 2.0` and that stage 3
   then offers collections. Silence there plus an empty collection list is the failure
   this correction exists to prevent.
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
