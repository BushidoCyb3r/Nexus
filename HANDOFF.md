# Nexus — Handoff

Written for a fresh assistant with no prior context. Read this, then `PLAN.md` for the full design.

**Last updated:** 2026-08-17
**State:** phases 0–6 complete, phase 7 remaining. 313 offline tests passing.
**Never yet run against a real MISP or a real Security Onion box.** Everything below was verified against fakes.

---

## 1. What this is

`nexus.py` is an interactive CLI for a **Security Onion 3.x manager**. It asks for a MISP address and API token, interrogates that MISP for what's actually in it (attribute types, tags, orgs, feeds), walks the operator through a staged interview, pulls matching IOCs from the MISP REST API, maps them to Zeek Intel framework types, diffs them against the existing `intel.dat`, and appends only genuinely new indicators. It can then apply the result to either a standalone node or a distributed sensor grid via salt and verify Zeek accepted it.

Not a library. Not a package. **One script**, standard library only, so it drops onto an air-gapped manager with no pip install.

### Files

```
nexus.py        3238 lines   the tool
test_nexus.py   2767 lines   313 tests, no MISP or SO required
PLAN.md          461 lines   full design doc, section numbers referenced below
HANDOFF.md        226 lines   this file
```

Not a git repository. There is no CI. `python3 -m unittest test_nexus` is the only gate.

---

## 2. Run it

```bash
python3 -m unittest test_nexus        # 313 tests, ~8s, needs nothing external
python3 nexus.py --help

python3 nexus.py                      # default: full interview -> writes intel.dat
python3 nexus.py --check-env          # verify SO paths, __load__.Zeek, do_notice
python3 nexus.py --seed               # copy SO default intel files into the local dir
python3 nexus.py --probe --misp HOST  # connect, print per-type IOC counts, write nothing
python3 nexus.py --lint PATH          # validate an intel.dat
python3 nexus.py --apply              # push existing intel.dat to the grid
python3 nexus.py --explain --profile daily          # show the resolved MISP query
python3 nexus.py --profile daily --yes              # unattended
python3 nexus.py --profile daily --dry-run --diff   # build and compare, write nothing
```

`--probe` is the cheapest way to test credentials — it needs a token but skips the interview.

**On a workstation, the default mode exits early.** `cmd_build` calls `check_env()` first and bails when `/opt/so/saltstack/local/salt/zeek/policy/intel` is absent. That is correct behaviour, not a bug. Use `--probe` or `--lint` off-box.

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

---

## 4. Architecture

One file, banner-delimited sections in dependency order:

```
CONSTANTS   32  SO paths, ZEEK_TYPES, MISP_TO_ZEEK mapping, thresholds
LOGGING    179  RedactingFilter + RedactingFormatter (token scrubbing)
CLIENT     269  MispClient, NoCrossHostRedirect, flatten_attribute
FEEDS      596  feed_provenance, apply_feed_to_params
MAPPING    656  map_attribute — MISP type -> Zeek type, composite splitting
NORMALISE  713  norm_addr/subnet/domain/url/hash/email/..., sanitize_meta
FILTERS    961  ExclusionSet — private IPs, own networks/domains, allowlist
INTEL     1039  build/render/lint/read/merge_additive/backup/write_atomic
CHECKENV  1396  check_env + notice_policy_loaded — stage 0
GUARDRAILS 1510 check_size/not_empty/delta/load_file/broad, run_guardrails
INTERVIEW 1681  ask* primitives, discover, _stage1.._stage8, build_search_params
PROFILES 2472   save_profile, load_profile (JSON, 0600)
DIFF     2525   indicator_delta, summarise_delta, unified_intel_diff
APPLY    2569   seed_load_file, salt_apply, log_errors_since, apply_to_grid
MAIN     2713   argparse, cmd_* dispatch, cmd_build orchestration
```

### Rules the code holds to — preserve these

- **Stdlib only.** No pip, no venv, no new dependencies. Ever.
- **Python 3.6+ syntax.** No f-strings, no type hints, no dataclasses, no walrus. `%`-formatting throughout. The manager's Python version is unconfirmed, so the floor stays low.
- **Purity where it matters.** `mapping`, `normalise`, `filters`, `intel`, `guardrails`, `diff`, `build_search_params` touch no network and no filesystem. That is what makes 313 tests runnable with nothing installed. Do not put I/O in them.
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

### Explicitly out of scope (`PLAN.md` §14)

Indicator aging/expiry, multiple MISP instances, Suricata rule generation, an Elastic feedback loop to prune indicators that never fire, event-level pull for richer descriptions, PyMISP as an optional backend.

---

## 8. Working style the user expects

- Verify claims by running code, not by asserting them. Several real bugs in this codebase were found by executing the suspect case before trusting a review.
- Report failures plainly with the output. Do not claim something works that has not been run.
- Prefer the smallest change that actually fixes the root cause, but never trade away input validation, error handling that prevents data loss, or security measures for brevity.
- Every non-trivial change lands with a test that fails without it.
- The user runs subagents when they ask for them, with this session as orchestrator. Do not spawn them unprompted.
