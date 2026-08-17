# Nexus — MISP → Zeek `intel.dat` Builder for Security Onion

**Status:** phases 0–6 built and tested, plus feed selection; phase 7 (systemd timer, install docs) is all that remains
**Target host:** Security Onion 3.2 manager node
**Form:** a single Python 3 script, `nexus.py`, stdlib only — no pip, no venv, no packaging

```
nexus.py        the tool          python3 nexus.py
test_nexus.py   313 tests         python3 -m unittest test_nexus
```

**New assistant picking this up: read `HANDOFF.md` first.**

Working today: the full interview end-to-end including apply, and unattended replay from a profile. Modes: `--check-env`, `--seed`, `--apply`, `--probe`, `--lint`, `--explain`, `--profile`, `--yes`, `--dry-run --diff`.

---

## 1. What Nexus does

Nexus is an interactive script that runs on a Security Onion 3.2 manager. It:

1. Prompts for a MISP instance address and API token.
2. Connects and *interrogates* the MISP instance to discover what's actually there — attribute types in use, tags, taxonomies, organisations, sharing groups, live counts.
3. Walks the operator through a full interview: which IOC classes, which specific attribute types, which tags to include/exclude, what time window, what quality filters, what metadata to embed.
4. Pulls matching attributes via `/attributes/restSearch` (paginated).
5. Normalises, validates, deduplicates and maps them to Zeek Intel framework types.
6. Preserves every existing indicator, appends newly discovered MISP IOCs,
   and atomically publishes the resulting `intel.dat`.
7. Optionally backs up, validates, and applies it out to the grid.

Interview answers can be saved as a **profile** so later runs are non-interactive (systemd timer friendly).

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

---

## 3. Script structure

One file: `nexus.py`. Executable, `#!/usr/bin/env python3`, stdlib only (`urllib.request`, `ssl`, `json`, `ipaddress`, `getpass`, `argparse`, `os`, `tempfile`, `shutil`, `subprocess`, `datetime`, `re`, `logging`). Drops onto an air-gapped manager and runs.

Internally organised into banner-delimited sections, in dependency order so the file reads top to bottom:

```
#!/usr/bin/env python3
"""nexus.py — build a Zeek intel.dat from MISP, for Security Onion 3.2."""

# ── CONSTANTS ──────────────────────────────────────────────
#   SO paths, Zeek type set, MISP→Zeek mapping table, defaults

# ── LOGGING ────────────────────────────────────────────────
#   setup_logging(), a redacting Filter that scrubs the API token

# ── MISP CLIENT ────────────────────────────────────────────
#   class MispClient:  _request, get_version, describe_types,
#                      get_tags, get_orgs, get_sharing_groups,
#                      count_type, search_attributes (generator, paginated)

# ── MAPPING ────────────────────────────────────────────────
#   map_attribute(attr) -> [(indicator, intel_type), ...]
#   handles composite splitting: domain|ip, ip-src|port, filename|md5

# ── NORMALISE / VALIDATE ───────────────────────────────────
#   norm_addr, norm_subnet, norm_domain, norm_url, norm_hash,
#   norm_email, norm_cert_hash, sanitize_meta
#   NORMALISERS = {Intel::TYPE: fn}

# ── FILTERS ────────────────────────────────────────────────
#   ExclusionSet: RFC1918, own CIDRs, own domain suffixes, allowlist file

# ── INTEL FILE ─────────────────────────────────────────────
#   render_lines(), dedupe(), lint_lines(), read_existing(),
#   merge_additive(), write_atomic(), backup()

# ── PROFILES ───────────────────────────────────────────────
#   load_profile(), save_profile()   (JSON — no YAML dependency)

# ── INTERVIEW ──────────────────────────────────────────────
#   ask(), ask_yes_no(), ask_int(), ask_choice(), ask_multi(),
#   then run_interview() -> Config, one stage per §4 heading

# ── APPLY ──────────────────────────────────────────────────
#   ensure_load_file(), salt_apply(), check_reporter_log()

# ── MAIN ───────────────────────────────────────────────────
#   argparse, mode dispatch, summary printing
```

**Design rules that survive the single-file form:**

- The mapping / normalise / filter / intel-file sections must not touch the network or the filesystem — pure functions over plain dicts, so they're testable by importing `nexus.py` from a test script.
- Only `write_atomic()` may write to the live intel path.
- `MispClient` is the only thing that speaks HTTP.

Internal record shape after fetch:

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

The heart of the tool. Every question has a default in `[brackets]`; Enter accepts it. Every list-select is populated **live from the MISP instance**, never hardcoded. Answers are echoed as a summary for confirmation before anything is fetched or written.

### Stage 0 — Environment check (no questions)

Detects SO version, verifies `/opt/so/saltstack/local/salt/zeek/policy/intel/` exists, and checks for `__load__.Zeek`. If the directory is empty or the load file is missing, offers to seed it from `/opt/so/saltstack/default/salt/zeek/policy/intel/` before going any further.

### Stage 1 — Connection

1. MISP address (IP or hostname)
2. Scheme + port `[https / 443]`
3. Verify TLS certificate? `[yes]` — `no` warns and requires typed confirmation
4. HTTP proxy? `[none]`
5. API token — `getpass`, never echoed, never logged
6. Timeout / retries `[30s / 3]`

→ `GET /servers/getVersion`. Shows MISP version and the token's owning org. Clean abort on 401/403.

### Stage 2 — Discovery (no questions)

Fetches `describeTypes`, `tags`, `organisations`, `sharing_groups`, then a cheap count per candidate attribute type so the operator sees **how many of each actually exist** before choosing.

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
10. Treat `hostname` as `Intel::DOMAIN`? `[yes]`
11. Emit `Intel::SUBNET` for CIDR values in IP attributes? `[yes]`

### Stage 4 — Quality filters

12. `to_ids` flagged only? `[yes]` — the biggest signal/noise lever
13. Published events only? `[yes]`
14. `enforceWarninglist`? `[yes]` — strips known-good (top sites, cloud ranges, root servers)
15. Exclude deleted attributes? `[yes]`
16. Minimum event threat level? `[any]`
17. Event analysis state? `[any / initial / ongoing / completed]`

### Stage 5 — Scope

18. Time window: `last N days` / explicit `from`–`to` / `all` `[last 90d]`
19. Which timestamp — attribute `timestamp` or event `publish_timestamp`? `[timestamp]`
20. Include tags (multi-select, live list, OR semantics) `[none = all]`
21. Exclude tags (multi-select, `NOT` semantics) — pre-suggests `false-positive`, `type:OSINT`
22. Restrict to organisations? `[all]`
23. Restrict to sharing groups / distribution level? `[all]`
24. Restrict to specific event IDs/UUIDs? `[none]`

### Stage 6 — Local exclusions

25. Exclude RFC1918 / loopback / link-local / multicast? `[yes]`
26. Exclude your own networks — CIDR list `[none]`
27. Exclude your own domains — suffix list `[none]`
28. Extra allowlist file to subtract `[none]`

*Prevents Nexus arming Zeek against your own infrastructure — a real risk when MISP holds sinkhole and sandbox artefacts.*

### Stage 7 — Metadata

29. `meta.source` format: fixed string / `MISP` / `MISP-<org>` / `MISP-event-<id>` `[MISP-event-<id>]`
30. `meta.desc` template over `{event_info}`, `{category}`, `{tags}`, `{comment}`, `{type}`, `{org}`, `{uuid}` `[{event_info} | {category}]`
31. `meta.url` — link back to the MISP event? `[yes → https://<misp>/events/view/<id>]`
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

Before fetching: prints the resolved MISP query, estimated result count, and every filter in effect, then one final confirmation. Before writing: prints a per-type breakdown (kept / dropped / deduped / excluded) and asks again.

---

## 4b. Feed selection

Stage 2b, between discovery and IOC selection. `GET /feeds` lists what's configured; the operator picks which to pull from.

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

**Merge mode**: existing lines whose `meta.source` does *not* match the Nexus source prefix are preserved verbatim at the top, so hand-maintained entries survive regeneration.

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
nexus --explain --profile daily.json   # print the resolved MISP query, fetch nothing
nexus --check-env                      # stage 0 only: paths, __load__.Zeek, SO version
```

Token resolution order: `--token-file` → `NEXUS_MISP_TOKEN` env → `/opt/nexus/credentials.json` (0600) → interactive prompt. Under `--yes` the prompt is skipped and the run fails loudly instead — an unattended job must never block forever on a `getpass` nobody will answer.

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

- **Unit** — mapping, normalisation, filters, rendering against fixture attribute dicts. Table-driven, one case per MISP type including every malformed variant.
- **Golden file** — fixture MISP response → expected `intel.dat`, byte-for-byte. Catches the whitespace regressions the SO docs explicitly warn about.
- **Fake MISP** — `http.server` responder replaying canned `restSearch` pages; exercises pagination, 401, 403, 429, timeout, malformed JSON, mid-pagination failure.
- **Linter self-test** — writer output must always pass `--lint`.
- **Integration** — against a MISP training VM or `demo.misp-project.org`, then a lab SO 3.2 grid: seed `__load__.Zeek`, apply, confirm the file reaches `/opt/so/conf/zeek/policy/intel/`, clean `reporter.log`, generate a hit, confirm it lands in `intel.log`.

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

Phases 1–2 are independently useful and fully testable without a Security Onion box. Phase 3 is where the tool becomes what was asked for.

---

## 14. Later (out of scope for v1)

- Indicator **aging** — expire entries older than N days, or honour MISP `first_seen` / `last_seen` and decay scores.
- Multiple MISP instances merged into one file.
- Generating **Suricata** rules from MISP alongside the Zeek intel.
- Feedback loop: query Elastic for `intel.log` hits to find which indicators actually fire, and prune the dead weight.
- MISP **event**-level pull (`/events/restSearch`) for richer `meta.desc` context.
- PyMISP as an optional backend where it's already installed.

---

## 15. Open questions

1. Exact 3.2.x point release on the target manager, and whether the local intel dir is currently populated (does `__load__.Zeek` exist there today?).
2. Does that grid already have an intel feed or anything else managing that file? Merge mode depends on the answer.
4. Expected indicator volume from your MISP — drives the cap, and whether aging moves up from §14.
5. Unattended on a schedule from day one, or interactive-only until it's trusted?

---

## Sources

- [Zeek — Security Onion 3 Documentation](https://docs.securityonion.net/en/3/main/zeek/)
- [Zeek Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html)
- [Zeek `Intel::Type`](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html)
- [MISP Automation / RestSearch API](https://www.circl.lu/doc/misp/automation/)
- [Security Onion 3.2.0 release announcement](https://blog.securityonion.net/2026/07/security-onion-320-now-available-with.html)
