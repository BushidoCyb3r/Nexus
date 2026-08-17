# Nexus — OpenCTI as a second IOC source

**Date:** 2026-08-17
**Status:** design approved, implementation plan pending
**Phase:** 8 (phase 7 — systemd timer and operator README — remains outstanding and now lands after this work, so it documents both sources)

---

## 1. Goal

Nexus currently pulls IOCs from MISP only. This design adds OpenCTI as a second,
independently selectable source that produces the same Zeek `intel.dat`, through
the same normalisation, filtering, guardrail and apply pipeline.

Non-goals: replacing MISP, querying both platforms in a single run, and anything
already listed as out of scope in `PLAN.md` §14.

---

## 2. Decisions taken

These were chosen explicitly by the operator on 2026-08-17 after alternatives
were presented. Do not relitigate without asking.

| Decision | Chosen | Rejected |
|---|---|---|
| Source model | One source per run | Both merged in one run; OpenCTI replacing MISP |
| OpenCTI entities | Indicators only, values from their linked observables | Observables only; both with an interview toggle |
| Filter depth | Full parity with the MISP interview | Core filters only; types plus score only |
| OpenCTI version | 6.x `FilterGroup` syntax only | 5.x flat filters; runtime detection of both |
| Naming | Neutral shared spine, source-specific edges, profile v1 migrated forward | Parallel per-source keys; neutral rename with no back-compat |

Rationale for the source model: `intel.dat` is append-only by
`(indicator, Intel::Type)`. A MISP profile and an OpenCTI profile running as two
separate timer units already converge into one file with no new merge code, no
cross-source dedupe path and no combined query planner. Merging inside a single
run would buy nothing the append-only file does not already provide.

Rationale for indicators-only: OpenCTI observables are artifacts anyone enriched,
not verdicts. They routinely include benign infrastructure. Indicators carry
`x_opencti_score`, `confidence`, `x_opencti_detection`, `revoked` and
`valid_until` — the quality signals that keep `intel.dat` from arming Zeek
against the operator's own resolvers.

---

## 3. Constraints inherited from the existing codebase

These are not negotiable and every part of this design respects them.

- **One file.** `nexus.py` stays a single script that drops onto an air-gapped
  manager. No package, no second module, no `pip install`.
- **Standard library only.** GraphQL is spoken with `urllib.request` and `json`.
  No GraphQL client library.
- **Python 3.6 syntax.** No f-strings, no type hints, no dataclasses, no walrus.
  `%`-formatting throughout.
- **Purity where it matters.** `mapping`, `normalise`, `filters`, `intel`,
  `guardrails`, `diff` and both query builders touch no network and no
  filesystem. This is what keeps the test suite runnable with nothing installed.
- **Every prompt takes `input_fn`** (and `getpass_fn` for tokens). No test may
  block on a TTY.
- **Only `write_atomic` writes the intel file.**
- **Append-only by indicator key.** Existing rows are retained byte-for-byte.
  Any computed removal remains a hard invariant failure.
- **Interactive by default.** Absent a command-line switch, the script asks.
  See §9.

---

## 4. Architecture — where OpenCTI attaches

`flatten_attribute()` is the existing boundary between "talks to a threat intel
platform" and "builds a Zeek file". Everything below it — `map_attribute`,
`normalise`, `ExclusionSet`, `build_indicators`, `lint_lines`,
`merge_additive`, `run_guardrails`, `indicator_delta`, `apply_to_grid` — reads a
plain record dict and has no idea where the record came from.

OpenCTI attaches above that line. Nothing below it changes behaviour.

```
CONSTANTS      + OPENCTI_TO_ZEEK, OPENCTI_UNMAPPABLE, OPENCTI_IOC_CLASSES,
                 OPENCTI_OFF_BY_DEFAULT, GRAPHQL_PATH, default port
LOGGING          unchanged
CLIENT         + _HttpTransport extracted from MispClient
               + OpenctiClient(_HttpTransport)
               + flatten_indicator, parse_stix_pattern
FEEDS            unchanged, MISP-only, skipped for OpenCTI with a printed line
MAPPING        ~ map_attribute gains table=MISP_TO_ZEEK
NORMALISE        unchanged
FILTERS          unchanged
INTEL          ~ build_indicators gains mapping_table=MISP_TO_ZEEK
CHECKENV         unchanged
GUARDRAILS       unchanged
INTERVIEW      ~ stage 1 gains the source question and branches
               + _stage4_quality_opencti, _stage5_scope_opencti
               + build_opencti_filters
PROFILES       ~ PROFILE_VERSION 2, v1 read and migrated forward
DIFF             unchanged
APPLY            unchanged
MAIN           ~ --source, --host, client construction dispatch
```

### 4.1 Shared transport

`MispClient.__init__`, `_request`, `_decode` and `_backoff` contain the TLS
context handling, the `NoCrossHostRedirect` install, the proxy handler, the
retry loop and the token redaction. All of that is source-independent.

Extract it into `_HttpTransport`:

```python
class _HttpTransport(object):
    """Shared HTTP plumbing.  Subclasses own their auth header and their API."""

    RETRY_STATUS = frozenset((429, 500, 502, 503, 504))

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3):
        ...
    def _auth_headers(self):
        raise NotImplementedError
    def _request(self, method, path, body=None):
        ...
```

`MispClient` overrides `_auth_headers` to return `{"Authorization": token}`.
`OpenctiClient` returns `{"Authorization": "Bearer " + token}`.

This is an extraction, not a rewrite. The existing MISP behaviour — cross-host
redirect blocking, the cleartext-HTTP warning, the unverified-TLS warning, the
401/403 to `MispAuthError` mapping, exponential backoff capped at 30s — is
preserved exactly, and the existing transport tests must pass unchanged against
it.

### 4.2 GraphQL specifics that have no MISP analogue

**Errors arrive with HTTP 200.** A GraphQL endpoint signals failure in the body:
`{"errors": [{"message": "...", "extensions": {...}}]}`. An expired or
unprivileged token is a 200 with an errors entry, not a 401. Left unhandled it
looks like an empty result set — the same silent-success failure class as a
missing `__load__.Zeek`, and just as dangerous, because a run would happily
report "0 new indicators" and exit 0 forever.

`OpenctiClient._check_errors(payload)` raises before any data is read:

- message matching `auth|token|forbidden|unauthor` (case-insensitive), or
  `extensions.code` in `("AUTH_REQUIRED", "FORBIDDEN_ACCESS", "AUTH_FAILURE")`
  → `SourceAuthError`
- anything else in `errors` → `SourceError` carrying the first message
- `data` missing or null with no `errors` → `SourceError`

**Cursor pagination.** OpenCTI uses Relay connections: `first: N`, `after:
<cursor>`, with `pageInfo { endCursor hasNextPage globalCount }`. There is no
page number. The loop terminates on `hasNextPage == false`.

The MISP client has a repeated-page-signature guard against a server that
ignores `page`. The cursor equivalent: if `endCursor` is unchanged from the
previous iteration, or is null while `hasNextPage` is true, stop and warn. A
proxy that strips variables would otherwise loop forever.

`max_results` and the optional `max_pages` ceiling behave exactly as they do in
`search_attributes`.

---

## 5. The OpenCTI query

Endpoint: `POST {scheme}://{host}:{port}/graphql`
Headers: `Authorization: Bearer <token>`, `Content-Type: application/json`,
`Accept: application/json`, `User-Agent: nexus/<version>`
Body: `{"query": "...", "variables": {...}}`

Default port 4000 when the scheme is `http`, 443 when `https`. The interview
offers that default; the operator can override it.

### 5.1 Version probe

```graphql
query { about { version } }
```

Replaces `get_version()`. The reported version is logged and printed in the
pre-flight, as MISP's is. A version below 6.0 is a **warning, not a block** — the
filter syntax will simply fail loudly on the first search, and blocking on a
version string parse would be a worse failure mode than a clear query error.

### 5.2 Discovery

Three list queries plus per-type counts.

```graphql
query { labels(first: 500) { edges { node { id value } } } }
query { markingDefinitions(first: 200) { edges { node { id definition definition_type } } } }
query { organizations(first: 500) { edges { node { id name } } } }
```

Each is wrapped in the same "log a warning and carry on" handling `discover()`
already applies to MISP's tag/org/sharing-group calls — discovery failure
degrades the interview, it does not abort the run.

Counts, one query per candidate main observable type:

```graphql
query Count($filters: FilterGroup) {
  indicators(first: 1, filters: $filters) { pageInfo { globalCount } }
}
```

`globalCount` is an exact total, so `count_type` returns `(count, True)` — better
than MISP's bounded probe, which returns `exact=False` when it hits its ceiling.
If `globalCount` is absent (permission-dependent), fall back to
`(len(edges), False)` so the interview still shows something honest.

Discovery builds `name -> id` maps for labels, markings and organizations,
because 6.x filters take ids (§5.4).

### 5.3 The indicator search

```graphql
query Indicators($first: Int!, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters,
             orderBy: created_at, orderMode: asc) {
    pageInfo { endCursor hasNextPage globalCount }
    edges {
      node {
        id
        standard_id
        name
        description
        pattern
        pattern_type
        x_opencti_score
        confidence
        revoked
        x_opencti_detection
        valid_from
        valid_until
        created_at
        updated_at
        createdBy { ... on Identity { name } }
        objectLabel { id value }
        objectMarking { id definition }
        observables(first: 50) {
          edges {
            node {
              id
              entity_type
              observable_value
              ... on StixFile { name hashes { algorithm hash } }
              ... on Artifact { hashes { algorithm hash } }
              ... on X509Certificate { hashes { algorithm hash } }
              ... on UserAccount { account_login }
              ... on Software { name }
            }
          }
        }
      }
    }
  }
}
```

`orderBy: created_at, orderMode: asc` gives a stable cursor walk. Without a
stable sort, an instance ingesting during a long pull can shift the window and
drop rows.

`observables(first: 50)` is a deliberate ceiling. An indicator linked to more
than 50 observables is unusual; when `observables.pageInfo.hasNextPage` is true
the client increments a truncation counter and the run report prints
`N indicators had more than 50 linked observables; some values were not read`.
Silent truncation would drop IOCs, which is the failure class this codebase
already refuses to tolerate elsewhere.

### 5.4 `build_opencti_filters(config)`

Pure function, no I/O, the exact counterpart to `build_search_params`. Returns
the `FilterGroup` dict that `--explain` prints.

```python
{
  "mode": "and",
  "filters": [
    {"key": ["x_opencti_main_observable_type"],
     "values": ["IPv4-Addr", "Domain-Name"], "operator": "eq", "mode": "or"},
    {"key": ["x_opencti_score"], "values": ["50"], "operator": "gte", "mode": "or"},
    {"key": ["confidence"], "values": ["60"], "operator": "gte", "mode": "or"},
    {"key": ["revoked"], "values": ["false"], "operator": "eq", "mode": "or"},
    {"key": ["x_opencti_detection"], "values": ["true"], "operator": "eq", "mode": "or"},
    {"key": ["valid_until"], "values": ["2026-08-17T00:00:00Z"], "operator": "gt", "mode": "or"},
    {"key": ["created_at"], "values": ["2026-07-18T00:00:00Z"], "operator": "gte", "mode": "or"},
    {"key": ["objectLabel"], "values": ["<label-id>"], "operator": "eq", "mode": "or"},
    {"key": ["objectMarking"], "values": ["<marking-id>"], "operator": "eq", "mode": "or"},
    {"key": ["createdBy"], "values": ["<org-id>"], "operator": "eq", "mode": "or"}
  ],
  "filterGroups": []
}
```

Excluded labels cannot sit in the same `and` group as included ones with the same
key, so they go into a nested group:

```python
"filterGroups": [
  {"mode": "and",
   "filters": [{"key": ["objectLabel"], "values": ["<id>"],
                "operator": "not_eq", "mode": "and"}],
   "filterGroups": []}
]
```

Only keys the operator actually chose are emitted. An unfiltered run produces
`{"mode": "and", "filters": [], "filterGroups": []}`, which OpenCTI accepts.

**Label ids versus values.** 6.x filter keys `objectLabel`, `objectMarking` and
`createdBy` take entity ids. The interview shows names; discovery's `name -> id`
map does the translation; the filter carries ids. A name with no discovered id
is dropped with a printed warning rather than passed through as a guess. This
is flagged in §11 as needing confirmation against the live instance — some
builds also accept values.

---

## 6. Mapping

### 6.1 `OPENCTI_TO_ZEEK`

Same `[(part_index, zeek_type)]` shape as `MISP_TO_ZEEK`, so `map_attribute`
gains one parameter and no new branches. Part index is always 0 — OpenCTI has no
`domain|ip` composite equivalent.

```python
OPENCTI_TO_ZEEK = {
    "IPv4-Addr":       [(0, "Intel::ADDR")],
    "IPv6-Addr":       [(0, "Intel::ADDR")],
    "Domain-Name":     [(0, "Intel::DOMAIN")],
    "Hostname":        [(0, "Intel::DOMAIN")],
    "Url":             [(0, "Intel::URL")],
    "Email-Addr":      [(0, "Intel::EMAIL")],
    "File-Name":       [(0, "Intel::FILE_NAME")],
    "MD5":             [(0, "Intel::FILE_HASH")],
    "SHA-1":           [(0, "Intel::FILE_HASH")],
    "SHA-224":         [(0, "Intel::FILE_HASH")],
    "SHA-256":         [(0, "Intel::FILE_HASH")],
    "SHA-384":         [(0, "Intel::FILE_HASH")],
    "SHA-512":         [(0, "Intel::FILE_HASH")],
    "X509-SHA-1":      [(0, "Intel::CERT_HASH")],
    "User-Account":    [(0, "Intel::USER_NAME")],
    "Software":        [(0, "Intel::SOFTWARE")],
}
```

An `IPv4-Addr` whose value is a CIDR is routed to `Intel::SUBNET` by the same
rule `map_attribute` already applies to MISP `ip-src`, honouring `allow_subnet`
and the `MIN_PREFIX_V4` / `MIN_PREFIX_V6` floors.

Hash algorithm labels are normalised before lookup — OpenCTI emits `SHA-256`,
`SHA256` and `sha-256` depending on the connector that wrote the object. The
normaliser upper-cases and inserts the hyphen, then `VALID_HASH_LENGTHS`
validates the hash itself as it already does for MISP.

X.509 hashes are keyed separately (`X509-SHA-1`) because certificate SHA-1 is
`Intel::CERT_HASH`, not `Intel::FILE_HASH`. MD5 and SHA-256 certificate
fingerprints are dropped and counted, matching the existing MISP treatment.

### 6.2 `OPENCTI_UNMAPPABLE`

Reported, never silently discarded:

```python
OPENCTI_UNMAPPABLE = {
    "Mutex":                  "no Zeek Intel equivalent",
    "Windows-Registry-Key":   "no Zeek Intel equivalent",
    "Autonomous-System":      "no Zeek Intel equivalent",
    "Process":                "no Zeek Intel equivalent",
    "Directory":              "no Zeek Intel equivalent",
    "Network-Traffic":        "no Zeek Intel equivalent",
    "Cryptocurrency-Wallet":  "no Zeek Intel equivalent",
    "Phone-Number":           "no Zeek Intel equivalent",
    "Text":                   "free-form, not an indicator",
    "X509-MD5":               "Intel::CERT_HASH is SHA-1 only",
    "X509-SHA-256":           "Intel::CERT_HASH is SHA-1 only",
    "SSDEEP":                 "fuzzy hash, no Zeek equivalent",
    "TLSH":                   "fuzzy hash, no Zeek equivalent",
}
```

### 6.3 `OPENCTI_IOC_CLASSES` and defaults

Mirrors `IOC_CLASSES`, keyed by `x_opencti_main_observable_type` values so a
stage 3 selection translates directly into a filter:

```python
OPENCTI_IOC_CLASSES = {
    "network": ("Network - IP / subnet / domain / URL",
                ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "Url"]),
    "file":    ("File - hashes / filenames", ["StixFile", "Artifact"]),
    "email":   ("Email - addresses", ["Email-Addr"]),
    "tls":     ("TLS - certificate hashes", ["X509-Certificate"]),
    "host":    ("Host - user agents / usernames", ["User-Account", "Software"]),
}

OPENCTI_OFF_BY_DEFAULT = frozenset(("User-Account", "Software"))
```

Note the asymmetry between the class values (`StixFile`, which is what
`x_opencti_main_observable_type` reports) and the mapping table keys (`MD5`,
`SHA-256`, `File-Name`, which are what `flatten_indicator` emits per extracted
value). The filter speaks main-observable-type; the mapper speaks extracted
value type. `flatten_indicator` is where one becomes the other.

### 6.4 `flatten_indicator(node)`

Emits zero or more records in the existing internal shape, one per extracted
value, so `build_indicators` needs no knowledge of OpenCTI.

| Record field | Source |
|---|---|
| `value` | `observable_value`, hash value, `name`, or `account_login` |
| `type` | extracted value type — an `OPENCTI_TO_ZEEK` key |
| `category` | `pattern_type` |
| `to_ids` | `x_opencti_detection` |
| `uuid` | `standard_id` |
| `timestamp` | `updated_at` converted to epoch seconds |
| `comment` | `description` |
| `event_id` | indicator `id` |
| `event_uuid` | `standard_id` |
| `event_info` | indicator `name` |
| `event_tags` | `objectLabel[].value` + `objectMarking[].definition` |
| `org` | `createdBy.name` |

Labels and markings both land in `event_tags`, so the existing client-side tag
filtering in `_fetch_records` and any tag-based exclusion works unchanged.

A `StixFile` observable yields one record per hash plus one for `name` — an
indicator carrying both MD5 and SHA-256 for one file produces two
`Intel::FILE_HASH` rows, which is correct: Zeek matches whichever algorithm it
is configured to compute.

### 6.5 STIX pattern fallback — `parse_stix_pattern(pattern)`

Used only when an indicator has zero linked observables **and**
`pattern_type == "stix"`.

Extracts comparison expressions of the form
`<object-type>:<property> = '<value>'`, including
`file:hashes.'SHA-256' = '...'`. Handles `OR`-joined and bracketed comparisons
by extracting every match. Ignores `AND`, `FOLLOWEDBY`, qualifiers
(`WITHIN`, `REPEATS`, `START`/`STOP`) and negations — an expression Nexus cannot
represent as a flat indicator list is skipped and counted, not approximated.

Property-to-type resolution:

```
ipv4-addr:value       -> IPv4-Addr
ipv6-addr:value       -> IPv6-Addr
domain-name:value     -> Domain-Name
url:value             -> Url
email-addr:value      -> Email-Addr
file:name             -> File-Name
file:hashes.'MD5'     -> MD5           (and SHA-1 / SHA-256 / SHA-512, quoted or not)
x509-certificate:hashes.'SHA-1' -> X509-SHA-1
user-account:account_login -> User-Account
software:name         -> Software
```

Non-STIX pattern types — `sigma`, `yara`, `snort`, `suricata`, `pcre`, `spl`,
`eql`, `shodan` — are counted as unmappable and reported. They are never
regex-mined for values; a YARA rule's string literals are not indicators.

---

## 7. `BuildStats` additions

The run report gains OpenCTI-specific counters, printed only when the source is
OpenCTI:

- indicators with no linked observables that fell back to pattern parsing
- indicators skipped because their pattern type is not `stix`
- indicators whose STIX pattern parsed to zero usable values
- indicators whose linked observables were truncated at 50
- per-type unmappable counts, using the existing reporting path

---

## 8. Interview

Stage 0 (environment), stage 6 (exclusions), stage 7 (metadata) and stage 8
(output) are shared and unchanged.

### Stage 1 — source and connection

New first question, asked whenever `--source` was not supplied:

```
Threat intel platform [misp/opencti]:
```

Then the same connection questions for either source — host, scheme, port, TLS
verification, proxy, token, timeout, retries — with source-appropriate labels
and defaults:

| | MISP | OpenCTI |
|---|---|---|
| Address prompt | `MISP address (IP or hostname)` | `OpenCTI address (IP or hostname)` |
| Default port | 443 / 80 | 443 (https) / 4000 (http) |
| Token prompt | `MISP API token` | `OpenCTI API token` |

The `INSECURE` typed confirmation for disabled TLS verification applies to both,
unchanged.

### Stage 2 — discovery

MISP: unchanged.
OpenCTI: labels, marking definitions, organizations, and exact per-type counts
from `globalCount`. Prints
`N labels, N markings, N organisations` in the same shape as the MISP line.

### Stage 2b — feeds

MISP only. For OpenCTI the stage prints one line and moves on:

```
-- Stage 2b: feeds
  Not applicable to OpenCTI; provenance is filtered by author and label in stage 5.
```

Skipping silently would look like a bug to an operator who knows the MISP flow.

### Stage 3 — IOC types

Driven by `OPENCTI_IOC_CLASSES`, annotated with live counts exactly as the MISP
version is, with `OPENCTI_OFF_BY_DEFAULT` unselected. The result populates the
`x_opencti_main_observable_type` filter.

### Stage 4 — quality, OpenCTI variant

| Question | Default |
|---|---|
| Minimum `x_opencti_score` (0-100) | 50 |
| Minimum `confidence` (0-100) | 0 (no filter) |
| Exclude revoked indicators? | yes |
| Require the detection flag? | no |
| Exclude indicators past `valid_until`? | yes |

`valid_until` is compared against the run's own UTC timestamp, computed at
query-build time. `build_opencti_filters` therefore takes an optional `now`
parameter defaulting to `None`, resolved inside to
`datetime.now(timezone.utc)` — tests pass a fixed value so the builder stays
deterministic and pure with respect to its inputs.

### Stage 5 — scope, OpenCTI variant

| Question | Notes |
|---|---|
| Include labels | multi-select from discovery, translated to ids |
| Exclude labels | nested `not_eq` filter group |
| TLP markings | multi-select from discovery, translated to ids |
| Created by (organisations) | multi-select from discovery, translated to ids |
| Time window | all / last N days / explicit range |
| Timestamp field | `created_at` or `valid_from` |

The MISP stage 5 questions that have no OpenCTI counterpart — sharing groups,
event ids, threat level, analysis state — are simply not asked.

### Pre-flight summary

`summarise_config` gains a source line and prints whichever query the run will
issue:

```
  source      : opencti
  OpenCTI     : https://cti.example.org (verify TLS: yes)
  ...
  filters     : {"filterGroups": [], "filters": [...], "mode": "and"}
```

---

## 9. Interactivity rule

**Absent a command-line switch, the script asks.** No flag may be silently
defaulted into a behaviour the operator did not choose.

Concretely:

- `--source` absent → stage 1 asks which platform. There is no implicit default
  to MISP.
- `--host` absent → stage 1 asks for the address.
- Token absent from `--token-file` / `NEXUS_TOKEN` → `getpass` prompt.
- `--profile` absent → the full interview runs.

Flags exist to *skip* questions for unattended replay, never to change what a
flagless run means. A bare `python3 nexus.py` is a complete interview for either
platform, exactly as it is today for MISP.

`--yes` remains the only switch that answers questions on the operator's behalf,
and its existing scope is unchanged.

---

## 10. Config, profiles and CLI

### 10.1 Neutral spine

| Old | New |
|---|---|
| `misp_host` | `source_host` |
| `misp_base_url` | `source_base_url` |
| `MispError` | `SourceError` (`MispError = SourceError` alias retained) |
| `MispAuthError` | `SourceAuthError` (`MispAuthError` alias retained) |
| — | `source` = `"misp"` \| `"opencti"` |

`MispClient` keeps its name — it is the MISP-specific client, and
`OpenctiClient` sits beside it. Only the shared spine goes neutral.

The exception aliases exist so that existing `except MispError` sites and tests
keep working through the rename; new code raises and catches the neutral names.

### 10.2 Profile schema

`PROFILE_VERSION` moves from 1 to 2.

`load_profile` accepts both:

- **v2** — read as-is.
- **v1** — migrated forward in memory: `misp_host` → `source_host`,
  `misp_base_url` → `source_base_url`, `source` set to `"misp"`. A log line
  records the migration.
- **anything else** — rejected as today.

Migration is in-memory only; the file is rewritten as v2 the next time the
profile is saved. A systemd timer replaying a v1 profile keeps working across
the upgrade, which is the whole point — silently breaking a scheduled run is
worse than any amount of migration code.

`PROFILE_EXCLUDED_KEYS` is unchanged: `token` and `discovery` are still never
persisted.

### 10.3 CLI

New:

```
--source {misp,opencti}   which platform to pull from; asked if omitted
--host HOST               platform address; asked if omitted
```

`--misp HOST` is retained as a deprecated alias for `--host` and implies
`--source misp`. It prints a one-line deprecation notice and continues.

Unchanged and source-independent: `--check-env`, `--seed`, `--lint`, `--apply`.
Working for both sources: `--probe`, `--explain`, `--profile`, `--yes`,
`--dry-run`, `--diff`.

`--probe` against OpenCTI prints per-main-observable-type counts from
`globalCount` and writes nothing, matching its MISP behaviour.

### 10.4 Metadata defaults

- `meta.source` defaults to `OpenCTI` for that source (`MISP` unchanged).
- `meta.url` becomes `{source_base_url}/dashboard/observations/indicators/{id}`.
- `DEFAULT_SOURCE_PREFIX` stays `"MISP"` as the module-level default; the
  interview sets the OpenCTI value in stage 7.

Because `intel.dat` is append-only by `(indicator, Intel::Type)`, running a MISP
profile and an OpenCTI profile against the same file converges cleanly. The
first source to write an indicator owns its `meta.source`, so a `intel.log` hit
names whichever platform contributed it first. That is existing merge behaviour,
not new logic.

---

## 11. Testing

A fake GraphQL transport mirroring the existing fake-MISP pattern: canned
`{"data": ...}` payloads keyed by the operation in the request body, plus
injectable error payloads.

Roughly 95 new tests, no new framework, `python3 -m unittest test_nexus` stays
the only gate. Coverage:

- **Transport** — Bearer header, `errors`-with-200 → `SourceAuthError` /
  `SourceError`, `data: null` handling, retry and backoff reuse, cross-host
  redirect still blocked, token still redacted from logs and tracebacks.
- **Pagination** — multi-page cursor walk, `hasNextPage` termination,
  repeated-cursor guard, null-cursor guard, `max_results` and `max_pages`.
- **`build_opencti_filters`** — every filter key, exclusion nesting, empty
  config produces a valid empty `FilterGroup`, name→id translation, unknown name
  dropped with a warning, fixed `now` for `valid_until`.
- **`flatten_indicator`** — every field, multi-hash `StixFile`, `X509Certificate`
  SHA-1 kept and MD5/SHA-256 dropped, labels and markings merged into
  `event_tags`, missing `createdBy`, `updated_at` to epoch.
- **Mapping** — every `OPENCTI_TO_ZEEK` key end to end through `normalise`,
  CIDR-valued `IPv4-Addr` to `Intel::SUBNET`, hash algorithm label normalisation,
  hash length validation, every `OPENCTI_UNMAPPABLE` key counted and reported.
- **`parse_stix_pattern`** — each supported property form, quoted and unquoted
  hash keys, `OR`-joined comparisons, qualifiers ignored, non-STIX pattern types
  counted and never mined.
- **Truncation** — `observables.hasNextPage` increments the counter and the
  report prints it.
- **Profiles** — v1 read and migrated, v2 round-trip, `token` and `discovery`
  still excluded, 0600 mode preserved, a v1 file with an injected `token` still
  has it stripped.
- **Interview** — stages 1, 3, 4 and 5 for OpenCTI under scripted `input_fn`,
  the source question, stage 2b's skip line, source defaults, and the
  flagless-run-is-interactive rule from §9.
- **CLI** — `--source`, `--host`, `--misp` alias and its deprecation notice,
  `--explain` printing the FilterGroup, `--probe` against the fake.
- **Regression** — all 313 existing tests pass unchanged. The rename touches
  them; behaviour must not change.

---

## 12. Unverified, to confirm against a live instance

Flagged the same way `threat_level_id` and `analysis` already are in `HANDOFF.md`
§7. None of these block implementation; all of them could change one line each.

1. **`x_opencti_detection` as a filter key.** The field exists on Indicator; its
   filterability is what needs checking. If it is not filterable, the detection
   requirement moves to a client-side filter in the fetch loop.
2. **`objectLabel` / `objectMarking` return shape.** This design assumes bare
   lists, which is 6.x. 5.x returned `edges { node { ... } }`. If a 6.x point
   release differs, the flattener needs the edges walk.
3. **Label filtering by id versus value.** This design translates names to ids.
   Some builds accept values directly; if so the discovery id map becomes
   optional rather than required.
4. **`globalCount` under the operator's auth level.** Falls back to a bounded
   count if absent, but the interview's count annotations get less useful.
5. **Rate limiting on a large paginated pull.** The existing retry/backoff
   handles 429, but OpenCTI's actual ceiling and page size sweet spot are
   unknown. Default page size starts at 100 (OpenCTI's connection default is
   smaller than MISP's) and is tunable.
6. **OpenCTI version and reachability from the manager.** Same pre-flight class
   as the outstanding `--check-env` run against the real Security Onion box.

---

## 13. Out of scope

Everything in `PLAN.md` §14 stays out of scope. Additionally, and specific to
this work:

- Querying MISP and OpenCTI in the same run.
- OpenCTI observables as a source (indicators only, per §2).
- OpenCTI 5.x filter syntax.
- Pushing anything back to OpenCTI — no sightings, no hit feedback. Nexus stays
  read-only against the platform.
- OpenCTI connectors, streams and the live-stream API. This is a polled pull,
  the same shape as the MISP path.
- Relationship traversal (indicator → intrusion set → campaign) for richer
  `meta.desc`. Same reasoning as the existing event-level-pull exclusion.
