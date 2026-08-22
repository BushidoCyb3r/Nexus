# TAXII as a third IOC source — design

Date: 2026-08-22
Status: approved, not yet implemented
Applies to: `nexus.py` 0.4.0-dev (branch `taxii-source`, forked from `main` at 2c5b9ba)

## 1. Problem

Nexus pulls from MISP and OpenCTI. A large amount of shared threat intelligence
is published over TAXII instead — it is the transport most ISACs, commercial
feeds and government sharing programmes expose. An operator whose intelligence
arrives that way cannot use Nexus at all today.

## 2. Goals

1. TAXII becomes a third value for `--source`, selectable exactly like the
   other two, with no change to anything below the `flatten_*` seam.
2. Both TAXII 2.1 and TAXII 2.0 are supported.
3. Both HTTP Basic and Bearer authentication are supported.
4. Several collections can be pulled in one run and merged into one
   `intel.dat`, with `meta.source` naming the originating collection.
5. The interview is honest about which filters the server applies and which
   Nexus applies after download.

## 3. Non-goals

- No new dependencies. Standard library only.
- No persistent run state. See §7.
- No writing back to a TAXII server. Nexus is a consumer.
- No TAXII 1.x. It is a different protocol (XML over a different transport),
  not a version of this one.
- No support for STIX objects other than `indicator`. Observables arriving as
  bare SCOs are artifacts someone collected, not verdicts, which is the same
  reasoning applied to OpenCTI observables.

## 4. Decisions taken

Recorded because each closes a real fork, and a later reader should not have to
re-derive them:

1. **Both protocol versions**, not 2.1 only.
2. **Both auth schemes**, Basic and Bearer.
3. **Hybrid filtering** — the server does what it can, Nexus does the rest
   after download, and the interview says which is which (§6).
4. **Time window computed per run**, not remembered incremental state (§7).
5. **Several collections per run**, chosen in the interview (§8).

## 5. Where it attaches

The seam is unchanged from the OpenCTI work:

```
  MISP restSearch  ─┐
  OpenCTI GraphQL  ─┼─→ flatten_* ─→ map ─→ normalise ─→ filter ─→ render ─→ merge ─→ write
  TAXII collections─┘              └──────────── source-agnostic ────────────┘
```

- `TaxiiClient(_HttpTransport)` — reuses the shared retry/backoff transport,
  TLS handling, proxy support and redirect guard.
- `flatten_taxii_object(obj, stats=None)` — returns a list of records in the
  existing shape, one per value extracted from the indicator's STIX pattern.
  1:N like `flatten_indicator`, not 1:1 like `flatten_attribute`.
- `parse_stix_pattern` is reused unchanged. A TAXII indicator's `pattern` is
  the same STIX pattern grammar OpenCTI indicators carry, so the extraction
  logic already exists and is already tested.
- `TAXII_TO_ZEEK` is not a new table. STIX property paths already map through
  `STIX_PROPERTY_TO_TYPE` to the same value types `OPENCTI_TO_ZEEK` is keyed
  on, so the existing table is reused.

Nothing in mapping, normalisation, filtering, merging, guardrails or writing
changes.

## 6. Filtering: what the server can do, and what it cannot

This is the substantive difference from the other two sources and the reason
the interview needs different wording rather than just a third branch.

Nexus currently pushes fifteen filter parameters to MISP or OpenCTI, so the
server narrows the result and only the wanted subset is transferred. The TAXII
specification defines two filters that are useful here:

- `match[type]=indicator` — object type
- `added_after=<timestamp>` — when the object entered the collection

There is no server-side filter for labels, marking definitions, confidence,
validity, or the creating organisation. Those properties live inside the STIX
objects, and TAXII has no syntax for reaching into them. Individual products
add proprietary extensions; none are portable, and Nexus will not depend on
one.

**The design:**

- Server-side: `match[type]` and `added_after`, always.
- Client-side, after download: labels, marking definitions (TLP), confidence,
  `valid_until`, and `created_by_ref`.
- The interview presents the client-side questions with explicit wording that
  they are applied after download, not as part of the query. An operator must
  not believe a filter is reducing transfer volume when it is not.
- `--probe` reports **pre-filter** counts for TAXII and says so. The server
  cannot count a filtered subset, and reporting a post-filter number would
  require downloading everything to produce a number about downloading
  everything.

**A version trap that must be surfaced, not silently absorbed:** STIX 2.0
indicators have no `confidence` property. It was added in STIX 2.1. A
confidence filter on a 2.0 feed therefore matches nothing unless Nexus treats
absent confidence as "unfiltered". Nexus treats it as unfiltered and tells the
operator during the interview when the detected version is 2.0.

## 7. What each run pulls

`added_after` is computed per run from the interview's existing time-window
question — the same question MISP's `--days` already drives. No state is
remembered between runs.

The alternative, storing the last cursor per collection, would buy less
bandwidth on a repeat run but introduces persistent run state Nexus does not
have today, plus recovery behaviour for state that is lost (re-pull
everything), stale, or corrupt (silently skip a window). The append-only merge
already makes a repeated window harmless: re-imported rows collapse to nothing
because the key is `(indicator, Intel::Type)`.

This can be revisited if an operator with a genuinely large collection over a
slow link asks for it. It is not needed to ship.

## 8. Collections

TAXII exposes a discovery endpoint listing API roots, and each API root lists
collections. The interview walks both and offers the collections the
credentials can actually see, the same way OpenCTI's discovery offers real
labels and organisations rather than making the operator type them blind.

Several may be selected. The run pulls each in turn and merges the results into
one `intel.dat`. `meta.source` becomes `TAXII-<collection>` — slugged through
the existing `_slug` so it survives as a single tab-free field — so an
`intel.log` hit names the collection it came from. This mirrors the existing
`MISP-feed-<slug>` behaviour and needs no new merge code.

## 9. Protocol details

Both versions differ in four places:

| | TAXII 2.0 | TAXII 2.1 |
|---|---|---|
| Discovery path | `/taxii/` | `/taxii2/` |
| Media type | `application/vnd.oasis.taxii+json; version=2.0` | `application/taxii+json;version=2.1` |
| Objects response | STIX bundle (`objects` inside a `bundle`) | envelope (`objects`, `more`, `next`) |
| Pagination | `Range` request header, `Content-Range` response | `limit` parameter, `more`/`next` in the body |

Nexus probes `/taxii2/` first, then `/taxii/`, and presents the detected
version as the interview's default. Per the standing rule, it still asks — the
detection sets the default answer, it does not replace the question.

## 10. Authentication

- **Bearer**: `Authorization: Bearer <token>`. Reuses the existing single
  secret path unchanged.
- **Basic**: `Authorization: Basic <base64(user:password)>`. This is the first
  source needing **two** secrets; MISP and OpenCTI each need one. Stage 1
  branches on the chosen scheme and collects both.

Both secrets are subject to every existing rule: never logged (both are
registered with the redactor), never written to a profile
(`PROFILE_EXCLUDED_KEYS`), never shown in the pre-flight summary. `base64` is
in the standard library.

## 11. Errors

`TaxiiError` and `TaxiiAuthError` subclass the existing `SourceError` and
`SourceAuthError`, so `cmd_build`'s existing handling covers them with no
change. Unlike OpenCTI's GraphQL — which returns HTTP 200 on an auth failure —
TAXII uses ordinary HTTP status codes, so 401 and 403 map directly.

## 12. Unverified against a real TAXII server

Every protocol claim in §9 and §10 comes from the specification documents, not
from a server this project has talked to. The same honesty applied to OpenCTI
applies here: these ship documented as unverified, with a first-contact
checklist, and are confirmed the first time an instance is available.

1. The `/taxii2/` then `/taxii/` probe order, and whether servers reliably
   answer the version they implement.
2. TAXII 2.0's `Range` / `Content-Range` pagination, which is materially
   different from 2.1's `more`/`next` and is the most likely place for the
   client to be wrong.
3. Whether real servers honour `match[type]=indicator`, or return everything
   and expect the client to filter.
4. Whether `added_after` is inclusive or exclusive at the boundary.
5. The 2.0 confidence gap — that absent `confidence` is genuinely absent
   rather than defaulted by the server.
6. Basic auth in practice, including whether servers challenge with `WWW-
   Authenticate` before accepting a pre-emptive header.

## 13. Testing

- A fake TAXII server on a local `HTTPServer`, in the style of the existing
  `FakeOpencti`, serving both a 2.1 envelope and a 2.0 bundle.
- Version detection picks the right one, and the interview still asks.
- Pagination terminates on both versions, including a repeated-cursor guard
  matching the one `OpenctiClient` already carries.
- Basic and Bearer both produce the correct header, and neither secret appears
  in a log record, a saved profile, or the config summary.
- Client-side filters actually filter: an object failing a label, marking,
  confidence or validity test does not reach the output.
- A 2.0 indicator with no `confidence` is not dropped by a confidence filter.
- Several collections in one run merge into one file, with `meta.source`
  naming each collection.
- End to end: fake server → records → rendered `intel.dat` lines.

## 14. Open questions

None. All five structural decisions are settled and recorded in §4.
