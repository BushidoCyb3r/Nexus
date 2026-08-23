# TAXII Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TAXII 2.0 and 2.1 as a third selectable IOC source alongside MISP and OpenCTI, pulling STIX indicators from one or more collections into the existing `intel.dat` pipeline.

**Architecture:** A `TaxiiClient` on the existing `_HttpTransport`, and a `flatten_taxii_object()` that emits the established record shape. Everything below the `flatten_*` seam is untouched — `parse_stix_pattern` already extracts every type a TAXII indicator pattern can carry, and all of them resolve against the existing `OPENCTI_TO_ZEEK` table, so no third mapping table is needed. The one genuinely new thing is client-side filtering, because TAXII defines only two useful server-side filters where Nexus currently pushes fifteen.

**Tech Stack:** Python 3.6 standard library only. `unittest`. Fakes built on `http.server.HTTPServer`. No new files.

**Spec:** `docs/superpowers/specs/2026-08-22-taxii-source-design.md`

## Global Constraints

Every task's requirements implicitly include all of these. Violating one is a task failure regardless of whether that task's own steps mention it.

- **Standard library only. No new dependencies, ever.**
- **Python 3.6 syntax floor.** No f-strings, no variable type hints, no dataclasses, no walrus. Use `%`-formatting. The suite runs on 3.9, so a 3.7+-only construct passes tests and fails in production — this has already happened once in this project (`%z` did not accept a colon before 3.7).
- **One file.** Production code in `nexus.py`, tests in `test_nexus.py`.
- **Only `write_atomic()` writes the intel file.**
- **Append-only merge by `(indicator, Intel::Type)`.** Existing rows survive byte-for-byte. A computed removal is a hard invariant failure that blocks the write.
- **Secrets are never logged, never persisted to a profile, never displayed.** TAXII Basic auth introduces a *second* secret; both are covered by this rule.
- **Absent a command-line switch, the script asks.** Flags skip questions for unattended replay only. A flagless run runs the full interview. There is no implicit default for anything the operator should choose.
- **Never let a filter silently do nothing.** This project has fixed that defect three times. If a filter cannot be applied, say so.
- Every non-trivial change lands with a test that fails without it. **Watch each new test fail before making it pass.**
- Run `python3 -m unittest test_nexus 2>&1 | tail -3` before every commit. Baseline is **537 tests, OK**; the count only goes up.

---

### Task 1: Transport hooks for a second secret and a per-source Accept header

`_request` hardcodes `Accept: application/json`, but TAXII requires a version-specific media type. `_HttpTransport.__init__` registers exactly one secret with the redactor, but Basic auth has two. Both are small, shared changes; doing them first keeps every later task from monkey-patching around them.

**Files:**
- Modify: `nexus.py` — `_HttpTransport` (locate with `grep -n 'class _HttpTransport' nexus.py`)
- Test: `test_nexus.py`

**Interfaces:**
- Produces: `_HttpTransport.ACCEPT` (class attribute, default `"application/json"`), used by `_request`; and `_HttpTransport.add_secret(value)`, which registers an additional secret with `REDACTOR` and tolerates `None`/empty.

- [ ] **Step 1: Write the failing tests**

```python
class TestTransportHooks(unittest.TestCase):
    def test_accept_defaults_to_json(self):
        self.assertEqual(nexus._HttpTransport.ACCEPT, "application/json")

    def test_a_subclass_can_override_accept(self):
        class Probe(nexus._HttpTransport):
            ACCEPT = "application/taxii+json;version=2.1"

            def _auth_headers(self):
                return {}
        client = Probe(host="example.test", token="t")
        self.assertEqual(client.ACCEPT, "application/taxii+json;version=2.1")

    def test_add_secret_registers_with_the_redactor(self):
        class Probe(nexus._HttpTransport):
            def _auth_headers(self):
                return {}
        client = Probe(host="example.test", token="first")
        client.add_secret("second-secret")
        record = logging.LogRecord("n", logging.INFO, "p", 1,
                                   "saw second-secret here", None, None)
        nexus.REDACTOR.filter(record)
        self.assertNotIn("second-secret", record.getMessage())

    def test_add_secret_tolerates_empty(self):
        class Probe(nexus._HttpTransport):
            def _auth_headers(self):
                return {}
        client = Probe(host="example.test", token="t")
        client.add_secret(None)      # must not raise
        client.add_secret("")
```

Confirm `logging` is imported in `test_nexus.py`; add it if not. Check `REDACTOR`'s real filter method name with `grep -n 'class .*Redact' -A 20 nexus.py` and adjust the assertion to match how the existing redactor tests drive it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestTransportHooks -v`
Expected: FAIL — no `ACCEPT`, no `add_secret`.

- [ ] **Step 3: Implement**

In `_HttpTransport`, beside `RETRY_STATUS`:

```python
    # TAXII negotiates a version-specific media type; everything else is
    # plain JSON.  A class attribute rather than a constructor argument
    # because it is a property of the protocol, not of the connection.
    ACCEPT = "application/json"
```

In `__init__`, after the existing `REDACTOR.add_secret(token)`, nothing changes. Add the method:

```python
    def add_secret(self, value):
        """Register a further secret with the redactor.

        Basic auth carries two -- a username and a password -- where every
        other source Nexus speaks to carries one.
        """
        if value:
            REDACTOR.add_secret(value)
```

In `_request`, change the `Accept` line to:

```python
            "Accept": self.ACCEPT,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestTransportHooks -v`
Expected: PASS, 4 tests

- [ ] **Step 5: Run the full suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 541 tests. If any existing MISP or OpenCTI test fails, the `Accept` change altered a header those fakes assert on — read the test before touching it and confirm the default is genuinely unchanged.

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: transport hooks for a per-source Accept header and a second secret"
```

---

### Task 2: `TaxiiClient` — auth and version detection

**Files:**
- Modify: `nexus.py` — add to the `# CLIENT` section after `OpenctiClient`
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `_HttpTransport.ACCEPT`, `_HttpTransport.add_secret` (Task 1).
- Produces:
  - `TAXII_VERSIONS = ("2.1", "2.0")`
  - `TAXII_ACCEPT = {"2.1": "application/taxii+json;version=2.1", "2.0": "application/vnd.oasis.taxii+json; version=2.0"}`
  - `TAXII_DISCOVERY = {"2.1": "/taxii2/", "2.0": "/taxii/"}`
  - `TaxiiError`, `TaxiiAuthError` — subclasses of `SourceError`, `SourceAuthError`
  - `TaxiiClient(host, token, scheme="https", port=None, verify_tls=True, proxy=None, timeout=30, retries=3, version="2.1", username=None)` — when `username` is set it uses Basic, otherwise Bearer.
  - `TaxiiClient.detect_version()` → `"2.1"` or `"2.0"`, or raises `TaxiiError` if neither answers.
  - `TaxiiClient.get_version()` → dict with a `"version"` key, matching the shape `cmd_build` already logs from the other two clients.

- [ ] **Step 1: Write the failing tests**

```python
class TestTaxiiAuth(unittest.TestCase):
    def test_bearer_when_no_username(self):
        client = nexus.TaxiiClient(host="taxii.test", token="tok")
        self.assertEqual(client._auth_headers()["Authorization"], "Bearer tok")

    def test_basic_when_username_given(self):
        client = nexus.TaxiiClient(host="taxii.test", token="pw",
                                   username="alice")
        expected = "Basic " + base64.b64encode(b"alice:pw").decode("ascii")
        self.assertEqual(client._auth_headers()["Authorization"], expected)

    def test_the_username_is_registered_as_a_secret(self):
        nexus.TaxiiClient(host="taxii.test", token="pw", username="alice")
        record = logging.LogRecord("n", logging.INFO, "p", 1,
                                   "user alice here", None, None)
        nexus.REDACTOR.filter(record)
        self.assertNotIn("alice", record.getMessage())

    def test_accept_follows_the_version(self):
        self.assertEqual(
            nexus.TaxiiClient(host="h", token="t", version="2.1").ACCEPT,
            "application/taxii+json;version=2.1")
        self.assertEqual(
            nexus.TaxiiClient(host="h", token="t", version="2.0").ACCEPT,
            "application/vnd.oasis.taxii+json; version=2.0")

    def test_auth_errors_are_source_auth_errors(self):
        self.assertTrue(issubclass(nexus.TaxiiAuthError, nexus.SourceAuthError))
        self.assertTrue(issubclass(nexus.TaxiiError, nexus.SourceError))
```

Add `import base64` to `test_nexus.py` if absent.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestTaxiiAuth -v`
Expected: FAIL — no `TaxiiClient`.

- [ ] **Step 3: Implement the constants and errors**

Beside the other source constants near `SOURCES`:

```python
TAXII_VERSIONS = ("2.1", "2.0")
# 2.1 renamed the media type and moved discovery; 2.0 servers answer neither.
TAXII_ACCEPT = {
    "2.1": "application/taxii+json;version=2.1",
    "2.0": "application/vnd.oasis.taxii+json; version=2.0",
}
TAXII_DISCOVERY = {"2.1": "/taxii2/", "2.0": "/taxii/"}
```

In the exceptions block beside `SourceError`:

```python
class TaxiiError(SourceError):
    pass


class TaxiiAuthError(SourceAuthError):
    pass
```

- [ ] **Step 4: Implement the client**

```python
class TaxiiClient(_HttpTransport):
    """TAXII 2.0 and 2.1.

    Unlike OpenCTI's GraphQL -- which answers 200 even when it refuses you --
    TAXII uses ordinary HTTP status codes, so the transport's existing 401/403
    handling already covers authentication failure.
    """

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3, version="2.1",
                 username=None):
        _HttpTransport.__init__(self, host, token, scheme=scheme, port=port,
                                verify_tls=verify_tls, proxy=proxy,
                                timeout=timeout, retries=retries)
        if version not in TAXII_ACCEPT:
            raise TaxiiError("unsupported TAXII version %r" % (version,))
        self.version = version
        self.username = username
        # The username is half of a Basic credential, so it is as much a
        # secret as the password it is paired with.
        self.add_secret(username)

    @property
    def ACCEPT(self):
        return TAXII_ACCEPT[self.version]

    def _auth_headers(self):
        if self.username:
            raw = ("%s:%s" % (self.username, self.token)).encode("utf-8")
            return {"Authorization": "Basic %s"
                                     % base64.b64encode(raw).decode("ascii")}
        return {"Authorization": "Bearer %s" % self.token}

    def detect_version(self):
        """Probe 2.1's discovery path, then 2.0's.

        The detected value becomes the interview's default answer; it does not
        replace the question.
        """
        for version in TAXII_VERSIONS:
            saved = self.version
            self.version = version
            try:
                self._request("GET", TAXII_DISCOVERY[version])
                return version
            except SourceAuthError:
                raise            # credentials are wrong, not the version
            except SourceError:
                self.version = saved
        raise TaxiiError(
            "no TAXII discovery endpoint answered at %s (tried %s)"
            % (self.base_url, " and ".join(
                TAXII_DISCOVERY[v] for v in TAXII_VERSIONS)))

    def get_version(self):
        payload, _ = self._request("GET", TAXII_DISCOVERY[self.version])
        title = (payload or {}).get("title") or "TAXII server"
        return {"version": self.version, "title": title}
```

`ACCEPT` is a property here where the base class has a plain attribute; that is deliberate — the media type depends on the instance's negotiated version. Add `import base64` to `nexus.py` if absent.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestTaxiiAuth -v`
Expected: PASS, 5 tests

- [ ] **Step 6: Run the full suite and commit**

```bash
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: TaxiiClient with Basic and Bearer auth and version detection"
```

Expected: `OK`, 546 tests.

---

### Task 3: A fake TAXII server, and collection discovery

**Files:**
- Modify: `nexus.py` — `TaxiiClient`
- Test: `test_nexus.py` — add the fake beside the existing `FakeOpencti`

**Interfaces:**
- Produces: `TaxiiClient.get_collections()` → list of dicts `{"id", "title", "api_root"}`, across every API root the credentials can see.

- [ ] **Step 1: Write the fake server**

Model it on the existing OpenCTI fake — find it with `grep -n 'class FakeOpencti' test_nexus.py` and follow its start/stop and threading style rather than inventing a new one. It must serve, for 2.1:

- `GET /taxii2/` → `{"title": "Test TAXII", "api_roots": ["/api1/", "/api2/"]}`
- `GET /api1/collections/` → `{"collections": [{"id": "c1", "title": "Feed One"}]}`
- `GET /api2/collections/` → `{"collections": [{"id": "c2", "title": "Feed Two"}]}`

and for 2.0, the same shapes under `/taxii/`. Have the fake record every `Accept` header it receives so tests can assert the media type.

- [ ] **Step 2: Write the failing tests**

```python
class TestTaxiiDiscovery(unittest.TestCase):
    def setUp(self):
        self.server = FakeTaxii()
        self.addCleanup(self.server.stop)
        self.server.start()

    def _client(self, version="2.1"):
        return nexus.TaxiiClient(host="127.0.0.1", token="t", scheme="http",
                                 port=self.server.port, version=version)

    def test_detects_21(self):
        self.assertEqual(self._client().detect_version(), "2.1")

    def test_collections_span_every_api_root(self):
        found = self._client().get_collections()
        self.assertEqual(sorted(c["id"] for c in found), ["c1", "c2"])
        self.assertEqual(found[0]["api_root"], "/api1/")

    def test_the_accept_header_names_the_version(self):
        self._client().get_collections()
        self.assertIn("application/taxii+json;version=2.1",
                      self.server.accepts)

    def test_a_server_with_no_discovery_endpoint_raises(self):
        self.server.serve_discovery = False
        with self.assertRaises(nexus.TaxiiError):
            self._client().detect_version()
```

- [ ] **Step 3: Run to verify they fail**

Run: `python3 -m unittest test_nexus.TestTaxiiDiscovery -v`
Expected: FAIL — no `get_collections`.

- [ ] **Step 4: Implement**

```python
    def get_collections(self):
        """Every collection under every API root, in discovery order.

        A server may expose several API roots; the operator picks collections,
        not roots, so the root is carried on each collection rather than being
        a separate question.
        """
        payload, _ = self._request("GET", TAXII_DISCOVERY[self.version])
        roots = (payload or {}).get("api_roots") or []
        found = []
        for root in roots:
            path = root if root.endswith("/") else root + "/"
            try:
                body, _ = self._request("GET", path + "collections/")
            except SourceAuthError:
                raise
            except SourceError as exc:
                # One unreadable root must not cost the operator the others.
                log.warning("could not read collections under %s: %s", path, exc)
                continue
            for entry in (body or {}).get("collections") or []:
                if not entry.get("id"):
                    continue
                found.append({"id": entry["id"],
                              "title": entry.get("title") or entry["id"],
                              "api_root": path})
        return found
```

- [ ] **Step 5: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus.TestTaxiiDiscovery -v
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: TAXII collection discovery across API roots"
```

Expected: `OK`, 550 tests.

---

### Task 4: Fetching objects — 2.1 envelope pagination

**Files:**
- Modify: `nexus.py` — `TaxiiClient`; `test_nexus.py` — extend `FakeTaxii`

**Interfaces:**
- Produces: `TaxiiClient.fetch_objects(collection, added_after=None, max_results=None, page_size=100)` — a generator of raw STIX object dicts.

- [ ] **Step 1: Extend the fake**

`GET /api1/collections/c1/objects/` returns a 2.1 envelope:

```json
{"objects": [ ...STIX... ], "more": true, "next": "cursor-2"}
```

Honour `limit`, `next`, `match[type]` and `added_after` query parameters so the tests can assert they were sent.

- [ ] **Step 2: Write the failing tests**

```python
class TestTaxii21Fetch(unittest.TestCase):
    def setUp(self):
        self.server = FakeTaxii()
        self.addCleanup(self.server.stop)
        self.server.start()
        self.client = nexus.TaxiiClient(host="127.0.0.1", token="t",
                                        scheme="http", port=self.server.port,
                                        version="2.1")

    def test_pages_until_more_is_false(self):
        self.server.pages = [
            {"objects": [{"id": "indicator--1"}], "more": True, "next": "n1"},
            {"objects": [{"id": "indicator--2"}], "more": False},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual([o["id"] for o in got],
                         ["indicator--1", "indicator--2"])

    def test_it_asks_the_server_for_indicators_only(self):
        list(self.client.fetch_objects({"id": "c1", "api_root": "/api1/"}))
        self.assertIn("match[type]=indicator", self.server.last_query)

    def test_added_after_is_sent_when_given(self):
        list(self.client.fetch_objects({"id": "c1", "api_root": "/api1/"},
                                       added_after="2026-08-01T00:00:00Z"))
        self.assertIn("added_after=", self.server.last_query)

    def test_max_results_stops_early(self):
        self.server.pages = [
            {"objects": [{"id": "a"}, {"id": "b"}, {"id": "c"}], "more": True,
             "next": "n1"},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}, max_results=2))
        self.assertEqual(len(got), 2)

    def test_a_repeated_cursor_stops_the_loop(self):
        # A server that keeps handing back the same next value would spin
        # forever; OpenctiClient carries the same guard.
        self.server.pages = [
            {"objects": [{"id": "a"}], "more": True, "next": "same"},
            {"objects": [{"id": "b"}], "more": True, "next": "same"},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertLessEqual(len(got), 2)
```

- [ ] **Step 3: Run to verify they fail**

Run: `python3 -m unittest test_nexus.TestTaxii21Fetch -v`
Expected: FAIL — no `fetch_objects`.

- [ ] **Step 4: Implement**

```python
    def fetch_objects(self, collection, added_after=None, max_results=None,
                      page_size=100):
        """Yield raw STIX objects from one collection.

        `match[type]=indicator` and `added_after` are the only filters TAXII
        defines that are useful here; everything else the operator asked for is
        applied after download, in taxii_object_allowed().
        """
        if self.version == "2.0":
            for obj in self._fetch_objects_20(collection, added_after,
                                              max_results, page_size):
                yield obj
            return

        path = "%scollections/%s/objects/" % (collection["api_root"],
                                              collection["id"])
        params = {"match[type]": "indicator", "limit": page_size}
        if added_after:
            params["added_after"] = added_after

        sent = 0
        cursor = None
        seen_cursors = set()
        while True:
            query = dict(params)
            if cursor:
                query["next"] = cursor
            body, _ = self._request(
                "GET", path + "?" + urllib.parse.urlencode(query))
            objects = (body or {}).get("objects") or []
            for obj in objects:
                yield obj
                sent += 1
                if max_results is not None and sent >= max_results:
                    return
            if not (body or {}).get("more"):
                return
            cursor = (body or {}).get("next")
            if not cursor or cursor in seen_cursors:
                log.warning("TAXII server repeated or omitted its next "
                            "cursor; stopping to avoid an endless pull")
                return
            seen_cursors.add(cursor)
```

- [ ] **Step 5: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus.TestTaxii21Fetch -v
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: TAXII 2.1 object fetching with envelope pagination"
```

Expected: `OK`, 555 tests. `_fetch_objects_20` does not exist yet — add a stub raising `TaxiiError("TAXII 2.0 fetching lands in the next commit")` so the 2.1 path is testable in isolation, and remove it in Task 5.

---

### Task 5: Fetching objects — 2.0 bundle and `Range` pagination

This is the most likely place for the client to be wrong against a real server; the spec lists it as unverified for that reason.

**Files:**
- Modify: `nexus.py` — `TaxiiClient._fetch_objects_20`; `test_nexus.py` — extend `FakeTaxii`

**Interfaces:**
- Consumes: `fetch_objects` (Task 4) dispatches here when `version == "2.0"`.
- Produces: `TaxiiClient._fetch_objects_20(collection, added_after, max_results, page_size)` — same generator contract.

- [ ] **Step 1: Extend the fake for 2.0**

`GET /api1/collections/c1/objects/` under 2.0 returns a STIX bundle and a `Content-Range` header:

```json
{"type": "bundle", "id": "bundle--x", "objects": [ ... ]}
```

with `Content-Range: items 0-1/5`. Record the `Range` request header so tests can assert it.

- [ ] **Step 2: Write the failing tests**

```python
class TestTaxii20Fetch(unittest.TestCase):
    def setUp(self):
        self.server = FakeTaxii(version="2.0")
        self.addCleanup(self.server.stop)
        self.server.start()
        self.client = nexus.TaxiiClient(host="127.0.0.1", token="t",
                                        scheme="http", port=self.server.port,
                                        version="2.0")

    def test_reads_objects_out_of_a_bundle(self):
        self.server.bundles = [
            ({"type": "bundle", "objects": [{"id": "indicator--1"}]},
             "items 0-0/1"),
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual([o["id"] for o in got], ["indicator--1"])

    def test_it_pages_with_range_until_the_total_is_reached(self):
        self.server.bundles = [
            ({"type": "bundle", "objects": [{"id": "a"}]}, "items 0-0/2"),
            ({"type": "bundle", "objects": [{"id": "b"}]}, "items 1-1/2"),
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual([o["id"] for o in got], ["a", "b"])
        self.assertTrue(any(r.startswith("items ")
                            for r in self.server.ranges))

    def test_a_missing_content_range_ends_the_pull(self):
        # Not every 2.0 server sends it; one page is better than a loop.
        self.server.bundles = [
            ({"type": "bundle", "objects": [{"id": "only"}]}, None),
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual([o["id"] for o in got], ["only"])
```

- [ ] **Step 3: Run to verify they fail**

Run: `python3 -m unittest test_nexus.TestTaxii20Fetch -v`
Expected: FAIL — the stub raises `TaxiiError`.

- [ ] **Step 4: Implement**

Replace the stub:

```python
    _CONTENT_RANGE = re.compile(r"items\s+(\d+)\s*-\s*(\d+)\s*/\s*(\d+|\*)")

    def _fetch_objects_20(self, collection, added_after, max_results,
                          page_size):
        """TAXII 2.0: a STIX bundle per page, paged by Range headers.

        2.1 replaced this with an envelope carrying `more`/`next`.  A 2.0
        server that omits Content-Range gets one page and no loop -- better a
        short pull than an endless one.
        """
        path = "%scollections/%s/objects/" % (collection["api_root"],
                                              collection["id"])
        params = {"match[type]": "indicator"}
        if added_after:
            params["added_after"] = added_after
        query = path + "?" + urllib.parse.urlencode(params)

        sent = 0
        start = 0
        while True:
            end = start + page_size - 1
            body, headers = self._request_with_range(query, start, end)
            objects = (body or {}).get("objects") or []
            for obj in objects:
                yield obj
                sent += 1
                if max_results is not None and sent >= max_results:
                    return
            header = headers.get("Content-Range") if headers else None
            match = self._CONTENT_RANGE.search(header or "")
            if not match:
                return
            last, total = match.group(2), match.group(3)
            if total == "*":
                return              # unknown total; do not guess
            if int(last) + 1 >= int(total):
                return
            if not objects:
                return              # no progress; stop rather than spin
            start = int(last) + 1
```

**`_request`'s real signature is `_request(self, method, path, body=None)` —
it has no way to carry an extra header.** Verified at `nexus.py:518`. You must
widen it, and this is the one place in the plan where a shared function used by
every source changes, so do it carefully:

```python
    def _request(self, method, path, body=None, extra_headers=None):
```

and after the existing `headers.update(self._auth_headers())`:

```python
        if extra_headers:
            headers.update(extra_headers)
```

Every existing call site passes positional `method` and `path` only, so the new
keyword is invisible to them — **confirm that by grepping `self._request(` and
reading each caller** before you commit, and say in your report how many call
sites you checked. A default of `None` must leave MISP and OpenCTI byte-identical
in behaviour; add a test asserting a request with no `extra_headers` sends the
same header set it did before.

- [ ] **Step 5: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus.TestTaxii20Fetch -v
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: TAXII 2.0 bundle fetching with Range pagination"
```

Expected: `OK`, 558 tests.

---

### Task 6: `flatten_taxii_object`

**Files:**
- Modify: `nexus.py` — the `# CLIENT` section, beside `flatten_indicator`
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `parse_stix_pattern(pattern)` → list of `(value_type, value)`; `OPENCTI_TO_ZEEK`.
- Produces: `flatten_taxii_object(obj, collection_title=None, stats=None)` → list of record dicts in the shape `flatten_indicator` already emits. Locate that shape with `grep -n 'def flatten_indicator' -A 45 nexus.py` and match it field for field.

- [ ] **Step 1: Write the failing tests**

```python
class TestFlattenTaxii(unittest.TestCase):
    def _indicator(self, **over):
        obj = {
            "type": "indicator", "id": "indicator--abc",
            "pattern_type": "stix",
            "pattern": "[domain-name:value = 'evil.example']",
            "created": "2026-08-01T00:00:00.000Z",
            "labels": ["phishing"],
        }
        obj.update(over)
        return obj

    def test_a_domain_pattern_becomes_one_record(self):
        rows = nexus.flatten_taxii_object(self._indicator())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["value"], "evil.example")
        self.assertEqual(rows[0]["type"], "Domain-Name")

    def test_a_file_pattern_fans_out(self):
        obj = self._indicator(pattern=(
            "[file:name = 'x.exe' OR file:hashes.'SHA-256' = '"
            + "a" * 64 + "']"))
        rows = nexus.flatten_taxii_object(obj)
        self.assertEqual(sorted(r["type"] for r in rows),
                         ["File-Name", "SHA-256"])

    def test_a_non_stix_pattern_is_counted_not_guessed(self):
        stats = nexus.BuildStats()
        rows = nexus.flatten_taxii_object(
            self._indicator(pattern_type="yara", pattern="rule x {}"),
            stats=stats)
        self.assertEqual(rows, [])

    def test_the_collection_title_reaches_the_record(self):
        rows = nexus.flatten_taxii_object(self._indicator(),
                                          collection_title="Feed One")
        self.assertEqual(rows[0]["collection"], "Feed One")

    def test_a_non_indicator_object_yields_nothing(self):
        self.assertEqual(
            nexus.flatten_taxii_object({"type": "malware", "id": "malware--1"}),
            [])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest test_nexus.TestFlattenTaxii -v`
Expected: FAIL — no `flatten_taxii_object`.

- [ ] **Step 3: Implement**

```python
def flatten_taxii_object(obj, collection_title=None, stats=None):
    """One STIX indicator -> a record per value in its pattern.

    1:N like flatten_indicator(), not 1:1 like flatten_attribute().  Only
    `indicator` objects are read; a collection also carries malware, campaigns
    and relationships, which are context rather than verdicts.
    """
    if (obj or {}).get("type") != "indicator":
        return []
    pattern_type = (obj.get("pattern_type") or "stix").lower()
    if pattern_type not in OPENCTI_PARSEABLE_PATTERN_TYPES:
        if stats is not None:
            stats.unmap("pattern:%s" % pattern_type)
        return []

    records = []
    for value_type, value in parse_stix_pattern(obj.get("pattern") or ""):
        records.append({
            "type": value_type,
            "value": value,
            "event_id": obj.get("id") or "",
            "category": ", ".join(obj.get("labels") or []) or "indicator",
            "comment": obj.get("description") or obj.get("name") or "",
            "timestamp": obj.get("created") or "",
            "collection": collection_title or "",
            "labels": list(obj.get("labels") or []),
            "confidence": obj.get("confidence"),
            "valid_until": obj.get("valid_until") or "",
            "created_by_ref": obj.get("created_by_ref") or "",
            "object_marking_refs": list(obj.get("object_marking_refs") or []),
        })
    return records
```

**The sketch above is deliberately incomplete and its key names are NOT
authoritative.** `flatten_indicator` really emits `category`, `to_ids`, `uuid`,
`timestamp`, `comment`, `event_id`, `event_uuid`, `event_info`, `event_tags` and
`org`, among others — several of which the sketch omits. Read the real function
with `grep -n 'def flatten_indicator' -A 50 nexus.py` and align **every** shared
key exactly, because `build_indicators`, `render_meta` and the filters all read
those names. A missing key silently renders an empty metadata field rather than
raising.

Only the last five keys in the sketch — `collection`, `labels`, `confidence`,
`valid_until`, `created_by_ref`, `object_marking_refs` — are TAXII-only, and
they exist solely for Task 7's client-side filters.

- [ ] **Step 4: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus.TestFlattenTaxii -v
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: flatten a TAXII STIX indicator into Nexus records"
```

Expected: `OK`, 563 tests.

---

### Task 7: Client-side filters

The heart of the hybrid design. TAXII cannot filter on labels, markings, confidence, validity or author, so Nexus does it after download.

**Files:**
- Modify: `nexus.py` — a new block in the `# FILTERS` section
- Test: `test_nexus.py`

**Interfaces:**
- Produces: `taxii_object_allowed(record, config, now=None)` → bool. Consumes the TAXII-only record keys from Task 6.

- [ ] **Step 1: Write the failing tests**

```python
class TestTaxiiClientSideFilters(unittest.TestCase):
    def _record(self, **over):
        rec = {"labels": ["phishing"], "confidence": 80,
               "valid_until": "", "created_by_ref": "identity--a",
               "object_marking_refs": ["marking-definition--green"]}
        rec.update(over)
        return rec

    def test_no_filters_allows_everything(self):
        self.assertTrue(nexus.taxii_object_allowed(self._record(), {}))

    def test_include_labels_excludes_a_non_match(self):
        config = {"include_labels": ["malware"]}
        self.assertFalse(nexus.taxii_object_allowed(self._record(), config))

    def test_exclude_labels_wins_over_include(self):
        config = {"include_labels": ["phishing"],
                  "exclude_labels": ["phishing"]}
        self.assertFalse(nexus.taxii_object_allowed(self._record(), config))

    def test_min_confidence_excludes_a_lower_score(self):
        config = {"min_confidence": 90}
        self.assertFalse(nexus.taxii_object_allowed(self._record(), config))

    def test_absent_confidence_is_not_filtered_out(self):
        # STIX 2.0 indicators have no confidence property at all.  Treating
        # absent as zero would silently drop every object on a 2.0 feed.
        config = {"min_confidence": 90}
        self.assertTrue(nexus.taxii_object_allowed(
            self._record(confidence=None), config))

    def test_an_expired_indicator_is_excluded_when_asked(self):
        config = {"drop_expired": True}
        record = self._record(valid_until="2020-01-01T00:00:00Z")
        self.assertFalse(nexus.taxii_object_allowed(
            record, config, now=datetime(2026, 8, 22, tzinfo=timezone.utc)))

    def test_markings_filter_matches_on_any_ref(self):
        config = {"include_markings": ["marking-definition--red"]}
        self.assertFalse(nexus.taxii_object_allowed(self._record(), config))

    def test_authors_filter(self):
        config = {"include_authors": ["identity--b"]}
        self.assertFalse(nexus.taxii_object_allowed(self._record(), config))
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest test_nexus.TestTaxiiClientSideFilters -v`
Expected: FAIL — no `taxii_object_allowed`.

- [ ] **Step 3: Implement**

```python
def taxii_object_allowed(record, config, now=None):
    """The filters TAXII cannot express, applied after download.

    A server-side filter that silently matches nothing is the defect this
    project has fixed three times; here the filters are honest by construction
    because Nexus applies them itself.  The one trap is confidence: STIX 2.0
    indicators have no such property, so ABSENT means unknown, not zero.
    """
    labels = set(record.get("labels") or [])
    exclude = set(config.get("exclude_labels") or [])
    if exclude and labels & exclude:
        return False
    include = set(config.get("include_labels") or [])
    if include and not (labels & include):
        return False

    markings = set(record.get("object_marking_refs") or [])
    wanted_markings = set(config.get("include_markings") or [])
    if wanted_markings and not (markings & wanted_markings):
        return False

    authors = config.get("include_authors") or []
    if authors and record.get("created_by_ref") not in authors:
        return False

    minimum = config.get("min_confidence")
    confidence = record.get("confidence")
    if minimum is not None and confidence is not None:
        try:
            if int(confidence) < int(minimum):
                return False
        except (TypeError, ValueError):
            pass          # an unparseable confidence is unknown, not zero

    if config.get("drop_expired") and record.get("valid_until"):
        stamp = _opencti_epoch(record["valid_until"])
        if stamp:
            reference = time.time() if now is None else _epoch_of(now)
            if float(stamp) < reference:
                return False
    return True
```

Reuse `_opencti_epoch` — it already normalises STIX timestamps for Python 3.6,
including the `%z`-colon fix that a naive implementation gets wrong on this
project's syntax floor.

**Check what `_opencti_epoch` actually returns before writing the comparison** —
read it with `grep -n 'def _opencti_epoch' -A 15 nexus.py`. If it returns a
string rather than a number, coerce once and say so in your report.

`calendar` is **not** imported in `nexus.py` and must not be added — `time` is
already imported, so `time.time()` is the reference clock. `_epoch_of(now)` in
the sketch above is a stand-in: implement the test seam however the existing
code already converts a `datetime` for comparison, or change the parameter to
take an epoch number directly and adjust the test. Do not add an import for
this.

- [ ] **Step 4: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus.TestTaxiiClientSideFilters -v
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: client-side filters for the properties TAXII cannot query"
```

Expected: `OK`, 571 tests.

---

### Task 8: The interview — stage 1 and collection discovery

**Files:**
- Modify: `nexus.py` — `_stage1_connection`, a new `discover_taxii`, `run_interview`
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `TaxiiClient`, `get_collections`, `detect_version` (Tasks 2-3).
- Produces:
  - `config["taxii_version"]`, `config["taxii_auth"]` (`"bearer"` or `"basic"`), `config["taxii_username"]`, `config["collections"]` (list of the dicts from `get_collections`).
  - `discover_taxii(client)` → `{"collections": [...]}`.

- [ ] **Step 1: Write the failing tests**

```python
class TestTaxiiStage1(unittest.TestCase):
    def test_basic_auth_collects_both_secrets(self):
        answers = iter(["taxii.test", "1", "2", "alice"])
        config = {}
        nexus._stage1_connection(
            config, None, lambda _p: next(answers),
            lambda _p: "s3cret", source="taxii")
        self.assertEqual(config["taxii_auth"], "basic")
        self.assertEqual(config["taxii_username"], "alice")
        self.assertEqual(config["token"], "s3cret")

    def test_neither_secret_is_persisted(self):
        config = {"token": "pw", "taxii_username": "alice",
                  "source": "taxii"}
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "p.json")
        nexus.save_profile(config, path)
        raw = open(path).read()
        self.assertNotIn("pw", raw)
        self.assertNotIn("alice", raw)
```

The answer sequence above is a guess at the prompt order — run the interview once by hand and script the real sequence. The second test is the load-bearing one: a Basic username is half a credential and must be excluded from profiles exactly as the token is.

- [ ] **Step 2: Run to verify they fail**

- [ ] **Step 3: Implement**

Add `"taxii_username"` to `PROFILE_EXCLUDED_KEYS`. In `_stage1_connection`, branch when `source == "taxii"`: ask for the address, ask the protocol version (offering the detected value as the default when a client is reachable, per the standing rule), ask Bearer or Basic, then collect the secrets — `getpass_fn` for both the token and the Basic password, and `ask_required` for the username.

Add:

```python
def discover_taxii(client):
    """Collections the credentials can actually see."""
    found = {"collections": []}
    if client is None:
        return found
    try:
        found["collections"] = client.get_collections()
    except SourceError as exc:
        log.warning("TAXII discovery failed: %s", exc)
    return found
```

- [ ] **Step 4: Run tests, full suite, commit**

```bash
python3 -m unittest test_nexus 2>&1 | tail -3
git add nexus.py test_nexus.py
git commit -m "feat: TAXII connection stage and collection discovery"
```

---

### Task 9: The interview — collection selection and the post-download filters

**Files:**
- Modify: `nexus.py` — new `_stage3_collections_taxii`, `_stage5_scope_taxii`, wired into `run_interview`
- Test: `test_nexus.py`

**Interfaces:**
- Produces: `config["collections"]`, `config["include_labels"]`, `config["exclude_labels"]`, `config["include_markings"]`, `config["include_authors"]`, `config["min_confidence"]`, `config["drop_expired"]`, `config["days"]`.

- [ ] **Step 1: Write the failing tests**

```python
class TestTaxiiScopeStage(unittest.TestCase):
    def test_the_wording_says_the_filters_are_applied_after_download(self):
        printed = []
        config = {"source": "taxii", "taxii_version": "2.1"}
        nexus._stage5_scope_taxii(config, {"collections": []},
                                  lambda _p: "", printer=printed.append)
        text = " ".join(printed).lower()
        self.assertIn("after download", text)

    def test_a_20_feed_is_warned_about_confidence(self):
        printed = []
        config = {"source": "taxii", "taxii_version": "2.0"}
        nexus._stage5_scope_taxii(config, {"collections": []},
                                  lambda _p: "", printer=printed.append)
        text = " ".join(printed).lower()
        self.assertIn("confidence", text)
        self.assertIn("2.0", text)
```

The `printer` seam is a suggestion — if the existing stages capture stdout instead, follow that and adjust these tests. Say which you did.

- [ ] **Step 2-4: Run to fail, implement, run to pass**

The scope stage asks: time window (feeding `added_after`), include/exclude labels, markings, authors, minimum confidence, and whether to drop expired indicators. Every one of those questions must be introduced with wording making clear it is applied **after** download, not sent to the server. When `config["taxii_version"] == "2.0"`, print a line saying STIX 2.0 indicators carry no confidence property, so a minimum will not exclude them.

Collection selection reuses whatever multi-select helper `_stage_feeds` already uses — find it with `grep -n 'def _stage_feeds' -A 40 nexus.py` and follow that pattern rather than writing a new selector.

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: TAXII collection selection and post-download scope questions"
```

---

### Task 10: Wiring — `SOURCES`, `make_client`, `_fetch_records`, summary, profiles

**Files:**
- Modify: `nexus.py` — `SOURCES`, `SOURCE_LABELS`, `make_client`, `_fetch_records`, `summarise_config`, `migrate_profile_config`, `build_indicators`'s source handling, `render_meta`
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: everything from Tasks 2-9.
- Produces: a TAXII run reaching `intel.dat` end to end.

- [ ] **Step 1: Write the failing test**

```python
class TestTaxiiWiring(unittest.TestCase):
    def test_taxii_is_a_selectable_source(self):
        self.assertIn("taxii", nexus.SOURCES)
        args = nexus.build_parser().parse_args(["--source", "taxii"])
        self.assertEqual(args.source, "taxii")

    def test_make_client_builds_a_taxii_client(self):
        config = {"source": "taxii", "source_host": "h", "token": "t",
                  "scheme": "https", "port": None, "verify_tls": True,
                  "timeout": 30, "retries": 3, "taxii_version": "2.1",
                  "taxii_username": None}
        self.assertIsInstance(nexus.make_client(config), nexus.TaxiiClient)

    def test_meta_source_names_the_collection(self):
        rows, _ = nexus.build_indicators(
            [{"type": "Domain-Name", "value": "evil.example",
              "event_id": "indicator--1", "category": "phishing",
              "comment": "", "timestamp": "", "collection": "Feed One"}],
            types=None, source="taxii", mapping_table=nexus.OPENCTI_TO_ZEEK,
            source_fmt="TAXII-{collection}")
        self.assertIn("TAXII-Feed-One", rows[0][2])
```

- [ ] **Step 2-4: Run to fail, implement, run to pass**

`SOURCES = ("misp", "opencti", "taxii")`, `SOURCE_LABELS["taxii"] = "TAXII"`. `make_client` grows a `taxii` branch passing `version=config["taxii_version"]` and `username=config.get("taxii_username")`. `_fetch_records` grows a TAXII branch that loops the selected collections, calls `fetch_objects` with `added_after` computed from `config["days"]`, flattens each object with `flatten_taxii_object(obj, collection_title=...)`, and yields only records passing `taxii_object_allowed(record, config)`. `summarise_config` gains a TAXII block that shows the collections and marks the client-side filters as post-download. `migrate_profile_config` needs no change but confirm a v2 profile without TAXII keys still loads.

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: wire TAXII into the source machinery end to end"
```

---

### Task 11: `--probe` for TAXII, and end-to-end coverage

**Files:**
- Modify: `nexus.py` — `cmd_probe` dispatch, new `_cmd_probe_taxii`
- Test: `test_nexus.py`

- [ ] **Step 1: Write the failing tests**

```python
class TestTaxiiEndToEnd(unittest.TestCase):
    def test_a_taxii_pull_reaches_rendered_intel_lines(self):
        # Fake server -> fetch -> flatten -> filter -> build -> render.
        # Assert an Intel::DOMAIN line appears with meta.source naming the
        # collection.
        ...

    def test_probe_says_its_counts_are_pre_filter(self):
        printed = []
        ...
        self.assertIn("before the post-download filters",
                      " ".join(printed).lower())
```

Fill both in fully against the fake from Task 3 — model the end-to-end one on `TestOpenctiEndToEnd`, which already does exactly this shape for the other source.

- [ ] **Step 2-4: Run to fail, implement, run to pass**

`_cmd_probe_taxii` lists collections and reports the object count each returns, stating plainly that the numbers are **pre-filter** because the server cannot count a filtered subset.

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: --probe for TAXII, reporting pre-filter counts"
```

---

### Task 12: Documentation

**Files:**
- Modify: `nexus.py` (`__version__`, module docstring), `HANDOFF.md`, `PLAN.md`

- [ ] **Step 1: Bump the version** to `0.5.0-dev` and add TAXII to the docstring's source list.

- [ ] **Step 2: Update `HANDOFF.md`** — the quick-command block, the architecture map's CLIENT and INTERVIEW entries, §3 "verified ground truth" gaining a TAXII subsection, and §7's unverified list gaining the six items from spec §12 plus a first-contact checklist in the same shape as the OpenCTI one.

Record plainly in §6 "things that will bite you": **TAXII filters most scoping after download, not on the server.** An operator used to MISP will expect `include_labels` to reduce transfer volume; on TAXII it does not. Say so.

- [ ] **Step 3: Update `PLAN.md`** — the phase table gains phase 10, and §14 records that TAXII 1.x, non-indicator STIX objects, and remembered incremental state were considered and rejected, with the spec's reasoning.

- [ ] **Step 4: Verify the docs against the code**

```bash
python3 nexus.py --help
python3 nexus.py --version
python3 -m unittest test_nexus 2>&1 | tail -3
grep -n '^# [A-Z]' nexus.py
```

Every flag named in either document must appear in `--help`. `HANDOFF.md`'s architecture map no longer carries line numbers, so nothing there needs re-deriving — do not reintroduce them.

- [ ] **Step 5: Commit**

```bash
git add nexus.py HANDOFF.md PLAN.md
git commit -m "docs: document TAXII as a third source"
```

---

## Self-Review

**Spec coverage.** §5 (where it attaches) → Tasks 2, 6. §6 (hybrid filtering) → Tasks 7, 9, 11 — the "after download" wording is asserted by test in Task 9, and `--probe`'s pre-filter honesty in Task 11. §7 (time window, no state) → Task 10's `added_after` from `config["days"]`; no task adds persistent state. §8 (collections) → Tasks 3, 9, 10, with `meta.source` asserted in Task 10. §9 (protocol differences) → Tasks 2, 4, 5. §10 (auth) → Task 2, with the profile-exclusion test in Task 8. §11 (errors) → Task 2. §12 (unverified) → Task 12. §13 (testing) → every task's test step; the fake serving both versions is Tasks 3-5.

**Placeholder scan.** Tasks 9 and 11 deliberately delegate two test bodies to existing fixtures rather than reproducing large fakes — both name the exact class to copy and the exact `grep` to find it. Task 11's end-to-end test body is the one genuine sketch in the plan; its shape is fully specified and its model named.

**Type consistency.** `TaxiiClient(...)` signature in Task 2 matches `make_client`'s call in Task 10. `get_collections()` → `{"id", "title", "api_root"}` in Task 3 is consumed unchanged by `fetch_objects` in Task 4 and `discover_taxii` in Task 8. `flatten_taxii_object(obj, collection_title=None, stats=None)` in Task 6 is called exactly that way in Task 10. `taxii_object_allowed(record, config, now=None)` in Task 7 is called with the record keys Task 6 produces.

**Two risks flagged for executors.** Task 5's `Range` pagination is the least certain part of the whole plan — the spec lists it as unverified for good reason, and the implementer is told to report which route it took for the extra-headers problem. Task 6's record shape must be aligned against the real `flatten_indicator` rather than the sketch; the plan says so explicitly.
