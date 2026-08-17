# OpenCTI Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenCTI as a second, independently selectable IOC source in `nexus.py`, producing the same Zeek `intel.dat` through the same normalise/filter/guardrail/apply pipeline as MISP.

**Architecture:** `flatten_attribute()` is the existing seam — everything below it is source-agnostic. OpenCTI attaches above that line as a sibling client (`OpenctiClient`) sharing an extracted `_HttpTransport` base with `MispClient`, a parallel mapping table consumed by the same `map_attribute`, a parallel pure query builder, and parallel interview stages. One source per run, selected in stage 1 or by `--source`.

**Tech Stack:** Python 3.6+ syntax, standard library only (`urllib.request`, `json`, `ssl`, `ipaddress`, `getpass`, `argparse`, `re`, `datetime`, `logging`). Single file `nexus.py`. Tests: `unittest`, run with `python3 -m unittest test_nexus`.

**Spec:** `docs/superpowers/specs/2026-08-17-opencti-source-design.md`

## Global Constraints

Every task's requirements implicitly include all of these. Copied from the spec §3.

- **One file.** All production code goes in `nexus.py`. No second module, no package, no `pip install`.
- **Standard library only.** GraphQL is spoken with `urllib.request` and `json`. No GraphQL client library.
- **Python 3.6 syntax.** No f-strings, no type hints, no dataclasses, no walrus operator. `%`-formatting throughout.
- **Purity.** `mapping`, `normalise`, `filters`, `intel`, `guardrails`, `diff`, `build_search_params` and `build_opencti_filters` touch no network and no filesystem.
- **Every prompt takes `input_fn`** (and `getpass_fn` for tokens). No test may block on a TTY.
- **Only `write_atomic` writes the intel file.**
- **Append-only by `(indicator, Intel::Type)`.** Existing rows retained byte-for-byte; computed removal is a hard invariant failure.
- **Interactive by default.** Absent a command-line switch, the script asks. Flags skip questions for unattended replay; they never change what a flagless run means.
- **Comments explain WHY, not what.** Match surrounding density.
- **Every existing test must keep passing.** Baseline is 313 tests. Run `python3 -m unittest test_nexus` after every task; the count only ever goes up.
- **Tests live in `test_nexus.py`**, appended in new `unittest.TestCase` classes following the existing style (see `TestMispClient`, `TestFlatten`, `TestBuildSearchParams`).

---

### Task 1: Repository baseline

**Files:**
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing
- Produces: a git repository so every later task can commit and roll back

- [ ] **Step 1: Initialise the repository**

The project is not currently under version control. Every later task ends in a commit, so this has to exist first.

```bash
cd /Users/phill/Projects/Nexus
git init
```

- [ ] **Step 2: Add a .gitignore**

```
__pycache__/
*.pyc
.DS_Store
```

- [ ] **Step 3: Verify the baseline test suite passes before anything changes**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK` and a count of 313 tests. Record the exact number — every later task compares against it.

- [ ] **Step 4: Commit the current state**

```bash
git add -A
git commit -m "chore: baseline before OpenCTI source work"
```

---

### Task 2: Extract shared HTTP transport and neutral exception names

**Files:**
- Modify: `nexus.py` — CLIENT section, `MispError`/`MispAuthError` at lines 300-306, `MispClient.__init__`/`_request`/`_decode`/`_backoff` at lines 308-409
- Test: `test_nexus.py` — new class `TestTransportRefactor`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `class SourceError(Exception)` and `class SourceAuthError(SourceError)`
  - `MispError = SourceError`, `MispAuthError = SourceAuthError` (module-level aliases)
  - `class _HttpTransport(object)` with `__init__(self, host, token, scheme="https", port=None, verify_tls=True, proxy=None, timeout=30, retries=3)`, attributes `host scheme port token verify_tls timeout retries base_url _opener`, methods `_auth_headers(self)` (raises `NotImplementedError`), `_request(self, method, path, body=None)` returning `(parsed_json, headers)`, `_decode(raw, url)` staticmethod, `_backoff(attempt, reason)` staticmethod, and class attribute `RETRY_STATUS`
  - `class MispClient(_HttpTransport)` — unchanged public API, gains `page_size` kwarg handling in its own `__init__`

This is a pure refactor. No behaviour changes. Cross-host redirect blocking, the cleartext-HTTP warning, the unverified-TLS warning, the 401/403 mapping, and the capped exponential backoff all survive exactly as they are.

- [ ] **Step 1: Write the failing test**

Append to `test_nexus.py`:

```python
class TestTransportRefactor(unittest.TestCase):
    """The shared transport is what OpenCTI reuses; MISP behaviour must not move."""

    def test_neutral_exception_names_exist_and_alias(self):
        self.assertTrue(issubclass(nexus.SourceAuthError, nexus.SourceError))
        self.assertIs(nexus.MispError, nexus.SourceError)
        self.assertIs(nexus.MispAuthError, nexus.SourceAuthError)

    def test_misp_client_is_a_transport(self):
        self.assertTrue(issubclass(nexus.MispClient, nexus._HttpTransport))

    def test_transport_base_refuses_to_guess_auth(self):
        transport = nexus._HttpTransport("10.0.0.1", "tok")
        self.assertRaises(NotImplementedError, transport._auth_headers)

    def test_misp_auth_header_is_the_bare_token(self):
        client = nexus.MispClient("10.0.0.1", "tok")
        self.assertEqual(client._auth_headers(), {"Authorization": "tok"})

    def test_base_url_still_built_from_scheme_host_port(self):
        client = nexus.MispClient("10.0.0.1", "tok", scheme="http", port=8080)
        self.assertEqual(client.base_url, "http://10.0.0.1:8080")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestTransportRefactor -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'SourceError'`

- [ ] **Step 3: Rename the exceptions**

Replace lines 300-306 of `nexus.py`:

```python
class SourceError(Exception):
    """Any failure talking to a threat intel platform."""


class SourceAuthError(SourceError):
    """The platform rejected the API token."""


# The MISP names predate OpenCTI support.  Kept so existing call sites and
# tests keep working; new code raises and catches the neutral names.
MispError = SourceError
MispAuthError = SourceAuthError
```

- [ ] **Step 4: Extract the transport base**

Replace `class MispClient(object):` and its `__init__`/`_request`/`_decode`/`_backoff` with a `_HttpTransport` base carrying the plumbing verbatim, plus a thin `MispClient`. The only edits to the moved code are: `MispError` → `SourceError`, `MispAuthError` → `SourceAuthError`, and the `Authorization` header now coming from `self._auth_headers()`.

```python
class _HttpTransport(object):
    """Shared HTTP plumbing.  Subclasses own their auth header and their API.

    Only transport subclasses speak HTTP.  Everything downstream sees flattened
    dicts.
    """

    RETRY_STATUS = frozenset((429, 500, 502, 503, 504))

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3):
        self.host = host
        self.scheme = scheme
        self.port = port
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.retries = max(1, retries)  # retries=0 would send no request at all
        REDACTOR.add_secret(token)

        netloc = host if not port else "%s:%d" % (host, port)
        self.base_url = "%s://%s" % (scheme, netloc)

        handlers = []
        if scheme == "https":
            if verify_tls:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_unverified_context()
                log.warning(
                    "TLS certificate verification is DISABLED for %s", self.base_url
                )
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if scheme == "http" and not _is_loopback(host):
            log.warning("using plain HTTP for %s -- the API token is sent in "
                        "cleartext", self.base_url)
        handlers.append(NoCrossHostRedirect())
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def _auth_headers(self):
        raise NotImplementedError("a transport subclass must supply its auth header")

    def _request(self, method, path, body=None):
        """Return (parsed_json, headers).  Retries on transient failures."""
        url = urllib.parse.urljoin(self.base_url, path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "nexus/%s" % __version__,
        }
        headers.update(self._auth_headers())

        last_exc = None
        for attempt in range(1, self.retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    # Keep the Message object -- its lookup is case-insensitive.
                    return self._decode(raw, url), resp.headers
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    raise SourceAuthError(
                        "the platform rejected the API token (HTTP %d) for %s"
                        % (exc.code, url)
                    )
                if exc.code in self.RETRY_STATUS and attempt < self.retries:
                    last_exc = exc
                    self._backoff(attempt, "HTTP %d" % exc.code)
                    continue
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                except Exception:  # pragma: no cover - best effort only
                    pass
                raise SourceError("HTTP %d from %s %s" % (exc.code, url, detail))
            except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
                if attempt < self.retries:
                    last_exc = exc
                    self._backoff(attempt, str(exc))
                    continue
                raise SourceError("could not reach %s: %s" % (url, exc))
        raise SourceError("giving up on %s after %d attempts: %s"
                          % (url, self.retries, last_exc))

    @staticmethod
    def _decode(raw, url):
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SourceError("malformed JSON from %s: %s" % (url, exc))

    @staticmethod
    def _backoff(attempt, reason):
        delay = min(2 ** attempt, 30)
        log.debug("retrying in %ss (%s)", delay, reason)
        time.sleep(delay)


class MispClient(_HttpTransport):
    """Minimal MISP REST client over urllib."""

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3, page_size=1000):
        _HttpTransport.__init__(self, host, token, scheme=scheme, port=port,
                                verify_tls=verify_tls, proxy=proxy,
                                timeout=timeout, retries=retries)
        self.page_size = page_size

    def _auth_headers(self):
        return {"Authorization": self.token}
```

Everything from `# -- discovery ---` (`get_version` onward) stays exactly where it is, still inside `MispClient`.

One MISP-specific message changed: the auth error text is now platform-neutral. Check `test_nexus.py` for any assertion on the old `"MISP rejected the API token"` string and update it to match if one exists.

- [ ] **Step 5: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestTransportRefactor -v`
Expected: PASS, 5 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 318 tests (313 + 5)

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "refactor: extract _HttpTransport, add neutral SourceError names"
```

---

### Task 3: OpenCTI mapping constants and table-driven mapping

**Files:**
- Modify: `nexus.py` — CONSTANTS section after `IOC_CLASSES` (around line 173); MAPPING section `map_attribute` at line 676, `mappable_types` at 659, `zeek_type_for` at 664; INTEL section `build_indicators` at line 1155
- Test: `test_nexus.py` — new class `TestOpenctiMapping`

**Interfaces:**
- Consumes: `SourceError` (Task 2)
- Produces:
  - `OPENCTI_TO_ZEEK` — dict, same `{key: [(part_index, zeek_type)]}` shape as `MISP_TO_ZEEK`
  - `OPENCTI_UNMAPPABLE` — dict of `{type: reason}`
  - `OPENCTI_IOC_CLASSES` — dict of `{key: (label, [main_observable_types])}`
  - `OPENCTI_IOC_CLASS_ORDER` — tuple
  - `OPENCTI_OFF_BY_DEFAULT` — frozenset
  - `normalise_hash_algorithm(label)` → canonical string (`"sha-256"` → `"SHA-256"`)
  - `map_attribute(record, split_composites="both", allow_subnet=True, table=MISP_TO_ZEEK)`
  - `mappable_types(table=MISP_TO_ZEEK)`, `zeek_type_for(misp_type, table=MISP_TO_ZEEK)`
  - `build_indicators(..., mapping_table=MISP_TO_ZEEK, unmappable=MISP_UNMAPPABLE)`

- [ ] **Step 1: Write the failing test**

```python
class TestOpenctiMapping(unittest.TestCase):

    def rec(self, value_type, value):
        return {"type": value_type, "value": value}

    def test_observable_types_map_to_zeek(self):
        cases = [
            ("IPv4-Addr", "45.33.32.1", [("45.33.32.1", "Intel::ADDR")]),
            ("IPv6-Addr", "2606:4700::1", [("2606:4700::1", "Intel::ADDR")]),
            ("Domain-Name", "evil.com", [("evil.com", "Intel::DOMAIN")]),
            ("Hostname", "a.evil.com", [("a.evil.com", "Intel::DOMAIN")]),
            ("Url", "http://evil.com/a", [("http://evil.com/a", "Intel::URL")]),
            ("Email-Addr", "a@evil.com", [("a@evil.com", "Intel::EMAIL")]),
            ("File-Name", "bad.exe", [("bad.exe", "Intel::FILE_NAME")]),
            ("SHA-256", "a" * 64, [("a" * 64, "Intel::FILE_HASH")]),
            ("X509-SHA-1", "b" * 40, [("b" * 40, "Intel::CERT_HASH")]),
            ("User-Account", "bad_actor", [("bad_actor", "Intel::USER_NAME")]),
            ("Software", "Mozilla/4.0", [("Mozilla/4.0", "Intel::SOFTWARE")]),
        ]
        for value_type, value, expected in cases:
            with self.subTest(value_type=value_type):
                self.assertEqual(
                    nexus.map_attribute(self.rec(value_type, value),
                                        table=nexus.OPENCTI_TO_ZEEK),
                    expected)

    def test_cidr_valued_ipv4_becomes_a_subnet(self):
        out = nexus.map_attribute(self.rec("IPv4-Addr", "45.33.32.0/24"),
                                  table=nexus.OPENCTI_TO_ZEEK)
        self.assertEqual(out, [("45.33.32.0/24", "Intel::SUBNET")])

    def test_cidr_dropped_when_subnets_disallowed(self):
        out = nexus.map_attribute(self.rec("IPv4-Addr", "45.33.32.0/24"),
                                  allow_subnet=False,
                                  table=nexus.OPENCTI_TO_ZEEK)
        self.assertEqual(out, [])

    def test_misp_table_is_still_the_default(self):
        self.assertEqual(nexus.map_attribute(self.rec("ip-dst", "45.33.32.1")),
                         [("45.33.32.1", "Intel::ADDR")])

    def test_unmappable_types_carry_reasons(self):
        for key in ("Mutex", "Windows-Registry-Key", "X509-MD5", "TLSH"):
            self.assertIn(key, nexus.OPENCTI_UNMAPPABLE)
            self.assertTrue(nexus.OPENCTI_UNMAPPABLE[key])

    def test_cert_hash_is_sha1_only(self):
        self.assertIn("X509-SHA-1", nexus.OPENCTI_TO_ZEEK)
        self.assertNotIn("X509-SHA-256", nexus.OPENCTI_TO_ZEEK)
        self.assertNotIn("X509-MD5", nexus.OPENCTI_TO_ZEEK)

    def test_hash_algorithm_labels_normalise(self):
        for raw in ("sha-256", "SHA256", "sha256", "SHA-256"):
            self.assertEqual(nexus.normalise_hash_algorithm(raw), "SHA-256")
        self.assertEqual(nexus.normalise_hash_algorithm("md5"), "MD5")
        self.assertEqual(nexus.normalise_hash_algorithm("SHA-1"), "SHA-1")
        self.assertEqual(nexus.normalise_hash_algorithm("ssdeep"), "SSDEEP")

    def test_ioc_classes_cover_the_mappable_surface(self):
        listed = set()
        for _, types in nexus.OPENCTI_IOC_CLASSES.values():
            listed.update(types)
        self.assertIn("IPv4-Addr", listed)
        self.assertIn("StixFile", listed)
        self.assertIn("X509-Certificate", listed)

    def test_mappable_types_follows_the_table(self):
        self.assertIn("IPv4-Addr", nexus.mappable_types(nexus.OPENCTI_TO_ZEEK))
        self.assertIn("ip-dst", nexus.mappable_types())

    def test_build_indicators_accepts_the_opencti_table(self):
        records = [{"type": "Domain-Name", "value": "evil.com", "to_ids": True,
                    "uuid": "x", "event_info": "i", "event_id": "1",
                    "event_tags": [], "org": "o", "comment": "", "category": "",
                    "timestamp": ""}]
        rows, _ = nexus.build_indicators(records,
                                         mapping_table=nexus.OPENCTI_TO_ZEEK)
        self.assertEqual([r[0] for r in rows], ["evil.com"])
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiMapping -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'OPENCTI_TO_ZEEK'`

- [ ] **Step 3: Add the constants**

Insert into the CONSTANTS section, immediately after `IOC_CLASSES` (line 173):

```python
# -- OpenCTI ---------------------------------------------------------------
# Keys here are the value types flatten_indicator() emits, not OpenCTI entity
# types: a StixFile observable yields one record per hash plus one for its name,
# so the hash algorithm is the key that reaches the mapper.
OPENCTI_TO_ZEEK = {
    "IPv4-Addr":    [(0, "Intel::ADDR")],
    "IPv6-Addr":    [(0, "Intel::ADDR")],
    "Domain-Name":  [(0, "Intel::DOMAIN")],
    "Hostname":     [(0, "Intel::DOMAIN")],
    "Url":          [(0, "Intel::URL")],
    "Email-Addr":   [(0, "Intel::EMAIL")],
    "File-Name":    [(0, "Intel::FILE_NAME")],
    "MD5":          [(0, "Intel::FILE_HASH")],
    "SHA-1":        [(0, "Intel::FILE_HASH")],
    "SHA-224":      [(0, "Intel::FILE_HASH")],
    "SHA-256":      [(0, "Intel::FILE_HASH")],
    "SHA-384":      [(0, "Intel::FILE_HASH")],
    "SHA-512":      [(0, "Intel::FILE_HASH")],
    # Certificate SHA-1 is Intel::CERT_HASH, not Intel::FILE_HASH, so it needs
    # a key of its own rather than sharing "SHA-1".
    "X509-SHA-1":   [(0, "Intel::CERT_HASH")],
    "User-Account": [(0, "Intel::USER_NAME")],
    "Software":     [(0, "Intel::SOFTWARE")],
}

OPENCTI_UNMAPPABLE = {
    "Mutex": "no Zeek Intel equivalent",
    "Windows-Registry-Key": "no Zeek Intel equivalent",
    "Autonomous-System": "no Zeek Intel equivalent",
    "Process": "no Zeek Intel equivalent",
    "Directory": "no Zeek Intel equivalent",
    "Network-Traffic": "no Zeek Intel equivalent",
    "Cryptocurrency-Wallet": "no Zeek Intel equivalent",
    "Phone-Number": "no Zeek Intel equivalent",
    "Text": "free-form, not an indicator",
    "X509-MD5": "Intel::CERT_HASH is SHA-1 only",
    "X509-SHA-256": "Intel::CERT_HASH is SHA-1 only",
    "SSDEEP": "fuzzy hash, no Zeek equivalent",
    "TLSH": "fuzzy hash, no Zeek equivalent",
}

# Keyed on x_opencti_main_observable_type, which is what the type filter takes.
OPENCTI_IOC_CLASSES = {
    "network": ("Network - IP / subnet / domain / URL",
                ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "Url"]),
    "file": ("File - hashes / filenames", ["StixFile", "Artifact"]),
    "email": ("Email - addresses", ["Email-Addr"]),
    "tls": ("TLS - certificate hashes", ["X509-Certificate"]),
    "host": ("Host - user agents / usernames", ["User-Account", "Software"]),
}

OPENCTI_IOC_CLASS_ORDER = ("network", "file", "email", "tls", "host")

OPENCTI_OFF_BY_DEFAULT = frozenset(("User-Account", "Software"))

# Connectors write the same algorithm a dozen ways; the mapping table holds one.
_HASH_ALGORITHM_ALIASES = {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA-1": "SHA-1",
    "SHA224": "SHA-224", "SHA-224": "SHA-224",
    "SHA256": "SHA-256", "SHA-256": "SHA-256",
    "SHA384": "SHA-384", "SHA-384": "SHA-384",
    "SHA512": "SHA-512", "SHA-512": "SHA-512",
    "SSDEEP": "SSDEEP", "TLSH": "TLSH",
}


def normalise_hash_algorithm(label):
    """OpenCTI hash algorithm label -> the OPENCTI_TO_ZEEK key."""
    key = (label or "").strip().upper().replace("_", "-")
    return _HASH_ALGORITHM_ALIASES.get(key, _HASH_ALGORITHM_ALIASES.get(
        key.replace("-", ""), key))
```

`normalise_hash_algorithm` is defined in CONSTANTS because the alias table lives there; it is a pure lookup with no dependencies.

- [ ] **Step 4: Make the mapping functions table-driven**

In the MAPPING section, add a `table` parameter to the three functions. Read the current bodies first — the change is mechanical: every reference to `MISP_TO_ZEEK` becomes `table`.

```python
def mappable_types(table=None):
    return sorted(table if table is not None else MISP_TO_ZEEK)


def zeek_type_for(misp_type, table=None):
    entries = (table if table is not None else MISP_TO_ZEEK).get(misp_type)
    ...  # rest of the existing body, reading `entries`


def map_attribute(record, split_composites="both", allow_subnet=True, table=None):
    lookup = table if table is not None else MISP_TO_ZEEK
    ...  # rest of the existing body, reading `lookup` in place of MISP_TO_ZEEK
```

Default to `None` rather than `MISP_TO_ZEEK` directly so the default is resolved at call time — a module-level default would freeze the dict object into the signature.

The existing CIDR-to-`Intel::SUBNET` routing and the `allow_subnet` check are already inside `map_attribute`; they now apply to `IPv4-Addr` for free because the routing keys off the resolved Zeek type, not the source type. Verify this while implementing — if the existing code keys off MISP type names, generalise it to key off `Intel::ADDR` instead.

- [ ] **Step 5: Thread the table through `build_indicators`**

```python
def build_indicators(records, types=None, exclusions=None, stats=None,
                     ..., mapping_table=None, unmappable=None):
    lookup = mapping_table if mapping_table is not None else MISP_TO_ZEEK
    reasons = unmappable if unmappable is not None else MISP_UNMAPPABLE
```

Pass `table=lookup` into its `map_attribute` call and use `reasons` wherever it currently reads `MISP_UNMAPPABLE`.

- [ ] **Step 6: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiMapping -v`
Expected: PASS, 10 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 328 tests

- [ ] **Step 7: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add OpenCTI mapping tables and table-driven map_attribute"
```

---

### Task 4: OpenctiClient — GraphQL transport and version probe

**Files:**
- Modify: `nexus.py` — CLIENT section, after `MispClient` (before `_misp_bool` at line 558)
- Test: `test_nexus.py` — new classes `FakeOpenctiHandler`, `FakeOpencti`, `TestOpenctiClient`

**Interfaces:**
- Consumes: `_HttpTransport`, `SourceError`, `SourceAuthError` (Task 2)
- Produces:
  - `GRAPHQL_PATH = "/graphql"`
  - `OPENCTI_DEFAULT_PORT_HTTP = 4000`
  - `OPENCTI_AUTH_ERROR_CODES` — frozenset
  - `class OpenctiClient(_HttpTransport)` with `__init__(self, host, token, scheme="https", port=None, verify_tls=True, proxy=None, timeout=30, retries=3, page_size=100)`, `_auth_headers()` returning `{"Authorization": "Bearer <token>"}`, `_graphql(self, query, variables=None)` returning the `data` dict, `_check_errors(payload)` staticmethod, `get_version(self)` returning `{"version": "6.x.y"}`

- [ ] **Step 1: Write the fake and the failing test**

Model the fake on the existing `FakeMispHandler` / `FakeMisp` pair at `test_nexus.py:668-766` — a real `HTTPServer` on `127.0.0.1:0` in a thread, replaying a script of canned responses.

```python
class FakeOpenctiHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self.server.requests.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": json.loads(raw.decode("utf-8")) if raw else {},
        })
        if self.server.script:
            status, payload = self.server.script.pop(0)
        else:
            status, payload = 200, {"data": {}}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeOpencti(object):
    """A local GraphQL endpoint replaying a scripted list of responses."""

    def __init__(self, script=None):
        self.server = HTTPServer(("127.0.0.1", 0), FakeOpenctiHandler)
        self.server.script = list(script or [])
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def requests(self):
        return self.server.requests

    def client(self, **kwargs):
        return nexus.OpenctiClient("127.0.0.1", "tok", scheme="http",
                                   port=self.port, retries=1, **kwargs)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class TestOpenctiClient(unittest.TestCase):

    def tearDown(self):
        if getattr(self, "cti", None):
            self.cti.stop()

    def test_bearer_token_and_graphql_path(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"about": {"version": "6.4.1"}}})])
        client = self.cti.client()
        self.assertEqual(client.get_version(), {"version": "6.4.1"})
        request = self.cti.requests[0]
        self.assertEqual(request["path"], "/graphql")
        self.assertEqual(request["auth"], "Bearer tok")
        self.assertIn("query", request["body"])

    def test_errors_in_a_200_body_raise(self):
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "Something went wrong"}], "data": None})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceError, client.get_version)

    def test_auth_message_in_a_200_body_raises_auth_error(self):
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "You must be logged in to do this."}],
                   "data": None})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceAuthError, client.get_version)

    def test_auth_extension_code_raises_auth_error(self):
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "nope",
                               "extensions": {"code": "FORBIDDEN_ACCESS"}}]})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceAuthError, client.get_version)

    def test_null_data_without_errors_raises(self):
        self.cti = FakeOpencti(script=[(200, {"data": None})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceError, client.get_version)

    def test_http_401_still_raises_auth_error(self):
        self.cti = FakeOpencti(script=[(401, {"errors": []})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceAuthError, client.get_version)

    def test_variables_are_sent(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"x": 1}})])
        client = self.cti.client()
        client._graphql("query Q($a: Int) { x }", {"a": 3})
        self.assertEqual(self.cti.requests[0]["body"]["variables"], {"a": 3})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiClient -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'OpenctiClient'`

- [ ] **Step 3: Add the constants and the client**

Constants, in the CONSTANTS section beside the other OpenCTI values:

```python
GRAPHQL_PATH = "/graphql"
OPENCTI_DEFAULT_PORT_HTTP = 4000
# GraphQL answers 200 even when it refuses you, so auth failure has to be read
# out of the error body rather than the status line.
OPENCTI_AUTH_ERROR_CODES = frozenset(
    ("AUTH_REQUIRED", "FORBIDDEN_ACCESS", "AUTH_FAILURE", "UNAUTHORIZED"))
_OPENCTI_AUTH_PATTERN = re.compile(
    r"auth|token|forbidden|unauthor|logged in", re.IGNORECASE)
```

Client, after `MispClient`:

```python
class OpenctiClient(_HttpTransport):
    """Minimal OpenCTI 6.x GraphQL client over urllib."""

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3, page_size=100):
        _HttpTransport.__init__(self, host, token, scheme=scheme, port=port,
                                verify_tls=verify_tls, proxy=proxy,
                                timeout=timeout, retries=retries)
        self.page_size = page_size
        # Counted rather than raised: an indicator with more linked observables
        # than one page holds is unusual, and dropping values silently is the
        # failure mode this tool exists to avoid.
        self.truncated_observables = 0

    def _auth_headers(self):
        return {"Authorization": "Bearer %s" % self.token}

    def _graphql(self, query, variables=None):
        body = {"query": query, "variables": variables or {}}
        payload, _ = self._request("POST", GRAPHQL_PATH, body)
        self._check_errors(payload)
        return payload.get("data") or {}

    @staticmethod
    def _check_errors(payload):
        """GraphQL reports failure inside a 200 response, so read the body.

        Unhandled, a rejected token looks exactly like an empty result set and
        a scheduled run would report "0 new indicators" forever.
        """
        if not isinstance(payload, dict):
            raise SourceError("OpenCTI returned %s, not a JSON object"
                              % type(payload).__name__)
        errors = payload.get("errors") or []
        if errors:
            first = errors[0] if isinstance(errors[0], dict) else {}
            message = str(first.get("message") or "unspecified GraphQL error")
            code = str((first.get("extensions") or {}).get("code") or "")
            if code in OPENCTI_AUTH_ERROR_CODES or _OPENCTI_AUTH_PATTERN.search(message):
                raise SourceAuthError("OpenCTI rejected the API token: %s" % message)
            raise SourceError("OpenCTI error: %s" % message)
        if payload.get("data") is None:
            raise SourceError("OpenCTI returned no data and no error")

    def get_version(self):
        data = self._graphql("query NexusVersion { about { version } }")
        about = data.get("about") or {}
        return {"version": about.get("version") or "unknown"}
```

Confirm `re` is already imported at the top of `nexus.py` (it is — the NORMALISE section uses it).

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiClient -v`
Expected: PASS, 7 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 335 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add OpenctiClient GraphQL transport and version probe"
```

---

### Task 5: OpenCTI discovery and counts

**Files:**
- Modify: `nexus.py` — `OpenctiClient`, after `get_version`
- Test: `test_nexus.py` — new class `TestOpenctiDiscovery`

**Interfaces:**
- Consumes: `OpenctiClient._graphql` (Task 4), `OPENCTI_IOC_CLASSES` (Task 3)
- Produces:
  - `OpenctiClient.get_labels()` → `[{"id":..., "value":...}]`
  - `OpenctiClient.get_markings()` → `[{"id":..., "definition":..., "definition_type":...}]`
  - `OpenctiClient.get_organizations()` → `[{"id":..., "name":...}]`
  - `OpenctiClient.count_type(main_observable_type, base_filters=None, probe_limit=None)` → `(count, exact)`
  - `_edge_nodes(connection)` module-level helper → list of node dicts

- [ ] **Step 1: Write the failing test**

```python
class TestOpenctiDiscovery(unittest.TestCase):

    def tearDown(self):
        if getattr(self, "cti", None):
            self.cti.stop()

    def conn(self, nodes, **page_info):
        info = {"endCursor": None, "hasNextPage": False}
        info.update(page_info)
        return {"pageInfo": info,
                "edges": [{"node": n} for n in nodes]}

    def test_labels_flatten_from_edges(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"labels": self.conn(
            [{"id": "l1", "value": "malware"}, {"id": "l2", "value": "apt"}])}})])
        client = self.cti.client()
        self.assertEqual(client.get_labels(),
                         [{"id": "l1", "value": "malware"},
                          {"id": "l2", "value": "apt"}])

    def test_markings_flatten(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"markingDefinitions": self.conn(
            [{"id": "m1", "definition": "TLP:AMBER", "definition_type": "TLP"}])}})])
        client = self.cti.client()
        self.assertEqual(client.get_markings(),
                         [{"id": "m1", "definition": "TLP:AMBER",
                           "definition_type": "TLP"}])

    def test_organizations_flatten(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"organizations": self.conn(
            [{"id": "o1", "name": "CIRCL"}])}})])
        client = self.cti.client()
        self.assertEqual(client.get_organizations(), [{"id": "o1", "name": "CIRCL"}])

    def test_nodes_without_a_name_are_dropped(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"labels": self.conn(
            [{"id": "l1", "value": "malware"}, {"id": "l2", "value": ""}])}})])
        client = self.cti.client()
        self.assertEqual(client.get_labels(), [{"id": "l1", "value": "malware"}])

    def test_count_type_uses_global_count_and_is_exact(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"globalCount": 4231, "endCursor": None,
                         "hasNextPage": False},
            "edges": []}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("IPv4-Addr"), (4231, True))

    def test_count_type_sends_the_type_filter(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"globalCount": 1, "endCursor": None,
                         "hasNextPage": False}, "edges": []}}})])
        client = self.cti.client()
        client.count_type("Domain-Name")
        sent = self.cti.requests[0]["body"]["variables"]["filters"]
        keys = [f["key"] for f in sent["filters"]]
        self.assertIn(["x_opencti_main_observable_type"], keys)
        values = [f["values"] for f in sent["filters"]
                  if f["key"] == ["x_opencti_main_observable_type"]][0]
        self.assertEqual(values, ["Domain-Name"])

    def test_count_type_merges_base_filters(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"globalCount": 1, "endCursor": None,
                         "hasNextPage": False}, "edges": []}}})])
        client = self.cti.client()
        base = {"mode": "and",
                "filters": [{"key": ["revoked"], "values": ["false"],
                             "operator": "eq", "mode": "or"}],
                "filterGroups": []}
        client.count_type("Url", base)
        sent = self.cti.requests[0]["body"]["variables"]["filters"]
        keys = [f["key"] for f in sent["filters"]]
        self.assertIn(["revoked"], keys)
        self.assertIn(["x_opencti_main_observable_type"], keys)

    def test_count_type_falls_back_to_edge_length(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"endCursor": None, "hasNextPage": True},
            "edges": [{"node": {"id": "a"}}]}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("Url"), (1, False))
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiDiscovery -v`
Expected: FAIL — `AttributeError: 'OpenctiClient' object has no attribute 'get_labels'`

- [ ] **Step 3: Implement**

Module-level helper, in the CLIENT section beside `flatten_attribute`:

```python
def _edge_nodes(connection):
    """Relay connection -> the list of node dicts, tolerating nulls."""
    if not isinstance(connection, dict):
        return []
    out = []
    for edge in connection.get("edges") or []:
        node = edge.get("node") if isinstance(edge, dict) else None
        if isinstance(node, dict):
            out.append(node)
    return out
```

Methods on `OpenctiClient`:

```python
    # -- discovery ---------------------------------------------------------

    LABELS_QUERY = """
    query NexusLabels($first: Int!) {
      labels(first: $first) { edges { node { id value } } }
    }
    """

    MARKINGS_QUERY = """
    query NexusMarkings($first: Int!) {
      markingDefinitions(first: $first) {
        edges { node { id definition definition_type } }
      }
    }
    """

    ORGANIZATIONS_QUERY = """
    query NexusOrganizations($first: Int!) {
      organizations(first: $first) { edges { node { id name } } }
    }
    """

    COUNT_QUERY = """
    query NexusCount($filters: FilterGroup) {
      indicators(first: 1, filters: $filters) {
        pageInfo { globalCount endCursor hasNextPage }
        edges { node { id } }
      }
    }
    """

    def get_labels(self, first=500):
        data = self._graphql(self.LABELS_QUERY, {"first": first})
        return [{"id": n.get("id"), "value": n.get("value")}
                for n in _edge_nodes(data.get("labels"))
                if n.get("value")]

    def get_markings(self, first=200):
        data = self._graphql(self.MARKINGS_QUERY, {"first": first})
        return [{"id": n.get("id"), "definition": n.get("definition"),
                 "definition_type": n.get("definition_type")}
                for n in _edge_nodes(data.get("markingDefinitions"))
                if n.get("definition")]

    def get_organizations(self, first=500):
        data = self._graphql(self.ORGANIZATIONS_QUERY, {"first": first})
        return [{"id": n.get("id"), "name": n.get("name")}
                for n in _edge_nodes(data.get("organizations"))
                if n.get("name")]

    def count_type(self, main_observable_type, base_filters=None,
                   probe_limit=None):
        """Return (count, exact).

        globalCount is an exact total, unlike MISP's bounded probe.  It is
        permission-dependent, so fall back to what the page actually returned
        and say so rather than reporting a guess as fact.
        """
        filters = merge_opencti_filters(base_filters, [{
            "key": ["x_opencti_main_observable_type"],
            "values": [main_observable_type],
            "operator": "eq", "mode": "or"}])
        data = self._graphql(self.COUNT_QUERY, {"filters": filters})
        connection = data.get("indicators") or {}
        page_info = connection.get("pageInfo") or {}
        if page_info.get("globalCount") is not None:
            try:
                return int(page_info["globalCount"]), True
            except (TypeError, ValueError):
                pass
        nodes = _edge_nodes(connection)
        return len(nodes), not page_info.get("hasNextPage")
```

`probe_limit` is accepted and ignored so `count_type` is call-compatible with `MispClient.count_type`; `discover()` calls both through the same code path.

`merge_opencti_filters` is a small pure helper — add it in the CLIENT section above the class:

```python
def merge_opencti_filters(base, extra_filters):
    """Return a FilterGroup with `extra_filters` ANDed onto `base`."""
    merged = {"mode": "and", "filters": [], "filterGroups": []}
    if isinstance(base, dict):
        merged["mode"] = base.get("mode") or "and"
        merged["filters"] = list(base.get("filters") or [])
        merged["filterGroups"] = list(base.get("filterGroups") or [])
    merged["filters"] = merged["filters"] + list(extra_filters or [])
    return merged
```

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiDiscovery -v`
Expected: PASS, 8 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 343 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add OpenCTI discovery queries and exact type counts"
```

---

### Task 6: flatten_indicator

**Files:**
- Modify: `nexus.py` — CLIENT section, after `flatten_attribute` (line 592)
- Test: `test_nexus.py` — new class `TestFlattenIndicator`

**Interfaces:**
- Consumes: `normalise_hash_algorithm` (Task 3), `_edge_nodes` (Task 5)
- Produces:
  - `flatten_indicator(node, stats=None)` → list of records in the existing internal shape
  - `_opencti_epoch(value)` → int epoch seconds or `""`
  - `OPENCTI_OBSERVABLE_TYPE_ALIASES` — dict mapping observable `entity_type` to `OPENCTI_TO_ZEEK` keys for the direct-value cases

Record shape produced, matching `flatten_attribute` exactly:
`value type category to_ids uuid timestamp comment event_id event_uuid event_info event_tags org`

- [ ] **Step 1: Write the failing test**

```python
class TestFlattenIndicator(unittest.TestCase):

    def node(self, **overrides):
        base = {
            "id": "indicator--1",
            "standard_id": "indicator--std",
            "name": "Evil domain",
            "description": "seen in phishing",
            "pattern": "[domain-name:value = 'evil.com']",
            "pattern_type": "stix",
            "x_opencti_score": 80,
            "confidence": 75,
            "revoked": False,
            "x_opencti_detection": True,
            "valid_from": "2026-08-01T00:00:00Z",
            "valid_until": "2027-08-01T00:00:00Z",
            "created_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-02T12:00:00Z",
            "createdBy": {"name": "CIRCL"},
            "objectLabel": [{"id": "l1", "value": "phishing"}],
            "objectMarking": [{"id": "m1", "definition": "TLP:AMBER"}],
            "observables": {"pageInfo": {"hasNextPage": False}, "edges": []},
        }
        base.update(overrides)
        return base

    def observables(self, nodes, has_next=False):
        return {"pageInfo": {"hasNextPage": has_next},
                "edges": [{"node": n} for n in nodes]}

    def test_simple_observable_becomes_one_record(self):
        node = self.node(observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}]))
        records = nexus.flatten_indicator(node)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["value"], "evil.com")
        self.assertEqual(rec["type"], "Domain-Name")
        self.assertEqual(rec["category"], "stix")
        self.assertIs(rec["to_ids"], True)
        self.assertEqual(rec["uuid"], "indicator--std")
        self.assertEqual(rec["event_id"], "indicator--1")
        self.assertEqual(rec["event_info"], "Evil domain")
        self.assertEqual(rec["comment"], "seen in phishing")
        self.assertEqual(rec["org"], "CIRCL")

    def test_labels_and_markings_both_land_in_event_tags(self):
        node = self.node(observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}]))
        rec = nexus.flatten_indicator(node)[0]
        self.assertIn("phishing", rec["event_tags"])
        self.assertIn("TLP:AMBER", rec["event_tags"])

    def test_stixfile_yields_one_record_per_hash_plus_the_name(self):
        node = self.node(observables=self.observables([{
            "entity_type": "StixFile",
            "observable_value": "bad.exe",
            "name": "bad.exe",
            "hashes": [{"algorithm": "MD5", "hash": "d" * 32},
                       {"algorithm": "sha-256", "hash": "e" * 64}],
        }]))
        records = nexus.flatten_indicator(node)
        pairs = sorted((r["type"], r["value"]) for r in records)
        self.assertEqual(pairs, sorted([
            ("File-Name", "bad.exe"),
            ("MD5", "d" * 32),
            ("SHA-256", "e" * 64),
        ]))

    def test_x509_hashes_are_keyed_separately(self):
        node = self.node(observables=self.observables([{
            "entity_type": "X509-Certificate",
            "observable_value": "cert",
            "hashes": [{"algorithm": "SHA-1", "hash": "b" * 40},
                       {"algorithm": "SHA-256", "hash": "c" * 64}],
        }]))
        types = sorted(r["type"] for r in nexus.flatten_indicator(node))
        self.assertEqual(types, ["X509-SHA-1", "X509-SHA-256"])

    def test_user_account_uses_account_login(self):
        node = self.node(observables=self.observables([{
            "entity_type": "User-Account", "observable_value": "",
            "account_login": "bad_actor"}]))
        rec = nexus.flatten_indicator(node)[0]
        self.assertEqual(rec["value"], "bad_actor")
        self.assertEqual(rec["type"], "User-Account")

    def test_missing_created_by_is_empty_not_a_crash(self):
        node = self.node(createdBy=None, observables=self.observables(
            [{"entity_type": "Url", "observable_value": "http://evil.com/a"}]))
        self.assertEqual(nexus.flatten_indicator(node)[0]["org"], "")

    def test_updated_at_becomes_epoch_seconds(self):
        node = self.node(observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}]))
        rec = nexus.flatten_indicator(node)[0]
        self.assertIsInstance(rec["timestamp"], int)
        self.assertGreater(rec["timestamp"], 1750000000)

    def test_unparseable_timestamp_is_empty(self):
        node = self.node(updated_at="not a date", observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}]))
        self.assertEqual(nexus.flatten_indicator(node)[0]["timestamp"], "")

    def test_detection_false_sets_to_ids_false(self):
        node = self.node(x_opencti_detection=False, observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}]))
        self.assertIs(nexus.flatten_indicator(node)[0]["to_ids"], False)

    def test_truncated_observables_are_counted(self):
        stats = nexus.BuildStats()
        node = self.node(observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": "evil.com"}],
            has_next=True))
        nexus.flatten_indicator(node, stats=stats)
        self.assertEqual(stats.opencti_truncated_observables, 1)

    def test_observable_with_no_usable_value_is_skipped(self):
        node = self.node(observables=self.observables(
            [{"entity_type": "Domain-Name", "observable_value": ""}]))
        self.assertEqual(nexus.flatten_indicator(node), [])
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestFlattenIndicator -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'flatten_indicator'`

- [ ] **Step 3: Implement**

Constants, beside the other OpenCTI constants:

```python
# Observable entity types whose observable_value maps straight to a mapping-table
# key.  Anything not here needs field-specific extraction (hashes, logins).
OPENCTI_OBSERVABLE_TYPE_ALIASES = {
    "IPv4-Addr": "IPv4-Addr",
    "IPv6-Addr": "IPv6-Addr",
    "Domain-Name": "Domain-Name",
    "Hostname": "Hostname",
    "Url": "Url",
    "Email-Addr": "Email-Addr",
}
```

Functions, in the CLIENT section after `flatten_attribute`:

```python
def _opencti_epoch(value):
    """ISO-8601 from OpenCTI -> epoch seconds, or "" when it will not parse."""
    if not value:
        return ""
    text = str(value).strip().replace("Z", "+00:00")
    # OpenCTI emits millisecond precision; datetime in 3.6 will not take it.
    text = re.sub(r"\.\d+", "", text)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
            parsed = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return ""
    return int(parsed.timestamp())


def _observable_values(observable):
    """One observable -> [(mapping_table_key, value), ...]."""
    entity_type = observable.get("entity_type") or ""
    value = (observable.get("observable_value") or "").strip()

    alias = OPENCTI_OBSERVABLE_TYPE_ALIASES.get(entity_type)
    if alias:
        return [(alias, value)] if value else []

    out = []
    if entity_type in ("StixFile", "Artifact"):
        name = (observable.get("name") or "").strip()
        if name:
            out.append(("File-Name", name))
        for entry in observable.get("hashes") or []:
            digest = (entry.get("hash") or "").strip()
            if digest:
                out.append((normalise_hash_algorithm(entry.get("algorithm")),
                            digest))
    elif entity_type == "X509-Certificate":
        for entry in observable.get("hashes") or []:
            digest = (entry.get("hash") or "").strip()
            if digest:
                # Certificate hashes are Intel::CERT_HASH, and only SHA-1 is;
                # the X509- prefix keeps them out of the file-hash keys.
                out.append(("X509-%s"
                            % normalise_hash_algorithm(entry.get("algorithm")),
                            digest))
    elif entity_type == "User-Account":
        login = (observable.get("account_login") or value).strip()
        if login:
            out.append(("User-Account", login))
    elif entity_type == "Software":
        name = (observable.get("name") or value).strip()
        if name:
            out.append(("Software", name))
    elif value:
        # Unknown observable type: pass its entity_type through so
        # build_indicators reports it against OPENCTI_UNMAPPABLE rather than
        # dropping it without a word.
        out.append((entity_type, value))
    return out


def flatten_indicator(node, stats=None):
    """OpenCTI indicator node -> the internal records the rest of Nexus uses.

    One record per extracted value: an indicator carrying both an MD5 and a
    SHA-256 for one file produces two rows, which is correct -- Zeek matches
    whichever algorithm it is configured to compute.
    """
    tags = []
    for label in node.get("objectLabel") or []:
        name = label.get("value") if isinstance(label, dict) else None
        if name and name not in tags:
            tags.append(name)
    for marking in node.get("objectMarking") or []:
        name = marking.get("definition") if isinstance(marking, dict) else None
        if name and name not in tags:
            tags.append(name)

    created_by = node.get("createdBy") or {}
    common = {
        "category": node.get("pattern_type") or "",
        "to_ids": bool(node.get("x_opencti_detection")),
        "uuid": node.get("standard_id") or node.get("id") or "",
        "timestamp": _opencti_epoch(node.get("updated_at")
                                    or node.get("created_at")),
        "comment": node.get("description") or "",
        "event_id": str(node.get("id") or ""),
        "event_uuid": node.get("standard_id") or "",
        "event_info": node.get("name") or "",
        "event_tags": tags,
        "org": created_by.get("name") or "",
    }

    connection = node.get("observables") or {}
    if (connection.get("pageInfo") or {}).get("hasNextPage") and stats is not None:
        stats.opencti_truncated_observables += 1

    records = []
    for observable in _edge_nodes(connection):
        for value_type, value in _observable_values(observable):
            record = dict(common)
            record["type"] = value_type
            record["value"] = value
            records.append(record)
    return records
```

Confirm `datetime` and `timezone` are imported at the top of `nexus.py` — the PROFILES section already uses `datetime.now(timezone.utc)`, so the import is `from datetime import datetime, timezone` or equivalent. Match whatever is there.

- [ ] **Step 4: Add the stats counter**

`BuildStats.__init__` (line 1111) gains:

```python
        self.opencti_truncated_observables = 0
        self.opencti_pattern_fallbacks = 0
        self.opencti_unparsed_patterns = 0
        self.opencti_non_stix_patterns = 0
```

All four are added now so later tasks only wire them, and `BuildStats.report()` gains a block that prints them only when non-zero:

```python
        if self.opencti_truncated_observables:
            lines.append("  %d indicators had more than one page of linked "
                         "observables; some values were not read"
                         % self.opencti_truncated_observables)
        if self.opencti_pattern_fallbacks:
            lines.append("  %d indicators had no linked observables; their STIX "
                         "pattern was parsed instead"
                         % self.opencti_pattern_fallbacks)
        if self.opencti_unparsed_patterns:
            lines.append("  %d STIX patterns yielded no usable indicator"
                         % self.opencti_unparsed_patterns)
        if self.opencti_non_stix_patterns:
            lines.append("  %d indicators skipped: their pattern is not STIX"
                         % self.opencti_non_stix_patterns)
```

Match the existing `report()` structure — read it before editing, and append into whatever list variable it already builds.

- [ ] **Step 5: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestFlattenIndicator -v`
Expected: PASS, 11 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 354 tests

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add flatten_indicator with hash and truncation handling"
```

---

### Task 7: STIX pattern fallback

**Files:**
- Modify: `nexus.py` — CLIENT section, after `flatten_indicator`
- Test: `test_nexus.py` — new class `TestStixPattern`

**Interfaces:**
- Consumes: `OPENCTI_TO_ZEEK` (Task 3)
- Produces:
  - `STIX_PROPERTY_TO_TYPE` — dict mapping `"<object-type>:<property>"` to a mapping-table key
  - `parse_stix_pattern(pattern)` → `[(value_type, value), ...]`
  - `OPENCTI_PARSEABLE_PATTERN_TYPES = frozenset(("stix",))`

- [ ] **Step 1: Write the failing test**

```python
class TestStixPattern(unittest.TestCase):

    def test_simple_comparisons(self):
        cases = [
            ("[ipv4-addr:value = '45.33.32.1']", [("IPv4-Addr", "45.33.32.1")]),
            ("[ipv6-addr:value = '2606:4700::1']", [("IPv6-Addr", "2606:4700::1")]),
            ("[domain-name:value = 'evil.com']", [("Domain-Name", "evil.com")]),
            ("[url:value = 'http://evil.com/a']", [("Url", "http://evil.com/a")]),
            ("[email-addr:value = 'a@evil.com']", [("Email-Addr", "a@evil.com")]),
            ("[file:name = 'bad.exe']", [("File-Name", "bad.exe")]),
        ]
        for pattern, expected in cases:
            with self.subTest(pattern=pattern):
                self.assertEqual(nexus.parse_stix_pattern(pattern), expected)

    def test_quoted_hash_property(self):
        self.assertEqual(
            nexus.parse_stix_pattern("[file:hashes.'SHA-256' = '%s']" % ("a" * 64)),
            [("SHA-256", "a" * 64)])

    def test_unquoted_hash_property(self):
        self.assertEqual(
            nexus.parse_stix_pattern("[file:hashes.MD5 = '%s']" % ("d" * 32)),
            [("MD5", "d" * 32)])

    def test_certificate_hash_keys_separately(self):
        self.assertEqual(
            nexus.parse_stix_pattern(
                "[x509-certificate:hashes.'SHA-1' = '%s']" % ("b" * 40)),
            [("X509-SHA-1", "b" * 40)])

    def test_or_joined_comparisons_all_extracted(self):
        pattern = ("[domain-name:value = 'a.com' OR domain-name:value = 'b.com']")
        self.assertEqual(nexus.parse_stix_pattern(pattern),
                         [("Domain-Name", "a.com"), ("Domain-Name", "b.com")])

    def test_qualifiers_are_ignored(self):
        pattern = "[ipv4-addr:value = '45.33.32.1'] REPEATS 2 TIMES WITHIN 60 SECONDS"
        self.assertEqual(nexus.parse_stix_pattern(pattern),
                         [("IPv4-Addr", "45.33.32.1")])

    def test_unsupported_property_yields_nothing(self):
        self.assertEqual(
            nexus.parse_stix_pattern("[windows-registry-key:key = 'HKLM\\\\Run']"),
            [])

    def test_not_equals_is_not_treated_as_an_indicator(self):
        self.assertEqual(
            nexus.parse_stix_pattern("[domain-name:value != 'good.com']"), [])

    def test_empty_and_none_are_safe(self):
        self.assertEqual(nexus.parse_stix_pattern(""), [])
        self.assertEqual(nexus.parse_stix_pattern(None), [])

    def test_duplicate_values_are_deduped_in_order(self):
        pattern = "[domain-name:value = 'a.com' OR domain-name:value = 'a.com']"
        self.assertEqual(nexus.parse_stix_pattern(pattern),
                         [("Domain-Name", "a.com")])
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestStixPattern -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'parse_stix_pattern'`

- [ ] **Step 3: Implement**

```python
# Only STIX patterns are parsed.  A YARA rule's string literals are not
# indicators, and mining them would arm Zeek against whatever a rule happened
# to mention.
OPENCTI_PARSEABLE_PATTERN_TYPES = frozenset(("stix",))

STIX_PROPERTY_TO_TYPE = {
    "ipv4-addr:value": "IPv4-Addr",
    "ipv6-addr:value": "IPv6-Addr",
    "domain-name:value": "Domain-Name",
    "hostname:value": "Hostname",
    "url:value": "Url",
    "email-addr:value": "Email-Addr",
    "email-message:from_ref.value": "Email-Addr",
    "file:name": "File-Name",
    "user-account:account_login": "User-Account",
    "software:name": "Software",
}

# `object-type:property = 'value'`, with the hash forms carrying a quoted or
# bare algorithm after `hashes.`.  Only `=` is matched: `!=` is an exclusion,
# and a flat indicator list cannot express one.
_STIX_COMPARISON = re.compile(
    r"([a-z0-9-]+):([a-zA-Z0-9_.\-']+?)\s*=\s*'([^']*)'")


def parse_stix_pattern(pattern):
    """STIX pattern -> [(mapping_table_key, value), ...].

    Used only when an indicator has no linked observables.  Anything that
    cannot be represented as a flat indicator -- negations, qualifiers, object
    types with no Zeek equivalent -- is skipped rather than approximated.
    """
    if not pattern:
        return []

    out = []
    seen = set()
    for match in _STIX_COMPARISON.finditer(str(pattern)):
        obj_type, prop, value = match.group(1), match.group(2), match.group(3)
        value = value.strip()
        if not value:
            continue
        # `!=` leaves a trailing `!` on the property when the regex stops at `=`.
        if prop.endswith("!"):
            continue

        prop = prop.strip()
        value_type = None
        if prop.lower().startswith("hashes."):
            algorithm = normalise_hash_algorithm(prop[len("hashes."):].strip("'\""))
            if obj_type == "x509-certificate":
                value_type = "X509-%s" % algorithm
            else:
                value_type = algorithm
        else:
            value_type = STIX_PROPERTY_TO_TYPE.get(
                "%s:%s" % (obj_type.lower(), prop))

        if not value_type or value_type not in OPENCTI_TO_ZEEK:
            continue
        key = (value_type, value)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out
```

The `!=` guard matters: with `[domain-name:value != 'good.com']` the regex's property group would capture `value !`, so the trailing `!` is the signal. Verify the test for it passes before moving on — if the regex captures differently, adjust the guard to match reality rather than adjusting the test.

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestStixPattern -v`
Expected: PASS, 10 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 364 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add STIX pattern fallback for observable-less indicators"
```

---

### Task 8: Cursor-paginated indicator search

**Files:**
- Modify: `nexus.py` — `OpenctiClient`, after `count_type`
- Test: `test_nexus.py` — new class `TestOpenctiSearch`

**Interfaces:**
- Consumes: `flatten_indicator` (Task 6), `parse_stix_pattern` (Task 7), `_edge_nodes` (Task 5)
- Produces:
  - `OpenctiClient.INDICATORS_QUERY` — the GraphQL document from spec §5.3
  - `OpenctiClient.search_indicators(self, filters, max_results=None, max_pages=None, stats=None)` — generator of flattened records

- [ ] **Step 1: Write the failing test**

```python
class TestOpenctiSearch(unittest.TestCase):

    def tearDown(self):
        if getattr(self, "cti", None):
            self.cti.stop()

    def node(self, value, ident="i1", **overrides):
        node = {
            "id": ident, "standard_id": "indicator--" + ident,
            "name": "n", "description": "", "pattern": "",
            "pattern_type": "stix", "x_opencti_detection": True,
            "updated_at": "2026-08-02T12:00:00Z", "createdBy": None,
            "objectLabel": [], "objectMarking": [],
            "observables": {"pageInfo": {"hasNextPage": False}, "edges": [
                {"node": {"entity_type": "Domain-Name",
                          "observable_value": value}}]},
        }
        node.update(overrides)
        return node

    def page(self, nodes, cursor, has_next):
        return {"data": {"indicators": {
            "pageInfo": {"endCursor": cursor, "hasNextPage": has_next,
                         "globalCount": len(nodes)},
            "edges": [{"node": n} for n in nodes]}}}

    def test_single_page(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com")], "c1", False))])
        client = self.cti.client()
        records = list(client.search_indicators({}))
        self.assertEqual([r["value"] for r in records], ["a.com"])

    def test_walks_pages_with_the_cursor(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com", "i1")], "c1", True)),
            (200, self.page([self.node("b.com", "i2")], "c2", False))])
        client = self.cti.client()
        records = list(client.search_indicators({}))
        self.assertEqual([r["value"] for r in records], ["a.com", "b.com"])
        self.assertIsNone(self.cti.requests[0]["body"]["variables"]["after"])
        self.assertEqual(self.cti.requests[1]["body"]["variables"]["after"], "c1")

    def test_repeated_cursor_stops_the_walk(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com", "i1")], "c1", True)),
            (200, self.page([self.node("b.com", "i2")], "c1", True)),
            (200, self.page([self.node("c.com", "i3")], "c1", True))])
        client = self.cti.client()
        with self.assertLogs("nexus", level="WARNING"):
            records = list(client.search_indicators({}))
        self.assertEqual([r["value"] for r in records], ["a.com", "b.com"])

    def test_null_cursor_with_more_pages_stops_the_walk(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com")], None, True)),
            (200, self.page([self.node("b.com", "i2")], None, True))])
        client = self.cti.client()
        with self.assertLogs("nexus", level="WARNING"):
            records = list(client.search_indicators({}))
        self.assertEqual([r["value"] for r in records], ["a.com"])

    def test_max_results_stops_early(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com", "i1"),
                             self.node("b.com", "i2")], "c1", True))])
        client = self.cti.client()
        records = list(client.search_indicators({}, max_results=1))
        self.assertEqual(len(records), 1)

    def test_max_pages_ceiling(self):
        self.cti = FakeOpencti(script=[
            (200, self.page([self.node("a.com", "i1")], "c1", True)),
            (200, self.page([self.node("b.com", "i2")], "c2", True))])
        client = self.cti.client()
        with self.assertLogs("nexus", level="WARNING"):
            records = list(client.search_indicators({}, max_pages=1))
        self.assertEqual(len(records), 1)

    def test_empty_page_terminates(self):
        self.cti = FakeOpencti(script=[(200, self.page([], None, False))])
        client = self.cti.client()
        self.assertEqual(list(client.search_indicators({})), [])

    def test_pattern_fallback_when_no_observables(self):
        stats = nexus.BuildStats()
        node = self.node("unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": []}
        node["pattern"] = "[domain-name:value = 'pattern.com']"
        self.cti = FakeOpencti(script=[(200, self.page([node], None, False))])
        client = self.cti.client()
        records = list(client.search_indicators({}, stats=stats))
        self.assertEqual([r["value"] for r in records], ["pattern.com"])
        self.assertEqual(records[0]["type"], "Domain-Name")
        self.assertEqual(stats.opencti_pattern_fallbacks, 1)

    def test_non_stix_pattern_is_counted_not_mined(self):
        stats = nexus.BuildStats()
        node = self.node("unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": []}
        node["pattern_type"] = "yara"
        node["pattern"] = "rule x { strings: $a = 'evil.com' condition: $a }"
        self.cti = FakeOpencti(script=[(200, self.page([node], None, False))])
        client = self.cti.client()
        records = list(client.search_indicators({}, stats=stats))
        self.assertEqual(records, [])
        self.assertEqual(stats.opencti_non_stix_patterns, 1)

    def test_unparseable_stix_pattern_is_counted(self):
        stats = nexus.BuildStats()
        node = self.node("unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": []}
        node["pattern"] = "[windows-registry-key:key = 'HKLM']"
        self.cti = FakeOpencti(script=[(200, self.page([node], None, False))])
        client = self.cti.client()
        self.assertEqual(list(client.search_indicators({}, stats=stats)), [])
        self.assertEqual(stats.opencti_unparsed_patterns, 1)

    def test_filters_and_page_size_are_sent(self):
        self.cti = FakeOpencti(script=[(200, self.page([], None, False))])
        client = self.cti.client(page_size=250)
        filters = {"mode": "and", "filters": [], "filterGroups": []}
        list(client.search_indicators(filters))
        variables = self.cti.requests[0]["body"]["variables"]
        self.assertEqual(variables["first"], 250)
        self.assertEqual(variables["filters"], filters)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiSearch -v`
Expected: FAIL — `AttributeError: 'OpenctiClient' object has no attribute 'search_indicators'`

- [ ] **Step 3: Implement**

```python
    # -- search ------------------------------------------------------------

    INDICATORS_QUERY = """
    query NexusIndicators($first: Int!, $after: ID, $filters: FilterGroup) {
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
              pageInfo { hasNextPage }
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
    """

    def search_indicators(self, filters, max_results=None, max_pages=None,
                          stats=None):
        """Yield flattened records, walking the cursor until OpenCTI runs dry.

        The sort is fixed so the cursor walk is stable: an instance ingesting
        during a long pull would otherwise shift the window and drop rows.
        """
        after = None
        previous_cursor = None
        yielded = 0
        pages = 0
        while max_pages is None or pages < max_pages:
            data = self._graphql(self.INDICATORS_QUERY, {
                "first": self.page_size, "after": after, "filters": filters})
            connection = data.get("indicators") or {}
            nodes = _edge_nodes(connection)
            page_info = connection.get("pageInfo") or {}
            pages += 1

            for node in nodes:
                for record in self._records_for(node, stats):
                    yield record
                    yielded += 1
                    if max_results is not None and yielded >= max_results:
                        log.info("stopped at max_results=%d", max_results)
                        return

            if not page_info.get("hasNextPage"):
                return
            cursor = page_info.get("endCursor")
            # A proxy that drops `after` would otherwise replay page one for ever.
            if not cursor or cursor == previous_cursor:
                log.warning("stopped because OpenCTI did not advance the cursor "
                            "-- does this endpoint honour `after`?")
                return
            previous_cursor = cursor
            after = cursor
        log.warning("stopped at the explicit %d page ceiling", max_pages)

    def _records_for(self, node, stats):
        """Records from linked observables, falling back to the STIX pattern."""
        records = flatten_indicator(node, stats=stats)
        if records:
            return records

        pattern_type = (node.get("pattern_type") or "").lower()
        if pattern_type not in OPENCTI_PARSEABLE_PATTERN_TYPES:
            if stats is not None:
                stats.opencti_non_stix_patterns += 1
            return []

        pairs = parse_stix_pattern(node.get("pattern"))
        if not pairs:
            if stats is not None:
                stats.opencti_unparsed_patterns += 1
            return []
        if stats is not None:
            stats.opencti_pattern_fallbacks += 1

        # flatten_indicator with no observables still produced the shared
        # metadata; rebuild records around the parsed values.
        stripped = dict(node)
        out = []
        for value_type, value in pairs:
            stripped["observables"] = {"pageInfo": {"hasNextPage": False},
                                       "edges": [{"node": {
                                           "entity_type": "__parsed__",
                                           "observable_value": value}}]}
            built = flatten_indicator(stripped)
            if built:
                built[0]["type"] = value_type
                out.append(built[0])
        return out
```

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiSearch -v`
Expected: PASS, 11 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 375 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add cursor-paginated OpenCTI indicator search"
```

---

### Task 9: build_opencti_filters

**Files:**
- Modify: `nexus.py` — INTERVIEW section, beside `build_search_params` (line 2319)
- Test: `test_nexus.py` — new class `TestBuildOpenctiFilters`

**Interfaces:**
- Consumes: nothing beyond the config dict
- Produces: `build_opencti_filters(config, now=None)` → FilterGroup dict. Pure — no network, no filesystem, and `now` injectable so it is deterministic.

Config keys read (all optional): `types`, `min_score`, `min_confidence`, `exclude_revoked`, `require_detection`, `exclude_expired`, `time_mode`, `days`, `date_from`, `date_to`, `timestamp_field`, `include_label_ids`, `exclude_label_ids`, `marking_ids`, `author_ids`.

- [ ] **Step 1: Write the failing test**

```python
class TestBuildOpenctiFilters(unittest.TestCase):

    FIXED_NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)

    def keys(self, group):
        return [f["key"][0] for f in group["filters"]]

    def filter_for(self, group, key):
        for entry in group["filters"]:
            if entry["key"] == [key]:
                return entry
        return None

    def test_empty_config_is_a_valid_empty_group(self):
        out = nexus.build_opencti_filters({}, now=self.FIXED_NOW)
        self.assertEqual(out, {"mode": "and", "filters": [], "filterGroups": []})

    def test_types_become_one_or_filter(self):
        out = nexus.build_opencti_filters(
            {"types": ["IPv4-Addr", "Domain-Name"]}, now=self.FIXED_NOW)
        entry = self.filter_for(out, "x_opencti_main_observable_type")
        self.assertEqual(entry["values"], ["IPv4-Addr", "Domain-Name"])
        self.assertEqual(entry["operator"], "eq")
        self.assertEqual(entry["mode"], "or")

    def test_min_score_uses_gte(self):
        out = nexus.build_opencti_filters({"min_score": 60}, now=self.FIXED_NOW)
        entry = self.filter_for(out, "x_opencti_score")
        self.assertEqual(entry["values"], ["60"])
        self.assertEqual(entry["operator"], "gte")

    def test_zero_min_score_is_not_a_filter(self):
        out = nexus.build_opencti_filters({"min_score": 0}, now=self.FIXED_NOW)
        self.assertIsNone(self.filter_for(out, "x_opencti_score"))

    def test_min_confidence_uses_gte(self):
        out = nexus.build_opencti_filters({"min_confidence": 75},
                                          now=self.FIXED_NOW)
        self.assertEqual(self.filter_for(out, "confidence")["values"], ["75"])

    def test_exclude_revoked(self):
        out = nexus.build_opencti_filters({"exclude_revoked": True},
                                          now=self.FIXED_NOW)
        entry = self.filter_for(out, "revoked")
        self.assertEqual(entry["values"], ["false"])
        self.assertEqual(entry["operator"], "eq")

    def test_require_detection(self):
        out = nexus.build_opencti_filters({"require_detection": True},
                                          now=self.FIXED_NOW)
        self.assertEqual(self.filter_for(out, "x_opencti_detection")["values"],
                         ["true"])

    def test_exclude_expired_uses_the_injected_now(self):
        out = nexus.build_opencti_filters({"exclude_expired": True},
                                          now=self.FIXED_NOW)
        entry = self.filter_for(out, "valid_until")
        self.assertEqual(entry["values"], ["2026-08-17T12:00:00Z"])
        self.assertEqual(entry["operator"], "gt")

    def test_last_n_days_on_created_at(self):
        out = nexus.build_opencti_filters(
            {"time_mode": "last", "days": 30, "timestamp_field": "created_at"},
            now=self.FIXED_NOW)
        entry = self.filter_for(out, "created_at")
        self.assertEqual(entry["values"], ["2026-07-18T12:00:00Z"])
        self.assertEqual(entry["operator"], "gte")

    def test_last_n_days_on_valid_from(self):
        out = nexus.build_opencti_filters(
            {"time_mode": "last", "days": 7, "timestamp_field": "valid_from"},
            now=self.FIXED_NOW)
        self.assertIsNotNone(self.filter_for(out, "valid_from"))

    def test_explicit_range_emits_both_bounds(self):
        out = nexus.build_opencti_filters(
            {"time_mode": "range", "date_from": "2026-01-01",
             "date_to": "2026-06-30", "timestamp_field": "created_at"},
            now=self.FIXED_NOW)
        bounds = [f for f in out["filters"] if f["key"] == ["created_at"]]
        self.assertEqual(sorted(b["operator"] for b in bounds), ["gte", "lte"])

    def test_time_mode_all_emits_no_time_filter(self):
        out = nexus.build_opencti_filters({"time_mode": "all", "days": 30},
                                          now=self.FIXED_NOW)
        self.assertEqual(self.keys(out), [])

    def test_include_labels_markings_authors(self):
        out = nexus.build_opencti_filters(
            {"include_label_ids": ["l1", "l2"], "marking_ids": ["m1"],
             "author_ids": ["o1"]}, now=self.FIXED_NOW)
        self.assertEqual(self.filter_for(out, "objectLabel")["values"],
                         ["l1", "l2"])
        self.assertEqual(self.filter_for(out, "objectMarking")["values"], ["m1"])
        self.assertEqual(self.filter_for(out, "createdBy")["values"], ["o1"])

    def test_excluded_labels_go_into_a_nested_group(self):
        out = nexus.build_opencti_filters({"exclude_label_ids": ["bad"]},
                                          now=self.FIXED_NOW)
        self.assertEqual(self.keys(out), [])
        group = out["filterGroups"][0]
        self.assertEqual(group["filters"][0]["key"], ["objectLabel"])
        self.assertEqual(group["filters"][0]["operator"], "not_eq")
        self.assertEqual(group["filters"][0]["values"], ["bad"])

    def test_include_and_exclude_labels_coexist(self):
        out = nexus.build_opencti_filters(
            {"include_label_ids": ["good"], "exclude_label_ids": ["bad"]},
            now=self.FIXED_NOW)
        self.assertEqual(self.filter_for(out, "objectLabel")["values"], ["good"])
        self.assertEqual(out["filterGroups"][0]["filters"][0]["values"], ["bad"])

    def test_result_is_json_serialisable(self):
        out = nexus.build_opencti_filters(
            {"types": ["Url"], "min_score": 50, "exclude_revoked": True},
            now=self.FIXED_NOW)
        json.dumps(out)
```

The test module needs `from datetime import datetime, timezone` at the top — add it if it is not already there.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestBuildOpenctiFilters -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'build_opencti_filters'`

- [ ] **Step 3: Implement**

```python
def _opencti_filter(key, values, operator="eq", mode="or"):
    return {"key": [key], "values": [str(v) for v in values],
            "operator": operator, "mode": mode}


def _opencti_stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_opencti_filters(config, now=None):
    """Interview answers -> the OpenCTI 6.x FilterGroup.  Pure, no I/O.

    `now` is injectable so valid_until comparisons stay deterministic under
    test; production passes nothing and gets the run's own UTC clock.
    """
    moment = now or datetime.now(timezone.utc)
    filters = []
    groups = []

    if config.get("types"):
        filters.append(_opencti_filter("x_opencti_main_observable_type",
                                       config["types"]))
    if config.get("min_score"):
        filters.append(_opencti_filter("x_opencti_score",
                                       [config["min_score"]], "gte"))
    if config.get("min_confidence"):
        filters.append(_opencti_filter("confidence",
                                       [config["min_confidence"]], "gte"))
    if config.get("exclude_revoked"):
        filters.append(_opencti_filter("revoked", ["false"]))
    if config.get("require_detection"):
        filters.append(_opencti_filter("x_opencti_detection", ["true"]))
    if config.get("exclude_expired"):
        # An indicator past its valid_until is stale by its own author's
        # judgement; keeping it would arm Zeek on expired intel.
        filters.append(_opencti_filter("valid_until",
                                       [_opencti_stamp(moment)], "gt"))

    field = config.get("timestamp_field") or "created_at"
    mode = config.get("time_mode") or "all"
    if mode == "last" and config.get("days"):
        since = moment - timedelta(days=int(config["days"]))
        filters.append(_opencti_filter(field, [_opencti_stamp(since)], "gte"))
    elif mode == "range":
        if config.get("date_from"):
            filters.append(_opencti_filter(
                field, ["%sT00:00:00Z" % config["date_from"]], "gte"))
        if config.get("date_to"):
            filters.append(_opencti_filter(
                field, ["%sT23:59:59Z" % config["date_to"]], "lte"))

    if config.get("include_label_ids"):
        filters.append(_opencti_filter("objectLabel",
                                       config["include_label_ids"]))
    if config.get("marking_ids"):
        filters.append(_opencti_filter("objectMarking", config["marking_ids"]))
    if config.get("author_ids"):
        filters.append(_opencti_filter("createdBy", config["author_ids"]))

    if config.get("exclude_label_ids"):
        # A not_eq cannot share the objectLabel key with the include list in one
        # group, so exclusions get a group of their own.
        groups.append({
            "mode": "and",
            "filters": [_opencti_filter("objectLabel",
                                        config["exclude_label_ids"],
                                        "not_eq", "and")],
            "filterGroups": [],
        })

    return {"mode": "and", "filters": filters, "filterGroups": groups}
```

`timedelta` must be importable — check the top of `nexus.py` and extend the datetime import to `from datetime import datetime, timedelta, timezone` if needed.

The date range strings assume `YYYY-MM-DD` from `ask_date`, which is what stage 5 already produces for MISP.

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestBuildOpenctiFilters -v`
Expected: PASS, 16 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 391 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: add pure build_opencti_filters FilterGroup builder"
```

---

### Task 10: Neutral config keys and profile v2 migration

**Files:**
- Modify: `nexus.py` — `PROFILE_VERSION` (line 59), `save_profile`/`load_profile` (lines 2482-2521), every reader of `misp_host` / `misp_base_url` (`cmd_build` line 3071, `summarise_config` line 2390, `_stage1_connection` line 1993, `_stage7_metadata`)
- Test: `test_nexus.py` — new class `TestProfileMigration`; existing `TestProfiles` and `TestSummarise` will need their key names updated

**Interfaces:**
- Consumes: nothing
- Produces:
  - `PROFILE_VERSION = 2`
  - `PROFILE_V1_KEY_MAP = {"misp_host": "source_host", "misp_base_url": "source_base_url"}`
  - `migrate_profile_config(config, version)` → migrated dict
  - `load_profile(path)` accepting v1 and v2
  - config keys `source`, `source_host`, `source_base_url` replacing `misp_host`, `misp_base_url`

- [ ] **Step 1: Write the failing test**

```python
class TestProfileMigration(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "p.json")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, payload):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    def test_v1_profile_migrates_forward(self):
        self.write({"profile_version": 1, "config": {
            "misp_host": "misp.local", "misp_base_url": "https://misp.local",
            "types": ["ip-dst"]}})
        config = nexus.load_profile(self.path)
        self.assertEqual(config["source"], "misp")
        self.assertEqual(config["source_host"], "misp.local")
        self.assertEqual(config["source_base_url"], "https://misp.local")
        self.assertNotIn("misp_host", config)

    def test_v1_migration_is_logged(self):
        self.write({"profile_version": 1, "config": {"misp_host": "m"}})
        with self.assertLogs("nexus", level="INFO"):
            nexus.load_profile(self.path)

    def test_v1_token_is_still_stripped(self):
        self.write({"profile_version": 1,
                    "config": {"misp_host": "m", "token": "leaked"}})
        self.assertNotIn("token", nexus.load_profile(self.path))

    def test_v2_round_trip(self):
        config = {"source": "opencti", "source_host": "cti.local",
                  "types": ["IPv4-Addr"], "token": "secret"}
        nexus.save_profile(config, self.path)
        with open(self.path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["profile_version"], 2)
        loaded = nexus.load_profile(self.path)
        self.assertEqual(loaded["source"], "opencti")
        self.assertEqual(loaded["source_host"], "cti.local")
        self.assertNotIn("token", loaded)

    def test_unknown_version_is_rejected(self):
        self.write({"profile_version": 99, "config": {}})
        self.assertRaises(ValueError, nexus.load_profile, self.path)

    def test_v2_files_stay_0600(self):
        nexus.save_profile({"source": "misp", "source_host": "m"}, self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_migration_defaults_source_to_misp_only_when_absent(self):
        self.write({"profile_version": 1,
                    "config": {"misp_host": "m", "source": "opencti"}})
        self.assertEqual(nexus.load_profile(self.path)["source"], "opencti")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestProfileMigration -v`
Expected: FAIL — the v1 profile is rejected by the version check

- [ ] **Step 3: Implement the migration**

Constants:

```python
PROFILE_VERSION = 2
# v1 predates OpenCTI support and named everything after MISP.
PROFILE_V1_KEY_MAP = {"misp_host": "source_host",
                      "misp_base_url": "source_base_url"}
```

Migration and loader:

```python
def migrate_profile_config(config, version):
    """Bring an older profile's keys up to the current schema, in memory.

    A systemd timer replaying a v1 profile must keep working across the
    upgrade; silently breaking a scheduled run is worse than migration code.
    """
    if version == PROFILE_VERSION:
        return config
    if version == 1:
        migrated = dict(config)
        for old, new in PROFILE_V1_KEY_MAP.items():
            if old in migrated:
                migrated.setdefault(new, migrated.pop(old))
            migrated.pop(old, None)
        migrated.setdefault("source", "misp")
        log.info("migrated a profile-version-1 profile forward to version %d",
                 PROFILE_VERSION)
        return migrated
    raise ValueError("profile version %r is not supported by this nexus"
                     % version)


def load_profile(path):
    """Read a saved profile back into a config dict."""
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict) or "config" not in payload:
        raise ValueError("%s is not a nexus profile" % path)
    version = payload.get("profile_version")
    if version not in (1, PROFILE_VERSION):
        raise ValueError("%s is profile version %r, this nexus writes %d"
                         % (path, version, PROFILE_VERSION))

    config = migrate_profile_config(dict(payload["config"]), version)
    for key in PROFILE_EXCLUDED_KEYS:
        config.pop(key, None)  # a hand-edited profile does not get to inject one
    return config
```

- [ ] **Step 4: Rename the config keys at every reader**

`grep -n "misp_host\|misp_base_url" nexus.py test_nexus.py` and rename each to `source_host` / `source_base_url`. Known sites: `_stage1_connection`, `_stage7_metadata`, `summarise_config`, `cmd_build`'s client construction, and the corresponding assertions in `TestRunInterview`, `TestSummarise` and `TestProfiles`.

`build_indicators`' `misp_base_url` **parameter** name may stay as-is or be renamed to `base_url` — if renamed, update its call site in `cmd_build`. Pick one and be consistent; the tests will catch a half-rename.

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 398 tests

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: neutral source_* config keys and profile v2 with v1 migration"
```

---

### Task 11: Interview stage 1 — source selection and connection

**Files:**
- Modify: `nexus.py` — `_stage1_connection` (line 1990), `run_interview` (line 2279)
- Test: `test_nexus.py` — new class `TestOpenctiStage1`

**Interfaces:**
- Consumes: `OPENCTI_DEFAULT_PORT_HTTP` (Task 4), config keys from Task 10
- Produces:
  - `SOURCES = ("misp", "opencti")`
  - `SOURCE_LABELS = {"misp": "MISP", "opencti": "OpenCTI"}`
  - `_stage1_connection(config, client, input_fn, getpass_fn, source=None)` — asks for the source when `source` is `None`, sets `config["source"]`

- [ ] **Step 1: Write the failing test**

```python
class TestOpenctiStage1(Quiet):

    def test_source_question_is_asked_when_not_supplied(self):
        fake = scripted(["2", "cti.local", "1", "443", "y", "none", "30", "3"])
        config = {}
        nexus._stage1_connection(config, None, fake, lambda *a, **k: "tok")
        self.assertEqual(config["source"], "opencti")
        self.assertEqual(config["source_host"], "cti.local")

    def test_source_question_is_skipped_when_supplied(self):
        fake = scripted(["cti.local", "1", "443", "y", "none", "30", "3"])
        config = {}
        nexus._stage1_connection(config, None, fake, lambda *a, **k: "tok",
                                 source="opencti")
        self.assertEqual(config["source"], "opencti")
        self.assertEqual(config["source_host"], "cti.local")

    def test_prompts_name_the_selected_platform(self):
        fake = scripted(["cti.local", "1", "443", "y", "none", "30", "3"])
        nexus._stage1_connection({}, None, fake, lambda *a, **k: "tok",
                                 source="opencti")
        joined = " ".join(fake.state["prompts"])
        self.assertIn("OpenCTI address", joined)

    def test_http_default_port_is_4000_for_opencti(self):
        fake = scripted(["cti.local", "2", "", "y", "none", "30", "3"])
        config = {}
        nexus._stage1_connection(config, None, fake, lambda *a, **k: "tok",
                                 source="opencti")
        self.assertEqual(config["port"], nexus.OPENCTI_DEFAULT_PORT_HTTP)

    def test_misp_http_default_port_is_unchanged(self):
        fake = scripted(["misp.local", "2", "", "y", "none", "30", "3"])
        config = {}
        nexus._stage1_connection(config, None, fake, lambda *a, **k: "tok",
                                 source="misp")
        self.assertEqual(config["port"], 80)

    def test_token_prompt_names_the_platform(self):
        seen = {}

        def getpass_fn(prompt=""):
            seen["prompt"] = prompt
            return "tok"

        fake = scripted(["cti.local", "1", "443", "y", "none", "30", "3"])
        nexus._stage1_connection({}, None, fake, getpass_fn, source="opencti")
        self.assertIn("OpenCTI", seen["prompt"])
```

`scripted` and `Quiet` already exist in `test_nexus.py` (lines 1133 and 1168). The answer order above must match the real question order — read `_stage1_connection` and adjust the scripted answers to fit, keeping the assertions intact.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiStage1 -v`
Expected: FAIL — `_stage1_connection() got an unexpected keyword argument 'source'`

- [ ] **Step 3: Implement**

Constants:

```python
SOURCES = ("misp", "opencti")
SOURCE_LABELS = {"misp": "MISP", "opencti": "OpenCTI"}
```

`ask_token` gains a label so its prompt names the platform:

```python
def ask_token(prompt="MISP API token", getpass_fn=getpass.getpass):
```

is already parameterised — pass `"%s API token" % SOURCE_LABELS[source]` at the call site.

`_stage1_connection`:

```python
def _stage1_connection(config, client, input_fn, getpass_fn, source=None):
    """Stage 1.  Collects connection answers only -- main() builds the client."""
    _stage(1, "Connection")

    # No silent default: a flagless run asks which platform it is pointed at.
    if source is None:
        source = ask_choice("Threat intel platform", list(SOURCES),
                            "misp", input_fn)
    config["source"] = source
    label = SOURCE_LABELS.get(source, source)

    config["source_host"] = ask_required(
        "%s address (IP or hostname)" % label,
        client.host if client is not None else None, input_fn)
    config["scheme"] = ask_choice(
        "Scheme", ["https", "http"],
        client.scheme if client is not None else "https", input_fn)
    if config["scheme"] == "https":
        default_port = 443
    elif source == "opencti":
        default_port = OPENCTI_DEFAULT_PORT_HTTP
    else:
        default_port = 80
    if client is not None and client.port:
        default_port = client.port
    config["port"] = ask_int("Port", default_port, 1, 65535, input_fn)

    ...  # TLS, proxy unchanged

    config["token"] = (client.token if client is not None
                       else ask_token("%s API token" % label,
                                      getpass_fn=getpass_fn))

    ...  # timeout, retries unchanged
    return config
```

`run_interview` gains a matching `source=None` parameter and passes it through:

```python
def run_interview(client, input_fn=input, getpass_fn=getpass.getpass, source=None):
    config = {}
    _stage1_connection(config, client, input_fn, getpass_fn, source=source)
```

- [ ] **Step 4: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiStage1 -v`
Expected: PASS, 6 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 404 tests

- [ ] **Step 5: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: stage 1 asks which platform and branches its connection questions"
```

---

### Task 12: Interview stages 2, 2b and 3 for OpenCTI

**Files:**
- Modify: `nexus.py` — `discover` (line 1944), `_stage_feeds` (line 2033), `_stage3_iocs` (line 2084), `run_interview`
- Test: `test_nexus.py` — new class `TestOpenctiInterviewStages`; new stub `StubOpenctiClient`

**Interfaces:**
- Consumes: `OpenctiClient` discovery methods (Task 5), `OPENCTI_IOC_CLASSES` (Task 3)
- Produces:
  - `discover_opencti(client, probe_limit=None)` → `{"version", "types", "counts", "labels", "markings", "orgs", "label_ids", "marking_ids", "org_ids"}` where the `*_ids` values are `{name: id}` dicts
  - `_stage_feeds(config, discovery, input_fn, source="misp")` — prints a skip line for OpenCTI
  - `_stage3_iocs(config, discovery, input_fn, source="misp")`

- [ ] **Step 1: Write the failing test**

```python
class StubOpenctiClient(object):
    """A no-network OpenCTI client for interview tests."""

    def __init__(self):
        self.host = "cti.local"
        self.scheme = "https"
        self.port = 443
        self.token = "tok"
        self.verify_tls = True
        self.timeout = 30
        self.retries = 3

    def get_version(self):
        return {"version": "6.4.1"}

    def get_labels(self):
        return [{"id": "l1", "value": "phishing"},
                {"id": "l2", "value": "apt"}]

    def get_markings(self):
        return [{"id": "m1", "definition": "TLP:AMBER",
                 "definition_type": "TLP"}]

    def get_organizations(self):
        return [{"id": "o1", "name": "CIRCL"}]

    def count_type(self, main_type, base_filters=None, probe_limit=None):
        return ({"IPv4-Addr": 100, "Domain-Name": 50}.get(main_type, 0), True)


class TestOpenctiInterviewStages(Quiet):

    def test_discovery_returns_names_and_id_maps(self):
        found = nexus.discover_opencti(StubOpenctiClient())
        self.assertEqual(found["labels"], ["phishing", "apt"])
        self.assertEqual(found["label_ids"]["phishing"], "l1")
        self.assertEqual(found["markings"], ["TLP:AMBER"])
        self.assertEqual(found["marking_ids"]["TLP:AMBER"], "m1")
        self.assertEqual(found["orgs"], ["CIRCL"])
        self.assertEqual(found["org_ids"]["CIRCL"], "o1")
        self.assertEqual(found["counts"]["IPv4-Addr"], (100, True))

    def test_discovery_with_no_client_is_empty_not_a_crash(self):
        found = nexus.discover_opencti(None)
        self.assertEqual(found["labels"], [])
        self.assertEqual(found["counts"], {})

    def test_feed_stage_prints_a_skip_line_for_opencti(self):
        config = {}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            nexus._stage_feeds(config, {}, scripted([]), source="opencti")
        self.assertIn("Not applicable to OpenCTI", out.getvalue())
        self.assertEqual(config["feeds"], [])

    def test_ioc_stage_offers_opencti_classes(self):
        discovery = {"counts": {"IPv4-Addr": (100, True)},
                     "types": ["IPv4-Addr", "Domain-Name"]}
        fake = scripted(["1", "all"])
        config = {}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            nexus._stage3_iocs(config, discovery, fake, source="opencti")
        self.assertIn("IPv4-Addr", out.getvalue())
        self.assertTrue(set(config["types"]) <= {
            "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "Url"})

    def test_ioc_stage_still_offers_misp_classes_by_default(self):
        discovery = {"counts": {}, "types": []}
        fake = scripted(["1", "all"])
        config = {}
        with contextlib.redirect_stdout(io.StringIO()):
            nexus._stage3_iocs(config, discovery, fake)
        self.assertIn("ip-dst", config["types"])
```

The scripted answers for `_stage3_iocs` must match its real question sequence — read it and adjust while keeping the assertions.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiInterviewStages -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute 'discover_opencti'`

- [ ] **Step 3: Implement discovery**

```python
def discover_opencti(client, probe_limit=None):
    """Stage 2 for OpenCTI.  Names for the operator, ids for the filters.

    6.x filters take entity ids, so the interview shows names and translates
    through these maps rather than passing a name through as a guess.
    """
    found = {"version": {}, "types": [], "counts": {}, "labels": [],
             "markings": [], "orgs": [], "label_ids": {}, "marking_ids": {},
             "org_ids": {}}
    if client is None:
        return found

    try:
        found["version"] = client.get_version()
    except SourceError as exc:
        log.warning("could not fetch the OpenCTI version: %s", exc)

    for label, call, name_key, names_key, ids_key in (
            ("labels", client.get_labels, "value", "labels", "label_ids"),
            ("marking definitions", client.get_markings, "definition",
             "markings", "marking_ids"),
            ("organisations", client.get_organizations, "name", "orgs",
             "org_ids")):
        try:
            rows = call()
        except SourceError as exc:
            log.warning("could not fetch %s: %s", label, exc)
            continue
        for row in rows:
            name = row.get(name_key)
            if not name:
                continue
            if name not in found[names_key]:
                found[names_key].append(name)
            found[ids_key][name] = row.get("id")

    candidates = []
    for key in OPENCTI_IOC_CLASS_ORDER:
        candidates.extend(OPENCTI_IOC_CLASSES[key][1])
    for main_type in candidates:
        try:
            found["counts"][main_type] = client.count_type(main_type)
        except SourceError as exc:
            log.warning("count for %s failed: %s", main_type, exc)
    found["types"] = [t for t in candidates if found["counts"].get(t, (0,))[0]]
    return found
```

- [ ] **Step 4: Branch the feed and IOC stages**

`_stage_feeds` gains `source="misp"` and returns early for OpenCTI:

```python
def _stage_feeds(config, discovery, input_fn, source="misp"):
    config["feeds"] = []
    if source == "opencti":
        # Skipping silently would look like a bug to an operator who knows the
        # MISP flow.
        print("")
        print("-- Stage 2b: feeds")
        print("  Not applicable to OpenCTI; provenance is filtered by author "
              "and label in stage 5.")
        return
    ...  # the existing MISP body, unchanged
```

`_stage3_iocs` gains `source="misp"` and selects its class table:

```python
def _stage3_iocs(config, discovery, input_fn, source="misp"):
    if source == "opencti":
        classes = OPENCTI_IOC_CLASSES
        order = [k for k in OPENCTI_IOC_CLASS_ORDER if k in OPENCTI_IOC_CLASSES]
        off_by_default = OPENCTI_OFF_BY_DEFAULT
    else:
        classes = IOC_CLASSES
        order = [k for k in IOC_CLASS_ORDER if k in IOC_CLASSES]
        off_by_default = MISP_OFF_BY_DEFAULT
    ...  # the existing body, reading `classes`, `order` and `off_by_default`
```

The count annotation helpers `_count_label` and `_type_annotation` already take a counts dict; they work unchanged for both sources.

- [ ] **Step 5: Dispatch in `run_interview`**

```python
    _stage(2, "Discovery")
    if config["source"] == "opencti":
        discovery = discover_opencti(client)
        if client is not None:
            print("  %d labels, %d markings, %d organisations"
                  % (len(discovery["labels"]), len(discovery["markings"]),
                     len(discovery["orgs"])))
    else:
        discovery = discover(client)
        ...  # the existing MISP print
    config["discovery"] = discovery

    _stage_feeds(config, discovery, input_fn, source=config["source"])
    _stage3_iocs(config, discovery, input_fn, source=config["source"])
```

- [ ] **Step 6: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiInterviewStages -v`
Expected: PASS, 5 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 409 tests

- [ ] **Step 7: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: OpenCTI discovery, feed-stage skip and IOC type stage"
```

---

### Task 13: Interview stages 4 and 5 for OpenCTI, and the summary

**Files:**
- Modify: `nexus.py` — after `_stage4_quality` (line 2125) and `_stage5_scope` (line 2155), `run_interview`, `summarise_config` (line 2383)
- Test: `test_nexus.py` — new class `TestOpenctiQualityAndScope`

**Interfaces:**
- Consumes: `discover_opencti` output (Task 12), `build_opencti_filters` (Task 9)
- Produces:
  - `_stage4_quality_opencti(config, input_fn)` setting `min_score`, `min_confidence`, `exclude_revoked`, `require_detection`, `exclude_expired`
  - `_stage5_scope_opencti(config, discovery, input_fn)` setting `include_labels`, `exclude_labels`, `markings`, `authors` and their `*_ids` counterparts, `time_mode`, `days`, `date_from`, `date_to`, `timestamp_field`
  - `_names_to_ids(names, mapping)` → list of ids, dropping and warning on unknown names
  - `summarise_config` printing the source and the resolved query for either platform

- [ ] **Step 1: Write the failing test**

```python
class TestOpenctiQualityAndScope(Quiet):

    def discovery(self):
        return {"labels": ["phishing", "apt"], "markings": ["TLP:AMBER"],
                "orgs": ["CIRCL"],
                "label_ids": {"phishing": "l1", "apt": "l2"},
                "marking_ids": {"TLP:AMBER": "m1"},
                "org_ids": {"CIRCL": "o1"}}

    def test_quality_defaults(self):
        fake = scripted(["", "", "", "", ""])
        config = {}
        nexus._stage4_quality_opencti(config, fake)
        self.assertEqual(config["min_score"], 50)
        self.assertEqual(config["min_confidence"], 0)
        self.assertIs(config["exclude_revoked"], True)
        self.assertIs(config["require_detection"], False)
        self.assertIs(config["exclude_expired"], True)

    def test_quality_answers_are_taken(self):
        fake = scripted(["70", "60", "n", "y", "n"])
        config = {}
        nexus._stage4_quality_opencti(config, fake)
        self.assertEqual(config["min_score"], 70)
        self.assertEqual(config["min_confidence"], 60)
        self.assertIs(config["exclude_revoked"], False)
        self.assertIs(config["require_detection"], True)
        self.assertIs(config["exclude_expired"], False)

    def test_names_to_ids_translates_and_drops_unknowns(self):
        mapping = {"phishing": "l1"}
        with self.assertLogs("nexus", level="WARNING"):
            out = nexus._names_to_ids(["phishing", "ghost"], mapping)
        self.assertEqual(out, ["l1"])

    def test_scope_translates_names_to_ids(self):
        # include labels, exclude labels, markings, authors, time mode, field
        fake = by_prompt({
            "Include labels": "1",
            "Exclude labels": "2",
            "TLP markings": "1",
            "Created by": "1",
            "Time window": "1",
            "Timestamp field": "1",
        })
        config = {}
        nexus._stage5_scope_opencti(config, self.discovery(), fake)
        self.assertEqual(config["include_label_ids"], ["l1"])
        self.assertEqual(config["exclude_label_ids"], ["l2"])
        self.assertEqual(config["marking_ids"], ["m1"])
        self.assertEqual(config["author_ids"], ["o1"])

    def test_summary_names_the_source_and_shows_the_filter_group(self):
        config = {"source": "opencti", "source_host": "cti.local",
                  "scheme": "https", "port": 443, "verify_tls": True,
                  "types": ["IPv4-Addr"], "min_score": 50,
                  "exclude_revoked": True, "output_path": "/tmp/intel.dat"}
        text = nexus.summarise_config(config)
        self.assertIn("opencti", text)
        self.assertIn("x_opencti_main_observable_type", text)
        self.assertNotIn("restSearch", text)

    def test_misp_summary_still_shows_restsearch(self):
        config = {"source": "misp", "source_host": "misp.local",
                  "scheme": "https", "port": 443, "verify_tls": True,
                  "types": ["ip-dst"], "output_path": "/tmp/intel.dat"}
        text = nexus.summarise_config(config)
        self.assertIn("restSearch", text)
```

`by_prompt` is the existing prompt-keyed fake input at `test_nexus.py:1153`. Read its exact signature before use; if it matches on substring, the keys above must be substrings of the real prompts.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestOpenctiQualityAndScope -v`
Expected: FAIL — `AttributeError: module 'nexus' has no attribute '_stage4_quality_opencti'`

- [ ] **Step 3: Implement the stages**

```python
def _stage4_quality_opencti(config, input_fn):
    _stage(4, "Quality filters")
    config["min_score"] = ask_int(
        "Minimum x_opencti_score (0 = no filter)", 50, 0, 100, input_fn)
    config["min_confidence"] = ask_int(
        "Minimum confidence (0 = no filter)", 0, 0, 100, input_fn)
    config["exclude_revoked"] = ask_yes_no(
        "Exclude revoked indicators?", True, input_fn)
    config["require_detection"] = ask_yes_no(
        "Only indicators flagged for detection?", False, input_fn)
    # An indicator past its own author's valid_until is stale by their
    # judgement, and Zeek has no expiry of its own.
    config["exclude_expired"] = ask_yes_no(
        "Exclude indicators past their valid_until?", True, input_fn)
    return config


def _names_to_ids(names, mapping):
    """Selected names -> OpenCTI ids, dropping anything discovery never saw."""
    out = []
    for name in names or []:
        ident = mapping.get(name)
        if not ident:
            log.warning("no OpenCTI id for %r; it was dropped from the filter",
                        name)
            continue
        out.append(ident)
    return out


def _stage5_scope_opencti(config, discovery, input_fn):
    _stage(5, "Scope")
    labels = discovery.get("labels") or []
    markings = discovery.get("markings") or []
    orgs = discovery.get("orgs") or []

    config["include_labels"] = _ask_names("Include labels", labels,
                                          input_fn=input_fn)
    config["exclude_labels"] = _ask_names("Exclude labels", labels,
                                          input_fn=input_fn)
    config["markings"] = _ask_names("TLP markings", markings, input_fn=input_fn)
    config["authors"] = _ask_names("Created by (organisations)", orgs,
                                   input_fn=input_fn)

    config["include_label_ids"] = _names_to_ids(
        config["include_labels"], discovery.get("label_ids") or {})
    config["exclude_label_ids"] = _names_to_ids(
        config["exclude_labels"], discovery.get("label_ids") or {})
    config["marking_ids"] = _names_to_ids(
        config["markings"], discovery.get("marking_ids") or {})
    config["author_ids"] = _names_to_ids(
        config["authors"], discovery.get("org_ids") or {})

    mode = ask_choice("Time window", ["all", "last", "range"], "all", input_fn)
    config["time_mode"] = mode
    if mode == "last":
        config["days"] = ask_int("Days", 30, 1, 3650, input_fn)
    elif mode == "range":
        config["date_from"] = ask_date("From (YYYY-MM-DD)", None, input_fn)
        config["date_to"] = ask_date("To (YYYY-MM-DD)", None, input_fn)
    config["timestamp_field"] = ask_choice(
        "Timestamp field", ["created_at", "valid_from"], "created_at", input_fn)
    return config
```

`_ask_names` already exists at line 2146 — read its signature and match the call shape. If it takes `(prompt, live, preselected=None, input_fn=input)`, the calls above are correct.

- [ ] **Step 4: Dispatch in `run_interview` and the summary**

```python
    if config["source"] == "opencti":
        _stage4_quality_opencti(config, input_fn)
        _stage5_scope_opencti(config, discovery, input_fn)
    else:
        _stage4_quality(config, input_fn)
        _stage5_scope(config, discovery, input_fn)
```

In `summarise_config`, replace the hardcoded `MISP` label line and the trailing `restSearch` line:

```python
    source = config.get("source", "misp")
    label = SOURCE_LABELS.get(source, source)
    lines.append("  source      : %s" % source)
    lines.append("  %-12s: %s://%s%s (verify TLS: %s)"
                 % (label, scheme, config.get("source_host", "?"), shown_port,
                    _yes_no(config.get("verify_tls"))))
```

and at the end:

```python
    lines.append("")
    if source == "opencti":
        lines.append("  filters     : %s"
                     % json.dumps(build_opencti_filters(config), sort_keys=True))
    else:
        lines.append("  restSearch  : %s"
                     % json.dumps(build_search_params(config), sort_keys=True))
```

The MISP-only blocks in the middle of `summarise_config` — feeds, quality flags, threat level, sharing groups, event ids — should be skipped for OpenCTI and replaced with the OpenCTI equivalents (score, confidence, revoked, detection, expiry, labels, markings, authors). Guard each block on `source`.

- [ ] **Step 5: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestOpenctiQualityAndScope -v`
Expected: PASS, 6 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 415 tests

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: OpenCTI quality and scope stages, source-aware summary"
```

---

### Task 14: CLI wiring and command dispatch

**Files:**
- Modify: `nexus.py` — `build_parser` (line 2913), `main` (line 2981), `resolve_token` (line 2720), `cmd_probe` (line 2833), `cmd_explain` (line 2782), `cmd_build` (line 3010), `_fetch_records` (line 3187)
- Test: `test_nexus.py` — new class `TestSourceCli`

**Interfaces:**
- Consumes: everything from Tasks 2-13
- Produces:
  - `--source {misp,opencti}` and `--host HOST` arguments; `--misp HOST` retained as a deprecated alias
  - `make_client(config_or_args, token=None)` → `MispClient` or `OpenctiClient`
  - `resolve_token` reading `NEXUS_TOKEN` then `NEXUS_MISP_TOKEN`
  - `_fetch_records(client, config)` dispatching on `config["source"]`
  - `cmd_probe` / `cmd_explain` / `cmd_build` working for both sources

- [ ] **Step 1: Write the failing test**

```python
class TestSourceCli(unittest.TestCase):

    def parse(self, argv):
        return nexus.build_parser().parse_args(argv)

    def test_source_flag(self):
        self.assertEqual(self.parse(["--source", "opencti"]).source, "opencti")

    def test_source_defaults_to_none_so_the_interview_asks(self):
        self.assertIsNone(self.parse([]).source)

    def test_host_flag(self):
        self.assertEqual(self.parse(["--host", "cti.local"]).host, "cti.local")

    def test_misp_alias_sets_host_and_source(self):
        args = self.parse(["--misp", "misp.local"])
        resolved = nexus.resolve_source_args(args)
        self.assertEqual(resolved.host, "misp.local")
        self.assertEqual(resolved.source, "misp")

    def test_explicit_host_wins_over_the_alias(self):
        args = self.parse(["--host", "a", "--misp", "b"])
        self.assertEqual(nexus.resolve_source_args(args).host, "a")

    def test_make_client_picks_the_opencti_client(self):
        config = {"source": "opencti", "source_host": "cti.local",
                  "scheme": "https", "port": 443, "verify_tls": True,
                  "proxy": None, "timeout": 30, "retries": 3, "token": "tok"}
        self.assertIsInstance(nexus.make_client(config), nexus.OpenctiClient)

    def test_make_client_picks_the_misp_client(self):
        config = {"source": "misp", "source_host": "misp.local",
                  "scheme": "https", "port": 443, "verify_tls": True,
                  "proxy": None, "timeout": 30, "retries": 3, "token": "tok"}
        self.assertIsInstance(nexus.make_client(config), nexus.MispClient)

    def test_neutral_token_env_var_is_read_first(self):
        args = self.parse([])
        os.environ["NEXUS_TOKEN"] = "neutral"
        os.environ["NEXUS_MISP_TOKEN"] = "legacy"
        try:
            self.assertEqual(nexus.resolve_token(args, interactive=False),
                             "neutral")
        finally:
            del os.environ["NEXUS_TOKEN"]
            del os.environ["NEXUS_MISP_TOKEN"]

    def test_legacy_token_env_var_still_works(self):
        args = self.parse([])
        os.environ["NEXUS_MISP_TOKEN"] = "legacy"
        try:
            self.assertEqual(nexus.resolve_token(args, interactive=False),
                             "legacy")
        finally:
            del os.environ["NEXUS_MISP_TOKEN"]

    def test_fetch_records_uses_the_opencti_path(self):
        class Client(object):
            def __init__(self):
                self.calls = []

            def search_indicators(self, filters, max_results=None, stats=None):
                self.calls.append(filters)
                return iter([{"value": "evil.com", "type": "Domain-Name"}])

        client = Client()
        config = {"source": "opencti", "types": ["Domain-Name"]}
        records = list(nexus._fetch_records(client, config))
        self.assertEqual(records[0]["value"], "evil.com")
        self.assertEqual(len(client.calls), 1)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest test_nexus.TestSourceCli -v`
Expected: FAIL — `AttributeError: 'Namespace' object has no attribute 'source'`

- [ ] **Step 3: Add the arguments**

In `build_parser`, rename the connection group and add the new flags:

```python
    conn = parser.add_argument_group("platform connection")
    conn.add_argument("--source", choices=SOURCES, default=None,
                      help="which platform to pull from; asked if omitted")
    conn.add_argument("--host", metavar="HOST", default=None,
                      help="platform IP or hostname; asked if omitted")
    conn.add_argument("--misp", metavar="HOST", default=None,
                      help="deprecated alias for --host --source misp")
```

Everything else in that group is unchanged. Also update the parser description and the `--explain` / `--probe` help strings to say "platform" rather than "MISP".

- [ ] **Step 4: Add the resolvers**

```python
def resolve_source_args(args):
    """Fold the deprecated --misp alias into --host/--source."""
    if getattr(args, "misp", None):
        if not args.host:
            args.host = args.misp
            args.source = args.source or "misp"
            print("--misp is deprecated; use --host with --source misp",
                  file=sys.stderr)
        else:
            print("--misp ignored: --host was also given", file=sys.stderr)
    return args


def make_client(config):
    """Build the client for whichever platform the config names."""
    kwargs = {
        "host": config["source_host"], "token": config["token"],
        "scheme": config["scheme"], "port": config["port"],
        "verify_tls": config["verify_tls"], "proxy": config.get("proxy"),
        "timeout": config["timeout"], "retries": config["retries"],
    }
    if config.get("source") == "opencti":
        return OpenctiClient(**kwargs)
    return MispClient(**kwargs)
```

`resolve_token` gains the neutral env var first:

```python
    for name in ("NEXUS_TOKEN", "NEXUS_MISP_TOKEN"):
        env = os.environ.get(name)
        if env:
            return env.strip()
```

and its final prompt becomes `getpass.getpass("API token: ")` — the platform-specific prompt is the interview's job.

- [ ] **Step 5: Dispatch the fetch**

```python
def _fetch_records(client, config):
    """Yield records from whichever platform the config names."""
    if config.get("source") == "opencti":
        filters = build_opencti_filters(config)
        for record in client.search_indicators(
                filters, max_results=config.get("max_indicators"),
                stats=config.get("_stats")):
            yield record
        return
    ...  # the existing MISP body, unchanged
```

`cmd_build` must put the `BuildStats` instance it will use into `config["_stats"]` before calling `_fetch_records`, and pass that same instance into `build_indicators(..., stats=stats)`, so the OpenCTI counters and the mapping counters land in one report. `_stats` must also be added to `PROFILE_EXCLUDED_KEYS` — it is a live object, not an answer.

`cmd_build` also selects the mapping table:

```python
    if config.get("source") == "opencti":
        table, reasons = OPENCTI_TO_ZEEK, OPENCTI_UNMAPPABLE
    else:
        table, reasons = MISP_TO_ZEEK, MISP_UNMAPPABLE
    rows, stats = build_indicators(records, ..., stats=stats,
                                   mapping_table=table, unmappable=reasons)
```

and builds its client with `make_client(config)` instead of the direct `MispClient(...)` call.

- [ ] **Step 6: Make probe and explain source-aware**

`main` calls `resolve_source_args(args)` immediately after parsing, and the `--probe` guard changes from a hard error to a question, per the interactivity rule:

```python
    if args.probe:
        if not args.host:
            args.host = ask_required("Platform address (IP or hostname)", None)
        if not args.source:
            args.source = ask_choice("Threat intel platform", list(SOURCES),
                                     "misp")
        return cmd_probe(args)
```

`cmd_probe` branches on `args.source`: the MISP body is unchanged; the OpenCTI body prints the version, the label/marking/organisation counts, and a per-main-observable-type count table using `client.count_type`, followed by the `OPENCTI_UNMAPPABLE` list. Follow the existing MISP output layout exactly — same column widths, same headings.

`cmd_explain` prints `summarise_config(config)` as it already does, then either the restSearch body (MISP, per feed) or the FilterGroup:

```python
    if config.get("source") == "opencti":
        print("One query to POST /graphql:")
        print("  " + json.dumps(build_opencti_filters(config), indent=2,
                                sort_keys=True))
        return 0
    ...  # the existing MISP body
```

- [ ] **Step 7: Run the new tests and the whole suite**

Run: `python3 -m unittest test_nexus.TestSourceCli -v`
Expected: PASS, 10 tests

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 425 tests

- [ ] **Step 8: Smoke-test the flagless path is still interactive**

Run: `printf '' | python3 nexus.py --probe 2>&1 | head -5`
Expected: a prompt for the platform address, not `--probe requires --misp HOST`.

Run: `python3 nexus.py --help`
Expected: `--source`, `--host` and the deprecated `--misp` all listed.

- [ ] **Step 9: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: --source/--host CLI, client factory, source-aware probe and explain"
```

---

### Task 15: End-to-end OpenCTI build test

**Files:**
- Test: `test_nexus.py` — new class `TestOpenctiEndToEnd`

**Interfaces:**
- Consumes: everything
- Produces: no production code — this task proves the pipeline holds together

- [ ] **Step 1: Write the test**

```python
class TestOpenctiEndToEnd(unittest.TestCase):
    """An OpenCTI profile all the way to rendered intel lines."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def indicator(self, ident, entity_type, value):
        return {
            "id": ident, "standard_id": "indicator--" + ident,
            "name": "bad thing", "description": "seen in phishing",
            "pattern": "", "pattern_type": "stix",
            "x_opencti_detection": True, "updated_at": "2026-08-02T12:00:00Z",
            "createdBy": {"name": "CIRCL"},
            "objectLabel": [{"id": "l1", "value": "phishing"}],
            "objectMarking": [{"id": "m1", "definition": "TLP:AMBER"}],
            "observables": {"pageInfo": {"hasNextPage": False}, "edges": [
                {"node": {"entity_type": entity_type,
                          "observable_value": value}}]},
        }

    def test_records_render_to_valid_intel_lines(self):
        nodes = [self.indicator("i1", "Domain-Name", "evil.com"),
                 self.indicator("i2", "IPv4-Addr", "45.33.32.1"),
                 self.indicator("i3", "Url", "http://evil.com/payload")]
        records = []
        for node in nodes:
            records.extend(nexus.flatten_indicator(node))

        rows, stats = nexus.build_indicators(
            records, mapping_table=nexus.OPENCTI_TO_ZEEK,
            unmappable=nexus.OPENCTI_UNMAPPABLE,
            source_fmt="OpenCTI", desc_template="{event_info}",
            exclusions=nexus.ExclusionSet(exclude_private=True))

        lines = [nexus.header_line(False)] + nexus.rows_to_lines(rows, False)
        self.assertEqual(nexus.lint_lines(lines, False), [])

        indicators = sorted(r[0] for r in rows)
        self.assertEqual(indicators,
                         ["45.33.32.1", "evil.com", "evil.com/payload"])
        self.assertTrue(all(row[2] == "OpenCTI" for row in rows))

    def test_private_addresses_are_still_excluded(self):
        records = nexus.flatten_indicator(
            self.indicator("i1", "IPv4-Addr", "10.0.0.1"))
        rows, _ = nexus.build_indicators(
            records, mapping_table=nexus.OPENCTI_TO_ZEEK,
            exclusions=nexus.ExclusionSet(exclude_private=True))
        self.assertEqual(rows, [])

    def test_append_only_merge_across_sources(self):
        path = os.path.join(self.dir, "intel.dat")
        existing = [nexus.header_line(False),
                    "evil.com\tIntel::DOMAIN\tMISP\told desc\t-"]
        nexus.write_atomic(path, existing)

        records = nexus.flatten_indicator(
            self.indicator("i1", "Domain-Name", "evil.com"))
        rows, _ = nexus.build_indicators(
            records, mapping_table=nexus.OPENCTI_TO_ZEEK,
            source_fmt="OpenCTI", desc_template="{event_info}")
        _, existing_rows = nexus.read_existing(path)
        combined = nexus.merge_additive(
            existing_rows, nexus.rows_to_lines(rows, False))

        # The MISP row owns the key; the OpenCTI run adds nothing and removes
        # nothing.
        self.assertEqual(len(combined), 1)
        self.assertIn("MISP", combined[0])
        added, removed = nexus.indicator_delta(existing_rows, combined)
        self.assertEqual(removed, [])
```

Check `build_indicators`' real signature before finalising the calls above — parameter names must match exactly. Check `rows_to_lines` and `merge_additive` too; if `build_indicators` returns rows as tuples in a different order than `(indicator, type, source, desc, url)`, adjust the index in the `row[2]` assertion.

- [ ] **Step 2: Run it**

Run: `python3 -m unittest test_nexus.TestOpenctiEndToEnd -v`
Expected: PASS, 3 tests. If a test fails because of a signature mismatch, fix the test to match the real API — this task adds no production code unless a genuine defect is found, in which case fix the defect and say so in the commit message.

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 428 tests

- [ ] **Step 3: Commit**

```bash
git add test_nexus.py
git commit -m "test: end-to-end OpenCTI records through to rendered intel lines"
```

---

### Task 16: Documentation

**Files:**
- Modify: `HANDOFF.md`, `PLAN.md`
- Modify: `nexus.py` — module docstring (line 2), `__version__`

**Interfaces:**
- Consumes: everything
- Produces: documentation matching the shipped behaviour

- [ ] **Step 1: Update the module docstring and version**

```python
"""nexus.py -- build a Zeek intel.dat from MISP or OpenCTI, for Security Onion 3.2."""
```

Bump `__version__` — read its current value and increment the minor component.

- [ ] **Step 2: Update HANDOFF.md**

Edit these sections; do not rewrite the file wholesale.

- **State line** — phases 0-6 and 8 complete, phase 7 remaining, new test count.
- **§1 What this is** — say it asks for a MISP *or* OpenCTI address; one source per run.
- **§2 Run it** — add `--source`, `--host`, note `--misp` is deprecated, add an OpenCTI probe example.
- **§3 Verified ground truth** — add an OpenCTI subsection: `POST /graphql`, `Authorization: Bearer`, errors arrive with HTTP 200, cursor pagination, 6.x FilterGroup syntax, filters take entity ids.
- **§4 Architecture** — update the section map with `_HttpTransport`, `OpenctiClient`, `flatten_indicator`, `parse_stix_pattern`, `build_opencti_filters`, `discover_opencti` and the OpenCTI stages.
- **§5 Decisions already made** — add the five decisions from the spec's table, dated 2026-08-17.
- **§6 Non-obvious things that will bite you** — add: GraphQL returns 200 on auth failure and an unhandled error body looks exactly like an empty result set; OpenCTI filters take entity ids, not names; certificate hashes need their own `X509-` mapping keys or SHA-1 certs land in `Intel::FILE_HASH`; non-STIX pattern types are never mined for values.
- **§7 What is left** — phase 7 unchanged, plus the six unverified OpenCTI items from spec §12.

- [ ] **Step 3: Update PLAN.md**

- Title and status line: two sources, phase 8 complete, phase 7 outstanding.
- §1: add the OpenCTI flow beside the MISP one.
- §2: add the OpenCTI ground-truth subsection.
- §3: update the script-structure map.
- §4: add the OpenCTI interview stages beside the MISP ones.
- Add a line to §14 (out of scope) covering the exclusions in spec §13: no dual-source runs, no observables-as-source, no 5.x syntax, no write-back, no connectors or live streams, no relationship traversal.

- [ ] **Step 4: Verify the docs match reality**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 428 tests — confirm the number quoted in `HANDOFF.md` matches this exactly.

Run: `python3 nexus.py --help`
Expected: every flag named in `HANDOFF.md` §2 appears.

- [ ] **Step 5: Commit**

```bash
git add HANDOFF.md PLAN.md nexus.py
git commit -m "docs: document OpenCTI as a second source"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §4.1 shared transport | 2 |
| §4.2 GraphQL errors, cursor pagination | 4, 8 |
| §5.1 version probe | 4 |
| §5.2 discovery, counts | 5 |
| §5.3 indicator search | 8 |
| §5.4 build_opencti_filters | 9 |
| §6.1 OPENCTI_TO_ZEEK | 3 |
| §6.2 OPENCTI_UNMAPPABLE | 3 |
| §6.3 IOC classes | 3 |
| §6.4 flatten_indicator | 6 |
| §6.5 STIX pattern fallback | 7 |
| §7 BuildStats counters | 6 (declared), 8 (wired) |
| §8 interview stages | 11, 12, 13 |
| §9 interactivity rule | 11 (stage 1), 14 (probe) |
| §10.1 neutral spine | 2 (exceptions), 10 (config keys) |
| §10.2 profile v2 | 10 |
| §10.3 CLI | 14 |
| §10.4 metadata defaults | 13 (summary), 14 (cmd_build) |
| §11 testing | every task, plus 15 |
| §12 unverified items | 16 (documented) |

**Placeholder scan:** no TBDs, no "add error handling", every code step carries real code.

**Type consistency:** `flatten_indicator(node, stats=None)` is called with `stats=` in Task 8. `count_type(main_observable_type, base_filters=None, probe_limit=None)` is called positionally in Task 12's stub with the same arity. `build_opencti_filters(config, now=None)` is called with one argument in Tasks 13 and 14 and two under test in Task 9. `_names_to_ids(names, mapping)` matches its Task 13 call sites. `map_attribute(..., table=None)` and `build_indicators(..., mapping_table=None, unmappable=None)` match Tasks 3, 14 and 15.

**Test count arithmetic:** 313 → 318 → 328 → 335 → 343 → 354 → 364 → 375 → 391 → 398 → 404 → 409 → 415 → 425 → 428. Each task's expected total is the previous total plus that task's new tests. If a task's real count differs because an existing test needed splitting, carry the corrected number forward rather than forcing the number in this plan.
