#!/usr/bin/env python3
"""nexus.py - build a Zeek intel.dat from MISP, OpenCTI or TAXII, for Security
Onion 3.2.

Phases 0-6 and 8-10: environment check, source client (MISP, OpenCTI or a
TAXII 2.0/2.1 server), the mapping/normalise/write core, the interactive
interview, profiles and the unattended modes, the safety guardrails,
apply-to-grid, offline build plus airgapped import, and OpenCTI (phase 9)
and TAXII (phase 10) as further sources.  Phase 7 (systemd timer, install
docs) is outstanding.
One source per run, selected in the interview or via --source.  --offline
builds a transfer-ready intel.dat on a host with no Security Onion installed;
--import PATH merges one back into a manager's live file, append-only.

Standard library only.  Python 3.6+.
"""

import argparse
import base64
import difflib
import getpass
import http.client
import ipaddress
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

__version__ = "0.5.0-dev"

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Security Onion 3.2 paths.  The manager-side source of truth is under
# saltstack/local; `salt -C 'I@zeek:enabled:true' state.apply zeek` syncs it to
# the runtime path on each node.
SO_INTEL_DIR = "/opt/so/saltstack/local/salt/zeek/policy/intel"
SO_INTEL_DEFAULT_DIR = "/opt/so/saltstack/default/salt/zeek/policy/intel"
SO_INTEL_RUNTIME_DIR = "/opt/so/conf/zeek/policy/intel"
SO_INTEL_FILE = os.path.join(SO_INTEL_DIR, "intel.dat")
SO_LOAD_FILE = "__load__.Zeek"
SO_VERSION_FILES = ("/etc/soversion", "/opt/so/saltstack/local/pillar/global.sls")
# argv rather than a shell string -- nothing here needs a shell, and the
# compound target contains quotes that a shell would have to be trusted with.
SO_APPLY_ARGV = ["sudo", "salt", "-C", "I@zeek:enabled:true",
                 "state.apply", "zeek"]
SO_APPLY_CMD = "sudo salt -C 'I@zeek:enabled:true' state.apply zeek"
SO_REPORTER_LOG = "/nsm/zeek/logs/current/reporter.log"
SO_INTEL_LOG = "/nsm/zeek/logs/current/intel.log"
SO_ZEEK_POLICY_DIRS = (
    "/opt/so/saltstack/local/salt/zeek/policy",
    "/opt/so/conf/zeek/policy",
)

# Nexus working state.
NEXUS_HOME = "/opt/nexus"

PROFILE_VERSION = 2
# Never persisted.  `token` and `taxii_username` are secrets -- a Basic
# username is half a credential and is excluded exactly like the password it
# is paired with; `discovery` is a cache of live MISP lists that would be
# stale the moment it is written.
PROFILE_EXCLUDED_KEYS = ("token", "taxii_username", "discovery", "_stats")
# v1 predates OpenCTI support and named everything after MISP.
PROFILE_V1_KEY_MAP = {"misp_host": "source_host",
                      "misp_base_url": "source_base_url"}

SOURCES = ("misp", "opencti", "taxii")
SOURCE_LABELS = {"misp": "MISP", "opencti": "OpenCTI", "taxii": "TAXII"}

TAXII_VERSIONS = ("2.1", "2.0")
# 2.1 renamed the media type and moved discovery; 2.0 servers answer neither.
TAXII_ACCEPT = {
    "2.1": "application/taxii+json;version=2.1",
    "2.0": "application/vnd.oasis.taxii+json; version=2.0",
}
TAXII_DISCOVERY = {"2.1": "/taxii2/", "2.0": "/taxii/"}
# 2.1 sends this as `limit`; 2.0 has no such parameter and can only express it
# as the width of a Range window.
TAXII_PAGE_SIZE = 100

# Zeek Intel framework.  This is the complete Intel::Type set.
ZEEK_TYPES = (
    "Intel::ADDR",
    "Intel::SUBNET",
    "Intel::URL",
    "Intel::SOFTWARE",
    "Intel::EMAIL",
    "Intel::DOMAIN",
    "Intel::USER_NAME",
    "Intel::CERT_HASH",
    "Intel::PUBKEY_HASH",
    "Intel::FILE_HASH",
    "Intel::FILE_NAME",
)

INTEL_FIELDS = ("indicator", "indicator_type", "meta.source", "meta.desc", "meta.url")
NULL_FIELD = "-"

# Reject subnets broader than these -- a stray /8 in MISP would arm Zeek
# against a sixteenth of the internet.
MIN_PREFIX_V4 = 16
MIN_PREFIX_V6 = 32

# md5 32, sha1 40, sha224 56, sha256 64, sha384 96, sha512 128.
VALID_HASH_LENGTHS = frozenset((32, 40, 56, 64, 96, 128))

DEFAULT_META_MAXLEN = 200
DEFAULT_SOURCE_PREFIX = "MISP"

# MISP attribute type -> [(value part index, Zeek Intel type), ...]
# Composite MISP types ("domain|ip") carry two indicators separated by "|";
# the part index selects which half feeds which Zeek type.
MISP_TO_ZEEK = {
    # -- network -----------------------------------------------------------
    "ip-src": [(0, "Intel::ADDR")],
    "ip-dst": [(0, "Intel::ADDR")],
    "ip-src|port": [(0, "Intel::ADDR")],
    "ip-dst|port": [(0, "Intel::ADDR")],
    "domain": [(0, "Intel::DOMAIN")],
    "hostname": [(0, "Intel::DOMAIN")],
    "domain|ip": [(0, "Intel::DOMAIN"), (1, "Intel::ADDR")],
    "hostname|port": [(0, "Intel::DOMAIN")],
    "url": [(0, "Intel::URL")],
    "uri": [(0, "Intel::URL")],
    "link": [(0, "Intel::URL")],
    # -- file --------------------------------------------------------------
    "md5": [(0, "Intel::FILE_HASH")],
    "sha1": [(0, "Intel::FILE_HASH")],
    "sha224": [(0, "Intel::FILE_HASH")],
    "sha256": [(0, "Intel::FILE_HASH")],
    "sha384": [(0, "Intel::FILE_HASH")],
    "sha512": [(0, "Intel::FILE_HASH")],
    "filename": [(0, "Intel::FILE_NAME")],
    "filename|md5": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    "filename|sha1": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    "filename|sha224": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    "filename|sha256": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    "filename|sha384": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    "filename|sha512": [(0, "Intel::FILE_NAME"), (1, "Intel::FILE_HASH")],
    # -- email -------------------------------------------------------------
    "email": [(0, "Intel::EMAIL")],
    "email-src": [(0, "Intel::EMAIL")],
    "email-dst": [(0, "Intel::EMAIL")],
    "email-reply-to": [(0, "Intel::EMAIL")],
    "target-email": [(0, "Intel::EMAIL")],
    "whois-registrant-email": [(0, "Intel::EMAIL")],
    # -- tls ---------------------------------------------------------------
    "x509-fingerprint-sha1": [(0, "Intel::CERT_HASH")],
    # -- host --------------------------------------------------------------
    "user-agent": [(0, "Intel::SOFTWARE")],
    "target-user": [(0, "Intel::USER_NAME")],
    "github-username": [(0, "Intel::USER_NAME")],
    "whois-registrant-name": [(0, "Intel::USER_NAME")],
}

# Types deliberately dropped, with the reason surfaced in the run report so
# nothing disappears silently.
MISP_UNMAPPABLE = {
    "x509-fingerprint-md5": "Intel::CERT_HASH is SHA-1 only",
    "x509-fingerprint-sha256": "Intel::CERT_HASH is SHA-1 only",
    "ssdeep": "fuzzy hash, no Zeek equivalent",
    "imphash": "no Zeek equivalent",
    "authentihash": "no Zeek equivalent",
    "vhash": "no Zeek equivalent",
    "tlsh": "fuzzy hash, no Zeek equivalent",
    "pehash": "no Zeek equivalent",
}

# Noisy or low-value by default; the interview turns these on explicitly.
MISP_OFF_BY_DEFAULT = frozenset(
    ("filename", "link", "target-user", "github-username", "whois-registrant-name")
)

# IOC classes offered in the interview (phase 3 consumes this).
IOC_CLASSES = {
    "network": ("Network - IP / subnet / domain / URL",
                ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain",
                 "hostname", "domain|ip", "hostname|port", "url", "uri", "link"]),
    "file": ("File - hashes / filenames",
             ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "filename",
              "filename|md5", "filename|sha1", "filename|sha224",
              "filename|sha256", "filename|sha384", "filename|sha512"]),
    "email": ("Email - addresses",
              ["email", "email-src", "email-dst", "email-reply-to",
               "target-email", "whois-registrant-email"]),
    "tls": ("TLS - certificate hashes", ["x509-fingerprint-sha1"]),
    "host": ("Host - user agents / usernames",
             ["user-agent", "target-user", "github-username",
              "whois-registrant-name"]),
}

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

# Two vocabularies meet here.  config["types"] holds
# x_opencti_main_observable_type names, because that is what the server-side
# type filter takes; flatten_indicator() emits the finer OPENCTI_TO_ZEEK keys,
# because a StixFile carries several value types at once.  This is the
# expansion between them -- identity where the two happen to agree.
_OPENCTI_FILE_RECORD_TYPES = ["File-Name", "MD5", "SHA-1", "SHA-224",
                              "SHA-256", "SHA-384", "SHA-512", "SSDEEP",
                              "TLSH"]

OPENCTI_MAIN_TO_RECORD_TYPES = {
    "IPv4-Addr":        ["IPv4-Addr"],
    "IPv6-Addr":        ["IPv6-Addr"],
    "Domain-Name":      ["Domain-Name"],
    "Hostname":         ["Hostname"],
    "Url":              ["Url"],
    "Email-Addr":       ["Email-Addr"],
    "StixFile":         _OPENCTI_FILE_RECORD_TYPES,
    "Artifact":         _OPENCTI_FILE_RECORD_TYPES,
    "X509-Certificate": ["X509-SHA-1", "X509-MD5", "X509-SHA-256"],
    "User-Account":     ["User-Account"],
    "Software":         ["Software"],
}


def opencti_record_types(main_types):
    """Selected main observable types -> the record types they can emit.

    Emissions with no Zeek equivalent (SSDEEP, X509-SHA-256) are included on
    purpose: they then reach build_indicators' unmapped counter instead of
    being dropped without a word.
    """
    out = []
    for main_type in main_types or ():
        for record_type in OPENCTI_MAIN_TO_RECORD_TYPES.get(main_type,
                                                            [main_type]):
            if record_type not in out:
                out.append(record_type)
    return out


def opencti_zeek_types(main_type):
    """The Zeek Intel types one main observable type can produce, in order."""
    out = []
    for record_type in OPENCTI_MAIN_TO_RECORD_TYPES.get(main_type,
                                                        [main_type]):
        for _, zeek_type in OPENCTI_TO_ZEEK.get(record_type, ()):
            if zeek_type not in out:
                out.append(zeek_type)
    return out

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

GRAPHQL_PATH = "/graphql"
OPENCTI_DEFAULT_PORT_HTTP = 4000
# GraphQL answers 200 even when it refuses you, so auth failure has to be read
# out of the error body rather than the status line.
OPENCTI_AUTH_ERROR_CODES = frozenset(
    ("AUTH_REQUIRED", "FORBIDDEN_ACCESS", "AUTH_FAILURE", "UNAUTHORIZED"))
_OPENCTI_AUTH_PATTERN = re.compile(
    r"\bunauthori[sz]ed\b|\bforbidden\b|\bauthenticat\w*\b"
    r"|\bmust be logged in\b|\blogged in\b|invalid token|expired token"
    r"|missing token", re.IGNORECASE)

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


log = logging.getLogger("nexus")


# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

class RedactingFilter(logging.Filter):
    """Scrub secrets out of every log record.

    The API token reaches a surprising number of places -- exception text from
    urllib, debug dumps of request headers -- so redaction happens at the
    logging layer rather than at each call site.
    """

    def __init__(self):
        super(RedactingFilter, self).__init__()
        self._secrets = []

    def add_secret(self, secret):
        if secret and len(secret) >= 8:
            self._secrets.append(secret)

    def scrub(self, text):
        for secret in self._secrets:
            text = text.replace(secret, "***REDACTED***")
        return text

    _scrub = scrub  # retained: callers predate the public name

    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = dict(
                    (k, self._scrub(v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                )
            else:
                record.args = tuple(
                    self._scrub(a) if isinstance(a, str) else a for a in record.args
                )
        if record.exc_text:
            record.exc_text = self._scrub(record.exc_text)
        return True


REDACTOR = RedactingFilter()


class RedactingFormatter(logging.Formatter):
    """Scrub the fully rendered record, tracebacks included.

    RedactingFilter alone is not enough: logging runs filters before
    formatting, so `record.exc_text` is still None at filter time and an
    exception carrying the token would reach the handler unredacted.
    """

    def format(self, record):
        return REDACTOR.scrub(logging.Formatter.format(self, record))


def setup_logging(verbose=False, logfile=None, required=True):
    """Configure the nexus logger.

    `required` is False when the log path is just the built-in default -- an
    offline `--lint` on a workstation should not nag about /opt/nexus.
    """
    root = logging.getLogger("nexus")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers = []

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(RedactingFormatter("%(levelname)s %(message)s"))
    stream.addFilter(REDACTOR)
    root.addHandler(stream)

    if logfile:
        try:
            os.makedirs(os.path.dirname(logfile), exist_ok=True)
            fh = logging.FileHandler(logfile)
            fh.setFormatter(
                RedactingFormatter("%(asctime)s %(levelname)s %(message)s")
            )
            fh.addFilter(REDACTOR)
            root.addHandler(fh)
        except OSError as exc:
            log_at = root.warning if required else root.debug
            log_at("could not open log file %s: %s", logfile, exc)
    return root


# ---------------------------------------------------------------------------
# CLIENT
# ---------------------------------------------------------------------------

def _is_loopback(host):
    """Plain HTTP to localhost is a lab setup, not a token disclosure."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that would leak the Authorization header.

    urllib's default handler forwards all headers on a 3xx, so a compromised
    or merely misconfigured MISP could bounce the request -- and the API
    token with it -- to an arbitrary host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_host = urllib.parse.urlparse(req.full_url).netloc
        new_host = urllib.parse.urlparse(newurl).netloc
        if new_host and new_host != old_host:
            raise urllib.error.HTTPError(
                req.full_url, code,
                "refusing cross-host redirect to %s (would leak the API token)"
                % newurl, headers, fp)
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)


class SourceError(Exception):
    """Any failure talking to a threat intel platform."""


class SourceAuthError(SourceError):
    """The platform rejected the API token."""


class TaxiiError(SourceError):
    pass


# The MISP names predate OpenCTI support.  Kept so existing call sites and
# tests keep working; new code raises and catches the neutral names.
MispError = SourceError
MispAuthError = SourceAuthError


class _HttpTransport(object):
    """Shared HTTP plumbing.  Subclasses own their auth header and their API.

    Only transport subclasses speak HTTP.  Everything downstream sees flattened
    dicts.
    """

    RETRY_STATUS = frozenset((429, 500, 502, 503, 504))

    # TAXII negotiates a version-specific media type; everything else is
    # plain JSON.  A class attribute rather than a constructor argument
    # because it is a property of the protocol, not of the connection.
    ACCEPT = "application/json"

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

    def _request(self, method, path, body=None, extra_headers=None):
        """Return (parsed_json, headers).  Retries on transient failures.

        extra_headers is merged last, for the one-off headers a single call
        needs (TAXII 2.0's Range); leaving it out sends exactly what every
        other caller has always sent.
        """
        url = urllib.parse.urljoin(self.base_url, path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Accept": self.ACCEPT,
            "Content-Type": "application/json",
            "User-Agent": "nexus/%s" % __version__,
        }
        headers.update(self._auth_headers())
        if extra_headers:
            headers.update(extra_headers)

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
            except (UnicodeError, http.client.InvalidURL) as exc:
                # urllib rejects a malformed host before it opens a socket,
                # and neither of these is an OSError.  Retrying cannot help:
                # the URL will be just as unbuildable next time.
                raise SourceError("cannot build a request for %s: %s"
                                  % (url, exc))
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

    # -- discovery ---------------------------------------------------------

    def get_version(self):
        data, _ = self._request("GET", "/servers/getVersion")
        return data

    def describe_types(self):
        data, _ = self._request("GET", "/attributes/describeTypes")
        result = data.get("result", data)
        return {
            "types": result.get("types", []),
            "categories": result.get("categories", []),
        }

    def get_tags(self):
        data, _ = self._request("GET", "/tags")
        tags = data.get("Tag", data if isinstance(data, list) else [])
        return [
            {"id": t.get("id"), "name": t.get("name"), "colour": t.get("colour")}
            for t in tags
            if isinstance(t, dict) and t.get("name")
        ]

    def get_orgs(self):
        data, _ = self._request("GET", "/organisations")
        out = []
        for row in data if isinstance(data, list) else []:
            org = row.get("Organisation", row)
            if org.get("name"):
                out.append({"id": org.get("id"), "name": org.get("name"),
                            "uuid": org.get("uuid")})
        return out

    def get_feeds(self):
        """Configured feeds, enabled or not.

        A feed's own record is the only place that says how its data can be
        recognised once ingested -- restSearch has no feed_id filter.
        """
        data, _ = self._request("GET", "/feeds")
        # MISP returns a bare list here on some versions, an envelope on others.
        rows = data if isinstance(data, list) else data.get("response", [])
        out = []
        for row in rows:
            feed = row.get("Feed", row) if isinstance(row, dict) else {}
            if not feed.get("id"):
                continue
            tag = (row.get("Tag") or {}) if isinstance(row, dict) else {}
            out.append({
                "id": str(feed.get("id")),
                "name": feed.get("name") or "feed %s" % feed.get("id"),
                "provider": feed.get("provider") or "",
                "url": feed.get("url") or "",
                "enabled": _misp_bool(feed.get("enabled")),
                "caching_enabled": _misp_bool(feed.get("caching_enabled")),
                "source_format": feed.get("source_format") or "",
                "tag_id": feed.get("tag_id"),
                "tag_name": tag.get("name") or "",
                "orgc_id": feed.get("orgc_id"),
                "fixed_event": _misp_bool(feed.get("fixed_event")),
                "event_id": feed.get("event_id"),
            })
        return out

    def get_sharing_groups(self):
        data, _ = self._request("GET", "/sharing_groups")
        # MISP returns a bare list here on some versions, an envelope on others.
        rows = data if isinstance(data, list) else data.get("response", [])
        out = []
        for row in rows:
            sg = row.get("SharingGroup", row)
            if sg.get("name"):
                out.append({"id": sg.get("id"), "name": sg.get("name")})
        return out

    # -- search ------------------------------------------------------------

    def count_type(self, misp_type, base_params=None, probe_limit=5000):
        """Return (count, exact).

        MISP does not reliably report a total, so trust the X-Result-Count
        header when it is present and fall back to a bounded probe otherwise.
        `exact` is False when the probe hit its ceiling.
        """
        params = dict(base_params or {})
        params.update({"type": misp_type, "limit": probe_limit, "page": 1,
                       "returnFormat": "json"})
        data, headers = self._request("POST", "/attributes/restSearch", params)

        header_count = headers.get("X-Result-Count")
        if header_count is not None:
            try:
                return int(header_count), True
            except (TypeError, ValueError):
                pass

        attrs = self._extract_attributes(data)
        return len(attrs), len(attrs) < probe_limit

    def search_attributes(self, params, max_results=None, max_pages=None):
        """Yield flattened attribute records, paging until MISP runs dry."""
        page = 1
        yielded = 0
        previous_signature = None
        while max_pages is None or page <= max_pages:
            body = dict(params)
            body.update({"returnFormat": "json", "limit": self.page_size,
                         "page": page})
            data, _ = self._request("POST", "/attributes/restSearch", body)
            attrs = self._extract_attributes(data)
            if not attrs:
                return

            signature = tuple((a.get("uuid"), a.get("id"), a.get("value"))
                              for a in attrs)
            if signature == previous_signature:
                log.warning("stopped because MISP repeated page %d -- does "
                            "this instance honour the `page` parameter?", page)
                return
            previous_signature = signature

            for attr in attrs:
                yield flatten_attribute(attr)
                yielded += 1
                if max_results is not None and yielded >= max_results:
                    log.info("stopped at max_results=%d", max_results)
                    return

            if len(attrs) < self.page_size:
                return
            page += 1
        log.warning("stopped at the explicit %d page ceiling", max_pages)

    @staticmethod
    def _extract_attributes(data):
        if not isinstance(data, dict):
            return []
        response = data.get("response", data)
        if isinstance(response, dict):
            attrs = response.get("Attribute", [])
        elif isinstance(response, list):
            attrs = response
        else:
            attrs = []
        return [a for a in attrs if isinstance(a, dict)]


def merge_opencti_filters(base, extra_filters):
    """Return a FilterGroup with `extra_filters` ANDed onto `base`."""
    merged = {"mode": "and", "filters": [], "filterGroups": []}
    if isinstance(base, dict):
        merged["mode"] = base.get("mode") or "and"
        merged["filters"] = list(base.get("filters") or [])
        merged["filterGroups"] = list(base.get("filterGroups") or [])
    merged["filters"] = merged["filters"] + list(extra_filters or [])
    return merged


class OpenctiClient(_HttpTransport):
    """Minimal OpenCTI 6.x GraphQL client over urllib."""

    def __init__(self, host, token, scheme="https", port=None, verify_tls=True,
                 proxy=None, timeout=30, retries=3, page_size=100):
        _HttpTransport.__init__(self, host, token, scheme=scheme, port=port,
                                verify_tls=verify_tls, proxy=proxy,
                                timeout=timeout, retries=retries)
        self.page_size = page_size

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
        permission-dependent, so when it's missing or unreadable we fall back
        to what the page actually returned and say so rather than reporting a
        guess as fact.

        The fallback's exactness still holds even without globalCount:
        COUNT_QUERY asks for `first: 1`, so `hasNextPage=False` means that
        single row *was* the whole result set and len(nodes) (0 or 1) is the
        true total, not a lower bound.  This is coupled to the query's page
        size — if COUNT_QUERY's `first:` ever grows past 1, `not hasNextPage`
        stops meaning "we saw everything" and this exactness claim must
        change with it.

        probe_limit is accepted and ignored so this stays call-compatible
        with MispClient.count_type; a later stage calls both through one
        code path.
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
        # first: 1 above means a closed page (no hasNextPage) already saw the
        # entire result set, so len(nodes) is exact even without globalCount.
        nodes = _edge_nodes(connection)
        return len(nodes), not page_info.get("hasNextPage")

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
            x_opencti_detection
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
        REDACTOR.add_secret(username)

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

    def fetch_objects(self, collection, added_after=None, max_results=None,
                      page_size=TAXII_PAGE_SIZE):
        """Yield raw STIX objects from one collection.

        `match[type]=indicator` and `added_after` are the only filters TAXII
        defines that are useful here; everything else the operator asked for
        is applied after download, in taxii_object_allowed().
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
        previous_cursor = None
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
            if not objects:
                # `more: True` with a fresh cursor every page satisfies both
                # guards below for ever, and no record is yielded for a cap to
                # count.  _fetch_objects_20 carries the same guard.
                return
            if not (body or {}).get("more"):
                return
            cursor = (body or {}).get("next")
            # A server that repeats or omits `next` would otherwise be
            # pulled forever; OpenctiClient.search_indicators carries the
            # same single-cursor guard.
            if not cursor or cursor == previous_cursor:
                log.warning("stopped because TAXII did not advance the "
                            "cursor -- does this server honour `next`?")
                return
            previous_cursor = cursor

    _CONTENT_RANGE = re.compile(r"items\s+(\d+)\s*-\s*(\d+)\s*/\s*(\d+|\*)")

    def _fetch_objects_20(self, collection, added_after, max_results,
                          page_size):
        """TAXII 2.0: a STIX bundle per page, paged by Range headers.

        2.1 replaced this with an envelope carrying `more`/`next`.  Every
        exit below is load-bearing: a 2.0 server that omits Content-Range,
        reports an unknown total, sends an empty page or repeats the same
        window gets one more request and no more -- a short pull beats an
        endless one.  Unverified against a real 2.0 server.
        """
        path = "%scollections/%s/objects/" % (collection["api_root"],
                                              collection["id"])
        params = {"match[type]": "indicator"}
        if added_after:
            params["added_after"] = added_after
        query = path + "?" + urllib.parse.urlencode(params)

        sent = 0
        start = 0
        first_total = None
        while True:
            body, headers = self._request(
                "GET", query,
                extra_headers={"Range": "items %d-%d"
                                        % (start, start + page_size - 1)})
            objects = (body or {}).get("objects") or []
            for obj in objects:
                yield obj
                sent += 1
                if max_results is not None and sent >= max_results:
                    return
            match = self._CONTENT_RANGE.search(
                headers.get("Content-Range") or "")
            if not match:
                return           # no header, or one we cannot read
            last, total = match.group(2), match.group(3)
            if total == "*":
                return           # unknown total; do not guess
            if first_total is None:
                # Pin the first page's total.  A server whose reported total
                # keeps outrunning `last` -- items 0-0/2, then 1-1/3, then
                # 2-2/4 -- satisfies every other guard here forever.  The
                # trade-off is deliberate: a collection genuinely growing
                # mid-pull is truncated at the total it had when the pull
                # started, and the next run's `added_after` picks up the
                # remainder.  A short pull beats an endless one.
                first_total = int(total)
            if int(last) + 1 >= first_total:
                return
            if not objects:
                return           # no progress; stop rather than spin
            if int(last) + 1 <= start:
                # The window did not move, so asking again would fetch the
                # same items forever; 2.1's repeated-cursor guard, in Range
                # clothing.
                log.warning("stopped because TAXII did not advance the "
                            "range -- does this server honour Range?")
                return
            start = int(last) + 1


def _misp_bool(value):
    """MISP returns booleans as 0/1, "0"/"1", or real bools depending on age."""
    if isinstance(value, str):
        return value not in ("0", "", "false", "False")
    return bool(value)


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


def flatten_attribute(attr):
    """MISP attribute JSON -> the internal record the rest of Nexus uses."""
    event = attr.get("Event") or {}
    tags = []
    for source in (attr.get("Tag") or [], event.get("Tag") or []):
        for tag in source:
            name = tag.get("name") if isinstance(tag, dict) else None
            if name and name not in tags:
                tags.append(name)

    return {
        "value": attr.get("value") or "",
        "type": attr.get("type") or "",
        "category": attr.get("category") or "",
        "uuid": attr.get("uuid") or "",
        "timestamp": attr.get("timestamp") or "",
        "comment": attr.get("comment") or "",
        "event_id": str(attr.get("event_id") or event.get("id") or ""),
        "event_uuid": attr.get("event_uuid") or event.get("uuid") or "",
        "event_info": event.get("info") or "",
        "event_tags": tags,
        "org": (event.get("Orgc") or {}).get("name") or event.get("org_id") or "",
    }


def _opencti_timestamp_text(value):
    """OpenCTI ISO-8601 -> a string strptime("%z") can take on Python 3.6.

    strptime's %z directive only learned to accept a colon in the offset in
    3.7 (the ":?" in CPython's _strptime.TimeRE pattern) -- this project's
    floor is 3.6, so "+00:00" has to become "+0000" before parsing, not after.
    """
    text = str(value).strip().replace("Z", "+0000")
    # OpenCTI emits millisecond precision; datetime in 3.6 will not take it.
    text = re.sub(r"\.\d+", "", text)
    return re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)


def _opencti_epoch(value):
    """ISO-8601 from OpenCTI -> epoch seconds, or "" when it will not parse."""
    if not value:
        return ""
    text = _opencti_timestamp_text(value)
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


# Only STIX patterns are parsed.  A YARA/Sigma/Snort/PCRE rule's string
# literals are not indicators, and mining them would arm Zeek against
# whatever text a detection rule happened to mention.
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

# `object-type:property = 'value'`.  The property class deliberately excludes
# "!" and whitespace, so a "!=" comparison can never bridge from the property
# to the "=" and the regex simply fails to match there -- an exclusion is not
# something a flat indicator list can express, so it is dropped for free
# rather than needing a special case.
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
        obj_type = match.group(1)
        prop = match.group(2).strip()
        value = match.group(3).strip()
        if not value:
            continue

        if prop.lower().startswith("hashes."):
            algorithm = normalise_hash_algorithm(
                prop[len("hashes."):].strip("'\""))
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


def flatten_taxii_object(obj, collection_title=None, stats=None):
    """One STIX indicator -> a record per value in its pattern.

    1:N like flatten_indicator(), not 1:1 like flatten_attribute().  Only
    `indicator` objects are read; a collection also carries malware, campaigns
    and relationships, which are context rather than verdicts.

    The shared keys below (everything but the last six) match
    flatten_indicator()'s output field for field -- build_indicators(),
    render_meta() and the exclusion filters all read those names regardless
    of source, and a missing one would silently blank a metadata field
    rather than raise.  TestFlattenTaxii pins the two flatteners' shared key
    sets equal so a future divergence fails loudly.

    Fields with no honest TAXII source are left empty rather than guessed:
    "org" would otherwise have to hold a raw identity *reference* (an
    unresolved "identity--..." id, not a name) -- that goes in the
    TAXII-only created_by_ref instead, where it is labelled for what it is.
    STIX 2.0 has no `confidence` property at all, and it must never be
    defaulted to 0 -- that is a real (low) confidence value in 2.1, and
    treating "absent" as "zero" would let a confidence filter silently drop
    every object from a 2.0 feed. So confidence carries through as
    obj.get(...), i.e. None when absent, never coerced.
    """
    obj = obj or {}
    if obj.get("type") != "indicator":
        return []
    pattern_type = (obj.get("pattern_type") or "stix").lower()
    if pattern_type not in OPENCTI_PARSEABLE_PATTERN_TYPES:
        if stats is not None:
            stats.unmap("pattern:%s" % pattern_type)
        return []

    # STIX 2.1 moved the indicator open-vocab to `indicator_types` and made
    # `labels` optional, so a 2.1 feed can carry an empty `labels` -- reading
    # only that would let an include-labels answer exclude everything while
    # the pre-flight summary reports the filter as applied.
    labels = []
    for label in (obj.get("labels") or []) + (obj.get("indicator_types") or []):
        if label and label not in labels:
            labels.append(label)

    common = {
        # Shared with flatten_indicator() / flatten_attribute():
        "category": pattern_type,
        "uuid": str(obj.get("id") or ""),
        "timestamp": _opencti_epoch(obj.get("modified") or obj.get("created")),
        "comment": obj.get("description") or "",
        "event_id": str(obj.get("id") or ""),
        "event_uuid": str(obj.get("id") or ""),
        "event_info": obj.get("name") or "",
        "event_tags": labels,
        "org": "",
        # TAXII-only, for Task 7's client-side filters:
        "collection": collection_title or "",
        "labels": list(labels),
        "confidence": obj.get("confidence"),
        "valid_until": obj.get("valid_until") or "",
        "created_by_ref": obj.get("created_by_ref") or "",
        "object_marking_refs": list(obj.get("object_marking_refs") or []),
    }

    records = []
    for value_type, value in parse_stix_pattern(obj.get("pattern") or ""):
        record = dict(common)
        record["type"] = value_type
        record["value"] = value
        records.append(record)
    return records


# ---------------------------------------------------------------------------
# FEEDS
# ---------------------------------------------------------------------------

# Once a feed's data is ingested it is just attributes -- restSearch has no
# feed_id.  These are the three traces a feed can leave, most precise first.
FEED_PROVENANCE_ORDER = ("fixed_event", "tag", "org")


def feed_provenance(feed):
    """How this feed's ingested attributes can be recognised, or None.

    Returns (kind, value, description).  A feed with no fixed event, no
    default tag and no dedicated org leaves nothing behind to filter on --
    its attributes are indistinguishable from the rest of MISP, so it is
    reported untraceable rather than silently matching everything.
    """
    if feed.get("fixed_event") and feed.get("event_id"):
        return ("fixed_event", str(feed["event_id"]),
                "all its data lands in event %s" % feed["event_id"])
    if feed.get("tag_name"):
        return ("tag", feed["tag_name"], "tagged %s" % feed["tag_name"])
    if feed.get("orgc_id"):
        return ("org", str(feed["orgc_id"]),
                "created as org %s" % feed["orgc_id"])
    return None


def feed_is_selectable(feed):
    return feed_provenance(feed) is not None


def apply_feed_to_params(params, feed):
    """AND a feed's provenance onto an existing restSearch body.

    Returns a new dict -- the caller runs one query per feed and merges, since
    two feeds identified by different mechanisms (one by event, one by tag)
    cannot be expressed as a single restSearch body.
    """
    provenance = feed_provenance(feed)
    if provenance is None:
        raise ValueError("feed %r is not traceable after ingest" % feed.get("name"))

    kind, value, _ = provenance
    merged = dict(params)
    if kind == "fixed_event":
        merged["eventid"] = [value]
    elif kind == "tag":
        # restSearch ORs a tag list, so the feed's tag and the operator's own
        # include-tags cannot both be *required* in one body.  The feed tag is
        # the narrower selector and goes to MISP; the operator's include-tags
        # are then applied client-side by _fetch_records().
        tags = dict(merged.get("tags") or {})
        tags["OR"] = [value]
        merged["tags"] = tags
    elif kind == "org":
        merged["org"] = [value]
    return merged


# ---------------------------------------------------------------------------
# MAPPING
# ---------------------------------------------------------------------------

def mappable_types(table=None):
    """Attribute types Nexus can turn into Zeek intel, for the given table."""
    return sorted(table if table is not None else MISP_TO_ZEEK)


def zeek_type_for(misp_type, table=None):
    """Human-readable target type(s), for the interview's annotated list."""
    spec = (table if table is not None else MISP_TO_ZEEK).get(misp_type)
    if not spec:
        return None
    seen = []
    for _, ztype in spec:
        if ztype not in seen:
            seen.append(ztype)
    return " + ".join(seen)


def map_attribute(record, split_composites="both", allow_subnet=True, table=None):
    """Record -> [(raw_indicator, zeek_type), ...] before normalisation.

    `split_composites` is "both", "first" or "second" and decides which halves
    of a composite MISP value (domain|ip, filename|md5) become indicators.
    `table` selects the source's {type: [(part_index, zeek_type)]} mapping --
    defaults to MISP_TO_ZEEK so existing callers are unaffected.
    """
    lookup = table if table is not None else MISP_TO_ZEEK
    spec = lookup.get(record.get("type"))
    if not spec:
        return []

    value = (record.get("value") or "").strip()
    if not value:
        return []

    parts = value.split("|") if "|" in record.get("type", "") else [value]

    wanted = set(idx for idx, _ in spec)
    if len(spec) > 1 and split_composites != "both":
        wanted = {0} if split_composites == "first" else {1}

    out = []
    for idx, ztype in spec:
        if idx not in wanted or idx >= len(parts):
            continue
        part = parts[idx].strip()
        if not part:
            continue
        # A CIDR value in an ip-src/ip-dst attribute is a subnet, not a host.
        if ztype == "Intel::ADDR" and "/" in part:
            if not allow_subnet:
                continue
            ztype = "Intel::SUBNET"
        out.append((part, ztype))
    return out


# ---------------------------------------------------------------------------
# NORMALISE / VALIDATE
# ---------------------------------------------------------------------------

class Rejected(Exception):
    """An indicator did not survive normalisation.  Carries a tally reason."""

    def __init__(self, reason):
        super(Rejected, self).__init__(reason)
        self.reason = reason


_CONTROL_RE = re.compile(r"[\t\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# Defanging seen in the wild.  MISP normally stores fanged values, but
# copy-paste from reports leaks these through often enough to be worth undoing.
_DEFANG = (
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
    ("[:]", ":"), ("[at]", "@"), ("(at)", "@"), ("[@]", "@"),
    ("hxxps", "https"), ("hxxp", "http"),
)


def defang_repair(value):
    """Undo common defanging.

    Only applied to network indicators -- a filename may legitimately contain
    something like "report(dot)exe" and must not be rewritten.
    """
    out = value
    for needle, replacement in _DEFANG:
        if needle in out:
            out = out.replace(needle, replacement)
        upper = needle.upper()
        if upper != needle and upper in out:
            out = out.replace(upper, replacement)
    return out


def _reject_control(value):
    """Tabs and newlines would split a record into garbage columns."""
    if _CONTROL_RE.search(value):
        raise Rejected("control_char")
    return value


def _prepare(value, defang=False):
    if value is None:
        raise Rejected("empty")
    value = value.strip()
    if defang:
        value = defang_repair(value)
    if not value:
        raise Rejected("empty")
    return _reject_control(value)


def norm_addr(value):
    value = _prepare(value, defang=True)
    if "/" in value:
        raise Rejected("cidr_in_addr")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise Rejected("invalid_ip")
    if addr.is_unspecified:
        raise Rejected("unspecified_ip")
    if addr.is_loopback:
        raise Rejected("loopback_ip")
    if addr.is_multicast:
        raise Rejected("multicast_ip")
    if addr.is_link_local:
        raise Rejected("link_local_ip")
    return str(addr)


def norm_subnet(value):
    value = _prepare(value, defang=True)
    if "/" not in value:
        raise Rejected("not_a_cidr")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise Rejected("invalid_cidr")
    if net.prefixlen == 0:
        raise Rejected("default_route")
    minimum = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    if net.prefixlen < minimum:
        raise Rejected("subnet_too_broad")
    # Mirror norm_addr: a loopback or multicast range is never a real IOC.
    if net.is_loopback:
        raise Rejected("loopback_subnet")
    if net.is_multicast:
        raise Rejected("multicast_subnet")
    if net.is_link_local:
        raise Rejected("link_local_subnet")
    return str(net)


def norm_domain(value):
    value = _prepare(value, defang=True).lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value:
        raise Rejected("empty")
    if "/" in value or " " in value:
        raise Rejected("not_a_domain")
    try:
        ipaddress.ip_address(value)
        raise Rejected("ip_as_domain")
    except ValueError:
        pass

    if any(ord(ch) > 127 for ch in value):
        try:
            value = value.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            raise Rejected("idna_failed")

    if len(value) > 253:
        raise Rejected("domain_too_long")
    labels = value.split(".")
    if len(labels) < 2:
        raise Rejected("bare_tld")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise Rejected("invalid_label")
    if labels[-1].isdigit():
        raise Rejected("numeric_tld")
    return value


def norm_url(value):
    """Strip the scheme -- Zeek matches host+uri with no protocol prefix."""
    value = _prepare(value, defang=True)
    value = _SCHEME_RE.sub("", value)
    value = value.lstrip("/")
    value = value.split("#", 1)[0]
    if not value:
        raise Rejected("empty_url")
    if " " in value:
        raise Rejected("whitespace_in_url")

    host, sep, rest = value.partition("/")
    if not host:
        raise Rejected("empty_url")
    # user:pass@host -- credentials never appear in the host header Zeek
    # matches against, so drop them rather than emit an indicator that cannot
    # possibly fire.
    authority = host.rpartition("@")[2]
    host_only = authority.split(":", 1)[0]
    try:
        norm_domain(host_only)
    except Rejected:
        try:
            norm_addr(host_only)
        except Rejected:
            raise Rejected("url_no_host")
    host = authority
    # Zeek builds the match candidate as host+uri, and a uri always starts
    # with "/".  A pathless indicator would therefore never fire.
    if not sep:
        return host.lower() + "/"
    return host.lower() + "/" + rest


def norm_hash(value):
    value = _prepare(value).lower().replace(":", "")
    if not _HEX_RE.match(value):
        raise Rejected("hash_not_hex")
    if len(value) not in VALID_HASH_LENGTHS:
        raise Rejected("hash_bad_length")
    return value


def norm_cert_hash(value):
    value = _prepare(value).lower().replace(":", "")
    if not _HEX_RE.match(value):
        raise Rejected("cert_not_hex")
    if len(value) != 40:
        raise Rejected("cert_not_sha1")
    return value


def norm_email(value):
    value = _prepare(value, defang=True).lower()
    value = value.strip("<>")
    if value.count("@") != 1:
        raise Rejected("invalid_email")
    local, _, domain = value.partition("@")
    if not local or _CONTROL_RE.search(local) or " " in local:
        raise Rejected("invalid_email")
    if any(ch in local for ch in "<>,;"):
        raise Rejected("invalid_email")
    # Rebuild from the normalised domain -- returning the raw input would
    # keep a trailing dot, a wildcard label, or mixed case.
    return local + "@" + norm_domain(domain)


def norm_filename(value, reason="filename_too_long"):
    value = _prepare(value)
    if len(value) > 255:
        raise Rejected(reason)
    return value


def norm_freeform(value):
    return norm_filename(value, reason="value_too_long")


NORMALISERS = {
    "Intel::ADDR": norm_addr,
    "Intel::SUBNET": norm_subnet,
    "Intel::DOMAIN": norm_domain,
    "Intel::URL": norm_url,
    "Intel::FILE_HASH": norm_hash,
    "Intel::CERT_HASH": norm_cert_hash,
    "Intel::EMAIL": norm_email,
    "Intel::FILE_NAME": norm_filename,
    "Intel::SOFTWARE": norm_freeform,
    "Intel::USER_NAME": norm_freeform,
}


def normalise(indicator, zeek_type):
    """Canonicalise, or raise Rejected with a tally-able reason."""
    fn = NORMALISERS.get(zeek_type)
    if fn is None:
        raise Rejected("unknown_intel_type")
    return fn(indicator)


def sanitize_meta(value, maxlen=DEFAULT_META_MAXLEN):
    """Metadata is freeform, so it is the most likely thing to hold a tab."""
    if value is None:
        return NULL_FIELD
    text = _CONTROL_RE.sub(" ", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return NULL_FIELD
    if len(text) > maxlen:
        text = text[:maxlen].rstrip()
    return text or NULL_FIELD


# ---------------------------------------------------------------------------
# FILTERS
# ---------------------------------------------------------------------------

class ExclusionSet(object):
    """Local exclusions -- keeps Nexus from arming Zeek against your own kit."""

    def __init__(self, exclude_private=True, own_networks=None, own_domains=None,
                 allowlist=None):
        self.exclude_private = exclude_private
        self.own_networks = []
        for cidr in own_networks or []:
            try:
                self.own_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("ignoring invalid exclusion network %r", cidr)
        self.own_domains = [d.strip().lower().lstrip(".")
                            for d in (own_domains or []) if d.strip()]
        # Indicators arrive normalised (lowercased), so match both forms.
        entries = set(a.strip() for a in (allowlist or []) if a.strip())
        self.allowlist = entries | set(a.lower() for a in entries)

    def _domain_excluded(self, domain):
        for own in self.own_domains:
            if domain == own or domain.endswith("." + own):
                return "own_domain"
        return None

    def reason(self, indicator, zeek_type):
        """Return an exclusion reason, or None to keep the indicator."""
        if indicator in self.allowlist or indicator.lower() in self.allowlist:
            return "allowlisted"

        # `own_network` is reported ahead of `private_ip` because it is the
        # more actionable answer when an operator's own space is also RFC1918.
        #
        # Note that Python's `is_private` is broader than RFC1918: it also
        # covers the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
        # 203.0.113.0/24, 2001:db8::/32), benchmarking, and carrier-grade NAT.
        # That is what we want -- none of those belong in threat intel -- but
        # it does mean example addresses get dropped, which surprises people.
        try:
            return self._reason(indicator, zeek_type)
        except ValueError:
            # Callers are expected to pass normalised indicators; an
            # unnormalised one is not this method's problem to reject.
            return None

    def _reason(self, indicator, zeek_type):
        if zeek_type == "Intel::ADDR":
            addr = ipaddress.ip_address(indicator)
            for net in self.own_networks:
                if addr.version == net.version and addr in net:
                    return "own_network"
            if self.exclude_private and (addr.is_private or addr.is_reserved):
                return "private_ip"

        elif zeek_type == "Intel::SUBNET":
            net = ipaddress.ip_network(indicator, strict=False)
            for own in self.own_networks:
                if net.version == own.version and net.overlaps(own):
                    return "own_network"
            if self.exclude_private and net.is_private:
                return "private_subnet"

        elif zeek_type == "Intel::DOMAIN":
            return self._domain_excluded(indicator)

        elif zeek_type == "Intel::URL":
            host = indicator.split("/", 1)[0].split(":", 1)[0]
            return self._domain_excluded(host)

        elif zeek_type == "Intel::EMAIL":
            return self._domain_excluded(indicator.partition("@")[2])

        return None


def taxii_object_allowed(record, config, now=None):
    """The filters TAXII cannot express, applied after download.

    TAXII's own query params only reach `match[type]` and `added_after` --
    labels, markings, confidence, validity and author all live inside the
    STIX object, so Nexus filters them itself once the object has already
    been fetched.  A server-side filter that silently matches nothing is a
    defect this project has fixed three times; these are honest by
    construction, but only because every one of them is actually applied.

    The one trap is confidence: STIX 2.0 indicators have no such property at
    all, so `flatten_taxii_object` carries an absent value through as None.
    None means "unknown", not zero -- a minimum-confidence filter that
    treated it as zero would silently drop every object from a 2.0 feed.
    """
    labels = set(record.get("labels") or [])
    exclude_labels = set(config.get("exclude_labels") or [])
    if exclude_labels and labels & exclude_labels:
        return False
    include_labels = set(config.get("include_labels") or [])
    if include_labels and not (labels & include_labels):
        return False

    markings = set(record.get("object_marking_refs") or [])
    include_markings = set(config.get("include_markings") or [])
    if include_markings and not (markings & include_markings):
        return False

    include_authors = config.get("include_authors") or []
    if include_authors and record.get("created_by_ref") not in include_authors:
        return False

    minimum = config.get("min_confidence")
    confidence = record.get("confidence")
    if minimum is not None and confidence is not None:
        try:
            if int(confidence) < int(minimum):
                return False
        except (TypeError, ValueError):
            pass  # an unparseable confidence is unknown, not zero

    if config.get("drop_expired") and record.get("valid_until"):
        # _opencti_epoch returns an int on success, or "" when the
        # timestamp will not parse -- coerce the success case to float
        # once, deliberately, so it compares cleanly against time.time().
        stamp = _opencti_epoch(record["valid_until"])
        if stamp != "":
            reference = time.time() if now is None else now.timestamp()
            if float(stamp) < reference:
                return False

    return True


# ---------------------------------------------------------------------------
# INTEL FILE
# ---------------------------------------------------------------------------

def header_line(do_notice=False):
    fields = list(INTEL_FIELDS)
    if do_notice:
        fields.append("meta.do_notice")
    return "#fields\t" + "\t".join(fields)


def _slug(text):
    """meta.source must survive as a single tab-free field."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "none"


def _safe_format(template, **fields):
    """Apply a user-supplied template, falling back to it literally.

    An unknown placeholder is an operator typo, not a reason to abandon a
    fetch that may have taken minutes.
    """
    try:
        return template.format(**fields)
    except (KeyError, IndexError, ValueError) as exc:
        log.warning("template %r is invalid (%s); using it literally",
                    template, exc)
        return template


def render_meta(record, source_fmt=DEFAULT_SOURCE_PREFIX, desc_template=None,
                base_url=None, maxlen=DEFAULT_META_MAXLEN, source="misp"):
    """Build (source, desc, url) for one record.

    `source` picks the URL shape: MISP links to an event, OpenCTI to the
    indicator itself (record["event_id"] carries the indicator id there).
    """
    meta_source = _safe_format(
        source_fmt,
        org=record.get("org") or "unknown",
        event_id=record.get("event_id") or "0",
        event_uuid=record.get("event_uuid") or "",
        feed=_slug(record.get("feed") or "none"),
        collection=_slug(record.get("collection") or "none"),
    ) if "{" in source_fmt else source_fmt

    if desc_template:
        desc = _safe_format(
            desc_template,
            event_info=record.get("event_info") or "",
            category=record.get("category") or "",
            tags=", ".join(record.get("event_tags") or []),
            comment=record.get("comment") or "",
            type=record.get("type") or "",
            org=record.get("org") or "",
            uuid=record.get("uuid") or "",
            feed=record.get("feed") or "",
        )
    else:
        desc = record.get("event_info") or ""

    url = ""
    if base_url and record.get("event_id"):
        if source == "opencti":
            url = "%s/dashboard/observations/indicators/%s" % (
                base_url.rstrip("/"), record["event_id"])
        elif source == "misp":
            url = "%s/events/view/%s" % (base_url.rstrip("/"), record["event_id"])
        # A TAXII object has no browsable page of its own, so no URL is
        # invented for it -- the MISP shape would send an analyst to a
        # server that has no such event.

    return (sanitize_meta(meta_source, maxlen),
            sanitize_meta(desc, maxlen),
            sanitize_meta(url, maxlen))


def render_line(indicator, zeek_type, source, desc, url, do_notice=None):
    fields = [indicator, zeek_type,
              source or NULL_FIELD, desc or NULL_FIELD, url or NULL_FIELD]
    if do_notice is not None:
        fields.append("T" if do_notice else "F")
    return "\t".join(fields)


class BuildStats(object):
    """Everything the pre-write summary needs to be honest about."""

    def __init__(self):
        self.fetched = 0
        self.emitted = 0
        self.by_type = {}
        self.rejected = {}
        self.excluded = {}
        self.unmapped = {}
        self.duplicates = 0
        self.opencti_truncated_observables = 0
        self.opencti_pattern_fallbacks = 0
        self.opencti_unparsed_patterns = 0
        self.opencti_non_stix_patterns = 0

    def _bump(self, bucket, key):
        bucket[key] = bucket.get(key, 0) + 1

    def reject(self, reason):
        self._bump(self.rejected, reason)

    def exclude(self, reason):
        self._bump(self.excluded, reason)

    def unmap(self, misp_type):
        self._bump(self.unmapped, misp_type)

    def emit(self, zeek_type):
        self._bump(self.by_type, zeek_type)
        self.emitted += 1

    def report(self):
        lines = ["fetched %d records -> %d indicators"
                 % (self.fetched, self.emitted)]
        for label, bucket in (("by type", self.by_type),
                              ("rejected", self.rejected),
                              ("excluded", self.excluded),
                              ("unmapped source types", self.unmapped)):
            if bucket:
                lines.append("  %s:" % label)
                for key in sorted(bucket, key=lambda k: -bucket[k]):
                    lines.append("    %-24s %d" % (key, bucket[key]))
        if self.duplicates:
            lines.append("  deduplicated: %d" % self.duplicates)
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
        return "\n".join(lines)


def build_indicators(records, types=None, exclusions=None, stats=None,
                     split_composites="both", allow_subnet=True,
                     source_fmt=DEFAULT_SOURCE_PREFIX, desc_template=None,
                     base_url=None, meta_maxlen=DEFAULT_META_MAXLEN,
                     do_notice=None, mapping_table=None, source="misp"):
    """Records -> deduplicated intel rows.  Pure: no I/O, no network.

    `mapping_table` selects the type mapping; defaults to the MISP table so
    existing callers are unaffected.  `source` picks the meta.url shape
    (see render_meta) and likewise defaults to "misp".

    Returns (rows, stats) where each row is
    (indicator, zeek_type, source, desc, url, do_notice).
    """
    stats = stats or BuildStats()
    lookup = mapping_table if mapping_table is not None else MISP_TO_ZEEK
    allowed = set(types) if types is not None else None
    seen = {}
    rows = []

    for record in records:
        stats.fetched += 1
        misp_type = record.get("type") or ""

        # Order matters: a type the mapping table has never heard of (an
        # unknown hash algorithm, an unexpected observable entity) is a loss
        # whether or not it was selected, and a loss gets counted.  Being
        # deselected is a choice, and that one stays silent.
        if misp_type not in lookup:
            stats.unmap(misp_type or "<empty>")
            continue
        if allowed is not None and misp_type not in allowed:
            continue

        meta = render_meta(record, source_fmt, desc_template, base_url,
                           meta_maxlen, source=source)

        for raw, zeek_type in map_attribute(record, split_composites,
                                            allow_subnet, table=lookup):
            try:
                indicator = normalise(raw, zeek_type)
            except Rejected as exc:
                stats.reject(exc.reason)
                continue

            if exclusions is not None:
                reason = exclusions.reason(indicator, zeek_type)
                if reason:
                    stats.exclude(reason)
                    continue

            key = (indicator, zeek_type)
            if key in seen:
                stats.duplicates += 1
                continue
            seen[key] = True

            rows.append((indicator, zeek_type) + meta + (do_notice,))
            stats.emit(zeek_type)

    return rows, stats


def rows_to_lines(rows, do_notice=False):
    # bool() so rows built with do_notice=None still emit a valid "F".
    return [render_line(*row[:5], do_notice=bool(row[5]) if do_notice else None)
            for row in rows]


def lint_lines(lines, do_notice=False):
    """Validate an intel.dat body.  Returns a list of human-readable problems.

    Security Onion's docs are explicit that Zeek is strict here, and a bad
    file fails at load time on the sensor rather than at write time here.
    """
    problems = []
    expected = header_line(do_notice)
    expected_cols = len(INTEL_FIELDS) + (1 if do_notice else 0)

    if not lines:
        return ["file is empty"]
    if lines[0] != expected:
        problems.append("line 1: header must be exactly %r, got %r"
                        % (expected, lines[0]))

    seen = set()
    for num, line in enumerate(lines[1:], start=2):
        if line == "":
            problems.append("line %d: blank line" % num)
            continue
        if line.startswith("#"):
            continue  # operator comment; read_existing skips these too
        if line != line.strip():
            problems.append("line %d: leading or trailing whitespace" % num)
        # A filename indicator may legitimately contain spaces, so only flag
        # whitespace touching a tab separator.
        if " \t" in line or "\t " in line:
            problems.append("line %d: space adjacent to a tab separator" % num)

        fields = line.split("\t")
        if len(fields) != expected_cols:
            problems.append("line %d: expected %d tab-separated fields, got %d"
                            % (num, expected_cols, len(fields)))
            continue
        if "" in fields:
            problems.append("line %d: empty field (use %r for null)"
                            % (num, NULL_FIELD))
        if fields[1] not in ZEEK_TYPES:
            problems.append("line %d: %r is not a valid Intel::Type"
                            % (num, fields[1]))
        if do_notice and fields[-1] not in ("T", "F"):
            problems.append("line %d: meta.do_notice must be T or F, got %r"
                            % (num, fields[-1]))

        key = (fields[0], fields[1])
        if key in seen:
            problems.append("line %d: duplicate indicator %s (%s)"
                            % (num, fields[0], fields[1]))
        seen.add(key)

    return problems


def lint_file(path, do_notice=False):
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    lines = content.split("\n")
    problems = []
    if content and not content.endswith("\n"):
        problems.append("file does not end with a newline")
    if content.endswith("\n\n"):
        problems.append("file ends with a blank line")
    while lines and lines[-1] == "":
        lines.pop()
    return problems + lint_lines(lines, do_notice)


def read_existing(path):
    """Parse an existing intel.dat into (header, rows).  Missing file -> empty."""
    if not os.path.exists(path):
        return None, []
    with open(path, "r", encoding="utf-8") as handle:
        lines = [l.rstrip("\n") for l in handle]
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None, []
    header = lines[0] if lines[0].startswith("#fields") else None
    body = lines[1:] if header else lines
    return header, [l for l in body if l.strip() and not l.startswith("#")]


def merge_preserved(existing_rows, source_prefix=DEFAULT_SOURCE_PREFIX):
    """Keep hand-maintained lines -- anything whose meta.source is not ours."""
    preserved = []
    for line in existing_rows:
        fields = line.split("\t")
        source = fields[2] if len(fields) > 2 else ""
        if not source.startswith(source_prefix):
            preserved.append(line)
    return preserved


def merge_additive(existing_rows, new_rows):
    """Preserve every existing indicator and append only genuinely new keys.

    Identity is (indicator, Intel::Type), matching indicator_delta().  The
    existing line wins when MISP returns changed metadata for the same IOC.
    """
    merged = list(existing_rows)
    seen = set(_row_key(line) for line in existing_rows if line.strip())
    for line in new_rows:
        if not line.strip() or line.startswith("#fields"):
            continue
        key = _row_key(line)
        if key not in seen:
            merged.append(line)
            seen.add(key)
    return merged


def backup_file(path, backup_dir, retention=10):
    if not os.path.exists(path):
        return None
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(backup_dir, "%s.%s" % (os.path.basename(path), stamp))
    shutil.copy2(path, dest)

    prefix = os.path.basename(path) + "."
    old = sorted(f for f in os.listdir(backup_dir) if f.startswith(prefix))
    keep = max(0, retention)  # old[:-0] is empty, which would prune nothing
    for stale in old[:len(old) - keep]:
        try:
            os.remove(os.path.join(backup_dir, stale))
        except OSError:
            pass
    return dest


def write_atomic(path, lines):
    """Write via a same-directory temp file and os.replace.

    Zeek may be reading this file at any moment; it must never observe a
    partial write.
    """
    # Operators do symlink the salt path elsewhere; os.replace would clobber
    # the link itself and silently orphan the real file.
    path = os.path.realpath(path)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)

    mode, uid, gid = 0o644, -1, -1
    if os.path.exists(path):
        st = os.stat(path)
        mode, uid, gid = st.st_mode & 0o777, st.st_uid, st.st_gid

    body = "\n".join(lines) + "\n"  # exactly one trailing newline

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".nexus-", suffix=".tmp")
    try:
        os.close(fd)  # reopened below; closing here keeps the failure path simple
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if uid != -1 and os.geteuid() == 0:
            try:
                os.chown(tmp, uid, gid)
            except OSError as exc:
                log.warning("could not preserve ownership on %s: %s", path, exc)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

    # fsync the directory so the rename itself is durable.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------------
# ENVIRONMENT CHECK
# ---------------------------------------------------------------------------

def detect_so_version():
    for path in SO_VERSION_FILES:
        try:
            with open(path, "r") as handle:
                text = handle.read()
        except (OSError, IOError):
            continue
        match = re.search(r"\b(\d+\.\d+\.\d+)\b", text)
        if match:
            return match.group(1)
        stripped = text.strip()
        if stripped:
            return stripped.splitlines()[0][:40]
    return None


def notice_policy_loaded(policy_dirs=SO_ZEEK_POLICY_DIRS):
    """Return True when an active Zeek policy loads intel/do_notice.zeek.

    Security Onion policy layouts vary across 3.x releases, so inspect the
    configured policy trees instead of assuming one point-release path.
    """
    load_re = re.compile(
        r"^\s*@load\s+(?:policy/)?frameworks/intel/do_notice(?:\.zeek)?\s*$")
    for root in policy_dirs:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith((".zeek", ".bro")):
                    continue
                path = os.path.join(dirpath, filename)
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        for line in handle:
                            if not line.lstrip().startswith("#") and load_re.match(line):
                                return True
                except (OSError, IOError, UnicodeDecodeError):
                    continue
    return False


def check_env(intel_dir=SO_INTEL_DIR, default_dir=SO_INTEL_DEFAULT_DIR,
              policy_dirs=SO_ZEEK_POLICY_DIRS):
    """Stage 0.  Returns (ok, findings) where each finding is (level, message)."""
    findings = []
    ok = True

    version = detect_so_version()
    if version:
        findings.append(("info", "Security Onion version: %s" % version))
        if not version.startswith("3."):
            findings.append(("warn", "Nexus targets Security Onion 3.2; "
                                     "verify paths before applying"))
    else:
        findings.append(("warn", "could not detect the Security Onion version "
                                 "(not running on a manager?)"))

    if not os.path.isdir(intel_dir):
        findings.append(("error", "intel directory missing: %s" % intel_dir))
        ok = False
        return ok, findings
    findings.append(("info", "intel directory: %s" % intel_dir))

    load_path = os.path.join(intel_dir, SO_LOAD_FILE)
    if os.path.exists(load_path):
        findings.append(("info", "%s present" % SO_LOAD_FILE))
    else:
        ok = False
        default_load = os.path.join(default_dir, SO_LOAD_FILE)
        msg = ("%s is MISSING from %s -- Zeek will not load intel.dat without it"
               % (SO_LOAD_FILE, intel_dir))
        findings.append(("error", msg))
        if os.path.exists(default_load):
            findings.append(("fix", "sudo cp %s/* %s/" % (default_dir, intel_dir)))
        else:
            findings.append(("warn", "defaults not found at %s either" % default_dir))

    if notice_policy_loaded(policy_dirs):
        findings.append(("info", "policy/frameworks/intel/do_notice.zeek is loaded"))
    else:
        findings.append(("warn", "policy/frameworks/intel/do_notice.zeek is not loaded; "
                                 "meta.do_notice will have no effect"))

    intel_path = os.path.join(intel_dir, "intel.dat")
    if os.path.exists(intel_path):
        st = os.stat(intel_path)
        try:
            _, rows = read_existing(intel_path)
            problems = lint_file(intel_path)
        except (OSError, UnicodeDecodeError) as exc:
            # Every build merges into this file.  Unreadable here is a hard
            # stop, not a warning: the alternative is a traceback out of
            # cmd_build once it opens the same file for itself.
            ok = False
            findings.append(("error", "existing intel.dat is unreadable: %s "
                                      "-- append-only mode cannot merge into "
                                      "it" % exc))
        else:
            findings.append(("info", "intel.dat present: %d indicators, mode %o, %d bytes"
                                     % (len(rows), st.st_mode & 0o777, st.st_size)))
            if problems:
                findings.append(("warn", "existing intel.dat has %d lint problem(s); "
                                         "run --lint for detail" % len(problems)))
    else:
        findings.append(("warn", "intel.dat does not exist yet at %s" % intel_path))

    if os.path.isdir(SO_INTEL_RUNTIME_DIR):
        findings.append(("info", "runtime intel dir: %s" % SO_INTEL_RUNTIME_DIR))
    else:
        findings.append(("warn", "runtime dir %s not found (not a sensor node?)"
                                 % SO_INTEL_RUNTIME_DIR))

    findings.append(("info", "apply command: %s" % SO_APPLY_CMD))
    return ok, findings


def check_output_target(path, do_notice=False):
    """Stage 0 for an offline build.  Returns (ok, findings).

    check_env() asks whether this machine is a working Security Onion manager.
    Off-box there is no such question to ask -- the only thing that matters is
    whether the file we are about to write can be written, and whether
    anything already sitting at that path is something we can safely merge
    with.  Same return shape as check_env() so callers print both alike.
    """
    findings = []
    directory = os.path.dirname(os.path.abspath(path)) or "."

    if not os.path.isdir(directory):
        findings.append(("error", "output directory does not exist: %s"
                                  % directory))
        findings.append(("fix", "mkdir -p %s" % directory))
        return False, findings
    if not os.access(directory, os.W_OK):
        findings.append(("error", "output directory is not writable: %s"
                                  % directory))
        return False, findings
    findings.append(("info", "output directory: %s" % directory))

    if not os.path.exists(path):
        findings.append(("info", "%s will be created" % path))
        return True, findings

    try:
        _, rows = read_existing(path)
        problems = lint_file(path, do_notice)
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(("error", "existing file is unreadable: %s" % exc))
        return False, findings
    findings.append(("info", "existing file: %d indicator(s) in %s"
                             % (len(rows), path)))
    if problems:
        findings.append(("error", "existing file has %d lint problem(s); "
                                  "refusing to merge into it" % len(problems)))
        findings.append(("fix", "run --lint %s for detail" % path))
        return False, findings
    return True, findings


# ---------------------------------------------------------------------------
# GUARDRAILS
# ---------------------------------------------------------------------------

class GuardrailVerdict(object):
    """The outcome of one guardrail check.

    A plain data holder, not an exception -- a guardrail firing is not
    automatically fatal.  "warn" is still truthy: it means "proceed, but the
    operator should see this," while only "block" flips `.ok` (and the
    object itself, in a boolean context) to false.
    """

    def __init__(self, level, message):
        self.level = level  # "ok" / "warn" / "block"
        self.message = message
        self.ok = level != "block"

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return "GuardrailVerdict(%s, %r)" % (self.level, self.message)


def check_size(count, warn_at=100000, cap=None):
    """Warn past warn_at; optionally enforce an operator-selected cap.

    Every indicator is resident in every Zeek worker's memory -- this is the
    difference between a working grid and an OOM, so the cap is a hard stop
    rather than a confirmation prompt.
    """
    if cap is not None and count > cap:
        return GuardrailVerdict(
            "block",
            "%d indicators exceeds the hard cap of %d -- every indicator is "
            "resident in every Zeek worker's memory; narrow the query or "
            "raise the cap deliberately" % (count, cap))
    if count > warn_at:
        return GuardrailVerdict(
            "warn",
            "%d indicators is past the %d warn threshold -- every indicator "
            "is resident in every Zeek worker's memory" % (count, warn_at))
    return GuardrailVerdict("ok", "%d indicators" % count)


def check_not_empty(new_count, existing_count, min_absolute=1):
    """Refuse to write an empty or near-empty file over a populated one.

    A MISP outage, a broken filter, or a bad token must not silently wipe
    out intel that took real work to build.  A no-op when there is nothing
    populated yet to protect.
    """
    if not existing_count:
        return GuardrailVerdict("ok", "no existing populated file to protect")
    if new_count < min_absolute:
        return GuardrailVerdict(
            "block",
            "new set has %d indicator(s) (below the minimum of %d) but the "
            "existing file has %d -- refusing to overwrite populated intel "
            "with an empty or near-empty one" % (new_count, min_absolute, existing_count))
    return GuardrailVerdict("ok", "%d indicators, not empty" % new_count)


def check_delta(new_count, existing_count, max_drop_pct=25.0):
    """Block a run that would drop more than max_drop_pct of the previous set.

    A broken tag filter or a MISP-side purge should surface as a
    confirmation prompt, not a quiet write.  No-op when there is no existing
    file -- there is nothing yet to compare against.
    """
    if not existing_count:
        return GuardrailVerdict("ok", "no existing file to compare against")
    drop_pct = (existing_count - new_count) * 100.0 / existing_count
    if drop_pct > max_drop_pct:
        return GuardrailVerdict(
            "block",
            "new set drops %.1f%% of the existing %d indicators (new count: "
            "%d), over the %.1f%% limit" % (drop_pct, existing_count, new_count, max_drop_pct))
    if drop_pct <= 0:
        return GuardrailVerdict(
            "ok", "new set grew from %d to %d indicators" % (existing_count, new_count))
    return GuardrailVerdict(
        "ok", "%.1f%% drop, within the %.1f%% limit" % (drop_pct, max_drop_pct))


def check_load_file(intel_dir, load_filename=SO_LOAD_FILE):
    """Block if __load__.Zeek is absent -- without it Zeek never loads intel.dat.

    Touches the filesystem, unlike the checks above, so it is kept separate
    and callers only run it once a real intel_dir is known.
    """
    path = os.path.join(intel_dir, load_filename)
    if not os.path.exists(path):
        return GuardrailVerdict(
            "block",
            "%s is missing from %s -- Zeek will not load intel.dat without "
            "it; the write would silently do nothing" % (load_filename, intel_dir))
    return GuardrailVerdict("ok", "%s present" % load_filename)


def check_broad_indicators(rows):
    """Warn on indicators broad enough to be a liability rather than a signal.

    `rows` is the (indicator, zeek_type, source, desc, url, do_notice) tuples
    from build_indicators().  Everything flagged here already fails
    normalisation on the way in (norm_subnet enforces MIN_PREFIX_V4/V6,
    norm_domain rejects bare TLDs, norm_url rejects a hostless URL) -- this
    is a second, independent look at whatever actually ended up in `rows`,
    so a future caller that builds rows some other way is still covered.
    """
    offenders = []
    for row in rows:
        indicator, zeek_type = row[0], row[1]
        if zeek_type == "Intel::SUBNET":
            try:
                net = ipaddress.ip_network(indicator, strict=False)
            except ValueError:
                continue
            minimum = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
            if net.prefixlen <= minimum:
                offenders.append(
                    "%s (subnet at or broader than /%d)" % (indicator, minimum))
        elif zeek_type == "Intel::DOMAIN":
            if "." not in indicator:
                offenders.append("%s (single-label domain)" % indicator)
        elif zeek_type == "Intel::URL":
            host = indicator.split("/", 1)[0].split(":", 1)[0]
            if "." not in host:
                offenders.append("%s (URL host has no dot)" % indicator)

    if not offenders:
        return GuardrailVerdict("ok", "no overly broad indicators")

    shown = offenders[:10]
    message = "%d overly broad indicator(s): %s" % (len(offenders), "; ".join(shown))
    if len(offenders) > 10:
        message += "; ...and %d more" % (len(offenders) - 10)
    return GuardrailVerdict("warn", message)


_LEVEL_ORDER = {"block": 0, "warn": 1, "ok": 2}


def run_guardrails(rows, existing_count, intel_dir=None, append_only=False,
                   total_count=None, **thresholds):
    """Run every guardrail, worst verdict first.

    A flat ordered list rather than a dict -- the pre-write confirmation
    prompt wants to lead with whatever is most likely to make an operator
    stop and look.  `check_load_file` is skipped when intel_dir is None
    (e.g. a --dry-run against a scratch path with no real SO layout).

    `total_count` is the post-merge indicator count.  Append-only callers
    pass it because len(rows) + existing_count double-counts every key that
    is in both sets -- which, on a re-import of a refreshed build, is nearly
    all of them.
    """
    if total_count is None:
        total_count = (len(rows) + (existing_count or 0) if append_only
                       else len(rows))
    new_count = total_count
    verdicts = [check_size(new_count, thresholds.get("warn_at", 100000),
                           thresholds.get("cap")),
                check_broad_indicators(rows)]
    if not append_only:
        verdicts.extend([
            check_not_empty(new_count, existing_count,
                            thresholds.get("min_absolute", 1)),
            check_delta(new_count, existing_count,
                        thresholds.get("max_drop_pct", 25.0)),
        ])
    if intel_dir is not None:
        verdicts.append(check_load_file(
            intel_dir, thresholds.get("load_filename", SO_LOAD_FILE)))
    verdicts.sort(key=lambda v: _LEVEL_ORDER[v.level])
    return verdicts


# ---------------------------------------------------------------------------
# INTERVIEW
# ---------------------------------------------------------------------------

# Display order for stage 3.  IOC_CLASSES is keyed for lookup, not for reading
# aloud, and sorted() would put "email" before "network".
IOC_CLASS_ORDER = ("network", "file", "email", "tls", "host")

# Pre-suggested exclusions for stage 5.  These two tags account for most of the
# noise in a typical MISP: known false positives and bulk OSINT imports.
SUGGESTED_EXCLUDE_TAGS = ("false-positive", "type:OSINT")

THREAT_LEVELS = (("any", None), ("high", 1), ("medium", 2), ("low", 3),
                 ("undefined", 4))
ANALYSIS_STATES = (("any", None), ("initial", 0), ("ongoing", 1),
                   ("completed", 2))

SOURCE_FORMATS = (
    ("MISP-event-{event_id}", "MISP-event-42"),
    ("MISP-{org}", "MISP-CIRCL"),
    ("MISP", "MISP"),
    ("fixed string", "type your own"),
)

# meta.source ends up in intel.dat, so it has to name the platform the row
# actually came from -- an analyst chasing an intel.log hit reads it as a
# lookup key, and "MISP-event-6c1f0a2e-..." sends them to a MISP that has no
# such event.  {event_id} is OpenCTI's internal id, the same one meta.url
# links to, not the standard_id.
OPENCTI_SOURCE_FORMATS = (
    ("OpenCTI-{event_id}", "OpenCTI-6c1f0a2e-2b7d-4a55-..."),
    ("OpenCTI-{org}", "OpenCTI-CIRCL"),
    ("OpenCTI", "OpenCTI"),
    ("fixed string", "type your own"),
)

# TAXII's own identity for an object is the collection it came from; the
# STIX id is the only other thing on the wire worth naming, and there is no
# organisation -- created_by_ref is an unresolved identity reference, not a
# name, so it is not offered here.
TAXII_SOURCE_FORMATS = (
    ("TAXII-{collection}", "TAXII-Feed-One"),
    ("TAXII-{event_id}", "TAXII-indicator--6c1f0a2e-..."),
    ("TAXII", "TAXII"),
    ("fixed string", "type your own"),
)

DEFAULT_DESC_TEMPLATE = "{event_info} | {category}"
DEFAULT_DAYS = 90
DEFAULT_MAX_INDICATORS = None
PROFILE_DIR = os.path.join(NEXUS_HOME, "profiles")

NONE_WORDS = frozenset(("", "none", "-", "no", "any", "all time"))


class InterviewAborted(Exception):
    """Ctrl-C or EOF at a prompt.  Callers unwind and exit without a traceback."""


# -- prompt primitives ------------------------------------------------------

def _read(prompt, input_fn):
    """Single funnel for stdin so abort handling lives in exactly one place."""
    try:
        return input_fn(prompt)
    except (EOFError, KeyboardInterrupt):
        raise InterviewAborted("interview aborted at: %s" % prompt.strip())


def _opt_parts(option):
    """An option is either a bare value or (value, annotation)."""
    if isinstance(option, (tuple, list)) and len(option) == 2:
        return str(option[0]), str(option[1])
    return str(option), ""


def _opt_values(options):
    return [_opt_parts(o)[0] for o in options]


def ask(prompt, default=None, input_fn=input):
    text = "%s [%s]: " % (prompt, default) if default is not None else "%s: " % prompt
    answer = _read(text, input_fn).strip()
    if not answer:
        return default if default is not None else ""
    return answer


def ask_required(prompt, default=None, input_fn=input):
    """`ask` that will not take silence for an answer."""
    while True:
        answer = ask(prompt, default, input_fn)
        if answer:
            return answer
        print("  a value is required")


def ask_yes_no(prompt, default=True, input_fn=input):
    hint = "Y/n" if default else "y/N"
    while True:
        answer = _read("%s [%s]: " % (prompt, hint), input_fn).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  please answer y or n")


def ask_int(prompt, default, minimum=None, maximum=None, input_fn=input):
    while True:
        answer = _read("%s [%s]: " % (prompt, default), input_fn).strip()
        if not answer and default is not None:
            return default
        try:
            value = int(answer)
        except ValueError:
            print("  not a whole number: %r" % answer)
            continue
        if minimum is not None and value < minimum:
            print("  must be at least %d" % minimum)
            continue
        if maximum is not None and value > maximum:
            print("  must be at most %d" % maximum)
            continue
        return value


def ask_choice(prompt, options, default=None, input_fn=input):
    """Numbered single-select.  Returns the chosen option's value."""
    values = _opt_values(options)
    default_index = values.index(default) + 1 if default in values else None

    while True:
        print(prompt)
        for number, option in enumerate(options, 1):
            value, note = _opt_parts(option)
            print("   %2d) %-30s %s" % (number, value, note))
        suffix = " [%d]" % default_index if default_index else ""
        # The title is repeated on the read line so a scripted or piped
        # session can tell two consecutive choices apart.
        answer = _read("  %s -- choose 1-%d%s: "
                       % (prompt, len(options), suffix), input_fn).strip()
        if not answer:
            if default_index:
                return values[default_index - 1]
            print("  no default -- pick a number")
            continue
        if answer.isdigit() and 1 <= int(answer) <= len(values):
            return values[int(answer) - 1]
        print("  not a valid choice: %r" % answer)


def resolve_build_target(args, input_fn=input, intel_dir=SO_INTEL_DIR):
    """True for an offline build, False for a build on this manager.

    Asked before check_env(), because check_env() is what refuses to run on a
    host with no Security Onion.  The presented default is derived, but the
    question is always asked when the flag is absent -- flags skip questions
    for unattended replay, they do not change what a flagless run means.

    A missing Security Onion means "not a manager".  A *broken* Security Onion
    is a different thing and stays a hard error in check_env(); offline mode
    must never become a way to paper over a damaged manager.
    """
    if getattr(args, "offline", False):
        return True
    on_manager = detect_so_version() is not None or os.path.isdir(intel_dir)
    default = "manager" if on_manager else "offline"
    choice = ask_choice(
        "Where is this intel.dat going?",
        [("manager", "this machine's Security Onion"),
         ("offline", "another host -- write it here and transfer it")],
        default, input_fn)
    return choice == "offline"


def parse_selection(answer, count):
    """Parse "1,3,5" / "1-4" / "2-3,7" to zero-based indexes; None if invalid."""
    picked = []
    for token in answer.replace(" ", "").split(","):
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            if not start.isdigit() or not end.isdigit():
                return None
            span = range(int(start), int(end) + 1)
            if int(start) > int(end):
                return None
        elif token.isdigit():
            span = [int(token)]
        else:
            return None
        for number in span:
            if number < 1 or number > count:
                return None
            if number - 1 not in picked:
                picked.append(number - 1)
    return picked


def ask_multi(prompt, options, preselected=None, input_fn=input):
    """Numbered multi-select.  Enter keeps the preselected set.

    Accepts "1,3,5", "1-4", a mix of both, "all" and "none".  Returns values in
    option order, not in the order they were typed, so downstream output is
    stable regardless of how the operator typed the selection.
    """
    values = _opt_values(options)
    chosen = [v for v in values if v in set(preselected or ())]

    while True:
        print(prompt)
        for number, option in enumerate(options, 1):
            value, note = _opt_parts(option)
            mark = "x" if value in chosen else " "
            print("   %2d) [%s] %-24s %s" % (number, mark, value, note))
        answer = _read("  %s -- select (numbers, ranges, all, none) [%s]: "
                       % (prompt, ",".join(chosen) if chosen else "none"),
                       input_fn).strip().lower()

        if not answer:
            return list(chosen)
        if answer == "all":
            return list(values)
        if answer == "none":
            return []
        picked = parse_selection(answer, len(values))
        if picked is None:
            print("  could not read that selection: %r" % answer)
            continue
        return [values[i] for i in sorted(picked)]


def ask_list(prompt, default="none", validator=None, input_fn=input):
    """Comma-separated free text.  `validator` returns an error string or None."""
    while True:
        answer = ask(prompt, default, input_fn)
        if answer.strip().lower() in NONE_WORDS:
            return []
        items = [part.strip() for part in answer.split(",") if part.strip()]
        errors = [validator(item) for item in items] if validator else []
        errors = [e for e in errors if e]
        if errors:
            for error in errors:
                print("  " + error)
            continue
        return items


def ask_date(prompt, default=None, input_fn=input):
    """ISO date, or a MISP relative window like 30d.  Empty means unset."""
    while True:
        answer = ask(prompt, default, input_fn)
        if not answer or answer.lower() in NONE_WORDS:
            return ""
        if answer[:-1].isdigit() and answer[-1] in "dhm":
            return answer
        try:
            datetime.strptime(answer, "%Y-%m-%d")
            return answer
        except ValueError:
            print("  expected YYYY-MM-DD or a window like 30d")


def ask_token(prompt="MISP API token", getpass_fn=getpass.getpass):
    """Read the token without echo.  Never returned to any log or summary."""
    while True:
        try:
            token = getpass_fn("%s: " % prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise InterviewAborted("interview aborted at the token prompt")
        if token:
            return token
        print("  the token cannot be empty")


def _valid_cidr(text):
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return "not a network: %r" % text
    return None


def _valid_path(text):
    return None if os.path.exists(text) else "no such file: %s" % text


def _stage(number, title):
    print("")
    print("-- Stage %d: %s" % (number, title))


def _count_label(misp_type, counts):
    count, exact = counts.get(misp_type, (None, True))
    if count is None:
        return "?"
    return format(count, ",d") + ("" if exact else "+")


def _type_annotation(misp_type, counts, table=None, off_by_default=None,
                     source="misp"):
    """`table` and `off_by_default` default to the MISP pair so the one
    existing call site (pre-OpenCTI) is unaffected; _stage3_iocs passes the
    OpenCTI pair on that path so the Zeek-type column isn't just "None".

    On the OpenCTI path the type shown is a main_observable_type, which has no
    OPENCTI_TO_ZEEK entry of its own -- a StixFile is several Zeek types at
    once -- so the expansion table answers instead of zeek_type_for().
    """
    noisy_set = MISP_OFF_BY_DEFAULT if off_by_default is None else off_by_default
    if source == "opencti":
        zeek = " + ".join(opencti_zeek_types(misp_type)) or "None"
    else:
        zeek = zeek_type_for(misp_type, table)
    return "%9s  -> %s%s" % (
        _count_label(misp_type, counts), zeek,
        "   (noisy)" if misp_type in noisy_set else "")


# -- stage 2: discovery -----------------------------------------------------

def discover(client, probe_limit=5000):
    """Stage 2.  The live lists stages 3 and 5 select from.

    Counts are deliberately unfiltered: the quality filters are not chosen
    until stage 4, so these are ceilings, not predictions.
    """
    found = {"version": {}, "types": [], "counts": {}, "tags": [], "orgs": [],
             "sharing_groups": [], "feeds": []}
    if client is None:
        return found

    for label, key, call in (
            ("version", "version", client.get_version),
            ("tags", "tags", client.get_tags),
            ("organisations", "orgs", client.get_orgs),
            ("sharing groups", "sharing_groups", client.get_sharing_groups),
            ("feeds", "feeds", client.get_feeds)):
        try:
            found[key] = call()
        except SourceError as exc:
            log.warning("could not fetch %s: %s", label, exc)

    try:
        found["types"] = client.describe_types().get("types") or []
    except SourceError as exc:
        log.warning("could not fetch attribute types: %s", exc)

    known = set(found["types"])
    for misp_type in mappable_types():
        if known and misp_type not in known:
            continue
        try:
            found["counts"][misp_type] = client.count_type(
                misp_type, probe_limit=probe_limit)
        except SourceError as exc:
            log.warning("count for %s failed: %s", misp_type, exc)

    found["tags"] = [t.get("name") for t in found["tags"] if t.get("name")]
    found["orgs"] = [o.get("name") for o in found["orgs"] if o.get("name")]
    found["sharing_groups"] = [s.get("name") for s in found["sharing_groups"]
                               if s.get("name")]
    return found


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


# -- stages -----------------------------------------------------------------

def _stage1_connection(config, client, input_fn, getpass_fn, source=None,
                       host=None):
    """Stage 1.  Collects connection answers only -- main() builds the client."""
    _stage(1, "Connection")

    # No silent default: a flagless run asks which platform it is pointed at.
    # A caller that already knows (later, --source) skips the question.
    if source is None:
        source = ask_choice("Threat intel platform", list(SOURCES),
                            "misp", input_fn)
    config["source"] = source
    label = SOURCE_LABELS.get(source, source)

    # --host seeds the default; it does not skip the question.  It is also
    # returned verbatim, and urllib chokes on "cti.local " long before it
    # opens a socket, hence the strip.
    config["source_host"] = ask_required(
        "%s address (IP or hostname)" % label,
        host or (client.host if client is not None else None), input_fn).strip()
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

    verify_default = client.verify_tls if client is not None else True
    verify = ask_yes_no("Verify the TLS certificate?", verify_default, input_fn)
    if not verify:
        print("  WARNING: disabling verification exposes this session to a "
              "man-in-the-middle.")
        typed = ask("  type INSECURE to confirm, anything else keeps "
                    "verification on", "", input_fn)
        verify = typed.strip() != "INSECURE"
        if verify:
            print("  keeping certificate verification enabled")
    config["verify_tls"] = verify

    proxy = ask("HTTP proxy URL", "none", input_fn)
    config["proxy"] = None if proxy.strip().lower() in NONE_WORDS else proxy

    if source == "taxii":
        # TAXII carries its own protocol version and can authenticate two
        # ways, so secret collection branches instead of the single token
        # below.  The version question is always asked -- the standing
        # no-implicit-default rule -- a reachable client only supplies the
        # default via detect_version().
        default_version = TAXII_VERSIONS[0]
        if client is not None:
            try:
                default_version = client.detect_version()
            except SourceError as exc:
                log.warning("could not detect the TAXII version: %s", exc)
        config["taxii_version"] = ask_choice(
            "TAXII version", list(TAXII_VERSIONS), default_version, input_fn)

        auth_default = ("basic" if client is not None and client.username
                        else "bearer")
        config["taxii_auth"] = ask_choice(
            "Authentication",
            [("bearer", "Bearer token"),
             ("basic", "Basic (username + password)")],
            auth_default, input_fn)

        if config["taxii_auth"] == "basic":
            # A Basic username is not secret to *type* -- it goes out in the
            # clear on every request -- but it is secret to *store*: paired
            # with the password it is half a credential, so ask_required
            # (echoed) collects it while getpass_fn (silent) collects the
            # password.  Both are excluded from saved profiles regardless.
            config["taxii_username"] = (
                client.username if client is not None
                else ask_required("Username", None, input_fn))
            config["token"] = (client.token if client is not None
                               else ask_token("%s password" % label,
                                              getpass_fn=getpass_fn))
        else:
            config["taxii_username"] = None
            config["token"] = (client.token if client is not None
                               else ask_token("%s API token" % label,
                                              getpass_fn=getpass_fn))
    else:
        # An existing client already holds a working token; re-prompting for
        # it would only be a chance to fat-finger it.
        config["token"] = (client.token if client is not None
                           else ask_token("%s API token" % label,
                                          getpass_fn=getpass_fn))

    config["timeout"] = ask_int(
        "Request timeout (seconds)",
        client.timeout if client is not None else 30, 1, 3600, input_fn)
    config["retries"] = ask_int(
        "Retries on transient failure",
        client.retries if client is not None else 3, 1, 10, input_fn)
    return config


def _stage_feeds(config, discovery, input_fn, source="misp"):
    """Stage 2b: which MISP feeds to pull from.

    Runs after discovery so the list is live, and before the IOC types so the
    operator narrows by source first and by type second.
    """
    config["feeds"] = []
    if source == "opencti":
        # OpenCTI has no post-ingest feed trace worth a selectable/blocked
        # split -- its provenance filtering is author and label, in stage 5.
        # Skipping silently would look like a bug to an operator who knows
        # the MISP flow and sees stage 2b vanish.
        print("")
        print("-- Stage 2b: feeds")
        print("  Not applicable to OpenCTI; provenance is filtered by author "
              "and label in stage 5.")
        return

    feeds = discovery.get("feeds") or []
    if not feeds:
        return

    print("")
    print("-- Stage 2b: MISP feeds")

    selectable, blocked = [], []
    for feed in feeds:
        (selectable if feed_is_selectable(feed) else blocked).append(feed)

    if not ask_yes_no("Restrict to specific feeds? (no = all of MISP)",
                      False, input_fn):
        return

    if not selectable:
        print("  No feed can be traced after ingest; pulling from all of MISP.")
    else:
        options = []
        for feed in selectable:
            _, _, why = feed_provenance(feed)
            state = "enabled" if feed["enabled"] else "disabled"
            options.append((
                feed["id"],
                feed["name"],
                "%s, %s, %s" % (feed["provider"] or "no provider", state, why),
            ))
        chosen = ask_multi("Feeds to pull from", options, [], input_fn)
        by_id = dict((f["id"], f) for f in selectable)
        config["feeds"] = [by_id[fid] for fid in chosen if fid in by_id]

    if blocked:
        print("")
        print("  Not selectable -- no fixed event, default tag or dedicated")
        print("  org, so their attributes cannot be told apart after ingest:")
        for feed in blocked:
            print("    %-32s %s" % (feed["name"][:32],
                                    feed["provider"] or ""))

    if config["feeds"]:
        # meta.source carries the feed so an intel.log hit names its origin.
        config["source_fmt"] = "MISP-feed-{feed}"


def _stage3_iocs(config, discovery, input_fn, source="misp"):
    _stage(3, "What IOCs do you want?")
    counts = discovery.get("counts") or {}
    known = set(discovery.get("types") or ())

    if source == "opencti":
        classes = OPENCTI_IOC_CLASSES
        order = [k for k in OPENCTI_IOC_CLASS_ORDER if k in OPENCTI_IOC_CLASSES]
        off_by_default = OPENCTI_OFF_BY_DEFAULT
        table = OPENCTI_TO_ZEEK
    else:
        classes = IOC_CLASSES
        order = [k for k in IOC_CLASS_ORDER if k in IOC_CLASSES]
        off_by_default = MISP_OFF_BY_DEFAULT
        table = None  # None -> zeek_type_for's own MISP_TO_ZEEK default

    class_options = [(k, classes[k][0]) for k in order]
    config["ioc_classes"] = ask_multi("IOC classes", class_options,
                                      preselected=order, input_fn=input_fn)

    selected = []
    for key in order:
        if key not in config["ioc_classes"]:
            continue
        label, types = classes[key]
        # An empty `known` means discovery was skipped, not that the source is empty.
        candidates = [t for t in types if not known or t in known]
        if not candidates:
            print("  no %s attribute types exist on this instance" % key)
            continue
        options = [(t, _type_annotation(t, counts, table, off_by_default,
                                        source))
                   for t in candidates]
        preselected = [t for t in candidates
                       if t not in off_by_default
                       and counts.get(t, (1, True))[0] != 0]
        selected.extend(ask_multi(label, options, preselected, input_fn))

    if source == "opencti":
        # No OPENCTI_TO_ZEEK entry has more than one spec, so a first/second
        # split answer would have nothing to act on -- don't ask.
        config["split_composites"] = "both"
    else:
        config["split_composites"] = ask_choice(
            "Composite types (domain|ip, filename|md5): emit which half?",
            [("both", "domain + ip"), ("first", "domain only"),
             ("second", "ip only")], "both", input_fn)
    config["hostname_as_domain"] = ask_yes_no(
        "Treat hostname as Intel::DOMAIN?", True, input_fn)
    if not config["hostname_as_domain"]:
        # OpenCTI's type literal is "Hostname" (capital H); MISP's is
        # lowercase "hostname"/"hostname|port".
        hostname_prefix = "Hostname" if source == "opencti" else "hostname"
        selected = [t for t in selected if not t.startswith(hostname_prefix)]
    config["allow_subnet"] = ask_yes_no(
        "Emit Intel::SUBNET for CIDR values in IP attributes?", True, input_fn)

    config["types"] = selected
    return config


def _stage3_collections_taxii(config, discovery, input_fn):
    """Stage 3 for TAXII: which collections to pull from.

    Stands in for `_stage3_iocs` -- `match[type]=indicator` already narrows
    every collection to indicators on the wire, so there is no local type
    menu to offer; the only server-reachable choice left at this point is
    which collection(s) to query.  Reuses ask_multi the way every *working*
    caller in this file does it -- (value, single annotation) pairs -- and
    then maps the chosen ids back to the full collection dicts, the same
    two-step `_stage_feeds` uses.  `_stage_feeds` itself builds 3-tuple
    options; `_opt_parts` only unpacks a 2-tuple, so a 3-tuple's value comes
    back as the tuple's own repr and the id lookup below can never match --
    that is a pre-existing, pre-dates-this-branch bug in `_stage_feeds`
    (confirmed no test exercises its selection path), not a pattern worth
    reproducing here.
    """
    _stage(3, "Collections")
    # TAXII values come out of parse_stix_pattern against OPENCTI_TO_ZEEK, the
    # same table OpenCTI uses, so the two shaping answers _stage3_iocs asks
    # there apply here too and cmd_build reads all three off the config.  No
    # OPENCTI_TO_ZEEK entry carries a second spec, so there is no composite
    # half to choose -- same reason the OpenCTI path does not ask either.
    config["split_composites"] = "both"
    config["hostname_as_domain"] = True
    config["allow_subnet"] = True
    config["types"] = None
    collections = discovery.get("collections") or []
    if not collections:
        print("  no collections were discovered; check TAXII discovery and "
              "API-root access")
        config["collections"] = []
        return config

    options = [(c["id"], "%s (%s)" % (c["title"], c.get("api_root") or "?"))
              for c in collections]
    chosen = ask_multi("Collections to pull from", options,
                       [c["id"] for c in collections], input_fn)
    by_id = dict((c["id"], c) for c in collections)
    config["collections"] = [by_id[cid] for cid in chosen if cid in by_id]

    config["hostname_as_domain"] = ask_yes_no(
        "Treat hostname as Intel::DOMAIN?", True, input_fn)
    if not config["hostname_as_domain"]:
        # There is no type menu on this path, so "no" has to become an
        # explicit allow-list of everything else -- otherwise the answer
        # would be collected and then do nothing.
        config["types"] = [t for t in OPENCTI_TO_ZEEK if t != "Hostname"]
    config["allow_subnet"] = ask_yes_no(
        "Emit Intel::SUBNET for CIDR values in IP attributes?", True, input_fn)
    return config


def _stage4_quality(config, input_fn):
    _stage(4, "Quality filters")
    config["to_ids"] = ask_yes_no(
        "to_ids-flagged attributes only?", True, input_fn)
    config["published"] = ask_yes_no("Published events only?", True, input_fn)
    config["enforce_warninglist"] = ask_yes_no(
        "Enforce MISP warninglists (strip known-good)?", True, input_fn)
    config["exclude_deleted"] = ask_yes_no(
        "Exclude deleted attributes?", True, input_fn)

    levels = dict(THREAT_LEVELS)
    config["threat_level"] = levels[ask_choice(
        "Minimum event threat level", [name for name, _ in THREAT_LEVELS],
        "any", input_fn)]
    states = dict(ANALYSIS_STATES)
    config["analysis"] = states[ask_choice(
        "Event analysis state", [name for name, _ in ANALYSIS_STATES],
        "any", input_fn)]
    return config


def _ask_names(prompt, live, preselected=None, input_fn=input):
    """Multi-select off a live list, or free text when discovery found none."""
    if not live:
        return ask_list("%s (comma-separated, none = all)" % prompt,
                        ",".join(preselected or ()) or "none",
                        input_fn=input_fn)
    return ask_multi(prompt, list(live), preselected, input_fn)


def _stage5_scope(config, discovery, input_fn):
    _stage(5, "Scope")
    config["time_mode"] = ask_choice(
        "Time window", [("last", "last N days"), ("range", "explicit from/to"),
                        ("all", "everything")], "last", input_fn)
    config["days"] = None
    config["date_from"] = ""
    config["date_to"] = ""
    if config["time_mode"] == "last":
        config["days"] = ask_int("How many days back", DEFAULT_DAYS, 1,
                                 None, input_fn)
    elif config["time_mode"] == "range":
        config["date_from"] = ask_date("From (YYYY-MM-DD)", "", input_fn)
        config["date_to"] = ask_date("To (YYYY-MM-DD)", "", input_fn)

    config["timestamp_field"] = ask_choice(
        "Which timestamp does that window mean?",
        [("timestamp", "attribute last-edited"),
         ("publish_timestamp", "event published")], "timestamp", input_fn)

    tags = discovery.get("tags") or []
    config["include_tags"] = _ask_names("Include tags (OR, none = all)", tags,
                                        None, input_fn)
    exclude_options = list(tags)
    for name in SUGGESTED_EXCLUDE_TAGS:
        if name not in exclude_options:
            exclude_options.append(name)
    config["exclude_tags"] = _ask_names(
        "Exclude tags (NOT)", exclude_options if tags else [],
        list(SUGGESTED_EXCLUDE_TAGS), input_fn)

    config["orgs"] = _ask_names("Restrict to organisations",
                                discovery.get("orgs") or [], None, input_fn)
    config["sharing_groups"] = _ask_names(
        "Restrict to sharing groups", discovery.get("sharing_groups") or [],
        None, input_fn)
    config["event_ids"] = ask_list("Restrict to event IDs or UUIDs",
                                   "none", None, input_fn)
    return config


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


def _stage5_scope_taxii(config, discovery, input_fn):
    """Stage 5 for TAXII: the one filter the server can act on (time, as
    added_after) and the six it cannot.

    TAXII's query syntax only reaches `match[type]` (fixed to `indicator`,
    stage 3 picks the collection instead) and `added_after`.  Labels,
    markings, confidence, validity and author all live inside the STIX
    object, so every one of them is filtered locally, after the object has
    already been downloaded.  Telling the operator otherwise would make them
    believe a filter is cutting transfer volume when it is doing nothing of
    the kind -- so every question below the time window says plainly that it
    is applied after download.
    """
    _stage(5, "Scope")
    print("  Days back is the one answer in this stage TAXII narrows itself "
          "(sent as added_after).  Every other answer here is applied AFTER "
          "DOWNLOAD -- it thins what Nexus keeps, not what it fetches.")

    config["days"] = ask_int(
        "Days back, sent to the server as added_after (0 = no time filter)",
        DEFAULT_DAYS, 0, None, input_fn)

    if config.get("taxii_version") == "2.0":
        print("  This is a TAXII 2.0 feed: STIX 2.0 indicators carry no "
              "confidence property at all, so the minimum-confidence answer "
              "below will not exclude anything on this feed.")

    config["include_labels"] = ask_list(
        "Include labels, applied after download (none = all)", "none",
        input_fn=input_fn)
    config["exclude_labels"] = ask_list(
        "Exclude labels, applied after download (none = none)", "none",
        input_fn=input_fn)
    config["include_markings"] = ask_list(
        "Include marking-definition refs, applied after download "
        "(none = all)", "none", input_fn=input_fn)
    config["include_authors"] = ask_list(
        "Include created_by_ref authors, applied after download "
        "(none = all)", "none", input_fn=input_fn)
    config["min_confidence"] = ask_int(
        "Minimum confidence, applied after download (0 = no filter)",
        0, 0, 100, input_fn)
    config["drop_expired"] = ask_yes_no(
        "Drop indicators past valid_until? (checked after download)",
        True, input_fn)
    return config


def _stage6_exclusions(config, input_fn):
    _stage(6, "Local exclusions")
    config["exclude_private"] = ask_yes_no(
        "Exclude RFC1918 / loopback / link-local / multicast?", True, input_fn)
    config["own_networks"] = ask_list("Your own networks (CIDR list)", "none",
                                      _valid_cidr, input_fn)
    config["own_domains"] = ask_list("Your own domain suffixes", "none",
                                     None, input_fn)
    paths = ask_list("Extra allowlist file to subtract", "none", _valid_path,
                     input_fn)
    config["allowlist_file"] = paths[0] if paths else None
    return config


def _stage7_metadata(config, input_fn, offline=False):
    _stage(7, "Metadata")
    source = config.get("source") or "misp"
    formats = {"opencti": OPENCTI_SOURCE_FORMATS,
               "taxii": TAXII_SOURCE_FORMATS}.get(source, SOURCE_FORMATS)
    platform = SOURCE_LABELS.get(source, "MISP")
    choice = ask_choice("meta.source format", list(formats),
                        formats[0][0], input_fn)
    if choice == "fixed string":
        choice = ask_required("Fixed meta.source value", platform, input_fn)
    config["source_fmt"] = choice

    config["desc_template"] = ask(
        "meta.desc template ({event_info} {category} {tags} {comment} "
        "{type} {org} {uuid})", DEFAULT_DESC_TEMPLATE, input_fn)

    link_target = {"opencti": "OpenCTI indicator",
                   "taxii": None}.get(source, "MISP event")
    if link_target is None:
        # Nothing to ask: a TAXII object has no page to link to, and saying
        # so beats a question whose only honest answer is "no".
        print("  meta.url is left empty: a TAXII object has no browsable URL.")
        config["source_base_url"] = None
    elif ask_yes_no("Link meta.url back to the %s?" % link_target, True,
                    input_fn):
        netloc = config.get("source_host") or ""
        port = config.get("port")
        if port and port not in (80, 443):
            netloc = "%s:%d" % (netloc, port)
        config["source_base_url"] = "%s://%s" % (config.get("scheme", "https"),
                                                  netloc)
    else:
        config["source_base_url"] = None

    config["do_notice"] = ask_yes_no(
        "Emit the meta.do_notice column?", False, input_fn)
    # Offline, the local policy tree says nothing about the manager this
    # file is going to, so neither message would be true of it.
    if config["do_notice"] and not offline:
        if notice_policy_loaded():
            print("  detected: policy/frameworks/intel/do_notice.zeek is loaded")
        else:
            print("  WARNING: policy/frameworks/intel/do_notice.zeek was not "
                  "detected; meta.do_notice will have no effect.")
    config["meta_maxlen"] = ask_int("Max metadata field length", 200, 20,
                                    4096, input_fn)
    return config


def _stage8_output(config, input_fn, offline=False):
    _stage(8, "Output and apply")
    config["offline"] = bool(offline)
    if offline:
        # Neither question means anything off-box: there is no grid to pick a
        # topology for, and nothing to apply to.
        config["deployment"] = "offline"
        config["output_path"] = ask_required("Output path", "./intel.dat",
                                             input_fn)
    else:
        config["deployment"] = ask_choice(
            "Security Onion deployment",
            [("distributed", "manager plus sensor grid"),
             ("standalone", "one standalone node")],
            "distributed", input_fn)
        config["output_path"] = ask_required("Output path", SO_INTEL_FILE,
                                             input_fn)
    config["merge_mode"] = "append-only"
    config["backup"] = ask_yes_no("Back up the existing file first?", True,
                                  input_fn)
    cap = ask("Optional hard cap on indicator count (none = unlimited)",
              "none", input_fn).strip().lower()
    while cap not in NONE_WORDS and (not cap.isdigit() or int(cap) < 1):
        print("  enter a positive integer or none")
        cap = ask("Optional hard cap on indicator count (none = unlimited)",
                  "none", input_fn).strip().lower()
    config["max_indicators"] = None if cap in NONE_WORDS else int(cap)
    config["dry_run"] = ask_yes_no(
        "Dry run (write to a temp file and show a diff)?", False, input_fn)

    config["profile_path"] = None
    if ask_yes_no("Save these answers as a profile?", True, input_fn):
        name = ask_required("Profile name", "nexus", input_fn)
        if not name.endswith(".json"):
            name += ".json"
        # Off-box there is no writable /opt/nexus, and the output directory is
        # the one place check_output_target proves we can write -- same reason
        # the offline backups live there.
        directory = (os.path.dirname(os.path.abspath(config["output_path"]))
                     if offline else PROFILE_DIR)
        config["profile_path"] = os.path.join(directory, name)

    if offline:
        config["apply"] = False
    else:
        target = ("standalone node" if config["deployment"] == "standalone"
                  else "grid")
        config["apply"] = ask_yes_no(
            "Apply to the %s after writing?" % target, False, input_fn)
    return config


def run_interview(client, input_fn=input, getpass_fn=getpass.getpass,
                  source=None, host=None, connect=None, offline=False):
    """Walk stages 1-8 and return a plain dict config.

    `client` may be None, which skips discovery so the interview is runnable
    (and testable) with no MISP in reach.

    `connect` closes the chicken-and-egg: stage 1 is what collects the
    credentials, but stages 3 and 5 need a live client for their type, tag and
    label lists -- and OpenCTI's scope filters are entity ids, which only a
    connection can resolve a typed name to.  Callers that want a live
    interview pass make_client here; callers that must stay offline pass
    nothing.
    """
    config = {}
    _stage1_connection(config, client, input_fn, getpass_fn, source=source,
                       host=host)

    _stage(2, "Discovery")
    if client is None and connect is not None:
        try:
            candidate = connect(config)
            # Fail fast on one call: discovery is dozens of requests, and on
            # an unreachable host every one of them would retry and time out.
            candidate.get_version()
            client = candidate
        except SourceError as exc:
            print("  could not connect: %s" % REDACTOR.scrub(str(exc)))
            print("  continuing offline -- name-based filters cannot be "
                  "resolved and will not be applied")
    if config["source"] == "opencti":
        discovery = discover_opencti(client)
        if client is not None:
            print("  %d labels, %d markings, %d organisations"
                  % (len(discovery["labels"]), len(discovery["markings"]),
                     len(discovery["orgs"])))
    elif config["source"] == "taxii":
        discovery = discover_taxii(client)
        if client is None:
            print("  skipped -- no TAXII connection, no collections to offer")
        else:
            print("  %d collections" % len(discovery["collections"]))
    else:
        discovery = discover(client)
        if client is None:
            print("  skipped -- no MISP connection, offering the full type list")
        else:
            print("  %d attribute types, %d tags, %d orgs, %d sharing groups"
                  % (len(discovery["types"]), len(discovery["tags"]),
                     len(discovery["orgs"]), len(discovery["sharing_groups"])))
    config["discovery"] = discovery

    if config["source"] != "taxii":
        # _stage_feeds only has MISP feeds to offer (and an explanatory note
        # for OpenCTI); on TAXII it would silently set feeds=[] and return,
        # which reads as a stage that ran and found nothing.
        _stage_feeds(config, discovery, input_fn, source=config["source"])
    if config["source"] == "taxii":
        # TAXII has no local IOC-type menu (stage 3 asks collections
        # instead, above) and no separate quality stage -- everything that
        # would live there is one of the post-download filters stage 5 asks.
        _stage3_collections_taxii(config, discovery, input_fn)
        _stage5_scope_taxii(config, discovery, input_fn)
    else:
        _stage3_iocs(config, discovery, input_fn, source=config["source"])
        if config["source"] == "opencti":
            _stage4_quality_opencti(config, input_fn)
            _stage5_scope_opencti(config, discovery, input_fn)
        else:
            _stage4_quality(config, input_fn)
            _stage5_scope(config, discovery, input_fn)
    _stage6_exclusions(config, input_fn)
    _stage7_metadata(config, input_fn, offline=offline)
    _stage8_output(config, input_fn, offline=offline)

    if config.get("feeds") and "{feed}" not in (config.get("source_fmt") or ""):
        log.info("feeds selected but meta.source has no {feed} placeholder; "
                 "an intel.log hit will not name its feed")

    print("")
    print(summarise_config(config))
    if not ask_yes_no("Proceed with this configuration?", True, input_fn):
        raise InterviewAborted("operator declined the pre-flight summary")
    return config


# -- derived output ---------------------------------------------------------

def build_search_params(config):
    """Interview answers -> the /attributes/restSearch body.  Pure, no I/O."""
    params = {
        "returnFormat": "json",
        # flatten_attribute() reads meta.source/desc/url out of the event
        # block, which MISP only ships when these are asked for.
        "includeEventUuid": True,
        "includeEventTags": True,
    }

    if config.get("types"):
        params["type"] = list(config["types"])
    if config.get("to_ids"):
        params["to_ids"] = 1
    if config.get("published"):
        params["published"] = 1
    if config.get("enforce_warninglist"):
        params["enforceWarninglist"] = 1
    # MISP defaults to excluding deleted attributes; [0, 1] is how you ask for
    # both, and there is no way to ask for "deleted too" with a single flag.
    params["deleted"] = 0 if config.get("exclude_deleted", True) else [0, 1]

    tags = {}
    if config.get("include_tags"):
        tags["OR"] = list(config["include_tags"])
    if config.get("exclude_tags"):
        tags["NOT"] = list(config["exclude_tags"])
    if tags:
        params["tags"] = tags

    mode = config.get("time_mode") or "all"
    if mode == "last" and config.get("days"):
        # `last` is publish_timestamp-based in MISP; `timestamp` is the
        # attribute's own edit time.  Stage 5 question 19 picks between them.
        key = ("last" if config.get("timestamp_field") == "publish_timestamp"
               else "timestamp")
        params[key] = "%dd" % config["days"]
    elif mode == "range":
        if config.get("date_from"):
            params["from"] = config["date_from"]
        if config.get("date_to"):
            params["to"] = config["date_to"]

    if config.get("orgs"):
        params["org"] = list(config["orgs"])
    if config.get("feed_org_ids"):
        params["org"] = list(config["feed_org_ids"])
    if config.get("sharing_groups"):
        params["sharinggroup"] = list(config["sharing_groups"])
    if config.get("event_ids"):
        params["eventid"] = list(config["event_ids"])
    if config.get("threat_level"):
        # "minimum threat level medium" means high or medium, and MISP counts
        # 1 = high down to 4 = undefined, so the wanted set counts up to it.
        params["threat_level_id"] = list(range(1, config["threat_level"] + 1))
    if config.get("analysis") is not None:
        params["analysis"] = config["analysis"]
    return params


def _opencti_filter(key, values, operator="eq", mode="or"):
    return {"key": [key], "values": [str(v) for v in values],
            "operator": operator, "mode": mode}


def _opencti_stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _opencti_iso_date(value):
    # ask_date also accepts MISP-style relative windows ("30d"); those mean
    # nothing to an OpenCTI filter, which compares ISO-8601 timestamps.
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def taxii_added_after(config, now=None):
    """days back -> the `added_after` timestamp, or None for no time filter.

    Shared by _fetch_records and summarise_config deliberately: added_after
    is the only filter TAXII applies server-side, and a summary that
    computed it separately could describe a window the query does not have.
    """
    days = config.get("days")
    if not days:
        return None
    moment = now or datetime.now(timezone.utc)
    return _opencti_stamp(moment - timedelta(days=int(days)))


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
        date_from = config.get("date_from")
        if date_from and _opencti_iso_date(date_from):
            filters.append(_opencti_filter(
                field, ["%sT00:00:00Z" % date_from], "gte"))
        elif date_from:
            # A relative window like "30d" would silently build a filter
            # that matches nothing -- skip it and say why, instead of
            # returning a run that quietly fetches zero indicators.
            log.warning("date_from %r is not an ISO date (YYYY-MM-DD); "
                       "OpenCTI filters need a real timestamp -- skipping "
                       "the lower time bound", date_from)
        date_to = config.get("date_to")
        if date_to and _opencti_iso_date(date_to):
            filters.append(_opencti_filter(
                field, ["%sT23:59:59Z" % date_to], "lte"))
        elif date_to:
            log.warning("date_to %r is not an ISO date (YYYY-MM-DD); "
                       "OpenCTI filters need a real timestamp -- skipping "
                       "the upper time bound", date_to)

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


def _yes_no(flag):
    return "yes" if flag else "no"


def summarise_config(config):
    """The pre-flight summary.  Deliberately never shows the API token."""
    port = config.get("port")
    scheme = config.get("scheme", "https")
    shown_port = "" if port in (None, 80, 443) else ":%d" % port
    source = config.get("source", "misp")
    label = SOURCE_LABELS.get(source, source)
    lines = ["Pre-flight summary", ""]

    lines.append("  source      : %s" % source)
    lines.append("  %-12s: %s://%s%s (verify TLS: %s)"
                 % (label, scheme, config.get("source_host", "?"), shown_port,
                    _yes_no(config.get("verify_tls"))))
    if config.get("proxy"):
        lines.append("  proxy       : %s" % config["proxy"])

    if source == "misp":
        feeds = config.get("feeds") or []
        if feeds:
            lines.append("  feeds       : %d selected (one query each)" % len(feeds))
            for feed in feeds:
                kind, value, _ = feed_provenance(feed)
                lines.append("                  %-28s via %s=%s"
                             % (feed["name"][:28], kind, value))
        else:
            lines.append("  feeds       : all of MISP (no feed restriction)")

    if source == "taxii":
        collections = config.get("collections") or []
        if collections:
            lines.append("  collections : %d selected (one query each)"
                         % len(collections))
            for collection in collections:
                lines.append("                  %-28s via %s"
                             % ((collection.get("title") or "?")[:28],
                                collection.get("api_root") or "?"))
        else:
            lines.append("  collections : none selected -- this run would "
                         "fetch nothing")
    else:
        types = config.get("types") or []
        lines.append("  IOC types   : %d selected%s"
                     % (len(types),
                        " (%s)" % ", ".join(types[:6]) if types else ""))
    lines.append("  composites  : emit %s, subnets %s, hostname %s"
                 % (config.get("split_composites", "both"),
                    "on" if config.get("allow_subnet") else "off",
                    "as DOMAIN" if config.get("hostname_as_domain") else "dropped"))

    if source == "taxii":
        pass  # every TAXII filter is post-download; see the block below
    elif source == "opencti":
        lines.append("  quality     : min_score=%s min_confidence=%s revoked=%s "
                     "detection=%s expired=%s"
                     % (config.get("min_score", 0), config.get("min_confidence", 0),
                        "excluded" if config.get("exclude_revoked") else "included",
                        "required" if config.get("require_detection") else "any",
                        "excluded" if config.get("exclude_expired") else "included"))
    else:
        lines.append("  quality     : to_ids=%s published=%s warninglist=%s "
                     "deleted=%s" % (_yes_no(config.get("to_ids")),
                                     _yes_no(config.get("published")),
                                     _yes_no(config.get("enforce_warninglist")),
                                     "excluded" if config.get("exclude_deleted")
                                     else "included"))
        if config.get("threat_level") or config.get("analysis") is not None:
            lines.append("  event state : threat_level<=%s analysis=%s"
                         % (config.get("threat_level"), config.get("analysis")))

    if source == "taxii":
        # The TAXII path never sets time_mode; reading it here reported an
        # answered added_after window as "all time" -- misdescribing the one
        # filter TAXII really does apply server-side, on the very screen the
        # operator approves.
        added_after = taxii_added_after(config)
        if added_after:
            lines.append("  window      : last %s days, sent as "
                         "added_after=%s (server-side)"
                         % (config.get("days"), added_after))
        else:
            lines.append("  window      : all time (no added_after sent)")
        lines.append("  applied after download (TAXII cannot express these; "
                     "they thin what is kept, not what is fetched):")
        lines.append("      include labels  : %s"
                     % (", ".join(config.get("include_labels") or []) or "all"))
        lines.append("      exclude labels  : %s"
                     % (", ".join(config.get("exclude_labels") or []) or "none"))
        lines.append("      markings        : %s"
                     % (", ".join(config.get("include_markings") or [])
                        or "all"))
        lines.append("      authors         : %s"
                     % (", ".join(config.get("include_authors") or []) or "all"))
        lines.append("      min confidence  : %s%s"
                     % (config.get("min_confidence") or 0,
                        "  (STIX 2.0 carries no confidence; this excludes "
                        "nothing on a 2.0 feed)"
                        if config.get("taxii_version") == "2.0"
                        and config.get("min_confidence") else ""))
        lines.append("      past valid_until: %s"
                     % ("dropped" if config.get("drop_expired") else "kept"))
    else:
        mode = config.get("time_mode") or "all"
        if mode == "last":
            window = "last %s days (%s)" % (config.get("days"),
                                            config.get("timestamp_field"))
        elif mode == "range":
            window = "%s .. %s" % (config.get("date_from") or "beginning",
                                   config.get("date_to") or "now")
        else:
            window = "all time"
        lines.append("  window      : %s" % window)

    if source == "taxii":
        # The six lines above are the whole of the TAXII scope, and none of
        # them resolves to a server-side id.
        scope_fields = ()
    elif source == "opencti":
        scope_fields = (("include labels", "include_labels",
                         "include_label_ids"),
                        ("exclude labels", "exclude_labels",
                         "exclude_label_ids"),
                        ("markings", "markings", "marking_ids"),
                        ("authors", "authors", "author_ids"))
    else:
        scope_fields = (("include tags", "include_tags", None),
                        ("exclude tags", "exclude_tags", None),
                        ("orgs", "orgs", None),
                        ("sharing groups", "sharing_groups", None),
                        ("event ids", "event_ids", None))
    for scope_label, key, id_key in scope_fields:
        values = config.get(key) or []
        if not values:
            continue
        note = ""
        if id_key is not None:
            # OpenCTI filters on ids, not names.  Printing the names alone
            # would let the summary claim a scope the query does not have.
            resolved = config.get(id_key) or []
            if len(resolved) < len(values):
                note = "  (%d of %d resolved to an OpenCTI id; the rest are " \
                       "not filtered)" % (len(resolved), len(values))
        lines.append("  %-12s: %s%s" % (scope_label, ", ".join(values), note))

    lines.append("  exclusions  : private=%s networks=%s domains=%s allowlist=%s"
                 % (_yes_no(config.get("exclude_private")),
                    ",".join(config.get("own_networks") or []) or "none",
                    ",".join(config.get("own_domains") or []) or "none",
                    config.get("allowlist_file") or "none"))

    lines.append("  meta.source : %s" % config.get("source_fmt"))
    lines.append("  meta.desc   : %s" % config.get("desc_template"))
    lines.append("  meta.url    : %s" % (config.get("source_base_url") or "none"))
    lines.append("  do_notice   : %s  (max meta length %s)"
                 % (_yes_no(config.get("do_notice")), config.get("meta_maxlen")))

    lines.append("  output      : %s (append-only; existing indicators retained)"
                 % config.get("output_path"))
    lines.append("  deployment=%s backup=%s dry_run=%s cap=%s apply=%s"
                 % (config.get("deployment", "distributed"),
                    _yes_no(config.get("backup")), _yes_no(config.get("dry_run")),
                    config.get("max_indicators") or "unlimited",
                    _yes_no(config.get("apply"))))
    if config.get("profile_path"):
        lines.append("  profile     : %s" % config["profile_path"])

    lines.append("")
    if source == "taxii":
        added_after = taxii_added_after(config)
        lines.append("  TAXII query : match[type]=indicator%s  "
                     "(one per collection)"
                     % ("&added_after=%s" % added_after if added_after else ""))
    elif source == "opencti":
        lines.append("  filters     : %s"
                     % json.dumps(build_opencti_filters(config), sort_keys=True))
    else:
        lines.append("  restSearch  : %s"
                     % json.dumps(build_search_params(config), sort_keys=True))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PROFILES
# ---------------------------------------------------------------------------

def profile_path(name):
    """A bare name resolves under NEXUS_HOME; a path is taken as given."""
    if os.sep in name or name.endswith(".json"):
        return name
    return os.path.join(NEXUS_HOME, "profiles", "%s.json" % name)


def save_profile(config, path):
    """Persist the interview answers, minus anything secret or stale.

    Written 0600 before any content lands in it: a profile records which MISP
    an operator queries and how, which is not worth leaking even without the
    token in it.
    """
    payload = {"profile_version": PROFILE_VERSION,
               "nexus_version": __version__,
               "saved_utc": datetime.now(timezone.utc).strftime(
                   "%Y-%m-%dT%H:%M:%SZ"),
               "config": dict((k, v) for k, v in config.items()
                              if k not in PROFILE_EXCLUDED_KEYS)}

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, 0o600)  # an existing file keeps its old mode through O_CREAT
    return path


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


# ---------------------------------------------------------------------------
# DIFF
# ---------------------------------------------------------------------------

def _row_key(line):
    fields = line.split("\t")
    return (fields[0], fields[1]) if len(fields) > 1 else (line, "")


def indicator_delta(existing_rows, new_rows):
    """(added, removed) indicator keys between two intel bodies.

    Keyed on (indicator, type) rather than the whole line, so a changed
    description does not read as a delete plus an add.
    """
    before = dict((_row_key(l), l) for l in existing_rows if l.strip())
    after = dict((_row_key(l), l) for l in new_rows
                 if l.strip() and not l.startswith("#"))
    added = [after[k] for k in after if k not in before]
    removed = [before[k] for k in before if k not in after]
    return sorted(added), sorted(removed)


def summarise_delta(existing_rows, new_rows, sample=10):
    """Human-readable indicator delta for --dry-run."""
    added, removed = indicator_delta(existing_rows, new_rows)
    lines = ["%d added, %d removed, %d unchanged"
             % (len(added), len(removed),
                len(existing_rows) - len(removed))]
    for label, rows in (("+", added), ("-", removed)):
        for line in rows[:sample]:
            lines.append("  %s %s" % (label, line.split("\t")[0]))
        if len(rows) > sample:
            lines.append("  %s ...and %d more" % (label, len(rows) - sample))
    return "\n".join(lines)


def unified_intel_diff(existing_rows, new_rows, path):
    """Full line diff, for --diff."""
    return list(difflib.unified_diff(
        existing_rows, [l for l in new_rows if not l.startswith("#fields")],
        fromfile="%s (current)" % path, tofile="%s (new)" % path, lineterm=""))


# ---------------------------------------------------------------------------
# APPLY
# ---------------------------------------------------------------------------

# Zeek reports a bad intel file through the reporter log rather than failing
# the salt run, so a clean `state.apply` proves nothing on its own.
REPORTER_ERROR_HINTS = ("intel", "Intel::")


def seed_load_file(intel_dir=SO_INTEL_DIR, default_dir=SO_INTEL_DEFAULT_DIR):
    """Copy the default intel files into the local dir, without clobbering.

    A fresh Security Onion leaves the local intel directory empty.  Writing
    intel.dat there without __load__.Zeek produces a file Zeek never reads --
    the failure looks exactly like success, which is why this is a guard
    rather than a convenience.
    """
    copied = []
    if not os.path.isdir(default_dir):
        raise OSError("defaults not found at %s" % default_dir)
    os.makedirs(intel_dir, exist_ok=True)
    for name in os.listdir(default_dir):
        dest = os.path.join(intel_dir, name)
        if os.path.exists(dest):
            continue  # never overwrite intel.dat the operator already has
        shutil.copy2(os.path.join(default_dir, name), dest)
        copied.append(dest)
    return copied


def log_offset(path):
    """Byte offset to read a log from after an action.

    Size-based rather than time-based so the "did this run produce errors?"
    question stays deterministic and testable.
    """
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def log_errors_since(path, offset, hints=REPORTER_ERROR_HINTS):
    """Intel-related error lines appended to a log after `offset`."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            tail = handle.read()
    except OSError:
        return []
    found = []
    for line in tail.splitlines():
        lowered = line.lower()
        if "error" not in lowered and "warning" not in lowered:
            continue
        if any(hint.lower() in lowered for hint in hints):
            found.append(line.strip())
    return found


def salt_apply(argv=None, timeout=900, runner=None):
    """Run the state.apply.  Returns (returncode, stdout, stderr).

    `runner` is injectable so the whole apply path is testable without salt.
    """
    argv = list(argv or SO_APPLY_ARGV)
    if runner is None:
        if shutil.which(argv[0]) is None and shutil.which("salt") is None:
            raise OSError("salt not found on PATH")
        runner = _run_subprocess
    return runner(argv, timeout)


def _run_subprocess(argv, timeout):
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise OSError("salt timed out after %ds" % timeout)
    return proc.returncode, out, err


def verify_runtime(runtime_dir=SO_INTEL_RUNTIME_DIR, expected=None):
    """Confirm the file reached the node-local path salt syncs it to."""
    path = os.path.join(runtime_dir, "intel.dat")
    if not os.path.exists(path):
        return (False, "%s does not exist -- the sync did not reach this node"
                       % path)
    _, rows = read_existing(path)
    if expected is not None and len(rows) != expected:
        return (False, "%s has %d indicators, expected %d"
                       % (path, len(rows), expected))
    return (True, "%s has %d indicators" % (path, len(rows)))


def apply_to_grid(intel_dir=SO_INTEL_DIR, runtime_dir=SO_INTEL_RUNTIME_DIR,
                  reporter_log=SO_REPORTER_LOG, expected=None, runner=None,
                  argv=None):
    """Seed check, salt apply, runtime verify, reporter check.

    Returns (ok, steps) where steps is [(level, message), ...] in the order
    they happened, so a partial failure still shows what did work.
    """
    steps = []

    verdict = check_load_file(intel_dir)
    if not verdict.ok:
        return False, [("error", verdict.message)]
    steps.append(("info", verdict.message))

    offset = log_offset(reporter_log)

    try:
        rc, out, err = salt_apply(argv=argv, runner=runner)
    except OSError as exc:
        steps.append(("error", "could not run salt: %s" % exc))
        steps.append(("fix", SO_APPLY_CMD))
        return False, steps

    if rc != 0:
        steps.append(("error", "salt exited %d" % rc))
        for line in (err or out or "").splitlines()[-5:]:
            steps.append(("error", "  " + line.strip()))
        return False, steps
    steps.append(("info", "salt state.apply zeek completed"))

    ok, message = verify_runtime(runtime_dir, expected)
    steps.append(("info" if ok else "warn", message))

    errors = log_errors_since(reporter_log, offset)
    if errors:
        steps.append(("error", "%s reported %d intel problem(s):"
                               % (reporter_log, len(errors))))
        for line in errors[:10]:
            steps.append(("error", "  " + line))
        return False, steps
    steps.append(("info", "no intel errors in %s" % reporter_log))
    steps.append(("info", "confirm hits in %s" % SO_INTEL_LOG))
    return ok, steps


def print_transfer_instructions(path):
    """Both manager-side routes, and the difference between them.

    An operator who copies the file into place by hand gets no guardrails and
    no merge -- that route is supported, but it silently replaces whatever the
    manager had accumulated.  Saying so here is the only protection it gets.
    """
    print("\nBuilt for transfer: %s" % path)
    print("\nOn the Security Onion manager, either:")
    print("  1. Merge it (keeps the indicators already there):")
    print("       python3 nexus.py --import %s" % os.path.basename(path))
    print("  2. Or put it in place by hand:")
    print("       sudo cp %s %s" % (os.path.basename(path), SO_INTEL_FILE))
    print("     This REPLACES the manager's intel.dat. Safe on a fresh")
    print("     install; on a manager that has been running, it drops every")
    print("     indicator not in this file.")
    print("     It also needs %s already present -- check with:" % SO_LOAD_FILE)
    print("       python3 nexus.py --check-env    (and --seed if it is missing)")
    print("\nThen apply: %s" % SO_APPLY_CMD)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

LEVEL_PREFIX = {"info": "  [ok]   ", "warn": "  [warn] ",
                "error": "  [FAIL] ", "fix": "  [fix]  "}


def resolve_token(args, interactive=True):
    """Token from --token-file, env, credentials.json, then the operator.

    `interactive=False` under --yes: an unattended run must fail loudly rather
    than block forever on a getpass prompt nobody will ever answer.
    """
    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except (OSError, UnicodeDecodeError) as exc:
            log.warning("could not read %s: %s", args.token_file, exc)
            token = ""
        if token:
            return token
    for name in ("NEXUS_TOKEN", "NEXUS_MISP_TOKEN"):
        env = os.environ.get(name)
        if env:
            return env.strip()
    cred_path = os.path.join(NEXUS_HOME, "credentials.json")
    if os.path.exists(cred_path):
        try:
            with open(cred_path, "r", encoding="utf-8") as handle:
                token = json.load(handle).get("token")
            if token:
                return token.strip()
        except (ValueError, OSError) as exc:
            log.warning("could not read %s: %s", cred_path, exc)
    if not interactive:
        log.error("no token in --token-file, NEXUS_TOKEN/NEXUS_MISP_TOKEN or "
                  "%s/credentials.json, and --yes cannot prompt", NEXUS_HOME)
        return ""
    # Which platform this is for is the interview's job, asked in stage 1;
    # by the time resolve_token runs standalone (e.g. --probe) that context
    # may not exist yet, so the prompt stays platform-neutral.
    return getpass.getpass("API token: ").strip()


def resolve_taxii_username(interactive=True, input_fn=input):
    """The Basic username a profile deliberately did not store.

    It is half a credential, so PROFILE_EXCLUDED_KEYS keeps it off disk
    alongside the password -- which leaves a replayed Basic profile with
    nowhere to read it from but the environment or the operator.  "" is a hard
    failure at the call site: a client built without it authenticates Bearer,
    and the 401 that follows blames the token.
    """
    env = (os.environ.get("NEXUS_TAXII_USERNAME") or "").strip()
    if env:
        return env
    if not interactive:
        log.error("this profile authenticates to TAXII with Basic auth, and "
                  "the username is never stored -- set NEXUS_TAXII_USERNAME, "
                  "or drop --yes so it can be asked for")
        return ""
    return ask_required("TAXII Basic username", None, input_fn)


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
    if config.get("source") == "taxii":
        # A probe has no interview behind it, so the version falls back to
        # the current default rather than to None, which the constructor
        # rejects; _cmd_probe_taxii then detects the real one.
        return TaxiiClient(version=config.get("taxii_version")
                                   or TAXII_VERSIONS[0],
                           username=config.get("taxii_username"), **kwargs)
    return MispClient(**kwargs)


def cmd_check_env(args):
    ok, findings = check_env()
    print("Nexus environment check")
    for level, message in findings:
        print(LEVEL_PREFIX.get(level, "  ") + message)
    if not ok:
        print("\nEnvironment is not ready.  Address the [FAIL] items above.")
        return 1
    print("\nEnvironment looks ready.")
    return 0


def cmd_lint(args):
    try:
        problems = lint_file(args.lint, do_notice=args.do_notice)
    except (OSError, IOError, UnicodeDecodeError) as exc:
        print("cannot read %s: %s" % (args.lint, exc), file=sys.stderr)
        return 2
    if not problems:
        _, rows = read_existing(args.lint)
        print("%s: OK (%d indicators)" % (args.lint, len(rows)))
        return 0
    print("%s: %d problem(s)" % (args.lint, len(problems)))
    for problem in problems:
        print("  " + problem)
    return 1


def cmd_explain(args):
    """Show exactly what would be asked of the platform, without asking it."""
    if not args.profile:
        print("--explain requires --profile", file=sys.stderr)
        return 2
    try:
        config = load_profile(profile_path(args.profile))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print("could not load profile: %s" % exc, file=sys.stderr)
        return 2

    print(summarise_config(config))
    print("")
    if config.get("source") == "taxii":
        collections = config.get("collections") or []
        added_after = taxii_added_after(config)
        if not collections:
            print("No collections selected -- this profile would fetch "
                  "nothing.")
            return 0
        # One request per *page*, not per collection: 2.1 sends `limit` and
        # follows `next`, 2.0 walks a Range window.  The URL below is the
        # first page of each collection.
        version = config.get("taxii_version") or TAXII_VERSIONS[0]
        if version == "2.0":
            print("%d collection(s), paged with Range headers -- one GET per "
                  "page, starting with:" % len(collections))
        else:
            print("%d collection(s), paged with `next` -- one GET per page, "
                  "starting with:" % len(collections))
        for collection in collections:
            print("  %scollections/%s/objects/?match[type]=indicator%s%s"
                  % (collection.get("api_root") or "?", collection.get("id"),
                     "" if version == "2.0" else "&limit=%d" % TAXII_PAGE_SIZE,
                     "&added_after=%s" % added_after if added_after else ""))
        return 0

    if config.get("source") == "opencti":
        print("One query to POST /graphql:")
        print("  " + json.dumps(build_opencti_filters(config), indent=2,
                                sort_keys=True))
        return 0

    base = build_search_params(config)
    feeds = config.get("feeds") or []
    if not feeds:
        print("One query to POST /attributes/restSearch:")
        print("  " + json.dumps(base, indent=2, sort_keys=True))
        return 0

    print("%d queries to POST /attributes/restSearch, one per feed:" % len(feeds))
    for feed in feeds:
        print("\n  -- %s" % feed["name"])
        print("  " + json.dumps(apply_feed_to_params(base, feed),
                                indent=2, sort_keys=True).replace("\n", "\n  "))
    return 0


def cmd_seed(args):
    try:
        copied = seed_load_file()
    except OSError as exc:
        print("could not seed: %s" % exc, file=sys.stderr)
        return 1
    if not copied:
        print("Nothing to do -- %s is already populated." % SO_INTEL_DIR)
    for path in copied:
        print("copied %s" % path)
    return 0


def cmd_apply(args):
    _, rows = read_existing(SO_INTEL_FILE)
    print("Applying %s (%d indicators)" % (SO_INTEL_FILE, len(rows)))
    print("  %s" % SO_APPLY_CMD)
    applied, steps = apply_to_grid(expected=len(rows))
    for level, message in steps:
        print(LEVEL_PREFIX.get(level, "  ") + message)
    return 0 if applied else 1


def cmd_probe(args):
    token = resolve_token(args)
    if not token:
        print("no API token supplied", file=sys.stderr)
        return 2

    client = make_client({
        "source": args.source, "source_host": args.host, "token": token,
        "scheme": args.scheme, "port": args.port,
        "verify_tls": not args.insecure, "proxy": args.proxy,
        "timeout": args.timeout, "retries": args.retries,
    })

    if args.source == "opencti":
        return _cmd_probe_opencti(client, args)
    if args.source == "taxii":
        return _cmd_probe_taxii(client, args)
    return _cmd_probe_misp(client, args)


def _cmd_probe_taxii(client, args):
    """What this TAXII endpoint is, and what it will let us read."""
    try:
        # A probe has no interview to have asked the version, so it detects
        # one rather than assuming the 2.1 the client was built at.
        client.version = client.detect_version()
        version = client.get_version()
        collections = client.get_collections()
    except SourceAuthError as exc:
        print("authentication failed: %s" % exc, file=sys.stderr)
        return 2
    except SourceError as exc:
        print("connection failed: %s" % exc, file=sys.stderr)
        return 2

    print("Connected to %s" % client.base_url)
    print("  TAXII version : %s" % version.get("version", "unknown"))
    print("  title         : %s" % version.get("title", "unknown"))

    print("\nCollections (%d)" % len(collections))
    if not collections:
        print("  none readable -- check the API root permissions for this "
              "account")
        return 1

    # TAXII has no way to count a filtered subset -- match[type]=indicator
    # and added_after are the only filters the server understands, so a
    # collection's object count is "everything in it", not "what Nexus will
    # keep". Bounded by --probe-limit for the same reason MISP/OpenCTI's
    # counts are: an unbounded pull here would make --probe itself a slow,
    # unbounded download.
    probe_limit = args.probe_limit if args and args.probe_limit else 5000
    print("  %-40s %9s  %s" % ("title", "objects", "api root"))
    for collection in collections:
        try:
            count = 0
            for _ in client.fetch_objects(collection, max_results=probe_limit):
                count += 1
        except SourceError as exc:
            print("  %-40s %9s  %s" % ((collection["title"] or "")[:40],
                                       "ERR", exc))
            continue
        marker = "" if count < probe_limit else "+"
        print("  %-40s %8d%s  %s" % ((collection["title"] or "")[:40],
                                     count, marker, collection["api_root"]))

    print("\nThese are object counts in each collection, before the "
          "post-download filters: TAXII can filter on type and added_after "
          "only, so labels, markings, confidence, validity and authors are "
          "all applied after download, on objects already fetched.")
    return 0


def _cmd_probe_misp(client, args):
    try:
        version = client.get_version()
    except SourceAuthError as exc:
        print("authentication failed: %s" % exc, file=sys.stderr)
        return 2
    except SourceError as exc:
        print("connection failed: %s" % exc, file=sys.stderr)
        return 2

    print("Connected to %s" % client.base_url)
    print("  MISP version : %s" % version.get("version", "unknown"))
    for key in ("perm_sync", "perm_sighting", "perm_galaxy_editor", "role_name"):
        if key in version:
            print("  %-13s: %s" % (key, version[key]))

    try:
        described = client.describe_types()
        tags = client.get_tags()
        orgs = client.get_orgs()
    except SourceError as exc:
        print("discovery failed: %s" % exc, file=sys.stderr)
        return 2

    known = set(described.get("types") or [])
    print("\nDiscovery")
    print("  attribute types known to this MISP : %d" % len(known))
    print("  tags                               : %d" % len(tags))
    print("  organisations                      : %d" % len(orgs))

    base = {}
    if args.to_ids:
        base["to_ids"] = 1
    if args.published:
        base["published"] = 1
    if args.days:
        base["last"] = "%dd" % args.days

    candidates = [t for t in mappable_types() if not known or t in known]
    print("\nMappable attribute types (filters: %s)"
          % (", ".join("%s=%s" % kv for kv in sorted(base.items())) or "none"))
    print("  %-24s %10s  %s" % ("misp type", "count", "zeek type"))

    total = 0
    for misp_type in candidates:
        try:
            count, exact = client.count_type(misp_type, base,
                                             probe_limit=args.probe_limit)
        except SourceError as exc:
            print("  %-24s %10s  %s" % (misp_type, "ERR", exc))
            continue
        if count == 0 and not args.show_empty:
            continue
        total += count
        marker = "" if exact else "+"
        flag = "" if misp_type not in MISP_OFF_BY_DEFAULT else "   (off by default)"
        print("  %-24s %9d%s  %s%s"
              % (misp_type, count, marker, zeek_type_for(misp_type), flag))

    print("\n  approximate total indicators available: %d%s"
          % (total, "" if total < args.probe_limit else "+"))
    unmapped = sorted(t for t in known if t in MISP_UNMAPPABLE)
    if unmapped:
        print("\nPresent in MISP but not mappable to Zeek:")
        for misp_type in unmapped:
            print("  %-24s %s" % (misp_type, MISP_UNMAPPABLE[misp_type]))
    return 0


def _cmd_probe_opencti(client, args):
    try:
        version = client.get_version()
    except SourceAuthError as exc:
        print("authentication failed: %s" % exc, file=sys.stderr)
        return 2
    except SourceError as exc:
        print("connection failed: %s" % exc, file=sys.stderr)
        return 2

    print("Connected to %s" % client.base_url)
    print("  OpenCTI version : %s" % version.get("version", "unknown"))

    try:
        labels = client.get_labels()
        markings = client.get_markings()
        orgs = client.get_organizations()
    except SourceError as exc:
        print("discovery failed: %s" % exc, file=sys.stderr)
        return 2

    print("\nDiscovery")
    print("  labels                              : %d" % len(labels))
    print("  marking definitions                 : %d" % len(markings))
    print("  organisations                       : %d" % len(orgs))

    # x_opencti_main_observable_type is what count_type() and the search
    # filter both key on -- not the OPENCTI_TO_ZEEK value-type keys, which
    # are one level finer (a StixFile yields several value types at once).
    candidates = []
    for key in OPENCTI_IOC_CLASS_ORDER:
        candidates.extend(OPENCTI_IOC_CLASSES[key][1])
    print("\nMappable observable types")
    print("  %-24s %10s  %s" % ("opencti type", "count", "zeek type"))

    total = 0
    approximate = False
    for main_type in candidates:
        try:
            count, exact = client.count_type(main_type,
                                             probe_limit=args.probe_limit)
        except SourceError as exc:
            print("  %-24s %10s  %s" % (main_type, "ERR", exc))
            continue
        if count == 0 and not args.show_empty:
            continue
        total += count
        approximate = approximate or not exact
        marker = "" if exact else "+"
        flag = "" if main_type not in OPENCTI_OFF_BY_DEFAULT else "   (off by default)"
        print("  %-24s %9d%s  %s%s"
              % (main_type, count, marker,
                 " + ".join(opencti_zeek_types(main_type)), flag))

    # OpenCTI answers with globalCount, so unless a count actually came back
    # capped these totals are exact and a "+" would be a lie.
    print("\n  total indicators available: %d%s"
          % (total, "+" if approximate else ""))
    if OPENCTI_UNMAPPABLE:
        print("\nPresent in OpenCTI but not mappable to Zeek:")
        for main_type in sorted(OPENCTI_UNMAPPABLE):
            print("  %-24s %s" % (main_type, OPENCTI_UNMAPPABLE[main_type]))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="Build a Zeek intel.dat from MISP, OpenCTI or TAXII, "
                    "for Security Onion 3.2.",
    )
    parser.add_argument("--version", action="version",
                        version="nexus %s" % __version__)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--log-file", default=None,
                        help="run log (default %s/logs/nexus.log)" % NEXUS_HOME)

    mode = parser.add_argument_group("modes")
    mode.add_argument("--check-env", action="store_true",
                      help="stage 0 only: verify SO paths and __load__.Zeek")
    mode.add_argument("--lint", metavar="PATH",
                      help="validate an intel.dat and exit")
    mode.add_argument("--apply", action="store_true",
                      help="push the existing intel.dat to the grid and check "
                           "the reporter log; builds nothing")
    mode.add_argument("--seed", action="store_true",
                      help="copy the Security Onion default intel files "
                           "(including __load__.Zeek) into the local dir")
    mode.add_argument("--explain", action="store_true",
                      help="print the resolved platform query for a profile "
                           "and exit; contacts nothing")
    mode.add_argument("--probe", action="store_true",
                      help="connect to the platform and report available "
                           "IOC counts")
    mode.add_argument("--import", dest="import_file", metavar="PATH",
                      default=None,
                      help="merge an intel.dat built on another host into "
                           "this manager's file, append-only; with --yes, "
                           "also applies to the grid")

    conn = parser.add_argument_group("platform connection")
    conn.add_argument("--source", choices=SOURCES, default=None,
                      help="which platform to pull from; asked if omitted")
    conn.add_argument("--host", metavar="HOST", default=None,
                      help="platform IP or hostname; asked if omitted")
    conn.add_argument("--misp", metavar="HOST", default=None,
                      help="deprecated alias for --host --source misp")
    conn.add_argument("--scheme", default="https", choices=("https", "http"))
    conn.add_argument("--port", type=int, default=None)
    conn.add_argument("--insecure", action="store_true",
                      help="disable TLS certificate verification")
    conn.add_argument("--proxy", default=None)
    conn.add_argument("--timeout", type=int, default=30)
    conn.add_argument("--retries", type=int, default=3)
    conn.add_argument("--token-file", default=None)

    probe = parser.add_argument_group("probe filters")
    probe.add_argument("--days", type=int, default=None,
                       help="only count attributes from the last N days")
    probe.add_argument("--to-ids", action="store_true", default=False,
                       help="only count to_ids-flagged attributes")
    probe.add_argument("--published", action="store_true", default=False,
                       help="only count attributes in published events")
    probe.add_argument("--probe-limit", type=int, default=5000,
                       help="ceiling for count probes (default 5000)")
    probe.add_argument("--show-empty", action="store_true",
                       help="include types with a zero count")

    run = parser.add_argument_group("unattended operation")
    run.add_argument("--profile", metavar="NAME_OR_PATH",
                     help="replay saved answers instead of running the "
                          "interview")
    run.add_argument("--offline", action="store_true",
                     help="build for transfer to another host; skips the "
                          "Security Onion checks and the apply step. Asked "
                          "if omitted.")
    run.add_argument("--yes", action="store_true",
                     help="never prompt; a build requires --profile and a "
                          "token from --token-file, NEXUS_TOKEN/"
                          "NEXUS_MISP_TOKEN or credentials.json (--import "
                          "needs neither)")
    run.add_argument("--dry-run", action="store_true",
                     help="build and compare, write nothing")
    run.add_argument("--diff", action="store_true",
                     help="with --dry-run, show the full line diff")

    parser.add_argument("--do-notice", action="store_true",
                        help="expect/emit the meta.do_notice column")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    args = resolve_source_args(args)
    explicit_log = args.log_file is not None
    logfile = args.log_file or os.path.join(NEXUS_HOME, "logs", "nexus.log")
    setup_logging(args.verbose, logfile, required=explicit_log)

    if args.lint:
        return cmd_lint(args)
    if args.check_env:
        return cmd_check_env(args)
    if args.seed:
        return cmd_seed(args)
    if args.apply:
        return cmd_apply(args)
    if args.explain:
        return cmd_explain(args)
    # Above the --yes gate deliberately: an import runs no interview, so
    # --import --yes is a legitimate unattended invocation and the gate below
    # exists only to catch an unattended run with nothing to answer with.
    if args.import_file:
        return cmd_import(args)
    if args.yes and not args.profile:
        print("--yes requires --profile (there is nothing to answer "
              "unattended)", file=sys.stderr)
        return 2
    if args.probe:
        # Flags exist to skip questions, not to change what a flagless run
        # means: absent --host/--source, --probe asks rather than errors.
        try:
            if not args.host:
                args.host = ask_required("Platform address (IP or hostname)",
                                         None)
            if not args.source:
                args.source = ask_choice("Threat intel platform",
                                         list(SOURCES), "misp")
        except InterviewAborted as exc:
            print("\nAborted: %s" % exc)
            return 130
        return cmd_probe(args)

    return cmd_build(args)


def ensure_intel_env(assume_yes):
    """Stage 0 on a manager: check_env(), seeding __load__.Zeek if it can.

    True when this host is fit to be written to.  Shared by cmd_build and
    cmd_import; cmd_build skips it entirely when the build is offline, which
    is why the caller decides rather than a flag here.
    """
    ok, findings = check_env()
    if ok:
        return True
    for level, message in findings:
        if level in ("error", "fix"):
            print(LEVEL_PREFIX.get(level, "  ") + message)
    # The one failure Nexus can fix itself, and the one most likely to be
    # hit on a fresh manager.
    missing_load = not os.path.exists(
        os.path.join(SO_INTEL_DIR, SO_LOAD_FILE))
    # assume_yes seeds without asking; the alternative is an unattended run
    # that writes a file Zeek will never load.
    if missing_load and os.path.isdir(SO_INTEL_DIR) and (
            assume_yes or ask_yes_no(
                "Seed the intel directory from the Security Onion "
                "defaults?", True)):
        try:
            for path in seed_load_file():
                print("  copied %s" % path)
        except OSError as exc:
            print("  could not seed: %s" % exc)
            return False
        ok, _ = check_env()
    if not ok:
        print("Environment is not ready -- run --check-env for detail.")
    return ok


def _report_guardrails(verdicts):
    """Print every verdict and say whether one of them blocks the write."""
    print("\nGuardrails")
    blocked = False
    for verdict in verdicts:
        print("  %-7s %s" % (verdict.level, verdict.message))
        blocked = blocked or not verdict.ok
    if blocked:
        print("\nBlocked. Nothing written.")
    return blocked


def _report_lint(problems, context):
    """Print the first ten lint problems; True means do not write.

    `context` names the file the operator is looking at -- "rendered" for a
    build, "merged" for an import.  Kept as an argument because the two
    messages drifted apart while they were copies of each other.
    """
    if not problems:
        return False
    print("\nRefusing to write, the %s file fails lint:" % context)
    for problem in problems[:10]:
        print("  " + problem)
    return True


def _report_dry_run(dry_run, show_diff, existing, lines, path):
    """Say what a real run would have written; True means nothing was."""
    if not dry_run:
        return False
    print("\nDry run -- nothing written to %s" % path)
    if show_diff:
        diff = unified_intel_diff(existing, lines, path)
        print("")
        print("\n".join(diff) if diff else "(no line-level changes)")
    return True


def cmd_build(args):
    """The default mode: interview, fetch, build, check, write."""
    # Where the file is going decides whether this host has to be a manager at
    # all, so it is settled before check_env() -- and a profile is loaded first
    # because it already recorded the answer.  Re-asking it would break the one
    # unattended path (--profile --yes) that must never prompt.
    config = None
    if args.profile:
        try:
            config = load_profile(profile_path(args.profile))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            print("could not load profile: %s" % exc, file=sys.stderr)
            return 2
        offline = bool(args.offline or config.get("offline"))
    else:
        try:
            offline = resolve_build_target(args)
        except InterviewAborted as exc:
            print("\nAborted: %s" % exc)
            return 130

    # Off-box there is no Security Onion to check; check_output_target() below
    # takes its place once the output path is known.
    if not offline and not ensure_intel_env(args.yes):
        return 1

    if config is not None:
        config["token"] = resolve_token(args, interactive=not args.yes)
        if not config["token"]:
            print("no API token available", file=sys.stderr)
            return 2
        if (config.get("source") == "taxii"
                and config.get("taxii_auth") == "basic"
                and not config.get("taxii_username")):
            # Falling through would build a Bearer client out of a Basic
            # profile and report the resulting 401 as a bad token.
            config["taxii_username"] = resolve_taxii_username(
                interactive=not args.yes)
            if not config["taxii_username"]:
                print("no TAXII Basic username available; set "
                      "NEXUS_TAXII_USERNAME", file=sys.stderr)
                return 2
        print("Replaying profile %s" % profile_path(args.profile))
    else:
        # The interview needs a live client for its tag/org/type lists, but
        # stage 1 is what collects the credentials, so connect in between.
        try:
            # --source answers its own question; --host only seeds the
            # default, so the address is still asked.
            config = run_interview(None, source=args.source, host=args.host,
                                   connect=make_client, offline=offline)
        except InterviewAborted as exc:
            print("\nAborted: %s" % exc)
            return 130

    # Profiles written before topology became explicit remain compatible.
    config.setdefault("deployment", "distributed")
    config.setdefault("max_indicators", None)
    # Off-box this would report on the build host, which is not where the
    # file runs; the manager's own --check-env is what answers it.
    if not offline and config.get("do_notice") and not notice_policy_loaded():
        print("WARNING: policy/frameworks/intel/do_notice.zeek is not loaded; "
              "meta.do_notice will have no effect.")

    # CLI flags win over whatever the profile recorded.
    if args.dry_run:
        config["dry_run"] = True
    if args.yes:
        config["apply"] = config.get("apply", False)

    path = config["output_path"]
    if offline:
        # Stage 0 for an offline run: it needs the output path, and that is the
        # last thing the config settles.  Before the fetch, so a typo'd
        # directory costs nothing.  Every finding prints, not just the
        # failures -- "output directory: X" is the operator's only
        # confirmation of where the file is landing.
        ok, findings = check_output_target(path, config["do_notice"])
        for level, message in findings:
            print(LEVEL_PREFIX.get(level, "  ") + message)
        if not ok:
            return 1

    client = make_client(config)

    if config.get("profile_path") and not args.profile:
        try:
            saved = save_profile(config, config["profile_path"])
            print("saved profile %s (the token is not stored)" % saved)
        except OSError as exc:
            log.warning("could not save profile: %s", exc)

    print(summarise_config(config))
    label = SOURCE_LABELS.get(config.get("source"), "platform")
    try:
        version = client.get_version()
    except SourceError as exc:
        print("%s connection failed: %s" % (label, exc), file=sys.stderr)
        return 2
    log.info("connected to %s %s", label, version.get("version", "unknown"))

    exclusions = ExclusionSet(
        exclude_private=config["exclude_private"],
        own_networks=config["own_networks"],
        own_domains=config["own_domains"],
        allowlist=_load_allowlist(config.get("allowlist_file")),
    )

    # A live BuildStats has to be reachable from _fetch_records (OpenCTI's
    # pattern-fallback counters) as well as build_indicators (mapping
    # counters), so both write into the same instance via config["_stats"].
    stats = BuildStats()
    config["_stats"] = stats
    if config.get("source") == "opencti":
        table = OPENCTI_TO_ZEEK
        # config["types"] is in main_observable_type form for the server-side
        # filter; the records build_indicators sees are one level finer.
        wanted_types = opencti_record_types(config["types"])
    elif config.get("source") == "taxii":
        # parse_stix_pattern already emits OPENCTI_TO_ZEEK keys, so there is
        # no vocabulary to expand.  types is None (every mappable type)
        # unless stage 3's hostname answer narrowed it.
        table = OPENCTI_TO_ZEEK
        wanted_types = config.get("types")
    else:
        table = MISP_TO_ZEEK
        wanted_types = config["types"]
    records = _fetch_records(client, config)
    rows, stats = build_indicators(
        records, types=wanted_types, exclusions=exclusions,
        split_composites=config["split_composites"],
        allow_subnet=config["allow_subnet"], source_fmt=config["source_fmt"],
        desc_template=config["desc_template"],
        base_url=config["source_base_url"],
        meta_maxlen=config["meta_maxlen"],
        do_notice=config["do_notice"] or None,
        source=config.get("source", "misp"),
        mapping_table=table, stats=stats,
    )
    print("\n" + stats.report())

    try:
        existing_header, existing = read_existing(path)
    except (OSError, UnicodeDecodeError) as exc:
        print("\nBlocked. %s is unreadable: %s" % (path, exc), file=sys.stderr)
        return 1
    wanted_header = header_line(config["do_notice"])
    if existing_header and existing_header != wanted_header:
        print("\nBlocked. Existing intel.dat schema differs from the requested "
              "meta.do_notice setting; append-only mode will not rewrite "
              "existing rows.")
        return 1

    fresh_lines = rows_to_lines(rows, config["do_notice"])
    combined = merge_additive(existing, fresh_lines)
    verdicts = run_guardrails(rows, len(existing),
                              intel_dir=None if offline
                              else os.path.dirname(path),
                              append_only=True, total_count=len(combined),
                              cap=config.get("max_indicators"))
    if _report_guardrails(verdicts):
        return 1

    lines = [wanted_header] + combined

    if _report_lint(lint_lines(lines, config["do_notice"]), "rendered"):
        return 1

    added, removed = indicator_delta(existing, lines)
    print("\n%s indicator diff" % label)
    print(summarise_delta(existing, lines))
    if removed:
        # This is an invariant check, not an expected operator decision.
        print("\nBlocked. Append-only update unexpectedly removed indicators.")
        return 1

    if _report_dry_run(config.get("dry_run"), args.diff, existing, lines,
                       path):
        return 0

    if config["backup"]:
        # Off-box there is no writable /opt/nexus to back up into -- and the
        # output directory is the one place check_output_target proved we can
        # write.  Without this the second offline build over the same file
        # dies in os.makedirs.
        if offline:
            backup_dir = os.path.join(os.path.dirname(os.path.abspath(path)),
                                      "nexus-backups")
        else:
            backup_dir = os.path.join(NEXUS_HOME, "backups")
        saved = backup_file(path, backup_dir)
        if saved:
            print("\nbacked up to %s" % saved)
    write_atomic(path, lines)
    print("added %d new indicators; %d total in %s"
          % (len(added), len(combined), path))

    if offline:
        # Nothing here to apply to; the manager-side steps are the operator's.
        print_transfer_instructions(path)
        return 0

    if not config.get("apply"):
        target = ("standalone node" if config.get("deployment") == "standalone"
                  else "grid")
        print("\nNot applied. To push it to the %s:" % target)
        print("  %s" % SO_APPLY_CMD)
        print("Then check: %s" % SO_INTEL_LOG)
        return 0

    target = ("standalone node" if config.get("deployment") == "standalone"
              else "grid")
    print("\nApplying to the %s: %s" % (target, SO_APPLY_CMD))
    applied, steps = apply_to_grid(intel_dir=os.path.dirname(path),
                                   expected=len(rows))
    for level, message in steps:
        print(LEVEL_PREFIX.get(level, "  ") + message)
    return 0 if applied else 1


def _fetch_records(client, config):
    """Yield records from whichever platform the config names.

    OpenCTI expresses its whole query as one FilterGroup, so it is a single
    call.  TAXII gets one query per selected collection -- a collection is
    the only thing its query syntax can scope to -- and then filters what
    came back locally.  MISP needs the per-feed fan-out below: two feeds identified by
    different mechanisms -- one by fixed event, one by tag -- cannot be
    expressed in a single restSearch body, so each gets its own query and the
    results are merged.  build_indicators() dedupes across them, so an
    indicator carried by two feeds is written once.
    """
    if config.get("source") == "taxii":
        added_after = taxii_added_after(config)
        stats = config.get("_stats")
        budget = config.get("max_indicators")
        seen = 0
        for collection in config.get("collections") or []:
            log.info("fetching collection %s",
                     collection.get("title") or collection.get("id"))
            # No max_results: it caps objects, and this budget counts records,
            # which flattening produces 1:N from with N often zero -- passing
            # it down under-delivered the budget silently.  The seen >= budget
            # return below bounds the pull instead, and the generator
            # suspends, so the over-read is one page at worst.
            for obj in client.fetch_objects(collection,
                                            added_after=added_after):
                for record in flatten_taxii_object(
                        obj, collection_title=collection.get("title"),
                        stats=stats):
                    # Everything but match[type] and added_after is filtered
                    # here, after the object has already crossed the wire.
                    if not taxii_object_allowed(record, config):
                        # build_indicators counts what it is handed, so a
                        # record dropped here would never be counted at all
                        # and the stats line would report fewer records than
                        # crossed the wire -- contradicting the summary.
                        if stats is not None:
                            stats.fetched += 1
                            stats.exclude("taxii post-download filter")
                        continue
                    seen += 1
                    yield record
                    # The only place the cap is enforced: TAXII flattening
                    # is 1:N, so one 50-value pattern would blow a cap of 3
                    # ten times over.  check_size treats the cap as a hard
                    # block, not a trim, so overshooting means a failed build
                    # and no file at all.
                    if budget is not None and seen >= budget:
                        log.warning("indicator cap of %d reached; stopped "
                                    "fetching", budget)
                        return
        return

    if config.get("source") == "opencti":
        filters = build_opencti_filters(config)
        for record in client.search_indicators(
                filters, max_results=config.get("max_indicators"),
                stats=config.get("_stats")):
            yield record
        return

    base = build_search_params(config)
    feeds = config.get("feeds") or []
    if not feeds:
        for record in client.search_attributes(
                base, max_results=config.get("max_indicators")):
            yield record
        return

    budget = config.get("max_indicators")
    include_tags = config.get("include_tags") or []
    seen = 0
    for feed in feeds:
        params = apply_feed_to_params(base, feed)
        # See apply_feed_to_params: a tag-identified feed consumed the tags.OR
        # slot, so the operator's include-tags have to be honoured here.
        post_filter = include_tags if params.get("tags", {}).get(
            "OR") == [feed_provenance(feed)[1]] else []
        remaining = None if budget is None else max(0, budget - seen)
        if remaining == 0:
            log.warning("indicator budget spent before feed %s", feed["name"])
            return
        log.info("fetching feed %s", feed["name"])
        for record in client.search_attributes(params, max_results=remaining):
            if post_filter and not set(post_filter) & set(record["event_tags"]):
                continue
            record["feed"] = feed["name"]
            seen += 1
            yield record


def _load_allowlist(path):
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return [l.strip() for l in handle
                    if l.strip() and not l.startswith("#")]
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("could not read allowlist %s: %s", path, exc)
        return []


def cmd_import(args):
    """Merge an intel.dat built on another host into this manager's file.

    Everything here already exists for cmd_build; the only new thing is where
    the rows come from.  The append-only invariant is enforced identically --
    an import that would remove an indicator is a bug, not a decision, so it
    blocks the write rather than asking.
    """
    incoming = args.import_file
    if not os.path.exists(incoming):
        print("no such file: %s" % incoming, file=sys.stderr)
        return 2
    try:
        incoming_header, incoming_rows = read_existing(incoming)
        # The incoming file's own header settles the schema; a disagreement
        # with the manager's file is caught below, not papered over.
        do_notice = bool(incoming_header
                         and incoming_header == header_line(True))
        problems = lint_file(incoming, do_notice)
    except (OSError, UnicodeDecodeError) as exc:
        # The file arrived from another machine: it is a trust boundary, and
        # the wrong file scp'd here should read as an error, not a traceback.
        print("could not read %s: %s" % (incoming, exc), file=sys.stderr)
        return 2

    if not incoming_rows:
        print("%s contains no indicators" % incoming, file=sys.stderr)
        return 2
    if problems:
        print("Refusing to import, %s fails lint:" % incoming)
        for problem in problems[:10]:
            print("  " + problem)
        return 1
    print("importing %d indicator(s) from %s" % (len(incoming_rows), incoming))

    if not ensure_intel_env(args.yes):
        return 1

    path = SO_INTEL_FILE
    try:
        existing_header, existing = read_existing(path)
    except (OSError, UnicodeDecodeError) as exc:
        print("\nBlocked. %s is unreadable: %s" % (path, exc), file=sys.stderr)
        return 1
    wanted_header = header_line(do_notice)
    if existing_header and existing_header != wanted_header:
        print("\nBlocked. %s was built with a different meta.do_notice "
              "setting than %s; append-only mode will not rewrite existing "
              "rows." % (incoming, path))
        return 1

    combined = merge_additive(existing, incoming_rows)
    lines = [wanted_header] + combined

    # lint_file has already proved every incoming row has the right column
    # count, and INTEL_FIELDS puts the indicator and the Intel::Type in the
    # first two, which is all check_broad_indicators reads.  Import is the
    # caller that check exists for: rows normalised on another machine, by a
    # copy of Nexus this one cannot inspect.
    verdicts = run_guardrails([line.split("\t") for line in incoming_rows],
                              len(existing), intel_dir=SO_INTEL_DIR,
                              append_only=True, total_count=len(combined))
    if _report_guardrails(verdicts):
        return 1

    if _report_lint(lint_lines(lines, do_notice), "merged"):
        return 1

    added, removed = indicator_delta(existing, lines)
    print("\nIndicator diff")
    print(summarise_delta(existing, lines))
    if removed:
        # An invariant failure, not an operator decision: merge_additive
        # cannot drop a row, so a removal here means something upstream is
        # wrong and the file a sensor reads must not be rewritten on it.
        print("\nBlocked. Import unexpectedly removed indicators.")
        return 1

    if _report_dry_run(args.dry_run, args.diff, existing, lines, path):
        return 0

    saved = backup_file(path, os.path.join(NEXUS_HOME, "backups"))
    if saved:
        print("\nbacked up to %s" % saved)
    write_atomic(path, lines)
    print("added %d new indicators; %d total in %s"
          % (len(added), len(combined), path))

    try:
        apply_now = args.yes or ask_yes_no("Apply to the grid now?", False)
    except InterviewAborted:
        # The merge is already on disk.  A traceback here would read as a
        # failed write and invite a hand-copy, which is the one route that
        # drops the manager's own indicators.
        apply_now = False
    if not apply_now:
        print("\nNot applied. To push it:")
        print("  %s" % SO_APPLY_CMD)
        print("Then check: %s" % SO_INTEL_LOG)
        return 0
    print("\nApplying: %s" % SO_APPLY_CMD)
    applied, steps = apply_to_grid(intel_dir=SO_INTEL_DIR,
                                   expected=len(combined))
    for level, message in steps:
        print(LEVEL_PREFIX.get(level, "  ") + message)
    return 0 if applied else 1


if __name__ == "__main__":
    sys.exit(main())
