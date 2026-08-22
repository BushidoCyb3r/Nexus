#!/usr/bin/env python3
"""Tests for nexus.py.  Stdlib only:  python3 -m unittest test_nexus -v

No MISP and no Security Onion required -- the MISP client is exercised against
a local http.server that replays canned responses.
"""

import argparse
import base64
import contextlib
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import nexus


# ---------------------------------------------------------------------------
# MAPPING
# ---------------------------------------------------------------------------

class TestMapping(unittest.TestCase):

    def rec(self, misp_type, value):
        return {"type": misp_type, "value": value}

    def test_simple_types(self):
        cases = [
            ("ip-dst", "1.2.3.4", [("1.2.3.4", "Intel::ADDR")]),
            ("domain", "evil.com", [("evil.com", "Intel::DOMAIN")]),
            ("hostname", "a.evil.com", [("a.evil.com", "Intel::DOMAIN")]),
            ("url", "http://evil.com/a", [("http://evil.com/a", "Intel::URL")]),
            ("md5", "d41d8cd98f00b204e9800998ecf8427e",
             [("d41d8cd98f00b204e9800998ecf8427e", "Intel::FILE_HASH")]),
            ("email-src", "a@evil.com", [("a@evil.com", "Intel::EMAIL")]),
            ("user-agent", "Mozilla/4.0", [("Mozilla/4.0", "Intel::SOFTWARE")]),
        ]
        for misp_type, value, expected in cases:
            with self.subTest(misp_type=misp_type):
                self.assertEqual(nexus.map_attribute(self.rec(misp_type, value)),
                                 expected)

    def test_composite_domain_ip_splits_both_halves(self):
        out = nexus.map_attribute(self.rec("domain|ip", "evil.com|1.2.3.4"))
        self.assertEqual(out, [("evil.com", "Intel::DOMAIN"),
                               ("1.2.3.4", "Intel::ADDR")])

    def test_composite_filename_hash_splits_both_halves(self):
        out = nexus.map_attribute(
            self.rec("filename|md5", "bad.exe|d41d8cd98f00b204e9800998ecf8427e"))
        self.assertEqual(out, [("bad.exe", "Intel::FILE_NAME"),
                               ("d41d8cd98f00b204e9800998ecf8427e",
                                "Intel::FILE_HASH")])

    def test_composite_first_or_second_only(self):
        rec = self.rec("domain|ip", "evil.com|1.2.3.4")
        self.assertEqual(nexus.map_attribute(rec, split_composites="first"),
                         [("evil.com", "Intel::DOMAIN")])
        self.assertEqual(nexus.map_attribute(rec, split_composites="second"),
                         [("1.2.3.4", "Intel::ADDR")])

    def test_port_composite_discards_the_port(self):
        out = nexus.map_attribute(self.rec("ip-dst|port", "1.2.3.4|443"))
        self.assertEqual(out, [("1.2.3.4", "Intel::ADDR")])

    def test_cidr_in_ip_attribute_becomes_subnet(self):
        out = nexus.map_attribute(self.rec("ip-dst", "192.0.2.0/24"))
        self.assertEqual(out, [("192.0.2.0/24", "Intel::SUBNET")])

    def test_cidr_dropped_when_subnets_disabled(self):
        out = nexus.map_attribute(self.rec("ip-dst", "192.0.2.0/24"),
                                  allow_subnet=False)
        self.assertEqual(out, [])

    def test_unmapped_and_empty(self):
        self.assertEqual(nexus.map_attribute(self.rec("ssdeep", "3:abc")), [])
        self.assertEqual(nexus.map_attribute(self.rec("ip-dst", "   ")), [])

    def test_every_mapped_type_targets_a_real_zeek_type(self):
        for misp_type, spec in nexus.MISP_TO_ZEEK.items():
            for _, ztype in spec:
                self.assertIn(ztype, nexus.ZEEK_TYPES,
                              "%s maps to unknown %s" % (misp_type, ztype))
                self.assertIn(ztype, nexus.NORMALISERS,
                              "%s has no normaliser" % ztype)

    def test_composite_specs_match_composite_type_names(self):
        for misp_type, spec in nexus.MISP_TO_ZEEK.items():
            max_index = max(idx for idx, _ in spec)
            expected_parts = misp_type.count("|") + 1
            self.assertLess(max_index, expected_parts,
                            "%s indexes part %d but has %d part(s)"
                            % (misp_type, max_index, expected_parts))

    def test_off_by_default_and_unmappable_are_disjoint(self):
        self.assertFalse(set(nexus.MISP_UNMAPPABLE) & set(nexus.MISP_TO_ZEEK))
        self.assertTrue(set(nexus.MISP_OFF_BY_DEFAULT) <= set(nexus.MISP_TO_ZEEK))
        for _, types in nexus.IOC_CLASSES.values():
            for misp_type in types:
                self.assertIn(misp_type, nexus.MISP_TO_ZEEK)


# ---------------------------------------------------------------------------
# NORMALISATION
# ---------------------------------------------------------------------------

class TestNormalise(unittest.TestCase):

    def assertRejected(self, fn, value, reason=None):
        with self.assertRaises(nexus.Rejected) as ctx:
            fn(value)
        if reason:
            self.assertEqual(ctx.exception.reason, reason)

    # -- addresses ---------------------------------------------------------

    def test_addr_ok(self):
        self.assertEqual(nexus.norm_addr(" 1.2.3.4 "), "1.2.3.4")
        self.assertEqual(nexus.norm_addr("2001:0DB8::0001"), "2001:db8::1")

    def test_addr_defanged(self):
        self.assertEqual(nexus.norm_addr("1[.]2[.]3[.]4"), "1.2.3.4")

    def test_addr_rejections(self):
        self.assertRejected(nexus.norm_addr, "not-an-ip", "invalid_ip")
        self.assertRejected(nexus.norm_addr, "0.0.0.0", "unspecified_ip")
        self.assertRejected(nexus.norm_addr, "127.0.0.1", "loopback_ip")
        self.assertRejected(nexus.norm_addr, "224.0.0.1", "multicast_ip")
        self.assertRejected(nexus.norm_addr, "169.254.1.1", "link_local_ip")
        self.assertRejected(nexus.norm_addr, "10.0.0.0/8", "cidr_in_addr")
        self.assertRejected(nexus.norm_addr, "", "empty")

    def test_addr_rejects_embedded_tab(self):
        self.assertRejected(nexus.norm_addr, "1.2.3.4\tIntel::ADDR",
                            "control_char")

    # -- subnets -----------------------------------------------------------

    def test_subnet_ok(self):
        self.assertEqual(nexus.norm_subnet("192.0.2.0/24"), "192.0.2.0/24")
        self.assertEqual(nexus.norm_subnet("192.0.2.5/24"), "192.0.2.0/24")

    def test_subnet_rejections(self):
        self.assertRejected(nexus.norm_subnet, "1.2.3.4", "not_a_cidr")
        self.assertRejected(nexus.norm_subnet, "0.0.0.0/0", "default_route")
        self.assertRejected(nexus.norm_subnet, "10.0.0.0/8", "subnet_too_broad")
        self.assertRejected(nexus.norm_subnet, "junk/24", "invalid_cidr")

    # -- domains -----------------------------------------------------------

    def test_domain_ok(self):
        self.assertEqual(nexus.norm_domain("EVIL.com."), "evil.com")
        self.assertEqual(nexus.norm_domain("*.evil.com"), "evil.com")
        self.assertEqual(nexus.norm_domain("evil[.]com"), "evil.com")
        self.assertEqual(nexus.norm_domain("_dmarc.evil.com"), "_dmarc.evil.com")

    def test_domain_idna(self):
        self.assertEqual(nexus.norm_domain("bücher.de"), "xn--bcher-kva.de")

    def test_domain_rejections(self):
        self.assertRejected(nexus.norm_domain, "com", "bare_tld")
        self.assertRejected(nexus.norm_domain, "1.2.3.4", "ip_as_domain")
        self.assertRejected(nexus.norm_domain, "evil.com/path", "not_a_domain")
        self.assertRejected(nexus.norm_domain, "ev il.com", "not_a_domain")
        self.assertRejected(nexus.norm_domain, "evil..com", "invalid_label")
        self.assertRejected(nexus.norm_domain, "-evil.com", "invalid_label")
        self.assertRejected(nexus.norm_domain, "a." + "b" * 64, "invalid_label")

    # -- urls --------------------------------------------------------------

    def test_url_strips_scheme(self):
        self.assertEqual(nexus.norm_url("http://evil.com/a/b"), "evil.com/a/b")
        self.assertEqual(nexus.norm_url("https://EVIL.com/A/B"), "evil.com/A/B")

    def test_url_pathless_gets_a_root_slash(self):
        # Zeek matches host+uri and a uri always starts with "/", so a
        # pathless indicator would otherwise never fire.
        self.assertEqual(nexus.norm_url("http://evil.com"), "evil.com/")

    def test_url_drops_fragment_keeps_query(self):
        self.assertEqual(nexus.norm_url("http://evil.com/a?b=1#frag"),
                         "evil.com/a?b=1")

    def test_url_defanged(self):
        self.assertEqual(nexus.norm_url("hxxp://evil[.]com/a"), "evil.com/a")

    def test_url_rejections(self):
        self.assertRejected(nexus.norm_url, "http://", "empty_url")
        self.assertRejected(nexus.norm_url, "http://evil com/a",
                            "whitespace_in_url")
        self.assertRejected(nexus.norm_url, "http://localhost-ish/a",
                            "url_no_host")

    # -- hashes ------------------------------------------------------------

    def test_hash_ok(self):
        self.assertEqual(nexus.norm_hash("D41D8CD98F00B204E9800998ECF8427E"),
                         "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(len(nexus.norm_hash("a" * 64)), 64)

    def test_hash_rejections(self):
        self.assertRejected(nexus.norm_hash, "z" * 32, "hash_not_hex")
        self.assertRejected(nexus.norm_hash, "a" * 33, "hash_bad_length")

    def test_cert_hash_is_sha1_only(self):
        self.assertEqual(nexus.norm_cert_hash("AB:" * 19 + "AB"), "ab" * 20)
        self.assertRejected(nexus.norm_cert_hash, "a" * 64, "cert_not_sha1")

    # -- email / freeform --------------------------------------------------

    def test_email_ok(self):
        self.assertEqual(nexus.norm_email("<Bad@Evil.COM>"), "bad@evil.com")
        self.assertEqual(nexus.norm_email("bad@evil[.]com"), "bad@evil.com")

    def test_email_rejections(self):
        self.assertRejected(nexus.norm_email, "not-an-email", "invalid_email")
        self.assertRejected(nexus.norm_email, "a@b@c.com", "invalid_email")
        self.assertRejected(nexus.norm_email, "@evil.com", "invalid_email")
        self.assertRejected(nexus.norm_email, "bad@com", "bare_tld")

    def test_filename_keeps_case_and_is_not_defanged(self):
        self.assertEqual(nexus.norm_filename("Report(dot)exe"),
                         "Report(dot)exe")
        self.assertRejected(nexus.norm_filename, "a" * 256,
                            "filename_too_long")

    def test_normalise_dispatches_and_rejects_unknown_type(self):
        self.assertEqual(nexus.normalise("1.2.3.4", "Intel::ADDR"), "1.2.3.4")
        self.assertRejected(
            lambda v: nexus.normalise(v, "Intel::NOPE"), "x",
            "unknown_intel_type")

    # -- metadata ----------------------------------------------------------

    def test_sanitize_meta_strips_tabs_and_newlines(self):
        self.assertEqual(nexus.sanitize_meta("a\tb\nc"), "a b c")
        self.assertEqual(nexus.sanitize_meta("  spaced   out  "), "spaced out")

    def test_sanitize_meta_nulls_and_truncates(self):
        self.assertEqual(nexus.sanitize_meta(""), nexus.NULL_FIELD)
        self.assertEqual(nexus.sanitize_meta(None), nexus.NULL_FIELD)
        self.assertEqual(nexus.sanitize_meta("\t\n  "), nexus.NULL_FIELD)
        self.assertEqual(len(nexus.sanitize_meta("x" * 500, maxlen=200)), 200)


# ---------------------------------------------------------------------------
# FILTERS
# ---------------------------------------------------------------------------

class TestExclusions(unittest.TestCase):

    def test_private_addresses_excluded_by_default(self):
        ex = nexus.ExclusionSet()
        self.assertEqual(ex.reason("192.168.1.1", "Intel::ADDR"), "private_ip")
        self.assertIsNone(ex.reason("1.2.3.4", "Intel::ADDR"))

    def test_private_can_be_allowed(self):
        ex = nexus.ExclusionSet(exclude_private=False)
        self.assertIsNone(ex.reason("192.168.1.1", "Intel::ADDR"))

    def test_own_network(self):
        ex = nexus.ExclusionSet(own_networks=["45.33.32.0/24"])
        self.assertEqual(ex.reason("45.33.32.9", "Intel::ADDR"), "own_network")
        self.assertIsNone(ex.reason("8.8.8.8", "Intel::ADDR"))

    def test_own_network_overlap_for_subnets(self):
        ex = nexus.ExclusionSet(own_networks=["45.33.32.0/24"])
        self.assertEqual(ex.reason("45.33.32.0/25", "Intel::SUBNET"),
                         "own_network")

    def test_own_domain_matches_subdomains_only_at_a_label_boundary(self):
        ex = nexus.ExclusionSet(own_domains=["corp.example"])
        self.assertEqual(ex.reason("corp.example", "Intel::DOMAIN"),
                         "own_domain")
        self.assertEqual(ex.reason("mail.corp.example", "Intel::DOMAIN"),
                         "own_domain")
        self.assertIsNone(ex.reason("notcorp.example", "Intel::DOMAIN"))

    def test_own_domain_applies_to_urls_and_emails(self):
        ex = nexus.ExclusionSet(own_domains=["corp.example"])
        self.assertEqual(ex.reason("corp.example/a", "Intel::URL"), "own_domain")
        self.assertEqual(ex.reason("bob@corp.example", "Intel::EMAIL"),
                         "own_domain")

    def test_allowlist(self):
        ex = nexus.ExclusionSet(allowlist=["1.2.3.4"])
        self.assertEqual(ex.reason("1.2.3.4", "Intel::ADDR"), "allowlisted")

    def test_ipv4_ipv6_do_not_cross_match(self):
        ex = nexus.ExclusionSet(own_networks=["45.33.32.0/24"])
        self.assertIsNone(ex.reason("2606:4700::1111", "Intel::ADDR"))

    def test_invalid_exclusion_network_is_ignored_not_fatal(self):
        ex = nexus.ExclusionSet(own_networks=["not-a-network"])
        self.assertEqual(ex.own_networks, [])


# ---------------------------------------------------------------------------
# BUILD + RENDER
# ---------------------------------------------------------------------------

def sample_records():
    return [
        {"type": "ip-dst", "value": "45.33.32.7", "category": "Network activity",
         "to_ids": True, "uuid": "u1", "comment": "c2", "event_id": "42",
         "event_uuid": "e-42", "event_info": "Emotet infrastructure",
         "event_tags": ["tlp:amber", "malware:emotet"], "org": "CIRCL"},
        {"type": "domain|ip", "value": "evil.example|45.33.32.8",
         "category": "Network activity", "to_ids": True, "uuid": "u2",
         "comment": "", "event_id": "42", "event_uuid": "e-42",
         "event_info": "Emotet infrastructure", "event_tags": [], "org": "CIRCL"},
        {"type": "url", "value": "http://evil.example/gate.php",
         "category": "Network activity", "to_ids": True, "uuid": "u3",
         "comment": "", "event_id": "43", "event_uuid": "e-43",
         "event_info": "Panel\twith\ttabs", "event_tags": [], "org": "CIRCL"},
        # duplicate of the first record, different event
        {"type": "ip-src", "value": "45.33.32.7", "category": "Network activity",
         "to_ids": True, "uuid": "u4", "comment": "", "event_id": "44",
         "event_uuid": "e-44", "event_info": "Other", "event_tags": [],
         "org": "CIRCL"},
        # private -- excluded
        {"type": "ip-dst", "value": "10.1.2.3", "category": "Network activity",
         "to_ids": True, "uuid": "u5", "comment": "", "event_id": "45",
         "event_uuid": "e-45", "event_info": "Internal", "event_tags": [],
         "org": "CIRCL"},
        # malformed -- rejected
        {"type": "md5", "value": "nope", "category": "Payload delivery",
         "to_ids": True, "uuid": "u6", "comment": "", "event_id": "46",
         "event_uuid": "e-46", "event_info": "Bad hash", "event_tags": [],
         "org": "CIRCL"},
        # unmappable type -- tallied
        {"type": "ssdeep", "value": "3:abc", "category": "Payload delivery",
         "to_ids": True, "uuid": "u7", "comment": "", "event_id": "47",
         "event_uuid": "e-47", "event_info": "Fuzzy", "event_tags": [],
         "org": "CIRCL"},
    ]


GOLDEN = """#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url
45.33.32.7\tIntel::ADDR\tMISP-event-42\tEmotet infrastructure | Network activity\thttps://misp.example/events/view/42
evil.example\tIntel::DOMAIN\tMISP-event-42\tEmotet infrastructure | Network activity\thttps://misp.example/events/view/42
45.33.32.8\tIntel::ADDR\tMISP-event-42\tEmotet infrastructure | Network activity\thttps://misp.example/events/view/42
evil.example/gate.php\tIntel::URL\tMISP-event-43\tPanel with tabs | Network activity\thttps://misp.example/events/view/43
"""


class TestBuild(unittest.TestCase):

    def build(self, **kwargs):
        params = dict(
            exclusions=nexus.ExclusionSet(),
            source_fmt="MISP-event-{event_id}",
            desc_template="{event_info} | {category}",
            base_url="https://misp.example",
        )
        params.update(kwargs)
        return nexus.build_indicators(sample_records(), **params)

    def test_golden_file_output(self):
        rows, _ = self.build()
        body = "\n".join([nexus.header_line()] + nexus.rows_to_lines(rows)) + "\n"
        self.assertEqual(body, GOLDEN)

    def test_stats_account_for_every_input(self):
        _, stats = self.build()
        self.assertEqual(stats.fetched, 7)
        self.assertEqual(stats.emitted, 4)
        self.assertEqual(stats.duplicates, 1)
        self.assertEqual(stats.excluded, {"private_ip": 1})
        self.assertEqual(stats.rejected, {"hash_not_hex": 1})
        self.assertEqual(stats.unmapped, {"ssdeep": 1})
        self.assertEqual(stats.by_type,
                         {"Intel::ADDR": 2, "Intel::DOMAIN": 1, "Intel::URL": 1})

    def test_report_is_printable(self):
        _, stats = self.build()
        report = stats.report()
        self.assertIn("fetched 7 records -> 4 indicators", report)
        self.assertIn("private_ip", report)

    def test_type_selection_filters_input(self):
        rows, stats = self.build(types=["ip-dst"])
        self.assertEqual([r[1] for r in rows], ["Intel::ADDR"])
        # A mappable type the operator did not select is skipped in silence.
        self.assertNotIn("domain", stats.unmapped)
        # "ssdeep" is in no mapping table, so it is a loss whether or not it
        # was selected, and a loss is always counted.
        self.assertEqual(stats.unmapped, {"ssdeep": 1})

    def test_dedup_is_per_indicator_and_type(self):
        records = [
            {"type": "domain", "value": "evil.example", "event_id": "1"},
            {"type": "hostname", "value": "evil.example", "event_id": "2"},
        ]
        rows, stats = nexus.build_indicators(records)
        self.assertEqual(len(rows), 1)
        self.assertEqual(stats.duplicates, 1)

    def test_do_notice_column(self):
        rows, _ = self.build(do_notice=True)
        lines = nexus.rows_to_lines(rows, do_notice=True)
        self.assertTrue(lines[0].endswith("\tT"))
        self.assertEqual(len(lines[0].split("\t")), 6)

    def test_tab_in_metadata_never_reaches_the_file(self):
        rows, _ = self.build()
        for line in nexus.rows_to_lines(rows):
            self.assertEqual(len(line.split("\t")), 5)

    def test_missing_metadata_becomes_the_null_field(self):
        rows, _ = nexus.build_indicators(
            [{"type": "domain", "value": "evil.example"}])
        line = nexus.rows_to_lines(rows)[0]
        self.assertEqual(line,
                         "evil.example\tIntel::DOMAIN\tMISP\t-\t-")


# ---------------------------------------------------------------------------
# LINT
# ---------------------------------------------------------------------------

class TestLint(unittest.TestCase):

    def lines(self, *body):
        return [nexus.header_line()] + list(body)

    def test_clean_file_has_no_problems(self):
        self.assertEqual(
            nexus.lint_lines(self.lines("1.2.3.4\tIntel::ADDR\tMISP\t-\t-")), [])

    def test_bad_header(self):
        problems = nexus.lint_lines(["#fields\tindicator", "x"])
        self.assertTrue(any("header must be exactly" in p for p in problems))

    def test_wrong_column_count(self):
        problems = nexus.lint_lines(self.lines("1.2.3.4\tIntel::ADDR"))
        self.assertTrue(any("expected 5 tab-separated fields" in p
                            for p in problems))

    def test_invalid_intel_type(self):
        problems = nexus.lint_lines(self.lines("1.2.3.4\tIntel::IP\tMISP\t-\t-"))
        self.assertTrue(any("not a valid Intel::Type" in p for p in problems))

    def test_empty_field_and_blank_line(self):
        problems = nexus.lint_lines(
            self.lines("1.2.3.4\tIntel::ADDR\t\t-\t-", ""))
        self.assertTrue(any("empty field" in p for p in problems))
        self.assertTrue(any("blank line" in p for p in problems))

    def test_whitespace_problems(self):
        problems = nexus.lint_lines(
            self.lines(" 1.2.3.4\tIntel::ADDR\tMISP\t-\t-"))
        self.assertTrue(any("leading or trailing whitespace" in p
                            for p in problems))
        problems = nexus.lint_lines(
            self.lines("1.2.3.4 \tIntel::ADDR\tMISP\t-\t-"))
        self.assertTrue(any("space adjacent to a tab" in p for p in problems))

    def test_filename_with_spaces_is_not_flagged(self):
        self.assertEqual(
            nexus.lint_lines(
                self.lines("my  bad file.exe\tIntel::FILE_NAME\tMISP\t-\t-")),
            [])

    def test_duplicate_indicator(self):
        row = "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"
        problems = nexus.lint_lines(self.lines(row, row))
        self.assertTrue(any("duplicate indicator" in p for p in problems))

    def test_do_notice_column_validated(self):
        good = nexus.header_line(True) + "\n"
        problems = nexus.lint_lines(
            [nexus.header_line(True), "1.2.3.4\tIntel::ADDR\tMISP\t-\t-\tT"],
            do_notice=True)
        self.assertEqual(problems, [])
        problems = nexus.lint_lines(
            [nexus.header_line(True), "1.2.3.4\tIntel::ADDR\tMISP\t-\t-\tyes"],
            do_notice=True)
        self.assertTrue(any("must be T or F" in p for p in problems))
        self.assertTrue(good)

    def test_writer_output_always_passes_the_linter(self):
        rows, _ = nexus.build_indicators(sample_records(),
                                         exclusions=nexus.ExclusionSet())
        lines = [nexus.header_line()] + nexus.rows_to_lines(rows)
        self.assertEqual(nexus.lint_lines(lines), [])


# ---------------------------------------------------------------------------
# FILE I/O
# ---------------------------------------------------------------------------

class TestFileIO(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nexus-test-")
        self.path = os.path.join(self.tmp, "intel.dat")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, lines):
        return nexus.write_atomic(self.path, lines)

    def test_exactly_one_trailing_newline(self):
        self.write([nexus.header_line(), "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"])
        with open(self.path) as handle:
            content = handle.read()
        self.assertTrue(content.endswith("-\n"))
        self.assertFalse(content.endswith("\n\n"))

    def test_written_file_passes_lint_file(self):
        self.write([nexus.header_line(), "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"])
        self.assertEqual(nexus.lint_file(self.path), [])

    def test_lint_file_flags_trailing_blank_line(self):
        with open(self.path, "w") as handle:
            handle.write(nexus.header_line() +
                         "\n1.2.3.4\tIntel::ADDR\tMISP\t-\t-\n\n")
        self.assertTrue(any("blank line" in p
                            for p in nexus.lint_file(self.path)))

    def test_lint_file_flags_missing_final_newline(self):
        with open(self.path, "w") as handle:
            handle.write(nexus.header_line() +
                         "\n1.2.3.4\tIntel::ADDR\tMISP\t-\t-")
        self.assertIn("file does not end with a newline",
                      nexus.lint_file(self.path))

    def test_atomic_write_preserves_mode(self):
        self.write([nexus.header_line()])
        os.chmod(self.path, 0o640)
        self.write([nexus.header_line(), "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)

    def test_no_temp_files_left_behind(self):
        self.write([nexus.header_line()])
        leftovers = [f for f in os.listdir(self.tmp) if f.startswith(".nexus-")]
        self.assertEqual(leftovers, [])

    def test_read_existing(self):
        self.write([nexus.header_line(),
                    "1.2.3.4\tIntel::ADDR\tMISP\t-\t-",
                    "5.6.7.8\tIntel::ADDR\thand-added\t-\t-"])
        header, rows = nexus.read_existing(self.path)
        self.assertTrue(header.startswith("#fields"))
        self.assertEqual(len(rows), 2)

    def test_read_existing_missing_file(self):
        header, rows = nexus.read_existing(os.path.join(self.tmp, "nope.dat"))
        self.assertIsNone(header)
        self.assertEqual(rows, [])

    def test_merge_preserves_hand_added_rows_only(self):
        rows = ["1.2.3.4\tIntel::ADDR\tMISP-event-1\t-\t-",
                "5.6.7.8\tIntel::ADDR\thand-added\t-\t-"]
        preserved = nexus.merge_preserved(rows, source_prefix="MISP")
        self.assertEqual(preserved, ["5.6.7.8\tIntel::ADDR\thand-added\t-\t-"])

    def test_additive_merge_never_removes_or_rewrites_existing(self):
        existing = [
            "old.example\tIntel::DOMAIN\tMISP-old\told metadata\t-",
            "manual.example\tIntel::DOMAIN\tmanual\tkeep me\t-",
        ]
        fresh = [
            "old.example\tIntel::DOMAIN\tMISP-new\tnew metadata\t-",
            "new.example\tIntel::DOMAIN\tMISP-new\tnew IOC\t-",
        ]
        self.assertEqual(nexus.merge_additive(existing, fresh),
                         existing + [fresh[1]])

    def test_backup_and_retention(self):
        backups = os.path.join(self.tmp, "backups")
        self.write([nexus.header_line()])
        first = nexus.backup_file(self.path, backups, retention=2)
        self.assertTrue(os.path.exists(first))
        for _ in range(4):
            nexus.backup_file(self.path, backups, retention=2)
        self.assertLessEqual(len(os.listdir(backups)), 2)

    def test_backup_of_missing_file_is_a_noop(self):
        self.assertIsNone(nexus.backup_file(
            os.path.join(self.tmp, "nope.dat"), self.tmp))

    def test_round_trip_build_write_lint(self):
        rows, _ = nexus.build_indicators(
            sample_records(), exclusions=nexus.ExclusionSet(),
            source_fmt="MISP-event-{event_id}",
            desc_template="{event_info} | {category}",
            base_url="https://misp.example")
        self.write([nexus.header_line()] + nexus.rows_to_lines(rows))
        self.assertEqual(nexus.lint_file(self.path), [])
        _, parsed = nexus.read_existing(self.path)
        self.assertEqual(len(parsed), 4)


# ---------------------------------------------------------------------------
# ENVIRONMENT CHECK
# ---------------------------------------------------------------------------

class TestCheckEnv(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nexus-env-")
        self.intel = os.path.join(self.tmp, "local")
        self.default = os.path.join(self.tmp, "default")
        os.makedirs(self.intel)
        os.makedirs(self.default)
        open(os.path.join(self.default, nexus.SO_LOAD_FILE), "w").close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def messages(self, findings, level=None):
        return [m for lvl, m in findings if level is None or lvl == level]

    def test_missing_load_file_fails_and_suggests_the_fix(self):
        ok, findings = check = nexus.check_env(self.intel, self.default)
        self.assertFalse(ok)
        self.assertTrue(any(nexus.SO_LOAD_FILE in m and "MISSING" in m
                            for m in self.messages(findings, "error")))
        self.assertTrue(any(m.startswith("sudo cp")
                            for m in self.messages(findings, "fix")))
        self.assertTrue(check)

    def test_load_file_present_passes(self):
        open(os.path.join(self.intel, nexus.SO_LOAD_FILE), "w").close()
        ok, findings = nexus.check_env(self.intel, self.default)
        self.assertTrue(ok)
        self.assertTrue(any("present" in m for m in self.messages(findings)))

    def test_notice_policy_is_detected(self):
        open(os.path.join(self.intel, nexus.SO_LOAD_FILE), "w").close()
        policy = os.path.join(self.tmp, "policy")
        os.makedirs(policy)
        with open(os.path.join(policy, "local.zeek"), "w") as handle:
            handle.write("@load policy/frameworks/intel/do_notice.zeek\n")
        _, findings = nexus.check_env(self.intel, self.default, (policy,))
        self.assertTrue(any("do_notice.zeek is loaded" in m
                            for m in self.messages(findings, "info")))

    def test_notice_policy_missing_warns(self):
        open(os.path.join(self.intel, nexus.SO_LOAD_FILE), "w").close()
        _, findings = nexus.check_env(self.intel, self.default, ())
        self.assertTrue(any("do_notice.zeek is not loaded" in m
                            for m in self.messages(findings, "warn")))

    def test_missing_intel_dir_fails_early(self):
        ok, findings = nexus.check_env(os.path.join(self.tmp, "nope"),
                                       self.default)
        self.assertFalse(ok)
        self.assertTrue(any("intel directory missing" in m
                            for m in self.messages(findings, "error")))

    def test_an_unreadable_intel_dat_is_an_error_not_a_traceback(self):
        # check_env is the first thing to open the live file, so an
        # undecodable byte in it came out as a traceback from --check-env and
        # from every build that ran the check.
        open(os.path.join(self.intel, nexus.SO_LOAD_FILE), "w").close()
        with open(os.path.join(self.intel, "intel.dat"), "wb") as handle:
            handle.write(b"\xff\xfe not utf-8 at all\n")
        ok, findings = nexus.check_env(self.intel, self.default)
        self.assertFalse(ok)
        self.assertTrue(any("unreadable" in m
                            for m in self.messages(findings, "error")))

    def test_apply_command_is_the_3x_form(self):
        _, findings = nexus.check_env(self.intel, self.default)
        apply_msgs = [m for m in self.messages(findings) if "state.apply" in m]
        self.assertTrue(apply_msgs)
        self.assertIn("I@zeek:enabled:true", apply_msgs[0])


class TestCheckOutputTarget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_writable_empty_target_is_ok(self):
        ok, findings = nexus.check_output_target(
            os.path.join(self.tmp, "intel.dat"))
        self.assertTrue(ok)
        levels = [level for level, _ in findings]
        self.assertNotIn("error", levels)

    def test_missing_parent_directory_is_an_error(self):
        ok, findings = nexus.check_output_target(
            os.path.join(self.tmp, "nope", "intel.dat"))
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])

    def test_unwritable_parent_directory_is_an_error(self):
        locked = os.path.join(self.tmp, "locked")
        os.mkdir(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        ok, findings = nexus.check_output_target(
            os.path.join(locked, "intel.dat"))
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])

    def test_existing_file_that_fails_lint_is_an_error(self):
        path = os.path.join(self.tmp, "intel.dat")
        with open(path, "w") as handle:
            handle.write(nexus.header_line(False) + "\n")
            handle.write("this-is-not-a-valid-row\n")
        ok, findings = nexus.check_output_target(path)
        self.assertFalse(ok)
        joined = " ".join(message for _, message in findings)
        self.assertIn("lint", joined)

    def test_existing_clean_file_is_reported_but_ok(self):
        path = os.path.join(self.tmp, "intel.dat")
        nexus.write_atomic(path, [nexus.header_line(False),
                                  "evil.example\tIntel::DOMAIN\tt\td\t-"])
        ok, findings = nexus.check_output_target(path)
        self.assertTrue(ok)
        joined = " ".join(message for _, message in findings)
        self.assertIn("1 indicator", joined)

    def test_existing_file_with_bad_encoding_is_an_error(self):
        path = os.path.join(self.tmp, "intel.dat")
        with open(path, "wb") as handle:
            handle.write(b"\xff")
        ok, findings = nexus.check_output_target(path)
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])

    def test_existing_file_with_no_permissions_is_an_error(self):
        path = os.path.join(self.tmp, "intel.dat")
        nexus.write_atomic(path, [nexus.header_line(False),
                                  "evil.example\tIntel::DOMAIN\tt\td\t-"])
        os.chmod(path, 0o000)
        self.addCleanup(os.chmod, path, 0o600)
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        ok, findings = nexus.check_output_target(path)
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])


# ---------------------------------------------------------------------------
# MISP CLIENT (against a local fake)
# ---------------------------------------------------------------------------

class FakeMispHandler(BaseHTTPRequestHandler):
    """Replays canned MISP responses.  Behaviour driven by server.script."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, payload, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.calls.append(("GET", self.path))
        if self.headers.get("Authorization") != self.server.token:
            self._send(403, {"message": "Authentication failed"})
            return
        if self.path == "/servers/getVersion":
            self._send(200, {"version": "2.5.0", "perm_sync": False})
        elif self.path == "/attributes/describeTypes":
            self._send(200, {"result": {"types": ["ip-dst", "domain", "ssdeep"],
                                        "categories": ["Network activity"]}})
        elif self.path == "/tags":
            self._send(200, {"Tag": [{"id": "1", "name": "tlp:amber"}]})
        elif self.path == "/organisations":
            self._send(200, [{"Organisation": {"id": "1", "name": "CIRCL"}}])
        elif self.path == "/feeds":
            self._send(200, getattr(self.server, "feeds", []))
        else:
            self._send(404, {"message": "no such endpoint"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.calls.append(("POST", self.path, body))

        if self.headers.get("Authorization") != self.server.token:
            self._send(403, {"message": "Authentication failed"})
            return

        step = self.server.script.pop(0) if self.server.script else ("ok", [])
        kind = step[0]
        if kind == "flaky":
            self._send(503, {"message": "busy"})
        elif kind == "malformed":
            raw = b"{not json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif kind == "count":
            self._send(200, {"response": {"Attribute": []}},
                       {"X-Result-Count": str(step[1])})
        else:
            self._send(200, {"response": {"Attribute": step[1]}})


class FakeMisp(object):
    def __init__(self, token="test-token-1234", script=None):
        self.server = HTTPServer(("127.0.0.1", 0), FakeMispHandler)
        self.server.token = token
        self.server.script = list(script or [])
        self.server.feeds = []
        self.server.calls = []
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def client(self, token="test-token-1234", **kwargs):
        params = dict(host="127.0.0.1", token=token, scheme="http",
                      port=self.port, timeout=5, retries=2)
        params.update(kwargs)
        return nexus.MispClient(**params)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def attr(value, misp_type="ip-dst", event_id="1"):
    return {"value": value, "type": misp_type, "category": "Network activity",
            "to_ids": "1", "uuid": "u-" + value, "event_id": event_id,
            "Event": {"id": event_id, "info": "Event %s" % event_id,
                      "uuid": "e-" + event_id,
                      "Orgc": {"name": "CIRCL"},
                      "Tag": [{"name": "tlp:amber"}]}}


class TestMispClient(unittest.TestCase):

    def setUp(self):
        self.misp = None

    def tearDown(self):
        if self.misp:
            self.misp.close()

    def test_get_version_and_discovery(self):
        self.misp = FakeMisp()
        client = self.misp.client()
        self.assertEqual(client.get_version()["version"], "2.5.0")
        self.assertEqual(client.describe_types()["types"],
                         ["ip-dst", "domain", "ssdeep"])
        self.assertEqual(client.get_tags()[0]["name"], "tlp:amber")
        self.assertEqual(client.get_orgs()[0]["name"], "CIRCL")

    def test_bad_token_raises_auth_error(self):
        self.misp = FakeMisp()
        client = self.misp.client(token="wrong-token-9999")
        with self.assertRaises(nexus.MispAuthError):
            client.get_version()

    def test_unreachable_host_raises_misp_error(self):
        client = nexus.MispClient(host="127.0.0.1", token="t" * 12,
                                  scheme="http", port=1, timeout=1, retries=1)
        with self.assertRaises(nexus.MispError):
            client.get_version()

    def test_pagination_walks_until_short_page(self):
        page1 = [attr("45.33.32.%d" % i) for i in range(1, 4)]
        page2 = [attr("45.33.32.%d" % i) for i in range(4, 6)]
        self.misp = FakeMisp(script=[("ok", page1), ("ok", page2)])
        client = self.misp.client(page_size=3)
        records = list(client.search_attributes({"type": "ip-dst"}))
        self.assertEqual(len(records), 5)
        pages = [c[2]["page"] for c in self.misp.server.calls if c[0] == "POST"]
        self.assertEqual(pages, [1, 2])

    def test_pagination_stops_on_empty_page(self):
        page1 = [attr("45.33.32.%d" % i) for i in range(1, 4)]
        self.misp = FakeMisp(script=[("ok", page1), ("ok", [])])
        client = self.misp.client(page_size=3)
        self.assertEqual(len(list(client.search_attributes({}))), 3)

    def test_max_results_stops_mid_page(self):
        page1 = [attr("45.33.32.%d" % i) for i in range(1, 6)]
        self.misp = FakeMisp(script=[("ok", page1)])
        client = self.misp.client(page_size=5)
        records = list(client.search_attributes({}, max_results=2))
        self.assertEqual(len(records), 2)

    def test_retry_on_503_then_success(self):
        self.misp = FakeMisp(script=[("flaky",), ("ok", [attr("1.2.3.4")])])
        client = self.misp.client(retries=3)
        records = list(client.search_attributes({}))
        self.assertEqual(len(records), 1)

    def test_malformed_json_raises(self):
        self.misp = FakeMisp(script=[("malformed",)])
        client = self.misp.client()
        with self.assertRaises(nexus.MispError):
            list(client.search_attributes({}))

    def test_count_type_uses_the_result_count_header(self):
        self.misp = FakeMisp(script=[("count", 1234)])
        client = self.misp.client()
        count, exact = client.count_type("ip-dst")
        self.assertEqual((count, exact), (1234, True))

    def test_count_type_falls_back_to_a_bounded_probe(self):
        self.misp = FakeMisp(script=[("ok", [attr("1.2.3.%d" % i)
                                             for i in range(1, 4)])])
        client = self.misp.client()
        count, exact = client.count_type("ip-dst", probe_limit=10)
        self.assertEqual((count, exact), (3, True))

    def test_count_probe_reports_inexact_at_the_ceiling(self):
        self.misp = FakeMisp(script=[("ok", [attr("1.2.3.%d" % i)
                                             for i in range(1, 4)])])
        client = self.misp.client()
        count, exact = client.count_type("ip-dst", probe_limit=3)
        self.assertEqual((count, exact), (3, False))

    def test_end_to_end_fetch_to_intel_lines(self):
        page = [attr("45.33.32.7"), attr("evil.example", "domain", "2")]
        self.misp = FakeMisp(script=[("ok", page)])
        client = self.misp.client(page_size=10)
        rows, stats = nexus.build_indicators(
            client.search_attributes({}),
            exclusions=nexus.ExclusionSet(),
            source_fmt="MISP-event-{event_id}",
            desc_template="{event_info} | {tags}",
            base_url="https://misp.example")
        lines = nexus.rows_to_lines(rows)
        self.assertEqual(stats.emitted, 2)
        self.assertEqual(
            lines[0],
            "45.33.32.7\tIntel::ADDR\tMISP-event-1\tEvent 1 | tlp:amber"
            "\thttps://misp.example/events/view/1")
        self.assertEqual(nexus.lint_lines([nexus.header_line()] + lines), [])


# ---------------------------------------------------------------------------
# OPENCTI CLIENT (against a local fake)
# ---------------------------------------------------------------------------

class FakeOpenctiHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self.server.requests.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "accept": self.headers.get("Accept"),
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


TAXII_DISCOVERY_PATHS = ("/taxii2/", "/taxii/")

# Two API roots, one collection apiece -- the default fixture for
# TestTaxiiDiscovery.  Version-detection tests pass their own narrower
# routes= and never see this.
DEFAULT_TAXII_ROUTES = {
    "/taxii2/": (200, {"title": "Test TAXII", "api_roots": ["/api1/", "/api2/"]}),
    "/taxii/": (200, {"title": "Test TAXII", "api_roots": ["/api1/", "/api2/"]}),
    "/api1/collections/": (200, {"collections": [{"id": "c1", "title": "Feed One"}]}),
    "/api2/collections/": (200, {"collections": [{"id": "c2", "title": "Feed Two"}]}),
}


class FakeTaxiiHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        self.server.requests.append({
            "path": self.path,
            # Parsed, not raw: the client encodes query params with
            # urlencode (brackets become %5B/%5D), so a raw-string
            # assertion could never match what a later stage sends.
            "query": urllib.parse.parse_qs(parsed.query),
            "accept": self.headers.get("Accept"),
            "auth": self.headers.get("Authorization"),
        })
        if parsed.path in TAXII_DISCOVERY_PATHS and not self.server.serve_discovery:
            status, payload = 404, {"title": "not found"}
        elif "/collections/" in parsed.path and parsed.path.endswith("/objects/"):
            # Envelope pagination: each hit serves the next scripted page.
            # Once the script runs out, replay the last page forever rather
            # than fall back to a closed one -- a fake that can end the loop
            # on its own would let a test pass with the client's cursor
            # guard removed, which is exactly the bug this fake exists to
            # catch. Only the client's own guard (or a scripted page's own
            # more: False) may stop the pull.
            pages = self.server.pages
            idx = self.server.objects_index
            status, payload = 200, pages[min(idx, len(pages) - 1)]
            self.server.objects_index += 1
        else:
            status, payload = self.server.routes.get(
                parsed.path, (404, {"title": "not found"}))
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class FakeTaxii(object):
    """A local TAXII endpoint answering scripted per-path responses.

    With no routes given it serves a two-API-root 2.1/2.0 discovery and
    collections fixture (extended by later tasks to serve objects); pass
    routes= to script something narrower, as the version-detection tests do.
    """

    def __init__(self, routes=None):
        self.server = HTTPServer(("127.0.0.1", 0), FakeTaxiiHandler)
        self.server.routes = (dict(routes) if routes is not None
                              else dict(DEFAULT_TAXII_ROUTES))
        self.server.serve_discovery = True
        self.server.requests = []
        # Scripted 2.1 object envelopes for TestTaxii21Fetch; each request
        # to a .../objects/ path serves the next one and advances the index.
        self.server.pages = [{"objects": [], "more": False}]
        self.server.objects_index = 0
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def start(self):
        pass  # already serving from __init__; kept for call-site symmetry

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def requests(self):
        return self.server.requests

    @property
    def accepts(self):
        return [r["accept"] for r in self.server.requests]

    @property
    def serve_discovery(self):
        return self.server.serve_discovery

    @serve_discovery.setter
    def serve_discovery(self, value):
        self.server.serve_discovery = value

    def client(self, **kwargs):
        return nexus.TaxiiClient("127.0.0.1", "tok", scheme="http",
                                 port=self.port, retries=1, **kwargs)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class TestTaxiiVersionDetection(unittest.TestCase):
    """detect_version() probes 2.1 then 2.0; both a plain SourceError and a
    SourceAuthError need distinct handling, and self.version (which ACCEPT
    is derived from) must land in a well-defined place either way."""

    def tearDown(self):
        if getattr(self, "taxii", None):
            self.taxii.stop()

    def test_detects_2_1_when_it_answers(self):
        self.taxii = FakeTaxii(routes={"/taxii2/": (200, {"title": "S"})})
        client = self.taxii.client()
        self.assertEqual(client.detect_version(), "2.1")
        self.assertEqual(client.version, "2.1")
        self.assertEqual(self.taxii.requests[0]["accept"],
                         nexus.TAXII_ACCEPT["2.1"])

    def test_falls_back_to_2_0_and_the_accept_header_tracks_the_probe(self):
        self.taxii = FakeTaxii(routes={
            "/taxii2/": (404, {}),
            "/taxii/": (200, {"title": "old"}),
        })
        client = self.taxii.client()  # constructed at the 2.1 default
        self.assertEqual(client.detect_version(), "2.0")
        self.assertEqual(client.version, "2.0")
        # Each probe's Accept header must match the version being tried at
        # that moment, not the version the client started (or ends) on.
        self.assertEqual(self.taxii.requests[0]["path"], "/taxii2/")
        self.assertEqual(self.taxii.requests[0]["accept"],
                         nexus.TAXII_ACCEPT["2.1"])
        self.assertEqual(self.taxii.requests[1]["path"], "/taxii/")
        self.assertEqual(self.taxii.requests[1]["accept"],
                         nexus.TAXII_ACCEPT["2.0"])

    def test_raises_and_restores_the_original_version_when_neither_answers(self):
        self.taxii = FakeTaxii(routes={})  # both paths 404
        client = self.taxii.client(version="2.1")
        self.assertRaises(nexus.TaxiiError, client.detect_version)
        self.assertEqual(client.version, "2.1")

    def test_auth_error_propagates_instead_of_trying_the_next_version(self):
        self.taxii = FakeTaxii(routes={"/taxii2/": (401, {})})
        client = self.taxii.client()
        self.assertRaises(nexus.SourceAuthError, client.detect_version)
        # A wrong password must not be swallowed and retried as "try 2.0".
        self.assertEqual(len(self.taxii.requests), 1)

    def test_get_version_reads_the_negotiated_endpoint_over_the_wire(self):
        self.taxii = FakeTaxii(routes={"/taxii2/": (200, {"title": "My TAXII"})})
        client = self.taxii.client(version="2.1")
        self.assertEqual(client.get_version(),
                         {"version": "2.1", "title": "My TAXII"})
        self.assertEqual(self.taxii.requests[0]["accept"],
                         nexus.TAXII_ACCEPT["2.1"])


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

    def test_one_unreadable_root_does_not_cost_the_others(self):
        # api2 is broken (500, past the retry budget); api1's collection
        # must still come back rather than the whole call failing.  retries=1
        # so the 500 fails fast instead of eating the backoff schedule.
        self.server.server.routes["/api2/collections/"] = (500, {})
        client = nexus.TaxiiClient(host="127.0.0.1", token="t", scheme="http",
                                   port=self.server.port, retries=1)
        found = client.get_collections()
        self.assertEqual([c["id"] for c in found], ["c1"])

    def test_an_auth_failure_on_one_root_propagates_instead_of_being_skipped(self):
        # Unlike a broken root, a rejected token means the credentials are
        # wrong -- it must not be swallowed as "one root down, keep going".
        self.server.server.routes["/api1/collections/"] = (401, {})
        client = nexus.TaxiiClient(host="127.0.0.1", token="t", scheme="http",
                                   port=self.server.port, retries=1)
        with self.assertRaises(nexus.SourceAuthError):
            client.get_collections()


class TestTaxii21Fetch(unittest.TestCase):
    def setUp(self):
        self.server = FakeTaxii()
        self.addCleanup(self.server.stop)
        self.server.start()
        self.client = nexus.TaxiiClient(host="127.0.0.1", token="t",
                                        scheme="http", port=self.server.port,
                                        version="2.1")

    def test_pages_until_more_is_false(self):
        self.server.server.pages = [
            {"objects": [{"id": "indicator--1"}], "more": True, "next": "n1"},
            {"objects": [{"id": "indicator--2"}], "more": False},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual([o["id"] for o in got],
                         ["indicator--1", "indicator--2"])

    def test_it_asks_the_server_for_indicators_only(self):
        list(self.client.fetch_objects({"id": "c1", "api_root": "/api1/"}))
        params = self.server.requests[-1]["query"]
        self.assertEqual(params["match[type]"], ["indicator"])

    def test_added_after_is_sent_when_given(self):
        list(self.client.fetch_objects({"id": "c1", "api_root": "/api1/"},
                                       added_after="2026-08-01T00:00:00Z"))
        params = self.server.requests[-1]["query"]
        self.assertEqual(params["added_after"], ["2026-08-01T00:00:00Z"])

    def test_max_results_stops_early(self):
        self.server.server.pages = [
            {"objects": [{"id": "a"}, {"id": "b"}, {"id": "c"}], "more": True,
             "next": "n1"},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}, max_results=2))
        self.assertEqual(len(got), 2)

    def test_a_repeated_cursor_stops_the_loop(self):
        # A server that keeps handing back the same next value would spin
        # forever; OpenctiClient carries the same guard. The fake replays
        # its last scripted page indefinitely (see FakeTaxiiHandler), so
        # nothing but the client's own guard can end this pull -- without
        # it, this test hangs rather than passing by accident.
        self.server.server.pages = [
            {"objects": [{"id": "a"}], "more": True, "next": "same"},
            {"objects": [{"id": "b"}], "more": True, "next": "same"},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual(len(got), 2)
        self.assertEqual(len(self.server.requests), 2)

    def test_a_missing_cursor_stops_the_loop(self):
        # more: True with no next at all is the other way a server can
        # fail to hand back a usable cursor; same guard, same fake trap.
        self.server.server.pages = [
            {"objects": [{"id": "a"}], "more": True},
        ]
        got = list(self.client.fetch_objects(
            {"id": "c1", "api_root": "/api1/"}))
        self.assertEqual(len(got), 1)
        self.assertEqual(len(self.server.requests), 1)


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
        with self.assertRaises(nexus.SourceError) as ctx:
            client.get_version()
        # Must be the base type, not the auth subtype -- a generic failure
        # should never be reported to the operator as a rejected token.
        self.assertIs(type(ctx.exception), nexus.SourceError)

    def test_non_auth_message_does_not_raise_auth_error(self):
        # "Author" contains "auth"; a validation error naming a field must not
        # be misread as a rejected API token and sent the operator to rotate
        # credentials over an unrelated GraphQL input error.
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "Author field is required"}], "data": None})])
        client = self.cti.client()
        with self.assertRaises(nexus.SourceError) as ctx:
            client.get_version()
        self.assertIs(type(ctx.exception), nexus.SourceError)

    def test_auth_message_in_a_200_body_raises_auth_error(self):
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "You must be logged in to do this."}],
                   "data": None})])
        client = self.cti.client()
        self.assertRaises(nexus.SourceAuthError, client.get_version)

    def test_not_authenticated_phrasing_raises_auth_error(self):
        # The common OpenCTI wording; "authentication"/"authenticate" alone
        # missed it and the operator got a generic error instead of "rotate
        # your token".
        self.cti = FakeOpencti(script=[
            (200, {"errors": [{"message": "User is not authenticated"}],
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

    def test_count_type_no_global_count_closed_page_one_edge_is_exact(self):
        # first: 1 means a closed page (hasNextPage=False) already saw the
        # whole result set, so this is exact even without globalCount.
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"endCursor": None, "hasNextPage": False},
            "edges": [{"node": {"id": "a"}}]}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("Url"), (1, True))

    def test_count_type_no_global_count_closed_page_zero_edges_is_exact(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"endCursor": None, "hasNextPage": False},
            "edges": []}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("Url"), (0, True))

    def test_count_type_unparseable_global_count_falls_back(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"globalCount": "many", "endCursor": None,
                         "hasNextPage": False},
            "edges": [{"node": {"id": "a"}}]}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("Url"), (1, True))

    def test_count_type_null_global_count_falls_back(self):
        self.cti = FakeOpencti(script=[(200, {"data": {"indicators": {
            "pageInfo": {"globalCount": None, "endCursor": None,
                         "hasNextPage": True},
            "edges": [{"node": {"id": "a"}}]}}})])
        client = self.cti.client()
        self.assertEqual(client.count_type("Url"), (1, False))

    def test_edge_nodes_tolerates_malformed_connection(self):
        self.assertEqual(nexus._edge_nodes("not a dict"), [])
        self.assertEqual(nexus._edge_nodes(
            {"edges": ["not a dict", {"node": "not a dict"},
                       {"node": {"id": "ok"}}]}),
            [{"id": "ok"}])


class TestFlatten(unittest.TestCase):

    def test_flatten_pulls_event_context_and_tags(self):
        record = nexus.flatten_attribute(attr("1.2.3.4"))
        self.assertEqual(record["value"], "1.2.3.4")
        self.assertEqual(record["event_info"], "Event 1")
        self.assertEqual(record["event_tags"], ["tlp:amber"])
        self.assertEqual(record["org"], "CIRCL")
        self.assertIs(record["to_ids"], True)

    def test_to_ids_string_zero_is_false(self):
        raw = attr("1.2.3.4")
        raw["to_ids"] = "0"
        self.assertIs(nexus.flatten_attribute(raw)["to_ids"], False)

    def test_flatten_tolerates_a_bare_attribute(self):
        record = nexus.flatten_attribute({"value": "1.2.3.4", "type": "ip-dst"})
        self.assertEqual(record["event_info"], "")
        self.assertEqual(record["event_tags"], [])

    def test_attribute_and_event_tags_are_merged_without_duplicates(self):
        raw = attr("1.2.3.4")
        raw["Tag"] = [{"name": "tlp:amber"}, {"name": "malware:emotet"}]
        self.assertEqual(nexus.flatten_attribute(raw)["event_tags"],
                         ["tlp:amber", "malware:emotet"])


# ---------------------------------------------------------------------------
# REGRESSIONS
#
# One test per defect found in review.  Each failed before its fix.
# ---------------------------------------------------------------------------

class TestRegressions(unittest.TestCase):

    def test_every_mapped_hash_type_survives_a_real_digest(self):
        # sha224 is 56 hex chars and was missing from VALID_HASH_LENGTHS, so
        # every sha224 attribute was dropped as hash_bad_length.
        import hashlib
        for name in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
            with self.subTest(algorithm=name):
                digest = getattr(hashlib, name)(b"nexus").hexdigest()
                self.assertEqual(nexus.norm_hash(digest), digest)
                self.assertIn(name, nexus.MISP_TO_ZEEK)

    def test_email_is_rebuilt_from_the_normalised_domain(self):
        # norm_email validated the domain half but returned the raw input.
        self.assertEqual(nexus.norm_email("bad@EVIL.com."), "bad@evil.com")
        self.assertEqual(nexus.norm_email("bad@*.evil.com"), "bad@evil.com")

    def test_email_rejects_a_display_name(self):
        with self.assertRaises(nexus.Rejected):
            nexus.norm_email("Bad Person <bad@evil.com>")

    def test_url_strips_userinfo(self):
        # Credentials never appear in the host header Zeek matches against.
        self.assertEqual(nexus.norm_url("http://user:pass@evil.com/a"),
                         "evil.com/a")

    def test_url_host_must_be_a_real_domain_or_address(self):
        with self.assertRaises(nexus.Rejected):
            nexus.norm_url("http://.../a")

    def test_subnet_rejects_loopback_multicast_link_local(self):
        for value, reason in (("127.0.0.0/24", "loopback_subnet"),
                              ("224.0.0.0/16", "multicast_subnet"),
                              ("169.254.0.0/16", "link_local_subnet")):
            with self.subTest(value=value):
                with self.assertRaises(nexus.Rejected) as ctx:
                    nexus.norm_subnet(value)
                self.assertEqual(ctx.exception.reason, reason)

    def test_exclusion_reason_tolerates_an_unnormalised_value(self):
        # Public method; used to raise ValueError out of ipaddress.
        self.assertIsNone(nexus.ExclusionSet().reason("not-an-ip",
                                                      "Intel::ADDR"))
        self.assertIsNone(nexus.ExclusionSet().reason("junk/24",
                                                      "Intel::SUBNET"))

    def test_allowlist_matches_normalised_indicators(self):
        ex = nexus.ExclusionSet(allowlist=["EVIL.com"])
        self.assertEqual(ex.reason("evil.com", "Intel::DOMAIN"), "allowlisted")

    def test_do_notice_column_survives_rows_built_without_it(self):
        rows, _ = nexus.build_indicators([{"type": "domain",
                                           "value": "evil.example"}])
        lines = [nexus.header_line(True)] + nexus.rows_to_lines(rows,
                                                                do_notice=True)
        self.assertEqual(nexus.lint_lines(lines, do_notice=True), [])

    def test_lint_ignores_operator_comments(self):
        self.assertEqual(
            nexus.lint_lines([nexus.header_line(), "# operator note",
                              "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"]), [])

    def test_bad_template_falls_back_instead_of_aborting_the_build(self):
        source, _, _ = nexus.render_meta({"event_id": "1"},
                                         source_fmt="TI-{nope}")
        self.assertEqual(source, "TI-{nope}")

    def test_backup_retention_zero_prunes_everything(self):
        tmp = tempfile.mkdtemp(prefix="nexus-ret-")
        try:
            path = os.path.join(tmp, "intel.dat")
            nexus.write_atomic(path, [nexus.header_line()])
            backups = os.path.join(tmp, "backups")
            os.makedirs(backups)
            for stamp in ("20260101T000000Z", "20260102T000000Z"):
                open(os.path.join(backups, "intel.dat." + stamp), "w").close()
            nexus.backup_file(path, backups, retention=0)
            self.assertEqual(os.listdir(backups), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_backup_retention_keeps_exactly_n_newest(self):
        tmp = tempfile.mkdtemp(prefix="nexus-ret-")
        try:
            path = os.path.join(tmp, "intel.dat")
            nexus.write_atomic(path, [nexus.header_line()])
            backups = os.path.join(tmp, "backups")
            os.makedirs(backups)
            stamps = ["2026010%dT000000Z" % i for i in range(1, 6)]
            for stamp in stamps:
                open(os.path.join(backups, "intel.dat." + stamp), "w").close()
            nexus.backup_file(path, backups, retention=3)
            # 5 pre-existing + 1 fresh, newest 3 kept.
            self.assertEqual(len(os.listdir(backups)), 3)
            self.assertNotIn("intel.dat." + stamps[0], os.listdir(backups))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_write_atomic_follows_a_symlink(self):
        # os.replace on the link would orphan the real file.
        tmp = tempfile.mkdtemp(prefix="nexus-link-")
        try:
            real = os.path.join(tmp, "real.dat")
            link = os.path.join(tmp, "intel.dat")
            nexus.write_atomic(real, [nexus.header_line()])
            os.symlink(real, link)
            nexus.write_atomic(link, [nexus.header_line(),
                                      "1.2.3.4\tIntel::ADDR\tMISP\t-\t-"])
            self.assertTrue(os.path.islink(link))
            _, rows = nexus.read_existing(real)
            self.assertEqual(len(rows), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_write_atomic_leaves_no_temp_file_on_failure(self):
        tmp = tempfile.mkdtemp(prefix="nexus-fail-")
        try:
            path = os.path.join(tmp, "intel.dat")
            with self.assertRaises(TypeError):
                nexus.write_atomic(path, [nexus.header_line(), object()])
            self.assertEqual([f for f in os.listdir(tmp)
                              if f.startswith(".nexus-")], [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_non_ascii_metadata_round_trips(self):
        tmp = tempfile.mkdtemp(prefix="nexus-utf8-")
        try:
            path = os.path.join(tmp, "intel.dat")
            rows, _ = nexus.build_indicators(
                [{"type": "domain", "value": "evil.example",
                  "event_info": "Kampagne \u00fcber M\u00fcnchen"}],
                desc_template="{event_info}")
            nexus.write_atomic(path,
                               [nexus.header_line()] + nexus.rows_to_lines(rows))
            self.assertEqual(nexus.lint_file(path), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_retries_zero_still_sends_one_request(self):
        client = nexus.MispClient(host="127.0.0.1", token="t" * 12,
                                  scheme="http", port=1, timeout=1, retries=0)
        self.assertEqual(client.retries, 1)
        with self.assertRaises(nexus.MispError) as ctx:
            client.get_version()
        self.assertIn("could not reach", str(ctx.exception))

    def test_pagination_terminates_when_misp_ignores_the_page_parameter(self):
        # A repeated full page must stop without imposing a global ceiling.
        full = [attr("45.33.32.%d" % i) for i in range(1, 4)]
        misp = FakeMisp(script=[("ok", full)] * 20)
        try:
            client = misp.client(page_size=3)
            records = list(client.search_attributes({}, max_pages=5))
            self.assertEqual(len(records), 3)
        finally:
            misp.close()

    def test_traceback_carrying_the_token_is_redacted(self):
        # Filters run before formatting, so exc_text is None at filter time --
        # the formatter is what actually catches this.
        import logging as _logging
        token = "traceback-secret-token"
        nexus.REDACTOR.add_secret(token)
        formatter = nexus.RedactingFormatter("%(message)s")
        try:
            raise ValueError("auth failed for " + token)
        except ValueError:
            record = _logging.LogRecord("nexus", _logging.ERROR, __file__, 1,
                                        "request failed", None,
                                        sys.exc_info())
        self.assertNotIn(token, formatter.format(record))

    def test_non_string_log_message_is_redacted(self):
        token = "object-msg-secret-token"
        nexus.REDACTOR.add_secret(token)
        formatter = nexus.RedactingFormatter("%(message)s")
        record = logging_record(ValueError("boom " + token))
        self.assertNotIn(token, formatter.format(record))


# ---------------------------------------------------------------------------
# LOGGING REDACTION
# ---------------------------------------------------------------------------

class TestRedaction(unittest.TestCase):

    def test_token_is_scrubbed_from_log_records(self):
        redactor = nexus.RedactingFilter()
        redactor.add_secret("supersecrettoken123")
        record = logging_record("token is supersecrettoken123 here")
        redactor.filter(record)
        self.assertNotIn("supersecrettoken123", record.msg)
        self.assertIn("***REDACTED***", record.msg)

    def test_token_is_scrubbed_from_args(self):
        redactor = nexus.RedactingFilter()
        redactor.add_secret("supersecrettoken123")
        record = logging_record("url %s", ("https://x/?k=supersecrettoken123",))
        redactor.filter(record)
        self.assertNotIn("supersecrettoken123", record.args[0])

    def test_short_strings_are_not_treated_as_secrets(self):
        redactor = nexus.RedactingFilter()
        redactor.add_secret("abc")
        record = logging_record("abc def")
        redactor.filter(record)
        self.assertEqual(record.msg, "abc def")

    def test_client_registers_its_token_for_redaction(self):
        token = "another-secret-token"
        nexus.MispClient(host="127.0.0.1", token=token, scheme="http", port=1)
        record = logging_record("leaking " + token)
        nexus.REDACTOR.filter(record)
        self.assertNotIn(token, record.msg)


def logging_record(msg, args=None):
    import logging
    return logging.LogRecord("nexus", logging.INFO, __file__, 1, msg, args, None)




# ---------------------------------------------------------------------------
# HARNESS
# ---------------------------------------------------------------------------

def scripted(answers, fill=None, limit=500):
    """Fake `input`.  Replays `answers`, then `fill`, or EOF when fill is None."""
    state = {"reads": 0, "prompts": []}

    def _input(prompt=""):
        state["prompts"].append(prompt)
        state["reads"] += 1
        if state["reads"] > limit:
            raise AssertionError("more than %d prompts -- stuck in a loop" % limit)
        index = state["reads"] - 1
        if index < len(answers):
            return answers[index]
        if fill is None:
            raise EOFError()
        return fill

    _input.state = state
    return _input


def by_prompt(rules, fill=""):
    """Fake `input` that answers on prompt text rather than call order."""
    def _input(prompt=""):
        for needle, answer in rules:
            if needle in prompt:
                return answer
        return fill
    return _input


def boom(exc):
    def _raise(prompt=""):
        raise exc
    return _raise


class Quiet(unittest.TestCase):
    """Swallows the prompt output; `self.printed` exposes it for assertions."""

    def setUp(self):
        self.buffer = io.StringIO()
        redirect = contextlib.redirect_stdout(self.buffer)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    @property
    def printed(self):
        return self.buffer.getvalue()


# ---------------------------------------------------------------------------
# PROMPT PRIMITIVES
# ---------------------------------------------------------------------------

class TestAsk(Quiet):

    def test_returns_the_typed_answer(self):
        self.assertEqual(nexus.ask("Host", None, scripted(["a.example"])),
                         "a.example")

    def test_enter_accepts_the_default(self):
        self.assertEqual(nexus.ask("Host", "misp.local", scripted([""])),
                         "misp.local")

    def test_default_is_shown_in_brackets(self):
        fake = scripted([""])
        nexus.ask("Host", "misp.local", fake)
        self.assertIn("[misp.local]", fake.state["prompts"][0])

    def test_no_default_and_no_answer_is_empty(self):
        self.assertEqual(nexus.ask("Proxy", None, scripted([""])), "")

    def test_answer_is_stripped(self):
        self.assertEqual(nexus.ask("Host", None, scripted(["  a  "])), "a")

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask("Host", None, boom(EOFError()))

    def test_ctrl_c_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask("Host", None, boom(KeyboardInterrupt()))

    def test_ask_required_reprompts_until_answered(self):
        fake = scripted(["", "  ", "misp.local"])
        self.assertEqual(nexus.ask_required("Host", None, fake), "misp.local")
        self.assertEqual(fake.state["reads"], 3)


class TestAskYesNo(Quiet):

    def test_default_true_and_false(self):
        self.assertIs(nexus.ask_yes_no("ok?", True, scripted([""])), True)
        self.assertIs(nexus.ask_yes_no("ok?", False, scripted([""])), False)

    def test_accepts_long_and_short_forms(self):
        for answer, expected in (("y", True), ("Yes", True), ("n", False),
                                 ("NO", False)):
            with self.subTest(answer=answer):
                self.assertIs(nexus.ask_yes_no("ok?", True,
                                                   scripted([answer])), expected)

    def test_invalid_then_valid(self):
        fake = scripted(["maybe", "y"])
        self.assertIs(nexus.ask_yes_no("ok?", False, fake), True)
        self.assertIn("please answer y or n", self.printed)

    def test_hint_reflects_the_default(self):
        fake = scripted([""])
        nexus.ask_yes_no("ok?", False, fake)
        self.assertIn("[y/N]", fake.state["prompts"][0])

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_yes_no("ok?", True, boom(EOFError()))


class TestAskInt(Quiet):

    def test_default_and_value(self):
        self.assertEqual(nexus.ask_int("N", 30, None, None, scripted([""])),
                         30)
        self.assertEqual(nexus.ask_int("N", 30, None, None, scripted(["7"])),
                         7)

    def test_non_numeric_reprompts(self):
        fake = scripted(["abc", "12"])
        self.assertEqual(nexus.ask_int("N", 30, None, None, fake), 12)
        self.assertIn("not a whole number", self.printed)

    def test_below_minimum_reprompts(self):
        fake = scripted(["0", "5"])
        self.assertEqual(nexus.ask_int("N", 30, 1, None, fake), 5)
        self.assertIn("at least 1", self.printed)

    def test_above_maximum_reprompts(self):
        fake = scripted(["99999", "443"])
        self.assertEqual(nexus.ask_int("Port", 443, 1, 65535, fake), 443)
        self.assertIn("at most 65535", self.printed)

    def test_negative_is_allowed_when_no_minimum(self):
        self.assertEqual(nexus.ask_int("N", 0, None, None, scripted(["-3"])),
                         -3)

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_int("N", 1, None, None, boom(EOFError()))


class TestAskChoice(Quiet):

    OPTIONS = ["https", "http"]

    def test_pick_by_number(self):
        self.assertEqual(
            nexus.ask_choice("Scheme", self.OPTIONS, "https",
                                 scripted(["2"])), "http")

    def test_enter_accepts_the_default(self):
        self.assertEqual(
            nexus.ask_choice("Scheme", self.OPTIONS, "http", scripted([""])),
            "http")

    def test_out_of_range_then_valid(self):
        fake = scripted(["9", "nope", "1"])
        self.assertEqual(
            nexus.ask_choice("Scheme", self.OPTIONS, "https", fake), "https")
        self.assertIn("not a valid choice", self.printed)

    def test_no_default_forces_a_pick(self):
        fake = scripted(["", "2"])
        self.assertEqual(
            nexus.ask_choice("Scheme", self.OPTIONS, None, fake), "http")
        self.assertIn("no default", self.printed)

    def test_annotations_are_shown(self):
        nexus.ask_choice("Mode", [("both", "domain + ip")], "both",
                             scripted([""]))
        self.assertIn("domain + ip", self.printed)

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_choice("Scheme", self.OPTIONS, "https",
                                 boom(EOFError()))


class TestParseSelection(unittest.TestCase):

    def test_single_and_list(self):
        self.assertEqual(nexus.parse_selection("1", 5), [0])
        self.assertEqual(nexus.parse_selection("1,3,5", 5), [0, 2, 4])

    def test_range(self):
        self.assertEqual(nexus.parse_selection("1-4", 5), [0, 1, 2, 3])

    def test_mixed_and_spaced(self):
        self.assertEqual(nexus.parse_selection(" 1-2 , 5 ", 5), [0, 1, 4])

    def test_duplicates_collapse(self):
        self.assertEqual(nexus.parse_selection("2,2,1-2", 5), [1, 0])

    def test_invalid_forms_return_none(self):
        for answer in ("0", "6", "1-9", "4-2", "x", "1,,x", "-2", "1-"):
            with self.subTest(answer=answer):
                self.assertIsNone(nexus.parse_selection(answer, 5))


class TestAskMulti(Quiet):

    OPTIONS = ["a", "b", "c", "d", "e"]

    def multi(self, answer, preselected=None):
        return nexus.ask_multi("Pick", self.OPTIONS, preselected,
                                   scripted([answer]))

    def test_numbers(self):
        self.assertEqual(self.multi("1,3,5"), ["a", "c", "e"])

    def test_range(self):
        self.assertEqual(self.multi("1-4"), ["a", "b", "c", "d"])

    def test_all_and_none(self):
        self.assertEqual(self.multi("all"), self.OPTIONS)
        self.assertEqual(self.multi("ALL"), self.OPTIONS)
        self.assertEqual(self.multi("none", ["a"]), [])

    def test_enter_keeps_the_preselected_set(self):
        self.assertEqual(self.multi("", ["b", "d"]), ["b", "d"])

    def test_result_is_in_option_order_not_typed_order(self):
        self.assertEqual(self.multi("5,1"), ["a", "e"])

    def test_invalid_then_valid(self):
        fake = scripted(["7", "2"])
        self.assertEqual(nexus.ask_multi("Pick", self.OPTIONS, None, fake),
                         ["b"])
        self.assertIn("could not read that selection", self.printed)

    def test_preselection_is_marked_in_the_listing(self):
        self.multi("", ["b"])
        self.assertIn("[x] b", self.printed)
        self.assertIn("[ ] a", self.printed)

    def test_annotations_are_shown_per_row(self):
        nexus.ask_multi("Pick", [("ip-dst", "4,182   -> Intel::ADDR")],
                            None, scripted([""]))
        self.assertIn("4,182   -> Intel::ADDR", self.printed)

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_multi("Pick", self.OPTIONS, None, boom(EOFError()))


class TestAskListAndDate(Quiet):

    def test_list_splits_and_strips(self):
        self.assertEqual(
            nexus.ask_list("Nets", "none", None, scripted([" a , b ,, c "])),
            ["a", "b", "c"])

    def test_none_words_mean_empty(self):
        for answer in ("", "none", "-", "NONE"):
            with self.subTest(answer=answer):
                self.assertEqual(
                    nexus.ask_list("Nets", "none", None, scripted([answer])),
                    [])

    def test_validator_reprompts(self):
        fake = scripted(["not-a-net", "10.0.0.0/8"])
        self.assertEqual(
            nexus.ask_list("Nets", "none", nexus._valid_cidr, fake),
            ["10.0.0.0/8"])
        self.assertIn("not a network", self.printed)

    def test_path_validator(self):
        fake = scripted(["/nope/nope.txt", __file__])
        self.assertEqual(
            nexus.ask_list("File", "none", nexus._valid_path, fake),
            [__file__])

    def test_date_accepts_iso_and_relative(self):
        self.assertEqual(nexus.ask_date("From", "", scripted(["2026-01-02"])),
                         "2026-01-02")
        self.assertEqual(nexus.ask_date("From", "", scripted(["30d"])), "30d")

    def test_date_reprompts_on_junk(self):
        fake = scripted(["02/01/2026", "2026-01-02"])
        self.assertEqual(nexus.ask_date("From", "", fake), "2026-01-02")
        self.assertIn("expected YYYY-MM-DD", self.printed)

    def test_date_empty_is_unset(self):
        self.assertEqual(nexus.ask_date("From", "", scripted([""])), "")


class TestAskToken(Quiet):

    def test_reads_without_echo_and_strips(self):
        self.assertEqual(nexus.ask_token("Token", scripted([" abc123 "])),
                         "abc123")

    def test_empty_token_reprompts(self):
        fake = scripted(["", "abc123"])
        self.assertEqual(nexus.ask_token("Token", fake), "abc123")
        self.assertIn("cannot be empty", self.printed)

    def test_eof_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_token("Token", boom(EOFError()))

    def test_ctrl_c_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            nexus.ask_token("Token", boom(KeyboardInterrupt()))


# ---------------------------------------------------------------------------
# DISCOVERY
# ---------------------------------------------------------------------------

class StubClient(object):
    """Enough MispClient surface for stage 1 defaults and stage 2 discovery."""

    host = "misp.example"
    scheme = "https"
    port = 8443
    verify_tls = True
    token = "stub-token-1234"
    timeout = 45
    retries = 2

    def get_version(self):
        return {"version": "2.5.0"}

    def get_tags(self):
        return [{"name": "tlp:amber"}, {"name": None}]

    def get_orgs(self):
        return [{"name": "CIRCL"}]

    def get_sharing_groups(self):
        return [{"name": "internal"}]

    def get_feeds(self):
        return [
            # fixed event -- the most precise provenance
            {"id": "1", "name": "CIRCL OSINT Feed", "provider": "CIRCL",
             "enabled": True, "caching_enabled": True, "source_format": "misp",
             "tag_id": None, "tag_name": "", "orgc_id": None,
             "fixed_event": True, "event_id": "500"},
            # tag-identified
            {"id": "2", "name": "Botvrij.eu", "provider": "Botvrij",
             "enabled": True, "caching_enabled": False, "source_format": "csv",
             "tag_id": "12", "tag_name": "osint:source=botvrij",
             "orgc_id": None, "fixed_event": False, "event_id": None},
            # org-identified
            {"id": "3", "name": "Partner Feed", "provider": "Partner",
             "enabled": False, "caching_enabled": False, "source_format": "misp",
             "tag_id": None, "tag_name": "", "orgc_id": "9",
             "fixed_event": False, "event_id": None},
            # untraceable once ingested
            {"id": "4", "name": "Anonymous Feed", "provider": "",
             "enabled": True, "caching_enabled": False, "source_format": "freetext",
             "tag_id": None, "tag_name": "", "orgc_id": None,
             "fixed_event": False, "event_id": None},
        ]

    def describe_types(self):
        return {"types": ["ip-dst", "domain", "ssdeep"]}

    def count_type(self, misp_type, probe_limit=5000):
        return (7, True)


class BrokenClient(StubClient):
    def get_tags(self):
        raise nexus.MispError("boom")

    def describe_types(self):
        raise nexus.MispError("boom")


class TestDiscover(Quiet):

    def test_no_client_returns_empty_lists(self):
        found = nexus.discover(None)
        self.assertEqual(found["types"], [])
        self.assertEqual(found["counts"], {})
        self.assertEqual(found["tags"], [])

    def test_live_lists_are_flattened_to_names(self):
        found = nexus.discover(StubClient())
        self.assertEqual(found["tags"], ["tlp:amber"])
        self.assertEqual(found["orgs"], ["CIRCL"])
        self.assertEqual(found["sharing_groups"], ["internal"])

    def test_counts_only_cover_mappable_types_present_on_the_instance(self):
        found = nexus.discover(StubClient())
        self.assertEqual(sorted(found["counts"]), ["domain", "ip-dst"])
        self.assertEqual(found["counts"]["ip-dst"], (7, True))

    def test_a_failing_endpoint_does_not_abort_discovery(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        found = nexus.discover(BrokenClient())
        self.assertEqual(found["tags"], [])
        # describeTypes failed, so every mappable type stays on the menu
        self.assertEqual(len(found["counts"]), len(nexus.mappable_types()))


# ---------------------------------------------------------------------------
# SEARCH PARAMETERS
# ---------------------------------------------------------------------------

class TestBuildSearchParams(unittest.TestCase):

    def params(self, **kwargs):
        return nexus.build_search_params(kwargs)

    def test_minimum_config_still_asks_for_event_context(self):
        params = self.params()
        self.assertEqual(params["returnFormat"], "json")
        self.assertTrue(params["includeEventUuid"])
        self.assertTrue(params["includeEventTags"])
        self.assertEqual(params["deleted"], 0)

    def test_type_list_is_passed_through(self):
        self.assertEqual(self.params(types=["ip-dst", "domain"])["type"],
                         ["ip-dst", "domain"])

    def test_quality_flags_only_appear_when_true(self):
        params = self.params(to_ids=True, published=True,
                             enforce_warninglist=True)
        self.assertEqual((params["to_ids"], params["published"],
                          params["enforceWarninglist"]), (1, 1, 1))
        off = self.params(to_ids=False, published=False,
                          enforce_warninglist=False)
        for key in ("to_ids", "published", "enforceWarninglist"):
            self.assertNotIn(key, off)

    def test_deleted_flag(self):
        self.assertEqual(self.params(exclude_deleted=True)["deleted"], 0)
        self.assertEqual(self.params(exclude_deleted=False)["deleted"], [0, 1])

    def test_tags_use_or_and_not(self):
        params = self.params(include_tags=["tlp:amber"],
                             exclude_tags=["false-positive"])
        self.assertEqual(params["tags"], {"OR": ["tlp:amber"],
                                          "NOT": ["false-positive"]})

    def test_only_include_tags(self):
        self.assertEqual(self.params(include_tags=["a"])["tags"], {"OR": ["a"]})

    def test_only_exclude_tags(self):
        self.assertEqual(self.params(exclude_tags=["a"])["tags"], {"NOT": ["a"]})

    def test_no_tags_key_when_neither_side_is_set(self):
        self.assertNotIn("tags", self.params(include_tags=[], exclude_tags=[]))

    def test_last_window_on_attribute_timestamp(self):
        params = self.params(time_mode="last", days=90,
                             timestamp_field="timestamp")
        self.assertEqual(params["timestamp"], "90d")
        self.assertNotIn("last", params)

    def test_last_window_on_publish_timestamp(self):
        params = self.params(time_mode="last", days=7,
                             timestamp_field="publish_timestamp")
        self.assertEqual(params["last"], "7d")
        self.assertNotIn("timestamp", params)

    def test_explicit_range(self):
        params = self.params(time_mode="range", date_from="2026-01-01",
                             date_to="2026-02-01")
        self.assertEqual((params["from"], params["to"]),
                         ("2026-01-01", "2026-02-01"))

    def test_half_open_range(self):
        params = self.params(time_mode="range", date_from="2026-01-01",
                             date_to="")
        self.assertEqual(params["from"], "2026-01-01")
        self.assertNotIn("to", params)

    def test_all_time_sets_no_window(self):
        params = self.params(time_mode="all", days=90)
        for key in ("last", "timestamp", "from", "to"):
            self.assertNotIn(key, params)

    def test_org_sharing_group_and_event_ids(self):
        params = self.params(orgs=["CIRCL"], sharing_groups=["internal"],
                             event_ids=["42", "e-43"])
        self.assertEqual(params["org"], ["CIRCL"])
        self.assertEqual(params["sharinggroup"], ["internal"])
        self.assertEqual(params["eventid"], ["42", "e-43"])

    def test_empty_scope_lists_are_omitted(self):
        params = self.params(orgs=[], sharing_groups=[], event_ids=[])
        for key in ("org", "sharinggroup", "eventid"):
            self.assertNotIn(key, params)

    def test_minimum_threat_level_expands_to_everything_at_or_above_it(self):
        self.assertEqual(self.params(threat_level=2)["threat_level_id"], [1, 2])
        self.assertEqual(self.params(threat_level=1)["threat_level_id"], [1])
        self.assertNotIn("threat_level_id", self.params(threat_level=None))

    def test_analysis_zero_is_kept_not_dropped_as_falsy(self):
        self.assertEqual(self.params(analysis=0)["analysis"], 0)
        self.assertNotIn("analysis", self.params(analysis=None))

    def test_lists_are_copied_not_aliased(self):
        types = ["ip-dst"]
        params = nexus.build_search_params({"types": types})
        params["type"].append("domain")
        self.assertEqual(types, ["ip-dst"])

    def test_is_pure_and_does_not_mutate_the_config(self):
        config = {"types": ["ip-dst"], "to_ids": True}
        before = dict(config)
        nexus.build_search_params(config)
        self.assertEqual(config, before)


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

    def test_non_iso_date_from_is_skipped_and_warns(self):
        # ask_date accepts MISP-style relative windows ("30d"); those are
        # meaningless as an OpenCTI timestamp comparison, so silently passing
        # one through would build a filter that matches nothing.
        with self.assertLogs("nexus", level="WARNING") as cm:
            out = nexus.build_opencti_filters(
                {"time_mode": "range", "date_from": "30d",
                 "timestamp_field": "created_at"}, now=self.FIXED_NOW)
        self.assertEqual(self.keys(out), [])
        self.assertIn("30d", cm.output[0])


# ---------------------------------------------------------------------------
# FULL INTERVIEW
# ---------------------------------------------------------------------------

class TestRunInterview(Quiet):

    def run_it(self, input_fn, client=None, token="scripted-token-1234"):
        # source="misp" -- this class exercises the MISP path itself; the
        # new source question is covered separately by TestOpenctiStage1.
        return nexus.run_interview(
            client, input_fn=input_fn, getpass_fn=lambda prompt: token,
            source="misp")

    def test_all_defaults_produces_a_usable_config(self):
        fake = scripted(["misp.example"], fill="")
        config = self.run_it(fake)

        self.assertEqual(config["source_host"], "misp.example")
        self.assertEqual(config["scheme"], "https")
        self.assertEqual(config["port"], 443)
        self.assertIs(config["verify_tls"], True)
        self.assertIsNone(config["proxy"])
        self.assertEqual(config["token"], "scripted-token-1234")
        self.assertEqual((config["timeout"], config["retries"]), (30, 3))

        self.assertEqual(config["ioc_classes"], list(nexus.IOC_CLASS_ORDER))
        expected = [t for _, types in
                    (nexus.IOC_CLASSES[k] for k in nexus.IOC_CLASS_ORDER)
                    for t in types if t not in nexus.MISP_OFF_BY_DEFAULT]
        self.assertEqual(config["types"], expected)
        self.assertEqual(config["split_composites"], "both")
        self.assertIs(config["hostname_as_domain"], True)
        self.assertIs(config["allow_subnet"], True)

        self.assertIs(config["to_ids"], True)
        self.assertIs(config["published"], True)
        self.assertIs(config["enforce_warninglist"], True)
        self.assertIs(config["exclude_deleted"], True)
        self.assertIsNone(config["threat_level"])
        self.assertIsNone(config["analysis"])

        self.assertEqual(config["time_mode"], "last")
        self.assertEqual(config["days"], nexus.DEFAULT_DAYS)
        self.assertEqual(config["timestamp_field"], "timestamp")
        self.assertEqual(config["include_tags"], [])
        self.assertEqual(config["exclude_tags"],
                         list(nexus.SUGGESTED_EXCLUDE_TAGS))
        self.assertEqual(config["orgs"], [])
        self.assertEqual(config["sharing_groups"], [])
        self.assertEqual(config["event_ids"], [])

        self.assertIs(config["exclude_private"], True)
        self.assertEqual(config["own_networks"], [])
        self.assertEqual(config["own_domains"], [])
        self.assertIsNone(config["allowlist_file"])

        self.assertEqual(config["source_fmt"], "MISP-event-{event_id}")
        self.assertEqual(config["desc_template"],
                         nexus.DEFAULT_DESC_TEMPLATE)
        self.assertEqual(config["source_base_url"], "https://misp.example")
        self.assertIs(config["do_notice"], False)
        self.assertEqual(config["meta_maxlen"], 200)

        self.assertEqual(config["output_path"], nexus.SO_INTEL_FILE)
        self.assertEqual(config["deployment"], "distributed")
        self.assertEqual(config["merge_mode"], "append-only")
        self.assertIs(config["backup"], True)
        self.assertIsNone(config["max_indicators"])
        self.assertIs(config["dry_run"], False)
        self.assertEqual(config["profile_path"],
                         os.path.join(nexus.PROFILE_DIR, "nexus.json"))
        self.assertIs(config["apply"], False)

    def test_default_config_feeds_a_valid_search_body(self):
        config = self.run_it(scripted(["misp.example"], fill=""))
        params = nexus.build_search_params(config)
        self.assertEqual(params["timestamp"], "90d")
        self.assertEqual(params["tags"],
                         {"NOT": list(nexus.SUGGESTED_EXCLUDE_TAGS)})
        self.assertIn("ip-dst", params["type"])
        self.assertNotIn("filename", params["type"])

    def test_answers_that_are_not_defaults_are_honoured(self):
        rules = [
            ("MISP address", "10.9.8.7"),
            ("Scheme", "2"),                      # http
            ("Port", "8080"),
            ("Verify the TLS", "n"),
            ("type INSECURE", "INSECURE"),
            ("HTTP proxy", "http://proxy.local:3128"),
            ("IOC classes", "1"),                 # network only
            ("Network -", "1"),                   # first network type
            ("Composite types", "2"),             # first half only
            ("Treat hostname", "n"),
            ("Emit Intel::SUBNET", "n"),
            ("to_ids", "n"),
            ("Minimum event threat level", "3"),  # medium
            ("Event analysis state", "4"),        # completed
            ("Time window", "3"),                 # all
            ("Include tags", "tlp:amber, tlp:red"),
            ("Exclude tags", "none"),
            ("Restrict to event IDs", "42,e-43"),
            ("own networks", "10.0.0.0/8"),
            ("own domain", "corp.example"),
            ("meta.source format", "4"),          # fixed string
            ("Fixed meta.source", "OURSOC"),
            ("Link meta.url", "n"),
            ("Emit the meta.do_notice", "y"),
            ("Max metadata field length", "80"),
            ("Output path", "/tmp/intel.dat"),
            ("Security Onion deployment", "2"),  # standalone
            ("Save these answers", "n"),
            ("Apply to the standalone node", "y"),
        ]
        config = self.run_it(by_prompt(rules))

        self.assertEqual(config["source_host"], "10.9.8.7")
        self.assertEqual(config["scheme"], "http")
        self.assertEqual(config["port"], 8080)
        self.assertIs(config["verify_tls"], False)
        self.assertEqual(config["proxy"], "http://proxy.local:3128")
        self.assertEqual(config["ioc_classes"], ["network"])
        self.assertEqual(config["types"], ["ip-src"])
        self.assertEqual(config["split_composites"], "first")
        self.assertIs(config["hostname_as_domain"], False)
        self.assertIs(config["allow_subnet"], False)
        self.assertIs(config["to_ids"], False)
        self.assertEqual(config["threat_level"], 2)
        self.assertEqual(config["analysis"], 2)
        self.assertEqual(config["time_mode"], "all")
        self.assertIsNone(config["days"])
        self.assertEqual(config["include_tags"], ["tlp:amber", "tlp:red"])
        self.assertEqual(config["exclude_tags"], [])
        self.assertEqual(config["event_ids"], ["42", "e-43"])
        self.assertEqual(config["own_networks"], ["10.0.0.0/8"])
        self.assertEqual(config["own_domains"], ["corp.example"])
        self.assertEqual(config["source_fmt"], "OURSOC")
        self.assertIsNone(config["source_base_url"])
        self.assertIs(config["do_notice"], True)
        self.assertEqual(config["meta_maxlen"], 80)
        self.assertEqual(config["output_path"], "/tmp/intel.dat")
        self.assertEqual(config["deployment"], "standalone")
        self.assertEqual(config["merge_mode"], "append-only")
        self.assertIsNone(config["profile_path"])
        self.assertIs(config["apply"], True)

    def test_declining_insecure_confirmation_keeps_verification_on(self):
        config = self.run_it(by_prompt([("MISP address", "a.example"),
                                        ("Verify the TLS", "n"),
                                        ("type INSECURE", "")]))
        self.assertIs(config["verify_tls"], True)

    def test_hostname_types_are_dropped_when_not_treated_as_domains(self):
        config = self.run_it(by_prompt([("MISP address", "a.example"),
                                        ("Treat hostname", "n")]))
        self.assertNotIn("hostname", config["types"])
        self.assertNotIn("hostname|port", config["types"])
        self.assertIn("domain", config["types"])

    def test_explicit_date_range(self):
        config = self.run_it(by_prompt([("MISP address", "a.example"),
                                        ("Time window", "2"),
                                        ("From (", "2026-01-01"),
                                        ("To (", "2026-02-01")]))
        self.assertEqual(config["time_mode"], "range")
        params = nexus.build_search_params(config)
        self.assertEqual((params["from"], params["to"]),
                         ("2026-01-01", "2026-02-01"))

    def test_non_standard_port_lands_in_the_meta_url(self):
        config = self.run_it(by_prompt([("MISP address", "a.example"),
                                        ("Port", "8443")]))
        self.assertEqual(config["source_base_url"], "https://a.example:8443")

    def test_declining_the_summary_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            self.run_it(by_prompt([("MISP address", "a.example"),
                                   ("Proceed", "n")]))

    def test_eof_partway_through_aborts(self):
        with self.assertRaises(nexus.InterviewAborted):
            self.run_it(scripted(["misp.example", "", ""]))

    def test_abort_at_the_token_prompt(self):
        def refuse(prompt):
            raise KeyboardInterrupt()
        with self.assertRaises(nexus.InterviewAborted):
            nexus.run_interview(None,
                                    input_fn=scripted(["a.example"], fill=""),
                                    getpass_fn=refuse, source="misp")

    def test_a_connected_client_supplies_the_defaults_and_the_token(self):
        def no_token(prompt):
            raise AssertionError("must not re-prompt for a known token")
        config = nexus.run_interview(
            StubClient(), input_fn=scripted([], fill=""), getpass_fn=no_token,
            source="misp")
        self.assertEqual(config["source_host"], "misp.example")
        self.assertEqual(config["port"], 8443)
        self.assertEqual(config["token"], "stub-token-1234")
        self.assertEqual((config["timeout"], config["retries"]), (45, 2))
        # describeTypes only advertises ip-dst and domain as mappable
        self.assertEqual(config["types"], ["ip-dst", "domain"])
        self.assertEqual(config["include_tags"], [])
        self.assertEqual(config["exclude_tags"],
                         list(nexus.SUGGESTED_EXCLUDE_TAGS))


class TestOfflineInterview(Quiet):

    def run_it(self, offline):
        return nexus.run_interview(
            None, input_fn=scripted(["misp.example"], fill=""),
            getpass_fn=lambda prompt: "tok", source="misp", offline=offline)

    def test_offline_defaults_output_to_the_working_directory(self):
        config = self.run_it(offline=True)
        self.assertEqual(config["output_path"], "./intel.dat")

    def test_offline_never_applies(self):
        feed = scripted(["misp.example"], fill="")
        config = nexus.run_interview(
            None, input_fn=feed, getpass_fn=lambda prompt: "tok",
            source="misp", offline=True)
        self.assertIs(config["apply"], False)
        self.assertEqual(config["deployment"], "offline")
        # Not just "the answer came back False" -- the question must never
        # be asked at all off-box.
        self.assertFalse(any("Apply to" in p for p in feed.state["prompts"]))

    def test_offline_flag_is_recorded_in_the_config(self):
        self.assertIs(self.run_it(offline=True)["offline"], True)
        self.assertIs(self.run_it(offline=False)["offline"], False)

    def test_manager_mode_still_defaults_to_the_security_onion_path(self):
        config = self.run_it(offline=False)
        self.assertEqual(config["output_path"], nexus.SO_INTEL_FILE)
        self.assertEqual(config["deployment"], "distributed")

    def test_offline_saves_the_profile_beside_the_output_file(self):
        # "Save these answers as a profile?" defaults to yes, and /opt/nexus
        # is not writable on a workstation -- same reason the offline backups
        # moved.  Left in PROFILE_DIR the save dies in os.makedirs, so
        # --offline --profile ... could never be bootstrapped on its own host.
        config = self.run_it(offline=True)
        self.assertEqual(
            config["profile_path"],
            os.path.join(os.path.dirname(os.path.abspath(
                config["output_path"])), "nexus.json"))

    def test_manager_mode_still_saves_the_profile_under_nexus_home(self):
        self.assertEqual(self.run_it(offline=False)["profile_path"],
                         os.path.join(nexus.PROFILE_DIR, "nexus.json"))

    def test_offline_is_not_dropped_by_a_profile_round_trip(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "p.json")
        nexus.save_profile(self.run_it(offline=True), path)
        self.assertIs(nexus.load_profile(path)["offline"], True)


# ---------------------------------------------------------------------------
# STAGE 1 -- source selection
# ---------------------------------------------------------------------------

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

    def test_flagless_run_interview_asks_and_honours_the_answer(self):
        # The boundary that matters: main() calls run_interview(), not
        # _stage1_connection() directly.  With no `source` argument -- the
        # shape of a real flagless run -- it must still ask, and the answer
        # must actually be read.  OpenCTI (not the "misp" default) proves
        # that: a silently-defaulting implementation would fail this.
        config = nexus.run_interview(
            None, input_fn=scripted(["2", "cti.local"], fill=""),
            getpass_fn=lambda prompt: "tok")
        self.assertEqual(config["source"], "opencti")


# ---------------------------------------------------------------------------
# STAGES 2, 2b, 3 -- OpenCTI discovery, feeds and IOC types
# ---------------------------------------------------------------------------

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
        # "1" -> network class only, "all" -> every discovered network type;
        # everything after that (composite/hostname/subnet) is MISP-shaped
        # boilerplate this test does not care about, so fill="" takes the
        # default for the rest of the (unbranched) tail of the stage.
        fake = scripted(["1", "all"], fill="")
        config = {}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            nexus._stage3_iocs(config, discovery, fake, source="opencti")
        self.assertIn("IPv4-Addr", out.getvalue())
        self.assertTrue(set(config["types"]) <= {
            "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "Url"})

    def test_ioc_stage_still_offers_misp_classes_by_default(self):
        discovery = {"counts": {}, "types": []}
        fake = scripted(["1", "all"], fill="")
        config = {}
        with contextlib.redirect_stdout(io.StringIO()):
            nexus._stage3_iocs(config, discovery, fake)
        self.assertIn("ip-dst", config["types"])

    def test_opencti_hostname_answer_drops_the_capitalised_type(self):
        # OpenCTI's type literal is "Hostname" (capital H), not MISP's
        # "hostname" -- answering "no" here must actually remove it, or an
        # OpenCTI operator declining hostname-as-domain silently keeps them.
        discovery = {"counts": {}, "types": ["Hostname", "Domain-Name"]}
        fake = by_prompt([("Network -", "all"), ("Treat hostname", "n")])
        config = {}
        with contextlib.redirect_stdout(io.StringIO()):
            nexus._stage3_iocs(config, discovery, fake, source="opencti")
        self.assertNotIn("Hostname", config["types"])

    def test_opencti_skips_the_composite_question_entirely(self):
        # No OPENCTI_TO_ZEEK entry has more than one spec, so the composite
        # split question cannot do anything on this path; it must not be
        # asked, and the config value stays at the "both" default.
        discovery = {"counts": {}, "types": []}
        fake = scripted(["1", "all"], fill="")
        config = {}
        with contextlib.redirect_stdout(io.StringIO()):
            nexus._stage3_iocs(config, discovery, fake, source="opencti")
        self.assertEqual(config["split_composites"], "both")
        self.assertNotIn("Composite types", " ".join(fake.state["prompts"]))


# ---------------------------------------------------------------------------
# STAGES 4, 5 -- OpenCTI quality and scope
# ---------------------------------------------------------------------------

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
        fake = by_prompt([
            ("Include labels", "1"),
            ("Exclude labels", "2"),
            ("TLP markings", "1"),
            ("Created by", "1"),
            ("Time window", "1"),
            ("Timestamp field", "1"),
        ])
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


# ---------------------------------------------------------------------------
# STAGE 7 -- meta.source is source-aware
# ---------------------------------------------------------------------------

class TestStage7SourceFormats(Quiet):

    def stage7(self, source, input_fn=None):
        config = {"source": source, "source_host": "h.local",
                  "scheme": "https", "port": 443}
        fake = input_fn or scripted([], fill="")
        nexus._stage7_metadata(config, fake)
        return config, fake

    def test_opencti_default_is_not_a_misp_event(self):
        # meta.url points at OpenCTI, so a MISP-flavoured meta.source sends an
        # analyst chasing an intel.log hit into a MISP with no such event.
        config, _ = self.stage7("opencti")
        self.assertEqual(config["source_fmt"], "OpenCTI-{event_id}")

    def test_opencti_prompts_never_say_misp(self):
        fake = scripted([], fill="")
        self.stage7("opencti", fake)
        joined = " ".join(fake.state["prompts"]) + self.printed
        self.assertNotIn("MISP", joined)

    def test_opencti_fixed_string_default_is_opencti(self):
        config, _ = self.stage7(
            "opencti", by_prompt([("meta.source format", "4")], fill=""))
        self.assertEqual(config["source_fmt"], "OpenCTI")

    def test_offline_says_nothing_about_this_host_s_policy_tree(self):
        # Both the "detected" and the "not detected" line describe the build
        # host's Zeek policy; offline, the file runs on a manager this host
        # cannot see, so neither is a true statement about it.
        config = {"source": "misp", "source_host": "h.local",
                  "scheme": "https", "port": 443}
        nexus._stage7_metadata(
            config, by_prompt([("meta.do_notice", "y")], fill=""),
            offline=True)
        self.assertTrue(config["do_notice"])
        self.assertNotIn("do_notice.zeek", self.printed)

    def test_misp_stage7_is_byte_identical(self):
        config = {"source": "misp", "source_host": "h.local",
                  "scheme": "https", "port": 443}
        fake = scripted([], fill="")
        nexus._stage7_metadata(config, fake)
        self.assertEqual(config["source_fmt"], "MISP-event-{event_id}")
        self.assertEqual(
            fake.state["prompts"],
            ["  meta.source format -- choose 1-4 [1]: ",
             "meta.desc template ({event_info} {category} {tags} {comment} "
             "{type} {org} {uuid}) [{event_info} | {category}]: ",
             "Link meta.url back to the MISP event? [Y/n]: ",
             "Emit the meta.do_notice column? [y/N]: ",
             "Max metadata field length [200]: "])
        self.assertEqual(
            self.printed,
            "\n-- Stage 7: Metadata\n"
            "meta.source format\n"
            "    1) MISP-event-{event_id}          MISP-event-42\n"
            "    2) MISP-{org}                     MISP-CIRCL\n"
            "    3) MISP                           MISP\n"
            "    4) fixed string                   type your own\n")

    def test_a_shipped_opencti_row_names_opencti(self):
        # Built by flatten_indicator rather than by hand: event_id comes from
        # node["id"], the internal uuid meta.url also points at, not from
        # standard_id, and a hand-written fixture can quietly disagree.
        uuid = "6c1f0a2e-2b7d-4a55-9d3e-1f0a2e2b7d45"
        record = nexus.flatten_indicator({
            "id": uuid, "standard_id": "indicator--" + uuid, "name": "i",
            "pattern_type": "stix", "x_opencti_detection": True,
            "createdBy": {"name": "CIRCL"},
            "observables": {"edges": [{"node": {
                "entity_type": "Domain-Name",
                "observable_value": "evil.com"}}]}})[0]
        config, _ = self.stage7("opencti")
        rows, _ = nexus.build_indicators(
            [record], mapping_table=nexus.OPENCTI_TO_ZEEK, source="opencti",
            source_fmt=config["source_fmt"])
        self.assertEqual(rows[0][2], "OpenCTI-" + uuid)
        # The menu example has to show that shape, not a standard_id.
        example = dict(nexus.OPENCTI_SOURCE_FORMATS)["OpenCTI-{event_id}"]
        self.assertNotIn("indicator--", example)
        self.assertRegex(example, r"^OpenCTI-[0-9a-f]{8}-")


# ---------------------------------------------------------------------------
# STAGE 2 -- the interview connects for itself
# ---------------------------------------------------------------------------

class TestInterviewConnectsForDiscovery(Quiet):
    """Stage 5's OpenCTI filters are entity ids; only a live client resolves
    a typed name to one.  With no connection the whole stage is inert."""

    def interview(self, connect, input_fn=None, source="opencti"):
        return nexus.run_interview(
            None,
            input_fn=input_fn or by_prompt(
                [("OpenCTI address", "cti.local"),
                 ("Include labels", "1"),
                 ("TLP markings", "1"),
                 ("Created by", "1")], fill=""),
            getpass_fn=lambda prompt: "tok", source=source, connect=connect)

    def test_scope_names_resolve_to_ids_on_a_connected_run(self):
        seen = {}

        def connect(config):
            seen["config"] = config
            return StubOpenctiClient()

        config = self.interview(connect)
        self.assertEqual(config["include_labels"], ["phishing"])
        self.assertEqual(config["include_label_ids"], ["l1"])
        self.assertEqual(config["marking_ids"], ["m1"])
        self.assertEqual(config["author_ids"], ["o1"])
        # The client is built from stage 1's own answers, not from thin air.
        self.assertEqual(seen["config"]["source_host"], "cti.local")
        self.assertEqual(seen["config"]["token"], "tok")

    def test_filters_built_from_that_config_actually_carry_the_ids(self):
        config = self.interview(lambda c: StubOpenctiClient())
        filters = nexus.build_opencti_filters(config)
        keys = [f["key"][0] for f in filters["filters"]]
        self.assertIn("objectMarking", keys)
        self.assertIn("objectLabel", keys)

    def test_a_dead_host_degrades_to_an_offline_interview(self):
        def connect(config):
            raise nexus.SourceError("no route to host")

        config = self.interview(connect)
        self.assertEqual(config["source_host"], "cti.local")
        self.assertIn("could not connect", self.printed)

    def test_no_connect_callable_means_no_connection_attempt(self):
        # Every existing caller passes nothing and must stay offline.
        config = nexus.run_interview(
            None, input_fn=by_prompt([("OpenCTI address", "cti.local")],
                                     fill=""),
            getpass_fn=lambda prompt: "tok", source="opencti")
        self.assertEqual(config["include_label_ids"], [])

    def test_summary_flags_scope_terms_that_resolved_to_nothing(self):
        config = {"source": "opencti", "source_host": "cti.local",
                  "markings": ["TLP:GREEN"], "marking_ids": [],
                  "include_labels": ["phishing"], "include_label_ids": ["l1"]}
        text = nexus.summarise_config(config)
        self.assertIn("TLP:GREEN", text)
        self.assertIn("not filtered", text)
        # A term that did resolve must not be smeared with the same warning.
        label_line = [l for l in text.splitlines() if "include labels" in l][0]
        self.assertNotIn("not filtered", label_line)


class TestMalformedHostDoesNotCrashTheRun(Quiet):
    """urllib rejects some hostnames before it opens a socket, and it raises
    UnicodeError / http.client.InvalidURL to do it.  Neither is an OSError, so
    both used to sail past `except SourceError` and kill the interview."""

    def client(self, host):
        return nexus.OpenctiClient(host=host, token="tok", retries=1, timeout=1)

    def test_an_empty_dns_label_is_a_source_error(self):
        with self.assertRaises(nexus.SourceError):
            self.client("cti..local").get_version()

    def test_a_space_in_the_host_is_a_source_error(self):
        with self.assertRaises(nexus.SourceError):
            self.client("cti local").get_version()

    def test_the_interview_degrades_to_offline_instead_of_crashing(self):
        config = nexus.run_interview(
            None,
            input_fn=by_prompt([("OpenCTI address", "cti..local")], fill=""),
            getpass_fn=lambda prompt: "tok", source="opencti",
            connect=nexus.make_client)
        self.assertEqual(config["source_host"], "cti..local")
        self.assertIn("could not connect", self.printed)

    def test_a_host_default_is_stripped_before_it_reaches_urllib(self):
        config = {}
        nexus._stage1_connection(config, None, scripted([], fill=""),
                                 lambda *a, **k: "tok", source="opencti",
                                 host="cti.local ")
        self.assertEqual(config["source_host"], "cti.local")

    def test_the_connect_failure_message_is_redacted(self):
        token = "supersecret-token-1234"

        def connect(config):
            # Building the client is what registers the token with REDACTOR,
            # exactly as make_client does; the failure comes after.
            nexus.OpenctiClient(host=config["source_host"],
                                token=config["token"], retries=1, timeout=1)
            raise nexus.SourceError(
                "HTTP 500 from https://cti.local/graphql %s" % config["token"])

        nexus.run_interview(
            None,
            input_fn=by_prompt([("OpenCTI address", "cti.local")], fill=""),
            getpass_fn=lambda prompt: token, source="opencti", connect=connect)
        self.assertIn("could not connect", self.printed)
        self.assertNotIn(token, self.printed)



# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

class TestSummarise(Quiet):

    def config(self):
        return nexus.run_interview(
            None, input_fn=scripted(["misp.example"], fill=""),
            getpass_fn=lambda prompt: "scripted-token-1234", source="misp")

    def test_summary_covers_every_stage(self):
        text = nexus.summarise_config(self.config())
        for needle in ("MISP", "IOC types", "quality", "window", "exclusions",
                       "meta.source", "meta.desc", "output", "restSearch"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_summary_never_prints_the_token(self):
        self.assertNotIn("scripted-token-1234",
                         nexus.summarise_config(self.config()))

    def test_summary_survives_a_sparse_config(self):
        text = nexus.summarise_config({})
        self.assertIn("Pre-flight summary", text)
        self.assertIn("all time", text)




def row(indicator, zeek_type):
    """A minimal build_indicators()-shaped row for the broad-indicator tests."""
    return (indicator, zeek_type, "MISP", "desc", "-", None)


# ---------------------------------------------------------------------------
# GuardrailVerdict
# ---------------------------------------------------------------------------

class TestGuardrailVerdict(unittest.TestCase):

    def test_ok_and_warn_are_truthy_block_is_not(self):
        self.assertTrue(nexus.GuardrailVerdict("ok", "fine"))
        self.assertTrue(nexus.GuardrailVerdict("warn", "careful"))
        self.assertFalse(nexus.GuardrailVerdict("block", "no"))

    def test_ok_mirrors_level(self):
        self.assertTrue(nexus.GuardrailVerdict("ok", "fine").ok)
        self.assertTrue(nexus.GuardrailVerdict("warn", "careful").ok)
        self.assertFalse(nexus.GuardrailVerdict("block", "no").ok)


# ---------------------------------------------------------------------------
# check_size
# ---------------------------------------------------------------------------

class TestCheckSize(unittest.TestCase):

    def test_below_warn_at_is_ok(self):
        v = nexus.check_size(99999, warn_at=100000, cap=250000)
        self.assertEqual(v.level, "ok")

    def test_exactly_at_warn_at_is_ok(self):
        v = nexus.check_size(100000, warn_at=100000, cap=250000)
        self.assertEqual(v.level, "ok")

    def test_one_over_warn_at_is_warn(self):
        v = nexus.check_size(100001, warn_at=100000, cap=250000)
        self.assertEqual(v.level, "warn")

    def test_exactly_at_cap_is_warn_not_block(self):
        v = nexus.check_size(250000, warn_at=100000, cap=250000)
        self.assertEqual(v.level, "warn")
        self.assertTrue(v)

    def test_one_over_cap_is_block(self):
        v = nexus.check_size(250001, warn_at=100000, cap=250000)
        self.assertEqual(v.level, "block")
        self.assertFalse(v)

    def test_default_has_no_hard_cap(self):
        self.assertEqual(nexus.check_size(50).level, "ok")
        self.assertEqual(nexus.check_size(150000).level, "warn")
        self.assertEqual(nexus.check_size(300000).level, "warn")


# ---------------------------------------------------------------------------
# check_not_empty
# ---------------------------------------------------------------------------

class TestCheckNotEmpty(unittest.TestCase):

    def test_empty_over_populated_blocks(self):
        v = nexus.check_not_empty(0, 5000)
        self.assertEqual(v.level, "block")
        self.assertFalse(v)

    def test_near_empty_over_populated_blocks_with_min_absolute(self):
        v = nexus.check_not_empty(3, 5000, min_absolute=10)
        self.assertEqual(v.level, "block")

    def test_exactly_at_min_absolute_is_ok(self):
        v = nexus.check_not_empty(10, 5000, min_absolute=10)
        self.assertEqual(v.level, "ok")

    def test_no_existing_file_is_noop(self):
        v = nexus.check_not_empty(0, None)
        self.assertEqual(v.level, "ok")

    def test_existing_count_zero_is_noop(self):
        v = nexus.check_not_empty(0, 0)
        self.assertEqual(v.level, "ok")

    def test_populated_new_set_over_populated_existing_is_ok(self):
        v = nexus.check_not_empty(4000, 5000)
        self.assertEqual(v.level, "ok")


# ---------------------------------------------------------------------------
# check_delta
# ---------------------------------------------------------------------------

class TestCheckDelta(unittest.TestCase):

    def test_no_existing_file_is_noop(self):
        v = nexus.check_delta(0, None)
        self.assertEqual(v.level, "ok")

    def test_existing_count_zero_is_noop(self):
        v = nexus.check_delta(0, 0)
        self.assertEqual(v.level, "ok")

    def test_growth_is_ok(self):
        v = nexus.check_delta(6000, 5000, max_drop_pct=25.0)
        self.assertEqual(v.level, "ok")

    def test_exactly_at_max_drop_pct_is_ok(self):
        # 25% of 1000 is 250; dropping to 750 is exactly the limit.
        v = nexus.check_delta(750, 1000, max_drop_pct=25.0)
        self.assertEqual(v.level, "ok")

    def test_one_indicator_over_the_limit_blocks(self):
        v = nexus.check_delta(749, 1000, max_drop_pct=25.0)
        self.assertEqual(v.level, "block")
        self.assertFalse(v)

    def test_small_drop_within_limit_is_ok(self):
        v = nexus.check_delta(900, 1000, max_drop_pct=25.0)
        self.assertEqual(v.level, "ok")


# ---------------------------------------------------------------------------
# check_load_file
# ---------------------------------------------------------------------------

class TestCheckLoadFile(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_load_file_blocks(self):
        v = nexus.check_load_file(self.tmp)
        self.assertEqual(v.level, "block")
        self.assertFalse(v)

    def test_present_load_file_is_ok(self):
        open(os.path.join(self.tmp, nexus.SO_LOAD_FILE), "w").close()
        v = nexus.check_load_file(self.tmp)
        self.assertEqual(v.level, "ok")

    def test_custom_load_filename(self):
        open(os.path.join(self.tmp, "custom.zeek"), "w").close()
        v = nexus.check_load_file(self.tmp, load_filename="custom.zeek")
        self.assertEqual(v.level, "ok")


# ---------------------------------------------------------------------------
# check_broad_indicators
# ---------------------------------------------------------------------------

class TestCheckBroadIndicators(unittest.TestCase):

    def test_no_offenders_is_ok(self):
        rows = [
            row("1.2.3.4", "Intel::ADDR"),
            row("192.0.2.0/24", "Intel::SUBNET"),
            row("evil.example.com", "Intel::DOMAIN"),
            row("evil.example.com/path", "Intel::URL"),
        ]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "ok")

    def test_subnet_at_min_prefix_v4_warns(self):
        rows = [row("10.0.0.0/16", "Intel::SUBNET")]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "warn")
        self.assertIn("10.0.0.0/16", v.message)

    def test_subnet_narrower_than_min_prefix_v4_is_fine(self):
        rows = [row("10.0.0.0/24", "Intel::SUBNET")]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "ok")

    def test_subnet_at_prefix_32_v6_warns(self):
        rows = [row("2001:db8::1/32", "Intel::SUBNET")]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "warn")
        self.assertIn("2001:db8::1/32", v.message)

    def test_single_label_domain_warns(self):
        rows = [row("localdomain", "Intel::DOMAIN")]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "warn")
        self.assertIn("localdomain", v.message)

    def test_url_with_dotless_host_warns(self):
        rows = [row("localhost/path", "Intel::URL")]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "warn")
        self.assertIn("localhost/path", v.message)

    def test_offenders_capped_at_ten_in_message(self):
        rows = [row("bad%d" % i, "Intel::DOMAIN") for i in range(15)]
        v = nexus.check_broad_indicators(rows)
        self.assertEqual(v.level, "warn")
        self.assertIn("15 overly broad indicator(s)", v.message)
        self.assertIn("...and 5 more", v.message)
        for i in range(10):
            self.assertIn("bad%d" % i, v.message)


# ---------------------------------------------------------------------------
# run_guardrails
# ---------------------------------------------------------------------------

class TestRunGuardrails(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_clean_run_is_all_ok(self):
        rows = [row("evil.example.com", "Intel::DOMAIN")]
        open(os.path.join(self.tmp, nexus.SO_LOAD_FILE), "w").close()
        verdicts = nexus.run_guardrails(rows, existing_count=1, intel_dir=self.tmp)
        self.assertTrue(all(v.level == "ok" for v in verdicts))

    def test_worst_level_sorts_first(self):
        # Empty new set over a populated existing file blocks on two fronts
        # (check_not_empty and check_delta); a warn-worthy broad domain rides
        # alongside.  Block verdicts must lead the list.
        rows = []
        verdicts = nexus.run_guardrails(rows, existing_count=1000, intel_dir=None)
        self.assertEqual(verdicts[0].level, "block")
        levels = [v.level for v in verdicts]
        # once we hit the first "ok" nothing after it should be block/warn
        first_ok = levels.index("ok") if "ok" in levels else len(levels)
        self.assertNotIn("block", levels[first_ok:])
        self.assertNotIn("warn", levels[first_ok:])

    def test_load_file_skipped_when_intel_dir_none(self):
        rows = [row("evil.example.com", "Intel::DOMAIN")]
        verdicts = nexus.run_guardrails(rows, existing_count=1, intel_dir=None)
        # 4 checks run: size, not_empty, delta, broad -- no load-file check.
        self.assertEqual(len(verdicts), 4)

    def test_load_file_included_when_intel_dir_given(self):
        rows = [row("evil.example.com", "Intel::DOMAIN")]
        verdicts = nexus.run_guardrails(rows, existing_count=1, intel_dir=self.tmp)
        self.assertEqual(len(verdicts), 5)

    def test_missing_load_file_blocks_and_leads(self):
        rows = [row("evil.example.com", "Intel::DOMAIN")]
        verdicts = nexus.run_guardrails(rows, existing_count=1, intel_dir=self.tmp)
        self.assertEqual(verdicts[0].level, "block")

    def test_thresholds_are_forwarded(self):
        rows = [row("bad%d" % i, "Intel::FILE_NAME") for i in range(5)]
        verdicts = nexus.run_guardrails(
            rows, existing_count=None, intel_dir=None, warn_at=3, cap=10)
        size_verdicts = [v for v in verdicts if "indicators" in v.message and "warn threshold" in v.message]
        self.assertTrue(any(v.level == "warn" for v in size_verdicts))


if __name__ == "__main__":
    unittest.main()




# ---------------------------------------------------------------------------
# FEEDS
# ---------------------------------------------------------------------------

def feed(name="F", tag="", org=None, fixed=False, event=None, enabled=True):
    return {"id": "1", "name": name, "provider": "P", "enabled": enabled,
            "caching_enabled": False, "source_format": "misp",
            "tag_id": None, "tag_name": tag, "orgc_id": org,
            "fixed_event": fixed, "event_id": event}


class TestFeedProvenance(unittest.TestCase):

    def test_fixed_event_wins_over_tag_and_org(self):
        f = feed(tag="osint:x", org="9", fixed=True, event="500")
        self.assertEqual(nexus.feed_provenance(f)[:2], ("fixed_event", "500"))

    def test_tag_beats_org(self):
        f = feed(tag="osint:x", org="9")
        self.assertEqual(nexus.feed_provenance(f)[:2], ("tag", "osint:x"))

    def test_org_is_the_last_resort(self):
        self.assertEqual(nexus.feed_provenance(feed(org="9"))[:2], ("org", "9"))

    def test_untraceable_feed_returns_none(self):
        # No fixed event, no tag, no org: nothing distinguishes its
        # attributes from the rest of MISP after ingest.
        self.assertIsNone(nexus.feed_provenance(feed()))
        self.assertFalse(nexus.feed_is_selectable(feed()))

    def test_fixed_event_without_an_event_id_is_untraceable(self):
        self.assertIsNone(nexus.feed_provenance(feed(fixed=True, event=None)))

    def test_every_provenance_kind_is_in_the_documented_order(self):
        for f in (feed(fixed=True, event="1"), feed(tag="t"), feed(org="9")):
            self.assertIn(nexus.feed_provenance(f)[0],
                          nexus.FEED_PROVENANCE_ORDER)


class TestApplyFeedToParams(unittest.TestCase):

    def test_fixed_event_constrains_by_event_id(self):
        out = nexus.apply_feed_to_params({}, feed(fixed=True, event="500"))
        self.assertEqual(out["eventid"], ["500"])

    def test_org_feed_constrains_by_org(self):
        self.assertEqual(nexus.apply_feed_to_params({}, feed(org="9"))["org"],
                         ["9"])

    def test_tag_feed_takes_the_tags_or_slot(self):
        out = nexus.apply_feed_to_params({}, feed(tag="osint:botvrij"))
        self.assertEqual(out["tags"]["OR"], ["osint:botvrij"])

    def test_tag_feed_preserves_exclude_tags(self):
        base = {"tags": {"OR": ["tlp:amber"], "NOT": ["false-positive"]}}
        out = nexus.apply_feed_to_params(base, feed(tag="osint:botvrij"))
        self.assertEqual(out["tags"]["OR"], ["osint:botvrij"])
        self.assertEqual(out["tags"]["NOT"], ["false-positive"])

    def test_other_filters_survive_untouched(self):
        base = {"to_ids": 1, "enforceWarninglist": 1, "timestamp": "90d",
                "type": ["ip-dst"]}
        out = nexus.apply_feed_to_params(base, feed(fixed=True, event="500"))
        for key, value in base.items():
            self.assertEqual(out[key], value)

    def test_the_base_params_are_not_mutated(self):
        base = {"to_ids": 1}
        nexus.apply_feed_to_params(base, feed(fixed=True, event="500"))
        self.assertEqual(base, {"to_ids": 1})

    def test_an_untraceable_feed_raises(self):
        with self.assertRaises(ValueError):
            nexus.apply_feed_to_params({}, feed())


class TestFetchRecords(unittest.TestCase):
    """_fetch_records issues one restSearch per feed and merges the results."""

    class Recorder(object):
        def __init__(self, per_query):
            self.per_query = per_query
            self.queries = []

        def search_attributes(self, params, max_results=None):
            self.queries.append(params)
            for record in self.per_query:
                yield dict(record)

    def rec(self, value, tags=None):
        return {"value": value, "type": "ip-dst", "event_tags": tags or [],
                "event_id": "1"}

    def test_no_feeds_means_one_query_and_no_feed_label(self):
        client = self.Recorder([self.rec("45.33.32.1")])
        out = list(nexus._fetch_records(client, {"types": ["ip-dst"]}))
        self.assertEqual(len(client.queries), 1)
        self.assertNotIn("feed", out[0])

    def test_one_query_per_feed_each_labelled(self):
        client = self.Recorder([self.rec("45.33.32.1")])
        config = {"types": ["ip-dst"],
                  "feeds": [feed(name="CIRCL", fixed=True, event="500"),
                            feed(name="Botvrij", tag="osint:botvrij")]}
        out = list(nexus._fetch_records(client, config))
        self.assertEqual(len(client.queries), 2)
        self.assertEqual([r["feed"] for r in out], ["CIRCL", "Botvrij"])
        self.assertEqual(client.queries[0]["eventid"], ["500"])
        self.assertEqual(client.queries[1]["tags"]["OR"], ["osint:botvrij"])

    def test_include_tags_are_post_filtered_for_a_tag_feed(self):
        # The feed tag consumed tags.OR, so the operator's include-tags can
        # only be honoured client-side.
        client = self.Recorder([self.rec("45.33.32.1", ["tlp:amber"]),
                                self.rec("45.33.32.2", ["tlp:green"])])
        config = {"include_tags": ["tlp:amber"],
                  "feeds": [feed(name="Botvrij", tag="osint:botvrij")]}
        out = list(nexus._fetch_records(client, config))
        self.assertEqual([r["value"] for r in out], ["45.33.32.1"])

    def test_include_tags_stay_server_side_for_an_event_feed(self):
        client = self.Recorder([self.rec("45.33.32.1", ["tlp:green"])])
        config = {"include_tags": ["tlp:amber"],
                  "feeds": [feed(name="CIRCL", fixed=True, event="500")]}
        out = list(nexus._fetch_records(client, config))
        self.assertEqual(len(out), 1)  # MISP already applied the tag filter

    def test_the_indicator_budget_is_shared_across_feeds(self):
        client = self.Recorder([self.rec("45.33.32.%d" % i) for i in range(5)])
        config = {"max_indicators": 3,
                  "feeds": [feed(name="A", fixed=True, event="1"),
                            feed(name="B", fixed=True, event="2")]}
        list(nexus._fetch_records(client, config))
        self.assertEqual(len(client.queries), 1)  # budget spent on feed A


class TestFeedMetadata(unittest.TestCase):

    def test_feed_name_reaches_meta_source(self):
        source, _, _ = nexus.render_meta(
            {"feed": "CIRCL OSINT Feed", "event_id": "1"},
            source_fmt="MISP-feed-{feed}")
        self.assertEqual(source, "MISP-feed-CIRCL-OSINT-Feed")

    def test_feed_slug_never_breaks_the_tab_format(self):
        source, _, _ = nexus.render_meta(
            {"feed": "bad\tname\nhere/slashes", "event_id": "1"},
            source_fmt="MISP-feed-{feed}")
        self.assertNotIn("\t", source)
        self.assertEqual(source, "MISP-feed-bad-name-here-slashes")

    def test_missing_feed_renders_as_none_not_a_crash(self):
        source, _, _ = nexus.render_meta({"event_id": "1"},
                                         source_fmt="MISP-feed-{feed}")
        self.assertEqual(source, "MISP-feed-none")

    def test_feed_lines_lint_clean(self):
        rows, _ = nexus.build_indicators(
            [{"type": "ip-dst", "value": "45.33.32.7", "feed": "CIRCL OSINT",
              "event_id": "1"}],
            source_fmt="MISP-feed-{feed}", exclusions=nexus.ExclusionSet())
        lines = [nexus.header_line()] + nexus.rows_to_lines(rows)
        self.assertEqual(nexus.lint_lines(lines), [])
        self.assertIn("MISP-feed-CIRCL-OSINT", lines[1])


class TestSourceAwareMetaUrl(unittest.TestCase):
    """meta.url must point at a page that exists on the source platform."""

    def test_misp_url_shape_is_unchanged(self):
        _, _, url = nexus.render_meta({"event_id": "42"},
                                      base_url="https://misp.example")
        self.assertEqual(url, "https://misp.example/events/view/42")

    def test_opencti_url_points_at_the_indicator_dashboard(self):
        _, _, url = nexus.render_meta({"event_id": "abc-123"},
                                      base_url="https://cti.local",
                                      source="opencti")
        self.assertEqual(
            url, "https://cti.local/dashboard/observations/indicators/abc-123")

    def test_build_indicators_threads_source_into_the_url(self):
        rows, _ = nexus.build_indicators(
            [{"type": "IPv4-Addr", "value": "1.2.3.4", "event_id": "9"}],
            types=["IPv4-Addr"], exclusions=nexus.ExclusionSet(),
            base_url="https://cti.local", source="opencti",
            mapping_table=nexus.OPENCTI_TO_ZEEK)
        self.assertEqual(rows[0][4],
                         "https://cti.local/dashboard/observations/indicators/9")


class TestFeedDiscovery(Quiet):

    def test_feeds_are_discovered_and_split_by_selectability(self):
        found = nexus.discover(StubClient())
        self.assertEqual(len(found["feeds"]), 4)
        selectable = [f for f in found["feeds"] if nexus.feed_is_selectable(f)]
        self.assertEqual([f["name"] for f in selectable],
                         ["CIRCL OSINT Feed", "Botvrij.eu", "Partner Feed"])

    def test_get_feeds_parses_the_misp_envelope(self):
        misp = FakeMisp()
        try:
            misp.server.feeds = [
                {"Feed": {"id": "1", "name": "CIRCL", "provider": "CIRCL",
                          "enabled": "1", "caching_enabled": "0",
                          "source_format": "misp", "fixed_event": "1",
                          "event_id": "500"},
                 "Tag": {"name": "osint:circl"}}]
            feeds = misp.client().get_feeds()
        finally:
            misp.close()
        self.assertEqual(len(feeds), 1)
        self.assertEqual(feeds[0]["name"], "CIRCL")
        self.assertIs(feeds[0]["enabled"], True)      # "1" -> True
        self.assertIs(feeds[0]["caching_enabled"], False)  # "0" -> False
        self.assertEqual(feeds[0]["tag_name"], "osint:circl")


class TestMispBool(unittest.TestCase):

    def test_misp_string_booleans(self):
        for value in ("1", "true", 1, True):
            self.assertIs(nexus._misp_bool(value), True)
        for value in ("0", "", "false", 0, False, None):
            self.assertIs(nexus._misp_bool(value), False)




# ---------------------------------------------------------------------------
# APPLY
# ---------------------------------------------------------------------------

class ApplyBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nexus-apply-")
        self.intel = os.path.join(self.tmp, "local")
        self.default = os.path.join(self.tmp, "default")
        self.runtime = os.path.join(self.tmp, "runtime")
        for path in (self.intel, self.default, self.runtime):
            os.makedirs(path)
        self.reporter = os.path.join(self.tmp, "reporter.log")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_default(self, name, text=""):
        with open(os.path.join(self.default, name), "w") as handle:
            handle.write(text)

    def write_intel(self, directory, count):
        rows = ["45.33.32.%d\tIntel::ADDR\tMISP\t-\t-" % i
                for i in range(1, count + 1)]
        nexus.write_atomic(os.path.join(directory, "intel.dat"),
                           [nexus.header_line()] + rows)

    def runner(self, rc=0, out="", err="", record=None):
        def _run(argv, timeout):
            if record is not None:
                record.append((argv, timeout))
            return rc, out, err
        return _run


class TestSeedLoadFile(ApplyBase):

    def test_seeds_both_default_files(self):
        self.write_default(nexus.SO_LOAD_FILE, "@load ./intel.dat\n")
        self.write_default("intel.dat", nexus.header_line() + "\n")
        copied = nexus.seed_load_file(self.intel, self.default)
        self.assertEqual(len(copied), 2)
        self.assertTrue(os.path.exists(
            os.path.join(self.intel, nexus.SO_LOAD_FILE)))

    def test_never_overwrites_an_existing_intel_dat(self):
        # The operator's file is the whole point; clobbering it would be the
        # worst possible behaviour for a "seed" helper.
        self.write_default("intel.dat", "DEFAULT\n")
        self.write_default(nexus.SO_LOAD_FILE, "@load ./intel.dat\n")
        self.write_intel(self.intel, 3)
        copied = nexus.seed_load_file(self.intel, self.default)
        self.assertEqual([os.path.basename(p) for p in copied],
                         [nexus.SO_LOAD_FILE])
        _, rows = nexus.read_existing(os.path.join(self.intel, "intel.dat"))
        self.assertEqual(len(rows), 3)

    def test_seeding_twice_is_a_noop(self):
        self.write_default(nexus.SO_LOAD_FILE, "x")
        nexus.seed_load_file(self.intel, self.default)
        self.assertEqual(nexus.seed_load_file(self.intel, self.default), [])

    def test_missing_defaults_raise(self):
        with self.assertRaises(OSError):
            nexus.seed_load_file(self.intel, os.path.join(self.tmp, "nope"))


class TestLogScanning(ApplyBase):

    def test_offset_of_a_missing_log_is_zero(self):
        self.assertEqual(nexus.log_offset(self.reporter), 0)

    def test_only_lines_appended_after_the_offset_are_read(self):
        with open(self.reporter, "w") as handle:
            handle.write("error: intel.dat old problem\n")
        offset = nexus.log_offset(self.reporter)
        with open(self.reporter, "a") as handle:
            handle.write("error: intel.dat new problem\n")
        errors = nexus.log_errors_since(self.reporter, offset)
        self.assertEqual(errors, ["error: intel.dat new problem"])

    def test_unrelated_errors_are_ignored(self):
        with open(self.reporter, "w") as handle:
            handle.write("error: something about pcap\n"
                         "error: Intel::ADDR parse failure\n"
                         "info: intel loaded fine\n")
        errors = nexus.log_errors_since(self.reporter, 0)
        self.assertEqual(errors, ["error: Intel::ADDR parse failure"])

    def test_warnings_count_too(self):
        with open(self.reporter, "w") as handle:
            handle.write("warning: intel file line 4 malformed\n")
        self.assertEqual(len(nexus.log_errors_since(self.reporter, 0)), 1)

    def test_missing_log_yields_no_errors(self):
        self.assertEqual(nexus.log_errors_since(self.reporter, 0), [])


class TestVerifyRuntime(ApplyBase):

    def test_missing_runtime_file_fails(self):
        ok, message = nexus.verify_runtime(self.runtime)
        self.assertFalse(ok)
        self.assertIn("did not reach this node", message)

    def test_count_mismatch_fails(self):
        self.write_intel(self.runtime, 3)
        ok, message = nexus.verify_runtime(self.runtime, expected=5)
        self.assertFalse(ok)
        self.assertIn("expected 5", message)

    def test_matching_count_passes(self):
        self.write_intel(self.runtime, 4)
        ok, _ = nexus.verify_runtime(self.runtime, expected=4)
        self.assertTrue(ok)


class TestSaltApply(ApplyBase):

    def test_runner_receives_the_argv_not_a_shell_string(self):
        record = []
        nexus.salt_apply(runner=self.runner(record=record))
        argv, _ = record[0]
        self.assertEqual(argv, nexus.SO_APPLY_ARGV)
        self.assertIn("I@zeek:enabled:true", argv)
        # No shell means no quoting for the compound target to get wrong.
        self.assertNotIn("'", " ".join(argv))

    def test_return_code_is_passed_through(self):
        rc, out, err = nexus.salt_apply(runner=self.runner(rc=2, err="boom"))
        self.assertEqual((rc, err), (2, "boom"))


class TestApplyToGrid(ApplyBase):

    def apply(self, **kwargs):
        params = dict(intel_dir=self.intel, runtime_dir=self.runtime,
                      reporter_log=self.reporter, runner=self.runner())
        params.update(kwargs)
        return nexus.apply_to_grid(**params)

    def ready(self):
        open(os.path.join(self.intel, nexus.SO_LOAD_FILE), "w").close()
        self.write_intel(self.intel, 2)
        self.write_intel(self.runtime, 2)

    def levels(self, steps):
        return [level for level, _ in steps]

    def test_missing_load_file_blocks_before_running_salt(self):
        record = []
        ok, steps = self.apply(runner=self.runner(record=record))
        self.assertFalse(ok)
        self.assertEqual(record, [])  # salt never ran
        self.assertIn("__load__.Zeek", steps[0][1])

    def test_happy_path(self):
        self.ready()
        ok, steps = self.apply(expected=2)
        self.assertTrue(ok)
        messages = " ".join(m for _, m in steps)
        self.assertIn("completed", messages)
        self.assertIn("no intel errors", messages)
        self.assertNotIn("error", self.levels(steps))

    def test_salt_failure_reports_and_stops(self):
        self.ready()
        ok, steps = self.apply(runner=self.runner(rc=1, err="minion down"))
        self.assertFalse(ok)
        self.assertIn("salt exited 1", steps[1][1])

    def test_salt_missing_falls_back_to_printing_the_command(self):
        self.ready()
        def explode(argv, timeout):
            raise OSError("salt not found on PATH")
        ok, steps = self.apply(runner=explode)
        self.assertFalse(ok)
        self.assertIn("fix", self.levels(steps))
        self.assertIn(nexus.SO_APPLY_CMD, [m for _, m in steps])

    def test_reporter_errors_after_a_clean_salt_run_still_fail(self):
        # A clean state.apply proves nothing: Zeek rejects a bad intel file
        # through the reporter log, not through salt.
        self.ready()
        with open(self.reporter, "w") as handle:
            handle.write("old noise\n")
        def noisy(argv, timeout):
            with open(self.reporter, "a") as handle:
                handle.write("error: intel.dat line 3 malformed\n")
            return 0, "", ""
        ok, steps = self.apply(runner=noisy)
        self.assertFalse(ok)
        self.assertIn("malformed", " ".join(m for _, m in steps))

    def test_preexisting_reporter_errors_do_not_fail_the_run(self):
        self.ready()
        with open(self.reporter, "w") as handle:
            handle.write("error: intel.dat from a previous run\n")
        ok, _ = self.apply(expected=2)
        self.assertTrue(ok)

    def test_runtime_mismatch_warns_without_blocking_the_report(self):
        self.ready()
        self.write_intel(self.runtime, 1)
        ok, steps = self.apply(expected=2)
        self.assertFalse(ok)
        self.assertIn("warn", self.levels(steps))




# ---------------------------------------------------------------------------
# PROFILES
# ---------------------------------------------------------------------------

class TestProfiles(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nexus-profile-")
        self.path = os.path.join(self.tmp, "daily.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def config(self, **extra):
        base = {"source_host": "misp.example", "scheme": "https", "port": 443,
                "token": "super-secret-token-value", "types": ["ip-dst"],
                "to_ids": True, "days": 90, "time_mode": "last",
                "discovery": {"tags": [{"name": "tlp:amber"}] * 500}}
        base.update(extra)
        return base

    def test_round_trip_preserves_the_answers(self):
        nexus.save_profile(self.config(), self.path)
        loaded = nexus.load_profile(self.path)
        self.assertEqual(loaded["source_host"], "misp.example")
        self.assertEqual(loaded["types"], ["ip-dst"])
        self.assertIs(loaded["to_ids"], True)

    def test_the_token_never_reaches_disk(self):
        nexus.save_profile(self.config(), self.path)
        with open(self.path) as handle:
            raw = handle.read()
        self.assertNotIn("super-secret-token-value", raw)
        self.assertNotIn("token", json.loads(raw)["config"])

    def test_discovery_cache_is_not_persisted(self):
        # Live MISP lists are stale the moment they are written.
        nexus.save_profile(self.config(), self.path)
        self.assertNotIn("discovery", nexus.load_profile(self.path))

    def test_profile_is_written_0600(self):
        nexus.save_profile(self.config(), self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_overwriting_a_loose_profile_tightens_its_mode(self):
        open(self.path, "w").close()
        os.chmod(self.path, 0o644)
        nexus.save_profile(self.config(), self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_a_hand_added_token_is_dropped_on_load(self):
        nexus.save_profile(self.config(), self.path)
        payload = json.load(open(self.path))
        payload["config"]["token"] = "injected"
        json.dump(payload, open(self.path, "w"))
        self.assertNotIn("token", nexus.load_profile(self.path))

    def test_version_mismatch_is_refused(self):
        nexus.save_profile(self.config(), self.path)
        payload = json.load(open(self.path))
        payload["profile_version"] = 99
        json.dump(payload, open(self.path, "w"))
        with self.assertRaises(ValueError):
            nexus.load_profile(self.path)

    def test_a_foreign_json_file_is_refused(self):
        json.dump({"something": "else"}, open(self.path, "w"))
        with self.assertRaises(ValueError):
            nexus.load_profile(self.path)

    def test_saved_profile_still_builds_search_params(self):
        nexus.save_profile(self.config(), self.path)
        params = nexus.build_search_params(nexus.load_profile(self.path))
        self.assertEqual(params["type"], ["ip-dst"])
        self.assertEqual(params["timestamp"], "90d")

    def test_feeds_survive_a_round_trip(self):
        feeds = [feed(name="CIRCL", fixed=True, event="500")]
        nexus.save_profile(self.config(feeds=feeds), self.path)
        loaded = nexus.load_profile(self.path)
        self.assertEqual(nexus.feed_provenance(loaded["feeds"][0])[:2],
                         ("fixed_event", "500"))

    def test_bare_name_resolves_under_nexus_home(self):
        self.assertEqual(nexus.profile_path("daily"),
                         os.path.join(nexus.NEXUS_HOME, "profiles",
                                      "daily.json"))

    def test_a_path_is_taken_as_given(self):
        self.assertEqual(nexus.profile_path("/tmp/x.json"), "/tmp/x.json")


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


# ---------------------------------------------------------------------------
# DIFF
# ---------------------------------------------------------------------------

class TestDiff(unittest.TestCase):

    def rows(self, *pairs):
        return ["%s\tIntel::%s\tMISP\tdesc\t-" % p for p in pairs]

    def test_added_and_removed(self):
        before = self.rows(("1.1.1.1", "ADDR"), ("a.example", "DOMAIN"))
        after = [nexus.header_line()] + self.rows(("1.1.1.1", "ADDR"),
                                                  ("b.example", "DOMAIN"))
        added, removed = nexus.indicator_delta(before, after)
        self.assertEqual(len(added), 1)
        self.assertIn("b.example", added[0])
        self.assertIn("a.example", removed[0])

    def test_a_changed_description_is_not_an_add_plus_a_delete(self):
        # Keyed on (indicator, type), so metadata churn stays invisible.
        before = ["1.1.1.1\tIntel::ADDR\tMISP\told desc\t-"]
        after = [nexus.header_line(), "1.1.1.1\tIntel::ADDR\tMISP\tnew desc\t-"]
        added, removed = nexus.indicator_delta(before, after)
        self.assertEqual((added, removed), ([], []))

    def test_same_indicator_different_type_is_a_real_change(self):
        before = ["evil.example\tIntel::DOMAIN\tMISP\t-\t-"]
        after = [nexus.header_line(), "evil.example\tIntel::URL\tMISP\t-\t-"]
        added, removed = nexus.indicator_delta(before, after)
        self.assertEqual((len(added), len(removed)), (1, 1))

    def test_header_is_never_counted_as_an_indicator(self):
        added, _ = nexus.indicator_delta([], [nexus.header_line()])
        self.assertEqual(added, [])

    def test_summary_counts(self):
        before = self.rows(("1.1.1.1", "ADDR"), ("2.2.2.2", "ADDR"))
        after = [nexus.header_line()] + self.rows(("1.1.1.1", "ADDR"),
                                                  ("3.3.3.3", "ADDR"))
        text = nexus.summarise_delta(before, after)
        self.assertIn("1 added, 1 removed, 1 unchanged", text)

    def test_summary_caps_the_sample(self):
        after = [nexus.header_line()] + self.rows(
            *[("1.1.1.%d" % i, "ADDR") for i in range(1, 30)])
        text = nexus.summarise_delta([], after, sample=5)
        self.assertIn("...and 24 more", text)

    def test_unified_diff_is_produced(self):
        before = self.rows(("1.1.1.1", "ADDR"))
        after = [nexus.header_line()] + self.rows(("2.2.2.2", "ADDR"))
        diff = nexus.unified_intel_diff(before, after, "/x/intel.dat")
        self.assertTrue(any(l.startswith("+") for l in diff))
        self.assertTrue(any(l.startswith("-") for l in diff))

    def test_identical_bodies_produce_no_diff(self):
        rows = self.rows(("1.1.1.1", "ADDR"))
        self.assertEqual(
            nexus.unified_intel_diff(rows, [nexus.header_line()] + rows, "/x"),
            [])


class TestResolveToken(unittest.TestCase):

    class Args(object):
        token_file = None

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nexus-token-")
        self.args = self.Args()
        self.saved_home = nexus.NEXUS_HOME
        nexus.NEXUS_HOME = self.tmp
        self.saved_env = os.environ.pop("NEXUS_MISP_TOKEN", None)

    def tearDown(self):
        nexus.NEXUS_HOME = self.saved_home
        if self.saved_env is not None:
            os.environ["NEXUS_MISP_TOKEN"] = self.saved_env
        else:
            os.environ.pop("NEXUS_MISP_TOKEN", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_token_file_wins(self):
        path = os.path.join(self.tmp, "tok")
        with open(path, "w") as handle:
            handle.write("  from-file  \n")
        self.args.token_file = path
        self.assertEqual(nexus.resolve_token(self.args), "from-file")

    def test_env_is_used_next(self):
        os.environ["NEXUS_MISP_TOKEN"] = "from-env"
        self.assertEqual(nexus.resolve_token(self.args), "from-env")

    def test_unreadable_token_file_does_not_traceback(self):
        self.args.token_file = os.path.join(self.tmp, "nope")
        os.environ["NEXUS_MISP_TOKEN"] = "from-env"
        with self.assertLogs(nexus.log, level="WARNING"):
            self.assertEqual(nexus.resolve_token(self.args), "from-env")

    def test_non_interactive_returns_empty_instead_of_prompting(self):
        # --yes must fail loudly, never block on a prompt nobody will answer.
        with self.assertLogs(nexus.log, level="ERROR"):
            self.assertEqual(
                nexus.resolve_token(self.args, interactive=False), "")


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


class TestTransportHooks(unittest.TestCase):
    """TAXII needs a version-specific Accept header and a second secret --
    both are shared transport hooks so later sources don't monkey-patch."""

    def test_accept_defaults_to_json(self):
        self.assertEqual(nexus._HttpTransport.ACCEPT, "application/json")

    def test_a_subclass_can_override_accept(self):
        class Probe(nexus._HttpTransport):
            ACCEPT = "application/taxii+json;version=2.1"

            def _auth_headers(self):
                return {}
        client = Probe(host="example.test", token="t")
        self.assertEqual(client.ACCEPT, "application/taxii+json;version=2.1")

    def test_overridden_accept_header_reaches_the_server(self):
        # The class-attribute check above proves inheritance, not wiring --
        # this drives a real request through _request and inspects what the
        # server actually received.
        fake = FakeOpencti(script=[(200, {"data": {}})])
        try:
            class Probe(nexus._HttpTransport):
                ACCEPT = "application/taxii+json;version=2.1"

                def _auth_headers(self):
                    return {}
            client = Probe(host="127.0.0.1", token="t", scheme="http",
                          port=fake.port, retries=1)
            client._request("POST", "/")
            self.assertEqual(fake.requests[0]["accept"],
                             "application/taxii+json;version=2.1")
        finally:
            fake.stop()

    def test_default_accept_header_is_still_json_on_the_wire(self):
        # The mirror of the above: an unmodified client -- MISP, OpenCTI --
        # must still send application/json over the wire.
        fake = FakeOpencti(script=[(200, {"data": {}})])
        try:
            class Probe(nexus._HttpTransport):
                def _auth_headers(self):
                    return {}
            client = Probe(host="127.0.0.1", token="t", scheme="http",
                          port=fake.port, retries=1)
            client._request("POST", "/")
            self.assertEqual(fake.requests[0]["accept"], "application/json")
        finally:
            fake.stop()

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
        # 8+ chars: RedactingFilter.add_secret ignores anything shorter (see
        # TestRedaction.test_short_strings_are_not_treated_as_secrets), so a
        # short username here would pass even if registration were broken.
        nexus.TaxiiClient(host="taxii.test", token="pw", username="alice-admin")
        record = logging.LogRecord("n", logging.INFO, "p", 1,
                                   "user alice-admin here", None, None)
        nexus.REDACTOR.filter(record)
        self.assertNotIn("alice-admin", record.getMessage())

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

    def test_unknown_entity_type_passes_through_for_the_mapping_layer(self):
        # Mutex has no Zeek equivalent, but it must still surface as a record
        # of type "Mutex" so build_indicators can count it against
        # OPENCTI_UNMAPPABLE instead of it vanishing without a trace.
        node = self.node(observables=self.observables(
            [{"entity_type": "Mutex", "observable_value": "Global\\evil"}]))
        records = nexus.flatten_indicator(node)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["type"], "Mutex")
        self.assertEqual(records[0]["value"], "Global\\evil")


class TestOpenctiTimestamp(unittest.TestCase):
    """3.6 does not accept a colon in strptime's %z offset (bpo-30618, fixed
    in 3.7); these tests pin the colon-stripping fix at the text level so a
    3.9+ CI run -- which would parse the colon form silently -- can still
    catch a regression here."""

    def test_z_suffix_normalises_to_colon_free_utc_offset(self):
        text = nexus._opencti_timestamp_text("2026-08-02T12:00:00Z")
        self.assertEqual(text, "2026-08-02T12:00:00+0000")
        self.assertNotIn(":", text[-5:])  # the offset itself, not the time

    def test_explicit_offset_colon_is_stripped(self):
        text = nexus._opencti_timestamp_text("2026-08-02T12:00:00+01:00")
        self.assertEqual(text, "2026-08-02T12:00:00+0100")

    def test_epoch_from_z_timestamp(self):
        self.assertEqual(nexus._opencti_epoch("2026-08-02T12:00:00Z"),
                         1785672000)

    def test_epoch_honours_an_explicit_offset(self):
        # 13:00+01:00 is the same instant as 12:00Z -- if the offset were
        # ignored (or stripped instead of normalised) these would diverge.
        utc = nexus._opencti_epoch("2026-08-02T12:00:00Z")
        offset = nexus._opencti_epoch("2026-08-02T13:00:00+01:00")
        self.assertEqual(utc, offset)

    def test_epoch_from_millisecond_precision(self):
        self.assertEqual(nexus._opencti_epoch("2026-08-02T12:00:00.123Z"),
                         1785672000)

    def test_epoch_from_naive_timestamp_with_no_timezone(self):
        self.assertEqual(nexus._opencti_epoch("2026-08-02T12:00:00"),
                         1785672000)

    def test_epoch_from_unparseable_text_is_empty(self):
        self.assertEqual(nexus._opencti_epoch("not a date"), "")


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


class TestBuildHonoursSourceAndHostFlags(Quiet):
    """--source/--host say "asked if omitted" in the help; on a build run they
    were read by nobody, so they changed nothing at all."""

    def build(self, argv, interview):
        args = nexus.resolve_source_args(nexus.build_parser().parse_args(argv))
        seen = {}

        def fake_interview(client, **kwargs):
            seen.update(kwargs)
            return interview(kwargs)

        real = (nexus.run_interview, nexus.check_env,
                nexus.resolve_build_target)
        nexus.run_interview = fake_interview
        nexus.check_env = lambda: (True, [])
        # A build on this manager: the target question is Task 2's to test.
        nexus.resolve_build_target = lambda args: False
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                nexus.cmd_build(args)
        finally:
            (nexus.run_interview, nexus.check_env,
             nexus.resolve_build_target) = real
        return seen

    def test_flags_reach_the_interview(self):
        def stop(kwargs):
            raise nexus.InterviewAborted("enough")

        seen = self.build(["--source", "opencti", "--host", "cti.local"], stop)
        self.assertEqual(seen["source"], "opencti")
        self.assertEqual(seen["host"], "cti.local")

    def test_a_flagless_run_still_asks(self):
        # The interactivity rule: absent the switch, the script asks.  A fix
        # that silently defaulted to "misp" would pass the test above and
        # fail this one.
        def stop(kwargs):
            raise nexus.InterviewAborted("enough")

        seen = self.build([], stop)
        self.assertIsNone(seen["source"])
        self.assertIsNone(seen["host"])

        # ...and run_interview with source=None does ask.
        config = nexus.run_interview(
            None, input_fn=scripted(["2", "cti.local"], fill=""),
            getpass_fn=lambda prompt: "tok", source=None)
        self.assertEqual(config["source"], "opencti")

    def test_host_flag_is_only_a_default_the_question_still_runs(self):
        fake = scripted([], fill="")
        config = {}
        nexus._stage1_connection(config, None, fake, lambda *a, **k: "tok",
                                 source="opencti", host="cti.local")
        self.assertEqual(config["source_host"], "cti.local")
        self.assertIn("cti.local", fake.state["prompts"][0])

        typed = scripted(["other.local"], fill="")
        config = {}
        nexus._stage1_connection(config, None, typed, lambda *a, **k: "tok",
                                 source="opencti", host="cti.local")
        self.assertEqual(config["source_host"], "other.local")


class TestBuildTranslatesTheTypeVocabulary(Quiet):
    """cmd_build must expand config["types"] (main observable type names) into
    record types before build_indicators filters on them.  Every helper around
    that call was covered; the call itself was not, so reverting it -- and
    dropping every file hash -- passed the whole suite."""

    def setUp(self):
        Quiet.setUp(self)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        # Without __load__.Zeek the guardrails block before anything is written.
        with io.open(os.path.join(self.dir, nexus.SO_LOAD_FILE), "w"):
            pass

    def config(self):
        config = nexus.run_interview(
            None,
            input_fn=by_prompt([("OpenCTI address", "cti.local")], fill=""),
            getpass_fn=lambda prompt: "tok", source="opencti")
        # An operator who picked the "file" IOC class: class names, not the
        # finer record types flatten_indicator() emits.
        config["types"] = ["StixFile"]
        config["output_path"] = os.path.join(self.dir, "intel.dat")
        config["profile_path"] = None
        config["backup"] = False
        config["dry_run"] = False
        config["apply"] = False
        return config

    def records(self):
        node = {
            "id": "6c1f0a2e-2b7d-4a55-9d3e-1f0a2e2b7d45",
            "standard_id": "indicator--6c1f0a2e-2b7d-4a55-9d3e-1f0a2e2b7d45",
            "name": "dropper", "description": "", "pattern_type": "stix",
            "x_opencti_detection": True, "updated_at": "2026-08-02T12:00:00Z",
            "createdBy": {"name": "CIRCL"},
            "observables": {"pageInfo": {"hasNextPage": False}, "edges": [
                {"node": {"entity_type": "StixFile", "name": "bad.exe",
                          "observable_value": "bad.exe",
                          "hashes": [{"algorithm": "MD5", "hash": "d" * 32},
                                     {"algorithm": "sha-256",
                                      "hash": "e" * 64}]}}]},
        }
        return nexus.flatten_indicator(node)

    def test_the_hashes_reach_the_written_file(self):
        records = self.records()
        # The record types are finer than the class name in config["types"];
        # filtering the second vocabulary with the first matches nothing.
        self.assertIn("MD5", [r["type"] for r in records])

        class Client(object):
            host = "cti.local"

            def get_version(self):
                return {"version": "6.2.0"}

            def search_indicators(self, filters, max_results=None, stats=None):
                return iter(records)

        config = self.config()
        real = (nexus.check_env, nexus.run_interview, nexus.make_client,
                nexus.resolve_build_target)
        nexus.check_env = lambda: (True, [])
        nexus.run_interview = lambda client, **kwargs: config
        nexus.make_client = lambda cfg: Client()
        nexus.resolve_build_target = lambda args: False
        try:
            args = nexus.resolve_source_args(nexus.build_parser().parse_args([]))
            rc = nexus.cmd_build(args)
        finally:
            (nexus.check_env, nexus.run_interview, nexus.make_client,
             nexus.resolve_build_target) = real

        self.assertEqual(rc, 0)
        with io.open(config["output_path"], encoding="utf-8") as handle:
            body = handle.read()
        self.assertIn("d" * 32, body)
        self.assertIn("e" * 64, body)
        self.assertIn("bad.exe", body)


class TestOfflineBuild(Quiet):
    """A build on a host with no Security Onion, end to end.

    Every SO_* constant points at a path that does not exist, so any code that
    reaches for the local install fails here rather than quietly finding the
    real one on a developer's manager.
    """

    POISON = "/nonexistent/security-onion"

    def setUp(self):
        Quiet.setUp(self)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.out = os.path.join(self.dir, "intel.dat")
        for name in ("SO_INTEL_DIR", "SO_INTEL_DEFAULT_DIR",
                     "SO_INTEL_RUNTIME_DIR", "SO_INTEL_FILE"):
            self.addCleanup(setattr, nexus, name, getattr(nexus, name))
            setattr(nexus, name, os.path.join(self.POISON, name.lower()))

    def config(self, **overrides):
        config = {
            "offline": True, "deployment": "offline", "output_path": self.out,
            "apply": False, "backup": False, "dry_run": False,
            "do_notice": False, "source": "misp", "source_host": "misp.local",
            "types": ["ip-dst"], "exclude_private": True, "own_networks": [],
            "own_domains": [], "allowlist_file": None,
            "split_composites": "both", "allow_subnet": True,
            "source_fmt": "MISP", "desc_template": "{category}",
            "source_base_url": None, "meta_maxlen": 200,
            "max_indicators": None, "token": "t", "profile_path": None,
            "merge_mode": "append-only",
        }
        config.update(overrides)
        return config

    def records(self):
        return [{"type": "ip-dst", "value": "45.33.32.1",
                 "category": "Network activity", "event_id": "7",
                 "event_info": "phishing infrastructure"}]

    def build(self, config, argv=None):
        """Run cmd_build with the platform stubbed out; returns the exit code.

        check_env() is stubbed to fail the test outright: an offline run must
        not call it at all.  Poisoning the SO_* constants would not catch that
        on a real manager -- check_env() binds them as argument defaults at
        import, so a later setattr never reaches it.
        """
        class Client(object):
            host = "misp.local"

            def get_version(self):
                return {"version": "2.4.190"}

        self.interview_kwargs = None

        def fake_interview(client, **kwargs):
            self.interview_kwargs = kwargs
            return config

        real = (nexus.make_client, nexus.run_interview, nexus._fetch_records,
                nexus.check_env)
        self.client_factory = lambda cfg: Client()
        nexus.make_client = self.client_factory
        nexus.run_interview = fake_interview
        nexus._fetch_records = lambda client, cfg: iter(self.records())
        nexus.check_env = lambda: self.fail(
            "an offline build must not check this host's environment")
        try:
            args = nexus.resolve_source_args(
                nexus.build_parser().parse_args(
                    ["--offline"] if argv is None else argv))
            return nexus.cmd_build(args)
        finally:
            (nexus.make_client, nexus.run_interview, nexus._fetch_records,
             nexus.check_env) = real

    def test_offline_build_writes_without_any_security_onion(self):
        self.assertEqual(self.build(self.config()), 0)
        self.assertTrue(os.path.exists(self.out))
        header, rows = nexus.read_existing(self.out)
        self.assertEqual(header, nexus.header_line(False))
        self.assertEqual([row.split("\t")[0] for row in rows], ["45.33.32.1"])

    def test_offline_build_prints_both_transfer_routes(self):
        self.build(self.config())
        self.assertIn("--import", self.printed)
        self.assertIn("REPLACES", self.printed)
        # ...and never the on-box apply, which has nothing to apply to.
        self.assertNotIn(nexus.SO_APPLY_CMD + "\nThen check", self.printed)

    def test_the_output_directory_is_checked_and_a_bad_one_blocks(self):
        config = self.config(
            output_path=os.path.join(self.dir, "no-such-dir", "intel.dat"))
        self.assertEqual(self.build(config), 1)
        self.assertIn("output directory does not exist", self.printed)
        self.assertFalse(os.path.exists(config["output_path"]))

    def test_the_offline_answer_reaches_the_interview_with_the_others(self):
        # source/host/connect were dropped from this call once already; a
        # missing `connect` leaves the OpenCTI scope filters unresolvable.
        self.build(self.config(), argv=["--offline", "--source", "opencti",
                                        "--host", "cti.local"])
        self.assertEqual(self.interview_kwargs["offline"], True)
        self.assertEqual(self.interview_kwargs["source"], "opencti")
        self.assertEqual(self.interview_kwargs["host"], "cti.local")
        self.assertIs(self.interview_kwargs["connect"], self.client_factory)

    def test_no_do_notice_warning_about_a_policy_tree_on_the_wrong_host(self):
        # The warning describes the *build* host's Zeek policy, which says
        # nothing about the manager the file is going to.  Off-box the policy
        # dirs never exist, so it fired on every --do-notice offline build.
        self.assertEqual(self.build(self.config(do_notice=True)), 0)
        self.assertNotIn("do_notice.zeek is not loaded", self.printed)

    def test_the_guardrail_count_is_the_merged_total_not_the_sum(self):
        # Same double-count on the build path: the fetched row is already in
        # the file being merged into, so the total is 1, not 2.
        nexus.write_atomic(self.out, [nexus.header_line(False),
                                      "45.33.32.1\tIntel::ADDR\tMISP\td\t-"])
        self.assertEqual(self.build(self.config()), 0)
        self.assertIn("1 indicators", self.printed)
        self.assertNotIn("2 indicators", self.printed)

    def test_the_backup_lands_beside_the_output_not_in_opt_nexus(self):
        # The interview defaults "back up first" to yes, so the *second*
        # offline build is the common case: /opt/nexus is not writable on a
        # workstation and backup_file() would die in os.makedirs.
        self.assertEqual(self.build(self.config(backup=True)), 0)
        self.assertEqual(self.build(self.config(backup=True)), 0)
        saved = os.listdir(os.path.join(self.dir, "nexus-backups"))
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].startswith("intel.dat."))

    def test_the_offline_profile_is_written_where_the_interview_put_it(self):
        # The end-to-end half of the same point: no /opt/nexus anywhere on
        # this host, and the save still happens rather than warning past it.
        profile = os.path.join(self.dir, "laptop.json")
        self.assertEqual(self.build(self.config(profile_path=profile)), 0)
        self.assertTrue(os.path.exists(profile))
        self.assertIn(profile, self.printed)

    def test_a_profile_replay_honours_its_recorded_answer_without_asking(self):
        profile = os.path.join(self.dir, "offline.json")
        nexus.save_profile(self.config(), profile)
        token_file = os.path.join(self.dir, "token")
        with io.open(token_file, "w", encoding="utf-8") as handle:
            handle.write(u"t\n")

        real = nexus.ask_choice
        nexus.ask_choice = lambda *a, **k: self.fail(
            "an unattended replay must not be asked where the file is going")
        try:
            rc = self.build(None, argv=["--profile", profile, "--yes",
                                        "--token-file", token_file])
        finally:
            nexus.ask_choice = real
        self.assertEqual(rc, 0)
        self.assertIn("--import", self.printed)
        self.assertTrue(os.path.exists(self.out))


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
        rows, stats = nexus.build_indicators(
            records, mapping_table=nexus.OPENCTI_TO_ZEEK,
            exclusions=nexus.ExclusionSet(exclude_private=True))
        self.assertEqual(rows, [])
        # rows == [] alone doesn't distinguish "excluded" from "never mapped"
        # (an unmapped type hits stats.unmap() before exclusions run at all).
        # Pin down the actual exclusion reason so a broken OPENCTI_TO_ZEEK
        # entry or a broken exclusion check would fail this differently.
        self.assertEqual(stats.excluded.get("private_ip"), 1)
        self.assertEqual(stats.unmapped, {})

    def test_selected_ioc_classes_keep_their_hashes(self):
        # config["types"] holds x_opencti_main_observable_type names, but
        # flatten_indicator() emits the finer OPENCTI_TO_ZEEK keys.  Filtering
        # the second vocabulary with the first drops every file and cert hash
        # without a stats bucket or a warning.
        node = self.indicator("i1", "Domain-Name", "unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"entity_type": "StixFile", "observable_value": "bad.exe",
                      "name": "bad.exe",
                      "hashes": [{"algorithm": "MD5", "hash": "d" * 32},
                                 {"algorithm": "sha-256", "hash": "e" * 64}]}},
            {"node": {"entity_type": "X509-Certificate",
                      "observable_value": "cert",
                      "hashes": [{"algorithm": "SHA-1", "hash": "b" * 40}]}},
        ]}
        records = nexus.flatten_indicator(node)

        selected = (nexus.OPENCTI_IOC_CLASSES["file"][1]
                    + nexus.OPENCTI_IOC_CLASSES["tls"][1])
        rows, stats = nexus.build_indicators(
            records, types=nexus.opencti_record_types(selected),
            mapping_table=nexus.OPENCTI_TO_ZEEK, source="opencti")

        self.assertEqual(sorted(r[0] for r in rows),
                         sorted(["bad.exe", "d" * 32, "e" * 64, "b" * 40]))
        self.assertEqual(stats.by_type.get("Intel::CERT_HASH"), 1)
        self.assertEqual(stats.by_type.get("Intel::FILE_HASH"), 2)

    def test_expansion_is_identity_where_the_vocabularies_agree(self):
        for main_type in nexus.OPENCTI_IOC_CLASSES["network"][1]:
            self.assertEqual(nexus.opencti_record_types([main_type]),
                             [main_type])

    def test_every_offered_class_expands_to_mappable_record_types(self):
        for key, (_, main_types) in nexus.OPENCTI_IOC_CLASSES.items():
            expanded = nexus.opencti_record_types(main_types)
            mappable = [t for t in expanded if t in nexus.OPENCTI_TO_ZEEK]
            self.assertTrue(mappable, "%s expands to nothing mappable" % key)

    def test_unmappable_emissions_are_counted_not_dropped_silently(self):
        node = self.indicator("i1", "Domain-Name", "unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"entity_type": "StixFile", "observable_value": "bad.exe",
                      "hashes": [{"algorithm": "SSDEEP", "hash": "3:abc"}]}}]}
        _, stats = nexus.build_indicators(
            nexus.flatten_indicator(node),
            types=nexus.opencti_record_types(["StixFile"]),
            mapping_table=nexus.OPENCTI_TO_ZEEK, source="opencti")
        self.assertEqual(stats.unmapped.get("SSDEEP"), 1)

    def test_an_unknown_hash_algorithm_is_counted_not_dropped(self):
        # A connector shipping SHA3-256 produces record type "SHA3-256", which
        # is in no expansion list, so the types filter used to eat it with no
        # stats bucket -- the same silent loss the class-name filter caused.
        node = self.indicator("i1", "Domain-Name", "unused")
        node["observables"] = {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"entity_type": "StixFile", "observable_value": "bad.exe",
                      "hashes": [{"algorithm": "SHA3-256", "hash": "f" * 64}]}}]}
        _, stats = nexus.build_indicators(
            nexus.flatten_indicator(node),
            types=nexus.opencti_record_types(["StixFile"]),
            mapping_table=nexus.OPENCTI_TO_ZEEK, source="opencti")
        self.assertEqual(stats.unmapped.get("SHA3-256"), 1)

    def test_a_deselected_but_mappable_type_stays_silent(self):
        # Counting the unknown must not turn every deselected type into noise:
        # the operator chose not to have those.
        records = nexus.flatten_indicator(
            self.indicator("i1", "IPv4-Addr", "45.33.32.1"))
        _, stats = nexus.build_indicators(
            records, types=["Domain-Name"],
            mapping_table=nexus.OPENCTI_TO_ZEEK, source="opencti")
        self.assertEqual(stats.unmapped, {})

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
        # nothing. The existing row must survive byte-for-byte.
        self.assertEqual(len(combined), 1)
        self.assertEqual(combined[0], "evil.com\tIntel::DOMAIN\tMISP\told desc\t-")
        added, removed = nexus.indicator_delta(existing_rows, combined)
        self.assertEqual(removed, [])


class TestTransferInstructions(Quiet):
    """The hand-copy route printed after an offline build."""

    def test_the_hand_copy_names_the_destination_file(self):
        # The output path is free-form and dating an export is natural for a
        # sneakernet workflow.  Copying by source name drops a file Zeek never
        # loads beside the real intel.dat, with no error to notice.
        nexus.print_transfer_instructions(
            "/home/op/exports/misp-2026-08-22.dat")
        copies = [l.strip() for l in self.printed.splitlines()
                  if l.strip().startswith("sudo cp")]
        self.assertEqual(len(copies), 1)
        self.assertTrue(copies[0].endswith(nexus.SO_INTEL_FILE), copies[0])
        self.assertNotIn("misp-2026-08-22.dat", copies[0].split()[-1])


class TestResolveBuildTarget(Quiet):
    def _args(self, **kw):
        return argparse.Namespace(offline=kw.get("offline", False))

    def test_offline_flag_skips_the_question(self):
        def refuse(_prompt):
            raise AssertionError("must not ask when --offline is given")
        self.assertTrue(nexus.resolve_build_target(
            self._args(offline=True), input_fn=refuse))

    def test_flagless_run_asks(self):
        asked = []

        def record(prompt):
            asked.append(prompt)
            return ""
        nexus.resolve_build_target(self._args(), input_fn=record,
                                   intel_dir="/nonexistent/so/intel")
        self.assertTrue(asked, "a flagless run must ask which target")

    def test_flagless_run_honours_a_non_default_answer(self):
        # No Security Onion here, so the default is offline.  ask_choice is
        # numbered single-select, so "1" picks "manager" -- the non-default
        # option.  That must be obeyed; a silent default would return True.
        self.assertFalse(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "1",
            intel_dir="/nonexistent/so/intel"))

    def test_default_is_offline_when_no_security_onion_present(self):
        self.assertTrue(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "",
            intel_dir="/nonexistent/so/intel"))

    def test_default_is_manager_when_intel_dir_exists(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertFalse(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "", intel_dir=tmp))


class TestBuildAppendOnlyGuards(Quiet):
    """cmd_build's append-only guards, on the manager path.

    cmd_import grew tests for the identical checks; these older copies had
    none, so stubbing either condition out left the whole suite green.
    """

    class Client(object):
        host = "misp.local"

        def get_version(self):
            return {"version": "2.4.190"}

    def setUp(self):
        Quiet.setUp(self)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        open(os.path.join(self.dir, nexus.SO_LOAD_FILE), "w").close()
        self.out = os.path.join(self.dir, "intel.dat")
        for name in ("check_env", "run_interview", "make_client",
                     "_fetch_records", "resolve_build_target",
                     "merge_additive"):
            self.addCleanup(setattr, nexus, name, getattr(nexus, name))
        nexus.check_env = lambda: (True, [])
        nexus.make_client = lambda cfg: self.Client()
        nexus._fetch_records = lambda client, cfg: iter(
            [{"type": "ip-dst", "value": "45.33.32.1",
              "category": "Network activity", "event_id": "7",
              "event_info": "phishing infrastructure"}])
        nexus.resolve_build_target = lambda args: False

    def config(self, **overrides):
        config = nexus.run_interview(
            None, input_fn=scripted(["misp.local"], fill=""),
            getpass_fn=lambda prompt: "tok", source="misp")
        config.update({"output_path": self.out, "profile_path": None,
                       "backup": False, "dry_run": False, "apply": False})
        config.update(overrides)
        return config

    def build(self, config):
        nexus.run_interview = lambda client, **kwargs: config
        return nexus.cmd_build(nexus.resolve_source_args(
            nexus.build_parser().parse_args([])))

    def _raw(self):
        with io.open(self.out, encoding="utf-8") as handle:
            return handle.read()

    def test_a_header_mismatch_blocks_and_writes_nothing(self):
        # A do_notice file under a no-notice run: append-only mode will not
        # rewrite the existing rows into the other schema, so it stops.
        nexus.write_atomic(self.out, [
            nexus.header_line(True),
            "a.example\tIntel::DOMAIN\tMISP\td\t-\tT"])
        before = self._raw()
        self.assertEqual(self.build(self.config(do_notice=False)), 1)
        self.assertIn("schema differs", self.printed)
        self.assertEqual(self._raw(), before)

    def test_a_bad_row_in_the_existing_file_blocks_the_write(self):
        # The live file is not ours and not trusted; the merged result is
        # linted before anything is written over it.
        nexus.write_atomic(self.out, [
            nexus.header_line(False),
            "a.example\tIntel::NOPE\tMISP\td\t-"])
        before = self._raw()
        self.assertEqual(self.build(self.config()), 1)
        self.assertIn("the rendered file fails lint", self.printed)
        self.assertEqual(self._raw(), before)

    def test_a_computed_removal_blocks_and_writes_nothing(self):
        # The invariant, forced.  merge_additive cannot drop a row, so this
        # stubs it to prove the check downstream is real and not decorative.
        nexus.write_atomic(self.out, [
            nexus.header_line(False),
            "a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        nexus.merge_additive = lambda existing, new: list(new)
        self.assertEqual(self.build(self.config()), 1)
        self.assertIn("removed indicators", self.printed)
        self.assertEqual(self._raw(), before)

    def test_an_unreadable_existing_file_is_an_error_not_a_traceback(self):
        with open(self.out, "wb") as handle:
            handle.write(b"\xff\xfe not utf-8 at all\n")
        self.assertEqual(self.build(self.config()), 1)
        with open(self.out, "rb") as handle:
            self.assertEqual(handle.read(), b"\xff\xfe not utf-8 at all\n")


class TestOfflineFlagParsing(unittest.TestCase):
    def test_offline_defaults_to_false(self):
        args = nexus.build_parser().parse_args([])
        self.assertFalse(args.offline)

    def test_offline_flag_sets_true(self):
        args = nexus.build_parser().parse_args(["--offline"])
        self.assertTrue(args.offline)


# ---------------------------------------------------------------------------
# IMPORT
# ---------------------------------------------------------------------------

class TestImportMode(Quiet):
    """--import merges a file built elsewhere into this manager's intel.dat.

    The whole point of the mode is that the manager's own indicators survive,
    so the first test asserts byte-identity of an existing row rather than
    mere presence.
    """

    def setUp(self):
        Quiet.setUp(self)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.intel_dir = os.path.join(self.tmp, "intel")
        os.makedirs(self.intel_dir)
        open(os.path.join(self.intel_dir, nexus.SO_LOAD_FILE), "w").close()
        self.live = os.path.join(self.intel_dir, "intel.dat")
        self.incoming = os.path.join(self.tmp, "incoming.dat")
        self.applied = []
        for name in ("SO_INTEL_DIR", "SO_INTEL_FILE", "NEXUS_HOME",
                     "check_env", "apply_to_grid"):
            self.addCleanup(setattr, nexus, name, getattr(nexus, name))
        nexus.SO_INTEL_DIR = self.intel_dir
        nexus.SO_INTEL_FILE = self.live
        nexus.NEXUS_HOME = self.tmp
        nexus.check_env = lambda: (True, [])
        nexus.apply_to_grid = self.fake_apply

    def fake_apply(self, **kwargs):
        self.applied.append(kwargs)
        return True, [("info", "applied")]

    def _write(self, path, rows, do_notice=False):
        nexus.write_atomic(path, [nexus.header_line(do_notice)] + rows)

    def _import(self, **kwargs):
        args = argparse.Namespace(
            import_file=kwargs.get("import_file", self.incoming),
            yes=kwargs.get("yes", True),
            dry_run=kwargs.get("dry_run", False),
            diff=kwargs.get("diff", False))
        return nexus.cmd_import(args)

    def _raw(self):
        with open(self.live, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_existing_rows_survive_byte_for_byte(self):
        old = "old.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        new = "new.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        self._write(self.live, [old])
        self._write(self.incoming, [new])
        self.assertEqual(self._import(), 0)
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(rows[0], old)      # byte-identical, still first
        self.assertEqual(rows, [old, new])
        # The raw bytes, not just the parse: no re-rendering of the old row.
        self.assertIn("\n" + old + "\n", self._raw())

    def test_import_creates_the_file_on_a_manager_with_none(self):
        new = "new.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        self._write(self.incoming, [new])
        self.assertEqual(self._import(), 0)
        self.assertEqual(nexus.read_existing(self.live),
                         (nexus.header_line(False), [new]))

    def test_duplicate_key_does_not_duplicate_the_row(self):
        row = "dup.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        self._write(self.live, [row])
        self._write(self.incoming,
                    ["dup.example\tIntel::DOMAIN\tOTHER\tother\t-"])
        self.assertEqual(self._import(), 0)
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(rows, [row])       # existing wins, no second row

    def test_header_mismatch_blocks_and_writes_nothing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"], False)
        before = self._raw()
        # Six fields: valid for do_notice, so it clears the incoming lint and
        # the header comparison is what does the blocking.
        self._write(self.incoming,
                    ["b.example\tIntel::DOMAIN\tMISP\td\t-\tT"], True)
        self.assertEqual(self._import(), 1)
        self.assertIn("different meta.do_notice", self.printed)
        self.assertEqual(self._raw(), before)

    def test_malformed_incoming_file_blocks_and_writes_nothing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        with open(self.incoming, "w", encoding="utf-8") as handle:
            handle.write(nexus.header_line(False) + "\n")
            handle.write("garbage-with-no-tabs\n")
        self.assertEqual(self._import(), 1)
        self.assertEqual(self._raw(), before)
        self.assertIn("fails lint", self.printed)

    def test_missing_incoming_file_is_an_error(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(
                self._import(import_file=os.path.join(self.tmp, "nope")), 2)
        self.assertIn("no such file", errors.getvalue())
        self.assertEqual(self._raw(), before)

    def test_incoming_file_with_no_indicators_is_an_error(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, [])
        self.assertEqual(self._import(), 2)
        self.assertEqual(self._raw(), before)

    def test_unreadable_incoming_file_is_an_error_not_a_traceback(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        with open(self.incoming, "wb") as handle:
            handle.write(b"\xff\xfe not utf-8 at all\n")
        self.assertEqual(self._import(), 2)

    def test_an_unreadable_live_file_is_an_error_not_a_traceback(self):
        # The manager's own intel.dat, not the transferred one: on a real
        # manager check_env traps this first, but nothing guarantees that
        # ordering and the raise here escaped as a traceback.
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        with open(self.live, "wb") as handle:
            handle.write(b"\xff\xfe not utf-8 at all\n")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(self._import(), 1)
        self.assertIn("unreadable", errors.getvalue())
        with open(self.live, "rb") as handle:
            self.assertEqual(handle.read(), b"\xff\xfe not utf-8 at all\n")

    def test_broad_incoming_subnet_is_flagged(self):
        """The guardrail's own reason to exist: rows built somewhere else.

        norm_subnet would have rejected a /8 on the way in, but these rows
        were normalised on another host by a copy of Nexus this one cannot
        inspect, so they get looked at again here.
        """
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        self._write(self.incoming, ["10.0.0.0/8\tIntel::SUBNET\tMISP\td\t-"])
        self.assertEqual(self._import(), 0)
        # The exact verdict, not just the words: "no overly broad indicators"
        # is what an unparsed row list would have printed here.
        self.assertIn("warn    1 overly broad indicator(s): 10.0.0.0/8 "
                      "(subnet at or broader than /16)", self.printed)

    def test_the_guardrail_count_is_the_merged_total_not_the_sum(self):
        # Re-importing a refreshed offline build is near-total overlap, so
        # len(incoming) + len(existing) roughly doubles the true count and the
        # 100k warn threshold would fire at about half the real number.
        shared = "shared.example\tIntel::DOMAIN\tMISP\td\t-"
        self._write(self.live,
                    [shared, "only-live.example\tIntel::DOMAIN\tMISP\td\t-"])
        self._write(self.incoming,
                    [shared, "only-new.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(), 0)
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(len(rows), 3)
        self.assertIn("3 indicators", self.printed)
        self.assertNotIn("4 indicators", self.printed)

    def test_a_bad_row_in_the_live_file_blocks_the_write(self):
        """The merged-file lint: the live file is not ours and not trusted."""
        self._write(self.live, ["a.example\tIntel::NOPE\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(), 1)
        self.assertIn("the merged file fails lint", self.printed)
        self.assertEqual(self._raw(), before)

    def test_dry_run_writes_nothing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(dry_run=True), 0)
        self.assertEqual(self._raw(), before)
        self.assertEqual(self.applied, [])

    def test_dry_run_with_diff_shows_the_line_diff(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(dry_run=True, diff=True), 0)
        self.assertIn("+b.example\tIntel::DOMAIN\tMISP\td\t-", self.printed)

    def test_backs_up_the_live_file_before_writing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(), 0)
        backups = os.listdir(os.path.join(self.tmp, "backups"))
        self.assertEqual(len(backups), 1)
        with open(os.path.join(self.tmp, "backups", backups[0]),
                  encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_yes_applies_to_the_grid(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(self._import(), 0)
        self.assertEqual(self.applied,
                         [{"intel_dir": self.intel_dir, "expected": 2}])

    def test_ctrl_c_at_the_apply_prompt_keeps_the_written_merge(self):
        """The write already happened; aborting only skips the apply."""
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.addCleanup(setattr, nexus, "ask_yes_no", nexus.ask_yes_no)

        def abort(*args, **kwargs):
            raise nexus.InterviewAborted("end of input")

        nexus.ask_yes_no = abort
        self.assertEqual(self._import(yes=False), 0)
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.applied, [])
        self.assertIn("Not applied", self.printed)

    def test_an_unfit_environment_blocks_the_write(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        nexus.check_env = lambda: (False, [("error", "no intel dir")])
        self.assertEqual(self._import(), 1)
        self.assertEqual(self._raw(), before)

    def test_a_removal_blocks_the_write(self):
        """The invariant, forced.  merge_additive cannot drop a row, so this
        stubs it to prove the check downstream is real and not decorative."""
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = self._raw()
        self._write(self.incoming, ["b.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.addCleanup(setattr, nexus, "merge_additive", nexus.merge_additive)
        nexus.merge_additive = lambda existing, new: list(new)
        self.assertEqual(self._import(), 1)
        self.assertEqual(self._raw(), before)
        self.assertIn("removed indicators", self.printed)


class TestImportCli(Quiet):

    def test_import_parses_into_import_file(self):
        args = nexus.build_parser().parse_args(["--import", "/tmp/x.dat"])
        self.assertEqual(args.import_file, "/tmp/x.dat")

    def test_import_defaults_to_none(self):
        self.assertIsNone(nexus.build_parser().parse_args([]).import_file)

    def test_import_with_yes_does_not_need_a_profile(self):
        """--import runs no interview, so the --yes gate must not reject it."""
        seen = []
        for name in ("cmd_import", "setup_logging"):
            self.addCleanup(setattr, nexus, name, getattr(nexus, name))
        nexus.cmd_import = lambda args: seen.append(args.import_file) or 0
        # main() otherwise rewires the process-wide logger and reaches for
        # /opt/nexus, which outlives this test and pollutes the ones after it.
        nexus.setup_logging = lambda *a, **k: None
        rc = nexus.main(["--import", "/tmp/x.dat", "--yes"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen, ["/tmp/x.dat"])


class TestEnsureIntelEnv(Quiet):
    """The block cmd_build and cmd_import share."""

    def setUp(self):
        Quiet.setUp(self)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name in ("SO_INTEL_DIR", "check_env", "seed_load_file"):
            self.addCleanup(setattr, nexus, name, getattr(nexus, name))
        nexus.SO_INTEL_DIR = self.tmp

    def test_a_healthy_environment_seeds_nothing(self):
        nexus.check_env = lambda: (True, [])
        nexus.seed_load_file = lambda: self.fail("nothing to seed")
        self.assertTrue(nexus.ensure_intel_env(True))

    def test_a_missing_load_file_is_seeded_without_asking_under_yes(self):
        self.calls = []

        def check():
            self.calls.append(1)
            return len(self.calls) > 1, [("error", "__load__.Zeek missing")]

        def seed():
            path = os.path.join(self.tmp, nexus.SO_LOAD_FILE)
            open(path, "w").close()
            return [path]

        nexus.check_env = check
        nexus.seed_load_file = seed
        self.assertTrue(nexus.ensure_intel_env(True))
        self.assertTrue(
            os.path.exists(os.path.join(self.tmp, nexus.SO_LOAD_FILE)))

    def test_an_unfixable_environment_is_false(self):
        nexus.check_env = lambda: (False, [("error", "intel dir missing")])
        open(os.path.join(self.tmp, nexus.SO_LOAD_FILE), "w").close()
        self.assertFalse(nexus.ensure_intel_env(True))
        self.assertIn("Environment is not ready", self.printed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
