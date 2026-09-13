"""Tests for blocklist parsing and matching."""

import gzip
import http.server
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from symbivpn import blocklist
from symbivpn import blocklist as blocklist_module
from symbivpn.blocklist import (
    MAX_LIST_BYTES,
    BlocklistManager,
    DomainSet,
    parent_domains,
    parse_rules,
)


class ParentDomainTests(unittest.TestCase):
    def test_walks_up(self):
        self.assertEqual(
            list(parent_domains("a.b.example.com")),
            ["a.b.example.com", "b.example.com", "example.com", "com"],
        )

    def test_single_label(self):
        self.assertEqual(list(parent_domains("localhost")), ["localhost"])

    def test_empty(self):
        self.assertEqual(list(parent_domains("")), [])


class DomainSetTests(unittest.TestCase):
    def test_exact_match_only(self):
        rules = DomainSet()
        rules.add_exact("ads.example.com", "test")
        self.assertTrue(rules.match("ads.example.com"))
        self.assertFalse(rules.match("sub.ads.example.com"))

    def test_suffix_matches_subdomains(self):
        rules = DomainSet()
        rules.add_suffix("example.com", "test")
        self.assertTrue(rules.match("example.com"))
        self.assertTrue(rules.match("deep.sub.example.com"))
        self.assertFalse(rules.match("notexample.com"))

    def test_suffix_supersedes_exact(self):
        rules = DomainSet()
        rules.add_exact("example.com", "test")
        rules.add_suffix("example.com", "test")
        self.assertNotIn("example.com", rules.exact)
        self.assertTrue(rules.match("sub.example.com"))

    def test_regex(self):
        rules = DomainSet()
        rules.add_regex(r"^ad[sv]?\d*\.", "test")
        self.assertTrue(rules.match("ads1.example.com"))
        self.assertTrue(rules.match("adv.example.com"))
        self.assertFalse(rules.match("addition.example.com"))

    def test_invalid_regex_is_skipped(self):
        rules = DomainSet()
        rules.add_regex("([unclosed", "test")
        self.assertEqual(len(rules.regex), 0)

    def test_match_reports_source(self):
        rules = DomainSet()
        rules.add_suffix("tracker.net", "list-a")
        match = rules.match("x.tracker.net")
        self.assertTrue(match.matched)
        self.assertEqual(match.source, "list-a")
        self.assertEqual(match.rule, "*.tracker.net")


class ParseTests(unittest.TestCase):
    def test_hosts_format(self):
        result = parse_rules("0.0.0.0 ads.example.com\n127.0.0.1 tracker.net", "test")
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertTrue(result.block.match("tracker.net"))

    def test_hosts_with_real_address_ignored(self):
        # A hosts line pointing at a real host is a mapping, not a block rule.
        result = parse_rules("192.168.1.5 nas.local", "test")
        self.assertFalse(result.block.match("nas.local"))

    def test_multiple_names_per_line(self):
        result = parse_rules("0.0.0.0 a.example.com b.example.com", "test")
        self.assertTrue(result.block.match("a.example.com"))
        self.assertTrue(result.block.match("b.example.com"))

    def test_localhost_entries_skipped(self):
        result = parse_rules(
            "127.0.0.1 localhost\n::1 ip6-localhost\n255.255.255.255 broadcasthost", "test"
        )
        self.assertFalse(result.block.match("localhost"))
        self.assertFalse(result.block.match("ip6-localhost"))

    def test_adblock_block_syntax(self):
        result = parse_rules("||ads.example.com^", "test")
        self.assertTrue(result.block.match("sub.ads.example.com"))

    def test_exception_rules_are_ignored_by_default(self):
        """A downloaded list does not get to decide what stays unfiltered.

        An @@|| rule silently switches protection off for a name, so honouring
        one from a source that could be hijacked would let it un-block whatever
        it liked with nothing looking wrong.
        """
        result = parse_rules("||ads.example.com^\n@@||malware.example^", "test")
        self.assertFalse(result.allow.match("malware.example"))
        self.assertEqual(result.allow_rules_ignored, 1)

    def test_exception_rules_honoured_when_trusted(self):
        result = parse_rules("@@||good.example.com^", "test", trust_allow_rules=True)
        self.assertTrue(result.allow.match("good.example.com"))
        self.assertEqual(result.allow_rules_ignored, 0)

    def test_plain_domain_list(self):
        result = parse_rules("tracker.example\nanalytics.example", "test")
        self.assertTrue(result.block.match("tracker.example"))
        self.assertTrue(result.block.match("analytics.example"))

    def test_wildcard(self):
        result = parse_rules("*.doubleclick.net", "test")
        self.assertTrue(result.block.match("ad.doubleclick.net"))
        self.assertTrue(result.block.match("doubleclick.net"))

    def test_comments_and_blanks(self):
        result = parse_rules(
            "# a comment\n! another\n\n; third\n[Adblock Plus]\nreal.example\n", "test"
        )
        self.assertTrue(result.block.match("real.example"))
        self.assertEqual(len(result.block), 1)

    def test_trailing_comment_stripped(self):
        result = parse_rules("0.0.0.0 ads.example.com # why", "test")
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertFalse(result.block.match("why"))

    def test_exact_mode(self):
        result = parse_rules(
            "0.0.0.0 ads.example.com", "test", hosts_match_subdomains=False
        )
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertFalse(result.block.match("sub.ads.example.com"))

    def test_unsupported_adblock_rules_are_not_domains(self):
        result = parse_rules("example.com##.ad-banner\n||example.com/path", "test")
        self.assertFalse(result.block.match("example.com"))

    def test_garbage_is_counted_not_crashed(self):
        result = parse_rules("!!!\n@@@\n   \n<<<>>>\n", "test")
        self.assertEqual(len(result.block), 0)


class NormaliseTests(unittest.TestCase):
    def test_strips_scheme_and_case(self):
        self.assertEqual(blocklist._normalise("HTTPS://Ads.Example.COM/x"), "ads.example.com")

    def test_rejects_invalid(self):
        for candidate in ("", "..", "a b", "-bad.com", "x" * 300):
            self.assertEqual(blocklist._normalise(candidate), "", candidate)

    def test_accepts_underscore(self):
        # Underscores are illegal in hostnames but common in real blocklists.
        self.assertEqual(blocklist._normalise("_dmarc.example.com"), "_dmarc.example.com")


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_loads_local_file(self):
        source = self.root / "list.txt"
        source.write_text("0.0.0.0 ads.example.com\n")
        manager = BlocklistManager(self.root / "cache")
        manager.load([str(source)])
        self.assertTrue(manager.is_blocked("ads.example.com"))
        self.assertEqual(manager.sources[str(source)].rules, 1)

    def test_config_rules_applied(self):
        manager = BlocklistManager(self.root / "cache")
        manager.load([], extra_block=["bad.example"], extra_allow=["good.example"])
        self.assertTrue(manager.is_blocked("sub.bad.example"))
        self.assertTrue(manager.is_allowed("good.example"))

    def test_failed_source_recorded_not_raised(self):
        manager = BlocklistManager(self.root / "cache")
        manager.load([str(self.root / "missing.txt")])
        stats = next(iter(manager.sources.values()))
        self.assertTrue(stats.error)
        self.assertEqual(manager.rule_count, 0)

    def test_a_collapsed_download_is_refused(self):
        """A list that loses most of its rules is broken or hijacked."""
        manager = BlocklistManager(self.root / "cache")
        # 5000 rules previously, 3 now: far below the threshold.
        self.assertTrue(manager._has_collapsed("https://list.example/hosts", 3, 5000))

    def test_a_normal_download_is_accepted(self):
        manager = BlocklistManager(self.root / "cache")
        self.assertFalse(manager._has_collapsed("https://list.example/hosts", 4800, 5000))

    def test_a_small_list_is_not_judged(self):
        # Too small a baseline to tell a collapse from a legitimately short list.
        manager = BlocklistManager(self.root / "cache")
        self.assertFalse(manager._has_collapsed("https://list.example/hosts", 2, 40))

    def test_a_local_file_is_never_judged(self):
        # Shrinking a file on disk is its owner editing it.
        manager = BlocklistManager(self.root / "cache")
        self.assertFalse(manager._has_collapsed("/etc/symbivpn/mylist.txt", 3, 5000))

    def test_the_check_can_be_disabled(self):
        manager = BlocklistManager(self.root / "cache", collapse_threshold=0.0)
        self.assertFalse(manager._has_collapsed("https://list.example/hosts", 3, 5000))

    def test_a_collapsed_source_keeps_the_previous_rules(self):
        source = self.root / "list.txt"
        source.write_text("\n".join(f"0.0.0.0 h{i}.example.com" for i in range(2000)))
        manager = BlocklistManager(self.root / "cache")
        manager.load([str(source)])
        self.assertEqual(manager.rule_count, 2000)

    def test_doh_bypass_list_is_substantial(self):
        self.assertGreater(len(blocklist.DOH_BOOTSTRAP_DOMAINS), 30)
        self.assertIn("dns.google", blocklist.DOH_BOOTSTRAP_DOMAINS)
        self.assertIn("use-application-dns.net", blocklist.DOH_BOOTSTRAP_DOMAINS)


class RemoteRegexTests(unittest.TestCase):
    """A downloaded list does not get to write a regex.

    Every regex is run against every name the network looks up, so one crafted
    pattern is not a bad rule -- it is a stall for every device at once.
    """

    def test_a_regex_from_a_list_is_refused(self):
        result = parse_rules("/(a+)+b$/", "https://lists.example/x.txt")
        self.assertEqual(len(result.block.regex), 0)
        self.assertEqual(result.regexes_refused, 1)

    def test_the_rest_of_the_list_still_loads(self):
        result = parse_rules(
            "/(a+)+b$/\nads.example.com\n", "https://lists.example/x.txt"
        )
        self.assertEqual(result.regexes_refused, 1)
        self.assertTrue(result.block.match("ads.example.com"))

    def test_an_explicitly_trusted_source_may_write_one(self):
        result = parse_rules("/^ads[0-9]+\\./", "config", trust_regex_rules=True)
        self.assertEqual(len(result.block.regex), 1)

    def test_a_refused_regex_never_runs(self):
        # The measurement that matters: with the pattern refused, a name that
        # would have taken exponential time costs nothing.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "list.txt").write_text("/(a+)+b$/\n")

        manager = BlocklistManager(root / "cache")
        manager.load([str(root / "list.txt")])
        self.assertEqual(len(manager.block.regex), 0)

        started = time.perf_counter()
        manager.is_blocked("a" * 32 + ".example.com")
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_a_regex_from_the_local_config_still_applies(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manager = BlocklistManager(Path(tmp.name) / "cache")
        manager.load([], extra_regex=[r"^ads[0-9]+\."])
        self.assertTrue(manager.is_blocked("ads42.example.com"))
        self.assertFalse(manager.is_blocked("news.example.com"))


class ListSizeTests(unittest.TestCase):
    """A list is read into memory, and we ask for it gzipped."""

    def serve(self, body, *, gzipped):
        """Serve one response and return the URL it is at."""
        class Once(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                if gzipped:
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        server = http.server.HTTPServer(("127.0.0.1", port), Once)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # shutdown() stops the loop; server_close() releases the listening
        # socket. Without the second the suite emits a ResourceWarning, which
        # is exactly the noise that hides a real leak later.
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{port}/list.txt"

    def test_a_gzip_bomb_is_refused(self):
        # Around 1000:1, which is what gzip manages on repetitive input: a body
        # well inside any sane download cap still expands past this machine.
        bomb = gzip.compress(b"\0" * (MAX_LIST_BYTES * 4), compresslevel=9)
        self.assertLess(len(bomb), MAX_LIST_BYTES)
        with self.assertRaises(ValueError) as caught:
            BlocklistManager._download(self.serve(bomb, gzipped=True), {})
        self.assertIn("expands to more than", str(caught.exception))

    def test_an_oversized_plain_body_is_refused(self):
        body = b"x.example.com\n" * 10
        with mock.patch.object(blocklist_module, "MAX_LIST_BYTES", 8):
            with self.assertRaises(ValueError) as caught:
                BlocklistManager._download(self.serve(body, gzipped=False), {})
        self.assertIn("larger than", str(caught.exception))

    def test_an_ordinary_list_still_downloads(self):
        body = b"0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com\n"
        text, _ = BlocklistManager._download(self.serve(body, gzipped=False), {})
        self.assertIn("ads.example.com", text)

    def test_an_ordinary_gzipped_list_still_downloads(self):
        body = gzip.compress(b"0.0.0.0 ads.example.com\n")
        text, _ = BlocklistManager._download(self.serve(body, gzipped=True), {})
        self.assertIn("ads.example.com", text)


if __name__ == "__main__":
    unittest.main()
