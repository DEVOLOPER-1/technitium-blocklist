#!/usr/bin/env python3
"""Unit tests for the list parser. Run: python tests/test_parser.py (or pytest)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

from build_blocklist import normalize_domain, parents, parse_list  # noqa: E402


def _d(text, fmt="auto"):
    domains, exceptions, stats = parse_list(text)
    return set(domains), set(exceptions), stats


def test_hosts_format():
    d, _, _ = _d("0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n::1 v6.example.org\n")
    assert d == {"ads.example.com", "tracker.example.net", "v6.example.org"}, d


def test_hosts_inline_comment():
    d, _, _ = _d("0.0.0.0 ads.example.com # pushed by list\n")
    assert d == {"ads.example.com"}, d


def test_plain_domain_list():
    d, _, _ = _d("a.example.com\nb.example.com\n")
    assert d == {"a.example.com", "b.example.com"}, d


def test_comments_and_blank_lines():
    d, _, stats = _d("# comment\n! adblock comment\n[Adblock Plus 2.0]\n\n   \n")
    assert d == set() and stats["comment"] == 3, (d, stats)


def test_adblock_rules():
    d, _, _ = _d("||ads.example.com^\n||tracker.example.net^$third-party\n")
    assert d == {"ads.example.com", "tracker.example.net"}, d


def test_adblock_skipped_rules():
    _, _, stats = _d("||keep.example.com^$badfilter\n||x.example.com^$domain=a.com\n")
    assert stats["abp-skipped-option"] == 2, stats


def test_adblock_exception_becomes_allow_rule():
    d, exc, _ = _d("||ads.example.com^\n@@||good.example.com^\n")
    assert d == {"ads.example.com"} and exc == {"good.example.com"}, (d, exc)


def test_cosmetic_rules_ignored():
    d, _, stats = _d("example.com##.ad-banner\nexample.com#@#.ad-banner\nexample.com#?#.x\n")
    assert d == set() and stats["cosmetic"] == 3, (d, stats)


def test_normalisation():
    d, _, _ = _d("ADS.Example.COM.\n*.Wild.Example.com\n")
    assert d == {"ads.example.com", "wild.example.com"}, d


def test_rejects_garbage():
    d, _, stats = _d("0.0.0.0\n192.168.1.1\nhttp://bad.example.com/x\n"
                     "-bad.example.com\nbad..example.com\nlocalhost\n")
    assert d == set(), d
    assert stats["invalid:ip"] >= 1 and stats["invalid:local-name"] == 1, stats


def test_unicode_to_punycode():
    d, r = normalize_domain("Bücher.example")
    assert r is None and d == "xn--bcher-kva.example", (d, r)


def test_length_limits():
    assert normalize_domain("a" * 64 + ".com")[1] == "bad-label"
    long_name = ".".join(["a" * 60] * 5)
    assert normalize_domain(long_name)[1] == "too-long"


def test_parents():
    assert list(parents("a.b.example.com")) == ["b.example.com", "example.com", "com"]
    assert list(parents("example.com")) == ["com"]


def test_multiple_hosts_on_one_line():
    d, _, stats = _d("0.0.0.0 a.example.com b.example.com\n")
    assert d == {"a.example.com", "b.example.com"} and stats["multi-token"] == 0, (d, stats)


def test_ip_prefix_recovery():
    d, _, stats = _d("0.0.0.0.creative.hpyrdr.com\n0.0.0.0 0.0.0.0.hpyrdr.com\n")
    assert d == {"creative.hpyrdr.com", "hpyrdr.com"}, d
    assert stats["stripped-ip-prefix"] == 2, stats


def test_numeric_subdomain_not_stripped():
    # a genuine numeric subdomain must survive untouched
    d, _, stats = _d("1.2.3.4.legit.example.com\n")
    assert d == {"1.2.3.4.legit.example.com"} and stats["stripped-ip-prefix"] == 0, (d, stats)


if __name__ == "__main__":
    failures = 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        try:
            fn()
            print("ok   %s" % name)
        except AssertionError as exc:
            failures += 1
            print("FAIL %s: %s" % (name, exc))
    print("\n%d/%d passed" % (len(tests) - failures, len(tests)))
    sys.exit(1 if failures else 0)
