"""Tests for frfw.adblock: hosts-format parsing, fetch/dedupe orchestration,
and the local blocklist file writer/reader.

Network calls are monkeypatched at the same single seam
(`frfw.adblock._fetch_url`) production code goes through -- mirrors
tests/test_update.py's own approach for frfw.update's `_fetch_json`.
"""

from __future__ import annotations

import pytest

from frfw import adblock


# --- parse_hosts_text --------------------------------------------------------


def test_parse_hosts_text_extracts_domains():
    text = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com", "tracker.example.net"}


def test_parse_hosts_text_strips_comments():
    text = "# this is a comment\n0.0.0.0 ads.example.com # inline comment too\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com"}


def test_parse_hosts_text_skips_blank_lines():
    text = "0.0.0.0 ads.example.com\n\n\n   \n0.0.0.0 tracker.example.com\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com", "tracker.example.com"}


def test_parse_hosts_text_ignores_reserved_hostnames():
    text = (
        "127.0.0.1 localhost\n"
        "127.0.0.1 localhost.localdomain\n"
        "::1 ip6-localhost ip6-loopback\n"
        "0.0.0.0 broadcasthost\n"
        "0.0.0.0 ads.example.com\n"
    )
    assert adblock.parse_hosts_text(text) == {"ads.example.com"}


def test_parse_hosts_text_lowercases_domains():
    assert adblock.parse_hosts_text("0.0.0.0 ADS.EXAMPLE.COM\n") == {"ads.example.com"}


def test_parse_hosts_text_dedupes():
    text = "0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com"}


def test_parse_hosts_text_skips_lines_without_a_valid_ip():
    # A real host entry an admin might have (not a blocklist line at
    # all) -- still requires a valid IP in the first column, but this
    # module doesn't special-case *which* IP, only that one is present.
    text = "not-an-ip ads.example.com\nsingle-token-line\n0.0.0.0 real.example.com\n"
    assert adblock.parse_hosts_text(text) == {"real.example.com"}


def test_parse_hosts_text_accepts_ipv6_blocking_lines():
    assert adblock.parse_hosts_text(":: ads.example.com\n") == {"ads.example.com"}


def test_parse_hosts_text_supports_multiple_hostnames_per_line():
    text = "0.0.0.0 ads.example.com tracker.example.com\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com", "tracker.example.com"}


def test_parse_hosts_text_rejects_invalid_hostnames():
    text = "0.0.0.0 not_a_valid_hostname!!\n0.0.0.0 ads.example.com\n"
    assert adblock.parse_hosts_text(text) == {"ads.example.com"}


# --- fetch_and_parse ---------------------------------------------------------


def test_fetch_and_parse_unions_multiple_sources(monkeypatch):
    responses = {
        "https://a.example/hosts": "0.0.0.0 ads-a.example.com\n",
        "https://b.example/hosts": "0.0.0.0 ads-b.example.com\n",
    }

    def fake_fetch(url, timeout):
        return responses[url]

    monkeypatch.setattr(adblock, "_fetch_url", fake_fetch)

    result = adblock.fetch_and_parse(list(responses))
    assert result.domains == {"ads-a.example.com", "ads-b.example.com"}
    assert result.failed_urls == []


def test_fetch_and_parse_reports_partial_failure_without_raising(monkeypatch):
    def fake_fetch(url, timeout):
        if url == "https://bad.example/hosts":
            raise adblock.AdblockError("could not fetch")
        return "0.0.0.0 ads-good.example.com\n"

    monkeypatch.setattr(adblock, "_fetch_url", fake_fetch)

    result = adblock.fetch_and_parse(["https://good.example/hosts", "https://bad.example/hosts"])
    assert result.domains == {"ads-good.example.com"}
    assert result.failed_urls == ["https://bad.example/hosts"]


def test_fetch_and_parse_raises_when_every_source_fails(monkeypatch):
    def always_fails(url, timeout):
        raise adblock.AdblockError("x")

    monkeypatch.setattr(adblock, "_fetch_url", always_fails)

    with pytest.raises(adblock.AdblockError, match="all 2 source_urls failed"):
        adblock.fetch_and_parse(["https://a.example/hosts", "https://b.example/hosts"])


# --- write_hosts_file / count_blocked_domains --------------------------------


def test_write_hosts_file_is_sorted_and_deterministic(tmp_path):
    path = tmp_path / "adblock.hosts"
    adblock.write_hosts_file({"zzz.example.com", "aaa.example.com"}, path)

    lines = [l for l in path.read_text().splitlines() if not l.startswith("#")]
    assert lines == ["0.0.0.0 aaa.example.com", "0.0.0.0 zzz.example.com"]


def test_count_blocked_domains_counts_non_comment_lines(tmp_path):
    path = tmp_path / "adblock.hosts"
    adblock.write_hosts_file({"a.example.com", "b.example.com", "c.example.com"}, path)
    assert adblock.count_blocked_domains(path) == 3


def test_count_blocked_domains_missing_file_is_zero(tmp_path):
    assert adblock.count_blocked_domains(tmp_path / "does-not-exist.hosts") == 0


# --- refresh ------------------------------------------------------------------


def test_refresh_rejects_empty_source_urls():
    with pytest.raises(adblock.AdblockError, match="source_urls is empty"):
        adblock.refresh([])


def test_refresh_dry_run_never_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(adblock, "_fetch_url", lambda url, timeout: "0.0.0.0 ads.example.com\n")
    hosts_path = tmp_path / "adblock.hosts"

    result = adblock.refresh(["https://a.example/hosts"], hosts_path=hosts_path, dry_run=True)

    assert result.domain_count == 1
    assert "dry-run" in result.message.lower()
    assert not hosts_path.exists()


def test_refresh_requires_root_for_a_real_write(tmp_path, monkeypatch):
    monkeypatch.setattr(adblock, "_fetch_url", lambda url, timeout: "0.0.0.0 ads.example.com\n")
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    hosts_path = tmp_path / "adblock.hosts"

    with pytest.raises(adblock.AdblockError, match="root"):
        adblock.refresh(["https://a.example/hosts"], hosts_path=hosts_path)
    assert not hosts_path.exists()


def test_refresh_writes_deduped_file_as_root(tmp_path, monkeypatch):
    monkeypatch.setattr(adblock, "_fetch_url", lambda url, timeout: "0.0.0.0 ads.example.com\n")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    hosts_path = tmp_path / "adblock.hosts"

    result = adblock.refresh(["https://a.example/hosts"], hosts_path=hosts_path)

    assert result.domain_count == 1
    assert result.failed_urls == []
    assert adblock.count_blocked_domains(hosts_path) == 1


def test_refresh_message_mentions_failed_sources(tmp_path, monkeypatch):
    def fake_fetch(url, timeout):
        if url == "https://bad.example/hosts":
            raise adblock.AdblockError("x")
        return "0.0.0.0 ads.example.com\n"

    monkeypatch.setattr(adblock, "_fetch_url", fake_fetch)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    hosts_path = tmp_path / "adblock.hosts"

    result = adblock.refresh(
        ["https://good.example/hosts", "https://bad.example/hosts"], hosts_path=hosts_path
    )
    assert "1 source(s) failed" in result.message
