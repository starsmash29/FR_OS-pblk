"""Tests for frfw.pqc.

This sandbox has OpenSSL 3.0.13 (verified in this module's own
`test_this_sandbox_has_no_hybrid_tls_support`) and no sshd installed at
all, so every "host actually supports the hybrid algorithm" branch is
exercised via monkeypatched version tuples / fake `sshd -Q kex` output
rather than a real PQC-capable build -- see frfw.pqc's module docstring
for exactly what that does and doesn't verify.
"""

from __future__ import annotations

import ssl
import subprocess

import pytest

from frfw import pqc
from frfw.config import parse_config


def _config(*, enabled: bool, minimal_config_dict):
    minimal_config_dict["pqc"] = {"enabled": enabled}
    return parse_config(minimal_config_dict)


# --- capability detection ----------------------------------------------------


def test_this_sandbox_has_no_hybrid_tls_support():
    """Ground truth for every other test in this module: this
    development sandbox's real, unmocked OpenSSL predates 3.5 and has
    never heard of ML-KEM."""
    assert ssl.OPENSSL_VERSION_INFO < (3, 5, 0)
    assert pqc.openssl_supports_hybrid_tls() is False


@pytest.mark.parametrize(
    "version, expected",
    [
        ((3, 5, 0), True),
        ((3, 5, 1), True),
        ((4, 0, 0), True),
        ((3, 4, 99), False),
        ((3, 0, 13), False),
        ((1, 1, 1), False),
    ],
)
def test_openssl_supports_hybrid_tls_version_boundary(version, expected):
    assert pqc.openssl_supports_hybrid_tls(version) is expected


def test_set_ecdh_curve_cannot_express_a_group_priority_list():
    """Documents the exact CPython stdlib limitation frfw.pqc's module
    docstring describes: `SSLContext.set_ecdh_curve` resolves its
    argument as a single classic EC curve name and rejects a
    colon-joined list outright, even when every individual name in it is
    a valid TLS 1.3 group name. This is why frfw.pqc configures the
    group list via an OpenSSL config fragment instead."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ecdh_curve("X25519")  # a single, real name: works
    with pytest.raises(ValueError):
        ctx.set_ecdh_curve("X25519:P-256")  # a list: CPython rejects it


def test_sshd_supported_kex_methods_returns_empty_set_when_sshd_missing():
    assert pqc.sshd_supported_kex_methods(sshd_binary="definitely-not-a-real-binary") == set()


def test_sshd_supported_kex_methods_parses_fake_sshd_output(monkeypatch):
    def fake_run(args, **kwargs):
        assert args == ["/usr/sbin/sshd", "-Q", "kex"]
        return subprocess.CompletedProcess(
            args, 0, stdout="curve25519-sha256\nmlkem768x25519-sha256\n", stderr=""
        )

    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc.subprocess, "run", fake_run)

    methods = pqc.sshd_supported_kex_methods()
    assert methods == {"curve25519-sha256", "mlkem768x25519-sha256"}
    assert pqc.openssh_supports_hybrid_kex(methods) is True


def test_openssh_supports_hybrid_kex_false_for_older_build():
    methods = {"curve25519-sha256", "ecdh-sha2-nistp256"}
    assert pqc.openssh_supports_hybrid_kex(methods) is False


def test_build_kex_line_puts_hybrid_first():
    line = pqc.build_kex_line(hybrid=True)
    methods = line.split(",")
    assert methods[0] == pqc.MLKEM_KEX_NAME
    assert methods[1:] == list(pqc.CLASSICAL_KEX_FALLBACK)


def test_build_kex_line_classical_only():
    line = pqc.build_kex_line(hybrid=False)
    assert pqc.MLKEM_KEX_NAME not in line.split(",")
    assert line.split(",") == list(pqc.CLASSICAL_KEX_FALLBACK)


# --- TLS: SSLContext hardening + config-fragment generation -----------------


def test_tls_ssl_context_factory_restricts_to_tls13_only():
    real_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx = pqc.tls_ssl_context_factory(uvicorn_config=object(), default_factory=lambda: real_ctx)
    assert ctx is real_ctx
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3


def test_tls_ssl_context_factory_integrates_with_real_uvicorn_config(tmp_path):
    """Unlike the test above (a bare unit check of the factory function
    itself), this drives it through a real `uvicorn.Config(...).load()`
    with real generated cert/key files -- the actual code path
    frfw.webui.server.main() exercises -- to catch an integration break
    against the installed uvicorn version that a pure unit test of the
    factory in isolation could miss."""
    import uvicorn

    from frfw.webui.tls import ensure_self_signed_cert

    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    ensure_self_signed_cert(cert_path, key_path)

    async def app(scope, receive, send):  # pragma: no cover -- never actually invoked
        raise AssertionError("app should never be called by Config.load()")

    config = uvicorn.Config(
        app,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        ssl_context_factory=pqc.tls_ssl_context_factory,
    )
    config.load()

    assert config.ssl.minimum_version == ssl.TLSVersion.TLSv1_3
    assert config.ssl.maximum_version == ssl.TLSVersion.TLSv1_3


def test_write_and_read_openssl_pqc_conf_hybrid(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=True)
    assert pqc.read_configured_tls_groups(conf_path) == pqc.HYBRID_TLS_GROUPS
    assert "MinProtocol = TLSv1.3" in conf_path.read_text()
    assert "MaxProtocol = TLSv1.3" in conf_path.read_text()


def test_write_and_read_openssl_pqc_conf_classical(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=False)
    assert pqc.read_configured_tls_groups(conf_path) == pqc.CLASSICAL_TLS_GROUPS
    assert "MLKEM" not in conf_path.read_text()


def test_read_configured_tls_groups_missing_file_returns_none(tmp_path):
    assert pqc.read_configured_tls_groups(tmp_path / "does-not-exist.cnf") is None


def test_sync_tls_pqc_conf_disabled_and_never_applied_is_a_pure_read(tmp_path):
    """The important safety property: when PQC is (and always was)
    disabled, this must never attempt to create the conf file or its
    parent directory -- frfw.provision's own tests call this with the
    real system default path in scenarios that have nothing to do with
    PQC, and that must stay side-effect-free."""
    conf_path = tmp_path / "does" / "not" / "exist.cnf"
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})

    result = pqc.sync_tls_pqc_conf(config, conf_path=conf_path)

    assert result.hybrid_active is False
    assert "disabled" in result.message.lower()
    assert not conf_path.exists()
    assert not conf_path.parent.exists()


def test_sync_tls_pqc_conf_disabling_reverts_a_previously_hybrid_file(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=True)
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})

    result = pqc.sync_tls_pqc_conf(config, conf_path=conf_path)

    assert result.hybrid_active is False
    assert pqc.read_configured_tls_groups(conf_path) == pqc.CLASSICAL_TLS_GROUPS


def test_sync_tls_pqc_conf_disabling_dry_run_does_not_write(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=True)
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})

    result = pqc.sync_tls_pqc_conf(config, dry_run=True, conf_path=conf_path)

    assert "would" in result.message.lower()
    assert pqc.read_configured_tls_groups(conf_path) == pqc.HYBRID_TLS_GROUPS  # unchanged


def test_sync_tls_pqc_conf_enabled_but_host_unsupported_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc, "openssl_supports_hybrid_tls", lambda: False)
    conf_path = tmp_path / "pqc.cnf"
    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})

    result = pqc.sync_tls_pqc_conf(config, conf_path=conf_path)

    assert result.hybrid_active is False
    assert "older than 3.5" in result.message
    assert pqc.read_configured_tls_groups(conf_path) == pqc.CLASSICAL_TLS_GROUPS


def test_sync_tls_pqc_conf_enabled_and_host_supports_it(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc, "openssl_supports_hybrid_tls", lambda: True)
    conf_path = tmp_path / "pqc.cnf"
    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})

    result = pqc.sync_tls_pqc_conf(config, conf_path=conf_path)

    assert result.hybrid_active is True
    assert "restart fr-webui" in result.message
    assert pqc.read_configured_tls_groups(conf_path) == pqc.HYBRID_TLS_GROUPS


def test_sync_tls_pqc_conf_enabled_dry_run_does_not_write(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc, "openssl_supports_hybrid_tls", lambda: True)
    conf_path = tmp_path / "pqc.cnf"
    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})

    result = pqc.sync_tls_pqc_conf(config, dry_run=True, conf_path=conf_path)

    assert result.hybrid_active is True
    assert "dry-run" in result.message.lower()
    assert not conf_path.exists()


# --- SSH: sshd_config.d drop-in generation -----------------------------------


def test_sync_ssh_kex_noop_when_sshd_not_installed(tmp_path):
    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    result = pqc.sync_ssh_kex(config, dropin_path=dropin_path, sshd_binary="not-a-real-binary")

    assert result.hybrid_active is False
    assert "not installed" in result.message
    assert not dropin_path.exists()


def test_sync_ssh_kex_disabled_and_never_applied_is_a_pure_read(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})
    dropin_path = tmp_path / "does" / "not" / "exist.conf"

    result = pqc.sync_ssh_kex(config, dropin_path=dropin_path)

    assert result.hybrid_active is False
    assert not dropin_path.exists()
    assert not dropin_path.parent.exists()


def test_sync_ssh_kex_enabled_and_supported_writes_and_reloads(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: {pqc.MLKEM_KEX_NAME})
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(pqc, "_test_sshd_config", lambda binary: calls.append(("test", binary)))
    monkeypatch.setattr(pqc, "_reload_ssh_service", lambda: calls.append("reload"))

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    result = pqc.sync_ssh_kex(config, dropin_path=dropin_path)

    assert result.hybrid_active is True
    assert f"KexAlgorithms {pqc.build_kex_line(hybrid=True)}" in dropin_path.read_text()
    assert calls == [("test", "sshd"), "reload"]


def test_sync_ssh_kex_enabled_but_host_unsupported_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: set())
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(pqc, "_test_sshd_config", lambda binary: None)
    monkeypatch.setattr(pqc, "_reload_ssh_service", lambda: None)

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    result = pqc.sync_ssh_kex(config, dropin_path=dropin_path)

    assert result.hybrid_active is False
    assert "older than OpenSSH 9.9" in result.message
    content = dropin_path.read_text()
    assert pqc.MLKEM_KEX_NAME not in content
    assert pqc.CLASSICAL_KEX_FALLBACK[0] in content


def test_sync_ssh_kex_requires_root_for_a_real_apply(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: {pqc.MLKEM_KEX_NAME})
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    with pytest.raises(pqc.PqcError, match="root"):
        pqc.sync_ssh_kex(config, dropin_path=dropin_path)
    assert not dropin_path.exists()


def test_sync_ssh_kex_backs_out_a_config_sshd_rejects(tmp_path, monkeypatch):
    """The critical lockout-prevention property: if `sshd -t` rejects
    the freshly-written drop-in for any reason, the previous file
    content must be restored rather than left in a state sshd can't
    parse on its next reload/restart."""
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: {pqc.MLKEM_KEX_NAME})
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def failing_test(binary):
        raise pqc.PqcError("sshd -t rejected the generated KexAlgorithms drop-in")

    monkeypatch.setattr(pqc, "_test_sshd_config", failing_test)
    reload_calls = []
    monkeypatch.setattr(pqc, "_reload_ssh_service", lambda: reload_calls.append(True))

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"
    dropin_path.write_text("KexAlgorithms curve25519-sha256\n")  # pre-existing content

    with pytest.raises(pqc.PqcError):
        pqc.sync_ssh_kex(config, dropin_path=dropin_path)

    assert dropin_path.read_text() == "KexAlgorithms curve25519-sha256\n"  # restored
    assert reload_calls == []  # never reloaded a config that failed its own test


def test_sync_ssh_kex_backs_out_to_no_file_when_there_was_none_before(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: {pqc.MLKEM_KEX_NAME})
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def failing_test(binary):
        raise pqc.PqcError("nope")

    monkeypatch.setattr(pqc, "_test_sshd_config", failing_test)
    monkeypatch.setattr(pqc, "_reload_ssh_service", lambda: None)

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    with pytest.raises(pqc.PqcError):
        pqc.sync_ssh_kex(config, dropin_path=dropin_path)

    assert not dropin_path.exists()


def test_sync_ssh_kex_dry_run_never_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(pqc.shutil, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(pqc, "sshd_supported_kex_methods", lambda binary: {pqc.MLKEM_KEX_NAME})

    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})
    dropin_path = tmp_path / "dropin.conf"

    result = pqc.sync_ssh_kex(config, dry_run=True, dropin_path=dropin_path)

    assert result.hybrid_active is True
    assert "dry-run" in result.message.lower()
    assert not dropin_path.exists()


# --- combined status ----------------------------------------------------------


def test_get_status_disabled_no_sshd(tmp_path):
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})
    status = pqc.get_status(
        config,
        conf_path=tmp_path / "pqc.cnf",
        dropin_path=tmp_path / "dropin.conf",
        sshd_binary="not-a-real-binary",
    )

    assert status.enabled_in_config is False
    assert status.tls_host_supports_hybrid is False  # real check against this sandbox's OpenSSL
    assert status.ssh_installed is False
    assert status.quantum_safe is False


def test_get_status_reflects_last_applied_tls_conf(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=True)
    config = parse_config({**_bare_dict(), "pqc": {"enabled": True}})

    status = pqc.get_status(
        config, conf_path=conf_path, dropin_path=tmp_path / "dropin.conf", sshd_binary="none"
    )

    assert status.tls_applied_hybrid is True
    # quantum_safe also needs the host to actually support it, which this
    # sandbox's real OpenSSL does not -- applying a hybrid conf on a host
    # too old to use it must never be reported as "safe".
    assert status.quantum_safe is False


def test_quantum_safe_requires_both_enabled_and_applied(tmp_path):
    conf_path = tmp_path / "pqc.cnf"
    pqc.write_openssl_pqc_conf(conf_path, hybrid=True)
    config = parse_config({**_bare_dict(), "pqc": {"enabled": False}})

    status = pqc.get_status(
        config, conf_path=conf_path, dropin_path=tmp_path / "dropin.conf", sshd_binary="none"
    )

    # The file still says hybrid (stale from a previous apply the admin
    # hasn't re-run yet), but config now says disabled -- must not claim
    # quantum-safe based on stale on-disk state alone.
    assert status.tls_applied_hybrid is True
    assert status.quantum_safe is False


def _bare_dict() -> dict:
    return {
        "version": 1,
        "hostname": "fr-router",
        "zones": {"wan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"}},
        "rules": [],
    }
