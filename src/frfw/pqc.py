"""Best-effort hybrid (classical + post-quantum) key exchange for the
management layer: the webUI's own HTTPS listener and, if this host also
runs sshd, its SSH KexAlgorithms. See ARCHITECTURE.md's PQC section for
the full design writeup; this docstring covers the two hard version
floors everything here is gated on, and why each is checked for real
rather than assumed.

- **TLS**: OpenSSL 3.5.0 (released 2025-04) is the first release with
  ML-KEM (FIPS 203) support and the `X25519MLKEM768` hybrid TLS 1.3
  group. Older OpenSSL -- which is what most currently-shipping Debian
  releases still link, including this project's own installer base
  image -- has never heard of it, and there is no way around that from
  Python: `ssl.SSLContext` wraps whatever libssl.so the interpreter was
  built against, and no pip package can upgrade that shared library.
  `openssl_supports_hybrid_tls()` below is a real version check against
  `ssl.OPENSSL_VERSION_INFO`, not an assumption.

- **SSH**: OpenSSH added the `mlkem768x25519-sha256` key-exchange method
  in 9.9 (2024-09). Older sshd builds don't recognize the name at all,
  and -- critically -- naming an unrecognized algorithm in
  `KexAlgorithms` makes sshd refuse to *start* (a config-parse error),
  not silently skip it. `sync_ssh_kex` below queries the installed
  sshd's own compiled-in algorithm list (`sshd -Q kex`) immediately
  before writing anything, and additionally validates the generated
  drop-in with `sshd -t` before treating it as applied, backing the
  file out again if that check fails -- this is not optional caution,
  it is the difference between "gracefully falls back to classical" and
  "locks the admin out of SSH on the next daemon reload."

Both capability checks run fresh on every call rather than being cached
in config or state -- an OpenSSL/OpenSSH package upgrade should be
picked up on the very next `apply`, not require a separate "recheck"
step, and neither check is expensive enough to justify caching.

**A wrinkle specific to TLS, worth stating plainly**: CPython's
`ssl.SSLContext` has never grown a public API for configuring TLS 1.3
"groups" as a priority list. `SSLContext.set_ecdh_curve()` looks like it
might do this but doesn't -- empirically (see this module's test
suite), it resolves its argument through OpenSSL's classic
single-object (`OBJ_sn2nid`) EC curve name table and rejects anything
containing a ":" outright, even a colon-joined pair of individually
valid TLS 1.3 group names ("X25519:P-256" raises "unknown elliptic
curve name"). It can select exactly one legacy curve, never a priority
list, and a hybrid PQC group name is not in that curve table at all
regardless of the underlying OpenSSL's actual capability. The
documented, always-reliable mechanism for a *list* of TLS 1.3 groups is
instead OpenSSL's own config-file `[system_default_sect]` `Groups=`
directive -- the same mechanism Debian/Fedora already use system-wide
for `CipherString`-based crypto-policy defaults (see `man 5 config`) --
which is what `write_openssl_pqc_conf` generates. Because OpenSSL only
reads this file once, the first time anything in the process touches
libssl, toggling it always requires restarting fr-webui to take
effect -- the same "config change needs a restart/apply to become
live" reality every other subsystem in this project already has.

This whole module was written and reviewed without access to an actual
OpenSSL 3.5+ or OpenSSH 9.9+ build (this development sandbox has
OpenSSL 3.0.13 and no sshd at all) -- every capability check has
therefore been verified to *correctly detect absence* on this box, but
the positive "hybrid group actually negotiates end-to-end" path has not
been exercised against a real PQC-capable build. Treat that path as
implemented-per-specification, not as independently verified the way
this project's other kernel-facing subsystems (nftables, XDP, ZTNA)
were.
"""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frfw import svc
from frfw import paths
from frfw.config.schema import Config


class PqcError(Exception):
    pass


# --- TLS: hybrid group support + OpenSSL config-fragment generation --------

#: First OpenSSL release with ML-KEM / X25519MLKEM768 support.
MIN_OPENSSL_FOR_HYBRID_TLS = (3, 5, 0)

#: TLS 1.3 group preference list written into the generated OpenSSL
#: config when the host supports it: the hybrid group first, then
#: pure-classical fallbacks for any peer that doesn't offer it. This is
#: the entire "seamless fallback for old browsers" requirement -- it
#: needs no fallback code of its own, since a TLS 1.3 ClientHello always
#: carries its own supported_groups list and OpenSSL picks the
#: most-preferred name present in both lists.
HYBRID_TLS_GROUPS = "X25519MLKEM768:X25519:P-256"

#: Same fallback chain without the hybrid group, used when PQC is
#: disabled or the host's OpenSSL doesn't support it -- TLS 1.3-only is
#: still enforced either way (see `tls_ssl_context_factory`).
CLASSICAL_TLS_GROUPS = "X25519:P-256"


def openssl_supports_hybrid_tls(version_info: tuple[int, ...] | None = None) -> bool:
    """True if the OpenSSL this interpreter is linked against is new
    enough to recognize the X25519MLKEM768 group name at all.

    Purely a version check, not a test handshake -- OpenSSL doesn't
    expose "does this build know group X" any other way short of trying
    to use it and inspecting the resulting error, and every caller here
    needs an answer *before* attempting anything (see module docstring).
    """
    info = version_info if version_info is not None else ssl.OPENSSL_VERSION_INFO
    return tuple(info[:3]) >= MIN_OPENSSL_FOR_HYBRID_TLS


_OPENSSL_CNF_TEMPLATE = """\
# Managed by FR_OS (frfw.pqc) -- regenerated on every `apply`, do not
# edit by hand. Referenced only via fr-webui.service's OPENSSL_CONF=
# environment variable (see systemd/fr-webui.service): this affects the
# webUI's own TLS listener alone, never the system-wide
# /etc/ssl/openssl.cnf or any other process on the host.
openssl_conf = fr_os_conf

[fr_os_conf]
ssl_conf = fr_os_ssl_conf

[fr_os_ssl_conf]
system_default = fr_os_ssl_defaults

[fr_os_ssl_defaults]
Groups = {groups}
MinProtocol = TLSv1.3
MaxProtocol = TLSv1.3
"""


def write_openssl_pqc_conf(path: Path, *, hybrid: bool) -> None:
    """Write the OpenSSL config fragment fr-webui's `OPENSSL_CONF`
    points at.

    Always writes *something* valid (TLS 1.3-only, classical groups)
    even when `hybrid=False`, rather than leaving no file at all -- this
    file's existence is unconditional (baked into the systemd unit), so
    there must always be something for it to point at.
    """
    groups = HYBRID_TLS_GROUPS if hybrid else CLASSICAL_TLS_GROUPS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_OPENSSL_CNF_TEMPLATE.format(groups=groups))


def read_configured_tls_groups(path: Path) -> str | None:
    """Read back the `Groups=` value from a previously-written fragment,
    for status display -- `None` if the file doesn't exist yet (PQC has
    never been applied on this host)."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Groups"):
            _, _, value = line.partition("=")
            return value.strip()
    return None


def tls_ssl_context_factory(uvicorn_config: object, default_factory) -> ssl.SSLContext:
    """`uvicorn.Config(ssl_context_factory=...)` hook (see
    frfw.webui.server): takes the context uvicorn would otherwise build
    from `ssl_certfile`/`ssl_keyfile` and restricts it to TLS 1.3 only.

    This -- unlike the group selection above -- *is* directly supported
    by `ssl.SSLContext` with no OpenSSL-version caveats: `minimum_version`/
    `maximum_version` have worked since Python 3.7 against any OpenSSL
    with basic TLS 1.3 support (1.1.1+), which is every OpenSSL this
    project targets. The actual hybrid-group preference itself still
    comes from `OPENSSL_CONF` (see module docstring) -- this factory
    exists only for the part of requirement #1 that *is* a supported
    per-context setting.
    """
    ctx = default_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


@dataclass(frozen=True)
class TlsPqcResult:
    hybrid_active: bool
    message: str


def sync_tls_pqc_conf(
    config: Config,
    *,
    dry_run: bool = False,
    conf_path: Path = paths.PQC_OPENSSL_CONF_PATH,
) -> TlsPqcResult:
    """Refresh the OpenSSL config fragment to match `config.pqc.enabled`
    and the host's actual OpenSSL capability. Called from
    `frfw.provision.apply_all`.

    Never touches the already-running fr-webui process -- OpenSSL reads
    `OPENSSL_CONF` once, at the *next* process start, so an admin must
    still restart fr-webui after a change for it to take effect (the
    same "restart to pick up a change" reality the update mechanism
    already surfaces to admins for a different reason).
    """
    if not config.pqc.enabled:
        current = read_configured_tls_groups(conf_path)
        if current is None or "MLKEM" not in current:
            # Never written, or already classical-only -- a real no-op,
            # so this is a pure read: no write is attempted (matching
            # frfw.xdp's own "check state, only act if something would
            # actually change" pattern), which matters because this
            # function is called with the real system default conf_path
            # in several tests/CLI paths that never touch PQC at all.
            return TlsPqcResult(
                hybrid_active=False,
                message="PQC hybrid TLS disabled (classical X25519/P-256, TLS 1.3-only)",
            )
        if dry_run:
            return TlsPqcResult(
                False, f"Would revert {conf_path} to classical-only TLS groups (dry-run)"
            )
        write_openssl_pqc_conf(conf_path, hybrid=False)
        return TlsPqcResult(
            hybrid_active=False,
            message="PQC hybrid TLS disabled (reverted to classical X25519/P-256)",
        )

    supported = openssl_supports_hybrid_tls()
    if dry_run:
        state = "X25519MLKEM768" if supported else "classical-only (host OpenSSL too old)"
        return TlsPqcResult(supported, f"Would enable PQC hybrid TLS ({state}, dry-run)")

    write_openssl_pqc_conf(conf_path, hybrid=supported)
    if supported:
        return TlsPqcResult(
            hybrid_active=True,
            message="PQC hybrid TLS enabled (X25519MLKEM768) -- restart fr-webui to load it",
        )
    return TlsPqcResult(
        hybrid_active=False,
        message=(
            f"PQC hybrid TLS requested but host OpenSSL {ssl.OPENSSL_VERSION} is "
            "older than 3.5 and has no ML-KEM support; falling back to classical "
            "X25519/P-256 (TLS 1.3-only is still enforced)"
        ),
    )


# --- SSH: hybrid KEX support + sshd_config.d drop-in generation ------------

#: OpenSSH key-exchange method added in OpenSSH 9.9 (2024-09).
MLKEM_KEX_NAME = "mlkem768x25519-sha256"

#: Classical fallback KEX methods, listed explicitly (rather than
#: relying on sshd's own compiled-in default list) so the generated
#: drop-in is a complete, self-contained KexAlgorithms line regardless
#: of whatever else sshd_config does or doesn't already set.
CLASSICAL_KEX_FALLBACK = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
)

_SSHD_DROPIN_TEMPLATE = """\
# Managed by FR_OS (frfw.pqc) -- regenerated on every `apply`, do not
# edit by hand. Requires sshd_config's default
# `Include /etc/ssh/sshd_config.d/*.conf` (Debian's own default since
# the openssh 8.4p1 packaging); never touches /etc/ssh/sshd_config
# itself.
KexAlgorithms {kex_line}
"""


def sshd_supported_kex_methods(sshd_binary: str = "sshd") -> set[str]:
    """Query the installed sshd build's own compiled-in KEX method list
    (`sshd -Q kex`) -- the only reliable way to know whether it
    recognizes `mlkem768x25519-sha256` before ever writing that name
    into a config sshd has to parse.

    Returns an empty set (never raises) if sshd isn't installed at all
    or the query fails for any reason: "not installed" and "doesn't
    support it" mean exactly the same thing to every caller here --
    don't write the hybrid KEX name.
    """
    sshd = shutil.which(sshd_binary)
    if sshd is None:
        return set()
    try:
        proc = subprocess.run([sshd, "-Q", "kex"], capture_output=True, text=True)
    except OSError:
        return set()
    if proc.returncode != 0:
        return set()
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def openssh_supports_hybrid_kex(methods: set[str] | None = None) -> bool:
    supported = methods if methods is not None else sshd_supported_kex_methods()
    return MLKEM_KEX_NAME in supported


def build_kex_line(*, hybrid: bool) -> str:
    """`hybrid=True` puts the ML-KEM hybrid method first, per requirement
    #2 ("at the absolute top of the preferred key-exchange algorithm
    list"); `hybrid=False` is the classical-only fallback list. Never
    called with `hybrid=True` unless `openssh_supports_hybrid_kex()` has
    already confirmed the installed sshd recognizes the name."""
    methods = ([MLKEM_KEX_NAME] if hybrid else []) + list(CLASSICAL_KEX_FALLBACK)
    return ",".join(methods)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PqcError("Applying the sshd PQC KexAlgorithms drop-in requires root privileges.")


def _test_sshd_config(sshd_binary: str) -> None:
    try:
        proc = subprocess.run([sshd_binary, "-t"], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise PqcError(f"{sshd_binary!r} binary not found; install openssh-server") from exc
    if proc.returncode != 0:
        raise PqcError(
            proc.stderr.strip() or "sshd -t rejected the generated KexAlgorithms drop-in"
        )


def _reload_ssh_service() -> None:
    try:
        proc = svc.systemctl("reload", "ssh")
    except FileNotFoundError as exc:
        raise PqcError("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise PqcError(proc.stderr.strip() or "failed to reload the ssh service")


@dataclass(frozen=True)
class SshPqcResult:
    hybrid_active: bool
    message: str


def sync_ssh_kex(
    config: Config,
    *,
    dry_run: bool = False,
    dropin_path: Path = paths.SSHD_PQC_DROPIN_PATH,
    sshd_binary: str = "sshd",
) -> SshPqcResult:
    """Reconcile the sshd_config.d KexAlgorithms drop-in with
    `config.pqc.enabled` and the installed sshd's actual capabilities.
    Called from `frfw.provision.apply_all`; a no-op (and never touches
    sshd) if this host has no sshd installed at all -- FR_OS doesn't
    require SSH management to be present.

    Safety invariants that make this safe to run unattended on a box the
    admin might currently be SSH'd into:

    - `sshd -Q kex` is queried fresh on every call, never assumed or
      cached, so a `mlkem768x25519-sha256` name is never written unless
      the *currently installed* sshd build already claims to support it.
    - The generated drop-in is validated with `sshd -t` before being
      treated as applied; if that check fails for any reason, the
      previous drop-in content (or its absence) is restored rather than
      leaving a config sshd can't parse in place.
    - The running daemon is *reloaded*, never restarted -- a reload
      re-reads config for new connections without dropping any
      already-established SSH session, including the one the admin may
      be applying this change from.
    """
    if shutil.which(sshd_binary) is None:
        return SshPqcResult(False, "sshd not installed; nothing to do")

    if not config.pqc.enabled:
        if not dropin_path.exists():
            return SshPqcResult(False, "PQC hybrid SSH KEX disabled")
        if dry_run:
            return SshPqcResult(False, f"Would remove {dropin_path} (PQC disabled, dry-run)")
        _require_root()
        dropin_path.unlink()
        _reload_ssh_service()
        return SshPqcResult(False, "PQC hybrid SSH KEX disabled")

    supported = openssh_supports_hybrid_kex(sshd_supported_kex_methods(sshd_binary))
    kex_line = build_kex_line(hybrid=supported)
    content = _SSHD_DROPIN_TEMPLATE.format(kex_line=kex_line)

    if dry_run:
        state = MLKEM_KEX_NAME if supported else "classical-only (host sshd too old)"
        return SshPqcResult(supported, f"Would write {dropin_path} ({state}, dry-run)")

    _require_root()
    dropin_path.parent.mkdir(parents=True, exist_ok=True)
    previous = dropin_path.read_text() if dropin_path.exists() else None
    dropin_path.write_text(content)
    try:
        _test_sshd_config(sshd_binary)
    except PqcError:
        if previous is not None:
            dropin_path.write_text(previous)
        else:
            dropin_path.unlink(missing_ok=True)
        raise
    _reload_ssh_service()

    if supported:
        return SshPqcResult(True, f"PQC hybrid SSH KEX active ({MLKEM_KEX_NAME})")
    return SshPqcResult(
        False,
        "PQC hybrid SSH KEX requested but installed sshd is older than OpenSSH 9.9 "
        f"and doesn't support {MLKEM_KEX_NAME}; falling back to classical-only KexAlgorithms",
    )


# --- Combined status, for the webUI's /system screen -----------------------


@dataclass(frozen=True)
class PqcStatus:
    """Everything the /system screen needs to render honestly. Two
    different notions of "on" are kept separate throughout this module
    and here: *host capability* (does the installed OpenSSL/OpenSSH
    build support this at all -- a fact about the machine, independent
    of config) and *configured* (what the on-disk generated
    fragment/drop-in currently says -- reflects the last `apply`, which
    can lag behind an as-yet-unapplied config edit, the same
    "config vs. applied state can drift until you apply" pattern the
    XDP screen already has). Neither implies "this exact currently-open
    browser/SSH connection is using the hybrid group" -- that would
    require introspecting the negotiated group of one specific TLS/SSH
    session, which neither Python's `ssl` module nor this module attempt
    to do (see module docstring's verification-scope note)."""

    enabled_in_config: bool
    tls_host_supports_hybrid: bool
    tls_openssl_version: str
    tls_configured_groups: str | None
    ssh_installed: bool
    ssh_host_supports_hybrid: bool
    ssh_dropin_active: bool

    @property
    def tls_applied_hybrid(self) -> bool:
        return self.tls_configured_groups is not None and "MLKEM" in self.tls_configured_groups

    @property
    def quantum_safe(self) -> bool:
        """Best-effort "is the management layer currently hardened"
        summary for the small nav-bar badge: true only when hybrid PQC
        is enabled in config, the last apply actually wrote the hybrid
        group into the TLS conf, *and* the host's own OpenSSL genuinely
        supports it. That last check matters on its own: `tls_configured_
        groups` reflects whatever a *previous* apply wrote, which could
        predate an OpenSSL downgrade/reinstall -- a stale hybrid-looking
        file on a host that can no longer use it must never be reported
        as safe. See the class docstring for what this still doesn't
        prove about any one connection."""
        return (
            self.enabled_in_config
            and self.tls_applied_hybrid
            and self.tls_host_supports_hybrid
        )


def get_status(
    config: Config,
    *,
    conf_path: Path = paths.PQC_OPENSSL_CONF_PATH,
    dropin_path: Path = paths.SSHD_PQC_DROPIN_PATH,
    sshd_binary: str = "sshd",
) -> PqcStatus:
    tls_supported = openssl_supports_hybrid_tls()
    configured_groups = read_configured_tls_groups(conf_path)

    ssh_installed = shutil.which(sshd_binary) is not None
    ssh_methods = sshd_supported_kex_methods(sshd_binary) if ssh_installed else set()
    ssh_supported = openssh_supports_hybrid_kex(ssh_methods)
    ssh_dropin_active = ssh_supported and dropin_path.exists()

    return PqcStatus(
        enabled_in_config=config.pqc.enabled,
        tls_host_supports_hybrid=tls_supported,
        tls_openssl_version=ssl.OPENSSL_VERSION,
        tls_configured_groups=configured_groups,
        ssh_installed=ssh_installed,
        ssh_host_supports_hybrid=ssh_supported,
        ssh_dropin_active=ssh_dropin_active,
    )
