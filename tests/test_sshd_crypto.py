"""Security-lessons H3: no downgrade in negotiated SSH crypto. The drop-in
lists only strong key exchange, ciphers and MACs -- tested against a real
sshd with a real client that asks for weak ones.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from frfw import management, pqc
from frfw.config import parse_config
from frfw.skeleton import build_skeleton_config

from tests.test_sshd_hardening import effective_sshd_config


def _config(pqc_enabled=False):
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    raw["pqc"] = {"enabled": pqc_enabled}
    return parse_config(raw)


def test_no_weak_algorithm_is_listed():
    text = management.sshd_dropin(_config())
    offered = [n for line in text.splitlines() if line.split(" ")[0] in ("KexAlgorithms", "Ciphers", "MACs")
               for n in line.split(" ", 1)[1].split(",")]
    assert offered
    for weak in ("sha1", "cbc", "md5", "3des", "arcfour", "group1-", "group14-"):
        assert not any(weak in name for name in offered), weak
    assert "hmac-sha2-256" not in offered and "hmac-sha2-512" not in offered  # only the -etm forms
    assert all(m.endswith("-etm@openssh.com") for m in management.SSHD_MACS)


def test_with_pqc_on_the_pqc_dropin_keeps_key_exchange():
    assert "KexAlgorithms" not in management.sshd_dropin(_config(pqc_enabled=True))
    assert "Ciphers" in management.sshd_dropin(_config(pqc_enabled=True))


needs_openssh = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("sshd", "ssh", "ssh-keygen")) or os.geteuid() != 0,
    reason="needs openssh-server + client and root",
)


@needs_openssh
def test_real_sshd_uses_exactly_the_strong_lists(tmp_path):
    settings = effective_sshd_config(tmp_path, management.sshd_dropin(_config()))
    assert settings["kexalgorithms"] == [",".join(management.SSHD_KEX)]
    assert settings["ciphers"] == [",".join(management.SSHD_CIPHERS)]
    assert settings["macs"] == [",".join(management.SSHD_MACS)]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_sshd(tmp_path):
    Path("/run/sshd").mkdir(exist_ok=True)
    key = tmp_path / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    (tmp_path / "40.conf").write_text(management.sshd_dropin(_config()))
    port = _free_port()
    config = tmp_path / "sshd_config"
    config.write_text(f"Include {tmp_path}/40.conf\nHostKey {key}\nPort {port}\nPidFile {tmp_path}/sshd.pid\n")
    proc = subprocess.Popen([shutil.which("sshd"), "-D", "-e", "-f", str(config)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port
    proc.terminate()
    proc.wait(timeout=10)


def _connect(port: int, *options: str) -> str:
    proc = subprocess.run(
        ["ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", *options, "nobody@127.0.0.1", "true"],
        capture_output=True, text=True, timeout=30,
    )
    return proc.stderr


@needs_openssh
@pytest.mark.parametrize("option, weak", [
    ("KexAlgorithms", "diffie-hellman-group14-sha1"),
    ("KexAlgorithms", "diffie-hellman-group1-sha1"),
    ("KexAlgorithms", "ecdh-sha2-nistp256"),
    ("Ciphers", "aes128-cbc"),
    ("Ciphers", "3des-cbc"),
    ("MACs", "hmac-sha1"),
    ("MACs", "hmac-md5"),
    ("MACs", "hmac-sha2-256"),  # encrypt-and-MAC; only the -etm variants are allowed
])
def test_a_client_asking_for_weak_crypto_is_refused(running_sshd, option, weak):
    if option == "Ciphers":
        extra = ["-c", weak]
    elif option == "MACs":
        # With an AEAD cipher (chacha20-poly1305, AES-GCM) no MAC is used
        # at all; ask for CTR so the MAC is really negotiated.
        extra = ["-c", "aes256-ctr", "-m", weak]
    else:
        extra = ["-o", f"{option}={weak}"]
    assert "Unable to negotiate" in _connect(running_sshd, *extra)


@needs_openssh
def test_a_modern_client_negotiates_and_then_needs_a_key(running_sshd):
    err = _connect(running_sshd)
    assert "Unable to negotiate" not in err
    assert "Permission denied (publickey)" in err


@needs_openssh
def test_pqc_asks_openssh_what_it_supports():
    """frfw.pqc used to run `sshd -Q kex` -- sshd has no -Q, so the hybrid
    method was never offered."""
    methods = pqc.sshd_supported_kex_methods()
    assert "curve25519-sha256" in methods
