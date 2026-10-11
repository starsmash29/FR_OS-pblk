"""Who can log in, and what the router's own system files say (ROADMAP SEC-29).

The Debian files the router changes by itself -- the accounts files,
sshd_config, /etc/pam.d/login, FR_OS's sshd drop-ins -- are expected on
the persistence layer (SEC-22), so their content is judged here against
the image's copy: a second uid-0 account, a password on a locked account,
a member added to a privileged group, a key that lets someone log in,
a loosened sshd or PAM, a drop-in line FR_OS doesn't write.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from frfw import management, system_files

PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
_kea:x:100:101::/var/lib/kea:/usr/sbin/nologin
"""
SHADOW = """\
root:*:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
_kea:!:19000::::::
"""
GROUP = """\
root:x:0:
sudo:x:27:
shadow:x:42:
_kea:x:101:
"""
SSHD = """\
Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
UsePAM yes
"""
PAM_LOGIN = """\
auth       optional   pam_faildelay.so  delay=3000000
@include common-auth
"""


@pytest.fixture
def layers(tmp_path):
    lower, upper = tmp_path / "lower", tmp_path / "upper"
    for path, text in {"etc/passwd": PASSWD, "etc/shadow": SHADOW, "etc/group": GROUP,
                       "etc/ssh/sshd_config": SSHD, "etc/pam.d/login": PAM_LOGIN}.items():
        (lower / path).parent.mkdir(parents=True, exist_ok=True)
        (lower / path).write_text(text)
    upper.mkdir()
    # What frfw.accounts adds on every router.
    put(upper, "/etc/passwd", PASSWD + "fr_os-webui:x:998:998::/home/fr_os-webui:/usr/sbin/nologin\n"
                                       "fr_os-sensor:x:997:997::/home/fr_os-sensor:/usr/sbin/nologin\n")
    put(upper, "/etc/shadow", SHADOW + "fr_os-webui:!:20000::::::\nfr_os-sensor:!:20000::::::\n")
    put(upper, "/etc/group", GROUP + "fr_os-webui:x:998:\nfr_os-sensor:x:997:\n"
                                     "fr_os-feeds:x:996:fr_os-webui,fr_os-sensor\nfr_os-ssh:x:995:\n")
    return lower, upper


def put(upper: Path, path: str, text: str) -> None:
    target = upper / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def edit(layers, path: str, old: str, new: str) -> None:
    lower, upper = layers
    current = (upper / path.lstrip("/")) if (upper / path.lstrip("/")).exists() else (lower / path.lstrip("/"))
    text = current.read_text()
    assert old in text
    put(upper, path, text.replace(old, new))


def report(layers, **kwargs):
    return system_files.check(*layers, **kwargs)


def test_a_router_with_fr_os_accounts_only_is_clean(layers):
    result = report(layers)
    assert result.findings == [] and result.logins == []


def test_a_second_uid_0_account_is_found(layers):
    edit(layers, "/etc/passwd", "daemon:x:1:1:", "daemon:x:0:1:")
    edit(layers, "/etc/passwd", "fr_os-sensor:x:997", "fr_os-sensor:x:997")  # untouched
    lower, upper = layers
    put(upper, "/etc/passwd", (upper / "etc/passwd").read_text() + "toor:x:0:0::/root:/bin/sh\n")
    findings = report(layers).findings
    assert "/etc/passwd: daemon has uid 0" in findings
    assert "/etc/passwd: daemon's uid changed from 1 to 0" in findings
    assert "/etc/passwd: toor has uid 0" in findings
    assert "/etc/passwd: an account the image doesn't have: toor (uid 0, shell /bin/sh)" in findings


def test_a_password_on_a_locked_account_and_an_empty_one_are_found(layers):
    edit(layers, "/etc/shadow", "root:*:", "root:$y$j9T$salt$hash:")
    edit(layers, "/etc/shadow", "_kea:!:", "_kea::")
    result = report(layers)
    assert "/etc/shadow: root has a password; the image's account is locked" in result.findings
    assert "/etc/shadow: _kea has an empty password" in result.findings
    assert result.logins == ["root: password"]
    assert any(f.startswith("root can log in (password)") for f in result.findings)


def test_a_member_added_to_a_privileged_group_is_found(layers):
    edit(layers, "/etc/group", "sudo:x:27:", "sudo:x:27:daemon")
    edit(layers, "/etc/group", "fr_os-feeds:x:996:fr_os-webui,fr_os-sensor", "fr_os-feeds:x:996:fr_os-webui,fr_os-sensor,_kea")
    findings = report(layers).findings
    assert findings == ["/etc/group: _kea was added to the privileged group fr_os-feeds",
                        "/etc/group: daemon was added to the privileged group sudo"]


def test_an_fr_os_account_with_a_login_shell_is_found(layers):
    edit(layers, "/etc/passwd", "fr_os-webui:x:998:998::/home/fr_os-webui:/usr/sbin/nologin",
         "fr_os-webui:x:998:998::/home/fr_os-webui:/bin/bash")
    assert report(layers).findings == ["/etc/passwd: FR_OS's account fr_os-webui has the login shell /bin/bash"]


def test_a_key_for_root_is_a_login(layers):
    _lower, upper = layers
    put(upper, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA attacker\n")
    result = report(layers)
    assert result.logins == ["root: SSH key"]
    assert len(result.findings) == 1 and result.findings[0].startswith("root can log in (SSH key)")


def test_an_ssh_user_the_admin_added_is_listed_and_accepted_by_name(layers):
    _lower, upper = layers
    edit(layers, "/etc/passwd", "fr_os-sensor:x:997:997::/home/fr_os-sensor:/usr/sbin/nologin\n",
         "fr_os-sensor:x:997:997::/home/fr_os-sensor:/usr/sbin/nologin\nkolos:x:1000:1000::/home/kolos:/bin/bash\n")
    edit(layers, "/etc/shadow", "fr_os-sensor:!:", "kolos:!:20000::::::\nfr_os-sensor:!:")
    edit(layers, "/etc/group", "fr_os-ssh:x:995:", "fr_os-ssh:x:995:kolos")
    put(upper, "/home/kolos/.ssh/authorized_keys", "ssh-ed25519 AAAA kolos\n")
    unnamed = report(layers)
    assert unnamed.logins == ["kolos: SSH key"]
    assert set(unnamed.findings) == {
        "/etc/passwd: an account the image doesn't have: kolos (uid 1000, shell /bin/bash)",
        "/etc/group: kolos was added to the privileged group fr_os-ssh",
        unnamed.findings[-1],
    } and unnamed.findings[-1].startswith("kolos can log in (SSH key)")
    named = report(layers, login_ok={"kolos"})
    assert named.findings == [] and named.logins == ["kolos: SSH key"]


@pytest.mark.parametrize("path, old, new, finding", [
    ("/etc/ssh/sshd_config", "#PermitRootLogin prohibit-password", "PermitRootLogin yes",
     "/etc/ssh/sshd_config: a line the image doesn't have: PermitRootLogin yes"),
    ("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n", "",
     "/etc/ssh/sshd_config: a line of the image is gone: Include /etc/ssh/sshd_config.d/*.conf"),
    ("/etc/pam.d/login", "@include common-auth", "auth sufficient pam_permit.so\n@include common-auth",
     "/etc/pam.d/login: a line the image doesn't have: auth sufficient pam_permit.so"),
])
def test_a_loosened_sshd_or_pam_is_found(layers, path, old, new, finding):
    edit(layers, path, old, new)
    assert report(layers).findings == [finding]


def test_live_configs_own_edits_are_not_a_change(layers):
    lower, _upper = layers
    (lower / "etc/pam.d/login").write_text(PAM_LOGIN + "session    optional   pam_lastlog.so\n")
    edit(layers, "/etc/pam.d/login", "session    optional   pam_lastlog.so", "# session    optional   pam_lastlog.so")
    edit(layers, "/etc/ssh/sshd_config", "UsePAM yes", "UsePAM yes\nPasswordAuthentication no")
    assert report(layers).findings == []


def test_fstab_may_gain_only_live_boots_mounts(layers):
    lower, upper = layers
    (lower / "etc/fstab").write_text("# UNCONFIGURED FSTAB\n")
    put(upper, "/etc/fstab", "overlay / overlay rw 0 0\ntmpfs /tmp tmpfs nosuid,nodev 0 0\n")
    assert report(layers).findings == []
    put(upper, "/etc/fstab", "overlay / overlay rw 0 0\n/dev/sdb1 /usr/local/bin ext4 exec 0 0\n")
    assert report(layers).findings == ["/etc/fstab: a line the image doesn't have: /dev/sdb1 /usr/local/bin ext4 exec 0 0"]


def test_a_group_password_is_found(layers):
    lower, upper = layers
    (lower / "etc/gshadow").write_text("sudo:*::\n")
    put(upper, "/etc/gshadow", "sudo:$y$j9T$salt$hash::\n")
    assert report(layers).findings == ["/etc/gshadow: the group sudo has a password (newgrp joins it)"]


def test_comments_and_whitespace_are_not_a_change(layers):
    edit(layers, "/etc/ssh/sshd_config", "UsePAM yes", "# a note\nUsePAM    yes")
    assert report(layers).findings == []


def test_fr_os_sshd_drop_ins_hold_only_what_fr_os_writes(layers):
    _lower, upper = layers
    management_dropin, pqc_dropin = sorted(system_files.SSHD_DROPINS)  # the router's paths
    lines = ["# Managed by FR_OS", "ListenAddress 10.73.1.1", *management.SSHD_HARDENING]
    put(upper, management_dropin, "\n".join(lines) + "\n")
    put(upper, pqc_dropin, "# Managed by FR_OS\nKexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n")
    assert report(layers).findings == []

    tampered = [line for line in lines if line != "PermitRootLogin no"] + ["AuthorizedKeysCommand /tmp/x"]
    put(upper, management_dropin, "\n".join(tampered) + "\n")
    put(upper, pqc_dropin, "KexAlgorithms diffie-hellman-group1-sha1\n")
    assert report(layers).findings == [
        f"{management_dropin}: a line FR_OS doesn't write: AuthorizedKeysCommand /tmp/x",
        f"{management_dropin}: FR_OS's line is gone: PermitRootLogin no",
        f"{pqc_dropin}: a line FR_OS doesn't write: KexAlgorithms diffie-hellman-group1-sha1",
    ]


def test_a_link_in_place_of_a_file_is_not_followed(layers, tmp_path):
    _lower, upper = layers
    (tmp_path / "elsewhere").write_text("evil:x:0:0::/:/bin/sh\n")
    (upper / "etc/passwd").unlink()
    (upper / "etc/passwd").symlink_to(tmp_path / "elsewhere")
    assert "/etc/passwd: missing or unreadable" in report(layers).findings
