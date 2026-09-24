import shutil
from pathlib import Path

import pytest
import yaml

from frfw.cli import main

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def test_validate_valid_config(example_config_path, capsys):
    exit_code = main(["validate", str(example_config_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "OK" in out


def test_validate_invalid_config_returns_1(tmp_path, minimal_config_dict, capsys):
    del minimal_config_dict["hostname"]
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text(yaml.safe_dump(minimal_config_dict))

    exit_code = main(["validate", str(bad_config)])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "hostname" in err


def test_validate_missing_file_returns_1(tmp_path, capsys):
    exit_code = main(["validate", str(tmp_path / "nope.yaml")])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "not found" in err.lower()


def test_render_prints_ruleset(example_config_path, capsys):
    exit_code = main(["render", str(example_config_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "table inet fr_os" in out


@requires_nft
def test_apply_dry_run_does_not_touch_kernel_state(example_config_path, capsys):
    exit_code = main(["apply", str(example_config_path), "--dry-run"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "dry-run" in out.lower()


def test_detect_interfaces_runs(capsys):
    exit_code = main(["detect-interfaces", "--include-virtual"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "NAME" in out


def test_assign_interfaces_writes_valid_config(tmp_path):
    out_path = tmp_path / "generated.yaml"
    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--opt",
            "dmz:eth2",
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0
    assert out_path.exists()
    assert main(["validate", str(out_path)]) == 0


def test_assign_interfaces_refuses_to_overwrite_without_force(tmp_path):
    out_path = tmp_path / "generated.yaml"
    out_path.write_text("existing")

    exit_code = main(
        ["assign-interfaces", "--wan", "eth0", "--lan", "eth1", "--out", str(out_path)]
    )

    assert exit_code == 1
    assert out_path.read_text() == "existing"


def test_assign_interfaces_overwrites_with_force(tmp_path):
    out_path = tmp_path / "generated.yaml"
    out_path.write_text("existing")

    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--out",
            str(out_path),
            "--force",
        ]
    )

    assert exit_code == 0
    assert "existing" not in out_path.read_text()


def test_assign_interfaces_rejects_malformed_opt(tmp_path, capsys):
    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--opt",
            "not-a-mapping",
            "--out",
            str(tmp_path / "x.yaml"),
        ]
    )
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "ZONE:DEVICE" in err


def test_rollback_list_prints_backups(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.list_backups", lambda: [Path("/backups/ruleset-x.nft")])
    exit_code = main(["rollback", "--list"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ruleset-x.nft" in out


def test_rollback_list_empty(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.list_backups", lambda: [])
    exit_code = main(["rollback", "--list"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No backups found" in out


def test_rollback_invokes_rollback_last(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.rollback_last", lambda: Path("/backups/ruleset-y.nft"))
    exit_code = main(["rollback"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ruleset-y.nft" in out


def test_set_admin_password_success(tmp_path, monkeypatch, capsys):
    from frfw.admin_account import AdminStore

    monkeypatch.setattr("frfw.cli.AdminStore", lambda: AdminStore(tmp_path / "auth.json"))
    passwords = iter(["hunter22", "hunter22"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(passwords))

    exit_code = main(["set-admin-password"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "set" in out
    assert AdminStore(tmp_path / "auth.json").verify("admin", "hunter22")


def test_set_admin_password_mismatch_fails(tmp_path, monkeypatch, capsys):
    from frfw.admin_account import AdminStore

    monkeypatch.setattr("frfw.cli.AdminStore", lambda: AdminStore(tmp_path / "auth.json"))
    passwords = iter(["hunter22", "different"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(passwords))

    exit_code = main(["set-admin-password"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "do not match" in err
    assert not AdminStore(tmp_path / "auth.json").exists()


def test_set_admin_password_too_short_fails(tmp_path, monkeypatch, capsys):
    from frfw.admin_account import AdminStore

    monkeypatch.setattr("frfw.cli.AdminStore", lambda: AdminStore(tmp_path / "auth.json"))
    passwords = iter(["short", "short"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(passwords))

    exit_code = main(["set-admin-password"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "at least 8 characters" in err


def test_set_admin_password_generate_is_noninteractive(tmp_path, monkeypatch, capsys):
    from frfw.admin_account import AdminStore

    store = AdminStore(tmp_path / "auth.json")
    monkeypatch.setattr("frfw.cli.AdminStore", lambda: store)

    def _fail_if_prompted(prompt=""):
        raise AssertionError("--generate must not prompt")

    monkeypatch.setattr("getpass.getpass", _fail_if_prompted)

    exit_code = main(["set-admin-password", "--generate"])
    out = capsys.readouterr().out.strip()

    assert exit_code == 0
    assert len(out.splitlines()) == 1  # only the password, nothing else
    assert store.verify("admin", out)


def test_set_admin_password_generate_uses_username(tmp_path, monkeypatch, capsys):
    from frfw.admin_account import AdminStore

    store = AdminStore(tmp_path / "auth.json")
    monkeypatch.setattr("frfw.cli.AdminStore", lambda: store)

    exit_code = main(["set-admin-password", "--generate", "--username", "root-admin"])
    password = capsys.readouterr().out.strip()

    assert exit_code == 0
    assert store.verify("root-admin", password)
    assert not store.verify("admin", password)


def test_update_check_reports_available_update(tmp_path, monkeypatch, capsys):
    from frfw import update as update_mod

    result = update_mod.UpdateCheckResult(
        current_version="0.1.0",
        latest=update_mod.ReleaseInfo(tag="v0.2.0", version="0.2.0", notes="fixes stuff"),
        update_available=True,
        checked_at="2026-01-01T00:00:00Z",
    )
    monkeypatch.setattr("frfw.cli.update_mod.check_latest", lambda *a, **kw: result)

    missing_config = tmp_path / "no-such-config.yaml"
    exit_code = main(["update", "check", str(missing_config)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "0.1.0" in out
    assert "0.2.0" in out
    assert "Update available" in out
    assert "fixes stuff" in out


def test_update_check_no_releases_yet(monkeypatch, tmp_path, capsys):
    from frfw import update as update_mod

    result = update_mod.UpdateCheckResult(
        current_version="0.1.0", latest=None, update_available=False, checked_at="x"
    )
    monkeypatch.setattr("frfw.cli.update_mod.check_latest", lambda *a, **kw: result)

    exit_code = main(["update", "check", str(tmp_path / "no-such-config.yaml")])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No releases published" in out


def test_update_apply_invokes_apply_update(monkeypatch, capsys):
    from frfw import update as update_mod

    calls = []
    monkeypatch.setattr(
        "frfw.cli.update_mod.apply_update",
        lambda version, repo: calls.append((version, repo)) or "0.2.0",
    )

    exit_code = main(["update", "apply", "0.2.0", "--repo", "x/y"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert calls == [("0.2.0", "x/y")]
    assert "0.2.0" in out


def test_update_apply_failure_returns_1(monkeypatch, capsys):
    from frfw import update as update_mod

    def boom(version, repo):
        raise update_mod.UpdateError("no network")

    monkeypatch.setattr("frfw.cli.update_mod.apply_update", boom)

    exit_code = main(["update", "apply", "0.2.0"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "no network" in err


def test_update_rollback_invokes_rollback_update(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.update_mod.rollback_update", lambda repo: "0.1.0")

    exit_code = main(["update", "rollback"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "0.1.0" in out


def test_iot_status_lists_isolated_macs(monkeypatch, capsys):
    import frfw.cli as cli_mod

    monkeypatch.setattr(cli_mod, "list_isolated", lambda: ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"])
    assert main(["iot-status"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "IoT isolation: currently isolated devices:",
        "  aa:bb:cc:dd:ee:01",
        "  aa:bb:cc:dd:ee:02",
    ]


def test_iot_status_nft_error_returns_1(monkeypatch, capsys):
    import frfw.cli as cli_mod
    from frfw.iot_isolation import IotIsolationError

    def boom():
        raise IotIsolationError("'nft' binary not found; install the nftables package")

    monkeypatch.setattr(cli_mod, "list_isolated", boom)
    assert main(["iot-status"]) == 1
    assert "IoT isolation error" in capsys.readouterr().err


def test_apps_status_ranks_apps_by_activity(monkeypatch, capsys):
    import frfw.cli as cli_mod

    usage = {"generated": 1, "apps": {
        "zoom": {"hits_24h": 50, "active_clients": 0, "clients": {"10.0.0.9": {}}},
        "netflix": {"hits_24h": 3, "active_clients": 1, "clients": {"10.0.0.5": {}}},
    }}
    monkeypatch.setattr(cli_mod, "load_usage", lambda: usage)
    assert main(["apps-status", "--limit", "5"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1].startswith("Netflix") and lines[1].endswith("10.0.0.5")
    assert lines[2].startswith("Zoom")


def test_apps_status_without_data(monkeypatch, capsys):
    import frfw.cli as cli_mod

    monkeypatch.setattr(cli_mod, "load_usage", lambda: {"generated": None, "apps": {}})
    assert main(["apps-status"]) == 0
    assert "no usage recorded yet" in capsys.readouterr().out
