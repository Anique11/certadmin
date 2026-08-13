from types import SimpleNamespace

import pytest

from certadmin import certadmin as certadmin_module
from certadmin import config


class FakeRuntimeState:
    dry_run = False
    force_overwrite = False
    locked = False

    def lock(self) -> None:
        self.locked = True


@pytest.fixture
def fake_runtime_state(monkeypatch):
    state = FakeRuntimeState()
    monkeypatch.setattr(certadmin_module, "runtime_state", state)
    return state


def run_cli(monkeypatch, argv: list[str]) -> None:
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", *argv])
    certadmin_module.main()


def test_validate_user_ok():
    assert certadmin_module.validate_user("alice") == "alice"
    assert certadmin_module.validate_user("bob123") == "bob123"

def test_validate_user_transforms_to_lowercase():
    assert certadmin_module.validate_user("Alice") == "alice"
    assert certadmin_module.validate_user("BOB123") == "bob123"

def test_validate_user_rejects_bad_chars():
    with pytest.raises(ValueError):
        certadmin_module.validate_user("bad-123")
    with pytest.raises(ValueError):
        certadmin_module.validate_user("bad_123")
    with pytest.raises(ValueError):
        certadmin_module.validate_user("alice!")

def test_validate_device_ok():
    assert certadmin_module.validate_device("iphone14") == "iphone14"
    assert certadmin_module.validate_device("linux-laptop") == "linux-laptop"

def test_validate_device_transforms_to_lowercase():
    assert certadmin_module.validate_device("iPhone14") == "iphone14"
    assert certadmin_module.validate_device("Linux-Laptop") == "linux-laptop"

def test_validate_device_rejects_bad_chars():
    with pytest.raises(ValueError):
        certadmin_module.validate_device("bad_device")
    with pytest.raises(ValueError):
        certadmin_module.validate_device("bad.device")
    with pytest.raises(ValueError):
        certadmin_module.validate_device("bad-device!")

def test_validate_common_name_ok():
    assert certadmin_module.validate_common_name("alice-iphone14") == "alice-iphone14"
    assert certadmin_module.validate_common_name("alice-linux-laptop") == "alice-linux-laptop"

def test_validate_common_name_rejects_missing_hyphen():
    with pytest.raises(ValueError):
        certadmin_module.validate_common_name("aliceiphone14")


def test_runtime_paths_reject_pki_state_inside_app_dir(monkeypatch):
    app_path = config.Path(config.__file__).resolve().parent
    monkeypatch.setattr(config, "BASE_PATH", app_path)

    with pytest.raises(ValueError, match="must not be stored inside"):
        config.validate_runtime_paths()


def test_runtime_paths_reject_pki_state_below_app_dir(monkeypatch):
    app_path = config.Path(config.__file__).resolve().parent
    monkeypatch.setattr(config, "BASE_PATH", app_path / "clients")

    with pytest.raises(ValueError, match="must not be stored inside"):
        config.validate_runtime_paths()


def test_runtime_paths_accept_pki_state_outside_app_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)

    config.validate_runtime_paths()


# Command-line entrypoint tests - valid cases

@pytest.mark.parametrize("package_version", ["1.2.3", "2.0.0rc1"])
def test_cli_reports_package_version(
    capsys,
    monkeypatch,
    package_version,
):
    """CLI should report the version from installed package metadata."""
    requested_distributions = []

    def fake_version(distribution_name):
        requested_distributions.append(distribution_name)
        return package_version

    monkeypatch.setattr(
        certadmin_module,
        "metadata",
        SimpleNamespace(version=fake_version),
        raising=False,
    )

    with pytest.raises(SystemExit) as exc_info:
        run_cli(monkeypatch, ["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out == f"certadmin {package_version}\n"
    assert requested_distributions == ["certadmin"]


def test_cli_accepts_valid_enroll(monkeypatch, fake_runtime_state):
    """CLI should normalize and dispatch valid enroll arguments."""
    captured_args = None

    def fake_enroll(args):
        nonlocal captured_args
        captured_args = args

    monkeypatch.setattr(certadmin_module.enroll, "run", fake_enroll)

    run_cli(monkeypatch, ["enroll", "Alice", "iPhone14"])

    assert captured_args.user == "alice"
    assert captured_args.device == "iphone14"
    assert fake_runtime_state.locked is True


def test_cli_accepts_valid_expose(monkeypatch, fake_runtime_state):
    """CLI should normalize and dispatch valid expose arguments."""
    captured_args = None

    def fake_expose(args):
        nonlocal captured_args
        captured_args = args

    monkeypatch.setattr(certadmin_module.expose, "run", fake_expose)

    run_cli(monkeypatch, ["expose", "Alice-iPhone14"])

    assert captured_args.common_name == "alice-iphone14"
    assert fake_runtime_state.locked is True


def test_cli_accepts_list_with_no_arguments(monkeypatch):
    """CLI should accept list command with no extra arguments."""
    captured_args = None

    def fake_list(args):
        nonlocal captured_args
        captured_args = args

    monkeypatch.setattr(certadmin_module.list_certs, "run", fake_list)

    run_cli(monkeypatch, ["list"])

    assert captured_args.active is False
    assert captured_args.revoked is False
    assert captured_args.exposed is False
    assert captured_args.unexposed is False


def test_cli_accepts_flags(monkeypatch, fake_runtime_state):
    """CLI should apply --dry-run and --force flags to runtime state."""
    monkeypatch.setattr(certadmin_module.list_certs, "run", lambda args: None)

    run_cli(monkeypatch, ["--dry-run", "--force", "list"])

    assert fake_runtime_state.dry_run is True
    assert fake_runtime_state.force_overwrite is True


# Error message tests
def test_missing_subcommand_error_message(capsys, monkeypatch):
    """Error message should guide user when subcommand is missing."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    # Message should mention required argument or usage
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "usage" in error_output.lower()


def test_unknown_subcommand_error_message(capsys, monkeypatch):
    """Error message should identify unknown subcommand."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "badcommand"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "badcommand" in error_output or "invalid choice" in error_output.lower()


def test_enroll_missing_arguments_error_message(capsys, monkeypatch):
    """Error message should specify which arguments are needed for enroll."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "enroll"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "user" in error_output.lower()


def test_enroll_missing_device_error_message(capsys, monkeypatch):
    """Error message should specify device is needed when only user provided."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "enroll", "alice"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "device" in error_output.lower()


def test_expose_missing_argument_error_message(capsys, monkeypatch):
    """Error message should specify common_name is needed for expose."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "expose"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_unexpose_missing_argument_error_message(capsys, monkeypatch):
    """Error message should specify common_name is needed for unexpose."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "unexpose"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_revoke_missing_argument_error_message(capsys, monkeypatch):
    """Error message should specify common_name is needed for revoke."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "revoke"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_show_missing_argument_error_message(capsys, monkeypatch):
    """Error message should specify common_name is needed for show."""
    monkeypatch.setattr(certadmin_module.sys, "argv", ["certadmin", "show"])
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_list_with_mutually_exclusive_flags_error_message(capsys, monkeypatch):
    """Error message should indicate list flags are mutually exclusive."""
    monkeypatch.setattr(
        certadmin_module.sys,
        "argv",
        ["certadmin", "list", "--active", "--revoked"],
    )
    with pytest.raises(SystemExit):
        certadmin_module.main()
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "not allowed" in error_output.lower() or "mutually exclusive" in error_output.lower() or "argument" in error_output.lower()
