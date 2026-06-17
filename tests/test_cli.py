import pytest

from certadmin import config
from certadmin import certadmin as certadmin_module


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


# Command-line parsing tests - valid cases


def test_parser_accepts_valid_enroll():
    """Parser should succeed with valid enroll arguments."""
    parser = certadmin_module.build_parser()
    args = parser.parse_args(["enroll", "alice", "iphone14"])
    assert args.user == "alice"
    assert args.device == "iphone14"


def test_parser_accepts_valid_expose():
    """Parser should succeed with valid expose arguments."""
    parser = certadmin_module.build_parser()
    args = parser.parse_args(["expose", "alice-iphone14"])
    assert args.common_name == "alice-iphone14"


def test_parser_accepts_list_with_no_arguments():
    """Parser should accept list command with no extra arguments."""
    parser = certadmin_module.build_parser()
    args = parser.parse_args(["list"])
    assert args.active is False
    assert args.revoked is False
    assert args.exposed is False
    assert args.unexposed is False


def test_parser_accepts_flags():
    """Parser should accept --dry-run and --force flags."""
    parser = certadmin_module.build_parser()
    args = parser.parse_args(["--dry-run", "enroll", "alice", "iphone14"])
    assert args.dry_run is True
    assert args.force is False
    
    args = parser.parse_args(["--force", "expose", "alice-iphone14"])
    assert args.force is True
    assert args.dry_run is False
    
    args = parser.parse_args(["--dry-run", "--force", "list"])
    assert args.dry_run is True
    assert args.force is True


# Error message tests
def test_missing_subcommand_error_message(capsys):
    """Error message should guide user when subcommand is missing."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    captured = capsys.readouterr()
    
    # Message should mention required argument or usage
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "usage" in error_output.lower()


def test_unknown_subcommand_error_message(capsys):
    """Error message should identify unknown subcommand."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["badcommand"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "badcommand" in error_output or "invalid choice" in error_output.lower()


def test_enroll_missing_arguments_error_message(capsys):
    """Error message should specify which arguments are needed for enroll."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["enroll"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "user" in error_output.lower()


def test_enroll_missing_device_error_message(capsys):
    """Error message should specify device is needed when only user provided."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["enroll", "alice"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "device" in error_output.lower()


def test_expose_missing_argument_error_message(capsys):
    """Error message should specify common_name is needed for expose."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["expose"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_unexpose_missing_argument_error_message(capsys):
    """Error message should specify common_name is needed for unexpose."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["unexpose"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_revoke_missing_argument_error_message(capsys):
    """Error message should specify common_name is needed for revoke."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["revoke"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_show_missing_argument_error_message(capsys):
    """Error message should specify common_name is needed for show."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["show"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "required" in error_output.lower() or "common_name" in error_output.lower()


def test_list_with_mutually_exclusive_flags_error_message(capsys):
    """Error message should indicate list flags are mutually exclusive."""
    parser = certadmin_module.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["list", "--active", "--revoked"])
    captured = capsys.readouterr()
    
    error_output = captured.err + captured.out
    assert "not allowed" in error_output.lower() or "mutually exclusive" in error_output.lower() or "argument" in error_output.lower()
