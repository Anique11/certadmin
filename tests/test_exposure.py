"""Behavioural tests for PKCS#12 bundle exposure."""

from pathlib import Path
import subprocess

from certadmin import config
from certadmin.lib import exposure, util


def file_state(path: Path) -> tuple[bytes, int, int]:
    """Return content, permissions, and modification time for a file."""
    stat = path.stat()
    return path.read_bytes(), stat.st_mode, stat.st_mtime_ns


def create_protected_files(protected_file: Path) -> tuple[Path, ...]:
    """Create sentinels and return all files an operation must not modify."""
    client_sentinel = config.CLIENTS_PATH / "keep-client-file"
    client_sentinel.write_bytes(b"unchanged client content")
    share_sentinel = config.P12_SHARE_PATH / "keep-share-file"
    share_sentinel.write_bytes(b"unchanged share content")
    return (
        protected_file,
        client_sentinel,
        share_sentinel,
        config.REGISTRY_PATH,
    )


def snapshot_file_states(paths: tuple[Path, ...]) -> dict[Path, tuple[bytes, int, int]]:
    """Capture content, permissions, and modification time for selected files."""
    return {
        path: file_state(path)
        for path in paths
    }


def test_expose_dry_run_does_not_modify_files(tmp_path, monkeypatch):
    """Dry-run exposure must not create, delete, or modify any files."""
    assert config.BASE_PATH == tmp_path

    common_name = "active-unexposed-ipad"
    source = config.CLIENTS_PATH / f"{common_name}.p12"
    source.write_bytes(b"PKCS12 bundle")
    source.chmod(0o600)

    exposure_path = config.P12_SHARE_PATH / source.name
    protected_files = create_protected_files(source)
    files_before = snapshot_file_states(protected_files)
    paths_before = set(tmp_path.rglob("*"))

    monkeypatch.setattr(util, "runtime_state", util.RuntimeState(dry_run=True))

    def fail_if_run(*args, **kwargs):
        raise AssertionError("Dry-run must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", fail_if_run)

    exposure.expose_p12(common_name)

    assert not exposure_path.exists()
    assert set(tmp_path.rglob("*")) == paths_before
    files_after = snapshot_file_states(protected_files)
    assert files_after == files_before


def test_unexpose_dry_run_does_not_modify_files(tmp_path, monkeypatch):
    """Dry-run unexposure must not create, delete, or modify any files."""
    assert config.BASE_PATH == tmp_path

    common_name = "active-exposed-iphone"
    exposed_bundle = config.P12_SHARE_PATH / f"{common_name}.p12"
    exposed_bundle.write_bytes(b"exposed PKCS12 bundle")
    exposed_bundle.chmod(0o640)

    protected_files = create_protected_files(exposed_bundle)
    files_before = snapshot_file_states(protected_files)
    paths_before = set(tmp_path.rglob("*"))

    monkeypatch.setattr(util, "runtime_state", util.RuntimeState(dry_run=True))

    exposure.unexpose_p12(common_name)

    assert exposed_bundle.exists()
    assert set(tmp_path.rglob("*")) == paths_before
    files_after = snapshot_file_states(protected_files)
    assert files_after == files_before
