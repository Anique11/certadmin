"""Behavioural tests for PKCS#12 bundle exposure."""

import subprocess

from certadmin import config
from certadmin.lib import exposure, util
from tests.util import create_protected_files, snapshot_file_states


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
