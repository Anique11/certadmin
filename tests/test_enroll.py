"""Behavioural tests for certificate enrolment."""

import argparse
import subprocess

from certadmin import config
from certadmin.commands import enroll
from certadmin.lib import util
from tests.util import create_protected_files, snapshot_file_states


def test_enroll_dry_run_does_not_modify_files(tmp_path, monkeypatch):
    """Dry-run enrolment must not create, delete, or modify any files."""
    assert config.BASE_PATH == tmp_path

    common_name = "newuser-newdevice"
    generated_files = (
        config.CLIENTS_PATH / f"{common_name}.key.pem",
        config.CLIENTS_PATH / f"{common_name}.csr.pem",
        config.ISSUED_CERTS_PATH / f"{common_name}.cert.pem",
        config.CLIENTS_PATH / f"{common_name}.p12",
    )

    protected_files = create_protected_files()
    files_before = snapshot_file_states(protected_files)
    paths_before = set(tmp_path.rglob("*"))

    monkeypatch.setattr(util, "runtime_state", util.RuntimeState(dry_run=True))

    def fail_if_run(*args, **kwargs):
        raise AssertionError("Dry-run must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", fail_if_run)

    enroll.run(argparse.Namespace(user="newuser", device="newdevice"))

    assert all(not path.exists() for path in generated_files)
    assert set(tmp_path.rglob("*")) == paths_before
    files_after = snapshot_file_states(protected_files)
    assert files_after == files_before
