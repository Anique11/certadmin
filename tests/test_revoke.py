"""Behavioural tests for certificate revocation."""

import argparse
import subprocess

from certadmin import config
from certadmin.commands import revoke
from certadmin.lib import registry, util
from tests.util import create_protected_files, snapshot_file_states


def test_revoke_dry_run_does_not_modify_files(tmp_path, monkeypatch):
    """Dry-run revocation must not create, delete, or modify any files."""
    assert config.BASE_PATH == tmp_path

    common_name = "active-exposed-iphone"
    certificate = config.ISSUED_CERTS_PATH / f"{common_name}.cert.pem"
    certificate.write_bytes(b"issued certificate")
    exposed_bundle = config.P12_SHARE_PATH / f"{common_name}.p12"
    exposed_bundle.write_bytes(b"exposed PKCS12 bundle")
    exposed_bundle.chmod(0o640)
    config.CRL_PATH.write_bytes(b"existing CRL")

    protected_files = create_protected_files(
        certificate,
        exposed_bundle,
        config.CRL_PATH,
    )
    files_before = snapshot_file_states(protected_files)
    paths_before = set(tmp_path.rglob("*"))

    monkeypatch.setattr(util, "runtime_state", util.RuntimeState(dry_run=True))

    def fail_if_run(*args, **kwargs):
        raise AssertionError("Dry-run must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", fail_if_run)

    revoke.run(argparse.Namespace(common_name=common_name))

    assert exposed_bundle.exists()
    assert not registry.is_revoked(common_name)
    assert set(tmp_path.rglob("*")) == paths_before
    files_after = snapshot_file_states(protected_files)
    assert files_after == files_before
