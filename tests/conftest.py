import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "certadmin"
sys.path.insert(0, str(ROOT))

import config

TEST_REGISTRY_DATA = Path(__file__).parent / "registry_testdata.json"


@pytest.fixture(autouse=True)
def ensure_test_registry_dir(tmp_path: Path, monkeypatch):
    """Ensure config paths are isolated for tests."""
    monkeypatch.setenv("PKI_BASE_PATH", str(tmp_path))
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)
    monkeypatch.setattr(config, "CLIENTS_PATH", tmp_path / "clients")
    monkeypatch.setattr(config, "ISSUED_CERTS_PATH", tmp_path / "issued")
    monkeypatch.setattr(config, "P12_SHARE_PATH", tmp_path / "share")
    monkeypatch.setattr(config, "P12_SHARE_URL", "https://test.example/enroll")
    monkeypatch.setattr(config, "REGISTRY_PATH", tmp_path / "registry.json")
    monkeypatch.setattr(config, "OPENSSL_CONF", tmp_path / "openssl.cnf")
    monkeypatch.setattr(config, "CHAIN_PATH", tmp_path / "certs" / "ca-chain.pem")
    monkeypatch.setattr(config, "CRL_PATH", tmp_path / "crl" / "intermediate.crl.pem")

    # create directories referenced by tests
    (tmp_path / "clients").mkdir()
    (tmp_path / "issued").mkdir()
    (tmp_path / "share").mkdir()
    (tmp_path / "certs").mkdir()
    (tmp_path / "crl").mkdir()

    # load preloaded test registry data
    if TEST_REGISTRY_DATA.exists():
        shutil.copy(TEST_REGISTRY_DATA, tmp_path / "registry.json")

    yield
