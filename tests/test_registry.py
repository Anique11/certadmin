from pathlib import Path

import pytest

from certadmin import config
from certadmin.lib import registry


def test_load_registry_starts_empty_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PKI_BASE_PATH", str(tmp_path))
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)
    monkeypatch.setattr(config, "REGISTRY_PATH", tmp_path / "registry.json")
    config.REGISTRY_PATH.unlink()

    loaded = registry.load_registry()
    assert loaded == {}


def test_add_entry_and_get_registry_entry(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PKI_BASE_PATH", str(tmp_path))
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)
    monkeypatch.setattr(config, "REGISTRY_PATH", tmp_path / "registry.json")

    cert_info = {
        "common_name": "anique-iphone14",
        "serial": "1004",
        "not_before": "2026-06-01T19:41:44+00:00",
        "not_after": "2036-05-29T19:41:44+00:00"
    }
    registry.add_entry(cert_info)

    entry = registry.get_registry_entry("anique-iphone14")
    assert entry["user"] == "anique"
    assert entry["device"] == "iphone14"
    assert entry["serial"] == "1004"
    assert not entry["revoked"]


def test_mark_revoked_updates_registry(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PKI_BASE_PATH", str(tmp_path))
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)
    monkeypatch.setattr(config, "REGISTRY_PATH", tmp_path / "registry.json")

    cert_info = {
        "common_name": "anique-iphone14",
        "serial": "1004",
        "not_before": "2026-06-01T19:41:44+00:00",
        "not_after": "2036-05-29T19:41:44+00:00"
    }
    registry.add_entry(cert_info)
    registry.mark_revoked("anique-iphone14")

    entry = registry.get_registry_entry("anique-iphone14")
    assert entry["revoked"] is True


def test_list_active_and_revoked_certs(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PKI_BASE_PATH", str(tmp_path))
    monkeypatch.setattr(config, "BASE_PATH", tmp_path)
    monkeypatch.setattr(config, "REGISTRY_PATH", tmp_path / "registry.json")

    registry.add_entry({
        "common_name": "anique-iphone14",
        "serial": "1004",
        "not_before": "2026-06-01T19:41:44+00:00",
        "not_after": "2036-05-29T19:41:44+00:00"
    })
    registry.add_entry({
        "common_name": "another-phone",
        "serial": "1005",
        "not_before": "2026-06-02T19:41:44+00:00",
        "not_after": "2036-05-30T19:41:44+00:00"
    })
    registry.mark_revoked("another-phone")

    active = registry.list_active_certs()
    revoked = registry.list_revoked_certs()

    assert "anique-iphone14" in active
    assert "another-phone" not in active
    assert "another-phone" in revoked
    assert "anique-iphone14" not in revoked
