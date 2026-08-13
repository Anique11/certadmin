"""Shared helpers for behavioural tests."""

from pathlib import Path

from certadmin import config


def file_state(path: Path) -> tuple[bytes, int, int]:
    """Return content, permissions, and modification time for a file."""
    stat = path.stat()
    return path.read_bytes(), stat.st_mode, stat.st_mtime_ns


def create_protected_files(*operation_files: Path) -> tuple[Path, ...]:
    """Create sentinels and return all files an operation must not modify."""
    client_sentinel = config.CLIENTS_PATH / "keep-client-file"
    client_sentinel.write_bytes(b"unchanged client content")
    share_sentinel = config.P12_SHARE_PATH / "keep-share-file"
    share_sentinel.write_bytes(b"unchanged share content")
    return (
        *operation_files,
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
