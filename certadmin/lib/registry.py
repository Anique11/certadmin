"""Registry handling for certificate information.

This module provides functions to manage the certificate registry, 
which is a JSON file that stores information about enrolled certificates,
their status (active, revoked, exposed), and other relevant details. 

The registry allows the certificate management system to keep track of 
all certificates and their states.
"""
from __future__ import annotations
from typing import TYPE_CHECKING, TypedDict
if TYPE_CHECKING:
    from typing import Callable, Iterator, ParamSpec, TypeVar
    P = ParamSpec("P")
    R = TypeVar("R")

from contextlib import contextmanager
import fcntl
from functools import wraps
import json

from certadmin import config
from certadmin.lib.util import runtime_state

class RegistryEntry(TypedDict):
    user: str
    device: str
    serial: str
    not_before: str
    not_after: str
    revoked: bool


RegistryData = dict[str, RegistryEntry]
CertInfo = dict[str, str]


@contextmanager
def registry_write_lock() -> Iterator[None]:
    """Hold an exclusive lock for registry read-modify-write operations."""
    lock_path = config.REGISTRY_PATH.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def with_registry_write_lock(func: Callable[P, R]) -> Callable[P, R]:
    """Run a registry write operation under the registry write lock."""
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        with registry_write_lock():
            return func(*args, **kwargs)
    return wrapper


def load_registry() -> RegistryData:
    """Load the certificate registry from the JSON file.

    Returns:
        Registry data mapping common name to registry entry.
    """
    try:
        with open(config.REGISTRY_PATH) as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"Registry file {config.REGISTRY_PATH} not found. "
              "Starting with empty registry.")
        return {}

def save_registry(registry_data: RegistryData) -> None:
    """Save the certificate registry to the JSON file.

    Args:
        registry_data: Registry data to persist.
    """
    # write to temp file first to avoid corruption in case of write errors
    tmp_registry = config.REGISTRY_PATH.with_suffix(".tmp")
    with open(tmp_registry, "w") as f:
        json.dump(registry_data, f, indent=4)
    tmp_registry.replace(config.REGISTRY_PATH)

def get_registry_entry(common_name: str) -> RegistryEntry:
    """Get a registry entry for a given common name.

    Args:
        common_name: The certificate common name to look up.

    Raises:
        ValueError: If the certificate is not found in the registry.
            Use 'list' command to see all registered certificates.
    """
    registry_data = load_registry()
    if common_name not in registry_data:
        raise ValueError(
            f"Certificate with common name '{common_name}' not found in registry.\n"
            "Use 'list' command to see all registered certificates."
        )
    return registry_data[common_name]

@with_registry_write_lock
def add_entry(cert_info: CertInfo) -> None:
    """Add a new certificate entry to the registry.

    Args:
        cert_info: Certificate metadata extracted from the certificate.

    Raises:
        ValueError: If the certificate already exists and force is not enabled.
    """
    common_name = cert_info["common_name"]
    registry_data = load_registry()
    if not runtime_state.force_overwrite and common_name in registry_data:
        raise ValueError(
            f"Certificate with common name '{common_name}' "
            "already exists in registry.\n"
            "Use --force to overwrite existing registry entry."
        )
    print(f"Registering new certificate: {common_name}")
    user, device = common_name.split("-", 1)
    new_entry = {
        "user": user,
        "device": device,
        "serial": cert_info["serial"],
        "not_before": cert_info["not_before"],
        "not_after": cert_info["not_after"],
        "revoked": False
    }
    registry_data[common_name] = new_entry
    save_registry(registry_data)

@with_registry_write_lock
def mark_revoked(common_name: str) -> None:
    """Mark the certificate with the given common name as revoked.

    Args:
        common_name: The certificate common name to revoke.

    Raises:
        ValueError: If the certificate is not found in the registry.
            Use 'list' command to see all registered certificates.
    """
    registry_data = load_registry()
    if common_name not in registry_data:
        raise ValueError(
            f"Certificate with common name '{common_name}' not found in registry.\n"
            "Use 'list' command to see all registered certificates."
        )
    registry_data[common_name]["revoked"] = True
    save_registry(registry_data)
    

def list_active_certs() -> RegistryData:
    """List all active certificates."""
    registry_data = load_registry()
    return {cn: entry for cn, entry in registry_data.items() 
            if not entry["revoked"]}

def is_revoked(common_name: str) -> bool:
    """Check if a certificate is revoked."""
    entry = get_registry_entry(common_name)
    return entry["revoked"]

def list_revoked_certs() -> RegistryData:
    """List all revoked certificates."""
    registry_data = load_registry()
    return {cn: entry for cn, entry in registry_data.items()
            if entry["revoked"]}
