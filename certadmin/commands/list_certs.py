"""List certificates in the registry."""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse
    from typing import Any
    from certadmin.lib.registry import RegistryData

from certadmin.lib import registry
from certadmin.lib.exposure import is_exposed

def display_list(reg_list: dict[str, Any]) -> None:
    """Print dictionary keys as a numbered list."""
    names = sorted(reg_list.keys())
    for pos, name in enumerate(names, start=1):
        print(f"{pos:3d}. {name}")

def list_exposed_certs() -> RegistryData:
    """List all exposed certificates."""
    active = registry.list_active_certs()
    return {cn: entry for cn, entry in active.items()
            if is_exposed(cn)}

def list_unexposed_certs() -> RegistryData:
    """List all unexposed certificates."""
    active = registry.list_active_certs()
    return {cn: entry for cn, entry in active.items()
            if not is_exposed(cn)}


def run(args: argparse.Namespace) -> None:
    """List enrolled client certificates"""
    print("Listing enrolled client certificates")

    if args.active:
        print("Showing active certificates")
        reg_list = registry.list_active_certs()
    elif args.revoked:
        print("Showing revoked certificates")
        reg_list = registry.list_revoked_certs()
    elif args.exposed:
        print("Showing exposed certificates")
        reg_list = list_exposed_certs()
    elif args.unexposed:
        print("Showing unexposed certificates")
        reg_list = list_unexposed_certs()
    else:
        print("No filter specified, showing all certificates")
        reg_list = registry.load_registry()
    
    display_list(reg_list)
