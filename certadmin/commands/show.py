"""Handles showing certificate details from the registry.
It will retrieve the certificate info from the registry 
and display it in a human-readable format.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse

from lib.exposure import is_exposed
from lib.registry import get_registry_entry



def run(args: argparse.Namespace) -> None:
    """Show certificate details from the registry"""
    entry = get_registry_entry(args.common_name)
    exposed = not entry["revoked"] and is_exposed(args.common_name)

    print(f"Common name : {args.common_name}")
    print(f"User        : {entry['user']}")
    print(f"Device      : {entry['device']}")
    print(f"Serial      : {entry['serial']}")
    print(f"Not before  : {entry['not_before']}")
    print(f"Not after   : {entry['not_after']}")
    print(f"Revoked     : {entry['revoked']}")
    print(f"Exposed     : {exposed}")
