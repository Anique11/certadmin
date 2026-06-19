"""Orchestrate operations around enrolling a new client certificate device."""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse
    from pathlib import Path

from certadmin.lib import crypto
from certadmin.lib.registry import add_entry as registry_add_entry
from certadmin.lib import util


def run(args: argparse.Namespace) -> None:
    """Enroll a new client certificate device"""
    user = args.user
    device = args.device

    print("Enrolling new client certificate device")
    print(f"User: {user}")
    print(f"Device: {device}")

    common_name = f"{user}-{device}"
    key = crypto.gen_key(common_name)
    csr = crypto.gen_csr(common_name, key)
    cert = crypto.sign_cert(common_name, csr)
    crypto.gen_p12(common_name, key, cert)
    update_registry(cert)

    print(f"Enrollment complete. Common name: {common_name}")
    print(f"Use 'certadmin expose {common_name}' to expose the PKCS12 bundle.")

def update_registry(cert: Path) -> None:
    """Register the newly created certificate in the registry,
    except in dry-run mode
    """
    if util.runtime_state.dry_run:
        print("Dry run does not update registry.")
        return
    
    cert_info = crypto.get_cert_info(cert)
    registry_add_entry(cert_info)
