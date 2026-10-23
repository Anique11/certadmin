"""Orchestrate operations around enrolling a new client certificate device."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    from pathlib import Path

from certadmin import config
from certadmin.lib import crypto, enrollment, registry, util
from certadmin.lib.registry import add_entry as registry_add_entry


def run(args: argparse.Namespace) -> None:
    """Enroll a new client certificate device"""
    user = args.user
    device = args.device

    print("Enrolling new client certificate device")
    print(f"User: {user}")
    print(f"Device: {device}")

    common_name = f"{user}-{device}"
    resume = getattr(args, "resume", False)
    if resume and util.runtime_state.force_overwrite:
        raise ValueError("--resume cannot be combined with --force")
    key = config.CLIENTS_PATH / f"{common_name}.key.pem"
    csr = config.CLIENTS_PATH / f"{common_name}.csr.pem"
    cert = config.ISSUED_CERTS_PATH / f"{common_name}.cert.pem"
    p12 = config.CLIENTS_PATH / f"{common_name}.p12"
    paths = (key, csr, cert, p12)
    entry = registry.load_registry().get(common_name)
    conflicts = [str(path) for path in paths if path.exists()]
    if util.runtime_state.force_overwrite and (cert.exists() or entry is not None):
        raise ValueError("Cannot force replacement of an issued enrollment; use --resume or a new identity")
    if entry is not None:
        conflicts.append("registry entry")
    for path in paths:
        print(f"{path}: {'exists' if path.exists() else 'missing'}")
    if conflicts and not resume and not util.runtime_state.force_overwrite:
        message = "Existing enrollment artifacts: " + ", ".join(conflicts)
        message += f". Inspect them, then use enroll --resume {user} {device}."
        if util.runtime_state.dry_run:
            print(message)
            print("Enrollment blocked; no actions would be performed.")
            return
        raise ValueError(message)
    if util.runtime_state.dry_run:
        print("Pending validation: artifacts, CA database and registry; conflicts may block execution.")
        for path in paths:
            action = "Validate and reuse" if resume and path.exists() else "Create"
            print(f"{action}: {path}")
        print("Would reconcile registry after successful validation and enrollment.")
        return
    if resume:
        enrollment.validate_artifacts(common_name, key, csr, cert, p12)
    enrollment.check_ca(common_name, cert)
    if entry is not None and resume:
        if not cert.exists():
            raise ValueError("Registry entry exists without certificate; reconcile manually")
        info = crypto.get_cert_info(cert)
        if (entry["revoked"] or entry["serial"] != info["serial"]
                or entry["not_before"] != info["not_before"]
                or entry["not_after"] != info["not_after"]
                or entry["user"] != user or entry["device"] != device):
            raise ValueError("Registry conflicts with certificate; reconcile manually")
    stage = "key generation"
    try:
        if not resume or not key.exists():
            crypto.gen_key(common_name)
        stage = "CSR generation"
        if not resume or not csr.exists():
            crypto.gen_csr(common_name, key)
        stage = "certificate signing"
        if not resume or not cert.exists():
            crypto.sign_cert(common_name, csr)
        stage = "PKCS#12 export"
        if not resume or not p12.exists():
            crypto.gen_p12(common_name, key, cert)
        stage = "registry update"
        if not resume or entry is None:
            update_registry(cert)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(f"Enrollment incomplete during {stage}. Preserve artifacts and inspect with "
              f"certadmin --dry-run enroll --resume {user} {device}.")
        raise

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
