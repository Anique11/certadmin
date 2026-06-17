"""Revoke active certificates"""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse


from certadmin.lib.crypto import revoke_cert
from certadmin.lib.exposure import is_exposed, unexpose_p12
from certadmin.lib import registry



def run(args: argparse.Namespace) -> None:
    """Revoke a client certificate"""
    common_name = args.common_name
    print("Revoking client certificate")
    print(f"Common name: {common_name}")
    if registry.is_revoked(common_name):
        print(f"Certificate already revoked: {common_name}")
        return
    if is_exposed(common_name):
        unexpose_p12(common_name)
    
    revoke_cert(common_name)

    registry.mark_revoked(common_name)
