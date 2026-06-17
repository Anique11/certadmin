"""Expose a PKCS12 bundle for client download"""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse

from lib.exposure import expose_p12



def run(args: argparse.Namespace) -> None:
    """Expose a PKCS12 bundle for client download"""
    expose_p12(args.common_name)
