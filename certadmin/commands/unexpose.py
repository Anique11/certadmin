"""Remove exposed PKCS12 bundle from the exposed download location."""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import argparse

from lib.exposure import unexpose_p12



def run(args: argparse.Namespace) -> None:
    """Remove exposed PKCS12 bundle"""
    unexpose_p12(args.common_name)
