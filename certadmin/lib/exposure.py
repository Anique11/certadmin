"""Operations to move PKCS12 bundles to the enroll share for client download,
and to remove them after download.
"""

from __future__ import annotations

import shutil

from certadmin import config
from certadmin.lib.registry import is_revoked
from certadmin.lib import util


def expose_p12(common_name: str) -> None:
    """Expose a PKCS12 bundle for client download.

    Args:
        common_name: Certificate common name.

    Raises:
        ValueError: If the certificate has been revoked.
        FileNotFoundError: If the source PKCS12 bundle does not exist.
    """
    if is_revoked(common_name):
        raise ValueError(f"Cannot expose PKCS12 bundle for {common_name}: "
                         "certificate has been revoked.")
    p12 = config.CLIENTS_PATH / f"{common_name}.p12"
    if not p12.exists():
        raise FileNotFoundError(f"Source PKCS12 bundle not found: {p12}")
    exposure_path = config.P12_SHARE_PATH / f"{common_name}.p12"
    util.ensure_not_exists(exposure_path)
    print("Exposing PKCS12 bundle for client download")
    shutil.copy2(p12, exposure_path)
    util.run_cmd(["chown", "root:www-data", str(exposure_path)])
    util.run_cmd(["chmod", "640", str(exposure_path)])
    print(f"Exposure path: {exposure_path}")
    print(f"Download URL : {config.P12_SHARE_URL}/{p12.name}")
    print("After the .p12 has been downloaded and imported successfully "
          "you MUST directly remove it from the enroll share to prevent abuse! "
          "Use the unexpose command to handle this automatically.")

def unexpose_p12(common_name: str) -> None:
    """Remove the PKCS12 bundle for the given common name from the enroll share."""
    if is_exposed(common_name):
        print(f"Removing exposed PKCS12 bundle for {common_name}")
        exposure_path = config.P12_SHARE_PATH / f"{common_name}.p12"
        exposure_path.unlink()
    else:
        print(f"No exposed PKCS12 bundle found for {common_name}")

def is_exposed(common_name: str) -> bool:
    """Does the PKCS12 bundle for the given common name exist on the share?"""
    return (config.P12_SHARE_PATH / f"{common_name}.p12").exists()
