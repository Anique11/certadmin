"""Configuration of locations for use by the certificate administration tool."""

import os
from pathlib import Path

# Where the Certificate Authority files are located
BASE_PATH: Path = Path(os.getenv("PKI_BASE_PATH", "/opt/pki/intermediate-ca"))

# Subfolders for organization
CLIENTS_PATH: Path = BASE_PATH / "clients"
ISSUED_CERTS_PATH: Path = BASE_PATH / "issued"

P12_SHARE_PATH: Path = Path("/srv/share/enroll")
P12_SHARE_URL: str = "https://example.com/enroll"

# Registry file: not the CA registry, but registration of certificates 
# administered by this tool, including their status (active, revoked, exposed)
REGISTRY_PATH: Path = BASE_PATH / "registry.json"

# Path to the OpenSSL binary
OPENSSL: str = "openssl"
# OpenSSL config file
OPENSSL_CONF: Path = BASE_PATH / "openssl.cnf"
# Relevant CA files
CHAIN_PATH: Path = BASE_PATH / "certs/ca-chain.pem"
CRL_PATH: Path = BASE_PATH / "crl" / "intermediate.crl.pem"


# Override with local defaults, if available.
# This enables local testing before rolling out to 'production' environment. 
try:
    from config_local import (
        BASE_PATH, 
        CLIENTS_PATH, ISSUED_CERTS_PATH,
        P12_SHARE_PATH, P12_SHARE_URL, 
        REGISTRY_PATH,
        OPENSSL, OPENSSL_CONF, CHAIN_PATH, CRL_PATH
    )
except ImportError:
    pass


def validate_runtime_paths() -> None:
    """Fail if PKI state is configured inside the application directory."""
    app_path = Path(__file__).resolve().parent
    base_path = BASE_PATH.resolve()

    if base_path == app_path or base_path.is_relative_to(app_path):
        raise ValueError(
            "Invalid PKI_BASE_PATH configuration.\n"
            f"PKI state must not be stored inside the certadmin application directory: {app_path}\n"
            f"Configured BASE_PATH: {base_path}"
        )
