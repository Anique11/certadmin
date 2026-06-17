"""Cryptographic operations for certificate management."""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pathlib import Path

from datetime import UTC, datetime
import re
import subprocess

from certadmin import config
from certadmin.lib import util



def gen_key(common_name: str) -> Path:
    """Generate an EC private key for the certificate.
    
    Args:
        common_name: Certificate common name
        
    Returns:
        Path to generated key file
        
    Raises:
        ValueError: If key file already exists (unless --force)
    """
    key = config.CLIENTS_PATH / f"{common_name}.key.pem"
    util.ensure_not_exists(key)

    print("[Generating key]")
    util.run_cmd([
        config.OPENSSL, "ecparam",
        "-name", "prime256v1",
        "-genkey",
        "-noout",
        "-out", str(key)
    ])
    return key

def gen_csr(common_name: str, key: Path) -> Path:
    """Generate a certificate signing request.
    
    Args:
        common_name: Certificate common name
        key: Path to private key file
        
    Returns:
        Path to generated CSR file
        
    Raises:
        ValueError: If CSR file already exists (unless --force)
    """
    csr = config.CLIENTS_PATH / f"{common_name}.csr.pem"
    util.ensure_not_exists(csr)

    print("[Generating CSR]")
    util.run_cmd([
        config.OPENSSL, "req", "-new",
        "-key", str(key),
        "-out", str(csr),
        "-subj", f"/C=NL/O=Private PKI/OU=devices/CN={common_name}"
    ])
    return csr

def sign_cert(common_name: str, csr: Path) -> Path:
    """Sign a certificate signing request with the CA.
    
    Args:
        common_name: Certificate common name
        csr: Path to CSR file
        
    Returns:
        Path to signed certificate file
        
    Raises:
        ValueError: If cert file already exists (unless --force)
    """
    cert = config.ISSUED_CERTS_PATH / f"{common_name}.cert.pem"
    util.ensure_not_exists(cert)

    print("[Signing certificate]")
    util.run_cmd([
        config.OPENSSL, "ca",
        "-config", str(config.OPENSSL_CONF),
        "-extensions", "usr_cert",
        "-in", str(csr),
        "-out", str(cert),
        "-batch"
    ])
    return cert

def gen_p12(common_name: str, key: Path, cert: Path) -> Path:
    """Create a PKCS12 bundle with private key and certificate.
    
    Args:
        common_name: Certificate common name
        key: Path to private key file
        cert: Path to certificate file
        
    Returns:
        Path to generated PKCS12 bundle
        
    Raises:
        ValueError: If bundle file already exists (unless --force)
    """
    p12 = config.CLIENTS_PATH / f"{common_name}.p12"
    util.ensure_not_exists(p12)

    print("[Creating PKCS12 bundle]")
    util.run_cmd([
        config.OPENSSL, "pkcs12", "-export",
        "-inkey", str(key),
        "-in", str(cert),
        "-certfile", str(config.CHAIN_PATH),
        "-out", str(p12),
        "-name", common_name
    ])
    return p12

def get_cert_info(cert: Path) -> dict[str, str]:
    """Extract certificate information (CN, serial, validity dates).
    
    Uses ISO 8601 date format for parsing to avoid locale and timezone issues.
    
    Args:
        cert: Path to certificate file
        
    Returns:
        Dictionary with keys: common_name, serial, not_before, not_after (ISO format)
        
    Raises:
        ValueError: If CN not found in subject or parsing fails
        subprocess.CalledProcessError: If OpenSSL command fails
    """
    print(f"Extracting certificate info from: {cert}")
    
    def run_openssl_x509(flag: str, extra_args: list = None) -> str:
        cmd = [config.OPENSSL, "x509", "-in", str(cert), "-noout", flag]
        if extra_args:
            cmd.extend(extra_args)
        return subprocess.check_output(cmd, text=True).strip()

    subject = run_openssl_x509("-subject")
    serial = run_openssl_x509("-serial")
    # Use ISO 8601 format to avoid locale/timezone parsing issues
    not_before = run_openssl_x509("-startdate", ["-dateopt", "iso_8601"])
    not_after = run_openssl_x509("-enddate", ["-dateopt", "iso_8601"])

    def parse_subject(subj: str) -> str:
        """Extract CN from subject string."""
        match = re.search(r"CN\s*=\s*([^,/]+)", subj)
        if not match:
            raise ValueError("No CN found in subject")
        return match.group(1).strip()

    def parse_time(line: str) -> str:
        """Parse ISO 8601 date string.
        
        Input format: "notBefore=2026-06-01T19:41:44Z"
        Output: ISO format string with UTC timezone
        """
        t = line.split("=", 1)[1].strip()
        # Handle both "Z" (Zulu/UTC) and explicit timezone format
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        return datetime.fromisoformat(t).isoformat()

    return {
        "common_name": parse_subject(subject),
        "serial": serial.split("=", 1)[1],
        "not_before": parse_time(not_before),
        "not_after": parse_time(not_after),
    }

def revoke_cert(common_name: str) -> None:
    """Revoke a certificate and regenerate the CRL.
    
    Args:
        common_name: Certificate common name
        
    Raises:
        ValueError: If certificate file not found
        subprocess.CalledProcessError: If OpenSSL command fails
    """
    cert = config.ISSUED_CERTS_PATH / f"{common_name}.cert.pem"
    if not cert.exists():
        raise ValueError(
            f"Certificate file not found: {cert}"
        )
    print(f"Revoking certificate: {cert}")
    util.run_cmd([
        config.OPENSSL,
        "ca",
        "-config", str(config.OPENSSL_CONF),
        "-revoke", str(cert)
    ])
    gen_crl()

def gen_crl() -> None:
    """Regenerate the certificate revocation list.
    
    This is typically called after revoking a certificate.
    
    Raises:
        subprocess.CalledProcessError: If OpenSSL command fails
    """
    print("Regenerating CRL")
    util.run_cmd([
        config.OPENSSL,
        "ca",
        "-config", str(config.OPENSSL_CONF),
        "-gencrl",
        "-out", str(config.CRL_PATH)
    ])
