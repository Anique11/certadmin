"""Read-only checks for explicitly resumed enrollments."""

from __future__ import annotations

import configparser
import re
import subprocess
from pathlib import Path

from certadmin import config
from certadmin.lib import crypto


def openssl(*args: str, input_text: str | None = None) -> str:
    """Capture validation output without logging it."""
    return subprocess.check_output(
        [config.OPENSSL, *args], input=input_text, text=True,
        cwd=config.BASE_PATH.resolve(),
    ).strip()


class _OpenSSLConfig(configparser.ConfigParser):
    """Keep OpenSSL option and variable names case-sensitive."""

    def optionxform(self, optionstr: str) -> str:
        return optionstr


def ca_paths() -> tuple[Path, Path]:
    """Resolve database and CA certificate in the supported OpenSSL INI layout.

    Refuse unsupported syntax rather than guessing where authoritative state lives.
    OpenSSL still performs all certificate issuance and revocation.
    """
    parser = _OpenSSLConfig(interpolation=None, inline_comment_prefixes=("#",))
    try:
        parser.read_string("[DEFAULT]\n" + config.OPENSSL_CONF.read_text())
        section = parser.get("ca", "default_ca")

        def resolve(value: str, depth: int = 0) -> str:
            if depth > 10:
                raise ValueError("Recursive OpenSSL configuration variable")

            def replace(match: re.Match[str]) -> str:
                name = match.group(1) or match.group(2)
                parts = name.split("::", 1)
                source, option = parts if len(parts) == 2 else (section, name)
                return resolve(parser.get(source, option), depth + 1)

            value = re.sub(r"\$\{([^}]+)\}|\$([\w:]+)", replace, value)
            if "$" in value or '"' in value or "'" in value:
                raise ValueError("Unsupported OpenSSL configuration syntax")
            return value

        def path(option: str) -> Path:
            return (config.BASE_PATH.resolve() / resolve(parser.get(section, option))).resolve()

        return path("database"), path("certificate")
    except (configparser.Error, KeyError) as exc:
        raise ValueError("Cannot resolve CA state safely; inspect openssl.cnf before recovery") from exc


def check_ca(common_name: str, cert: Path) -> None:
    """Refuse duplicate issuance and reconcile an existing certificate with the CA."""
    database, ca_cert = ca_paths()
    rows = []
    for line in database.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise ValueError("Malformed CA database; manual reconciliation required")
        if re.search(rf"(?:^|/)CN={re.escape(common_name)}(?:/|$)", fields[5]):
            rows.append(fields)
    if not cert.exists():
        if rows:
            raise ValueError("CA already records this identity; recover its issued certificate before resuming")
        return
    info = crypto.get_cert_info(cert)
    matching = [row for row in rows if int(row[3], 16) == int(info["serial"], 16)]
    if len(rows) != 1 or len(matching) != 1 or matching[0][0] != "V":
        raise ValueError("Certificate does not match a single valid CA record; reconcile manually")
    openssl("verify", "-partial_chain", "-CAfile", str(ca_cert), str(cert.resolve()))


def validate_artifacts(common_name: str, key: Path, csr: Path, cert: Path, p12: Path) -> None:
    """Validate existing material before permitting any enrollment writes."""
    if not key.exists():
        if any(path.exists() for path in (csr, cert, p12)):
            raise ValueError("Private key missing; restore it before resuming")
        return
    openssl("pkey", "-in", str(key.resolve()), "-check", "-noout")
    public_key = openssl("pkey", "-in", str(key.resolve()), "-pubout")
    for kind, path in (("req", csr), ("x509", cert)):
        if not path.exists():
            continue
        if kind == "req":
            openssl("req", "-in", str(path.resolve()), "-verify", "-noout")
        subject = openssl(kind, "-in", str(path.resolve()), "-subject", "-noout", "-nameopt", "RFC2253")
        if not re.search(rf"(?:^|[, ])CN={re.escape(common_name)}(?:,|$)", subject.removeprefix("subject=").strip()):
            raise ValueError(f"Unexpected identity in {path}")
        if openssl(kind, "-in", str(path.resolve()), "-pubkey", "-noout") != public_key:
            raise ValueError(f"Public key mismatch: {path}")
    if p12.exists():
        if not cert.exists():
            raise ValueError("Bundle exists without certificate; reconcile manually")
        # Keep extracted material in memory only; OpenSSL prompts for the password.
        bundled = openssl("pkcs12", "-in", str(p12.resolve()), "-clcerts", "-nodes")
        if openssl("pkey", "-pubout", input_text=bundled) != public_key:
            raise ValueError("Existing bundle contains a different private key")
        fingerprint = openssl("x509", "-noout", "-fingerprint", "-sha256", input_text=bundled)
        expected = openssl("x509", "-in", str(cert.resolve()), "-noout", "-fingerprint", "-sha256")
        if fingerprint != expected:
            raise ValueError("Existing bundle contains a different certificate")
