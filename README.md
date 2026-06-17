# CertAdmin

A small command-line utility for managing client certificates in a private OpenSSL-based PKI.

CertAdmin was written for a home-lab environment where a handful of users and devices need client certificates for mTLS authentication. It provides a simple workflow for issuing, exposing, and revoking client certificates without introducing databases, web interfaces or heavyweight PKI infrastructure.

The tool is intentionally opinionated and assumes a traditional OpenSSL Certificate Authority layout.

## Design philosophy

CertAdmin is deliberately conservative in scope.

It is **not** intended to be a general-purpose PKI management platform. It does not provide:

* Web interfaces
* Multi-user administration
* Role-based access control
* ACME integration
* OCSP
* Automatic certificate renewal
* Database backends
* High-availability features

Instead, the design focuses on:

* Small codebase
* Explicit workflows
* Human-readable state
* Minimal dependencies
* Standard OpenSSL tooling
* Easy auditing and troubleshooting

The guiding principle is that a home-lab administrator should be able to understand the entire system in a single afternoon.

## Certificate lifecycle

CertAdmin manages the following workflow:

1. Enroll a new device certificate
2. Expose the PKCS#12 bundle for download,
   enabling installation of the certificate on the target device
3. Unexpose the PKCS#12 bundle
4. Revoke certificates when devices are retired or compromised
5. Regenerate the Certificate Revocation List (CRL)

Certificate metadata is stored in a simple JSON registry for convenience and reporting. OpenSSL remains the authoritative source for certificate issuance and revocation state.

## Commands

### List certificates (as stored in the registry)

Show all certificates:

```bash
certadmin list
```

Show only active certificates:

```bash
certadmin list --active
```

Show only revoked certificates:

```bash
certadmin list --revoked
```

Show certificates currently exposed for download:

```bash
certadmin list --exposed
```

Show active certificates that are not currently exposed:

```bash
certadmin list --unexposed
```

### Show certificate details (as stored in the registry)

```bash
certadmin show alice-laptop
```

### Enroll a new certificate

```bash
sudo certadmin enroll bob laptop
```

This generates:

* Private key
* Certificate Signing Request (CSR)
* Signed client certificate
* PKCS#12 bundle

Enrollment does **not** automatically expose the certificate for download.

### Expose a certificate

```bash
sudo certadmin expose bob-laptop
```

This copies the PKCS#12 bundle into the configured enrollment location.

### Unexpose a certificate

```bash
sudo certadmin unexpose bob-laptop
```

This removes the PKCS#12 bundle from the enrollment location.

### Revoke a certificate

```bash
sudo certadmin revoke alice-laptop
```

This:

* Revokes the certificate in OpenSSL
* Regenerates the CRL
* Marks the certificate as revoked in the registry
* Automatically removes any exposed PKCS#12 bundle

### Dry-run mode

Commands that modify state support dry-run mode:

```bash
sudo certadmin enroll bob laptop --dry-run
```

### Force overwrite

Commands that generate files support force mode:

```bash
sudo certadmin enroll alice laptop --force
```

## Installation

### Prerequisites

* Linux
* Python 3.13 or newer
* OpenSSL
* Existing OpenSSL CA

CertAdmin assumes a working OpenSSL intermediate CA already exists.

### Directory layout

Install the utility separately from the CA data:

```text
/opt/certadmin
/opt/pki/intermediate-ca
```

Example:

```text
/opt/certadmin/
├── pyproject.toml
└── certadmin/
    ├── certadmin.py
    ├── config.py
    ├── commands/
    └── lib/

/opt/pki/intermediate-ca/
├── private/
├── issued/
├── clients/
├── crl/
├── registry.json
├── index.txt
├── serial
└── openssl.cnf
```

### Configuration

Edit `config.py` and adjust the paths to match your OpenSSL CA installation.

Important paths include:

* CA base directory
* OpenSSL configuration file
* Issued certificate directory
* Client artifact directory
* CRL location
* Temporary enrollment share

CertAdmin also supports overriding the CA base directory without editing `config.py`:

```bash
export PKI_BASE_PATH=/path/to/intermediate-ca
```

This is useful for local testing or alternative installations.

CertAdmin refuses to run if the CA base directory is configured inside the
application directory. PKI state, private keys, issued certificates, and registry
files should live outside the CertAdmin source tree.

### Permissions

Recommended permissions:

```text
/opt/certadmin                    root:root 755
private/                          root:root 700
clients/                          root:root 700
issued/                           root:root 755
crl/                              root:root 755
registry.json                     root:root 644
```

Administrative commands should be executed with `sudo`.

Read-only commands such as `list` and `show` may be executed without elevated privileges.

## Setup checklist

1. Install prerequisites:
   * `python3`
   * `openssl` available on `PATH`
   * A valid OpenSSL intermediate CA layout under `BASE_PATH` with:
     * `openssl.cnf`
     * `certs/ca-chain.pem`
     * `crl/`
     * `issued/`
     * `clients/`
     * `private/`
     * `serial` and `index.txt`
2. Install CertAdmin:

```bash
python3 -m pip install .
```

For local development:

```bash
python3 -m pip install -e .[dev]
```

3. Adjust paths in `config.py` or create `config_local.py` for local overrides.
4. Optionally set `PKI_BASE_PATH` instead of editing `config.py`:

```bash
export PKI_BASE_PATH=/path/to/intermediate-ca
```

5. Verify the command and environment before use:

```bash
certadmin --version
python3 --version
openssl version
```

The package can also be run directly as a module:

```bash
python3 -m certadmin --version
```

## License

This project is licensed under the MIT License. See the included `LICENSE` file for details.
