# Engineering Notes

This document records the reasoning behind some of the design choices in CertAdmin.

It is not intended to be a complete architectural specification. Instead, it explains *why* the project has evolved the way it has, what principles guided its design, and where there is still room for improvement.

---

# Project philosophy

The easiest way to understand CertAdmin is by analogy to **syntactic sugar**.

The analogy is useful because CertAdmin is intended to make an existing workflow easier to express and less error-prone without changing the underlying model.

CertAdmin does not introduce a new PKI model.

Instead, it reduces the friction involved in managing an OpenSSL-based certificate authority while deliberately remaining non-essential.

If CertAdmin disappeared tomorrow, the CA should still be fully manageable using OpenSSL and the documented directory structure.

The project therefore aims to remain:

* transparent
* recoverable
* understandable
* easy to replace if necessary

Whenever possible, CertAdmin automates existing workflows instead of inventing new ones.

---

# OpenSSL remains the authority

OpenSSL is intentionally treated as the authoritative source for certificate state.

The JSON registry exists for administrative convenience rather than as the source of truth.

This keeps the underlying PKI independent from CertAdmin and makes it possible to continue operating the CA without the tool.

---

# Why a JSON registry?

The registry is intended to be a human-readable administrative record of devices that have been registered through the CA.

In principle, it could be reconstructed from existing certificate information, assuming the relevant certificate material still exists.

JSON was chosen because it is:

* human-readable
* easily editable with an ordinary text editor
* flexible enough for evolving metadata
* simple to process from Python

A database would introduce unnecessary operational overhead for a project whose philosophy is to remain simple and transparent.

CSV becomes awkward as records grow in size.

YAML was not explored in depth, but JSON already provided everything needed for this project.

---

# Why a command-line tool?

CertAdmin deliberately relies on existing operating-system mechanisms instead of reimplementing them.

Authentication is delegated to the operating system.

Authorisation is delegated to normal user permissions and `sudo`.

This avoids introducing unrelated concerns such as:

* web authentication
* session management
* web server deployment
* additional attack surface

The goal is to reduce administrative friction, not create another service that itself requires administration.

---

# Working with the operating system

Write operations require elevated privileges because the underlying PKI material is intentionally protected by filesystem permissions.

This is not an inconvenience that CertAdmin attempts to bypass.

Instead, CertAdmin works with the existing security model.

The sensitive files naturally live in privileged locations because they should be protected from accidental modification while restricting certificate administration to trusted administrators.

The tool deliberately preserves that boundary rather than weakening it.

---

# Reducing cognitive load

Many certificate-management operations happen infrequently, especially in a home-lab environment like the one this tool was built for.

The difficulty is often not the individual commands but remembering the complete procedure months later.

CertAdmin aims to reduce operational friction by making these workflows repeatable and discoverable.

The objective is not merely to save typing.

It is to reduce the cognitive effort required to perform administrative tasks correctly when they are needed.

This philosophy explains features such as:

* certificate enrolment
* exposing PKCS#12 bundles
* revocation
* CRL regeneration

Read-only commands make certificate state easier to inspect. Certificates can
be listed with filters for active, revoked, exposed, and unexposed records, and
an individual certificate record can be shown in detail.

State-changing commands provide a dry-run mode so that an administrator can
inspect the intended operations before applying them. Commands that generate
files also require an explicit force option before overwriting existing
artefacts. These safeguards keep potentially sensitive or destructive actions
visible rather than hiding them behind automatic behaviour.

Application code and PKI state must remain separate. CertAdmin refuses to run
when the configured CA base directory is inside the application directory.
This prevents sensitive CA material from being mixed into the source tree or
accidentally treated as application content.

---

# Exposing client bundles

The expose/unexpose workflow reflects the deployment model used in the author's own infrastructure.

Exposing a PKCS#12 bundle is an explicit workflow rather than simply leaving generated files in a delivery location.

This removes the need to repeatedly remember filesystem locations, permissions, and operational steps.

It also allows revocation workflows to clean up exposed bundles automatically where appropriate.

---

# Testing

The existing tests provide useful confidence in the supported certificate
workflows. Improving their breadth and depth remains an active engineering
quality goal rather than a condition of the application's readiness for use.

CertAdmin started life as a small personal utility before gradually becoming a reusable application.

As a result, the implementation initially matured ahead of the test suite.

Coverage reporting has recently been introduced and the long-term objective is to achieve comprehensive behavioural coverage.

The remaining work is not simply increasing coverage percentages.

The existing tests should also be reviewed critically to ensure they genuinely verify behaviour.

Some tests were initially produced with AI assistance and have not yet received the same level of engineering review as the implementation itself.

One early review already uncovered an error in the test code, reinforcing the principle that tests deserve the same level of scrutiny as production code.

---

# AI-assisted development

AI has been used extensively during the development of CertAdmin.

The goal has never been to accept generated code uncritically.

Instead, AI acts as an engineering collaborator whose suggestions are reviewed, redirected, or challenged where appropriate.

Examples include:

* replacing context-manager wrapping with a decorator to make registry write protection more explicit and readable;
* improving behavioural tests after identifying that an initial test did not actually verify the claimed locking behaviour.

The intention is that engineering judgement remains with the human developer, while AI accelerates exploration and implementation.
