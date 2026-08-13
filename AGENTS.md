# AGENTS.md

## Project context

CertAdmin is a small command-line utility for managing client certificates in a private OpenSSL-based PKI.

It is designed for a home-lab environment with a small number of users and devices that need client certificates for mTLS authentication.

The project intentionally remains small, understandable and operationally simple.

It is also part of my long-term development as a Python software engineer. Suggestions that improve maintainability, architecture, testing or developer experience are welcome, provided they do not unnecessarily increase complexity.

## Core design principles

Preserve these principles unless explicitly asked otherwise.

* Keep the codebase small and understandable.
* Prefer explicit workflows over hidden automation.
* OpenSSL remains the authoritative source for certificate state.
* The JSON registry exists for convenience and workflow metadata.
* Avoid unnecessary abstraction.
* Keep security-sensitive operations explicit.
* Keep PKI data outside the application source tree.

## How to assist

When working in this repository:

* Prefer maintainable Python over clever code.
* Explain architectural trade-offs.
* Keep changes focused and reviewable.
* Avoid large rewrites unless requested.
* Point out opportunities to improve engineering quality.
* Treat this as both a production tool and a learning project.

## Testing philosophy

The existing tests provide useful confidence in the supported certificate workflows. Improving their breadth and depth remains an active engineering-quality goal rather than a condition of the application's readiness for use.

The project started life as a personal utility script and gradually evolved into a reusable application. Because of that evolution, the implementation grew ahead of the test suite.

The current objective is to improve the tests until they provide comprehensive confidence in behaviour. Coverage reporting has recently been introduced and the long-term goal is to approach complete behavioural coverage where it adds value.

When modifying code:

* preserve or improve test quality
* suggest additional tests where behaviour is not yet covered
* avoid writing tests merely to increase coverage numbers
* prefer tests that document expected behaviour

## Before making changes

Summarise:

* intended approach
* affected files
* assumptions
* possible risks

## After making changes

Summarise:

* what changed
* how it was tested
* remaining manual verification
* engineering competencies exercised
