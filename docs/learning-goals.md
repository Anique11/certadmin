# Learning goals for CertAdmin

## Why this project exists

CertAdmin solves a real operational problem in my home infrastructure.

At the same time, it serves as a deliberate software engineering project used to develop and demonstrate Python engineering skills.

The project is intended to evolve beyond "working code" towards a well-engineered application.

## Engineering goals

This project is intended to exercise and demonstrate:

* Python 3.13 application structure and type annotations
* command-line application design
* maintainable software architecture and code organisation
* packaging and console entry points with setuptools
* behavioural testing with pytest and coverage.py
* static type checking with mypy
* linting and formatting checks with Ruff
* continuous integration with GitHub Actions
* subprocess integration with OpenSSL
* JSON-based workflow metadata
* secure filesystem, privilege, dry-run, and overwrite boundaries
* client-certificate lifecycle management, including enrolment, temporary
  PKCS#12 exposure, revocation, and CRL regeneration

## Testing goals

Testing deserves special mention.

This project was not started using strict Test-Driven Development. It began as a personal utility and only later became something suitable for publication.

Rather than pretending otherwise, the goal is to deliberately improve the test suite as the project matures.

Current direction:

* improve behavioural coverage
* increase confidence when refactoring
* use coverage reports to identify gaps
* make tests readable documentation of expected behaviour
* work towards very high (ideally complete) meaningful coverage without writing artificial tests simply to reach a percentage

## AI-assisted development

AI is used as an engineering assistant rather than an implementation engine.

Preferred workflow:

1. understand the problem
2. discuss design alternatives
3. implement incrementally
4. review generated code critically
5. improve tests
6. reflect on engineering decisions

## Learning strategy

This project forms part of a broader long-term learning strategy.

Advanced Python certification objectives (such as PCPP1) are used as competency checklists rather than study material.

When an advanced language feature becomes useful in this project, that is an opportunity to learn it in context.

Certification may follow later as external validation of skills developed through practical engineering work.
