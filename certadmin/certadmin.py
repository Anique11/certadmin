#!/usr/bin/env python3
"""Utility for automated certification management."""

import argparse
import re
from subprocess import CalledProcessError
import sys

import config
from commands import enroll, expose, unexpose, revoke, list_certs, show
from lib.util import runtime_state



USER_RE = re.compile(r"^[a-z0-9]+$")
DEVICE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

def validate_user(user: str) -> str:
    """Validate user: only letters and digits"""
    user = user.lower()
    if not USER_RE.fullmatch(user):
        raise ValueError(
            "Invalid user name.\n"
            "Allowed: lowercase letters and digits."
        )
    return user

def validate_device(device: str) -> str:
    """Validate device: letters, digits, and hyphens"""
    device = device.lower()
    if not DEVICE_RE.fullmatch(device):
        raise ValueError(
            f"Invalid device.\n"
            "Allowed: lowercase letters, digits, single hyphens."
        )
    return device

def validate_common_name(cn: str) -> str:
    """Validate common name format: user-device."""
    cn = cn.lower()
    if "-" not in cn:
        raise ValueError("Common name must contain at least one hyphen "
                         "(format: user-device)")
    user, device = cn.split("-", 1)
    validate_user(user)
    validate_device(device)
    return cn


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Configures global arguments (--dry-run, --force) and subcommands 
    (enroll, expose, unexpose, revoke, list, show) with their respective arguments.
    """
    parser = argparse.ArgumentParser(
        description="Client certificate administration utility"
    )
    parser.add_argument("--dry-run", action="store_true",
        help="Print actions without executing them"
    )
    parser.add_argument("--force", action="store_true",
        help="Overwrite existing files or registry entries where applicable"
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # enroll
    enroll_parser = subparsers.add_parser("enroll",
        help="Generate a new client certificate"
    )
    enroll_parser.add_argument("user", help="User name")
    enroll_parser.add_argument("device", help="Device name")
    enroll_parser.set_defaults(func=enroll.run)

    # expose
    expose_parser = subparsers.add_parser("expose",
        help="Expose a PKCS12 bundle"
    )
    expose_parser.add_argument("common_name",
        help="Certificate common name"
    )
    expose_parser.set_defaults(func=expose.run)

    # unexpose
    unexpose_parser = subparsers.add_parser("unexpose",
        help="Remove exposed PKCS12 bundle"
    )
    unexpose_parser.add_argument("common_name",
        help="Certificate common name"
    )
    unexpose_parser.set_defaults(func=unexpose.run)

    # revoke
    revoke_parser = subparsers.add_parser("revoke",
        help="Revoke certificate"
    )
    revoke_parser.add_argument("common_name",
        help="Certificate common name"
    )
    revoke_parser.set_defaults(func=revoke.run)

    # list
    list_parser = subparsers.add_parser("list",
        help="List certificates"
    )
    list_group = list_parser.add_mutually_exclusive_group()
    list_group.add_argument("--active", action="store_true")
    list_group.add_argument("--revoked", action="store_true")
    list_group.add_argument("--exposed", action="store_true")
    list_group.add_argument("--unexposed", action="store_true")
    list_parser.set_defaults(func=list_certs.run)

    # show
    show_parser = subparsers.add_parser("show",
        help="Show certificate details"
    )
    show_parser.add_argument("common_name",
        help="Certificate common name"
    )
    show_parser.set_defaults(func=show.run)

    return parser


def normalize_args(args: argparse.Namespace) -> None:
    """Validate the command-line arguments for user, device, and common name."""
    if hasattr(args, "user"):
        args.user = validate_user(args.user)

    if hasattr(args, "device"):
        args.device = validate_device(args.device)

    if hasattr(args, "common_name"):
        args.common_name = validate_common_name(args.common_name)


def main() -> None:
    """Entry point to CertAdmin.
    Parse command line arguments and hand over to commands.
    Catch errors to avoid displaying stack trace to user."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        normalize_args(args)
        config.validate_runtime_paths()
        runtime_state.dry_run = args.dry_run
        runtime_state.force_overwrite = args.force
        runtime_state.lock()
        args.func(args)
    except ValueError as e:
        print(e)
        sys.exit(1)
    except FileExistsError as e:
        print(e)
        sys.exit(1)
    except CalledProcessError as e:
        print(f"Command failed: {e}")
        sys.exit(2)
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        sys.exit(3)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
