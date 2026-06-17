"""Utility functions for certificate management."""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

from dataclasses import dataclass
import subprocess


@dataclass
class RuntimeState:
    _locked: bool = False
    dry_run: bool = False
    force_overwrite: bool = False

    def lock(self) -> None:
        """Lock runtime state to prevent further modifications."""
        self._locked = True

    def __setattr__(self, name, value):
        if getattr(self, "_locked", False) and name != "_locked":
            raise RuntimeError("RuntimeState is locked")
        super().__setattr__(name, value)

runtime_state = RuntimeState()

def ensure_not_exists(path: Path) -> None:
    """Fail if the given path exists unless force overwrite is enabled."""
    if not runtime_state.force_overwrite and path.exists():
        raise FileExistsError(
            f"ERROR: {path} already exists.\n"
            "Use --force to overwrite existing files."
        )

def run_cmd(cmd: Sequence[str]) -> None:
    print(" ".join(cmd))
    if not runtime_state.dry_run:
        subprocess.run(cmd, check=True)