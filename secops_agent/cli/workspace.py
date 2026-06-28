"""Pure-ish parsing helpers for workspace slash commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ADD_DIR_USAGE = "Usage: /add-dir <path>"


@dataclass(frozen=True)
class AddDirArgument:
    path: Path | None = None
    error: str = ""


def parse_add_dir_argument(argument: str, *, cwd: Path | None = None) -> AddDirArgument:
    text = str(argument or "").strip()
    if not text:
        return AddDirArgument(error=ADD_DIR_USAGE)

    path = Path(text).expanduser()
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    if not path.exists() or not path.is_dir():
        return AddDirArgument(error=f"Directory not found: {path}")
    return AddDirArgument(path=path)
