"""
Clipboard helpers for terminal paste/attachment UX.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse


IMAGE_MIME_EXTENSIONS = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}

Runner = Callable[..., subprocess.CompletedProcess[bytes]]
Which = Callable[[str], str | None]


def attachment_command_from_clipboard_text(
    text: str,
    *,
    cwd: Path | None = None,
    allow_uri_list: bool = False,
) -> str:
    """Return an /attach command when clipboard text identifies one local file."""
    candidate = _single_clipboard_reference(text, allow_uri_list=allow_uri_list)
    if not candidate:
        return ""

    path = _path_from_clipboard_reference(candidate, cwd=cwd)
    if path is None or not path.is_file():
        return ""
    return f"/attach {shlex.quote(str(path))}"


def system_clipboard_text(
    *,
    timeout: float = 0.35,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
) -> str:
    """Read plain text from the system clipboard when a known CLI is present."""
    commands: list[tuple[str, list[str]]] = [
        ("wl-paste", ["wl-paste", "--no-newline"]),
        ("xclip", ["xclip", "-selection", "clipboard", "-o"]),
        ("xsel", ["xsel", "--clipboard", "--output"]),
        ("pbpaste", ["pbpaste"]),
    ]
    for executable, command in commands:
        if not which(executable):
            continue
        result = _run(command, runner=runner, timeout=timeout)
        if result and result.returncode == 0 and result.stdout:
            return result.stdout.decode("utf-8", errors="replace")
    return ""


def system_clipboard_attach_command(
    *,
    cwd: Path | None = None,
    cache_dir: Path | None = None,
    timeout: float = 0.6,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
) -> str:
    """Create an /attach command from clipboard file references or image data."""
    text = _system_clipboard_uri_or_text(timeout=timeout, runner=runner, which=which)
    command = attachment_command_from_clipboard_text(
        text,
        cwd=cwd,
        allow_uri_list=True,
    )
    if command:
        return command

    image_command = _system_clipboard_image_attach_command(
        cache_dir=cache_dir,
        timeout=timeout,
        runner=runner,
        which=which,
    )
    return image_command


def _single_clipboard_reference(text: str, *, allow_uri_list: bool) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""

    lines = [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    if allow_uri_list:
        file_lines = [line for line in lines if line.startswith("file://") or "://" not in line]
        return file_lines[0] if len(file_lines) == 1 else ""

    if len(lines) != 1:
        return ""
    return lines[0].strip("'\"")


def _path_from_clipboard_reference(reference: str, *, cwd: Path | None) -> Path | None:
    candidate = str(reference or "").strip().strip("'\"")
    if not candidate:
        return None
    if candidate.startswith("file://"):
        parsed = urlparse(candidate)
        if parsed.netloc and parsed.netloc not in {"localhost", ""}:
            return None
        candidate = unquote(parsed.path)

    path = Path(os.path.expanduser(candidate))
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    try:
        return path.resolve()
    except OSError:
        return None


def _system_clipboard_uri_or_text(
    *,
    timeout: float,
    runner: Runner,
    which: Which,
) -> str:
    if which("wl-paste"):
        uri = _run(["wl-paste", "--type", "text/uri-list"], runner=runner, timeout=timeout)
        if uri and uri.returncode == 0 and uri.stdout:
            return uri.stdout.decode("utf-8", errors="replace")
    return system_clipboard_text(timeout=timeout, runner=runner, which=which)


def _system_clipboard_image_attach_command(
    *,
    cache_dir: Path | None,
    timeout: float,
    runner: Runner,
    which: Which,
) -> str:
    if which("wl-paste"):
        mime = _first_clipboard_image_mime(
            ["wl-paste", "--list-types"],
            runner=runner,
            timeout=timeout,
        )
        if mime:
            data = _run(["wl-paste", "--type", mime], runner=runner, timeout=timeout)
            if data and data.returncode == 0 and data.stdout:
                return _write_clipboard_image(data.stdout, mime, cache_dir)

    if which("xclip"):
        mime = _first_clipboard_image_mime(
            ["xclip", "-selection", "clipboard", "-t", "TARGETS", "-o"],
            runner=runner,
            timeout=timeout,
        )
        if mime:
            data = _run(
                ["xclip", "-selection", "clipboard", "-t", mime, "-o"],
                runner=runner,
                timeout=timeout,
            )
            if data and data.returncode == 0 and data.stdout:
                return _write_clipboard_image(data.stdout, mime, cache_dir)

    return ""


def _first_clipboard_image_mime(command: list[str], *, runner: Runner, timeout: float) -> str:
    result = _run(command, runner=runner, timeout=timeout)
    if not result or result.returncode != 0:
        return ""
    available = result.stdout.decode("utf-8", errors="replace")
    for mime in IMAGE_MIME_EXTENSIONS:
        if mime in available:
            return mime
    return ""


def _write_clipboard_image(data: bytes, mime_type: str, cache_dir: Path | None) -> str:
    target_dir = cache_dir or Path(tempfile.gettempdir()) / "secops-clipboard"
    target_dir.mkdir(parents=True, exist_ok=True)
    suffix = IMAGE_MIME_EXTENSIONS.get(mime_type, ".bin")
    path = target_dir / f"clipboard-{int(time.time() * 1000)}{suffix}"
    path.write_bytes(data)
    return f"/attach {shlex.quote(str(path))} clipboard image"


def _run(command: list[str], *, runner: Runner, timeout: float) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
