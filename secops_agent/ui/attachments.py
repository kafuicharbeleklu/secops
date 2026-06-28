"""
Attachment intake helpers for evidence files.
"""

from __future__ import annotations

import hashlib
import mimetypes
import shlex
from dataclasses import dataclass
from pathlib import Path

from secops_agent.ui.runtime import RuntimeArtifact, RuntimeState


MAX_TEXT_PREVIEW_CHARS = 12_000
MAX_PROMPT_ATTACHMENT_CHARS = 18_000
MAX_PROMPT_ATTACHMENTS = 5
MAX_INLINE_IMAGE_BYTES = 8 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".csv",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".nmap",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


class AttachmentError(ValueError):
    """Raised when a requested attachment cannot be safely registered."""


@dataclass(frozen=True)
class AttachmentDraft:
    title: str
    content: str
    path: Path
    summary: str


def parse_attach_argument(argument: str) -> tuple[str, str]:
    """Return path plus optional note from `/attach <path> [note]`."""
    try:
        parts = shlex.split(argument)
    except ValueError as exc:
        raise AttachmentError(f"Invalid attachment arguments: {exc}") from exc
    if not parts:
        raise AttachmentError("Usage: /attach <path> [note]")
    return parts[0], " ".join(parts[1:])


def attach_file(runtime: RuntimeState, argument: str, *, cwd: Path | None = None) -> RuntimeArtifact:
    raw_path, note = parse_attach_argument(argument)
    draft = build_attachment_draft(raw_path, note=note, cwd=cwd)
    artifact = runtime.add_artifact(
        draft.title,
        "attachment",
        draft.content,
        source="/attach",
        path=draft.path,
    )
    if artifact is None:
        raise AttachmentError("Attachment content was empty.")
    return artifact


def build_attachment_draft(raw_path: str, *, note: str = "", cwd: Path | None = None) -> AttachmentDraft:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise AttachmentError(f"Unable to resolve attachment path: {path}") from exc

    if not resolved.exists():
        raise AttachmentError(f"File not found: {resolved}")
    if not resolved.is_file():
        raise AttachmentError(f"Attachments must be files, not directories: {resolved}")

    stat = resolved.stat()
    mime_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
    attachment_type = _attachment_type(resolved, mime_type)
    digest = _sha256(resolved)
    size = _format_bytes(stat.st_size)
    preview, preview_status = _preview_text(resolved, mime_type, attachment_type)

    lines = [
        "Attachment",
        f"Name: {resolved.name}",
        f"Type: {attachment_type}",
        f"MIME: {mime_type}",
        f"Size: {size}",
        f"SHA256: {digest}",
        f"Path: {resolved}",
    ]
    if note:
        lines.append(f"Note: {note}")
    lines.append(f"Status: {preview_status}")
    if preview:
        lines.extend(["", "Preview:", preview])

    summary = f"{resolved.name} · {attachment_type} · {size}"
    return AttachmentDraft(
        title=f"Attachment: {resolved.name}",
        content="\n".join(lines),
        path=resolved,
        summary=summary,
    )


def build_attachment_prompt_context(runtime: RuntimeState) -> str:
    """Build bounded text context for attached evidence."""
    attachments = runtime.attachment_artifacts()[-MAX_PROMPT_ATTACHMENTS:]
    if not attachments:
        return ""

    remaining = MAX_PROMPT_ATTACHMENT_CHARS
    lines = [
        "Attached evidence available in this session.",
        "Image attachments are also sent as multimodal parts when the active model supports image input.",
    ]
    for artifact in attachments:
        if remaining <= 0:
            break
        header = f"- {artifact.id}: {artifact.title}"
        if artifact.path:
            header += f" ({artifact.path})"
        lines.append(header)
        remaining -= len(header)
        snippet = artifact.content[: max(0, remaining)]
        if snippet:
            lines.append(snippet)
            remaining -= len(snippet)
    return "\n".join(lines).strip()


def build_attachment_model_parts(runtime: RuntimeState) -> list[dict[str, str]]:
    """Return binary attachment descriptors that the LLM adapter can send as parts."""
    parts: list[dict[str, str]] = []
    for artifact in runtime.attachment_artifacts()[-MAX_PROMPT_ATTACHMENTS:]:
        if artifact.path is None:
            continue
        mime_type = _metadata_value(artifact.content, "MIME")
        attachment_type = _metadata_value(artifact.content, "Type")
        if attachment_type != "image" or not mime_type.startswith("image/"):
            continue
        try:
            stat = artifact.path.stat()
        except OSError:
            continue
        if stat.st_size > MAX_INLINE_IMAGE_BYTES:
            continue
        parts.append(
            {
                "id": artifact.id,
                "title": artifact.title,
                "type": "image",
                "path": str(artifact.path),
                "mime_type": mime_type,
            }
        )
    return parts


def _attachment_type(path: Path, mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("video/"):
        return "video"
    if mime_type.startswith("audio/"):
        return "audio"
    if mime_type.startswith("text/") or path.suffix.lower() in TEXT_EXTENSIONS:
        return "text"
    return "file"


def _preview_text(path: Path, mime_type: str, attachment_type: str) -> tuple[str, str]:
    if attachment_type != "text" and not mime_type.endswith("+json") and not mime_type.endswith("+xml"):
        if attachment_type == "image":
            return "", "metadata captured; image will be sent to compatible models"
        return "", "metadata captured; binary preview is not sent to the model"

    raw = path.read_bytes()[: MAX_TEXT_PREVIEW_CHARS + 1]
    truncated = len(raw) > MAX_TEXT_PREVIEW_CHARS
    raw = raw[:MAX_TEXT_PREVIEW_CHARS]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return "", "metadata captured; text preview could not be decoded"

    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip()
    if truncated:
        text += "\n... preview truncated ..."
    return text, "text preview captured"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _metadata_value(content: str, key: str) -> str:
    prefix = f"{key}:"
    for line in content.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""
