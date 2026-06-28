"""
Shared shell-command analysis for permission, sudo, sandbox, and scope checks.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass


SHELL_SEPARATORS = {";", "&&", "||", "|", "(", ")", "&"}
REDIRECT_TOKENS = {"<", ">", ">>", "2>", "2>>", "&>", "&>>"}
SHELLS = {"bash", "sh", "zsh"}

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_UNSAFE_EXTENSION_MARKERS = ("&&", "||", ";", "|", "$(", "`", ">", "<", "\n", "\r")


@dataclass(frozen=True)
class ShellCommandAnalysis:
    command: str
    tokens: tuple[str, ...]
    segments: tuple[tuple[str, ...], ...]
    executables: tuple[str, ...]
    nested_shell_scripts: tuple[str, ...]
    redirections: tuple[str, ...]
    command_substitutions: tuple[str, ...]
    uses_sudo: bool
    unsafe_extension: bool
    parse_error: str = ""


def analyze_shell_command(command: str, *, _depth: int = 0) -> ShellCommandAnalysis:
    text = str(command or "")
    tokens, parse_error = shell_tokens(text)
    nested_shell_scripts = _nested_shell_scripts(tokens)
    command_substitutions = _extract_command_substitutions(text)

    child_analyses: list[ShellCommandAnalysis] = []
    if _depth < 4:
        for script in [*nested_shell_scripts, *command_substitutions]:
            child_analyses.append(analyze_shell_command(script, _depth=_depth + 1))

    all_tokens: list[str] = list(tokens)
    all_redirections: list[str] = _redirections(tokens)
    all_executables: list[str] = _local_executables(tokens)
    for child in child_analyses:
        all_tokens.extend(child.tokens)
        all_redirections.extend(child.redirections)
        for executable in child.executables:
            _append_unique(all_executables, executable)

    all_nested_scripts = list(nested_shell_scripts)
    all_substitutions = list(command_substitutions)
    for child in child_analyses:
        for script in child.nested_shell_scripts:
            _append_unique(all_nested_scripts, script)
        for script in child.command_substitutions:
            _append_unique(all_substitutions, script)

    return ShellCommandAnalysis(
        command=text,
        tokens=tuple(all_tokens),
        segments=tuple(tuple(segment) for segment in _segments_from_tokens(tokens)),
        executables=tuple(all_executables),
        nested_shell_scripts=tuple(all_nested_scripts),
        redirections=tuple(all_redirections),
        command_substitutions=tuple(all_substitutions),
        uses_sudo=any(executable == "sudo" for executable in all_executables),
        unsafe_extension=any(marker in text for marker in _UNSAFE_EXTENSION_MARKERS),
        parse_error=parse_error,
    )


def shell_tokens(command: str) -> tuple[list[str], str]:
    normalized = str(command or "").replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\n", " ; ")
    try:
        lexer = shlex.shlex(normalized, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer), ""
    except ValueError as exc:
        try:
            return shlex.split(normalized, posix=True), str(exc)
        except ValueError as fallback_exc:
            return [], str(fallback_exc)


def extract_shell_executables(command: str) -> list[str]:
    return list(analyze_shell_command(command).executables)


def _local_executables(tokens: list[str]) -> list[str]:
    found: list[str] = []
    expect_command = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_SEPARATORS:
            expect_command = True
            index += 1
            continue
        if token in REDIRECT_TOKENS:
            index += 2
            continue
        if not expect_command:
            index += 1
            continue
        if _ASSIGNMENT_RE.match(token):
            index += 1
            continue

        executable = token.rsplit("/", 1)[-1]
        if executable and executable not in SHELLS:
            _append_unique(found, executable)

        expect_command = False
        index += 1
    return found


def _nested_shell_scripts(tokens: list[str]) -> list[str]:
    scripts: list[str] = []
    for index, token in enumerate(tokens):
        executable = token.rsplit("/", 1)[-1]
        if executable not in SHELLS:
            continue
        script = _nested_shell_command(tokens, index)
        if script:
            _append_unique(scripts, script)
    return scripts


def _nested_shell_command(tokens: list[str], shell_index: int) -> str:
    index = shell_index + 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_SEPARATORS:
            return ""
        if token in {"-c", "-lc", "-ic"}:
            return tokens[index + 1] if index + 1 < len(tokens) else ""
        index += 1
    return ""


def _segments_from_tokens(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _redirections(tokens: list[str]) -> list[str]:
    found: list[str] = []
    for index, token in enumerate(tokens):
        if token in REDIRECT_TOKENS:
            target = tokens[index + 1] if index + 1 < len(tokens) else ""
            found.append(f"{token} {target}".strip())
    return found


def _extract_command_substitutions(command: str) -> list[str]:
    text = str(command or "")
    substitutions: list[str] = []
    substitutions.extend(match.group(1) for match in re.finditer(r"`([^`]*)`", text))

    index = 0
    while index < len(text):
        start = text.find("$(", index)
        if start == -1:
            break
        cursor = start + 2
        depth = 1
        while cursor < len(text) and depth:
            char = text[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth == 0:
            substitutions.append(text[start + 2:cursor - 1])
            index = cursor
        else:
            substitutions.append(text[start + 2:])
            break
    return [item for item in substitutions if item.strip()]


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)
