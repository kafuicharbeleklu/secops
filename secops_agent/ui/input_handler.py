"""
Input handling matching the Antigravity CLI prompt style.
Simple '> ' prompt, clean toolbar, command completion.
Uses theme.py as single source of truth for all styling.
"""

from __future__ import annotations

import os
import contextlib
import importlib
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional, cast

from prompt_toolkit import PromptSession
from prompt_toolkit.application.current import get_app_or_none
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.history import FileHistory, InMemoryHistory
from prompt_toolkit.completion import Completer, Completion as PTCompletion
from prompt_toolkit.formatted_text import StyleAndTextTuples, fragment_list_to_text, to_formatted_text
import prompt_toolkit.layout.menus as pt_menus
from prompt_toolkit.styles import Style as PtStyle
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.document import Document
from prompt_toolkit.filters import has_completions
from prompt_toolkit.layout.dimension import Dimension

from secops_agent.core.model_catalog import completion_values
from secops_agent.ui.clipboard import (
    attachment_command_from_clipboard_text,
    system_clipboard_attach_command,
    system_clipboard_text,
)
from secops_agent.ui.commands import get_command, iter_commands
from secops_agent.ui.spool_display import supervised_detail_text
from secops_agent.ui.theme import COLORS, pt_style_dict, friendly_model_name

pt_prompt = importlib.import_module("prompt_toolkit.shortcuts.prompt")

COMPLETION_MENU_RESERVED_ROWS = 0
SLASH_COMPLETION_VISIBLE_ROWS = 5
ROOT_COMPLETION_HIDDEN_COMMANDS = {"/task"}


def _terminal_width(default: int = 80) -> int:
    widths: list[int] = []
    try:
        app = get_app_or_none()
        if app is not None:
            widths.append(app.output.get_size().columns)
    except Exception:
        pass
    try:
        widths.append(shutil.get_terminal_size((default, 24)).columns)
    except Exception:
        pass
    widths = [width for width in widths if width > 0]
    return max(1, min(widths) if widths else default)


# Cap the decorative prompt/toolbar frame so the border rule and statusline do
# not sprawl edge-to-edge on ultra-wide terminals (STAT). 120 matches the
# content cap already used in renderer.py. The input buffer keeps full width.
_FRAME_MAX_WIDTH = 120


def _frame_width(width: int) -> int:
    """Clamp the prompt-frame width to a comfortable reading width."""
    return max(1, min(int(width or 0), _FRAME_MAX_WIDTH))


def _terminal_height(default: int = 24) -> int:
    try:
        return max(1, shutil.get_terminal_size((80, default)).lines)
    except Exception:
        return default


def _ctrl_o_output_visible_limit(default: int = 40) -> int:
    """Keep ctrl+o output previews short enough to collapse cleanly."""
    return max(1, min(default, _terminal_height() - 8))


def _completion_display(label: str, description: str = "", label_width: int = 48) -> str:
    if not description:
        return label
    return f"{label:<{label_width}} {description}"


def _agy_menu_item_fragments(
    completion: PTCompletion,
    is_current_completion: bool,
    width: int,
    space_after: bool = False,
) -> StyleAndTextTuples:
    """Render completion rows with an Antigravity-style literal cursor."""
    if is_current_completion:
        style_str = f"class:completion-menu.completion.current {completion.style} {completion.selected_style}"
        marker = "> "
    else:
        style_str = "class:completion-menu.completion " + completion.style
        marker = "  "

    text_width = max(0, width - len(marker) - (1 if space_after else 0))
    text, text_cell_width = pt_menus._trim_formatted_text(completion.display, text_width)
    padding = " " * max(0, width - len(marker) - text_cell_width)

    return to_formatted_text(
        cast(StyleAndTextTuples, []) + [("", marker)] + text + [("", padding)],
        style=style_str,
    )


def _install_antigravity_completion_cursor() -> None:
    if getattr(pt_menus, "_secops_agy_cursor_installed", False):
        return
    pt_menus._get_menu_item_fragments = _agy_menu_item_fragments
    original_create_content = pt_menus.CompletionsMenuControl.create_content

    def _create_content_with_default_cursor(self, width: int, height: int):
        complete_state = pt_menus.get_app().current_buffer.complete_state
        if not complete_state:
            return original_create_content(self, width, height)

        completions = complete_state.completions
        index = complete_state.complete_index
        active_index = index if index is not None else 0

        menu_width = self._get_menu_width(width, complete_state)
        menu_meta_width = self._get_menu_meta_width(width - menu_width, complete_state)
        show_meta = self._show_meta(complete_state)

        def get_line(i: int) -> StyleAndTextTuples:
            completion = completions[i]
            is_current_completion = i == active_index
            result = pt_menus._get_menu_item_fragments(
                completion,
                is_current_completion,
                menu_width,
                space_after=True,
            )
            if show_meta:
                result += self._get_menu_item_meta_fragments(
                    completion,
                    is_current_completion,
                    menu_meta_width,
                )
            return result

        return pt_menus.UIContent(
            get_line=get_line,
            cursor_position=pt_menus.Point(x=0, y=active_index),
            line_count=len(completions),
        )

    pt_menus.CompletionsMenuControl.create_content = _create_content_with_default_cursor
    pt_menus._secops_agy_cursor_installed = True


_install_antigravity_completion_cursor()


def _fit_text(text: str, max_width: int) -> str:
    if max_width <= 0:
        return ""
    if len(text) <= max_width:
        return text
    if max_width <= 1:
        return "…"
    return text[: max_width - 1] + "…"


def _fit_segments(segments: list[str], max_width: int) -> str:
    """Fit statusline fields by dropping whole segments before truncating text."""
    if max_width <= 0:
        return ""

    materialized = [segment for segment in segments if segment]
    while materialized:
        text = " · ".join(materialized)
        if len(text) <= max_width:
            return text
        materialized.pop()

    return _fit_text(segments[0] if segments else "", max_width)


def _completion_more_text(total: int, visible_count: int = SLASH_COMPLETION_VISIBLE_ROWS) -> str:
    hidden = max(0, total - visible_count)
    return f"↓ {hidden} more" if hidden else ""


def _completion_preserves_text(document: Document, completion: PTCompletion) -> bool:
    """Return True when applying a completion would not change text before cursor."""
    before = document.text_before_cursor
    start_position = completion.start_position or 0
    if start_position < 0:
        replacement_start = max(0, len(before) + start_position)
    else:
        replacement_start = len(before)
    completed = before[:replacement_start] + completion.text
    return completed.strip() == before.strip()


def _completion_matches_current_argument(
    document: Document,
    completions: list[PTCompletion],
) -> bool:
    """Return True when the current slash-command argument is an exact completion."""
    text = document.text_before_cursor.strip()
    if " " not in text:
        return False
    argument = text.rsplit(" ", 1)[1]
    if not argument:
        return False
    return any(completion.text == argument for completion in completions)


def _completion_line_text(completion: PTCompletion, width: int) -> str:
    text = fragment_list_to_text(to_formatted_text(completion.display))
    return _fit_text(text, width)


def _refresh_slash_completion_after_edit(buffer: Any) -> None:
    """Keep slash suggestions visible after deletion/edit operations."""
    text = buffer.document.text_before_cursor.lstrip()
    try:
        if text.startswith("/"):
            buffer.start_completion(select_first=False)
        else:
            buffer.cancel_completion()
    except Exception:
        pass


def _tool_completion_rows() -> list[tuple[str, str]]:
    """Return executable slash entries for registered SecOps tools."""
    try:
        from secops_agent.core.tools import registry
    except Exception:
        return []

    rows: list[tuple[str, str]] = []
    for tool in sorted(registry.list_tools(), key=lambda item: item.name):
        category = getattr(getattr(tool, "category", ""), "value", str(getattr(tool, "category", "")))
        danger = " dangerous" if getattr(tool, "dangerous", False) else ""
        label = f"/tool {tool.name}"
        description = f"{category}{danger} · {getattr(tool, 'description', '')}"
        rows.append((label, description.strip()))
    return rows


def _clipboard_attachment_command(text: str) -> str:
    """Return an /attach command when clipboard text is a single local file path."""
    return attachment_command_from_clipboard_text(text)


def _prompt_separator(width: int) -> str:
    """Return a single prompt separator line that does not wrap at the edge."""
    return "─" * max(1, width - 1)


def _footer_spacing(left_text: str, right_text: str, width: int) -> int:
    return max(1, width - len(left_text) - len(right_text) - 1)


def _footer_parts(left_text: str, right_text: str, width: int) -> tuple[str, str, str]:
    """Fit footer text to the current prompt width without touching the edge."""
    target = max(1, width - 1)
    left = _fit_text(left_text, target)
    right_width = max(0, target - len(left) - 1)
    right = _fit_text(right_text, right_width)
    if not right:
        return left, "", ""
    spaces = " " * max(1, target - len(left) - len(right))
    return left, spaces, right


def _build_history():
    history_dir = os.getenv("SECOPS_HISTORY_DIR") or os.path.expanduser("~/.secops_agent")
    history_file = os.path.join(history_dir, "history")
    try:
        os.makedirs(history_dir, exist_ok=True)
        with open(history_file, "ab"):
            pass
        return FileHistory(history_file)
    except OSError:
        return InMemoryHistory()


class CompactPromptSession(PromptSession):
    """PromptSession variant that does not stretch the input to terminal height."""

    def _get_default_buffer_control_height(self) -> Dimension:
        try:
            line_count = self.default_buffer.document.line_count
        except Exception:
            line_count = 1
        return Dimension.exact(max(1, line_count))

    def _create_layout(self):
        """Create a compact layout and let the toolbar own completion rows."""
        dyncond = self._dyncond
        (
            has_before_fragments,
            get_prompt_text_1,
            get_prompt_text_2,
        ) = pt_prompt._split_multiline_prompt(self._get_prompt)

        default_buffer = self.default_buffer
        search_buffer = self.search_buffer

        @pt_prompt.Condition
        def display_placeholder() -> bool:
            return self.placeholder is not None and self.default_buffer.text == ""

        all_input_processors = [
            pt_prompt.HighlightIncrementalSearchProcessor(),
            pt_prompt.HighlightSelectionProcessor(),
            pt_prompt.ConditionalProcessor(
                pt_prompt.AppendAutoSuggestion(),
                pt_prompt.has_focus(default_buffer) & ~pt_prompt.is_done,
            ),
            pt_prompt.ConditionalProcessor(
                pt_prompt.PasswordProcessor(),
                dyncond("is_password"),
            ),
            pt_prompt.DisplayMultipleCursors(),
            pt_prompt.DynamicProcessor(lambda: pt_prompt.merge_processors(self.input_processors or [])),
            pt_prompt.ConditionalProcessor(
                pt_prompt.AfterInput(lambda: self.placeholder),
                filter=display_placeholder,
            ),
        ]

        bottom_toolbar = pt_prompt.ConditionalContainer(
            pt_prompt.Window(
                pt_prompt.FormattedTextControl(
                    lambda: self.bottom_toolbar,
                    style="class:bottom-toolbar.text",
                ),
                style="class:bottom-toolbar",
                dont_extend_height=True,
                height=Dimension(min=1),
            ),
            filter=pt_prompt.Condition(lambda: self.bottom_toolbar is not None)
            & ~pt_prompt.is_done
            & pt_prompt.renderer_height_is_known,
        )

        search_toolbar = pt_prompt.SearchToolbar(
            search_buffer,
            ignore_case=dyncond("search_ignore_case"),
        )
        search_buffer_control = pt_prompt.SearchBufferControl(
            buffer=search_buffer,
            input_processors=[pt_prompt.ReverseSearchProcessor()],
            ignore_case=dyncond("search_ignore_case"),
        )
        system_toolbar = pt_prompt.SystemToolbar(
            enable_global_bindings=dyncond("enable_system_prompt")
        )

        def get_search_buffer_control():
            if pt_prompt.is_true(self.multiline):
                return search_toolbar.control
            return search_buffer_control

        default_buffer_control = pt_prompt.BufferControl(
            buffer=default_buffer,
            search_buffer_control=get_search_buffer_control,
            input_processors=all_input_processors,
            include_default_input_processors=False,
            lexer=pt_prompt.DynamicLexer(lambda: self.lexer),
            preview_search=True,
        )

        default_buffer_window = pt_prompt.Window(
            default_buffer_control,
            height=self._get_default_buffer_control_height,
            get_line_prefix=pt_prompt.partial(
                self._get_line_prefix,
                get_prompt_text_2=get_prompt_text_2,
            ),
            wrap_lines=dyncond("wrap_lines"),
        )

        main_input_container = pt_prompt.FloatContainer(
            pt_prompt.HSplit(
                [
                    pt_prompt.ConditionalContainer(
                        pt_prompt.Window(
                            pt_prompt.FormattedTextControl(get_prompt_text_1),
                            dont_extend_height=True,
                        ),
                        pt_prompt.Condition(has_before_fragments),
                    ),
                    pt_prompt.ConditionalContainer(
                        default_buffer_window,
                        pt_prompt.Condition(
                            lambda: pt_prompt.get_app().layout.current_control
                            != search_buffer_control
                        ),
                    ),
                    pt_prompt.ConditionalContainer(
                        pt_prompt.Window(search_buffer_control),
                        pt_prompt.Condition(
                            lambda: pt_prompt.get_app().layout.current_control
                            == search_buffer_control
                        ),
                    ),
                ]
            ),
            [
                pt_prompt.Float(
                    right=0,
                    top=0,
                    hide_when_covering_content=True,
                    content=pt_prompt._RPrompt(lambda: self.rprompt),
                ),
            ],
        )

        layout = pt_prompt.HSplit(
            [
                pt_prompt.ConditionalContainer(
                    pt_prompt.Frame(main_input_container),
                    filter=dyncond("show_frame"),
                    alternative_content=main_input_container,
                ),
                pt_prompt.ConditionalContainer(
                    pt_prompt.ValidationToolbar(),
                    filter=~pt_prompt.is_done,
                ),
                pt_prompt.ConditionalContainer(
                    system_toolbar,
                    dyncond("enable_system_prompt") & ~pt_prompt.is_done,
                ),
                pt_prompt.ConditionalContainer(
                    pt_prompt.Window(pt_prompt.FormattedTextControl(self._get_arg_text), height=1),
                    dyncond("multiline") & pt_prompt.has_arg,
                ),
                pt_prompt.ConditionalContainer(search_toolbar, dyncond("multiline") & ~pt_prompt.is_done),
                bottom_toolbar,
            ]
        )

        return pt_prompt.Layout(layout, default_buffer_window)


def _editor_command() -> list[str]:
    editor = os.getenv("SECOPS_EDITOR") or os.getenv("VISUAL") or os.getenv("EDITOR") or "vi"
    command = shlex.split(editor)
    return command or ["vi"]


def _edit_text_in_external_editor(text: str) -> tuple[str | None, str]:
    """Open text in $EDITOR and return edited content plus an error message."""
    path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            prefix="secops-prompt-",
            suffix=".md",
        ) as handle:
            handle.write(text)
            path = handle.name

        command = [*_editor_command(), path]
        result = subprocess.run(command)
        if result.returncode != 0:
            return None, f"Editor exited with status {result.returncode}."

        with open(path, "r", encoding="utf-8") as handle:
            return handle.read(), ""
    except FileNotFoundError as exc:
        return None, f"Editor not found: {exc.filename}"
    except OSError as exc:
        return None, f"Unable to open editor: {exc}"
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _latest_expandable_artifact(runtime: Any | None) -> Any | None:
    if runtime is None:
        return None
    for artifact in reversed(getattr(runtime, "artifacts", [])):
        if getattr(artifact, "kind", "") == "tool-result":
            return artifact
    return None


def _artifact_call_text(artifact: Any) -> str:
    from secops_agent.ui.tool_display import format_tool_call_text

    source = str(getattr(artifact, "source", "") or "").strip()
    title = str(getattr(artifact, "title", "") or "Tool output").strip()
    title_call = title.removesuffix(" result").removesuffix(" error")
    return title_call if "(" in title_call else (format_tool_call_text(source, {}) if source else title_call)


def _artifact_status_color(artifact: Any) -> str:
    from secops_agent.ui.tool_display import _looks_like_tool_failure

    title = str(getattr(artifact, "title", "") or "").strip().lower()
    content = str(getattr(artifact, "content", "") or "")
    if title.endswith(" error") or _looks_like_tool_failure(content):
        return COLORS["error"]
    return COLORS["success"]


def _clear_previous_ctrl_o_surface(runtime: Any | None, console: Any) -> bool:
    if runtime is None:
        return False
    count = int(getattr(runtime, "ctrl_o_rendered_lines", 0) or 0)
    return _clear_terminal_lines(console, count, runtime=runtime, attr="ctrl_o_rendered_lines")


def _clear_terminal_lines(
    console: Any,
    count: int,
    *,
    runtime: Any | None = None,
    attr: str = "",
) -> bool:
    if count <= 0 or not bool(getattr(console, "is_terminal", False)):
        return False
    output = getattr(console, "file", None)
    if output is None:
        return False
    try:
        terminal_height = shutil.get_terminal_size((80, 24)).lines
    except Exception:
        terminal_height = 24
    if count > max(1, terminal_height - 1):
        return False
    output.write("\r\x1b[K")
    for _ in range(count):
        output.write("\x1b[1A\x1b[K")
    output.write("\r")
    with contextlib.suppress(Exception):
        output.flush()
    if runtime is not None and attr:
        setattr(runtime, attr, 0)
    return True


def _toggle_rendered_transcript(runtime: Any | None, console: Any | None) -> str:
    if runtime is None or console is None or not bool(getattr(console, "is_terminal", False)):
        return ""
    collapsed = str(getattr(runtime, "ctrl_o_transcript_collapsed", "") or "")
    expanded = str(getattr(runtime, "ctrl_o_transcript_expanded", "") or "")
    if not collapsed or not expanded:
        return ""
    current_lines = int(getattr(runtime, "ctrl_o_transcript_rendered_lines", 0) or 0)
    if current_lines <= 0:
        return ""

    cleared = _clear_terminal_lines(
        console,
        current_lines,
        runtime=runtime,
        attr="ctrl_o_transcript_rendered_lines",
    )
    if not cleared:
        return "unchanged"
    next_expanded = not bool(getattr(runtime, "ctrl_o_transcript_is_expanded", False))
    text = expanded if next_expanded else collapsed
    lines = text.split("\n")
    for line in lines:
        console.print(line, no_wrap=True, overflow="ellipsis")
    setattr(runtime, "ctrl_o_transcript_is_expanded", next_expanded)
    setattr(runtime, "ctrl_o_transcript_rendered_lines", len(lines))
    return "transcript"


def _toggle_anchored_ctrl_o_surface(runtime: Any | None, console: Any | None) -> str:
    if runtime is None or console is None or not bool(getattr(console, "is_terminal", False)):
        return ""

    collapsed = str(getattr(runtime, "ctrl_o_anchor_collapsed", "") or "")
    expanded = str(getattr(runtime, "ctrl_o_anchor_expanded", "") or "")
    current_lines = int(getattr(runtime, "ctrl_o_anchor_rendered_lines", 0) or 0)
    if not collapsed or not expanded or current_lines <= 0:
        return ""

    output = getattr(console, "file", None)
    if output is None:
        return ""

    next_expanded = not bool(getattr(runtime, "ctrl_o_anchor_is_expanded", False))
    next_text = expanded if next_expanded else collapsed
    next_lines = next_text.split("\n")
    next_result = "tool-output" if next_expanded else "tool-output-collapsed"

    tail_lines = max(0, int(getattr(runtime, "ctrl_o_anchor_tail_lines", 0) or 0))
    distance_to_start = tail_lines + current_lines
    try:
        terminal_height = shutil.get_terminal_size((80, 24)).lines
    except Exception:
        terminal_height = 24
    if distance_to_start > max(0, terminal_height - 1):
        return "tool-output-unchanged"

    output.write("\r")
    if distance_to_start:
        output.write(f"\x1b[{distance_to_start}A")
    output.write(f"\x1b[{current_lines}M")
    output.write(f"\x1b[{len(next_lines)}L")
    with contextlib.suppress(Exception):
        output.flush()

    for line in next_lines:
        console.print(line, no_wrap=True, overflow="ellipsis")

    if tail_lines:
        output.write(f"\x1b[{tail_lines}B")
    output.write("\r")
    with contextlib.suppress(Exception):
        output.flush()

    setattr(runtime, "ctrl_o_anchor_is_expanded", next_expanded)
    setattr(runtime, "ctrl_o_anchor_rendered_lines", len(next_lines))
    return next_result


def _formatted_line_count(fragments: Any) -> int:
    text = fragment_list_to_text(to_formatted_text(fragments))
    if not text:
        return 0
    return max(1, len(text.splitlines()))


def _apply_prompt_tail_to_ctrl_o_anchor(runtime: Any | None, prompt_lines: int) -> bool:
    if runtime is None:
        return False
    if not str(getattr(runtime, "ctrl_o_anchor_collapsed", "") or ""):
        return False
    if bool(getattr(runtime, "ctrl_o_anchor_prompt_tail_applied", False)):
        return False
    count = max(0, int(prompt_lines or 0))
    if count <= 0:
        return False
    runtime.advance_ctrl_o_anchor_lines(count)
    setattr(runtime, "ctrl_o_anchor_prompt_tail_applied", True)
    return True


def _render_collapsed_tool_output(console: Any, artifact: Any) -> int:
    """Render the latest tool output collapsed, matching the ctrl+o hint."""
    from rich.markup import escape

    width = _terminal_width()
    call_text = _artifact_call_text(artifact)
    hint = "(ctrl+o to expand)"
    fitted_call = _fit_text(call_text, max(1, width - len(hint) - 4))
    console.print()
    console.print(
        f"[{_artifact_status_color(artifact)}]●[/{_artifact_status_color(artifact)}] "
        f"[{COLORS['text']}]{escape(fitted_call)}[/{COLORS['text']}] "
        f"[{COLORS['text_muted']}]{hint}[/{COLORS['text_muted']}]"
    )
    return 2


def _render_expanded_tool_output(console: Any, artifact: Any) -> int:
    """Render latest tool detail without duplicating the already printed call row."""
    from rich.markup import escape

    width = _terminal_width()
    content = str(getattr(artifact, "content", "") or "(no output)")
    content = supervised_detail_text(getattr(artifact, "metadata", None), content)
    lines = [line.rstrip() for line in content.splitlines() if line.strip()] or ["(no output)"]
    first_line = _fit_text(lines[0], max(1, width - 34))
    console.print()
    console.print(
        f"  [{COLORS['text_muted']}]⎿  {escape(first_line)} "
        f"(ctrl+o to collapse)[/{COLORS['text_muted']}]"
    )
    rendered_lines = 2
    if len(lines) > 1:
        console.print()
        console.print(f"  [{COLORS['text_muted']}]Output:[/{COLORS['text_muted']}]")
        rendered_lines += 2
        visible_lines = lines[:_ctrl_o_output_visible_limit()]
        for line in visible_lines:
            console.print(f"    [{COLORS['text_muted']}]{escape(_fit_text(line, max(1, width - 6)))}[/{COLORS['text_muted']}]")
        rendered_lines += len(visible_lines)
        if len(lines) > len(visible_lines):
            console.print(f"    [{COLORS['text_dim']}]... {len(lines) - len(visible_lines):,} more lines hidden[/{COLORS['text_dim']}]")
            rendered_lines += 1
    return rendered_lines


def _show_ctrl_o_surface(memory: Any | None, runtime: Any | None, console: Any | None = None) -> str:
    """Toggle the latest local transcript; /trajectory owns the full session view."""
    anchored = _toggle_anchored_ctrl_o_surface(runtime, console)
    if anchored:
        return anchored

    transcript_toggle = _toggle_rendered_transcript(runtime, console)
    if transcript_toggle:
        return transcript_toggle

    has_current_transcript = bool(
        str(getattr(runtime, "ctrl_o_transcript_collapsed", "") or "")
        and str(getattr(runtime, "ctrl_o_transcript_expanded", "") or "")
    )
    has_anchor = bool(str(getattr(runtime, "ctrl_o_anchor_collapsed", "") or ""))
    if memory is not None and (not has_current_transcript or has_anchor):
        if console and not bool(getattr(console, "is_terminal", False)):
            console.print("\n\x1b[90m⎿  Nothing to expand yet.\x1b[m")
        return "none"

    artifact = _latest_expandable_artifact(runtime)
    if artifact is not None and console:
        rendered_count = int(getattr(runtime, "ctrl_o_rendered_lines", 0) or 0)
        cleared = _clear_previous_ctrl_o_surface(runtime, console)
        artifact_id = str(getattr(artifact, "id", "") or "")
        expanded_id = str(getattr(runtime, "ctrl_o_expanded_artifact_id", "") or "")
        if artifact_id and expanded_id == artifact_id:
            if rendered_count > 0 and not cleared and bool(getattr(console, "is_terminal", False)):
                return "tool-output-unchanged"
            setattr(runtime, "ctrl_o_expanded_artifact_id", "")
            setattr(runtime, "ctrl_o_rendered_lines", 0)
            return "tool-output-collapsed"
        if artifact_id:
            setattr(runtime, "ctrl_o_expanded_artifact_id", artifact_id)
        rendered_lines = _render_expanded_tool_output(console, artifact)
        setattr(runtime, "ctrl_o_rendered_lines", rendered_lines)
        return "tool-output"

    if console and not bool(getattr(console, "is_terminal", False)):
        console.print("\n\x1b[90m⎿  Nothing to expand yet.\x1b[m")
    return "none"


def _show_ctrl_r_surface(
    runtime: Any | None,
    *,
    model_name: str = "",
    console: Any | None = None,
) -> str:
    """Open the AGY-like artifact review surface used by ctrl+r."""
    if runtime is None:
        return "missing-runtime"

    from secops_agent.ui.renderer import Renderer

    renderer = Renderer()
    if console is not None:
        renderer.console = console
    renderer.render_artifacts(
        runtime,
        transient=True,
        status_right=friendly_model_name(model_name or "gemini-2.5-flash"),
    )
    return "artifacts"


class SlashCommandCompleter(Completer):
    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor.lstrip()
        if not text.startswith("/"):
            return

        # Check if we are typing arguments for a slash command
        if " " in text:
            parts = text.split(" ", 1)
            cmd = parts[0]
            arg = parts[1]

            spec = get_command(cmd)
            canonical_cmd = spec.name if spec else cmd

            if canonical_cmd == "/model":
                for model in completion_values():
                    if model.startswith(arg):
                        yield PTCompletion(
                            model,
                            start_position=-len(arg),
                            display=_completion_display(model, "Model identifier"),
                        )
            elif cmd == "/load":
                from secops_agent.config import settings
                try:
                    d = settings.sessions_dir
                    sessions = [f.stem for f in d.iterdir() if f.is_file() and f.suffix == ".json"]
                except Exception:
                    sessions = []
                for s in sorted(sessions):
                    if s.startswith(arg):
                        yield PTCompletion(
                            s,
                            start_position=-len(arg),
                            display=_completion_display(s, "Saved session"),
                        )
            elif canonical_cmd == "/permissions":
                if " " not in arg:
                    for action in ("allow", "ask", "deny", "clear"):
                        if action.startswith(arg):
                            yield PTCompletion(
                                action,
                                start_position=-len(arg),
                                display=_completion_display(action, "Permission action"),
                            )
                else:
                    action, resource_prefix = arg.split(" ", 1)
                    if action in {"allow", "ask", "deny"}:
                        try:
                            from secops_agent.core.tools import registry
                            resources = ["tool(*)"] + [f"tool({tool.name})" for tool in registry.list_tools()]
                        except Exception:
                            resources = ["tool(*)"]
                        for resource in resources:
                            if resource.startswith(resource_prefix):
                                yield PTCompletion(
                                    resource,
                                    start_position=-len(resource_prefix),
                                    display=_completion_display(resource, "Permission resource"),
                                )
            elif cmd == "/sandbox":
                for action in ("on", "off", "status"):
                    if action.startswith(arg):
                        yield PTCompletion(
                            action,
                            start_position=-len(arg),
                            display=_completion_display(action, "Sandbox action"),
                        )
            elif canonical_cmd == "/tools":
                for label, description in _tool_completion_rows():
                    tool_name = label.split(" ", 1)[1]
                    if tool_name.startswith(arg):
                        yield PTCompletion(
                            tool_name,
                            start_position=-len(arg),
                            display=_completion_display(tool_name, description),
                        )
            return

        # Otherwise autocomplete command itself
        for spec in iter_commands():
            if spec.name in ROOT_COMPLETION_HIDDEN_COMMANDS:
                continue
            if spec.name.startswith(text):
                meta = spec.description
                if not spec.implemented:
                    meta = f"{meta} (planned)"
                yield PTCompletion(
                    spec.name,
                    start_position=-len(text),
                    display=_completion_display(spec.name, meta),
                )


class InputHandler:
    """Antigravity-style input: simple '> ' prompt with bottom toolbar."""

    # Sentinel value returned when user types '?' alone
    SHORTCUT_REQUEST = "__SHORTCUT_REQUEST__"
    ARTIFACT_REVIEW_REQUEST = "__ARTIFACT_REVIEW_REQUEST__"

    def __init__(self):
        # Use theme.py as the single source of truth for all styling
        self.style = PtStyle.from_dict(pt_style_dict())

        self.bindings = KeyBindings()

        @self.bindings.add("escape", "enter")
        def _newline(event):
            event.current_buffer.insert_text("\n")

        @self.bindings.add("c-j")
        def _ctrl_j_newline(event):
            event.current_buffer.insert_text("\n")

        @self.bindings.add("backspace")
        def _backspace(event):
            buffer = event.current_buffer
            if buffer.cursor_position > 0:
                buffer.delete_before_cursor(1)
                _refresh_slash_completion_after_edit(buffer)

        @self.bindings.add("delete")
        def _delete(event):
            buffer = event.current_buffer
            if buffer.cursor_position < len(buffer.text):
                buffer.delete(1)
                _refresh_slash_completion_after_edit(buffer)

        @self.bindings.add("?")
        def _open_shortcuts(event):
            if event.current_buffer.text:
                event.current_buffer.insert_text("?")
                return
            event.app.exit(result=self.SHORTCUT_REQUEST)

        @self.bindings.add("down", filter=has_completions)
        def _completion_down(event):
            complete_state = event.current_buffer.complete_state
            if not complete_state or not complete_state.completions:
                return
            if complete_state.complete_index is None:
                target = 1 if len(complete_state.completions) > 1 else 0
                event.current_buffer.go_to_completion(target)
            else:
                event.current_buffer.complete_next()

        @self.bindings.add("up", filter=has_completions)
        def _completion_up(event):
            complete_state = event.current_buffer.complete_state
            if not complete_state or not complete_state.completions:
                return
            if complete_state.complete_index is None:
                event.current_buffer.go_to_completion(len(complete_state.completions) - 1)
            else:
                event.current_buffer.complete_previous()

        @self.bindings.add("c-m")
        def _submit(event):
            complete_state = event.current_buffer.complete_state
            if complete_state and complete_state.completions:
                index = complete_state.complete_index
                selected = complete_state.completions[index if index is not None else 0]
                document = event.current_buffer.document
                if (
                    document.text_before_cursor.strip() == selected.text
                    or _completion_preserves_text(document, selected)
                    or _completion_matches_current_argument(document, complete_state.completions)
                ):
                    event.current_buffer.validate_and_handle()
                    return
                event.current_buffer.apply_completion(selected)
                return
            event.current_buffer.validate_and_handle()

        @self.bindings.add("c-l")
        def _clear_screen(event):
            event.app.renderer.clear()

        @self.bindings.add("c-g")
        async def _open_prompt_editor(event):
            """Open the current prompt in the user's external editor."""
            buffer = event.current_buffer
            original_text = buffer.text

            def _edit_prompt():
                edited, error = _edit_text_in_external_editor(original_text)
                if error:
                    if self._console:
                        self._console.print(f"\n[{COLORS['error']}]⚠ {error}[/{COLORS['error']}]")
                    return
                if edited is None or edited == original_text:
                    return
                buffer.save_to_undo_stack()
                buffer.set_document(
                    Document(edited, cursor_position=len(edited)),
                    bypass_readonly=True,
                )

            await run_in_terminal(_edit_prompt)

        @self.bindings.add("c-_")
        def _undo_prompt_edit(event):
            event.current_buffer.undo()

        @self.bindings.add("c-y")
        def _yank_clipboard(event):
            data = event.app.clipboard.get_data()
            if data.text:
                event.current_buffer.paste_clipboard_data(data)

        @self.bindings.add("c-v")
        def _paste_or_attach_clipboard_file(event):
            data = event.app.clipboard.get_data()
            text = data.text or system_clipboard_text()
            attach_command = ""
            if not event.current_buffer.text.strip():
                attach_command = _clipboard_attachment_command(text)
                if not attach_command:
                    attach_command = system_clipboard_attach_command(cwd=Path.cwd())
            if attach_command:
                event.app.exit(result=attach_command)
                return
            if data.text:
                event.current_buffer.paste_clipboard_data(data)
            elif text:
                event.current_buffer.insert_text(text)

        @self.bindings.add("c-z")
        def _suspend_cli(event):
            try:
                event.app.suspend_to_background()
            except Exception:
                import signal
                os.kill(os.getpid(), signal.SIGTSTP)

        @self.bindings.add("escape", "j")
        def _open_agents(event):
            if event.current_buffer.text:
                return
            event.app.exit(result="/agents")

        @self.bindings.add("c-o")
        async def _expand_latest(event):
            """Expand or collapse the latest local transcript."""
            if not self._memory and not self._runtime:
                return

            def _show_expansion():
                if self._console and bool(getattr(self._console, "is_terminal", False)):
                    _apply_prompt_tail_to_ctrl_o_anchor(
                        self._runtime,
                        self._ctrl_o_prompt_tail_lines(),
                    )
                _show_ctrl_o_surface(self._memory, self._runtime, self._console)

            await run_in_terminal(_show_expansion)

        @self.bindings.add("c-r")
        async def _review_artifact(event):
            """Open the latest generated artifact."""
            event.app.exit(result=self.ARTIFACT_REVIEW_REQUEST)

        @self.bindings.add("s-tab")
        def _cycle_permission_mode_binding(event):
            """PROC-02: Shift+Tab cycles the permission mode (when not completing)."""
            buf = event.app.current_buffer
            if buf.complete_state is not None:
                buf.complete_previous()
                return
            cycler = self._permission_mode_cycler
            if cycler is None:
                return
            try:
                payload = cycler()
            except Exception:
                return
            if isinstance(payload, dict):
                self._statusline.update(payload)
            event.app.invalidate()

        self.session = CompactPromptSession(
            history=_build_history(),
            completer=SlashCommandCompleter(),
            style=self.style,
            key_bindings=self.bindings,
            complete_while_typing=True,
            reserve_space_for_menu=COMPLETION_MENU_RESERVED_ROWS,
            erase_when_done=True,
        )

        self._model_name = ""
        self._turn_count = 0
        self._memory = None
        self._runtime = None
        self._console = None
        self._permission_mode_cycler = None
        self._statusline = {
            "cwd": "",
            "tokens": 0,
            "tools": 0,
            "tasks": 0,
            "dirs": 0,
            "profile": "standard",
            "sandbox": False,
            "permissions": "default",
            "autonomy": "semi-auto",
            "phase": "",
            "state": "idle",
        }

    def update_context(
        self,
        model_name: str = "",
        turn_count: int = 0,
        memory: Optional[Any] = None,
        console: Optional[Any] = None,
        runtime: Optional[Any] = None,
        statusline: Optional[dict[str, Any]] = None,
        permission_cycler: Optional[Any] = None,
        **_,
    ):
        if model_name:
            self._model_name = model_name
        self._turn_count = turn_count
        if memory is not None:
            self._memory = memory
        if runtime is not None:
            self._runtime = runtime
        if console is not None:
            self._console = console
        if statusline:
            self._statusline.update(statusline)
        if permission_cycler is not None:
            self._permission_mode_cycler = permission_cycler

    def _build_statusline(self, width: int, completion_mode: bool = False) -> str:
        status = getattr(self, "_statusline", {})
        friendly = friendly_model_name(self._model_name or "gemini-2.5-flash")
        cwd = status.get("cwd") or os.getcwd().replace(os.path.expanduser("~"), "~")
        tokens = int(status.get("tokens") or 0)
        tasks = int(status.get("tasks") or 0)
        dirs_count = int(status.get("dirs") or 0)
        tools = int(status.get("tools") or 0)
        profile = str(status.get("profile") or "standard")
        state = str(status.get("state") or "idle")
        sandbox = "sandbox" if status.get("sandbox") else "no sandbox"
        permissions = str(status.get("permissions") or "default")
        autonomy = str(status.get("autonomy") or "")
        phase = str(status.get("phase") or "")
        posture_seg = f"auto:{autonomy}" if autonomy else ""
        phase_seg = f"phase:{phase}" if phase else ""

        if completion_mode or width < 60:
            segments = [friendly, state, f"{tasks} tasks"]
        elif width < 90:
            segments = [friendly, state, sandbox, permissions, posture_seg, f"{tasks} tasks"]
        elif width < 120:
            segments = [
                friendly, state, sandbox, permissions, posture_seg, f"~{tokens:,} tok", f"{tasks} tasks"
            ]
        else:
            segments = [
                friendly,
                state,
                phase_seg,
                cwd,
                profile,
                sandbox,
                permissions,
                posture_seg,
                f"~{tokens:,} tok",
                f"{tasks} tasks",
                f"{dirs_count} dirs",
                f"{tools} tools",
            ]

        return _fit_segments([seg for seg in segments if seg], width)

    def _footer_model(self, width: int) -> str:
        return _fit_text(friendly_model_name(self._model_name or "gemini-2.5-flash"), width)

    def _get_toolbar(self):
        """Antigravity-style toolbar: border top, shortcuts left, model right."""
        width = _frame_width(_terminal_width())

        # Check if completion is active
        is_completing = False
        try:
            if self.session.default_buffer.complete_state is not None:
                is_completing = True
        except Exception:
            pass

        if is_completing:
            complete_state = self.session.default_buffer.complete_state
            completions = list(complete_state.completions) if complete_state else []
            completion_count = len(completions)
            active_index = complete_state.complete_index if complete_state else None
            selected = active_index if active_index is not None else 0
            visible_count = SLASH_COMPLETION_VISIBLE_ROWS
            start = 0
            if selected >= visible_count:
                start = selected - visible_count + 1
            visible = completions[start : start + visible_count]
            hidden_above = max(0, start)
            hidden_below = max(0, completion_count - (start + len(visible)))
            left_text = "esc to cancel"

            result = [("class:prompt_border", _prompt_separator(width) + "\n")]
            if hidden_above:
                result.extend([
                    ("class:toolbar_left", "   "),
                    ("class:toolbar_key", f"↑ {hidden_above} more"),
                    ("class:toolbar_action", "\n"),
                ])
            for offset, completion in enumerate(visible):
                index = start + offset
                marker = "> " if index == selected else "  "
                style = (
                    "class:completion-menu.completion.current"
                    if index == selected
                    else "class:completion-menu.completion"
                )
                row = marker + _completion_line_text(completion, max(1, width - len(marker) - 1))
                result.append((style, _fit_text(row, max(1, width - 1)) + "\n"))
            if hidden_below:
                result.extend([
                    ("class:toolbar_left", "   "),
                    ("class:toolbar_key", f"↓ {hidden_below} more"),
                    ("class:toolbar_action", "\n"),
                ])
            result.append(("class:toolbar_left", "\n"))

            # Line 1: Key guides with exact Unicode arrows and 2-space indentation
            line1 = [
                ("class:toolbar_left", "  "),
                ("class:toolbar_key", "↑/↓"),
                ("class:toolbar_action", " Navigate · "),
                ("class:toolbar_key", "enter"),
                ("class:toolbar_action", " Select · "),
                ("class:toolbar_key", "tab"),
                ("class:toolbar_action", " Complete\n"),
            ]

            # Line 2: cancel help and active model info
            model_name = friendly_model_name(self._model_name or "gemini-2.5-flash")
            left_text, spaces, model_text = _footer_parts(left_text, model_name, width)

            line2 = [
                ("class:toolbar_left", left_text),
                ("class:toolbar_spaces", spaces),
                ("class:toolbar_right", model_text),
            ]

            result.extend(line1)
            result.extend(line2)
            return result
        else:
            # Keep the execution context on screen: the former minimal footer
            # hid permission mode, sandbox state and current phase behind the
            # /statusline overlay precisely while an operator needed them.
            statusline = self._build_statusline(width)
            return [
                ("class:prompt_border", _prompt_separator(width) + "\n"),
                ("class:toolbar_left", statusline),
            ]

    def _prompt_fragments(self):
        width = _frame_width(_terminal_width())
        return [
            ("class:prompt_border", _prompt_separator(width) + "\n"),
            ("class:prompt", "> "),
        ]

    def _ctrl_o_prompt_tail_lines(self) -> int:
        return _formatted_line_count(self._prompt_fragments()) + _formatted_line_count(self._get_toolbar())

    def show_shortcuts(self, console) -> None:
        """Compatibility wrapper for the shared shortcuts help surface."""
        from rich.markup import escape
        from secops_agent.ui.commands import iter_commands
        from secops_agent.ui.renderer import build_help_view_lines

        groups: dict[str, list[object]] = {}
        for spec in iter_commands():
            groups.setdefault(spec.category, []).append(spec)

        console.print()
        for line in build_help_view_lines(
            groups,
            active_view="shortcuts",
            width=console.size.width,
            height=min(28, max(12, console.size.height)),
        ):
            if line.startswith("─"):
                console.print(f"[{COLORS['text_dim']}]{line}[/]")
            else:
                console.print(f"[{COLORS['text_muted']}]{escape(line)}[/{COLORS['text_muted']}]")
        console.print()

    def refresh_theme(self) -> None:
        """Rebuild the prompt styling from the current theme palette (FMT-05)."""
        self.style = PtStyle.from_dict(pt_style_dict())
        with contextlib.suppress(Exception):
            self.session.style = self.style

    async def get_input(self, model_name: str = "") -> Optional[str]:
        if model_name:
            self._model_name = model_name

        try:
            user_input = await self.session.prompt_async(
                self._prompt_fragments(),
                bottom_toolbar=self._get_toolbar,
            )

            # Intercept lone '?' to show shortcuts
            if user_input and user_input.strip() == "?":
                return self.SHORTCUT_REQUEST

            return user_input.strip() if user_input else None
        except KeyboardInterrupt:
            return None
        except EOFError:
            return "/exit"
