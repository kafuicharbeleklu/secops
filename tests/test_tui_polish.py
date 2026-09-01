from __future__ import annotations

import os
import io
import asyncio
import contextlib
import inspect
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from prompt_toolkit.document import Document
    from prompt_toolkit.completion import Completion as PTCompletion
    from prompt_toolkit.history import InMemoryHistory
    from rich.console import Console
    from rich.markdown import Markdown
    from google.genai import types as genai_types
    from typer.testing import CliRunner

    from secops_agent import __version__
    from secops_agent.config import settings
    from secops_agent.core.agent import ErrorEvent, SuggestedActionsEvent, TextEvent, ThinkingEvent, ToolCallEvent, ToolStartEvent, ToolProgressEvent, ToolResultEvent, SudoAuthenticationRequestEvent
    from secops_agent.core.llm import GeminiProvider, Message
    from secops_agent.core.memory import ConversationMemory
    from secops_agent.core.model_catalog import DEFAULT_MODEL, GEMMA_FAST_MODEL, selectable_models
    from secops_agent.core.sudo import SudoAuthenticationDecision
    from secops_agent.ui.input_handler import (
        COMPLETION_MENU_RESERVED_ROWS,
        SLASH_COMPLETION_VISIBLE_ROWS,
        InputHandler,
        SlashCommandCompleter,
        _build_history,
        _agy_menu_item_fragments,
        _clipboard_attachment_command,
        _completion_matches_current_argument,
        _completion_preserves_text,
        _completion_more_text,
        _refresh_slash_completion_after_edit,
        _edit_text_in_external_editor,
        _footer_parts,
        _fit_segments,
        _artifact_status_color,
        _latest_expandable_artifact,
        _prompt_separator,
        _show_ctrl_r_surface,
        _show_ctrl_o_surface,
        _apply_prompt_tail_to_ctrl_o_anchor,
        ROOT_COMPLETION_HIDDEN_COMMANDS,
    )
    from secops_agent.core.permissions import PermissionResource
    from secops_agent.core.tools import ToolResult, _current_progress
    from secops_agent.core.extensions import SkillDefinition
    from secops_agent.core.mcp import MCPConfigState, MCPRuntime, MCPServerConfig, load_mcp_config
    from secops_agent.tools import network
    from secops_agent.ui.animations import (
        STARTUP_CLEAR_SEQUENCE,
        ThinkingSpinner,
        ToolExecutionSpinner,
        format_wait_message,
        wait_tip_for_elapsed,
    )
    from secops_agent.ui.attachments import attach_file, build_attachment_model_parts, build_attachment_prompt_context
    from secops_agent.ui.clipboard import attachment_command_from_clipboard_text, system_clipboard_attach_command
    from secops_agent.ui.menu import _model_choices
    from secops_agent.ui.overlay import (
        LOG_OVERLAY_CONTROLS,
        OverlayChoice,
        OverlayRow,
        build_choice_overlay_lines,
        choose_overlay,
        _is_choice_more_indicator,
        render_overlay,
        terminal_key_from_sequence,
    )
    from secops_agent.ui.panel import PanelRow, build_panel_lines
    from secops_agent.ui.permissions_menu import _permission_choices
    from secops_agent.ui.renderer import (
        AgentProfileSummary,
        Renderer,
        SettingsItem,
        _is_shortcut_help_label,
        _split_help_row,
        build_agents_view_lines,
        build_attachments_view_lines,
        build_artifacts_view_lines,
        build_help_view_lines,
        build_context_usage_lines,
        build_hooks_view_lines,
        build_mcp_view_lines,
        build_settings_view_lines,
        build_skills_view_lines,
        build_tools_view_lines,
        normalize_agent_markdown,
        _build_expanded_tool_result_lines,
        _build_collapsed_tool_result_lines,
    )
    from secops_agent.ui.session_review import build_artifact_text, build_trajectory_text
    from secops_agent.ui.sudo_prompt import request_sudo_authentication
    from secops_agent.ui.theme import COLORS, ansi, get_header_banner, pt_style_dict, rich_theme
    from secops_agent.ui.tool_display import ApprovalPrompt, ToolCallBox, ToolResultBox, _approval_lines, _approval_options, format_tool_call_text
    from secops_agent.ui.runtime import RuntimeState
    from secops_agent.ui.commands import get_command
    from secops_agent.main import _render_header_banner
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard for bare system Python.
    raise unittest.SkipTest("TUI dependencies are not installed") from exc


class TUIPolishTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self._isatty_patches = [
            patch("sys.stdin.isatty", return_value=False),
            patch("sys.stdout.isatty", return_value=False),
        ]
        for p in self._isatty_patches:
            p.start()

    def tearDown(self):
        for p in self._isatty_patches:
            p.stop()

    def test_slash_completion_renders_description_inline(self):
        completer = SlashCommandCompleter()
        completions = list(completer.get_completions(Document("/", cursor_position=1), None))

        self.assertTrue(completions)
        first = completions[0]
        self.assertEqual(first.display_meta_text, "")
        self.assertIn("/add-dir", str(first.display))
        self.assertNotIn("/add-dir <path>", str(first.display))
        self.assertIn("Add a directory", str(first.display))

    def test_root_slash_completion_keeps_command_labels_compact(self):
        completer = SlashCommandCompleter()
        completions = list(completer.get_completions(Document("/", cursor_position=1), None))
        rendered = "\n".join(str(item.display) for item in completions)
        labels = [item.text for item in completions]

        self.assertNotIn("<path>", rendered)
        self.assertNotIn("<id>", rendered)
        self.assertNotIn("[auto", rendered)
        self.assertNotIn("[allow", rendered)
        self.assertIn("/model", rendered)
        self.assertIn("/permissions", rendered)
        self.assertNotIn("/permission", labels)
        self.assertNotIn("/artifacts", labels)
        self.assertFalse(ROOT_COMPLETION_HIDDEN_COMMANDS & set(labels))

    def test_root_slash_completion_hides_semantic_detail_duplicates(self):
        completer = SlashCommandCompleter()

        task_labels = [
            item.text
            for item in completer.get_completions(Document("/ta", cursor_position=len("/ta")), None)
        ]
        tool_labels = [
            item.text
            for item in completer.get_completions(Document("/to", cursor_position=len("/to")), None)
        ]

        self.assertIn("/tasks", task_labels)
        self.assertNotIn("/task", task_labels)
        self.assertIn("/tools", tool_labels)
        self.assertNotIn("/tool", tool_labels)

    def test_root_slash_completion_omits_individual_tool_entries(self):
        # /tools already gives the detailed overview; the root menu must not be
        # flooded with one /tool <name> entry per registered tool.
        completer = SlashCommandCompleter()
        for probe in ("/", "/n", "/tool"):
            labels = [
                item.text
                for item in completer.get_completions(
                    Document(probe, cursor_position=len(probe)), None
                )
            ]
            self.assertNotIn("/tool nmap_scan", labels)
            self.assertFalse(
                any(label.startswith("/tool ") for label in labels),
                f"per-tool entries leaked into root completion for {probe!r}: {labels}",
            )

    def test_tool_argument_completion_lists_registered_tool_names(self):
        completer = SlashCommandCompleter()
        # canonical "/tools <name>" and its "/tool" alias both complete tool names
        for prefix in ("/tools nm", "/tool nm"):
            completions = list(
                completer.get_completions(Document(prefix, cursor_position=len(prefix)), None)
            )
            self.assertIn("nmap_scan", [item.text for item in completions])
            self.assertTrue(all(not item.text.startswith("/") for item in completions))

    def test_model_completion_has_no_meta_column(self):
        completer = SlashCommandCompleter()
        completions = list(
            completer.get_completions(Document("/model gem", cursor_position=len("/model gem")), None)
        )

        self.assertIn("gemini", [item.text for item in completions])
        self.assertTrue(all(item.display_meta_text == "" for item in completions))

    def test_permission_completion_accepts_singular_and_legacy_plural_alias(self):
        completer = SlashCommandCompleter()

        singular = list(
            completer.get_completions(Document("/permission al", cursor_position=len("/permission al")), None)
        )
        legacy_plural = list(
            completer.get_completions(Document("/permissions al", cursor_position=len("/permissions al")), None)
        )

        self.assertIn("allow", [item.text for item in singular])
        self.assertIn("allow", [item.text for item in legacy_plural])

    def test_slash_completion_does_not_advertise_uncaptured_action_variants(self):
        completer = SlashCommandCompleter()

        for command in ("/skills r", "/hooks r", "/mcp s", "/mcp r", "/task t", "/cancel t"):
            with self.subTest(command=command):
                completions = list(completer.get_completions(Document(command, cursor_position=len(command)), None))
                self.assertEqual([], [item.text for item in completions])

    def test_slash_surfaces_do_not_advertise_non_secops_agy_commands(self):
        from secops_agent.ui.commands import COMMANDS

        excluded = {"/changelog", "/credits", "/install", "/memory", "/plugin", "/plugins", "/update"}
        declared = {spec.name for spec in COMMANDS}
        self.assertFalse(declared & excluded)

        completer = SlashCommandCompleter()
        completions = []
        for prefix in ("/c", "/i", "/m", "/p", "/u"):
            completions.extend(
                item.text for item in completer.get_completions(Document(prefix, cursor_position=len(prefix)), None)
            )

        self.assertFalse(set(completions) & excluded)

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        for command in excluded:
            self.assertNotIn(command, readme)

    def test_visible_slash_commands_have_handlers(self):
        from secops_agent.ui.commands import ALIASES, COMMANDS

        main_source = (Path(__file__).resolve().parents[1] / "secops_agent" / "main.py").read_text(encoding="utf-8")
        handled = set(re.findall(r'canonical_cmd == "([^"]+)"', main_source))
        declared = {spec.name for spec in COMMANDS}

        self.assertFalse(declared - handled)
        self.assertFalse(handled - declared)
        self.assertEqual(set(ALIASES.values()) - declared, set())
        self.assertFalse([spec.name for spec in COMMANDS if not spec.implemented])

    def test_extension_command_descriptions_do_not_advertise_action_variants(self):
        completer = SlashCommandCompleter()
        completions = list(completer.get_completions(Document("/s", cursor_position=len("/s")), None))
        completions += list(completer.get_completions(Document("/h", cursor_position=len("/h")), None))
        completions += list(completer.get_completions(Document("/m", cursor_position=len("/m")), None))

        rendered = "\n".join(str(item.display) for item in completions)

        self.assertIn("/skills", rendered)
        self.assertIn("/hooks", rendered)
        self.assertIn("/mcp", rendered)
        self.assertNotIn("reload", rendered.lower())
        self.assertNotIn("manage", rendered.lower())
        self.assertEqual("/skills", get_command("/skills").display_name)
        self.assertEqual("/hooks", get_command("/hooks").display_name)
        self.assertEqual("/mcp", get_command("/mcp").display_name)

    def test_visible_extension_docs_do_not_advertise_action_variants(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

        self.assertIn("/skills\n/hooks\n/mcp", readme)
        self.assertNotIn("/skills [reload]", readme)
        self.assertNotIn("/hooks [reload]", readme)
        self.assertNotIn("/mcp [start|stop|restart|reload]", readme)
        self.assertNotIn("/skills reload", readme)
        self.assertNotIn("/hooks reload", readme)
        self.assertNotIn("/mcp reload", readme)

    def test_readme_slash_command_inventory_matches_registry(self):
        from secops_agent.ui.commands import COMMANDS

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        match = re.search(r"## Slash Commands\n(.*?)\n## Tools And Safety", readme, re.S)
        self.assertIsNotNone(match)

        documented = {
            line.strip().split()[0]
            for line in match.group(1).splitlines()
            if line.strip().startswith("/")
        }
        actual = {spec.name for spec in COMMANDS}

        self.assertEqual(documented, actual)

    def test_readme_model_alias_inventory_matches_catalog(self):
        from secops_agent.core.model_catalog import MODEL_ALIASES

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        match = re.search(r"Accepted model aliases:\n(.*?)\n\nGemma 4 thinking", readme, re.S)
        self.assertIsNotNone(match)

        documented = set(re.findall(r"`([^`]+)`", match.group(1)))
        documented -= {
            "gemini-2.5-flash",
            "gemma-4-26b-a4b-it",
            "gemma-4-31b-it",
        }

        self.assertEqual(documented, set(MODEL_ALIASES))

    def test_readme_dangerous_tools_match_registry(self):
        from secops_agent.core.tools import registry
        from secops_agent.tools import crypto, exploit, forensics, network, recon, web

        # Importing the modules above populates the decorator-backed global registry.
        self.assertTrue((crypto, exploit, forensics, network, recon, web))

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        match = re.search(r"Dangerous actions such as (.*?) require approval", readme, re.S)
        self.assertIsNotNone(match)

        documented = set(re.findall(r"`([^`]+)`", match.group(1)))
        actual = {tool.name for tool in registry.list_tools() if getattr(tool, "dangerous", False)}

        self.assertEqual(documented, actual)

    def test_command_surfaces_do_not_recommend_secondary_slash_commands(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        runtime = RuntimeState()
        artifact = runtime.add_artifact("nmap_scan result", "tool-result", "PORT 22/tcp open ssh", source="nmap_scan")
        self.assertIsNotNone(artifact)
        task = runtime.add_task("side question", "running", "example", kind="side-agent", query="check status")

        renderer.render_artifacts(runtime, artifact.id)
        renderer._render_tasks_static(runtime)
        renderer.render_task_detail(task)
        output = renderer.console.export_text()

        self.assertNotIn("Use /", output)
        self.assertNotIn("/artifact list", output)
        self.assertNotIn("/task <id>", output)
        self.assertNotIn(f"/task {task.id}", output)
        self.assertNotIn("/cancel <id>", output)

    def test_statusline_fits_by_dropping_whole_segments(self):
        fitted = _fit_segments(
            ["Gemini 2.5 Flash", "idle", "no sandbox", "perm default", "0 tasks"],
            36,
        )

        self.assertLessEqual(len(fitted), 36)
        self.assertNotIn("0 task…", fitted)
        self.assertFalse(fitted.endswith("tas"))

    def test_terminal_key_parser_handles_touchpad_scroll_without_escape(self):
        self.assertEqual(terminal_key_from_sequence(b"\x1b[A"), "up")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[B"), "down")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[<64;20;10M"), "mouse_up")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[<65;20;10M"), "mouse_down")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[1;5H"), "home")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[1;5F"), "end")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[1;2A"), "pgup")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[1;2B"), "pgdn")
        self.assertEqual(terminal_key_from_sequence(b"\x1b[999~"), "ignore")

    def test_log_overlay_controls_do_not_advertise_hidden_aliases(self):
        self.assertIn("home/end", LOG_OVERLAY_CONTROLS)
        self.assertIn("esc Close", LOG_OVERLAY_CONTROLS)
        self.assertNotIn("g/G", LOG_OVERLAY_CONTROLS)
        self.assertNotIn("esc/q", LOG_OVERLAY_CONTROLS)

    def test_inline_panels_do_not_keep_hidden_navigation_aliases(self):
        repo = Path(__file__).resolve().parents[1]
        renderer_source = (repo / "secops_agent" / "ui" / "renderer.py").read_text(encoding="utf-8")
        overlay_source = (repo / "secops_agent" / "ui" / "overlay.py").read_text(encoding="utf-8")
        panel_source = (repo / "secops_agent" / "ui" / "panel.py").read_text(encoding="utf-8")
        combined = "\n".join((renderer_source, overlay_source, panel_source))

        self.assertNotIn('key.lower() == "j"', combined)
        self.assertNotIn('key.lower() == "q"', combined)
        self.assertNotIn('key.lower() in {"h", "k"}', combined)
        self.assertNotIn('key.lower() == "l"', combined)
        self.assertIn('if key == "tab":\n                    return "right"', renderer_source)

    def test_clipboard_file_path_can_be_converted_to_attach_command(self):
        with tempfile.NamedTemporaryFile() as tmp:
            command = _clipboard_attachment_command(tmp.name)

        self.assertTrue(command.startswith("/attach "))
        self.assertIn("tmp", command)
        self.assertEqual(_clipboard_attachment_command("not-a-real-path"), "")
        self.assertEqual(_clipboard_attachment_command("/tmp/a\n/tmp/b"), "")

    def test_clipboard_uri_list_can_be_converted_to_attach_command(self):
        with tempfile.NamedTemporaryFile() as tmp:
            command = attachment_command_from_clipboard_text(
                f"# copied file\nfile://{tmp.name}\n",
                allow_uri_list=True,
            )

        self.assertTrue(command.startswith("/attach "))

    def test_system_clipboard_image_can_create_attach_command(self):
        def fake_which(name: str) -> str | None:
            return f"/usr/bin/{name}" if name == "wl-paste" else None

        def fake_runner(args, stdout=None, stderr=None, timeout=None):
            if args == ["wl-paste", "--type", "text/uri-list"]:
                return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")
            if args == ["wl-paste", "--no-newline"]:
                return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
            if args == ["wl-paste", "--list-types"]:
                return subprocess.CompletedProcess(args, 0, stdout=b"text/plain\nimage/png\n", stderr=b"")
            if args == ["wl-paste", "--type", "image/png"]:
                return subprocess.CompletedProcess(args, 0, stdout=b"\x89PNG\r\n\x1a\n", stderr=b"")
            return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as tmpdir:
            command = system_clipboard_attach_command(
                cache_dir=Path(tmpdir),
                runner=fake_runner,
                which=fake_which,
            )
            attached_path = Path(shlex.split(command)[1])

        self.assertTrue(command.startswith("/attach "))
        self.assertIn("clipboard image", command)
        self.assertEqual(attached_path.suffix, ".png")

    def test_external_editor_helper_uses_configured_editor(self):
        original = os.environ.get("SECOPS_EDITOR")
        os.environ["SECOPS_EDITOR"] = (
            f"{sys.executable} -c "
            "\"import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('edited prompt', encoding='utf-8')\""
        )
        try:
            edited, error = _edit_text_in_external_editor("original prompt")
        finally:
            if original is None:
                os.environ.pop("SECOPS_EDITOR", None)
            else:
                os.environ["SECOPS_EDITOR"] = original

        self.assertEqual(error, "")
        self.assertEqual(edited, "edited prompt")

    def test_completion_more_text_matches_antigravity_palette_hint(self):
        self.assertEqual(SLASH_COMPLETION_VISIBLE_ROWS, 5)
        self.assertEqual(_completion_more_text(24), "↓ 19 more")
        self.assertEqual(_completion_more_text(5), "")

    def test_slash_completion_refreshes_after_deletion(self):
        calls: list[str] = []

        class Buffer:
            document = SimpleNamespace(text_before_cursor="/per")

            def start_completion(self, select_first=False):
                calls.append(f"start:{select_first}")

            def cancel_completion(self):
                calls.append("cancel")

        _refresh_slash_completion_after_edit(Buffer())

        self.assertEqual(calls, ["start:False"])

    def test_non_slash_completion_cancels_after_deletion(self):
        calls: list[str] = []

        class Buffer:
            document = SimpleNamespace(text_before_cursor="per")

            def start_completion(self, select_first=False):
                calls.append(f"start:{select_first}")

            def cancel_completion(self):
                calls.append("cancel")

        _refresh_slash_completion_after_edit(Buffer())

        self.assertEqual(calls, ["cancel"])

    def test_argument_completion_enter_submits_when_text_is_already_complete(self):
        completion = PTCompletion("gemma", start_position=-len("gemma"))

        self.assertTrue(_completion_preserves_text(Document("/model gemma"), completion))

    def test_argument_completion_enter_submits_exact_argument_even_if_not_selected(self):
        completions = [
            PTCompletion("gemini", start_position=-len("gemma")),
            PTCompletion("gemma", start_position=-len("gemma")),
        ]

        self.assertTrue(_completion_matches_current_argument(Document("/model gemma"), completions))

    def test_completion_menu_uses_literal_active_cursor(self):
        completion = PTCompletion(
            "/help",
            display="/help                        Show slash command reference",
        )

        active = "".join(text for _, text in _agy_menu_item_fragments(completion, True, 80, True))
        inactive = "".join(text for _, text in _agy_menu_item_fragments(completion, False, 80, True))

        self.assertTrue(active.startswith("> /help"))
        self.assertTrue(inactive.startswith("  /help"))

    def test_prompt_separator_avoids_terminal_edge_wrap(self):
        self.assertEqual(_prompt_separator(1), "─")
        self.assertEqual(len(_prompt_separator(100)), 99)

    def test_footer_parts_fit_after_terminal_resize(self):
        left, spaces, right = _footer_parts("? for shortcuts", "Gemma 4 26B", 18)

        self.assertLessEqual(len(left + spaces + right), 17)
        self.assertIn("?", left)

    def test_overlay_lines_do_not_fill_terminal_edge(self):
        lines = build_choice_overlay_lines(
            "Switch Model",
            [OverlayChoice("gemma", "Gemma 4 26B (Off)")],
            selected=0,
            width=30,
            height=10,
        )

        self.assertTrue(all(len(line) <= 29 for line in lines))

    def test_help_tools_and_panel_lines_do_not_fill_terminal_edge(self):
        help_lines = build_help_view_lines({}, "shortcuts", width=44, height=12)
        tools_lines = build_tools_view_lines([], "all", width=44, height=12)
        panel_lines = build_panel_lines("Panel", [], width=44, height=10, empty_message="Empty")

        for lines in (help_lines, tools_lines, panel_lines):
            self.assertTrue(all(len(line) <= 43 for line in lines))

    def test_startup_banner_has_no_outer_blank_lines(self):
        banner = get_header_banner(DEFAULT_MODEL)

        self.assertFalse(banner.startswith("\n"))
        self.assertFalse(banner.endswith("\n"))
        self.assertIn("███████╗███████╗", banner)
        self.assertIn(f"SecOps CLI {__version__}", banner)
        self.assertIn("Pentest agent", banner)
        self.assertNotIn("@", banner)
        self.assertRegex(COLORS["accent"], r"^#[0-9a-fA-F]{6}$")  # a valid theme accent (palette-agnostic)

    def test_startup_does_not_emit_clear_screen_spacing(self):
        self.assertEqual(STARTUP_CLEAR_SEQUENCE, "")

    def test_startup_prints_one_blank_line_after_banner(self):
        from rich.text import Text

        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        console.print()
        console.print(Text.from_ansi(get_header_banner(DEFAULT_MODEL)))
        console.print()
        output = console.export_text()
        lines = output.splitlines()
        logo_line_index = next(index for index, line in enumerate(lines) if "╚══════╝╚══════╝" in line)

        self.assertEqual(lines[logo_line_index + 1], "")

    def test_header_banner_helper_does_not_expose_ansi_escape_codes(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        _render_header_banner(renderer, DEFAULT_MODEL)
        output = renderer.console.export_text()

        self.assertIn("███████╗███████╗", output)
        self.assertIn(f"SecOps CLI {__version__}", output)
        self.assertNotIn("[1;38;2;", output)
        self.assertNotRegex(output, r"\[(?:\d+;)*\d+m")

    def test_prompt_does_not_reserve_blank_completion_space(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            handler = InputHandler()

        self.assertEqual(COMPLETION_MENU_RESERVED_ROWS, 0)
        self.assertEqual(handler.session.reserve_space_for_menu, 0)

    def test_statusline_surfaces_autonomy_posture_and_phase(self):
        # G4 / P1-4: at a wide terminal, the statusline shows the active autonomy
        # posture and the current mission phase.
        handler = InputHandler.__new__(InputHandler)
        handler._model_name = DEFAULT_MODEL
        handler._statusline = {
            "state": "idle",
            "autonomy": "supervisé",
            "phase": "reconnaissance",
        }
        line = handler._build_statusline(width=200)
        self.assertIn("supervisé", line)
        self.assertIn("reconnaissance", line)

    def test_default_footer_keeps_operational_context_visible(self):
        handler = InputHandler.__new__(InputHandler)
        handler.session = SimpleNamespace(
            default_buffer=SimpleNamespace(complete_state=None)
        )
        handler._model_name = DEFAULT_MODEL
        handler._statusline = {"state": "thinking", "tasks": 2, "tokens": 1234}

        footer_text = "".join(text for _, text in handler._get_toolbar())

        self.assertIn("Gemini 2.5 Flash", footer_text)
        self.assertIn("thinking", footer_text)
        self.assertIn("2 tasks", footer_text)
        self.assertIn("no sandbox", footer_text)

    def test_prompt_frame_stays_stable_after_commands(self):
        handler = InputHandler.__new__(InputHandler)
        handler.session = SimpleNamespace(
            default_buffer=SimpleNamespace(complete_state=None)
        )
        handler._model_name = DEFAULT_MODEL

        prompt_text = "".join(text for _, text in handler._prompt_fragments())
        toolbar_text = "".join(text for _, text in handler._get_toolbar())

        self.assertIn("─", prompt_text)
        self.assertIn("> ", prompt_text)
        self.assertIn("idle", toolbar_text)
        self.assertIn("Gemini 2.5 Flash", toolbar_text)

    def test_prompt_toolbar_shows_completion_overflow_inline(self):
        handler = InputHandler.__new__(InputHandler)
        handler.session = SimpleNamespace(
            default_buffer=SimpleNamespace(
                document=SimpleNamespace(text_before_cursor="/"),
                complete_state=SimpleNamespace(
                    completions=[
                        PTCompletion(f"/cmd-{index}", display=f"/cmd-{index:<42} Description {index}")
                        for index in range(9)
                    ],
                    complete_index=None,
                )
            )
        )
        handler._model_name = DEFAULT_MODEL

        toolbar_text = "".join(text for _, text in handler._get_toolbar())

        self.assertIn("> /cmd-0", toolbar_text)
        self.assertIn("  /cmd-1", toolbar_text)
        self.assertIn("↓ 4 more", toolbar_text)
        self.assertIn("↑/↓ Navigate", toolbar_text)
        self.assertIn("esc to cancel", toolbar_text)
        self.assertNotIn("? for shortcuts", toolbar_text)

    def test_prompt_toolbar_shows_completion_overflow_above_and_below(self):
        handler = InputHandler.__new__(InputHandler)
        handler.session = SimpleNamespace(
            default_buffer=SimpleNamespace(
                document=SimpleNamespace(text_before_cursor="/"),
                complete_state=SimpleNamespace(
                    completions=[
                        PTCompletion(f"/cmd-{index}", display=f"/cmd-{index:<42} Description {index}")
                        for index in range(12)
                    ],
                    complete_index=6,
                )
            )
        )
        handler._model_name = DEFAULT_MODEL

        toolbar_text = "".join(text for _, text in handler._get_toolbar())

        self.assertIn("↑ 2 more", toolbar_text)
        self.assertIn("> /cmd-6", toolbar_text)
        self.assertIn("↓ 5 more", toolbar_text)

    def test_prompt_toolbar_styles_disable_reverse_blocks(self):
        styles = pt_style_dict()

        for key in ("bottom-toolbar", "toolbar_left", "toolbar_right", "toolbar_spaces"):
            self.assertIn("noinherit", styles[key])
            self.assertIn("noreverse", styles[key])

    def test_model_overlay_lines_match_antigravity_picker_shape(self):
        choices = _model_choices(selectable_models(), DEFAULT_MODEL)
        lines = build_choice_overlay_lines(
            "Switch Model",
            choices,
            selected=0,
            width=88,
            height=18,
            current_marker_column=29,
            visible_items=5,
        )
        rendered = "\n".join(lines)

        self.assertIn("Switch Model", rendered)
        self.assertNotIn("  Auto", rendered)
        self.assertRegex(rendered, r"> Gemini 2\.5 Flash\s{4,}\(current\)")

        labels = [c.label for c in choices]
        self.assertIn("Gemma 4 26B A4B IT (Off)", labels)
        self.assertIn("Gemma 4 26B A4B IT (High)", labels)
        self.assertIn("Gemma 4 31B IT (Off)", labels)
        self.assertIn("Gemma 4 31B IT (High)", labels)

        self.assertNotIn("Gemini 2.5 Flash   (current)\n\n  Gemma 4 26B A4B IT", rendered)
        self.assertNotIn("Gemma 4 26B A4B IT (Low)", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Select  esc Go Back", rendered)
        visible_choice_lines = [
            line for line in lines
            if line.startswith(("> ", "  "))
            and not _is_choice_more_indicator(line)
            and "Keyboard:" not in line
            and line.strip()
        ]
        self.assertEqual(len(visible_choice_lines), 5)
        self.assertIn("↓ 7 more", rendered)

    def test_model_overlay_scroll_indicators_wrap_visible_choices(self):
        choices = _model_choices(selectable_models(), DEFAULT_MODEL)
        lines = build_choice_overlay_lines(
            "Switch Model",
            choices,
            selected=6,
            width=88,
            height=18,
            current_marker_column=29,
            visible_items=5,
        )

        first_choice_index = next(index for index, line in enumerate(lines) if "Gemini 3.1 Pro Preview" in line)
        selected_index = next(index for index, line in enumerate(lines) if "> Gemini 3 Flash Preview" in line)
        up_index = lines.index("  ↑ 4 more")
        down_index = lines.index("  ↓ 3 more")
        footer_index = next(index for index, line in enumerate(lines) if line.startswith("Keyboard:"))

        self.assertLess(up_index, first_choice_index)
        self.assertLess(selected_index, down_index)
        self.assertLess(down_index, footer_index)
        visible_choice_lines = [
            line for line in lines
            if line.startswith(("> ", "  "))
            and not _is_choice_more_indicator(line)
            and "Keyboard:" not in line
            and line.strip()
        ]
        self.assertEqual(len(visible_choice_lines), 5)

    def test_choice_overlay_more_indicators_render_accent_bold(self):
        choices = [
            OverlayChoice(f"model-{index}", f"Model {index}", current=index == 3)
            for index in range(7)
        ]
        stream = io.StringIO()
        fake_stdin = SimpleNamespace(isatty=lambda: True, fileno=lambda: 0)

        with patch("sys.stdin", fake_stdin), patch("sys.stdout", stream), patch(
            "secops_agent.ui.overlay.read_terminal_key",
            return_value="esc",
        ), patch("secops_agent.ui.overlay.termios.tcgetattr", return_value=[]), patch(
            "secops_agent.ui.overlay.termios.tcsetattr",
        ), patch("secops_agent.ui.overlay.tty.setraw"), patch(
            "secops_agent.ui.overlay.shutil.get_terminal_size",
            return_value=os.terminal_size((88, 18)),
        ):
            self.assertIsNone(choose_overlay("Switch Model", choices, visible_items=5))

        output = stream.getvalue()
        self.assertIn(f"{ansi('accent_bright', bold=True)}  ↑ 1 more", output)
        self.assertIn(f"{ansi('accent_bright', bold=True)}  ↓ 1 more", output)

    def test_model_overlay_marks_only_matching_thinking_preset_current(self):
        choices = _model_choices(selectable_models(), GEMMA_FAST_MODEL, current_thinking="high")

        current = [choice for choice in choices if choice.current]

        self.assertEqual(len(current), 1)
        self.assertEqual(current[0].value, "gemma-high")

    def test_model_overlay_marks_auto_current_when_routing_enabled(self):
        choices = _model_choices(selectable_models(), GEMMA_FAST_MODEL, auto_routing=True)
        current = [choice for choice in choices if choice.current]

        self.assertFalse(any(choice.value == "auto" for choice in choices))
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0].value, "gemma")

    def test_permissions_overlay_matches_antigravity_active_permissions_shape(self):
        lines = build_choice_overlay_lines(
            "Active Permissions",
            _permission_choices("always-proceed"),
            selected=3,
            width=100,
            height=18,
            footer="Keyboard: ↑/↓ Navigate  enter Select  esc Close",
            show_descriptions=True,
        )
        rendered = "\n".join(lines)

        self.assertIn("Active Permissions", rendered)
        self.assertIn("  request-review", rendered)
        self.assertIn("Prompt for write, bash, and web tools", rendered)
        self.assertIn("> always-proceed", rendered)
        self.assertIn("(current)  Auto-approve all tools", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Select  esc Close", rendered)

    def test_render_permissions_uses_active_permissions_fallback_shape(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_permissions([], current_mode="proceed-in-sandbox")
        output = renderer.console.export_text()

        self.assertIn("Active Permissions", output)
        self.assertIn("request-review", output)
        self.assertIn("> proceed-in-sandbox", output)
        self.assertIn("(current)  Auto-approve terminal commands in sandbox", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Select  esc Close", output)
        self.assertNotIn("Policy", output)
        self.assertNotIn("Ask default", output)

    def test_settings_view_matches_antigravity_settings_shape(self):
        lines = build_settings_view_lines(
            [
                SettingsItem("Response Profile", "standard", "Fast profile lowers loop count"),
                SettingsItem("Model", "Gemini 2.5 Flash", "Active model profile"),
                SettingsItem("Tool Permission", "request-review", "Approval mode for tools"),
                SettingsItem("Sandbox Mode", "off", "Session command guard"),
            ],
            selected=2,
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("Settings", rendered)
        self.assertIn("  Search:", rendered)
        self.assertIn("────────────────────", rendered)
        self.assertIn("> Tool Permission", rendered)
        self.assertIn("request-review", rendered)
        self.assertIn("  Approval mode for tools", rendered)
        self.assertIn("↑/↓ Navigate · enter Edit · Esc Clear Search/Exit", rendered)

    def test_settings_view_filters_search_text(self):
        lines = build_settings_view_lines(
            [
                SettingsItem("Response Profile", "standard", "Fast profile lowers loop count"),
                SettingsItem("Model", "Gemini 2.5 Flash", "Active model profile"),
                SettingsItem("Tool Permission", "request-review", "Approval mode for tools"),
                SettingsItem("Sandbox Mode", "off", "Session command guard"),
            ],
            search_query="gemi",
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("Search: gemi", rendered)
        self.assertIn("> Model", rendered)
        self.assertIn("Gemini 2.5 Flash", rendered)
        self.assertNotIn("Tool Permission", rendered)

    def test_settings_view_renders_inline_edit_options(self):
        lines = build_settings_view_lines(
            [
                SettingsItem("Response Profile", "standard", "Fast profile lowers loop count", editable=True, options=("standard", "fast")),
                SettingsItem("Sandbox Mode", "off", "Session command guard", editable=True, options=("on", "off")),
            ],
            selected=1,
            editing_index=1,
            edit_selected=1,
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("  Sandbox Mode", rendered)
        self.assertIn("    on", rendered)
        self.assertIn("  > off (current)", rendered)
        self.assertIn("↑/↓ Navigate · enter Select", rendered)
        self.assertNotIn("enter Edit", rendered)

    def test_settings_view_empty_search_result_is_explicit(self):
        lines = build_settings_view_lines(
            [SettingsItem("Model", "Gemini 2.5 Flash", "Active model profile")],
            search_query="zzzz",
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("Search: zzzz", rendered)
        self.assertIn("No settings match.", rendered)
        self.assertNotIn("> Model", rendered)

    def test_settings_view_search_accepts_navigation_alias_letters(self):
        lines = build_settings_view_lines(
            [
                SettingsItem("API Key", "configured", "Project key source"),
                SettingsItem("Model", "Gemini 2.5 Flash", "Active model profile"),
            ],
            search_query="key",
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("Search: key", rendered)
        self.assertIn("> API Key", rendered)
        self.assertNotIn("> Model", rendered)

    def test_config_renders_real_settings_surface(self):
        runtime = RuntimeState()
        runtime.permission_mode = "request-review"
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_config("gemini-2.5-flash", 120, 8192, "secops_agent.log", runtime)
        output = renderer.console.export_text()

        self.assertIn("Settings", output)
        self.assertIn("Search:", output)
        self.assertIn("Tool Permission", output)
        self.assertIn("request-review", output)
        self.assertIn("Sandbox Mode", output)
        self.assertIn("enter Edit", output)
        self.assertIn("Esc Clear Search/Exit", output)
        self.assertNotIn("Configuration", output)

    def test_context_usage_view_matches_antigravity_budget_shape(self):
        lines = build_context_usage_lines(
            "gemini-2.5-flash",
            total_messages=4,
            user_messages=1,
            assistant_messages=2,
            tool_messages=1,
            estimated_tokens=4000,
            tools_count=28,
            width=120,
        )
        rendered = "\n".join(lines)

        self.assertIn("└ Context Usage", rendered)
        self.assertIn("Gemini 2.5 Flash", rendered)
        self.assertIn("4.0k/1.0M tokens", rendered)
        self.assertIn("Estimated usage", rendered)
        self.assertIn("◉ User messages:", rendered)
        self.assertIn("◉ Agent responses:", rendered)
        self.assertIn("◉ Tool calls:", rendered)
        self.assertIn("□ Free space:", rendered)
        self.assertIn("Related: /artifact · /skills · /rewind", rendered)
        self.assertNotIn("tools loaded", rendered)
        self.assertNotIn("~1.0k tokens", rendered)

    def test_context_renders_budget_surface_not_static_table(self):
        renderer = Renderer()
        renderer.console = Console(width=120, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_context(
            "gemini-2.5-flash",
            total_messages=0,
            user_messages=0,
            assistant_messages=0,
            tool_messages=0,
            estimated_tokens=0,
            tools_count=28,
        )
        output = renderer.console.export_text()

        self.assertIn("└ Context Usage", output)
        self.assertIn("□ □ □", output)
        self.assertIn("0/1.0M tokens", output)
        self.assertIn("◉ User messages: 0 tokens", output)
        self.assertIn("Related:", output)
        self.assertNotIn("tools loaded", output)
        self.assertNotIn("Messages  0", output)

    def test_hooks_view_matches_antigravity_inline_shape(self):
        runtime = RuntimeState()
        lines = build_hooks_view_lines(runtime.hooks, selected=1, width=100)
        rendered = "\n".join(lines)

        self.assertIn(" Hooks", rendered)
        self.assertIn("3 hook types", rendered)
        self.assertIn("  PreToolUse", rendered)
        self.assertIn("> PostToolUse", rendered)
        self.assertIn("Before tool execution", rendered)
        self.assertIn("After tool execution", rendered)
        self.assertIn("OnError", rendered)
        self.assertNotIn("No hooks configured", rendered)
        self.assertIn("↑/↓ Navigate · enter Select", rendered)
        self.assertNotIn("Related:", rendered)
        self.assertNotIn("/hooks reload", rendered)

    def test_hooks_render_inline_surface_without_static_overlay(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_hooks(RuntimeState().hooks)
        output = renderer.console.export_text()

        self.assertIn(" Hooks", output)
        self.assertIn("PreToolUse", output)
        self.assertNotIn("No hooks configured", output)
        self.assertNotIn("────────────────", output)

    def test_mcp_view_matches_antigravity_inline_empty_shape(self):
        lines = build_mcp_view_lines(MCPConfigState(), MCPRuntime(), selected=1, width=110, height=22)
        rendered = "\n".join(lines)

        self.assertIn("MCP Servers", rendered)
        self.assertIn("> Workspace (.agents/mcp_config.json)", rendered)
        self.assertIn("No MCP servers configured.", rendered)
        self.assertNotIn("Antigravity config", rendered)
        self.assertNotIn("Global config", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", rendered)

    def test_mcp_view_uses_real_server_state(self):
        state = MCPConfigState(
            servers=[
                MCPServerConfig(
                    name="evidence",
                    command="python",
                    args=["server.py"],
                    env={"TOKEN": "redacted"},
                    source="workspace",
                    path=Path.cwd() / ".agents" / "mcp_config.json",
                ),
                MCPServerConfig(
                    name="disabled-feed",
                    command="node",
                    disabled=True,
                    source="global",
                    path=Path.home() / ".gemini" / "config" / "mcp_config.json",
                ),
            ],
        )
        lines = build_mcp_view_lines(state, MCPRuntime(), selected=0, width=120, height=24)
        rendered = "\n".join(lines)

        self.assertIn("2 configured · 1 enabled · 0 running · 0 tools", rendered)
        self.assertIn("> evidence (configured)", rendered)
        self.assertIn("python server.py · 1 env · workspace · .agents/mcp_config.json", rendered)
        self.assertIn("disabled-feed (disabled)", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", rendered)

    def test_mcp_render_inline_surface_without_static_overlay(self):
        renderer = Renderer()
        renderer.console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_mcp(MCPConfigState(), MCPRuntime())
        output = renderer.console.export_text()

        self.assertIn("MCP Servers", output)
        self.assertIn("No MCP servers configured.", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", output)
        self.assertNotIn("/mcp start|stop", output)
        self.assertNotIn("────────────────", output)

    def test_skills_view_matches_antigravity_inline_empty_shape(self):
        lines = build_skills_view_lines([], selected=1, width=110, height=22)
        rendered = "\n".join(lines)

        self.assertIn("Skills", rendered)
        self.assertIn("> Workspace (.agents/skills)", rendered)
        self.assertIn("No workspace or global skills loaded.", rendered)
        self.assertNotIn("Antigravity skills", rendered)
        self.assertNotIn("Global skills", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", rendered)

    def test_skills_view_uses_loaded_skill_state(self):
        skills = [
            SkillDefinition(
                name="recon",
                title="Recon Playbook",
                source="workspace",
                path=Path.cwd() / ".agents" / "skills" / "recon.md",
                content="# Recon Playbook\n",
            ),
            SkillDefinition(
                name="reporting",
                title="Reporting",
                source="global",
                path=Path.home() / ".gemini" / "config" / "skills" / "reporting.md",
                content="# Reporting\n",
            ),
        ]
        lines = build_skills_view_lines(skills, selected=0, width=120, height=24)
        rendered = "\n".join(lines)

        self.assertIn("2 loaded · 1 workspace · 1 global", rendered)
        self.assertIn("> recon", rendered)
        self.assertIn("Recon Playbook · workspace · .agents/skills/recon.md", rendered)
        self.assertIn("reporting", rendered)
        self.assertIn("Reporting · global · ~/.gemini/config/skills/reporting.md", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", rendered)

    def test_skills_render_inline_surface_without_static_overlay(self):
        renderer = Renderer()
        renderer.console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_skills([])
        output = renderer.console.export_text()

        self.assertIn("Skills", output)
        self.assertIn("No workspace or global skills loaded.", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Actions", output)
        self.assertNotIn("/skills reload refreshes", output)
        self.assertNotIn("────────────────", output)

    def test_history_falls_back_to_memory_when_path_is_not_writable_dir(self):
        old_value = os.environ.get("SECOPS_HISTORY_DIR")
        with tempfile.NamedTemporaryFile() as tmp:
            os.environ["SECOPS_HISTORY_DIR"] = tmp.name
            history = _build_history()

        if old_value is None:
            os.environ.pop("SECOPS_HISTORY_DIR", None)
        else:
            os.environ["SECOPS_HISTORY_DIR"] = old_value

        self.assertIsInstance(history, InMemoryHistory)

    def test_overlay_truncates_long_labels_before_value(self):
        console = Console(width=60, record=True, force_terminal=False, file=io.StringIO())
        render_overlay(
            console,
            "Long Label Check",
            [OverlayRow("a very very long label that used to overflow", "running", "detail")],
        )

        output = console.export_text()
        self.assertIn("a very very long lab", output)
        self.assertIn("running", output)
        self.assertNotIn("overflowrunning", output)

    def test_statusline_renders_inspectable_fields(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()
        runtime.fast_mode = True
        runtime.sandbox_enabled = True
        runtime.agent_state = "tool"
        runtime.add_workspace_dir(Path("/tmp/secops-extra"))

        renderer.render_statusline("gemma-4-31b-it", 7, 12345, 29, runtime)
        output = renderer.console.export_text()

        self.assertIn("Statusline", output)
        self.assertIn("Prompt", output)
        self.assertIn("Model", output)
        self.assertIn("State", output)
        self.assertIn("Gemma 4 31B", output)
        self.assertNotIn("Shown in the prompt footer", output)

    def test_renderer_echoes_user_input_once(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_user_input("comment mettre à jour ubuntu?")
        output = renderer.console.export_text()

        self.assertIn("> comment mettre à jour ubuntu?", output)
        self.assertEqual(output.count("> comment mettre à jour ubuntu?"), 1)
        self.assertIn("────────────────", output)
        self.assertLess(output.index("────────────────"), output.index("> comment mettre à jour ubuntu?"))

    def test_renderer_highlights_user_input_text_with_accent_color(self):
        renderer = Renderer()
        renderer.console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            theme=rich_theme,
            file=io.StringIO(),
        )

        renderer.render_user_input("/statusline")
        html = renderer.console.export_html(inline_styles=True)

        self.assertIn(COLORS["accent_bright"].lower(), html.lower())
        self.assertIn("font-weight: bold", html)

    def test_renderer_can_echo_command_without_trailing_blank(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_user_input("/agents", trailing_blank=False, separator=False)
        renderer.render_status("Exited /agents command")
        output = renderer.console.export_text()

        self.assertIn("> /agents\n  ⎿  Exited /agents command", output)
        self.assertIn("> /agents\n  ⎿  Exited /agents command\n\n", output)
        self.assertNotIn("> /agents\n\n  ⎿", output)
        self.assertNotIn("────────────────", output)

    def test_renderer_replays_loaded_session_transcript(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())
        memory = ConversationMemory()
        memory.add_user_message("bonjour\n\n[SecOps attached evidence]\ninternal model-only context")
        memory.add_assistant_message("Bonjour, je reprends la session.")
        memory.add_assistant_message(
            "",
            tool_calls=[{"name": "run_shell", "arguments": {"command": "date"}, "id": "call_1"}],
        )
        memory.add_tool_result("run_shell", "Sun Jun  4 10:00:00 GMT 2026\n[Exit Code: 0]")

        renderer.render_session_transcript(memory)
        output = renderer.console.export_text()

        self.assertIn("> bonjour", output)
        self.assertIn("Bonjour, je reprends la session.", output)
        self.assertIn("● Bash(date)", output)
        self.assertIn("Sun Jun", output)
        self.assertNotIn("TOOL DATA", output)
        self.assertNotIn("internal model-only context", output)

    def test_renderer_echoes_agent_prompt_with_antigravity_gap_before_thought(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Greeting")
            yield TextEvent("Bonjour.")
            yield TextEvent("", done=True)

        renderer.render_user_input("bonjour", trailing_blank=False)
        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("> bonjour\n\n▸ Thought", output)
        self.assertNotIn("> bonjour\n\n\n▸ Thought", output)

    def test_renderer_can_reprint_empty_prompt_frame_for_inline_help(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_empty_prompt_frame()
        output = renderer.console.export_text()

        self.assertIn(">\n", output)
        separator_lines = [line for line in output.splitlines() if line.startswith("─")]
        self.assertEqual(len(separator_lines), 2)

    def test_command_error_uses_compact_result_marker(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_error("Usage: /permissions [allow|ask|deny|clear] <resource>")
        output = renderer.console.export_text()

        self.assertIn("⎿  Usage: /permissions", output)
        self.assertIn("Check the command syntax with /help.", output)
        self.assertNotIn("✗", output)

    def test_agent_error_event_uses_same_compact_error_style(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Thinking...")
            yield ErrorEvent("Gemini API Error: quota exceeded")

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("Thought for", output)
        self.assertIn("⚠ Gemini API Error: quota exceeded", output)
        self.assertNotIn("⎿  Gemini API Error: quota exceeded", output)
        self.assertNotIn("✗ Gemini API Error", output)

    def test_suggested_actions_event_renders_compact_proposal_block(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield SuggestedActionsEvent(actions=[
                SimpleNamespace(
                    title="Analyze HTTP headers on http://10.129.153.73",
                    tool_name="http_headers",
                    arguments={"url": "http://10.129.153.73"},
                    risk="low",
                )
            ])

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("Suggested next actions:", output)
        self.assertIn("1. Analyze HTTP headers on http://10.129.153.73", output)
        self.assertIn("http_headers", output)
        self.assertIn("Reply with a number or describe what to do next.", output)

    def test_agent_quota_error_is_compacted_like_antigravity(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Thinking...")
            yield ErrorEvent("Gemini API Error: 429 RESOURCE_EXHAUSTED. {'error': {'message': 'Quota exceeded', 'details': [{'x': 'y'}]}}")

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("Our servers are experiencing high traffic right now", output)
        self.assertNotIn("RESOURCE_EXHAUSTED", output)
        self.assertNotIn("{'error'", output)

    def test_interruptible_agent_events_stop_on_escape_signal(self):
        from secops_agent.ui.renderer import _AgentStreamInterrupted, _EscInterruptMonitor, _interruptible_events

        async def events():
            await asyncio.sleep(60)
            yield TextEvent("late")

        async def collect():
            interrupt = _EscInterruptMonitor()
            interrupt.event.set()
            with self.assertRaises(_AgentStreamInterrupted):
                async for _ in _interruptible_events(events(), interrupt):
                    pass

        asyncio.run(collect())

    def test_interruptible_agent_events_emit_ctrl_o_transcript_request(self):
        from secops_agent.ui.renderer import _EscInterruptMonitor, _TranscriptToggleRequest, _interruptible_events

        async def events():
            await asyncio.sleep(0.01)
            yield TextEvent("late")

        async def collect():
            interrupt = _EscInterruptMonitor()
            interrupt.expand_event.set()
            collected = []
            async for event in _interruptible_events(events(), interrupt):
                collected.append(event)
            return collected

        collected = asyncio.run(collect())

        self.assertIsInstance(collected[0], _TranscriptToggleRequest)
        self.assertEqual(collected[1].content, "late")

    def test_help_renders_antigravity_overlay_shape(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_help()
        output = renderer.console.export_text()

        self.assertIn("SecOps CLI", output)
        self.assertIn("[General]", output)
        self.assertIn("Commands", output)
        self.assertIn("Shortcuts", output)
        self.assertIn("────────────────", output)
        self.assertIn("←/→ Switch View", output)

    def test_help_general_version_matches_startup_version(self):
        lines = build_help_view_lines({}, "general", width=88, height=22)
        rendered = "\n".join(lines)

        self.assertIn(f"Version {__version__}", rendered)
        self.assertNotIn("Version 0.1.0", rendered)

    def test_help_view_lines_switch_to_commands(self):
        groups = {
            "Core": [SimpleNamespace(display_name="/help", description="Show help", implemented=True)],
            "Configuration": [
                SimpleNamespace(display_name="/model", description="Switch the active model", implemented=True)
            ],
        }

        lines = build_help_view_lines(groups, "commands", width=88, height=14, selected_item=1)
        rendered = "\n".join(lines)

        self.assertIn("[Commands]", rendered)
        self.assertIn("Available Commands\n\n", rendered)
        self.assertIn("  /help", rendered)
        self.assertIn("> /model", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  ←/→ Switch View  esc Close", rendered)

    def test_help_row_split_keeps_shortcut_description_separate(self):
        row = _split_help_row("  alt+j                           Manage subagent")

        self.assertIsNotNone(row)
        marker, label, spacing, description = row
        self.assertEqual(marker, "  ")
        self.assertEqual(label, "alt+j")
        self.assertGreaterEqual(len(spacing), 2)
        self.assertEqual(description, "Manage subagent")

    def test_help_shortcut_color_rule_only_matches_shortcuts_tab_items(self):
        self.assertTrue(_is_shortcut_help_label(2, "alt+j"))
        self.assertFalse(_is_shortcut_help_label(0, "/"))
        self.assertFalse(_is_shortcut_help_label(1, "/model"))
        self.assertFalse(_is_shortcut_help_label(2, "/keybindings"))

    def test_help_view_lines_show_shortcuts(self):
        lines = build_help_view_lines({}, "shortcuts", width=88, height=34)
        rendered = "\n".join(lines)

        self.assertIn("[Shortcuts]", rendered)
        self.assertIn("Keyboard Shortcuts", rendered)
        self.assertIn("/keybindings", rendered)
        self.assertNotIn("to customize", rendered)
        self.assertIn("Open slash commands", rendered)
        self.assertNotIn("Allow once in a permission prompt", rendered)
        self.assertNotIn("ctrl+k", rendered)
        self.assertIn("[1-10 of", rendered)

        later_lines = build_help_view_lines({}, "shortcuts", selected_item=12, width=88, height=34)
        later_rendered = "\n".join(later_lines)
        self.assertIn("ctrl+g", later_rendered)
        self.assertIn("Toggle trajectory view", later_rendered)
        self.assertIn("> ctrl+r", later_rendered)
        deeper_lines = build_help_view_lines({}, "shortcuts", selected_item=15, width=88, height=34)
        self.assertIn("Yank (paste from kill ring)", "\n".join(deeper_lines))

    def test_help_view_lines_move_shortcut_selection(self):
        lines = build_help_view_lines({}, "shortcuts", selected_item=1, width=88, height=34)
        rendered = "\n".join(lines)

        self.assertIn("  /                               Open slash commands", rendered)
        self.assertIn("> \\ + enter", rendered)

    def test_tools_view_lines_use_tabs_and_navigation(self):
        tools = [
            SimpleNamespace(name="dns_lookup", description="Resolve DNS records", category="network", dangerous=False),
            SimpleNamespace(name="nmap_scan", description="Run an Nmap scan", category="network", dangerous=True),
            SimpleNamespace(name="hash_lookup", description="Inspect hash reputation", category="osint", dangerous=False),
        ]

        lines = build_tools_view_lines(tools, "network", selected_tool=1, width=88, height=14)
        rendered = "\n".join(lines)

        self.assertIn("SecOps Tools", rendered)
        self.assertIn("[network]", rendered)
        self.assertIn("Tools", rendered)
        self.assertIn("> nmap_scan", rendered)
        self.assertIn("dangerous", rendered)
        self.assertIn("←/→ Switch View", rendered)

    def test_trajectory_text_includes_messages_tools_and_artifacts(self):
        from secops_agent.core.memory import ConversationMemory

        memory = ConversationMemory()
        memory.add_user_message("scan 127.0.0.1")
        memory.add_assistant_message(
            "Running a scan.",
            tool_calls=[{"name": "nmap_scan", "arguments": {"target": "127.0.0.1"}}],
        )
        memory.add_tool_result("nmap_scan", "PORT 22/tcp open ssh\nPORT 80/tcp open http\n")
        runtime = RuntimeState()
        artifact = runtime.add_artifact("nmap_scan result", "tool-result", "PORT 22/tcp open ssh", source="nmap_scan")

        rendered = build_trajectory_text(memory, runtime)

        self.assertIsNotNone(artifact)
        self.assertIn("SecOps Trajectory", rendered)
        self.assertIn("01 User", rendered)
        self.assertIn("02 Agent", rendered)
        self.assertIn("Tool calls:", rendered)
        self.assertIn("03 Tool · nmap_scan", rendered)
        self.assertIn("a001 · tool-result · nmap_scan result", rendered)

    def test_empty_trajectory_uses_compact_overlay_instead_of_empty_pager(self):
        from unittest.mock import patch

        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())
        memory = ConversationMemory()
        runtime = RuntimeState()

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
            patch("secops_agent.ui.session_review.view_trajectory") as view_trajectory,
        ):
            renderer.render_trajectory(memory, runtime)

        view_trajectory.assert_not_called()
        output = renderer.console.export_text()
        self.assertIn("Trajectory", output)
        self.assertIn("No messages yet.", output)
        self.assertNotIn("Trace", output)
        self.assertNotIn("ctrl+o toggles latest transcript", output)
        self.assertNotIn("Line 1 -", output)

    def test_artifacts_view_matches_antigravity_empty_shape(self):
        runtime = RuntimeState()

        lines = build_artifacts_view_lines(runtime, width=110, height=20)
        rendered = "\n".join(lines)

        self.assertIn("Artifacts", rendered)
        self.assertIn("  No artifacts", rendered)
        self.assertNotIn("No artifacts yet.", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss", rendered)

    def test_artifacts_view_supports_preview_and_open_modes(self):
        runtime = RuntimeState()
        artifact = runtime.add_artifact(
            "nmap_scan result",
            "tool-result",
            "PORT 22/tcp open ssh\nPORT 80/tcp open http",
            source="nmap_scan",
        )

        self.assertIsNotNone(artifact)
        preview = "\n".join(build_artifacts_view_lines(runtime, selected=0, detail_mode="preview", width=110, height=24))
        opened = "\n".join(build_artifacts_view_lines(runtime, selected=0, detail_mode="open", width=110, height=24))

        self.assertIn("> a001   nmap_scan result", preview)
        self.assertIn("Preview: a001 · nmap_scan result", preview)
        self.assertIn("PORT 22/tcp open ssh", preview)
        self.assertIn("Open: a001 · nmap_scan result", opened)
        self.assertIn("Content:", opened)
        self.assertIn("PORT 80/tcp open http", opened)

    def test_artifacts_open_reads_truncated_tool_detail_from_spool(self):
        runtime = RuntimeState()
        with tempfile.TemporaryDirectory() as tmpdir:
            stdout_path = Path(tmpdir) / "stdout.log"
            stdout_path.write_text("complete artifact line\n", encoding="utf-8")
            artifact = runtime.add_artifact(
                "Bash(long) result",
                "tool-result",
                "[Output truncated in memory; full spool: /tmp/example]",
                source="run_shell",
                metadata={"stdout_path": str(stdout_path)},
            )

            self.assertIsNotNone(artifact)
            opened = "\n".join(
                build_artifacts_view_lines(runtime, selected=0, detail_mode="open", width=110, height=24)
            )
            artifact_text = build_artifact_text(artifact)

        self.assertIn("complete artifact line", opened)
        self.assertIn("complete artifact line", artifact_text)
        self.assertNotIn("Output truncated in memory", opened.split("Content:", 1)[1])

    def test_ctrl_o_prefers_latest_tool_result_artifact(self):
        runtime = RuntimeState()
        runtime.add_artifact("Assistant response", "response", "Long explanation", source="assistant")
        tool_artifact = runtime.add_artifact("nmap_scan result", "tool-result", "PORT 22/tcp open ssh", source="nmap_scan")
        runtime.add_artifact("Attachment: notes.txt", "attachment", "Evidence body", source="/attach")

        self.assertIs(_latest_expandable_artifact(runtime), tool_artifact)

    def test_tool_result_artifact_status_color_detects_text_failure(self):
        runtime = RuntimeState()
        artifact = runtime.add_artifact(
            "Bash(sleep 300) result",
            "tool-result",
            "❌ Command timed out after 300s and was stopped",
            source="run_shell",
        )

        self.assertIsNotNone(artifact)
        self.assertEqual(_artifact_status_color(artifact), COLORS["error"])

    def test_tool_result_artifact_status_color_detects_vpn_failure_text(self):
        runtime = RuntimeState()
        artifact = runtime.add_artifact(
            "ConnectVpnConfig(/home/administrator/Downloads/lab.ovpn) result",
            "tool-result",
            "VPN failed: /home/administrator/Downloads/lab.ovpn\nStatus: TLS handshake timed out.",
            source="connect_vpn_config",
        )

        self.assertIsNotNone(artifact)
        self.assertEqual(_artifact_status_color(artifact), COLORS["error"])

    def test_ctrl_o_expands_latest_tool_output_inline_for_non_tty_fallback(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two\n[Exit Code: 0]", source="run_shell")
        console = Console(width=42, record=True, force_terminal=False, file=io.StringIO())

        result = _show_ctrl_o_surface(None, runtime, console)
        output = console.export_text()

        self.assertEqual(result, "tool-output")
        self.assertIn("⎿  line one (ctrl+o to collapse)", output)
        self.assertIn("line one", output)
        self.assertIn("line two", output)
        self.assertIn("[Exit Code: 0]", output)
        self.assertNotIn("Trajectory", output)
        self.assertNotIn("● Bash(pwd)", output)

    def test_ctrl_o_expands_truncated_tool_output_from_spool_metadata(self):
        runtime = RuntimeState()
        with tempfile.TemporaryDirectory() as tmpdir:
            stdout_path = Path(tmpdir) / "stdout.log"
            stderr_path = Path(tmpdir) / "stderr.log"
            stdout_path.write_text("full line one\nfull line two\n", encoding="utf-8")
            stderr_path.write_text("warning detail\n", encoding="utf-8")
            runtime.add_artifact(
                "Bash(long) result",
                "tool-result",
                "[Output truncated in memory; full spool: /tmp/example]\n[Exit Code: 0]",
                source="run_shell",
                metadata={
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                },
            )
            console = Console(width=80, record=True, force_terminal=False, file=io.StringIO())

            result = _show_ctrl_o_surface(None, runtime, console)
            output = console.export_text()

        self.assertEqual(result, "tool-output")
        self.assertIn("full line one", output)
        self.assertIn("full line two", output)
        self.assertIn("[STDERR]", output)
        self.assertIn("warning detail", output)
        self.assertIn("[Exit Code: 0]", output)
        self.assertNotIn("Output truncated in memory", output)

    def test_ctrl_o_second_press_collapses_latest_tool_output(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two", source="run_shell")
        first_console = Console(width=42, record=True, force_terminal=False, file=io.StringIO())
        second_console = Console(width=42, record=True, force_terminal=False, file=io.StringIO())

        self.assertEqual(_show_ctrl_o_surface(None, runtime, first_console), "tool-output")
        self.assertEqual(_show_ctrl_o_surface(None, runtime, second_console), "tool-output-collapsed")
        output = second_console.export_text()

        self.assertNotIn("● Bash(pwd)", output)
        self.assertNotIn("ctrl+o to collapse", output)
        self.assertEqual(runtime.ctrl_o_expanded_artifact_id, "")
        self.assertEqual(runtime.ctrl_o_rendered_lines, 0)

    def test_ctrl_o_second_press_clears_previous_terminal_block(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two", source="run_shell")
        stream = io.StringIO()
        console = Console(width=42, force_terminal=True, color_system=None, file=stream)

        self.assertEqual(_show_ctrl_o_surface(None, runtime, console), "tool-output")
        self.assertEqual(_show_ctrl_o_surface(None, runtime, console), "tool-output-collapsed")
        output = stream.getvalue()

        self.assertIn("\x1b[1A\x1b[K", output)
        self.assertIn("ctrl+o to collapse", output)
        self.assertNotIn("ctrl+o to expand", output)

    def test_ctrl_o_tty_uses_tool_detail_surface_without_replaying_transcript(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two", source="run_shell")
        runtime.set_ctrl_o_anchor(
            ["● Bash(pwd) (ctrl+o to expand)", "  ⎿  2 lines (ctrl+o to expand)"],
            ["● Bash(pwd)", "  ⎿  line one (ctrl+o to collapse)", "", "  Output:", "    line one", "    line two"],
        )
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=42, force_terminal=True, color_system=None, file=stream)

        result = _show_ctrl_o_surface(memory, runtime, console)

        self.assertEqual(result, "tool-output")
        output = stream.getvalue()
        self.assertIn("⎿  line one (ctrl+o to collapse)", output)
        self.assertIn("\x1b[2M", output)
        self.assertIn("\x1b[6L", output)

    def test_ctrl_o_tty_with_anchor_rewrites_previous_tool_block_in_place(self):
        runtime = RuntimeState()
        runtime.set_ctrl_o_anchor(
            ["● Bash(ip addr show) (ctrl+o to expand)", "  ⎿  21 lines (ctrl+o to expand)"],
            ["● Bash(ip addr show)", "  ⎿  1: lo (ctrl+o to collapse)", "", "  Output:", "    1: lo", "    5: tun0"],
        )
        runtime.advance_ctrl_o_anchor_lines(8)
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=80, force_terminal=True, color_system=None, file=stream)

        result = _show_ctrl_o_surface(memory, runtime, console)
        output = stream.getvalue()

        self.assertEqual(result, "tool-output")
        self.assertIn("\x1b[10A", output)
        self.assertIn("\x1b[2M", output)
        self.assertIn("\x1b[6L", output)
        self.assertIn("\x1b[8B", output)
        self.assertIn("5: tun0", output)
        self.assertEqual(runtime.ctrl_o_anchor_rendered_lines, 6)
        self.assertTrue(runtime.ctrl_o_anchor_is_expanded)

    def test_ctrl_o_tty_rewrites_anchor_at_top_visible_line(self):
        runtime = RuntimeState()
        runtime.set_ctrl_o_anchor(
            ["● Bash(ip addr show) (ctrl+o to expand)", "  ⎿  21 lines (ctrl+o to expand)"],
            ["● Bash(ip addr show)", "  ⎿  1: lo (ctrl+o to collapse)", "", "  Output:", "    1: lo", "    5: tun0"],
        )
        runtime.advance_ctrl_o_anchor_lines(4)
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=80, force_terminal=True, color_system=None, file=stream)

        with patch(
            "secops_agent.ui.input_handler.shutil.get_terminal_size",
            return_value=os.terminal_size((80, 7)),
        ):
            result = _show_ctrl_o_surface(memory, runtime, console)

        output = stream.getvalue()
        self.assertEqual(result, "tool-output")
        self.assertIn("\x1b[6A", output)
        self.assertIn("\x1b[2M", output)
        self.assertIn("\x1b[6L", output)
        self.assertTrue(runtime.ctrl_o_anchor_is_expanded)
        self.assertEqual(runtime.ctrl_o_anchor_tail_lines, 4)

    def test_ctrl_o_collapse_stays_silent_when_expanded_anchor_is_too_tall(self):
        runtime = RuntimeState()
        collapsed_lines = [
            "● ConnectVpnConfig(/home/administrator/Downloads/lab.ovpn) (ctrl+o to expand)",
            "  ⎿  1m 3.8s · 27 lines · 1,731 chars (ctrl+o to expand)",
        ]
        expanded_lines = [
            "● ConnectVpnConfig(/home/administrator/Downloads/lab.ovpn)",
            "  ⎿  VPN failed: /home/administrator/Downloads/lab.ovpn (ctrl+o to collapse)",
            "",
            "  Output:",
            "    VPN failed: /home/administrator/Downloads/lab.ovpn",
            "    Status: TLS handshake timed out.",
            "    Recent log output:",
            "    2026-06-15 17:26:28 TLS Error: TLS handshake failed",
        ]
        runtime.set_ctrl_o_anchor(collapsed_lines, expanded_lines, tail_lines=5)
        runtime.ctrl_o_anchor_is_expanded = True
        runtime.ctrl_o_anchor_rendered_lines = len(expanded_lines)
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=80, force_terminal=True, color_system=None, file=stream)

        with patch(
            "secops_agent.ui.input_handler.shutil.get_terminal_size",
            return_value=os.terminal_size((80, 10)),
        ):
            result = _show_ctrl_o_surface(memory, runtime, console)

        output = stream.getvalue()
        self.assertEqual(result, "tool-output-unchanged")
        self.assertEqual(output, "")
        self.assertNotIn("Output:", output)
        self.assertTrue(runtime.ctrl_o_anchor_is_expanded)
        self.assertEqual(runtime.ctrl_o_anchor_rendered_lines, len(expanded_lines))
        self.assertEqual(runtime.ctrl_o_anchor_tail_lines, 5)

    def test_ctrl_o_transcript_toggle_stays_silent_when_rendered_surface_is_too_tall(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two", source="run_shell")
        runtime.ctrl_o_transcript_collapsed = (
            "● Bash(pwd) (ctrl+o to expand)\n"
            "  ⎿  2 lines (ctrl+o to expand)"
        )
        runtime.ctrl_o_transcript_expanded = (
            "● Bash(pwd)\n"
            "  ⎿  line one (ctrl+o to collapse)\n"
            "\n"
            "  Output:\n"
            "    line one\n"
            "    line two"
        )
        runtime.ctrl_o_transcript_is_expanded = True
        runtime.ctrl_o_transcript_rendered_lines = 30
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=88, force_terminal=True, color_system=None, file=stream)

        with patch(
            "secops_agent.ui.input_handler.shutil.get_terminal_size",
            return_value=os.terminal_size((88, 12)),
        ):
            result = _show_ctrl_o_surface(memory, runtime, console)

        self.assertEqual(result, "unchanged")
        self.assertEqual(stream.getvalue(), "")
        self.assertTrue(runtime.ctrl_o_transcript_is_expanded)
        self.assertEqual(runtime.ctrl_o_transcript_rendered_lines, 30)

    def test_ctrl_o_tty_with_memory_toggles_current_rendered_transcript(self):
        runtime = RuntimeState()
        runtime.add_artifact(
            "Bash(pwd) result",
            "tool-result",
            "/home/administrator/secops_v2\n[Exit Code: 0]",
            source="run_shell",
        )
        runtime.ctrl_o_transcript_collapsed = (
            "● Bash(pwd) (ctrl+o to expand)\n"
            "  ⎿  2 lines (ctrl+o to expand)"
        )
        runtime.ctrl_o_transcript_expanded = (
            "● Bash(pwd)\n"
            "  ⎿  /home/administrator/secops_v2 (ctrl+o to collapse)\n"
            "\n"
            "  Output:\n"
            "    /home/administrator/secops_v2\n"
            "    [Exit Code: 0]"
        )
        runtime.ctrl_o_transcript_rendered_lines = 2
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=88, force_terminal=True, color_system=None, file=stream)

        result = _show_ctrl_o_surface(memory, runtime, console)

        self.assertEqual(result, "transcript")
        self.assertIn("● Bash(pwd)", stream.getvalue())
        self.assertIn("ctrl+o to collapse", stream.getvalue())
        self.assertTrue(runtime.ctrl_o_transcript_is_expanded)
        self.assertEqual(runtime.ctrl_o_transcript_rendered_lines, 6)

    def test_ctrl_o_prompt_tail_is_applied_once_before_anchor_toggle(self):
        runtime = RuntimeState()
        runtime.set_ctrl_o_anchor(
            ["● Bash(ip addr show) (ctrl+o to expand)", "  ⎿  21 lines (ctrl+o to expand)"],
            ["● Bash(ip addr show)", "  ⎿  1: lo (ctrl+o to collapse)", "", "  Output:", "    1: lo", "    5: tun0"],
        )
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=80, force_terminal=True, color_system=None, file=stream)

        self.assertTrue(_apply_prompt_tail_to_ctrl_o_anchor(runtime, 4))
        self.assertFalse(_apply_prompt_tail_to_ctrl_o_anchor(runtime, 4))
        result = _show_ctrl_o_surface(memory, runtime, console)
        output = stream.getvalue()

        self.assertEqual(result, "tool-output")
        self.assertIn("\x1b[6A", output)
        self.assertIn("\x1b[2M", output)
        self.assertEqual(runtime.ctrl_o_anchor_tail_lines, 4)
        self.assertTrue(runtime.ctrl_o_anchor_prompt_tail_applied)

    def test_ctrl_o_tty_without_cached_transcript_does_not_expand_stale_tool(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(pwd) result", "tool-result", "line one\nline two", source="run_shell")
        memory = ConversationMemory()
        stream = io.StringIO()
        console = Console(width=42, force_terminal=True, color_system=None, file=stream)

        result = _show_ctrl_o_surface(memory, runtime, console)

        self.assertEqual(result, "none")
        self.assertEqual(stream.getvalue(), "")

    def test_ctrl_o_non_tty_without_cached_transcript_reports_no_current_tool(self):
        runtime = RuntimeState()
        runtime.add_artifact("Bash(ip addr show) result", "tool-result", "old output", source="run_shell")
        memory = ConversationMemory()
        console = Console(width=42, record=True, force_terminal=False, file=io.StringIO())

        result = _show_ctrl_o_surface(memory, runtime, console)
        output = console.export_text()

        self.assertEqual(result, "none")
        self.assertIn("Nothing to expand yet.", output)
        self.assertNotIn("old output", output)

    def test_runtime_new_artifact_resets_ctrl_o_surface_state(self):
        runtime = RuntimeState()
        runtime.ctrl_o_expanded_artifact_id = "a001"
        runtime.ctrl_o_rendered_lines = 6

        runtime.add_artifact("Bash(date) result", "tool-result", "Sun May 31", source="run_shell")

        self.assertEqual(runtime.ctrl_o_expanded_artifact_id, "")
        self.assertEqual(runtime.ctrl_o_rendered_lines, 0)

    def test_tool_call_plain_text_matches_antigravity_label(self):
        self.assertEqual(format_tool_call_text("run_shell", {"command": "pwd"}), "Bash(pwd)")
        self.assertEqual(format_tool_call_text("nmap_scan", {"target": "127.0.0.1"}), "Nmap(127.0.0.1)")
        self.assertEqual(
            format_tool_call_text(
                "connect_vpn_config",
                {"background": True, "config_path": "/home/user/Downloads/lab.ovpn"},
            ),
            "ConnectVpnConfig(/home/user/Downloads/lab.ovpn)",
        )

    def test_renderer_ctrl_o_inline_expands_running_tool(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        renderer._latest_tool_name = "run_shell"
        renderer._latest_tool_arguments = {"command": "pwd"}

        self.assertTrue(renderer._render_latest_transcript_expansion())
        output = renderer.console.export_text()

        self.assertIn("● Bash(pwd)", output)
        self.assertIn("ctrl+o to collapse", output)
        self.assertNotIn("⎿  Running", output)

    def test_renderer_ctrl_o_second_press_collapses_running_tool(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        renderer._latest_tool_name = "run_shell"
        renderer._latest_tool_arguments = {"command": "pwd"}

        self.assertTrue(renderer._toggle_latest_transcript())
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        self.assertTrue(renderer._toggle_latest_transcript())
        output = renderer.console.export_text()

        self.assertIn("● Bash(pwd) (ctrl+o to expand) R5", output)
        self.assertNotIn("R0", output)
        self.assertNotIn("ctrl+o to collapse", output)

    def test_renderer_ctrl_o_bounds_long_tool_output_to_terminal_height(self):
        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=120, force_terminal=True, color_system=None, file=stream)
        renderer._latest_tool_name = "connect_vpn_config"
        renderer._latest_tool_arguments = {"config_path": "/home/administrator/Downloads/lab.ovpn"}
        renderer._latest_tool_result = ToolResult(
            success=True,
            output="\n".join(
                [
                    "VPN failed: /home/administrator/Downloads/lab.ovpn",
                    "PID: 23109",
                    "Log: /home/administrator/.secops_agent/vpn/openvpn-lab.log",
                    "Status: TLS handshake timed out.",
                    "Recommended next checks:",
                    "  - Try another network or mobile hotspot if UDP/1194 is blocked.",
                    "  - If the provider offers TCP configs, download and use one.",
                    "  - Confirm the lab VPN server is currently available.",
                    "Recent log output:",
                    *[f"2026-06-15 18:38:{index:02d} TLS handshake detail {index}" for index in range(30)],
                ]
            ),
            execution_time=63.8,
        )

        with patch(
            "secops_agent.ui.renderer.shutil.get_terminal_size",
            return_value=os.terminal_size((120, 16)),
        ):
            self.assertTrue(renderer._toggle_latest_transcript())

        output = stream.getvalue()
        self.assertLessEqual(renderer._latest_transcript_rendered_lines, 15)
        self.assertIn("more lines hidden", output)

    def test_renderer_ctrl_o_does_not_duplicate_when_expanded_surface_cannot_clear(self):
        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=120, force_terminal=True, color_system=None, file=stream)
        renderer._latest_tool_name = "connect_vpn_config"
        renderer._latest_tool_arguments = {"config_path": "/home/administrator/Downloads/lab.ovpn"}
        renderer._latest_tool_result = ToolResult(
            success=True,
            output="VPN failed: /home/administrator/Downloads/lab.ovpn",
            execution_time=63.8,
        )
        renderer._latest_transcript_expanded = True
        renderer._latest_transcript_rendered_lines = 30

        with patch(
            "secops_agent.ui.renderer.shutil.get_terminal_size",
            return_value=os.terminal_size((120, 16)),
        ):
            self.assertTrue(renderer._toggle_latest_transcript())

        self.assertEqual(stream.getvalue(), "")
        self.assertTrue(renderer._latest_transcript_expanded)
        self.assertEqual(renderer._latest_transcript_rendered_lines, 30)

    def test_renderer_tty_shows_tool_once_via_spinner_not_static_row(self):
        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=88, force_terminal=True, color_system=None, file=stream)

        async def events():
            yield ToolCallEvent("run_shell", {"command": "date"}, "call_1", permission="allow")
            yield ToolStartEvent("run_shell", {"command": "date"}, "call_1")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="Sun May 31 03:45:11 PM GMT 2026\n[Exit Code: 0]"),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events()))
        output = stream.getvalue()

        # No static running row (and thus no premature tag / duplicate ●): the
        # tool appears once, as the final result row.
        self.assertNotIn("● Bash(date) (ctrl+o to expand)", output)
        self.assertIn("● Bash(date)", output)
        self.assertIn("⎿  2 lines", output)

    def test_tool_result_box_render_returns_exact_line_count(self):
        # The ctrl+o toggle clears the collapsed block by line count, so the
        # returned count must equal the lines actually printed (else leftover
        # lines like a dangling "── OS ──" leak on expand).
        cases = [
            # parsed_summary lead + preview lines + hidden notice
            (
                "🖥️  System Information\n── OS ──\n  Hostname: ubuntu\n"
                + "\n".join(f"  k{i}: v" for i in range(20)),
                {"parsed_summary": "Hostname: ubuntu"},
            ),
            ("single line only", {}),  # single-line branch
            ("\n".join(f"line {i}" for i in range(12)), {}),  # metrics branch
        ]
        for output, meta in cases:
            stream = io.StringIO()
            console = Console(width=200, force_terminal=False, file=stream)
            n = ToolResultBox.render(
                console,
                "sysinfo",
                ToolResult(success=True, output=output, execution_time=1.0, metadata=meta),
            )
            printed = len(stream.getvalue().splitlines())
            self.assertEqual(n, printed, f"line-count mismatch for metadata={meta}")

        # error branch
        stream = io.StringIO()
        console = Console(width=200, force_terminal=False, file=stream)
        n = ToolResultBox.render(console, "x", ToolResult(success=False, output="", error="boom"))
        self.assertEqual(n, len(stream.getvalue().splitlines()))

    def test_renderer_keeps_tool_expanded_when_result_arrives_after_ctrl_o(self):
        from secops_agent.ui.renderer import _TranscriptToggleRequest

        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=88, force_terminal=True, color_system=None, file=stream)

        async def events():
            yield ToolCallEvent("run_shell", {"command": "pwd"}, "call_1", permission="allow")
            yield ToolStartEvent("run_shell", {"command": "pwd"}, "call_1")
            yield _TranscriptToggleRequest()
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="/home/administrator/secops_v2\n[Exit Code: 0]", execution_time=0.02),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events(), status_right="Gemini 2.5 Flash"))
        output = stream.getvalue()

        self.assertIn("● Bash(pwd) (ctrl+o to collapse)", output)
        self.assertIn("⎿  /home/administrator/secops_v2 (ctrl+o to collapse)", output)
        self.assertNotIn("⎿  20ms · 2 lines", output)
        self.assertNotIn("⎿  Running", output)

    def test_renderer_ctrl_o_anchor_counts_text_rendered_after_tool(self):
        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=88, force_terminal=True, color_system=None, file=stream)
        runtime = RuntimeState()

        async def events():
            yield ToolCallEvent("run_shell", {"command": "pwd"}, "call_1", permission="allow")
            yield ToolStartEvent("run_shell", {"command": "pwd"}, "call_1")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="/home/administrator/secops_v2\n[Exit Code: 0]", execution_time=0.02),
                "call_1",
            )
            yield TextEvent("Résumé après outil.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))

        self.assertGreater(runtime.ctrl_o_anchor_rendered_lines, 0)
        self.assertGreater(runtime.ctrl_o_anchor_tail_lines, 0)
        self.assertIn("Bash", runtime.ctrl_o_anchor_collapsed)
        self.assertIn("(pwd)", runtime.ctrl_o_anchor_collapsed)

    def test_renderer_interrupt_message_names_stopped_active_tool(self):
        from secops_agent.ui.renderer import _AgentStreamInterrupted

        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()

        async def events():
            yield ToolStartEvent("run_shell", {"command": "sleep 300"}, "call_1")
            raise _AgentStreamInterrupted

        asyncio.run(renderer.render_agent_stream(events(), status_right="Gemini 2.5 Flash", runtime=runtime))
        output = renderer.console.export_text()

        self.assertIn("Interrupted · stopped Bash(sleep 300) · What should SecOps CLI do instead?", output)
        self.assertEqual(len(runtime.tasks), 1)
        self.assertEqual(runtime.tasks[0].kind, "tool-execution")
        self.assertEqual(runtime.tasks[0].status, "cancelled")
        self.assertIn("interrupted by user", runtime.tasks[0].log)

    def test_renderer_handles_sudo_authentication_request_without_leaking_secret(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        loop = asyncio.new_event_loop()
        future = loop.create_future()

        async def fake_request(console, *, command, reason=""):
            console.print("local sudo prompt")
            return SudoAuthenticationDecision(True, "sudo authentication cached")

        async def events():
            yield SudoAuthenticationRequestEvent(
                command="sudo apt update",
                reason="sudo requires interactive authentication",
                authentication_future=future,
            )
            yield TextEvent("done")
            yield TextEvent("", done=True)

        try:
            with patch("secops_agent.ui.renderer.request_sudo_authentication", fake_request):
                loop.run_until_complete(renderer.render_agent_stream(events()))
            output = renderer.console.export_text()
            self.assertTrue(future.done())
            self.assertTrue(future.result().success)
            self.assertIn("local sudo prompt", output)
            self.assertNotIn("password123", output)
        finally:
            loop.close()

    def test_sudo_prompt_explains_local_only_authentication(self):
        console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        async def fake_auth(_reader):
            return SudoAuthenticationDecision(True, "sudo authentication cached")

        with patch("secops_agent.ui.sudo_prompt.can_prompt_for_sudo", return_value=True), patch(
            "secops_agent.ui.sudo_prompt.authenticate_sudo_with_password",
            fake_auth,
        ):
            decision = asyncio.run(
                request_sudo_authentication(
                    console,
                    command="sudo apt update",
                    reason="sudo requires interactive authentication",
                )
            )

        output = console.export_text()
        self.assertTrue(decision.success)
        self.assertIn("Sudo authentication required", output)
        self.assertIn("Password is used locally", output)
        self.assertNotIn("password123", output)

    def test_renderer_keeps_long_tool_execution_in_tasks_for_review(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()

        async def events():
            yield ToolStartEvent("run_shell", {"command": "sleep 3"}, "call_1")
            yield ToolProgressEvent("run_shell", "call_1", "running", "2.0s elapsed")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(
                    success=True,
                    output="done\n[Exit Code: 0]",
                    execution_time=3.1,
                    metadata={"spool_path": "/tmp/secops-spool/combined.log"},
                ),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))

        self.assertEqual(len(runtime.tasks), 1)
        task = runtime.tasks[0]
        self.assertEqual(task.name, "Bash(sleep 3)")
        self.assertEqual(task.status, "done")
        self.assertIn("2.0s elapsed", "\n".join(task.log))
        self.assertIn("Spool: /tmp/secops-spool/combined.log", task.output)

    def test_renderer_removes_quick_successful_tool_task(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()

        async def events():
            yield ToolStartEvent("run_shell", {"command": "date"}, "call_1")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="Sun May 31\n[Exit Code: 0]", execution_time=0.05),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))

        self.assertEqual(runtime.tasks, [])

    def test_renderer_does_not_add_extra_blank_between_thought_and_tool(self):
        stream = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=stream)

        async def events():
            yield ThinkingEvent("Need the system time.")
            yield ToolCallEvent("run_shell", {"command": "date"}, "call_1", permission="allow")
            yield ToolStartEvent("run_shell", {"command": "date"}, "call_1")

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("Thought for", output)
        # Non-TTY: the static running row is shown (spinner does not animate
        # here) but without the premature "(ctrl+o to expand)" tag.
        self.assertIn("● Bash(date)", output)
        self.assertNotIn("● Bash(date) (ctrl+o to expand)", output)
        thought_tail = output.split("Thought for", 1)[1]
        self.assertNotIn("\n\n● Bash(date)", thought_tail)

    def test_renderer_caches_last_turn_for_ctrl_o_redraw(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()

        async def events():
            yield ThinkingEvent("Need time")
            yield ToolCallEvent("run_shell", {"command": "date"}, "call_1", permission="allow")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="Sun May 31 04:22:35 PM GMT 2026\n[Exit Code: 0]"),
                "call_1",
            )
            yield TextEvent("Il est 16:22.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))

        self.assertIn("●", runtime.ctrl_o_transcript_collapsed)
        self.assertIn("Bash", runtime.ctrl_o_transcript_collapsed)
        self.assertIn("(date)", runtime.ctrl_o_transcript_collapsed)
        self.assertNotIn("Need time", runtime.ctrl_o_transcript_collapsed)
        self.assertNotIn("Thought for", runtime.ctrl_o_transcript_collapsed)
        self.assertIn("●", runtime.ctrl_o_transcript_expanded)
        self.assertIn("Bash", runtime.ctrl_o_transcript_expanded)
        self.assertIn("(date)", runtime.ctrl_o_transcript_expanded)
        self.assertIn("ctrl+o to collapse", runtime.ctrl_o_transcript_expanded)
        self.assertEqual(runtime.ctrl_o_transcript_rendered_lines, 0)
        self.assertGreater(runtime.ctrl_o_anchor_rendered_lines, 0)

        stream = io.StringIO()
        console = Console(width=88, force_terminal=True, color_system=None, file=stream)
        self.assertEqual(_show_ctrl_o_surface(ConversationMemory(), runtime, console), "tool-output")
        self.assertIn("ctrl+o to collapse", stream.getvalue())

    def test_renderer_ctrl_o_cache_uses_spool_metadata_for_truncated_result(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stdout_path = Path(tmpdir) / "stdout.log"
            stdout_path.write_text("full output from spool\nsecond line\n", encoding="utf-8")
            result = ToolResult(
                success=True,
                output="[Output truncated in memory; full spool: /tmp/example]\n[Exit Code: 0]",
                metadata={"stdout_path": str(stdout_path)},
            )

            lines = _build_expanded_tool_result_lines(result, width=88)
            rendered = "\n".join(lines)

        self.assertIn("full output from spool", rendered)
        self.assertIn("second line", rendered)
        self.assertIn("[Exit Code: 0]", rendered)
        self.assertNotIn("Output truncated in memory", rendered)

    def test_trajectory_can_expand_latest_tool_output(self):
        runtime = RuntimeState()
        runtime.add_artifact("nmap result", "tool-result", "PORT 22 open\nPORT 80 open", source="nmap_scan")

        rendered = build_trajectory_text(ConversationMemory(), runtime, expand_latest_tool=True)

        self.assertIn("Expanded Tool Output", rendered)
        self.assertIn("a001 · nmap_scan", rendered)
        self.assertIn("PORT 80 open", rendered)

    def test_attachment_text_file_creates_auditable_artifact_and_prompt_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "finding.txt"
            path.write_text("Finding: SSH is exposed on 22/tcp\n", encoding="utf-8")
            runtime = RuntimeState()

            artifact = attach_file(runtime, str(path))
            context = build_attachment_prompt_context(runtime)

        self.assertEqual(artifact.kind, "attachment")
        self.assertEqual(runtime.attachment_artifacts(), [artifact])
        self.assertIn("Attachment: finding.txt", artifact.title)
        self.assertIn("Type: text", artifact.content)
        self.assertIn("SHA256:", artifact.content)
        self.assertIn("Preview:", artifact.content)
        self.assertIn("Finding: SSH is exposed", artifact.content)
        self.assertIn("Attached evidence available", context)
        self.assertIn("Finding: SSH is exposed", context)

    def test_attach_success_does_not_emit_redundant_preview_line(self):
        main_source = (Path(__file__).resolve().parents[1] / "secops_agent" / "main.py").read_text(encoding="utf-8")
        attach_branch = main_source.split('elif canonical_cmd == "/attach":', 1)[1].split('elif canonical_cmd == "/permissions":', 1)[0]

        self.assertIn("Attached {artifact.id}: {artifact.title}", attach_branch)
        self.assertNotIn("render_command_result(artifact.preview)", attach_branch)

    def test_attachments_view_uses_artifact_review_grammar(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "finding.txt"
            path.write_text("Finding: SSH is exposed on 22/tcp\nEvidence line two\n", encoding="utf-8")
            runtime = RuntimeState()
            attach_file(runtime, str(path))

        preview = "\n".join(build_attachments_view_lines(runtime, detail_mode="preview", width=120, height=24))
        opened = "\n".join(build_attachments_view_lines(runtime, detail_mode="open", width=120, height=24))

        self.assertIn("Attachments", preview)
        self.assertIn("> a001   Attachment: finding.txt", preview)
        self.assertIn("attachment · /attach", preview)
        self.assertNotIn("attachment · /attach · Attachment", preview)
        self.assertIn("Preview: a001 · Attachment: finding.txt", preview)
        self.assertNotIn("  Attachment\n", preview)
        self.assertIn("Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss", preview)
        self.assertIn("Open: a001 · Attachment: finding.txt", opened)
        self.assertNotIn("\n    Attachment\n", opened)
        self.assertIn("Finding: SSH is exposed on 22/tcp", opened)

    def test_attachments_render_inline_surface_without_static_overlay(self):
        renderer = Renderer()
        renderer.console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_attachments(RuntimeState())
        output = renderer.console.export_text()

        self.assertIn("Attachments", output)
        self.assertIn("No attachments", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss", output)
        self.assertNotIn("/attach <path> registers evidence", output)
        self.assertNotIn("────────────────", output)

    def test_attachment_image_records_metadata_without_binary_preview(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "screen.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
            runtime = RuntimeState()

            artifact = attach_file(runtime, str(path))

        self.assertEqual(artifact.kind, "attachment")
        self.assertIn("Type: image", artifact.content)
        self.assertIn("MIME: image/png", artifact.content)
        self.assertIn("metadata captured; image will be sent to compatible models", artifact.content)
        self.assertNotIn("Preview:", artifact.content)

    def test_attachment_image_builds_multimodal_model_part_descriptor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "screen.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
            runtime = RuntimeState()
            artifact = attach_file(runtime, str(path))

            parts = build_attachment_model_parts(runtime)

        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["id"], artifact.id)
        self.assertEqual(parts[0]["type"], "image")
        self.assertEqual(parts[0]["mime_type"], "image/png")
        self.assertEqual(parts[0]["path"], str(path))

    def test_trajectory_text_includes_attachments_section(self):
        from secops_agent.core.memory import ConversationMemory

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "evidence.txt"
            path.write_text("Evidence body", encoding="utf-8")
            runtime = RuntimeState()
            attach_file(runtime, str(path))

        rendered = build_trajectory_text(ConversationMemory(), runtime)

        self.assertIn("Attachments: 1", rendered)
        self.assertIn("Attachments", rendered)
        self.assertIn("a001 · Attachment: evidence.txt", rendered)

    def test_agent_prompt_includes_bounded_attachment_context(self):
        from secops_agent.main import _prompt_with_attachments

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "evidence.txt"
            path.write_text("Evidence body", encoding="utf-8")
            runtime = RuntimeState()
            attach_file(runtime, str(path))

        prompt = _prompt_with_attachments("Summarize the attachment.", runtime)

        self.assertIn("Summarize the attachment.", prompt)
        self.assertIn("[SecOps attached evidence]", prompt)
        self.assertIn("Evidence body", prompt)

    def test_llm_prepare_contents_sends_image_attachment_as_inline_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "screen.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
            provider = GeminiProvider(api_key="", model_name="gemma")
            message = Message(
                role="user",
                content="Analyse cette capture.",
                attachments=[
                    {
                        "type": "image",
                        "path": str(path),
                        "mime_type": "image/png",
                        "title": "screen.png",
                    }
                ],
            )

            contents = provider._prepare_contents([message])

        self.assertEqual(contents[0].parts[0].text, "Analyse cette capture.")
        self.assertEqual(contents[0].parts[1].inline_data.mime_type, "image/png")
        self.assertEqual(contents[0].parts[1].inline_data.data, b"\x89PNG\r\n\x1a\n\x00\x00")

    def test_google_search_grounding_is_added_for_web_sensitive_prompts(self):
        original = settings.GOOGLE_SEARCH_GROUNDING
        settings.GOOGLE_SEARCH_GROUNDING = "auto"
        try:
            provider = GeminiProvider(api_key="", model_name="gemini")
            profile = provider.prepare_for_prompt("cherche sur le net la derniere CVE OpenSSL")
            config = provider._build_config(genai_types, profile, tools_schema=[])
        finally:
            settings.GOOGLE_SEARCH_GROUNDING = original

        self.assertTrue(any(getattr(tool, "google_search", None) is not None for tool in config.tools))

    def test_google_search_grounding_is_not_mixed_with_function_declarations(self):
        original = settings.GOOGLE_SEARCH_GROUNDING
        settings.GOOGLE_SEARCH_GROUNDING = "auto"
        try:
            provider = GeminiProvider(api_key="", model_name="gemini")
            profile = provider.prepare_for_prompt("Find directories on the web server using GoBuster")
            config = provider._build_config(
                genai_types,
                profile,
                tools_schema=[
                    {
                        "name": "dir_brute",
                        "description": "Discover web paths",
                        "parameters": {
                            "url": {
                                "type": "string",
                                "description": "Target URL",
                                "required": True,
                            }
                        },
                    }
                ],
            )
        finally:
            settings.GOOGLE_SEARCH_GROUNDING = original

        self.assertTrue(any(getattr(tool, "function_declarations", None) for tool in config.tools))
        self.assertFalse(any(getattr(tool, "google_search", None) is not None for tool in config.tools))

    def test_google_search_grounding_can_be_disabled(self):
        original = settings.GOOGLE_SEARCH_GROUNDING
        settings.GOOGLE_SEARCH_GROUNDING = "off"
        try:
            provider = GeminiProvider(api_key="", model_name="gemini")
            profile = provider.prepare_for_prompt("cherche sur le net la derniere CVE OpenSSL")
            config = provider._build_config(genai_types, profile, tools_schema=[])
        finally:
            settings.GOOGLE_SEARCH_GROUNDING = original

        self.assertFalse(config.tools)

    def test_artifact_review_text_has_metadata_and_content(self):
        runtime = RuntimeState()
        artifact = runtime.add_artifact("session.md", "export", "# Report\nFinding", source="/export")

        self.assertIsNotNone(artifact)
        rendered = build_artifact_text(artifact)

        self.assertIn("Artifact: a001", rendered)
        self.assertIn("Kind: export", rendered)
        self.assertIn("# Report", rendered)

    def test_artifact_review_labels_supervised_spool_as_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spool_path = Path(tmpdir) / "combined.log"
            spool_path.write_text("[STDOUT] complete output\n", encoding="utf-8")
            runtime = RuntimeState()
            artifact = runtime.add_artifact(
                "Bash(long) result",
                "tool-result",
                "[Output truncated in memory; full spool: /tmp/example]",
                source="run_shell",
                path=spool_path,
                metadata={"spool_path": str(spool_path)},
            )

            self.assertIsNotNone(artifact)
            rendered = build_artifact_text(artifact)

        self.assertIn(f"Log: {spool_path}", rendered)
        self.assertNotIn(f"Path: {spool_path}", rendered)

    def test_artifacts_render_inline_surface_without_static_overlay(self):
        renderer = Renderer()
        renderer.console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())

        renderer.render_artifacts(RuntimeState())
        output = renderer.console.export_text()

        self.assertIn("Artifacts", output)
        self.assertIn("No artifacts", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss", output)
        self.assertNotIn("Tool outputs and substantial generated responses", output)
        self.assertNotIn("────────────────", output)

    def test_ctrl_r_uses_artifact_surface_even_when_empty(self):
        console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())

        result = _show_ctrl_r_surface(RuntimeState(), model_name="gemini-2.5-flash", console=console)
        output = console.export_text()

        self.assertEqual(result, "artifacts")
        self.assertIn("Artifacts", output)
        self.assertIn("No artifacts", output)
        self.assertIn("Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss", output)
        self.assertNotIn("Aucun artifact disponible", output)

    def test_agent_event_tracker_records_tool_and_response_artifacts(self):
        from secops_agent.main import _track_agent_artifacts

        runtime = RuntimeState()

        async def events():
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="shell output", execution_time=0.01),
                "call_1",
            )
            yield TextEvent("A" * 320)
            yield TextEvent("", done=True)

        async def collect():
            return [event async for event in _track_agent_artifacts(runtime, events())]

        collected = asyncio.run(collect())

        self.assertEqual(len(collected), 3)
        self.assertEqual([artifact.kind for artifact in runtime.artifacts], ["tool-result", "response"])
        self.assertEqual(runtime.artifacts[0].source, "run_shell")

    def test_agent_event_tracker_marks_text_failure_tool_artifact_as_error(self):
        from secops_agent.main import _track_agent_artifacts

        runtime = RuntimeState()

        async def events():
            yield ToolCallEvent("run_shell", {"command": "sleep 300"}, "call_1", permission="allow")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(
                    success=True,
                    output="❌ Command timed out after 300s and was stopped",
                    execution_time=300,
                ),
                "call_1",
            )

        async def collect():
            return [event async for event in _track_agent_artifacts(runtime, events())]

        collected = asyncio.run(collect())

        self.assertEqual(len(collected), 2)
        self.assertEqual(runtime.artifacts[0].title, "Bash(sleep 300) error")
        self.assertEqual(_artifact_status_color(runtime.artifacts[0]), COLORS["error"])

    def test_agent_event_tracker_marks_vpn_failed_tool_artifact_as_error(self):
        from secops_agent.main import _track_agent_artifacts

        runtime = RuntimeState()

        async def events():
            yield ToolCallEvent(
                "connect_vpn_config",
                {"config_path": "/home/administrator/Downloads/lab.ovpn"},
                "call_1",
                permission="allow",
            )
            yield ToolResultEvent(
                "connect_vpn_config",
                ToolResult(
                    success=True,
                    output=(
                        "VPN failed: /home/administrator/Downloads/lab.ovpn\n"
                        "PID: 9296\n"
                        "Status: TLS handshake timed out."
                    ),
                    execution_time=63.8,
                ),
                "call_1",
            )

        async def collect():
            return [event async for event in _track_agent_artifacts(runtime, events())]

        collected = asyncio.run(collect())

        self.assertEqual(len(collected), 2)
        self.assertEqual(
            runtime.artifacts[0].title,
            "ConnectVpnConfig(/home/administrator/Downloads/lab.ovpn) error",
        )
        self.assertEqual(_artifact_status_color(runtime.artifacts[0]), COLORS["error"])

    def test_tasks_render_stable_id_column(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()
        runtime.add_task(
            "side question with a rather long visible task name",
            "running",
            "nmap: scanning 42 ports",
        )

        renderer.render_tasks(runtime, interactive=False)
        output = renderer.console.export_text()

        self.assertIn("Summary", output)
        self.assertIn("t001", output)
        self.assertIn("running", output)
        self.assertIn("side question with a rather long visible task name", output)
        self.assertNotIn("namerunning", output)

    def test_runtime_cancel_task_marks_cancelling_and_cancels_handle(self):
        runtime = RuntimeState()

        async def scenario():
            task = runtime.add_task("side question", "running", "answering")
            task.handle = asyncio.create_task(asyncio.sleep(60))

            cancelled = runtime.cancel_task(task.id)

            self.assertIs(cancelled, task)
            self.assertEqual(task.detail, "cancelling")
            self.assertIn("cancellation requested", task.log)
            self.assertTrue(task.handle.cancelled() or task.handle.cancelling())
            with contextlib.suppress(asyncio.CancelledError):
                await task.handle

        asyncio.run(scenario())

    def test_task_detail_reads_spool_metadata_for_truncated_output(self):
        renderer = Renderer()
        renderer.console = Console(width=110, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()
        with tempfile.TemporaryDirectory() as tmpdir:
            spool_path = Path(tmpdir) / "combined.log"
            spool_path.write_text("[STDOUT] complete task output\n", encoding="utf-8")
            stdout_path = Path(tmpdir) / "stdout.log"
            stdout_path.write_text("complete task output\nsecond line\n", encoding="utf-8")
            task = runtime.add_task("Bash(long)", "done", "run_shell done", kind="tool-execution")
            task.output = "[Output truncated in memory; full spool: /tmp/example]"
            task.metadata = {"spool_path": str(spool_path), "stdout_path": str(stdout_path)}

            renderer.render_task_detail(task)
            panel_detail = "\n".join(renderer._task_panel_detail(task))
            from secops_agent.main import _task_transcript

            transcript = _task_transcript(task)

        output = renderer.console.export_text()
        self.assertIn("complete task output", output)
        self.assertIn("complete task output", panel_detail)
        self.assertIn("complete task output", transcript)
        self.assertIn(str(spool_path), output)
        self.assertIn(f"Log: {spool_path}", panel_detail)
        self.assertIn(f"Log file:\n{spool_path}", transcript)
        self.assertNotIn("Output truncated in memory", output)

    def test_panel_lines_render_list_and_detail_columns(self):
        lines = build_panel_lines(
            "Tasks",
            [
                PanelRow("t001", "t001", "running", "side question · 3s", accent=True),
                PanelRow("t002", "t002", "done", "completed"),
            ],
            ["t001 running", "Name: side question", "Elapsed: 3s"],
            selected=0,
            width=72,
            height=12,
            footer="Keyboard: ↑/↓ Navigate  enter Select  esc Go Back",
        )

        rendered = "\n".join(lines)
        self.assertTrue(all(len(line) <= 72 for line in lines))
        self.assertIn("Tasks", rendered)
        self.assertIn("› t001 running", rendered)
        self.assertIn("t001 running", rendered)
        self.assertIn("Keyboard: ↑/↓ Navigate  enter Select  esc Go Back", rendered)
        self.assertNotIn("l logs", rendered)
        self.assertNotIn("esc/q", rendered)

    def test_agents_render_static_without_active_tasks(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        runtime = RuntimeState()

        renderer.render_agents(runtime, interactive=False)
        output = renderer.console.export_text()

        self.assertIn("Create New Agents", output)
        self.assertIn("Available Agents", output)
        self.assertIn("{agent_name}/agent.json", output)
        self.assertIn("> ▸ Available Agents", output)
        self.assertNotIn("primary", output)
        self.assertNotIn("No background subagents are active.", output)
        self.assertNotIn("Use /btw", output)

    def test_agents_view_matches_antigravity_collapsed_create_and_available_shape(self):
        runtime = RuntimeState()

        lines = build_agents_view_lines(runtime, width=100, height=18)
        rendered = "\n".join(lines)

        self.assertIn("Create New Agents", rendered)
        self.assertIn("Workspace:", rendered)
        self.assertIn(".secops_agent/agents/{agent_name}/agent.json", rendered)
        self.assertNotIn("User:", rendered)
        self.assertIn("> ▸ Available Agents", rendered)
        self.assertNotIn("primary", rendered)
        self.assertNotIn("No background subagents are active.", rendered)
        self.assertIn("k Kill Active Subagent", rendered)
        self.assertNotIn("Use /btw", rendered)

    def test_agents_view_expands_to_secops_agent_rows(self):
        runtime = RuntimeState()
        runtime.agent_state = "idle"
        runtime.add_task("side question", "running", "answering")
        profile = AgentProfileSummary(
            name="Recon",
            description="Passive reconnaissance profile",
            source="workspace",
            path=Path.cwd() / ".agents" / "agents" / "recon" / "agent.json",
        )

        lines = build_agents_view_lines(
            runtime,
            expanded=True,
            profiles=[profile],
            width=100,
            height=18,
        )
        rendered = "\n".join(lines)

        self.assertIn("Create New Agents", rendered)
        self.assertIn("Workspace:", rendered)
        self.assertIn(".secops_agent/agents/{agent_name}/agent.json", rendered)
        self.assertNotIn("User:", rendered)
        self.assertIn("> ▾ Available Agents", rendered)
        self.assertIn("primary", rendered)
        self.assertIn("t001", rendered)
        self.assertIn("Recon", rendered)
        self.assertIn("k Kill Active Subagent", rendered)
        self.assertNotIn("Use /btw", rendered)

    def test_agent_panel_rows_include_primary_and_running_tasks(self):
        renderer = Renderer()
        runtime = RuntimeState()
        runtime.agent_state = "thinking"
        runtime.add_task("side question", "running", "answering")

        rows = renderer._agent_panel_rows(runtime)
        primary_detail = renderer._agent_panel_detail(runtime, rows[0])
        task_detail = renderer._agent_panel_detail(runtime, rows[1])

        self.assertEqual([row.value for row in rows], ["primary", "t001"])
        self.assertIn("foreground", "\n".join(primary_detail))
        self.assertIn("side question", "\n".join(task_detail))

    def test_orchestration_rows_filter_tasks_and_agents(self):
        renderer = Renderer()
        runtime = RuntimeState()
        runtime.add_task("running side question", "running", "answering")
        runtime.add_task("completed side question", "done", "completed")

        task_rows = renderer._orchestration_panel_rows(runtime, "tasks")
        agent_rows = renderer._orchestration_panel_rows(runtime, "agents")

        self.assertEqual([row.value for row in task_rows], ["t001", "t002"])
        self.assertEqual([row.value for row in agent_rows], ["primary", "t001"])
        self.assertIn("completed side question", task_rows[1].description)
        self.assertTrue(all("completed" not in row.description for row in agent_rows))

    def test_agent_markdown_normalization_keeps_model_output_compact(self):
        text = "\n# Analyse\n\nVoici le resultat.\n\n---\n\n## Actions\n- verifier\n"

        normalized = normalize_agent_markdown(text)

        # h1 is downgraded to a left-aligned h2 heading; h2 is preserved as a
        # real heading (structure), not flattened to inline bold.
        self.assertIn("## Analyse", normalized)
        self.assertIn("## Actions", normalized)
        self.assertNotIn("---", normalized)
        self.assertNotIn("\n\n\n", normalized)

    def test_collapsed_tool_result_leads_with_parsed_summary(self):
        from secops_agent.core.tools import ToolResult

        result = ToolResult(
            success=True,
            output=(
                "Starting Nmap 7.94\n"
                "Nmap scan report for 10.10.10.5\n"
                "22/tcp open ssh\n80/tcp open http\n443/tcp open https\n"
            ),
            execution_time=1.2,
            metadata={"parsed_summary": "3 service(s) on 10.10.10.5 (Linux)"},
        )

        lines = _build_collapsed_tool_result_lines(result, width=88)
        text = "\n".join(lines)

        # The fold leads with the structured key fact, not the raw banner head.
        self.assertIn("3 service(s) on 10.10.10.5 (Linux)", lines[0])
        self.assertNotIn("Starting Nmap", lines[0])
        self.assertIn("ctrl+o to expand", text)

    def test_agent_markdown_normalization_flattens_deep_headings(self):
        text = "#### Sous-detail\ntexte"

        normalized = normalize_agent_markdown(text)

        self.assertIn("**Sous-detail**", normalized)
        self.assertNotIn("#### Sous-detail", normalized)

    def test_agent_markdown_normalization_preserves_code_fences(self):
        text = "# Commande\n```markdown\n# garder ce titre\n---\n```\n"

        normalized = normalize_agent_markdown(text)

        self.assertIn("## Commande", normalized)
        self.assertIn("# garder ce titre", normalized)
        self.assertIn("---", normalized)

    def test_agent_markdown_normalization_keeps_ordered_list_periods_visible(self):
        text = "1 Que le fichier existe\n2 Que OpenVPN est installe"

        normalized = normalize_agent_markdown(text)
        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
        console.print(Markdown(normalized))
        output = console.export_text()

        self.assertIn("1\\. Que le fichier existe", normalized)
        self.assertIn("2\\. Que OpenVPN est installe", normalized)
        self.assertIn("1. Que le fichier existe", output)
        self.assertIn("2. Que OpenVPN est installe", output)

    def test_agent_markdown_normalization_does_not_rewrite_single_numeric_fact(self):
        text = "22 SSH est ouvert"

        normalized = normalize_agent_markdown(text)

        self.assertEqual(normalized, text)

    def test_terminal_output_contract_is_hierarchical_and_not_decorative(self):
        from secops_agent.core.llm import SECOPS_SYSTEM_INSTRUCTION

        self.assertIn("Terminal output standard", SECOPS_SYSTEM_INSTRUCTION)
        self.assertIn("smallest shape", SECOPS_SYSTEM_INSTRUCTION)
        self.assertIn("at most three `##` headings", SECOPS_SYSTEM_INSTRUCTION)
        self.assertIn("single status marker", SECOPS_SYSTEM_INSTRUCTION)
        self.assertIn("Response recipes", SECOPS_SYSTEM_INSTRUCTION)
        self.assertIn("Blocked action", SECOPS_SYSTEM_INSTRUCTION)

    def test_agent_stream_renders_thought_and_indented_text(self):
        renderer = Renderer()
        renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Analyzing response")
            yield TextEvent("Final answer.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("Thought for", output)
        self.assertIn("Analyzing response", output)
        self.assertIn("Analyzing response\n  Final answer.", output)
        self.assertIn("  Final answer.", output)
        self.assertRegex(output, r"Final answer\.[^\n]*\n\n")
        self.assertEqual(output.count("Final answer."), 1)

    def test_agent_markdown_emphasis_has_no_code_container_background(self):
        renderer = Renderer()
        renderer.console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            theme=rich_theme,
            file=io.StringIO(),
        )

        async def events():
            yield TextEvent("Verifier **DNS** avec `nmap`.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events()))
        html = renderer.console.export_html(inline_styles=True)

        self.assertIn(COLORS["accent_bright"].lower(), html.lower())
        self.assertNotIn("background-color: #000000", html)
        self.assertNotIn("background-color: #272822", html)

    def test_generation_wait_message_moves_contextual_tip_to_second_line_after_delay(self):
        initial = format_wait_message("Generating...", 0.0)
        delayed = format_wait_message("Generating...", 3.0)

        self.assertIn("Generating...", initial)
        self.assertNotIn("Tip:", initial)
        self.assertIn("Generating...", delayed)
        self.assertIn("\n", delayed)
        self.assertIn("└ Tip:", delayed)
        self.assertNotIn(" · Tip:", delayed)

    def test_generation_spinner_can_keep_prompt_frame_visible(self):
        console = Console(width=88, force_terminal=False, file=io.StringIO())
        spinner = ThinkingSpinner(
            "Generating...",
            console=console,
            status_right="Gemini 2.5 Flash",
        )

        message = spinner._status_message(0.0)

        self.assertIn("Generating...", message)
        self.assertIn("────────────────", message)
        self.assertIn(">", message)
        self.assertIn("esc to cancel", message)
        self.assertIn("Gemini 2.5 Flash", message)

    def test_wait_tip_rotates_with_elapsed_time(self):
        self.assertNotEqual(wait_tip_for_elapsed(0.0), wait_tip_for_elapsed(4.0))

    def test_tool_spinner_adds_tip_after_long_wait(self):
        spinner = ToolExecutionSpinner("nmap_scan")

        short_message = spinner._format_message(1.0)
        long_message = spinner._format_message(3.0)

        self.assertIn("Running.", short_message)
        self.assertNotIn("Running Nmap", short_message)
        self.assertNotIn("Tip:", short_message)
        self.assertIn("Running...", long_message)
        self.assertIn("└ Tip:", long_message)

    def test_tool_spinner_cycles_running_label_like_antigravity(self):
        spinner = ToolExecutionSpinner("run_shell")

        self.assertIn("Running", spinner._format_message(0.0))
        self.assertIn("Running.", spinner._format_message(1.0))
        self.assertIn("Running..", spinner._format_message(2.0))
        self.assertIn("Running...", spinner._format_message(3.0))

    def test_tool_spinner_can_keep_prompt_frame_visible(self):
        console = Console(width=88, force_terminal=False, file=io.StringIO())
        spinner = ToolExecutionSpinner(
            "run_shell",
            console=console,
            status_right="Gemma 4 26B",
        )

        message = spinner._format_message(3.0)

        self.assertIn("Running... (3s)", message)
        self.assertIn("────────────────", message)
        self.assertIn(">", message)
        self.assertIn("esc to cancel", message)
        self.assertIn("Gemma 4 26B", message)

    def test_diff_render_shows_git_status_summary(self):
        if not shutil.which("git"):
            self.skipTest("git is not installed")

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init"], cwd=tmpdir, check=True, capture_output=True)
            Path(tmpdir, "new-file.txt").write_text("hello\n", encoding="utf-8")

            renderer = Renderer()
            renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
            try:
                os.chdir(tmpdir)
                renderer.render_diff()
            finally:
                os.chdir(old_cwd)

        output = renderer.console.export_text()
        self.assertIn("Diff", output)
        self.assertIn("Summary", output)
        self.assertIn("new-file.txt", output)

    def test_diff_render_non_git_matches_antigravity_warning_shape(self):
        if not shutil.which("git"):
            self.skipTest("git is not installed")

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            renderer = Renderer()
            renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())
            try:
                os.chdir(tmpdir)
                renderer.render_diff()
            finally:
                os.chdir(old_cwd)

        output = renderer.console.export_text()
        self.assertIn("Diff (git)  All Changes  Per Turn  Commit Tree", output)
        self.assertIn("⚠ git: git diff: exit status", output)
        self.assertIn("Not a git repository", output)
        self.assertNotIn("No Git workspace available here.", output)

    def test_approval_prompt_lines_are_dynamic_and_bounded(self):
        from secops_agent.tools import network  # noqa: F401

        lines = _approval_lines(
            "nmap_scan",
            {
                "target": "127.0.0.1",
                "ports": "1-1000",
                "extra_args": "--reason --version-all",
                "very_long_argument": "x" * 120,
                "hidden_argument": "value",
            },
            PermissionResource(kind="tool", name="nmap_scan"),
            0,
            _approval_options(PermissionResource(kind="tool", name="nmap_scan")),
            72,
        )

        self.assertGreaterEqual(len(lines), 9)
        self.assertTrue(all(len(line) <= 72 for line in lines))
        self.assertIn("Permission", "\n".join(lines))
        self.assertIn("Requesting permission for: Nmap(127.0.0.1)", "\n".join(lines))
        self.assertIn("Resource: tool(nmap_scan)", "\n".join(lines))
        self.assertIn("Risk: R3 active enumeration", "\n".join(lines))
        self.assertIn("Do you want to proceed?", "\n".join(lines))
        self.assertIn("> 1. Allow once", "\n".join(lines))
        rendered = "\n".join(lines)
        self.assertIn("Permission\n" + "─" * 71 + "\n  Requesting permission", rendered)
        self.assertIn("> 1. Allow once\n  2. Always allow", rendered)
        self.assertIn("  2. Always allow tool 'nmap_scan' in this conversation", rendered)
        self.assertNotIn("Persist to settings", rendered)
        self.assertIn("\n  3. No\n\n  ↑/↓ Navigate · enter Select", rendered)
        self.assertIn("↑/↓ Navigate", "\n".join(lines))
        self.assertNotIn("tab Amend", "\n".join(lines))
        self.assertNotIn("e edit command", "\n".join(lines))

    def test_approval_prompt_shows_file_resource_context(self):
        resource = PermissionResource(kind="read_file", name="/etc/passwd")
        lines = _approval_lines(
            "file_analyze",
            {"filepath": "/etc/passwd"},
            resource,
            0,
            _approval_options(resource),
            100,
        )
        rendered = "\n".join(lines)

        self.assertIn("Resource: read_file(/etc/passwd)", rendered)
        self.assertIn("Risk: R4 local file access", rendered)
        self.assertIn("path checked before access", rendered)

    def test_approval_prompt_shows_write_file_diff_before_execution(self):
        # Audit T1.1: the operator must approve against the real content/diff shown at
        # the gate, not a prose summary rendered only after the write already happened.
        resource = PermissionResource(kind="tool", name="write_file")
        content = "<?php system($_GET['c']); ?>\necho 'second line';"
        lines = _approval_lines(
            "write_file",
            {"path": "shell.php", "content": content},
            resource,
            0,
            _approval_options(resource),
            100,
        )
        rendered = "\n".join(lines)

        self.assertIn("Do you want to proceed?", rendered)
        self.assertIn("Added 2 lines", rendered)
        self.assertIn("shell.php", rendered)
        self.assertIn("<?php system($_GET['c']); ?>", rendered)
        # The diff must render BEFORE the proceed line, i.e. at the gate, pre-write.
        self.assertLess(rendered.index("<?php"), rendered.index("Do you want to proceed?"))

    def test_approval_prompt_uses_captured_agy_command_permission_copy(self):
        resource = PermissionResource(kind="command_prefix", name="pwd")
        lines = _approval_lines(
            "run_shell",
            {"command": "pwd"},
            resource,
            0,
            _approval_options(resource),
            100,
        )
        rendered = "\n".join(lines)

        self.assertIn("Requesting permission for: pwd", rendered)
        self.assertIn("Resource: command_prefix(pwd)", rendered)
        self.assertIn("sandbox/sudo checked before run", rendered)
        self.assertIn(
            "Always allow commands matching 'pwd' in this conversation",
            rendered,
        )
        self.assertIn(
            "Always allow commands matching 'pwd' (Persist to settings.json)",
            rendered,
        )
        self.assertNotIn("Requesting permission for: Bash(pwd)", rendered)
        self.assertNotIn("command(pwd)", rendered)

    def test_approval_options_use_this_command_copy_for_exact_commands(self):
        resource = PermissionResource(kind="command_exact", name="pwd")
        rendered = "\n".join(label for _, label in _approval_options(resource))

        self.assertIn("Always allow this command in this conversation", rendered)
        self.assertNotIn("Persist to settings.json", rendered)
        self.assertNotIn("commands that start with 'pwd'", rendered)

    def test_approval_options_use_exact_copy_for_non_contextual_commands(self):
        resource = PermissionResource(kind="command_exact", name="uname -a")
        rendered = "\n".join(
            _approval_lines(
                "run_shell",
                {"command": "uname -a"},
                resource,
                0,
                _approval_options(resource),
                100,
            )
        )

        self.assertIn("Requesting permission for: uname -a", rendered)
        self.assertIn("Always allow this command in this conversation", rendered)
        self.assertNotIn("Persist to settings.json", rendered)
        self.assertNotIn("commands that start with 'uname -a'", rendered)

    def test_approval_options_preserve_persistent_scope_only_for_low_risk_tools(self):
        sensitive_rendered = "\n".join(
            label for _, label in _approval_options(PermissionResource(kind="tool", name="nmap_scan"))
        )
        low_risk_rendered = "\n".join(
            label for _, label in _approval_options(PermissionResource(kind="tool", name="hash_identify"))
        )

        self.assertIn("Always allow tool 'nmap_scan' in this conversation", sensitive_rendered)
        self.assertNotIn("Persist to settings.json", sensitive_rendered)
        self.assertIn("Always allow tool 'hash_identify' (Persist to settings.json)", low_risk_rendered)

    def test_approval_options_use_hybrid_agy_copy_for_command_prefixes(self):
        nmap_rendered = "\n".join(
            label for _, label in _approval_options(PermissionResource(kind="command_prefix", name="nmap 127.0.0.1"))
        )
        pwd_rendered = "\n".join(
            label for _, label in _approval_options(PermissionResource(kind="command_prefix", name="pwd"))
        )

        self.assertIn(
            "Always allow commands matching 'nmap 127.0.0.1' in this conversation",
            nmap_rendered,
        )
        self.assertNotIn("Persist to settings.json", nmap_rendered)
        self.assertIn(
            "Always allow commands matching 'pwd' in this conversation",
            pwd_rendered,
        )
        self.assertIn(
            "Always allow commands matching 'pwd' (Persist to settings.json)",
            pwd_rendered,
        )

    def test_approval_prompt_does_not_map_left_right_navigation_aliases(self):
        source = inspect.getsource(ApprovalPrompt.request_approval)

        self.assertIn('key in {"up", "mouse_up"}', source)
        self.assertIn('key in {"down", "mouse_down"}', source)
        self.assertNotIn('"left", "mouse_up"', source)
        self.assertNotIn('"right", "mouse_down"', source)

    def test_context_usage_view_only_accepts_advertised_escape_close(self):
        source = inspect.getsource(Renderer._render_context_usage_view)

        self.assertIn('if key == "esc":', source)
        self.assertIn('if read_key() == "esc":', source)
        self.assertNotIn('{"esc", "enter"}', source)

    def test_action_panels_do_not_use_enter_as_hidden_close(self):
        for method in (
            Renderer._render_artifacts_view,
            Renderer._render_skills_view,
            Renderer._render_hooks_view,
            Renderer._render_mcp_view,
        ):
            source = inspect.getsource(method)
            self.assertNotIn('key in {"esc", "enter"}', source)
            self.assertIn('elif key == "esc":', source)

        artifact_source = inspect.getsource(Renderer._render_artifacts_view)
        self.assertIn('key == "enter" and current_artifacts', artifact_source)

    def test_hooks_view_matches_captured_keyboard_footer_without_home_end_aliases(self):
        source = inspect.getsource(Renderer._render_hooks_view)

        self.assertIn('"up", "down", "esc", "enter"', source)
        self.assertNotIn('"home", "end"', source)
        self.assertNotIn('key == "home"', source)
        self.assertNotIn('key == "end"', source)

    def test_captured_action_panels_do_not_keep_unadvertised_page_aliases(self):
        for method in (
            Renderer._render_artifacts_view,
            Renderer._render_settings_view,
            Renderer._render_agents_view,
            Renderer._render_skills_view,
            Renderer._render_hooks_view,
            Renderer._render_mcp_view,
        ):
            source = inspect.getsource(method)
            self.assertIn('"up", "down", "esc", "enter"', source)
            for key_name in ("pgup", "pgdn", "home", "end"):
                self.assertNotIn(f'"{key_name}"', source)
                self.assertNotIn(f'key == "{key_name}"', source)

    def test_generic_inline_view_footer_does_not_advertise_unimplemented_navigation(self):
        source = inspect.getsource(Renderer._view_inline_lines)

        self.assertIn('footer: str = "Keyboard: esc Close"', source)
        self.assertNotIn('footer: str = "Keyboard: ↑/↓ Navigate  esc Close"', source)

    def test_approval_prompt_uses_exact_copy_for_compound_commands(self):
        command = "sudo apt update && sudo apt upgrade -y"
        resource = PermissionResource(kind="command_exact", name=command)
        rendered = "\n".join(
            _approval_lines(
                "run_shell",
                {"command": command},
                resource,
                0,
                _approval_options(resource),
                140,
            )
        )

        self.assertIn(f"Requesting permission for: {command}", rendered)
        self.assertNotIn("allow this command in this conversation", rendered)
        self.assertNotIn("Persist to settings.json", rendered)
        self.assertIn("> 1. Allow once", rendered)
        self.assertIn("  2. No", rendered)
        self.assertNotIn(f"commands that start with '{command}'", rendered)
        self.assertNotIn("commands that start with 'sudo'", rendered)

    def test_tool_call_renders_antigravity_expand_hint_without_permission_badge(self):
        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        ToolCallBox.render(console, "run_shell", {"command": "pwd"}, is_dangerous=True, permission="ask")
        output = console.export_text()

        self.assertIn("● Bash(pwd) (ctrl+o to expand)", output)
        self.assertNotIn("⚠", output)
        self.assertNotIn("ask", output)

    def test_tool_call_row_uses_filled_circle_like_agy(self):
        # Verified against the official agy hands-on transcript: tool rows always
        # use a solid ● circle. State is encoded by colour + spinner, never by an
        # empty ○ glyph.
        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        ToolCallBox.render(console, "run_shell", {"command": "pwd"})
        output = console.export_text()

        self.assertIn("● Bash(pwd) (ctrl+o to expand)", output)
        self.assertNotIn("○ Bash(pwd)", output)

    def test_tool_call_running_row_uses_full_neutral_circle(self):
        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        ToolCallBox.render_running(console, "run_shell", {"command": "pwd"})
        output = console.export_text()

        self.assertIn("● Bash(pwd) (ctrl+o to expand)", output)
        self.assertNotIn("○ Bash(pwd)", output)

    def test_tool_call_indicator_and_name_are_status_colored(self):
        console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )

        ToolCallBox.render(console, "run_shell", {"command": "pwd"}, status="success", permission="ask")
        ToolCallBox.render(console, "run_shell", {"command": "pwd"}, status="running", permission="allow")
        ToolCallBox.render(console, "run_shell", {"command": "pwd"}, status="error", permission="allow")
        html = console.export_html(inline_styles=True)

        self.assertIn(COLORS["success"], html)
        self.assertIn(COLORS["warning"], html)
        self.assertIn(COLORS["error"], html)
        self.assertIn(COLORS["accent_bright"].lower(), html.lower())
        self.assertIn("font-weight: bold", html)

    def test_tool_result_renders_single_line_with_corner_marker(self):
        console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())

        ToolResultBox.render(
            console,
            "run_shell",
            ToolResult(success=True, output="/home/administrator/secops_v2\n", execution_time=0.02),
        )
        output = console.export_text()

        self.assertIn("⎿  /home/administrator/secops_v2", output)
        self.assertNotIn("✓", output)

    def test_tool_result_shows_log_reference_for_long_supervised_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spool_path = Path(tmpdir) / "combined.log"
            spool_path.write_text("[STDOUT] done\n", encoding="utf-8")
            console = Console(width=200, record=True, force_terminal=False, file=io.StringIO())

            ToolResultBox.render(
                console,
                "run_shell",
                ToolResult(
                    success=True,
                    output="done\n",
                    execution_time=3.0,
                    metadata={"spool_path": str(spool_path)},
                ),
            )
            output = console.export_text()

        self.assertIn("⎿  done", output)
        self.assertIn(f"log: {spool_path}", output)

    def test_tool_result_hides_log_reference_for_fast_supervised_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spool_path = Path(tmpdir) / "combined.log"
            spool_path.write_text("[STDOUT] done\n", encoding="utf-8")
            console = Console(width=200, record=True, force_terminal=False, file=io.StringIO())

            ToolResultBox.render(
                console,
                "run_shell",
                ToolResult(
                    success=True,
                    output="done\n",
                    execution_time=0.02,
                    metadata={"spool_path": str(spool_path)},
                ),
            )
            output = console.export_text()

        self.assertIn("⎿  done", output)
        self.assertNotIn("log:", output)

    def test_tool_result_text_failure_uses_error_style(self):
        console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )

        ToolResultBox.render(
            console,
            "run_shell",
            ToolResult(success=True, output="❌ Command timed out after 300s and was stopped", execution_time=300),
        )
        output = console.export_text(clear=False)
        html = console.export_html(inline_styles=True)

        self.assertIn("⎿  ❌ Command timed out after 300s and was stopped", output)
        self.assertIn(COLORS["error"], html)

    def test_tool_result_vpn_failure_uses_error_style(self):
        console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )

        ToolResultBox.render(
            console,
            "connect_vpn_config",
            ToolResult(
                success=True,
                output=(
                    "VPN failed: /home/administrator/Downloads/lab.ovpn\n"
                    "PID: 9296\n"
                    "Status: TLS handshake timed out."
                ),
                execution_time=63.8,
            ),
        )
        output = console.export_text(clear=False)
        html = console.export_html(inline_styles=True)

        self.assertIn("⎿  VPN failed: /home/administrator/Downloads/lab.ovpn", output)
        self.assertIn(COLORS["error"], html)

    def test_renderer_tool_card_uses_error_status_for_text_failure(self):
        renderer = Renderer()
        renderer.console = Console(
            width=88,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )

        async def events():
            yield ToolCallEvent("run_shell", {"command": "sleep 300"}, "call_1", permission="allow")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(
                    success=True,
                    output="❌ Command timed out after 300s and was stopped",
                    execution_time=300,
                ),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text(clear=False)
        html = renderer.console.export_html(inline_styles=True)

        self.assertIn("● Bash(sleep 300) (ctrl+o to expand)", output)
        self.assertIn("⎿  ❌ Command timed out after 300s and was stopped", output)
        self.assertIn(COLORS["error"], html)
        self.assertNotIn(COLORS["success"], html)

    def test_renderer_tool_card_uses_error_status_for_vpn_failure_text(self):
        renderer = Renderer()
        renderer.console = Console(
            width=110,
            record=True,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )
        runtime = RuntimeState()

        async def events():
            yield ToolCallEvent(
                "connect_vpn_config",
                {"config_path": "/home/administrator/Downloads/lab.ovpn"},
                "call_1",
                permission="allow",
            )
            yield ToolResultEvent(
                "connect_vpn_config",
                ToolResult(
                    success=True,
                    output=(
                        "VPN failed: /home/administrator/Downloads/lab.ovpn\n"
                        "PID: 9296\n"
                        "Status: TLS handshake timed out."
                    ),
                    execution_time=63.8,
                ),
                "call_1",
            )

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))
        output = renderer.console.export_text(clear=False)
        html = renderer.console.export_html(inline_styles=True)

        self.assertIn("● ConnectVpnConfig(/home/administrator/Downloads/lab.ovpn) (ctrl+o to expand)", output)
        self.assertIn("⎿  VPN failed: /home/administrator/Downloads/lab.ovpn", output)
        self.assertIn(COLORS["error"], html)
        self.assertNotIn(COLORS["success"], html)
        self.assertIn(COLORS["error"], runtime.ctrl_o_anchor_collapsed)

    def test_tool_result_to_next_thought_uses_single_blank_gap(self):
        renderer = Renderer()
        renderer.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Need current time")
            yield ToolCallEvent("run_shell", {"command": "date"}, "call_1", permission="allow")
            yield TextEvent("", done=True)
            yield ToolResultEvent(
                "run_shell",
                ToolResult(
                    success=True,
                    output="Sat May 30 12:28:52 PM GMT 2026\n[Exit Code: 0]\n",
                    execution_time=0.03,
                ),
                "call_1",
            )
            yield ThinkingEvent("Use command output")
            yield TextEvent("Il est 12:28.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()

        self.assertIn("[Exit Code: 0]\n\n▸ Thought", output)
        self.assertNotIn("[Exit Code: 0]\n\n\n▸ Thought", output)
        self.assertNotIn("\n\n\n", output)

    def test_empty_mcp_config_is_ignored_and_invalid_json_is_friendly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = Path(tmpdir) / "empty.json"
            invalid = Path(tmpdir) / "invalid.json"
            empty.write_text("", encoding="utf-8")
            invalid.write_text("{", encoding="utf-8")

            state = load_mcp_config([("workspace", empty), ("workspace", invalid)])

        self.assertEqual(state.servers, [])
        self.assertEqual(len(state.errors), 1)
        self.assertIn("invalid JSON at line", state.errors[0])

    def test_nmap_progress_has_structured_percentages(self):
        events = []
        old_check_tool = network._check_tool
        old_run_cmd_streaming = network._run_cmd_streaming

        async def fake_run_cmd_streaming(cmd, timeout, progress=None, **_):
            if progress:
                await progress("0.1s · 1 lines · 9 chars · stdout: open port", 50)
            return "open port\nservice info", "", 0

        network._check_tool = lambda name: True
        network._run_cmd_streaming = fake_run_cmd_streaming
        token = _current_progress.set(lambda progress: events.append(progress))
        try:
            output = asyncio.run(network.nmap_scan("127.0.0.1", ports="top100"))
        finally:
            _current_progress.reset(token)
            network._check_tool = old_check_tool
            network._run_cmd_streaming = old_run_cmd_streaming

        self.assertIn("open port", output)
        self.assertEqual([event.percent for event in events], [5, 10, 20, 50, 95, 100])
        self.assertTrue(any("timeout 300s" in event.detail for event in events))

    def test_pre_tui_cli_help_exposes_backed_entrypoints(self):
        from secops_agent.main import app

        result = CliRunner().invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        for token in (
            "--print",
            "--prompt-interactive",
            "--print-timeout",
            "--sandbox",
            "--permission-mode",
            "--dangerously-skip-permissions",
            "--add-dir",
            "--log-file",
            "doctor",
        ):
            self.assertIn(token, result.output)
        lower_output = result.output.lower()
        self.assertNotIn("│ plugin", lower_output)
        self.assertNotIn("│ plugins", lower_output)
        self.assertNotIn("│ update", lower_output)
        self.assertNotIn("│ install", lower_output)
        self.assertNotIn("│ changelog", lower_output)

    def test_doctor_runs_without_starting_tui_or_requiring_api_key(self):
        from secops_agent.main import app

        result = CliRunner().invoke(app, ["doctor"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("SecOps Doctor", result.output)
        self.assertIn(f"Version: {__version__}", result.output)
        self.assertIn("Registered tools:", result.output)

    def test_print_prompt_helper_streams_without_tui(self):
        from secops_agent.main import _run_print_prompt

        class FakeAgent:
            max_iterations = 1
            llm = SimpleNamespace()

            def stream_response(self, prompt, attachments=None):
                self.prompt = prompt
                self.attachments = attachments

                async def events():
                    yield TextEvent("print response")

                return events()

        agent = FakeAgent()
        runtime = RuntimeState()
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            asyncio.run(_run_print_prompt(agent, runtime, "hello", 2.0))

        self.assertEqual(stdout.getvalue(), "print response\n")
        self.assertEqual(agent.prompt, "hello")


class SummarizeOutputLeadsWithKeyFactTests(unittest.TestCase):
    def test_collapsed_preview_skips_leading_banner_and_separators(self):
        from secops_agent.ui.tool_display import summarize_output

        output = (
            "========================================\n"
            "── TOOL DATA ──\n"
            "VPN active: connected via tun0 (10.10.14.7)\n"
            "Route: 10.10.10.0/24\n"
            "── END TOOL DATA ──\n"
        )

        summary = summarize_output(output, max_lines=4)

        # The fold opens on the key fact, not the rule or the TOOL DATA marker.
        self.assertEqual(summary["lines"][0], "VPN active: connected via tun0 (10.10.14.7)")
        self.assertNotIn("TOOL DATA", " ".join(summary["lines"]))
        self.assertNotIn("====", " ".join(summary["lines"]))

    def test_all_decoration_output_still_previews_something(self):
        from secops_agent.ui.tool_display import summarize_output

        summary = summarize_output("======\n------\n", max_lines=4)

        self.assertEqual(summary["visible_lines"], 2)


class StartThinkingDefensiveStopTests(unittest.TestCase):
    """R2 (latent): _start_thinking must defensively stop a spinner still
    running from a prior thinking phase, like _start_tool_feedback does, so two
    Live displays never stack (which would raise a rich LiveError)."""

    def test_second_start_thinking_stops_the_first_spinner(self):
        class _FakeSpinner:
            instances: list = []

            def __init__(self, *args, **kwargs):
                self.stopped = False
                self.started = False
                _FakeSpinner.instances.append(self)

            def start(self):
                self.started = True

            def stop(self):
                self.stopped = True

        renderer = Renderer()
        with patch("secops_agent.ui.renderer.ThinkingSpinner", _FakeSpinner):
            _FakeSpinner.instances.clear()
            renderer._start_thinking()
            renderer._start_thinking()  # would stack a 2nd Live without the fix

        self.assertEqual(len(_FakeSpinner.instances), 2)
        first, second = _FakeSpinner.instances
        self.assertTrue(first.stopped, "first thinking spinner was not defensively stopped")
        self.assertTrue(second.started)


class CollapsedToolCardExitCodeTests(unittest.TestCase):
    """P2-A (live agy diff 2026-07-05): agy renders a successful command's output
    directly on the ⎿ line (e.g. `⎿ /home/user/project`). Our tools append a
    trailing '[Exit Code: 0]' line that pushed single-line output into the metadata
    branch (`⎿ 30ms · 2 lines · …`). The collapsed summary must drop the zero-exit
    trailer so single-line output matches agy; a non-zero code stays diagnostic."""

    @staticmethod
    def _plain(result) -> list[str]:
        import re

        from secops_agent.ui.renderer import _build_collapsed_tool_result_lines

        return [
            re.sub(r"\[/?[a-z0-9_# ]+\]", "", line)
            for line in _build_collapsed_tool_result_lines(result, width=100)
        ]

    def test_single_line_success_shows_output_on_lima_line(self) -> None:
        from secops_agent.core.tools import ToolResult

        lines = self._plain(
            ToolResult(success=True, output="/home/user/project\n[Exit Code: 0]", execution_time=0.03)
        )
        self.assertEqual(len(lines), 1, f"expected one ⎿ line, got {lines!r}")
        self.assertIn("⎿  /home/user/project", lines[0])
        self.assertNotIn("chars", lines[0])          # not the metadata branch
        self.assertNotIn("Exit Code", lines[0])       # zero-exit trailer dropped

    def test_nonzero_exit_code_is_preserved(self) -> None:
        from secops_agent.core.tools import ToolResult

        joined = "\n".join(
            self._plain(ToolResult(success=True, output="boom\n[Exit Code: 1]", execution_time=0.03))
        )
        self.assertIn("[Exit Code: 1]", joined)


if __name__ == "__main__":
    unittest.main()
