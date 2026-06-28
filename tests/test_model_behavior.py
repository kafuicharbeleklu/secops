from __future__ import annotations

import unittest
import warnings
from types import SimpleNamespace

try:
    from secops_agent.core.llm import GeminiProvider, Message
    from secops_agent.core.model_catalog import (
        DEFAULT_MODEL,
        GEMMA_FAST_MODEL,
        GEMMA_STRATEGY_MODEL,
        adaptive_thinking_level,
        get_model_profile,
    )
    from secops_agent.core.tools import ToolCategory, ToolRegistry
    from google.genai import types as genai_types
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard for bare system Python.
    raise unittest.SkipTest("LLM dependencies are not installed") from exc


class ModelBehaviorTests(unittest.TestCase):
    def test_model_profiles_do_not_override_global_generation_defaults(self):
        for model in (DEFAULT_MODEL, GEMMA_FAST_MODEL, GEMMA_STRATEGY_MODEL):
            profile = get_model_profile(model)
            self.assertIsNone(profile.temperature)
            self.assertIsNone(profile.max_output_tokens)

    def test_gemma_fast_keeps_thinking_off_by_default(self):
        profile = get_model_profile(GEMMA_FAST_MODEL)

        thinking = adaptive_thinking_level(profile, prompt="continue", context={})

        self.assertEqual(thinking, "")
        self.assertTrue(profile.supports_thinking)

    def test_gemma_fast_does_not_escalate_thinking_from_prompt_markers(self):
        profile = get_model_profile(GEMMA_FAST_MODEL)

        thinking = adaptive_thinking_level(profile, prompt="explique pourquoi ce scan echoue", context={})

        self.assertEqual(thinking, "")

    def test_strategy_gemma_uses_supported_high_thinking(self):
        profile = get_model_profile(GEMMA_STRATEGY_MODEL)

        self.assertEqual(profile.thinking_level, "high")
        self.assertTrue(profile.supports_thinking)

    def test_hosted_google_model_profiles_expose_image_and_search_capabilities(self):
        for model in (DEFAULT_MODEL, GEMMA_FAST_MODEL, GEMMA_STRATEGY_MODEL):
            profile = get_model_profile(model)

            self.assertTrue(profile.supports_image_input)
            self.assertTrue(profile.supports_google_search)

    def test_system_instruction_preserves_terminal_response_contract(self):
        provider = GeminiProvider(api_key="", model_name="gemini")

        instruction = provider._system_instruction()

        self.assertIn("same concise terminal-agent interaction style", instruction)
        self.assertIn("Do not expose hidden reasoning", instruction)
        self.assertIn("Do not restate the user's task", instruction)
        self.assertIn("Emphasise key facts", instruction)
        self.assertIn("`code` for values", instruction)
        self.assertIn("A closed question gets one direct line", instruction)
        self.assertIn("dump Mission State", instruction)

    def test_gemma_system_instruction_preserves_same_terminal_contract(self):
        provider = GeminiProvider(api_key="", model_name="gemma")

        instruction = provider._system_instruction()

        self.assertIn("same concise terminal-agent interaction style", instruction)
        self.assertIn("elite Security Operations", instruction)
        self.assertIn("Use tools only when they materially improve accuracy", instruction)
        self.assertIn("Emphasise key facts", instruction)

    def test_gemma_user_message_is_not_rewritten_by_model_adapter(self):
        provider = GeminiProvider(api_key="", model_name="gemma")

        contents = provider._prepare_contents([Message(role="user", content="continue")])
        text = contents[0].parts[0].text

        self.assertEqual(text, "continue")

    def test_gemini_user_message_is_not_rewritten_by_model_adapter(self):
        provider = GeminiProvider(api_key="", model_name="gemini")

        contents = provider._prepare_contents([Message(role="user", content="continue")])
        text = contents[0].parts[0].text

        self.assertEqual(text, "continue")

    def test_disallowed_historical_tool_parts_are_serialized_as_text(self):
        provider = GeminiProvider(api_key="", model_name="gemini")
        messages = [
            Message(
                role="model",
                content="",
                tool_calls=[{"name": "execute_bash", "arguments": {"command": "pwd"}}],
            ),
            Message(
                role="tool",
                content="",
                tool_results=[{"name": "execute_bash", "content": "Tool not registered"}],
            ),
        ]

        contents = provider._prepare_contents(messages, allowed_function_names=set())
        rendered = "\n".join(
            getattr(part, "text", "") or ""
            for content in contents
            for part in content.parts
        )

        self.assertIn("Archived tool call: execute_bash", rendered)
        self.assertIn("Archived tool result: execute_bash", rendered)

    def test_message_serialization_preserves_attachment_descriptors(self):
        message = Message(
            role="user",
            content="analyse image",
            attachments=[{"type": "image", "path": "/tmp/screen.png", "mime_type": "image/png"}],
        )

        restored = Message.from_dict(message.to_dict())

        self.assertEqual(restored.attachments, message.attachments)

    def test_visible_text_extractor_skips_thought_parts(self):
        parts = [
            SimpleNamespace(text="internal draft", thought=True),
            SimpleNamespace(text="final answer", thought=False),
        ]

        self.assertEqual(GeminiProvider._visible_text_from_parts(parts), "final answer")

    def test_visible_text_extractor_concatenates_visible_parts(self):
        parts = [
            SimpleNamespace(text="final ", thought=False),
            SimpleNamespace(text="answer", thought=False),
        ]

        self.assertEqual(GeminiProvider._visible_text_from_parts(parts), "final answer")

    def test_gemma_high_preset_enables_high_thinking(self):
        provider = GeminiProvider(api_key="", model_name="gemma-high")

        self.assertEqual(provider.model_name, GEMMA_FAST_MODEL)
        self.assertEqual(provider.current_thinking_level, "high")

    def test_gemma_31b_off_preset_disables_default_high_thinking(self):
        provider = GeminiProvider(api_key="", model_name="gemma-31b-off")

        self.assertEqual(provider.model_name, GEMMA_STRATEGY_MODEL)
        self.assertEqual(provider.current_thinking_level, "off")

    def test_gemma_default_preset_clears_previous_thinking_override(self):
        provider = GeminiProvider(api_key="", model_name="gemma-31b-off")

        _, profile = provider.set_model("gemma-31b")

        self.assertEqual(profile.thinking_level, "high")
        self.assertEqual(provider.current_thinking_level, "high")

    def test_gemma_low_medium_thinking_overrides_are_rejected(self):
        provider = GeminiProvider(api_key="", model_name="gemma")

        with self.assertRaisesRegex(ValueError, "Gemma 4 supports only"):
            provider.set_model("gemma", thinking_level="medium")

    def test_tool_schema_conversion_handles_rich_lab_parameters(self):
        provider = GeminiProvider(api_key="", model_name="gemma")
        profile = provider.prepare_for_prompt("Find directories on the web server using GoBuster")

        config = provider._build_config(
            genai_types,
            profile,
            tools_schema=[
                {
                    "name": "lab_probe",
                    "description": "Probe an authorized lab target",
                    "parameters": {
                        "url": {"type": "string", "required": True},
                        "threads": {"type": "integer", "required": False},
                        "follow_redirects": {"type": "boolean", "required": False},
                        "modes": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["quick", "deep"]},
                            "required": False,
                        },
                        "options": {
                            "type": "object",
                            "properties": {
                                "wordlist": {"type": "string"},
                                "extensions": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                    },
                }
            ],
        )

        declarations = config.tools[0].function_declarations
        params = declarations[0].parameters.properties
        self.assertEqual(params["url"].type, genai_types.Type.STRING)
        self.assertEqual(params["threads"].type, genai_types.Type.INTEGER)
        self.assertEqual(params["follow_redirects"].type, genai_types.Type.BOOLEAN)
        self.assertEqual(params["modes"].type, genai_types.Type.ARRAY)
        self.assertEqual(params["modes"].items.enum, ["quick", "deep"])
        self.assertEqual(params["options"].type, genai_types.Type.OBJECT)
        self.assertIn("url", declarations[0].parameters.required)

    def test_tool_schema_conversion_handles_registry_object_schema(self):
        registry = ToolRegistry()
        registry.register(
            name="lab_probe",
            description="Probe an authorized lab target",
            category=ToolCategory.RECON,
            parameters={
                "url": {"type": "string", "required": True},
                "threads": {"type": "integer", "required": False, "default": 10},
                "follow_redirects": {"type": "boolean", "required": False, "default": True},
            },
            func=lambda **_: "ok",
        )
        provider = GeminiProvider(api_key="", model_name="gemma")
        profile = provider.prepare_for_prompt("Find directories on the web server using GoBuster")

        config = provider._build_config(
            genai_types,
            profile,
            tools_schema=registry.get_tools_schema(),
        )

        declarations = config.tools[0].function_declarations
        params = declarations[0].parameters.properties
        self.assertEqual(set(params), {"url", "threads", "follow_redirects"})
        self.assertEqual(params["url"].type, genai_types.Type.STRING)
        self.assertEqual(params["threads"].type, genai_types.Type.INTEGER)
        self.assertEqual(params["follow_redirects"].type, genai_types.Type.BOOLEAN)
        self.assertEqual(declarations[0].parameters.required, ["url"])

    def test_invalid_function_names_are_not_sent_to_gemini(self):
        provider = GeminiProvider(api_key="", model_name="gemma")
        profile = provider.prepare_for_prompt("Run lab tool")

        config = provider._build_config(
            genai_types,
            profile,
            tools_schema=[
                {
                    "name": "bad tool name",
                    "description": "Invalid function name",
                    "parameters": {"target": {"type": "string", "required": True}},
                }
            ],
        )

        self.assertFalse(config.tools)

    def test_known_google_sdk_warnings_are_suppressed(self):
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with GeminiProvider._suppress_known_sdk_warnings():
                warnings.warn(
                    "Tools at indices [0] are not compatible with automatic function calling (AFC). AFC is disabled.",
                    UserWarning,
                )
                warnings.warn("MALFORMED_RESPONSE is not a valid FinishReason", UserWarning)
                warnings.warn("other warning", UserWarning)

        self.assertEqual([str(item.message) for item in captured], ["other warning"])

    def test_invalid_argument_tool_errors_are_compact(self):
        message = GeminiProvider._format_api_error(
            RuntimeError("400 INVALID_ARGUMENT. AFC details and provider stack trace"),
            tools_schema=[{"name": "dir_brute", "parameters": {}}],
        )

        self.assertIn("model provider rejected the tool-call request", message)
        self.assertNotIn("AFC details", message)


if __name__ == "__main__":
    unittest.main()
