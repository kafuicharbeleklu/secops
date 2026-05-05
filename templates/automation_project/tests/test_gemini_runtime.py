import os
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import settings
from app.gemini_client import GeminiClient
from app.tool_executor import ToolSpec


class GeminiRuntimeConfigTests(unittest.TestCase):
    def test_prefers_gemini_api_key(self):
        with patch.dict(
            os.environ,
            {
                settings.GEMINI_API_ENV_VAR: "direct-key",
                settings.GOOGLE_API_ENV_VAR: "fallback-key",
            },
            clear=True,
        ):
            with patch.object(settings, "load_project_env", return_value={}):
                runtime = settings.get_gemini_runtime_config()

        self.assertTrue(runtime.api_key_present)
        self.assertEqual(runtime.api_key_env_var, settings.GEMINI_API_ENV_VAR)
        self.assertEqual(runtime.api_key, "direct-key")

    def test_falls_back_to_google_api_key(self):
        with patch.dict(
            os.environ,
            {settings.GOOGLE_API_ENV_VAR: "google-key"},
            clear=True,
        ):
            with patch.object(settings, "load_project_env", return_value={}):
                runtime = settings.get_gemini_runtime_config()

        self.assertTrue(runtime.api_key_present)
        self.assertEqual(runtime.api_key_env_var, settings.GOOGLE_API_ENV_VAR)
        self.assertEqual(runtime.api_key, "google-key")


class GeminiClientTests(unittest.TestCase):
    def test_passes_api_key_to_google_genai_client(self):
        runtime = settings.GeminiRuntimeConfig(
            env_file=Path(".env"),
            api_key_env_var=settings.GEMINI_API_ENV_VAR,
            api_key_present=True,
            api_key="secret-key",
            model="gemini-2.5-flash",
        )
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured["client_kwargs"] = kwargs
                self.models = SimpleNamespace(
                    generate_content=lambda **request: (
                        captured.setdefault("request_kwargs", request),
                        SimpleNamespace(text="ok"),
                    )[1]
                )

        fake_genai = types.ModuleType("google.genai")
        fake_genai.Client = FakeClient
        fake_google = types.ModuleType("google")
        fake_google.genai = fake_genai

        with patch("app.gemini_client.load_project_env", return_value={}):
            with patch("app.gemini_client.get_gemini_runtime_config", return_value=runtime):
                with patch.dict(
                    sys.modules,
                    {"google": fake_google, "google.genai": fake_genai},
                    clear=False,
                ):
                    client = GeminiClient()
                    result = client.generate_text("hello")

        self.assertEqual(captured["client_kwargs"], {"api_key": "secret-key"})
        self.assertEqual(captured["request_kwargs"]["model"], "gemini-2.5-flash")
        self.assertEqual(captured["request_kwargs"]["contents"], "hello")
        self.assertEqual(result.text, "ok")

    def test_generate_tool_decision_uses_native_function_declarations(self):
        runtime = settings.GeminiRuntimeConfig(
            env_file=Path(".env"),
            api_key_env_var=settings.GEMINI_API_ENV_VAR,
            api_key_present=True,
            api_key="secret-key",
            model="gemma-4-26b-a4b-it",
        )
        captured = {}

        class FakeFunctionCall:
            name = "scan_target"
            args = {"target": "10.10.10.10", "mode": "quick"}

        class FakeClient:
            def __init__(self, **kwargs):
                captured["client_kwargs"] = kwargs
                self.models = SimpleNamespace(generate_content=self.generate_content)

            def generate_content(self, **request):
                captured["request_kwargs"] = request
                return SimpleNamespace(function_calls=[FakeFunctionCall()], text="")

        class FakeModelType:
            STRING = "STRING"
            OBJECT = "OBJECT"

        class FakeFunctionCallingConfigMode:
            AUTO = "AUTO"

        class FakeTypeFactory:
            Type = FakeModelType
            FunctionCallingConfigMode = FakeFunctionCallingConfigMode

            class GenerateContentConfig:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class Tool:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class FunctionDeclaration:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class Schema:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class ToolConfig:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class FunctionCallingConfig:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

        fake_genai = types.ModuleType("google.genai")
        fake_google = types.ModuleType("google")

        fake_genai.Client = FakeClient
        fake_genai.types = FakeTypeFactory
        fake_google.genai = fake_genai

        with patch("app.gemini_client.load_project_env", return_value={}):
            with patch("app.gemini_client.get_gemini_runtime_config", return_value=runtime):
                with patch.dict(
                    sys.modules,
                    {"google": fake_google, "google.genai": fake_genai},
                    clear=False,
                ):
                    client = GeminiClient()
                    result = client.generate_tool_decision(
                        "scan la cible",
                        system_prompt="systeme",
                        tool_specs=[
                            ToolSpec(
                                name="scan_target",
                                description="scan",
                                arguments={"target": "cible", "mode": "mode"},
                            )
                        ],
                    )

        self.assertEqual(captured["request_kwargs"]["model"], "gemma-4-26b-a4b-it")
        self.assertEqual(captured["request_kwargs"]["contents"], "scan la cible")
        self.assertIn("config", captured["request_kwargs"])
        self.assertEqual(result.tool_name, "scan_target")
        self.assertEqual(result.arguments["target"], "10.10.10.10")


if __name__ == "__main__":
    unittest.main()
