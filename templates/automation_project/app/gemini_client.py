from dataclasses import dataclass

from app.settings import get_gemini_api_env_hint, get_gemini_runtime_config, load_project_env


class GeminiClientError(RuntimeError):
    pass


class GeminiConfigurationError(GeminiClientError):
    pass


class GeminiDependencyError(GeminiClientError):
    pass


class GeminiRequestError(GeminiClientError):
    pass


@dataclass(frozen=True)
class GeminiTextResult:
    model: str
    text: str


@dataclass(frozen=True)
class GeminiToolDecisionResult:
    model: str
    text: str
    tool_name: str | None = None
    arguments: dict | None = None
    thought: str = ""
    prompt_chars: int = 0


def _coerce_response_text(response):
    text = getattr(response, "text", None)
    if text:
        return text.strip()

    candidates = getattr(response, "candidates", None) or []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        parts = getattr(content, "parts", None) or []
        fragments = []
        for part in parts:
            fragment = getattr(part, "text", None)
            if fragment:
                fragments.append(fragment)
        if fragments:
            return "\n".join(fragments).strip()
    return ""


def _coerce_function_call(response):
    function_calls = getattr(response, "function_calls", None) or []
    if function_calls:
        call = function_calls[0]
        name = getattr(call, "name", "") or ""
        args = getattr(call, "args", {}) or {}
        if not isinstance(args, dict):
            try:
                args = dict(args)
            except (TypeError, ValueError):
                args = {}
        return name, args
    return "", {}


def _describe_request_error(exc):
    message = str(exc).strip() or exc.__class__.__name__
    lowered = message.lower()

    if "permission_denied" in lowered or "403" in lowered:
        return (
            "Acces refuse par l'API Gemini (403). "
            "Verifie la cle API, l'acces au modele demande et le statut du projet Google."
        )

    if "api key" in lowered and ("invalid" in lowered or "not valid" in lowered):
        return "Cle API Gemini invalide. Verifie la valeur chargee depuis le .env."

    return message


class GeminiClient:
    def __init__(self, model=None):
        load_project_env()
        runtime = get_gemini_runtime_config()
        if not runtime.api_key_present:
            raise GeminiConfigurationError(
                f"Aucune cle API detectee. Verifie {get_gemini_api_env_hint()} dans {runtime.env_file.name}."
            )

        try:
            from google import genai
        except ImportError as exc:
            raise GeminiDependencyError(
                "Le package google-genai est requis. Relance setup_secops_agent."
            ) from exc

        self.model = model or runtime.model
        self._client = genai.Client(api_key=runtime.api_key)

    def generate_text(
        self,
        prompt,
        *,
        temperature=None,
        max_output_tokens=None,
        thinking_level="",
    ):
        try:
            kwargs = {"model": self.model, "contents": prompt}
            config = self._build_generate_config(
                temperature=temperature,
                max_output_tokens=max_output_tokens,
                thinking_level=thinking_level,
            )
            if config is not None:
                kwargs["config"] = config
            response = self._client.models.generate_content(**kwargs)
        except Exception as exc:
            raise GeminiRequestError(_describe_request_error(exc)) from exc

        text = _coerce_response_text(response)
        if not text:
            raise GeminiRequestError("Reponse vide du modele Gemini.")
        return GeminiTextResult(model=self.model, text=text)

    def generate_tool_decision(
        self,
        prompt,
        *,
        system_prompt,
        tool_specs,
        temperature=None,
        max_output_tokens=None,
        thinking_level="",
    ):
        try:
            from google.genai import types

            declarations = [
                self._function_declaration(types, spec)
                for spec in tool_specs
            ]
            config = self._build_generate_config(
                temperature=temperature,
                max_output_tokens=max_output_tokens,
                thinking_level=thinking_level,
                system_prompt=system_prompt,
                tools=[
                    types.Tool(functionDeclarations=declarations)
                ] if declarations else None,
                tool_config=self._tool_config(types, declarations),
            )
            kwargs = {"model": self.model, "contents": prompt}
            if config is not None:
                kwargs["config"] = config
            response = self._client.models.generate_content(**kwargs)
        except Exception as exc:
            raise GeminiRequestError(_describe_request_error(exc)) from exc

        tool_name, arguments = _coerce_function_call(response)
        text = _coerce_response_text(response)
        if not tool_name and not text:
            raise GeminiRequestError("Reponse vide du modele Gemini.")
        return GeminiToolDecisionResult(
            model=self.model,
            text=text,
            tool_name=tool_name or None,
            arguments=arguments,
            thought=f"Appel d'outil natif: {tool_name}" if tool_name else "",
        )

    def _build_generate_config(
        self,
        *,
        temperature=None,
        max_output_tokens=None,
        thinking_level="",
        system_prompt=None,
        tools=None,
        tool_config=None,
    ):
        try:
            from google.genai import types
        except (ImportError, AttributeError):
            return None

        kwargs = {}
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_output_tokens is not None:
            kwargs["maxOutputTokens"] = max_output_tokens
        if system_prompt:
            kwargs["systemInstruction"] = system_prompt
        if tools:
            kwargs["tools"] = tools
        if tool_config is not None:
            kwargs["toolConfig"] = tool_config
        thinking_config = self._thinking_config(types, thinking_level)
        if thinking_config is not None:
            kwargs["thinkingConfig"] = thinking_config
        if not kwargs:
            return None
        return types.GenerateContentConfig(**kwargs)

    @staticmethod
    def _thinking_config(types, thinking_level):
        level = (thinking_level or "").strip().upper()
        if not level:
            return None
        enum_value = getattr(types.ThinkingLevel, level, None)
        if enum_value is None:
            return None
        return types.ThinkingConfig(thinkingLevel=enum_value)

    @staticmethod
    def _tool_config(types, declarations):
        if not declarations:
            return None
        mode = getattr(types.FunctionCallingConfigMode, "AUTO", None)
        if mode is None:
            return None
        return types.ToolConfig(
            functionCallingConfig=types.FunctionCallingConfig(mode=mode)
        )

    @staticmethod
    def _function_declaration(types, spec):
        properties = {}
        required = []
        for key, description in (spec.arguments or {}).items():
            properties[key] = types.Schema(
                type=types.Type.STRING,
                description=str(description)[:200],
            )
            required.append(key)
        parameters = types.Schema(
            type=types.Type.OBJECT,
            properties=properties,
            required=required or None,
        )
        return types.FunctionDeclaration(
            name=spec.name,
            description=str(spec.description)[:500],
            parameters=parameters,
        )
