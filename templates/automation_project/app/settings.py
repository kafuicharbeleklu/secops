import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from app.model_router import DEFAULT_MODEL


DEFAULT_PROFILE = "LOCAL"
DEFAULT_WORKSPACE_DIR = "workspace"
DEFAULT_LOG_DIR = "logs"
DEFAULT_CONFIG_DIR = "config"
APP_BASE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_BASE_DIR.parents[1]
PROJECT_ENV_FILE = REPO_ROOT / ".env"

GEMINI_API_ENV_VAR = "GEMINI_API_KEY"
GOOGLE_API_ENV_VAR = "GOOGLE_API_KEY"
GEMINI_MODEL_ENV_VAR = "GEMINI_MODEL"
DEFAULT_GEMINI_MODEL = DEFAULT_MODEL
SUPPORTED_GEMINI_API_ENV_VARS = (
    GEMINI_API_ENV_VAR,
    GOOGLE_API_ENV_VAR,
)

RECOMMENDED_TARGET_PLAN = [
    "PRECHECK",
    "INSTALL",
    "CONFIG",
    "VERIFY",
]


_ENV_LOADED = False


@dataclass(frozen=True)
class GeminiRuntimeConfig:
    env_file: Path
    api_key_env_var: str
    api_key_present: bool
    api_key: str
    model: str


def _parse_env_value(raw_value):
    candidate = raw_value.strip()
    if not candidate:
        return ""

    try:
        parsed = shlex.split(candidate, comments=True, posix=True)
    except ValueError:
        parsed = None

    if parsed:
        if len(parsed) == 1:
            return parsed[0]
        return " ".join(parsed)

    if " #" in candidate:
        candidate = candidate.split(" #", 1)[0].rstrip()

    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in ("'", '"'):
        return candidate[1:-1]
    return candidate


def load_project_env(env_file=PROJECT_ENV_FILE, override=False):
    global _ENV_LOADED

    env_path = Path(env_file)
    if _ENV_LOADED and not override:
        return {}

    if not env_path.exists():
        _ENV_LOADED = True
        return {}

    loaded = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        if "=" not in stripped:
            continue

        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = _parse_env_value(raw_value)
        if override or key not in os.environ:
            os.environ[key] = value
        loaded[key] = value

    _ENV_LOADED = True
    return loaded


def get_gemini_api_env_hint():
    return " ou ".join(SUPPORTED_GEMINI_API_ENV_VARS)


def _resolve_gemini_api_key():
    for env_var in SUPPORTED_GEMINI_API_ENV_VARS:
        value = os.getenv(env_var, "").strip()
        if value:
            return env_var, value
    return GEMINI_API_ENV_VAR, ""


def get_gemini_runtime_config():
    load_project_env()
    model = os.getenv(GEMINI_MODEL_ENV_VAR, DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL
    api_key_env_var, api_key = _resolve_gemini_api_key()
    return GeminiRuntimeConfig(
        env_file=PROJECT_ENV_FILE,
        api_key_env_var=api_key_env_var,
        api_key_present=bool(api_key),
        api_key=api_key,
        model=model,
    )
