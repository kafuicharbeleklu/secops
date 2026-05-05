"""Tool plugin contract used by the SECOPS tool executor."""

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments: dict


@dataclass(frozen=True)
class ToolPlugin:
    """Runtime tool plugin bound to a spec, handler and enablement rule."""

    spec: ToolSpec
    handler: Callable[[dict], object]
    enabled: Callable[[], bool] | None = None
    phases: tuple[str, ...] = ()
    risk: str = "low"

    def is_enabled(self) -> bool:
        if self.enabled is None:
            return True
        return bool(self.enabled())

    def run(self, arguments):
        if not isinstance(arguments, dict):
            arguments = {}
        return self.handler(arguments)


def make_plugin(
    *,
    name: str,
    description: str,
    arguments: dict,
    handler: Callable[[dict], object],
    enabled: Callable[[], bool] | None = None,
    phases=(),
    risk: str = "low",
) -> ToolPlugin:
    return ToolPlugin(
        spec=ToolSpec(name=name, description=description, arguments=arguments),
        handler=handler,
        enabled=enabled,
        phases=tuple(phases),
        risk=risk,
    )
