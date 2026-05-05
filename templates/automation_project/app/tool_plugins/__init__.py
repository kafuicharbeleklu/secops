"""Built-in SECOPS tool plugin registry."""

from app.tool_plugins import (
    analysis,
    command,
    core,
    credentials,
    dns,
    evidence,
    exploit,
    install,
    intelligence,
    parallel,
    planning,
    recon,
    web,
)


PLUGIN_MODULES = (
    core,
    command,
    install,
    recon,
    intelligence,
    web,
    credentials,
    dns,
    evidence,
    analysis,
    planning,
    exploit,
    parallel,
)


def load_builtin_tool_plugins(executor) -> dict:
    plugins = {}
    for module in PLUGIN_MODULES:
        for plugin in module.register(executor):
            name = plugin.spec.name
            if name in plugins:
                raise ValueError(f"Plugin d'outil duplique: {name}")
            plugins[name] = plugin
    return plugins
