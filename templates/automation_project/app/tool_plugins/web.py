"""Web enumeration tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="enumerate_web",
            description=(
                "Enumerer un service web: decouverte de repertoires (gobuster) "
                "et scan de vulnerabilites (nikto) en un seul appel."
            ),
            arguments={
                "target": "IP ou domaine de la cible",
                "port": "port HTTP (defaut: 80)",
            },
            handler=lambda args: executor._enumerate_web(
                args.get("target", ""),
                args.get("port", "80"),
            ),
            phases=("enumeration",),
            risk="medium",
        ),
    )
