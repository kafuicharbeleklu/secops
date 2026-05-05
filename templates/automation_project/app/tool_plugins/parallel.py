"""Parallel execution tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="execute_parallel",
            description=(
                "Executer plusieurs etapes independantes du plan d'attaque en parallele. "
                "Identifie automatiquement les steps sans dependances et les lance simultanement."
            ),
            arguments={},
            handler=lambda args: executor._execute_parallel(),
            phases=("enumeration", "exploitation"),
            risk="medium",
        ),
    )
