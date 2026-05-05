"""Local command execution tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    command_tools_enabled = lambda: executor.command_permission_mode != "deny"
    return (
        make_plugin(
            name="execute_command",
            description="Executer une commande locale, avec validation utilisateur si necessaire.",
            arguments={"command": "commande", "reason": "justification"},
            handler=lambda args: executor.execute_command(
                args.get("command", ""),
                args.get("reason", ""),
            ),
            enabled=command_tools_enabled,
            phases=("recon", "enumeration", "exploitation", "post_exploitation", "reporting"),
            risk="medium",
        ),
        make_plugin(
            name="execute_admin_command",
            description=(
                "Executer une commande locale d'administration systeme avec "
                "validation utilisateur et sudo interactif si necessaire."
            ),
            arguments={"command": "commande admin", "reason": "justification"},
            handler=lambda args: executor.execute_admin_command(
                args.get("command", ""),
                args.get("reason", ""),
            ),
            enabled=command_tools_enabled,
            phases=("recon", "enumeration", "exploitation", "post_exploitation", "reporting"),
            risk="high",
        ),
    )
