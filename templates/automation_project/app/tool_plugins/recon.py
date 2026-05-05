"""Reconnaissance tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="scan_target",
            description=(
                "Lancer un scan de reconnaissance standard sur une cible. "
                "Construit automatiquement la commande nmap optimale."
            ),
            arguments={
                "target": "IP, domaine ou URL de la cible",
                "mode": "quick (top 1000), full (tous ports), ou stealth (SYN scan)",
            },
            handler=lambda args: executor._scan_target(
                args.get("target", ""),
                args.get("mode", "quick"),
            ),
            phases=("recon",),
            risk="medium",
        ),
    )
