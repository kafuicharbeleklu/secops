"""Pentest tool installation request plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="suggest_pentest_tools",
            description=(
                "Lister les outils pentest disponibles et recommandes "
                "pour la phase et le type de cible actuels."
            ),
            arguments={
                "phase": "phase pentest (optionnel)",
                "target_type": "type de cible (optionnel)",
            },
            handler=lambda args: executor.suggest_pentest_tools(
                args.get("phase", ""),
                args.get("target_type", ""),
            ),
            phases=("recon", "enumeration", "exploitation", "post_exploitation"),
        ),
        make_plugin(
            name="list_findings",
            description="Lister les decouvertes accumulees pendant la session.",
            arguments={},
            handler=lambda args: executor.list_findings(),
            phases=("recon", "enumeration", "exploitation", "post_exploitation", "reporting"),
        ),
        make_plugin(
            name="install_pentest_tool",
            description="Declencher l'installation automatique d'un outil manquant.",
            arguments={"tool_name": "nom de l'outil a installer"},
            handler=lambda args: executor._trigger_install(args.get("tool_name", "")),
            phases=("recon", "enumeration", "exploitation", "post_exploitation"),
            risk="medium",
        ),
        make_plugin(
            name="install_pentest_tools",
            description=(
                "Declencher l'installation automatique de plusieurs outils manquants "
                "en une seule validation utilisateur. A utiliser quand la demande "
                "contient plusieurs noms d'outils."
            ),
            arguments={"tool_names": "liste de noms d'outils a installer"},
            handler=lambda args: executor._trigger_install_many(args.get("tool_names", [])),
            phases=("recon", "enumeration", "exploitation", "post_exploitation"),
            risk="medium",
        ),
    )
