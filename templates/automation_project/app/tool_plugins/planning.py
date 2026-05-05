"""Attack planning tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="plan_attack",
            description=(
                "Generer un plan d'attaque structure base sur les findings actuels. "
                "Produit une liste d'etapes ordonnees avec priorites et dependances."
            ),
            arguments={},
            handler=lambda args: executor._plan_attack(),
            phases=("recon", "enumeration", "exploitation", "post_exploitation"),
        ),
        make_plugin(
            name="route_services",
            description=(
                "Analyser les services decouverts et generer des playbooks d'analyse "
                "specifiques a chaque service (web, SSH, SMB, DB, etc.). "
                "A utiliser apres un scan nmap pour obtenir des recommandations ciblees."
            ),
            arguments={},
            handler=lambda args: executor._route_services(),
            phases=("enumeration", "exploitation"),
        ),
    )
