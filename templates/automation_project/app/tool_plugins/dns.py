"""DNS enumeration tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="enumerate_dns",
            description=(
                "Enumerer les enregistrements DNS et sous-domaines d'un domaine. "
                "Utilise dig, host ou dnsenum selon disponibilite."
            ),
            arguments={"domain": "domaine cible"},
            handler=lambda args: executor._enumerate_dns(args.get("domain", "")),
            phases=("recon", "enumeration"),
            risk="medium",
        ),
    )
