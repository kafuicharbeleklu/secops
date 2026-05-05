"""Vulnerability intelligence tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="search_cve",
            description="Chercher des CVEs connues pour un service et une version detectes.",
            arguments={
                "service": "nom du service (ex: apache, openssh)",
                "version": "version (optionnel)",
            },
            handler=lambda args: executor._search_cve(
                args.get("service", ""),
                args.get("version", ""),
            ),
            phases=("enumeration", "exploitation"),
        ),
        make_plugin(
            name="search_exploit",
            description=(
                "Rechercher des exploits publics pour un service ou un produit "
                "via searchsploit (ExploitDB local)."
            ),
            arguments={"query": "service, produit ou terme de recherche"},
            handler=lambda args: executor._search_exploit(args.get("query", "")),
            phases=("exploitation",),
            risk="medium",
        ),
    )
