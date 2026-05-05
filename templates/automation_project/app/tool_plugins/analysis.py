"""Service analysis tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="analyze_service",
            description=(
                "Pipeline complet d'analyse d'un service detecte: recherche CVE (NVD), "
                "recherche d'exploits (searchsploit), et scoring de risque. "
                "Combine search_cve + search_exploit en un seul appel."
            ),
            arguments={
                "service": "nom du service (ex: apache, openssh)",
                "version": "version detectee",
                "port": "port du service (optionnel)",
            },
            handler=lambda args: executor._analyze_service(
                args.get("service", ""),
                args.get("version", ""),
                args.get("port", ""),
            ),
            phases=("enumeration", "exploitation"),
            risk="medium",
        ),
    )
