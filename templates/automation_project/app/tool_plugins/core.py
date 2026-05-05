"""Core knowledge and filesystem tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="query_knowledge",
            description=(
                "Chercher un cas analogue dans la base de connaissance locale si "
                "une analogie de lab ou de precedent est utile."
            ),
            arguments={"query": "chaine de recherche"},
            handler=lambda args: executor.query_knowledge(args.get("query", "")),
            phases=("recon", "enumeration", "exploitation", "post_exploitation", "reporting"),
        ),
        make_plugin(
            name="read_file",
            description="Lire un fichier depuis workspace/ ou knowledge/.",
            arguments={"path": "chemin relatif ou absolu autorise"},
            handler=lambda args: executor.read_file(args.get("path", "")),
            phases=("recon", "enumeration", "exploitation", "post_exploitation", "reporting"),
        ),
        make_plugin(
            name="write_file",
            description="Ecrire une note ou un resultat dans workspace/.",
            arguments={"path": "chemin relatif", "content": "contenu texte"},
            handler=lambda args: executor.write_file(
                args.get("path", ""),
                args.get("content", ""),
            ),
            phases=("reporting",),
        ),
    )
