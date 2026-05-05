"""Evidence capture tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="capture_evidence",
            description=(
                "Sauvegarder une preuve (output, capture, note) dans workspace/evidence/ "
                "avec horodatage pour le rapport final."
            ),
            arguments={
                "title": "titre court de la preuve",
                "content": "contenu de la preuve (texte, output de commande)",
                "source_tool": "outil source (optionnel)",
            },
            handler=lambda args: executor._capture_evidence(
                args.get("title", ""),
                args.get("content", ""),
                args.get("source_tool", ""),
            ),
            phases=("enumeration", "exploitation", "post_exploitation", "reporting"),
        ),
    )
