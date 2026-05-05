"""Credential validation tool plugins."""

from app.tool_plugin import make_plugin


def register(executor):
    return (
        make_plugin(
            name="test_credentials",
            description=(
                "Tester des credentials sur un service specifique (SSH, FTP, SMB). "
                "Construit automatiquement la commande appropriee."
            ),
            arguments={
                "target": "IP ou domaine",
                "service": "ssh, ftp, smb, ou http",
                "username": "nom d'utilisateur",
                "password": "mot de passe",
            },
            handler=lambda args: executor._test_credentials(
                args.get("target", ""),
                args.get("service", ""),
                args.get("username", ""),
                args.get("password", ""),
            ),
            phases=("enumeration", "exploitation", "post_exploitation"),
            risk="high",
        ),
    )
