from datetime import datetime
from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.shell_template import BaseTerminalShell, ShellChromeConfig, StatusEntry


COMMAND_SPECS = {
    "/help": "Afficher les commandes du template",
    "/mode": "Choisir un mode de travail",
    "/workspace": "Afficher ou redefinir le dossier de travail",
    "/run": "Lancer l'action courante",
    "/reset": "Reinitialiser le template",
    "/quit": "Quitter le shell",
}

COMMAND_ALIASES = {
    "help": "/help",
    "mode": "/mode",
    "workspace": "/workspace",
    "run": "/run",
    "reset": "/reset",
    "quit": "/quit",
}

MODES = {
    "BUILD": "Construire un livrable",
    "AUDIT": "Verifier un dossier ou un jeu de donnees",
    "EXPORT": "Produire un export cible",
}

TIPS = [
    "Commence par choisir un mode avec /mode BUILD ou /mode AUDIT.",
    "Tu peux taper directement BUILD, AUDIT ou EXPORT sans /mode.",
]


class StarterShell(BaseTerminalShell):
    def __init__(self):
        base_dir = Path(__file__).resolve().parent
        self.workspace = base_dir / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.current_mode = None
        self.last_run = None

        super().__init__(
            base_dir=base_dir,
            chrome=ShellChromeConfig(
                app_name="PROJECT SHELL TEMPLATE",
                subtitle="base UX/TUI reutilisable",
                prompt_brand="starter",
                help_command="/help",
                input_hint="commande ou mode",
            ),
            command_specs=COMMAND_SPECS,
            command_aliases=COMMAND_ALIASES,
            tips=TIPS,
            keyword_completion_commands=("/mode", "/run", "mode", "run"),
        )

        self.set_panel(
            "Bienvenue",
            [
                "Template pret.",
                "Choisis un mode, adapte les commandes puis branche ton moteur metier.",
            ],
            tone="info",
        )

    def get_keyword_catalog(self):
        return MODES

    def build_state_payload(self):
        return {
            "workspace": self.persistable_path(self.workspace),
            "current_mode": self.current_mode,
            "last_run": self.last_run,
        }

    def apply_state_payload(self, payload):
        workspace = payload.get("workspace")
        if workspace:
            candidate = Path(workspace)
            self.workspace = candidate if candidate.is_absolute() else self.base_dir / candidate
            self.workspace.mkdir(parents=True, exist_ok=True)

        current_mode = payload.get("current_mode")
        if current_mode in MODES:
            self.current_mode = current_mode

        last_run = payload.get("last_run")
        if isinstance(last_run, dict):
            self.last_run = last_run

    def get_status_entries(self):
        return [
            StatusEntry("mode", self.current_mode or "aucun", "info" if self.current_mode else "muted"),
            StatusEntry("workspace", self.display_path(self.workspace), "path"),
            StatusEntry("focus", self.panel.title, self.panel.tone),
        ]

    def get_next_action_hint(self):
        if not self.current_mode:
            return "choisis un mode avec /mode BUILD, /mode AUDIT ou /mode EXPORT"
        return "lance /run pour executer ton flux ou redefinis le workspace avec /workspace"

    def get_context_actions(self):
        if not self.current_mode:
            return [
                ("/mode BUILD", "info"),
                ("/mode AUDIT", "info"),
                ("/mode EXPORT", "warn"),
            ]
        return [
            ("/run", "success"),
            ("/workspace .\\workspace", "info"),
            ("/reset", "warn"),
            ("/quit", "info"),
        ]

    def get_last_run_meta(self):
        if not self.last_run:
            return None
        return f"{self.last_run['timestamp']} | {self.last_run['mode']} | {self.last_run['workspace']}"

    def get_prompt_context_label(self):
        return self.display_path(self.workspace)

    def resolve_bare_tokens(self, tokens):
        if len(tokens) == 1 and tokens[0].upper() in MODES:
            return ["/mode", tokens[0].upper()]
        return None

    def handle_unresolved_text(self, raw_text):
        query = raw_text.strip().upper()
        matches = [code for code in MODES if query and query in code]
        if matches:
            self.set_panel(
                f"Modes: {query}",
                [f"{code:<6} {MODES[code]}" for code in matches],
                tone="info",
            )
            return True
        return super().handle_unresolved_text(raw_text)

    def dispatch_command(self, command, args):
        if command == "/quit":
            return False

        if command == "/help":
            self.set_panel(
                "Commandes",
                [
                    "/mode <BUILD|AUDIT|EXPORT>  choisir un mode",
                    "/workspace [path]          voir ou redefinir le workspace",
                    "/run                       executer le mode courant",
                    "/reset                     vider le contexte local",
                    "/quit                      quitter",
                ],
                tone="info",
            )
            return True

        if command == "/mode":
            if not args:
                self.set_panel(
                    "Modes",
                    [f"{code:<6} {description}" for code, description in MODES.items()],
                    tone="info",
                )
                return True

            selected = args[0].upper()
            if selected not in MODES:
                self.set_panel(
                    "Mode",
                    [f"{selected} n'est pas un mode valide."],
                    tone="error",
                )
                return True

            self.current_mode = selected
            self.save_state()
            self.set_panel(
                "Mode actif",
                [f"{selected} - {MODES[selected]}"],
                tone="success",
            )
            return True

        if command == "/workspace":
            if not args:
                self.set_panel(
                    "Workspace",
                    [f"Destination courante: {self.display_path(self.workspace)}"],
                    tone="info",
                )
                return True

            candidate = Path(" ".join(args))
            if not candidate.is_absolute():
                candidate = self.base_dir / candidate
            candidate.mkdir(parents=True, exist_ok=True)
            self.workspace = candidate
            self.save_state()
            self.set_panel(
                "Workspace",
                [f"Nouvelle destination: {self.display_path(self.workspace)}"],
                tone="success",
            )
            return True

        if command == "/run":
            if not self.current_mode:
                self.set_panel(
                    "Execution",
                    ["Choisis d'abord un mode avec /mode."],
                    tone="warn",
                )
                return True

            self.last_run = {
                "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
                "mode": self.current_mode,
                "workspace": self.display_path(self.workspace),
            }
            self.save_state()
            self.set_panel(
                "Execution terminee",
                [
                    f"Mode lance: {self.current_mode}",
                    f"Workspace: {self.display_path(self.workspace)}",
                    "Branche maintenant ton vrai moteur metier ici.",
                ],
                tone="success",
            )
            return True

        if command == "/reset":
            self.current_mode = None
            self.last_run = None
            self.save_state()
            self.set_panel(
                "Template reinitialise",
                ["Contexte local efface."],
                tone="success",
            )
            return True

        self.set_panel(
            "Commande inconnue",
            [f"{command} n'est pas reconnue.", "Tape /help pour voir les commandes."],
            tone="error",
        )
        return True

    def run(self):
        self.interactive_loop()


if __name__ == "__main__":
    StarterShell().run()
