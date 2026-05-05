import argparse

from app.project_shell import AutomationProjectShell

def main():
    shell = AutomationProjectShell()

    parser = argparse.ArgumentParser(description="SECOPS, agent conversationnel specialise pentest")
    parser.add_argument("--case", help="Activer un cas memoire au demarrage")
    parser.add_argument("--prompt", help="Envoyer une question one-shot puis quitter")
    args = parser.parse_args()

    if args.case:
        shell._activate_case(args.case)

    if args.prompt:
        shell.handle_unresolved_text(args.prompt)
        shell.render_panel_state()
        return

    shell.interactive_loop()


if __name__ == "__main__":
    main()
