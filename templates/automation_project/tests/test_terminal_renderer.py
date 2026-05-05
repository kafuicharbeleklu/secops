import unittest

from app.terminal_renderer import TerminalRenderer


class TerminalRendererTests(unittest.TestCase):
    def test_renders_thought_events_for_user_output(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thought", "content": "raisonnement interne"},
                {"type": "final_answer", "content": "Bonjour."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["title"], "Agent")
        self.assertEqual(rendered["lines"], ["◦ raisonnement interne", "", "Bonjour."])

    def test_formats_command_activity_without_debug_labels(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": {"command": "nmap 10.10.10.10", "stdout": "22/tcp open ssh", "stderr": "", "returncode": 0},
                },
                {"type": "final_answer", "content": "1 port ouvert."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(rendered["lines"][0].startswith("• Commande: nmap"))
        self.assertEqual(rendered["lines"].count("• Commande: nmap 10.10.10.10"), 1)
        self.assertIn("1 port ouvert.", rendered["lines"])

    def test_supports_partial_event_stream_without_final_answer(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "tool_start", "name": "query_knowledge", "args": {"query": "http smb ssh"}},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["answer"], "")
        self.assertEqual(rendered["lines"], ["• Memoire: http smb ssh"])

    def test_renders_tool_progress_event(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
                {"type": "tool_progress", "name": "execute_command", "stream": "status", "content": "commande toujours en cours... 5s"},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertIn("• Commande: nmap 10.10.10.10", rendered["lines"])
        self.assertIn("  ├ commande toujours en cours... 5s", rendered["lines"])

    def test_renders_structured_progress_event(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
                {
                    "type": "tool_progress",
                    "name": "execute_command",
                    "tool": "nmap",
                    "progress_kind": "activity",
                    "phase": "Connect Scan",
                    "percent": "43.0%",
                    "elapsed_label": "12s",
                    "eta": "7s remaining",
                    "content": "nmap | Connect Scan | 43.0% | ecoule 12s",
                },
                {
                    "type": "tool_progress",
                    "name": "execute_command",
                    "tool": "nmap",
                    "progress_kind": "finding",
                    "detail": "22/tcp open ssh OpenSSH",
                    "content": "nmap | port ouvert detecte: 22/tcp open ssh OpenSSH",
                },
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertIn("  ├ nmap | Connect Scan | 43.0% | ecoule 12s | 7s remaining", rendered["lines"])
        self.assertIn("  ├ nmap trouve: 22/tcp open ssh OpenSSH", rendered["lines"])

    def test_renders_high_level_tool_start_labels(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "scan_target", "args": {"target": "10.10.10.10", "mode": "quick"}},
                {"type": "tool_progress", "name": "execute_command", "stream": "status", "content": "nmap | SYN Stealth Scan | ecoule 0:00:05"},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertIn("• Scan: 10.10.10.10 (quick)", rendered["lines"])
        self.assertIn("  ├ nmap | SYN Stealth Scan | ecoule 0:00:05", rendered["lines"])

    def test_thought_lines_tracked_as_dim(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thought", "content": "premiere reflexion"},
                {"type": "thought", "content": "deuxieme reflexion"},
                {"type": "final_answer", "content": "Voici la reponse."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertIn(0, rendered["dim_lines"])
        self.assertIn(1, rendered["dim_lines"])
        # dim_lines should not include blank separator or answer lines
        self.assertNotIn(2, rendered["dim_lines"])

    def test_thought_uses_open_bullet_marker(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thought", "content": "je vais scanner"},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["lines"][0], "◦ je vais scanner")

    def test_findings_event_with_preview(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "findings", "count": 3, "tool": "nmap", "preview": "22, 80, 443"},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertIn("3 decouverte(s) (nmap): 22, 80, 443", rendered["lines"][0])

    def test_findings_event_without_preview(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "findings", "count": 2, "tool": "gobuster"},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["lines"][0], "  └ 2 decouverte(s) (gobuster)")

    def test_policy_block_includes_action(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {
                    "type": "tool_policy_blocked",
                    "name": "scan_target",
                    "error": "placeholder cible detecte",
                    "remediation": "Definis la cible active avec /target <ip|url>.",
                },
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["tone"], "warn")
        self.assertIn("outil bloque scan_target", rendered["lines"][0])
        self.assertIn("action:", rendered["lines"][1])

    def test_final_answer_separated_from_tool_output(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "ls"}},
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": {"stdout": "file.txt", "stderr": "", "returncode": 0},
                },
                {"type": "final_answer", "content": "Le fichier existe."},
            ],
            model_label="gemini-2.5-flash",
        )

        answer_idx = rendered["lines"].index("Le fichier existe.")
        self.assertTrue(answer_idx > 0)
        self.assertEqual(rendered["lines"][answer_idx - 1], "")

    def test_final_answer_no_separator_when_alone(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "final_answer", "content": "Bonjour."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["lines"], ["Bonjour."])

    def test_command_result_summarizes_nmap_open_ports(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": {
                        "command": "nmap 10.10.10.10",
                        "stdout": "22/tcp open ssh OpenSSH\n80/tcp open http Apache\n",
                        "stderr": "",
                        "returncode": 0,
                        "duration_seconds": 3,
                    },
                },
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("duree: 3s" in line for line in rendered["lines"]))
        self.assertTrue(any("2 port(s) ouvert(s): 22/ssh, 80/http" in line for line in rendered["lines"]))

    def test_command_result_summarizes_web_paths(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": {
                        "command": "gobuster dir -u http://10.10.10.10",
                        "stdout": "/admin (Status: 301)\nFound: /hidden (Status: 200)\n",
                        "stderr": "",
                        "returncode": 0,
                    },
                },
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("2 chemin(s) trouve(s): /admin, /hidden" in line for line in rendered["lines"]))

    def test_thought_deduplication_when_identical_to_final(self):
        """When thought == final_answer, thought lines should be removed."""
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thought", "content": "Bonjour !"},
                {"type": "final_answer", "content": "Bonjour !"},
            ],
            model_label="gemini-2.5-flash",
        )

        # Should only have the final answer, not the duplicate thought
        self.assertEqual(rendered["lines"], ["Bonjour !"])
        self.assertEqual(len(rendered["dim_lines"]), 0)

    def test_thought_kept_when_different_from_final(self):
        """When thought != final_answer, both should appear."""
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "thought", "content": "reflexion interne"},
                {"type": "final_answer", "content": "Voici la reponse."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertEqual(rendered["lines"], ["◦ reflexion interne", "", "Voici la reponse."])
        self.assertIn(0, rendered["dim_lines"])

    def test_install_tool_result_already_installed(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "install_pentest_tool", "args": {"tool_name": "nmap"}},
                {"type": "tool_success", "name": "install_pentest_tool", "result": {"status": "already_installed", "tool": "nmap"}},
                {"type": "final_answer", "content": "Nmap est deja installe."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("nmap est deja installe" in line for line in rendered["lines"]))
        self.assertTrue(any("Installation: nmap" in line for line in rendered["lines"]))

    def test_install_tools_result_batch_rendering(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {
                    "type": "tool_start",
                    "name": "install_pentest_tools",
                    "args": {"tool_names": ["hydra", "dirb"]},
                },
                {
                    "type": "tool_success",
                    "name": "install_pentest_tools",
                    "result": {
                        "status": "installed",
                        "installed": ["hydra", "dirb"],
                        "missing": [],
                    },
                },
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("Installation: hydra, dirb" in line for line in rendered["lines"]))
        self.assertTrue(any("installation groupee: installed" in line for line in rendered["lines"]))
        self.assertTrue(any("installe(s): hydra, dirb" in line for line in rendered["lines"]))

    def test_suggest_tools_result_rendering(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "suggest_pentest_tools", "args": {}},
                {"type": "tool_success", "name": "suggest_pentest_tools", "result": {
                    "tools": [
                        {"name": "nmap", "category": "scanner", "installed": True},
                        {"name": "gobuster", "category": "scanner", "installed": False},
                    ]
                }},
                {"type": "final_answer", "content": "Voici les outils."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("✓ nmap" in line for line in rendered["lines"]))
        self.assertTrue(any("✗ gobuster" in line for line in rendered["lines"]))

    def test_list_findings_result_rendering(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "tool_start", "name": "list_findings", "args": {}},
                {"type": "tool_success", "name": "list_findings", "result": {"count": 5, "summary": "5 findings"}},
                {"type": "final_answer", "content": "Il y a 5 decouvertes."},
            ],
            model_label="gemini-2.5-flash",
        )

        self.assertTrue(any("5 decouverte(s)" in line for line in rendered["lines"]))


if __name__ == "__main__":
    unittest.main()
