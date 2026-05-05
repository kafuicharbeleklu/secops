import unittest

from app.llm_client import ToolCallingLLMClient
from app.tool_executor import ToolSpec


class ToolCallingLLMClientTests(unittest.TestCase):
    def test_parses_tool_decision_json(self):
        client = ToolCallingLLMClient(lambda _prompt: '{"thought":"scan utile","tool":"query_knowledge","arguments":{"query":"http smb ssh"}}')
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "quoi faire ?"}],
            system_prompt="systeme",
            tool_specs=[
                ToolSpec(
                    name="query_knowledge",
                    description="kb",
                    arguments={"query": "texte"},
                )
            ],
        )

        self.assertEqual(decision.thought, "scan utile")
        self.assertEqual(decision.tool_name, "query_knowledge")
        self.assertEqual(decision.arguments["query"], "http smb ssh")
        self.assertIsNone(decision.final_answer)

    def test_compacts_large_prompt_before_model_call(self):
        captured = {}

        def runner(prompt):
            captured["prompt"] = prompt
            return '{"thought":"ok","final":"compact"}'

        client = ToolCallingLLMClient(
            runner,
            max_prompt_chars=2500,
            max_system_chars=1000,
            max_transcript_messages=3,
            max_message_chars=120,
            max_tool_description_chars=40,
            max_argument_description_chars=30,
        )
        messages = [
            {"role": "user", "content": f"message {index} " + ("x" * 500)}
            for index in range(10)
        ]
        decision = client.decide_next_step(
            messages=messages,
            system_prompt="systeme " + ("s" * 5000),
            tool_specs=[
                ToolSpec(
                    name="scan_target",
                    description="description " + ("d" * 500),
                    arguments={"target": "adresse de cible " + ("a" * 200)},
                )
            ],
        )

        self.assertEqual(decision.final_answer, "compact")
        self.assertLessEqual(client.last_prompt_chars, 2500)
        self.assertNotIn("message 0", captured["prompt"])
        self.assertIn("message 9", captured["prompt"])
        self.assertIn("[tronque]", captured["prompt"])

    def test_native_function_call_result_becomes_tool_decision(self):
        native_calls = []

        def native_runner(prompt, system_prompt, tool_specs):
            native_calls.append((prompt, system_prompt, tool_specs))
            return type(
                "Result",
                (),
                {
                    "tool_name": "scan_target",
                    "arguments": {"target": "10.10.10.10", "mode": "quick"},
                    "thought": "scan natif",
                    "text": "",
                    "prompt_chars": 120,
                },
            )()

        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"fallback","final":"fallback"}',
            native_decision_runner=native_runner,
            use_native_tools=True,
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "scan 10.10.10.10"}],
            system_prompt="systeme",
            tool_specs=[
                ToolSpec(
                    name="scan_target",
                    description="scan",
                    arguments={"target": "cible", "mode": "mode"},
                )
            ],
        )

        self.assertEqual(decision.tool_name, "scan_target")
        self.assertEqual(decision.arguments["target"], "10.10.10.10")
        self.assertEqual(decision.thought, "scan natif")
        self.assertEqual(len(native_calls), 1)

    def test_native_function_call_runtime_error_falls_back_to_json_prompt(self):
        def native_runner(_prompt, _system_prompt, _tool_specs):
            raise RuntimeError("native unavailable")

        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"ok","final":"fallback texte"}',
            native_decision_runner=native_runner,
            use_native_tools=True,
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "bonjour"}],
            system_prompt="systeme",
            tool_specs=[
                ToolSpec(name="query_knowledge", description="kb", arguments={"query": "texte"})
            ],
        )

        self.assertEqual(decision.final_answer, "fallback texte")

    def test_falls_back_to_raw_text_when_json_is_missing(self):
        client = ToolCallingLLMClient(lambda _prompt: "Reponse libre sans JSON")
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "reponds"}],
            system_prompt="systeme",
            tool_specs=[],
        )

        self.assertIsNone(decision.tool_name)
        self.assertEqual(decision.final_answer, "Reponse libre sans JSON")

    def test_parses_name_field_as_tool_call(self):
        client = ToolCallingLLMClient(
            lambda _prompt: 'TOOL: {"name":"query_knowledge","arguments":{"query":"smb"}}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "que faire ?"}],
            system_prompt="systeme",
            tool_specs=[],
        )

        self.assertEqual(decision.tool_name, "query_knowledge")
        self.assertEqual(decision.arguments["query"], "smb")

    def test_thought_only_json_uses_thought_as_final_answer(self):
        """When LLM returns JSON with thought but no final/tool, use thought as answer."""
        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"Bonjour ! Comment puis-je vous aider ?"}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "bonjour"}],
            system_prompt="systeme",
            tool_specs=[],
        )

        self.assertIsNone(decision.tool_name)
        self.assertEqual(decision.thought, "Bonjour ! Comment puis-je vous aider ?")
        self.assertEqual(decision.final_answer, "Bonjour ! Comment puis-je vous aider ?")
        # Must NOT contain raw JSON
        self.assertNotIn("{", decision.final_answer)

    def test_thought_with_final_uses_final(self):
        """When LLM returns both thought and final, use final as final_answer."""
        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"reflexion interne","final":"Voici ma reponse."}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "test"}],
            system_prompt="systeme",
            tool_specs=[],
        )

        self.assertEqual(decision.thought, "reflexion interne")
        self.assertEqual(decision.final_answer, "Voici ma reponse.")

    def test_answer_alias_accepted_as_final(self):
        """'answer' key should work as alias for 'final'."""
        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"test","answer":"Reponse via answer."}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "test"}],
            system_prompt="systeme",
            tool_specs=[],
        )
        self.assertEqual(decision.final_answer, "Reponse via answer.")

    def test_response_alias_accepted_as_final(self):
        """'response' key should work as alias for 'final'."""
        client = ToolCallingLLMClient(
            lambda _prompt: '{"thought":"test","response":"Reponse via response."}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "test"}],
            system_prompt="systeme",
            tool_specs=[],
        )
        self.assertEqual(decision.final_answer, "Reponse via response.")

    def test_markdown_wrapped_json_extracted(self):
        """JSON inside markdown fences should be extracted."""
        client = ToolCallingLLMClient(
            lambda _prompt: '```json\n{"thought":"ok","final":"Bonjour."}\n```'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "hi"}],
            system_prompt="systeme",
            tool_specs=[],
        )
        self.assertEqual(decision.final_answer, "Bonjour.")

    def test_text_before_json_extracted(self):
        """Text before JSON should be ignored, JSON extracted."""
        client = ToolCallingLLMClient(
            lambda _prompt: 'Voici ma reponse:\n{"thought":"raisonnement","final":"Resultat."}'
        )
        decision = client.decide_next_step(
            messages=[{"role": "user", "content": "test"}],
            system_prompt="systeme",
            tool_specs=[],
        )
        self.assertEqual(decision.final_answer, "Resultat.")
