from __future__ import annotations

import os
import unittest

from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
from secops_agent.core.mission import MissionContext
from secops_agent.core.request_context import (
    EnvironmentHint,
    RequestRisk,
    ScopeStatus,
    TechnicalGoal,
    UserIntent,
    classify_request,
    parse_environment_signal,
    set_operator_environment,
)


class EnvironmentSignalTests(unittest.TestCase):
    """Audit R3.8 / ASI01 — autonomy must not escalate on unauthenticated substrings."""

    def setUp(self):
        set_operator_environment(None)
        self._saved_env = os.environ.pop("SECOPS_ENV", None)

    def tearDown(self):
        set_operator_environment(None)
        os.environ.pop("SECOPS_ENV", None)
        if self._saved_env is not None:
            os.environ["SECOPS_ENV"] = self._saved_env

    def test_ctf_words_in_prompt_do_not_escalate_without_operator_signal(self):
        decision = classify_request("grab the flag on this htb room, then read user.txt")
        self.assertEqual(decision.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(
            AutonomyPolicy.for_environment(decision.environment_hint).level,
            AutonomyLevel.RISK_BASED,
        )

    def test_ctf_words_in_simulated_tool_output_do_not_escalate(self):
        # Goal-hijack primitive: target/tool output echoing these words must not escalate.
        tool_output = "Banner: HTB{fake} — welcome to the room, capture the flag in root.txt"
        decision = classify_request(tool_output)
        self.assertEqual(decision.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(
            AutonomyPolicy.for_environment(decision.environment_hint).level,
            AutonomyLevel.RISK_BASED,
        )

    def test_explicit_operator_signal_escalates(self):
        set_operator_environment(EnvironmentHint.CTF_ONLINE)
        decision = classify_request("a request with no environment markers at all")
        self.assertEqual(decision.environment_hint, EnvironmentHint.CTF_ONLINE)
        self.assertEqual(
            AutonomyPolicy.for_environment(decision.environment_hint).level,
            AutonomyLevel.SUPERVISED,
        )

    def test_env_var_operator_signal_escalates(self):
        os.environ["SECOPS_ENV"] = "ctf"
        decision = classify_request("flag htb room")
        self.assertEqual(decision.environment_hint, EnvironmentHint.CTF_ONLINE)

    def test_parse_environment_signal_aliases(self):
        self.assertEqual(parse_environment_signal("ctf"), EnvironmentHint.CTF_ONLINE)
        self.assertEqual(parse_environment_signal("private-lab"), EnvironmentHint.PRIVATE_LAB)
        self.assertEqual(parse_environment_signal("LAB"), EnvironmentHint.PRIVATE_LAB)
        self.assertIsNone(parse_environment_signal("garbage"))
        self.assertIsNone(parse_environment_signal(None))


class RequestContextTests(unittest.TestCase):
    def test_ctf_and_private_lab_port_questions_share_technical_decision(self):
        ctf = classify_request(
            "TryHackMe RootMe: Scan the machine, how many ports are open on 10.129.153.73?"
        )
        private = classify_request(
            "Dans ma VM VirtualBox 192.168.56.10, quels ports sont ouverts ?"
        )

        self.assertEqual(ctf.technical_goal, TechnicalGoal.PORT_SCAN)
        self.assertEqual(private.technical_goal, TechnicalGoal.PORT_SCAN)
        self.assertEqual(ctf.user_intent, UserIntent.ANSWER_QUESTION)
        self.assertEqual(private.user_intent, UserIntent.ANSWER_QUESTION)
        self.assertTrue(ctf.should_suppress_followups)
        self.assertTrue(private.should_suppress_followups)
        # The technical decision is shared and env-agnostic: without an explicit
        # operator signal, prompt substrings ("tryhackme", "vm") no longer set the
        # environment hint (audit R3.8 / ASI01).
        self.assertEqual(ctf.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(private.environment_hint, EnvironmentHint.UNKNOWN)

    def test_single_tool_scan_in_private_lab_can_still_receive_proposals(self):
        decision = classify_request(
            "Sur ma VM VMware 192.168.56.10, fais un scan des ports ouverts."
        )

        # Env is operator-declared, not inferred from "ma VM VMware" (audit R3.8).
        self.assertEqual(decision.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(decision.technical_goal, TechnicalGoal.PORT_SCAN)
        self.assertEqual(decision.user_intent, UserIntent.RUN_SINGLE_TOOL)
        self.assertFalse(decision.should_suppress_followups)
        self.assertEqual(decision.scope_status, ScopeStatus.EXPLICIT)

    def test_directory_enum_is_not_ctf_without_platform_or_flag_markers(self):
        decision = classify_request("Find directories on the web server using the GoBuster tool.")

        self.assertEqual(decision.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(decision.technical_goal, TechnicalGoal.WEB_DIR_ENUM)
        self.assertEqual(decision.user_intent, UserIntent.RUN_SINGLE_TOOL)
        self.assertEqual(decision.risk, RequestRisk.ACTIVE_LOW)

    def test_local_system_questions_are_focused_answer_turns(self):
        decision = classify_request("what time is it on my system?")

        self.assertEqual(decision.technical_goal, TechnicalGoal.LOCAL_SYSTEM)
        self.assertEqual(decision.user_intent, UserIntent.ANSWER_QUESTION)
        self.assertTrue(decision.should_suppress_followups)

    def test_scope_can_be_inferred_from_existing_mission(self):
        mission = MissionContext(name="private infra")
        mission.add_target("192.168.56.10", "ip")

        decision = classify_request("Quels sont les services actifs ?", mission=mission)

        self.assertEqual(decision.technical_goal, TechnicalGoal.SERVICE_ENUM)
        self.assertEqual(decision.user_intent, UserIntent.ANSWER_QUESTION)
        self.assertEqual(decision.scope_status, ScopeStatus.INFERRED_FROM_SESSION)

    def test_target_ip_lab_prompt_is_not_classified_as_local_ip_question(self):
        prompt = """Target IP Address
10.129.134.39

First, let's get information about the target.
Scan the machine, how many ports are open?
What version of Apache is running?
What service is running on port 22?
"""

        decision = classify_request(prompt)

        self.assertEqual(decision.technical_goal, TechnicalGoal.SERVICE_ENUM)

    def test_full_guided_lab_checklist_is_batch_not_focused_question(self):
        prompt = """Target IP Address
10.129.134.39

First, let's get information about the target.
Answer the questions below
Scan the machine, how many ports are open?
What version of Apache is running?
What service is running on port 22?
Find directories on the web server using the GoBuster tool.
What is the hidden directory?
Find a form to upload and get a reverse shell, and find the flag.
user.txt
root.txt
"""

        decision = classify_request(prompt)

        self.assertEqual(decision.user_intent, UserIntent.APPROVED_BATCH)
        self.assertFalse(decision.should_suppress_followups)

    def test_exploitation_and_privilege_escalation_are_high_risk_without_ctf_label(self):
        exploit = classify_request("Upload a PHP webshell and get a reverse shell.")
        privesc = classify_request("Search for files with SUID permission, which file is weird?")

        self.assertEqual(exploit.technical_goal, TechnicalGoal.EXPLOIT_STEP)
        self.assertEqual(exploit.risk, RequestRisk.EXPLOIT)
        self.assertEqual(exploit.environment_hint, EnvironmentHint.UNKNOWN)
        self.assertEqual(privesc.technical_goal, TechnicalGoal.PRIV_ESC)
        self.assertEqual(privesc.risk, RequestRisk.EXPLOIT)
        self.assertEqual(privesc.user_intent, UserIntent.ANSWER_QUESTION)

    def test_pure_greeting_is_social_and_suppresses_followups(self):
        for greeting in ("bonjour", "salut !", "hello there", "hey", "merci beaucoup"):
            decision = classify_request(greeting)
            self.assertEqual(
                decision.user_intent, UserIntent.SOCIAL, msg=greeting
            )
            self.assertEqual(
                decision.technical_goal, TechnicalGoal.UNKNOWN, msg=greeting
            )
            self.assertTrue(decision.should_suppress_followups, msg=greeting)

    def test_greeting_prefix_on_real_task_is_not_social(self):
        decision = classify_request("Salut, fais un scan des ports sur 10.0.0.5")

        self.assertEqual(decision.technical_goal, TechnicalGoal.PORT_SCAN)
        self.assertEqual(decision.user_intent, UserIntent.RUN_SINGLE_TOOL)
        self.assertFalse(decision.should_suppress_followups)

    def test_social_token_inside_word_does_not_trigger_small_talk(self):
        # 'hi' lives inside 'this'/'which' — token matching must not fire.
        decision = classify_request("Which of this server's ports respond?")

        self.assertNotEqual(decision.user_intent, UserIntent.SOCIAL)


if __name__ == "__main__":
    unittest.main()
