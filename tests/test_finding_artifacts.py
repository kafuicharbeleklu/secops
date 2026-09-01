"""/artifact as the primary finding surface (audit item #7 / T2.2, Part B).

Findings are written to structured artifacts *as they are found* — at the OBSERVE
step where tool output becomes a blackboard fact — so `/artifact` is a complete,
discovery-ordered record sufficient to write a report without scrolling back. The
emit is deduped by mission keys (re-observing the same scan does not re-emit), the
artifact is written live from the FindingEvent (no conversation/memory replay), and
the `/artifact` view leads with a Findings section above the raw evidence registry.
"""
from __future__ import annotations

import asyncio
import unittest

from secops_agent.core.agent import (
    FindingEvent,
    SecOpsAgent,
    ToolProgressEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext
from secops_agent.core.permissions import (
    ApprovalDecision,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry
from secops_agent.core.tools import ToolResult


NMAP_RAW = """Nmap scan report for 10.10.10.5
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.51
"""


class _NmapTwiceLLM:
    """Drives nmap_scan on the first two turns (same args), then answers."""

    model_name = "fake-model"

    def __init__(self):
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    def set_mission_context(self, context: str) -> None:
        pass

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls <= 2:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="nmap_scan", arguments={"target": "10.10.10.5"}, id=f"c{self.calls}"
                )
            )
            return
        yield StreamChunk(content="done")


def _agent():
    registry = ToolRegistry()

    async def nmap_scan(**_kwargs):
        return NMAP_RAW

    registry.register(
        name="nmap_scan", description="scan", category=ToolCategory.NETWORK,
        parameters={"target": {"type": "string", "required": True}},
        func=nmap_scan, dangerous=True,
    )
    memory = ConversationMemory()
    mission = MissionContext(name="finding-artifacts")
    structured = StructuredMemory(conversation=memory, mission=mission)
    permissions = PermissionEngine()
    # Pre-allow the scan so it executes; the plan gate auto-acks (SANDBOX) below.
    permissions.remember(
        PermissionResource(kind="tool", name="nmap_scan"), PermissionDecision.ALLOW
    )
    agent = SecOpsAgent(
        llm=_NmapTwiceLLM(),
        registry=registry,
        memory=memory,
        permissions=permissions,
        structured_memory=structured,
        result_parser=ToolResultParser(mission=mission),
        max_iterations=2,
    )
    from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
    agent.autonomy = AutonomyPolicy(level=AutonomyLevel.SANDBOX)
    return agent, mission


async def _collect(agent, prompt):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
    return events


async def _drain(stream):
    return [event async for event in stream]


class FindingEmissionTest(unittest.TestCase):
    def test_observe_emits_finding_events_for_new_blackboard_items(self):
        agent, mission = _agent()
        events = asyncio.run(_collect(agent, "run the network tool"))
        findings = [e for e in events if isinstance(e, FindingEvent)]
        self.assertTrue(findings, "OBSERVE emits a FindingEvent for each newly-added blackboard item")
        # nmap discovers a host and/or services.
        self.assertTrue(
            any(f.kind in {"host", "service"} for f in findings),
            f"expected host/service discoveries, got kinds {[f.kind for f in findings]!r}",
        )
        self.assertTrue(all(f.source == "nmap_scan" for f in findings))

    def test_reobservation_does_not_re_emit(self):
        # _NmapTwiceLLM drives two identical nmap turns in one stream; the 2nd adds
        # no new blackboard items, so no finding is emitted twice.
        agent, mission = _agent()
        events = asyncio.run(_collect(agent, "run the network tool"))
        findings = [e for e in events if isinstance(e, FindingEvent)]
        self.assertTrue(findings)
        unique = {(f.kind, f.title) for f in findings}
        self.assertEqual(
            len(findings), len(unique),
            "dedup by mission key: the repeated identical scan re-emits nothing",
        )


class TrackFindingArtifactTest(unittest.TestCase):
    def test_tool_progress_and_result_update_one_durable_timeline_artifact(self):
        from secops_agent.main import _track_agent_artifacts
        from secops_agent.ui.runtime import RuntimeState

        runtime = RuntimeState()

        async def events():
            yield ToolStartEvent("nmap_scan", {"target": "10.10.10.5"}, "scan-1")
            yield ToolProgressEvent("nmap_scan", "scan-1", "host discovery", "10.10.10.5", 20)
            yield ToolProgressEvent("nmap_scan", "scan-1", "service scan", "ports 1-1000", 70)
            yield ToolResultEvent(
                "nmap_scan", ToolResult(success=True, output="22/tcp open ssh"), "scan-1"
            )

        asyncio.run(_drain(_track_agent_artifacts(runtime, events())))

        artifacts = [artifact for artifact in runtime.artifacts if artifact.kind == "tool-result"]
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        self.assertEqual(artifact.metadata["status"], "result")
        self.assertIn("host discovery (20%) — 10.10.10.5", artifact.content)
        self.assertIn("service scan (70%) — ports 1-1000", artifact.content)
        self.assertIn("Result (result)", artifact.content)
        self.assertIn("22/tcp open ssh", artifact.content)

    def test_cancelled_tool_timeline_is_finalized_as_an_error_artifact(self):
        from secops_agent.main import _track_agent_artifacts
        from secops_agent.ui.runtime import RuntimeState

        runtime = RuntimeState()

        async def events():
            yield ToolStartEvent("run_shell", {"command": "sleep 300"}, "shell-1")
            yield ToolProgressEvent("run_shell", "shell-1", "still running", "5.0s elapsed")
            yield ToolResultEvent(
                "run_shell", ToolResult(success=False, output="", error="Interrupted by user"), "shell-1"
            )

        asyncio.run(_drain(_track_agent_artifacts(runtime, events())))

        artifact = runtime.latest_artifact()
        self.assertEqual(artifact.metadata["status"], "error")
        self.assertIn("failed or cancelled", artifact.content)
        self.assertIn("Interrupted by user", artifact.content)
    def test_finding_event_becomes_finding_artifact_without_replay(self):
        from secops_agent.main import _track_agent_artifacts
        from secops_agent.ui.runtime import RuntimeState

        runtime = RuntimeState()

        async def events():
            yield FindingEvent(
                kind="service", title="http on 10.10.10.5:80",
                detail="Apache httpd 2.4.51 · open", severity="info", source="nmap_scan",
            )

        async def run():
            return [e async for e in _track_agent_artifacts(runtime, events())]

        collected = asyncio.run(run())
        self.assertTrue(any(isinstance(e, FindingEvent) for e in collected), "event passes through")
        findings = [a for a in runtime.artifacts if a.kind == "finding"]
        self.assertEqual(len(findings), 1, "a 'finding' artifact is written live from the event")
        self.assertEqual(findings[0].title, "http on 10.10.10.5:80")
        self.assertEqual(findings[0].source, "nmap_scan")

    def test_empty_detail_falls_back_to_title(self):
        from secops_agent.main import _track_agent_artifacts
        from secops_agent.ui.runtime import RuntimeState

        runtime = RuntimeState()

        async def events():
            yield FindingEvent(kind="finding", title="WAF detected", detail="", source="waf_detect")

        asyncio.run(_drain(_track_agent_artifacts(runtime, events())))
        findings = [a for a in runtime.artifacts if a.kind == "finding"]
        self.assertEqual(len(findings), 1, "an empty-detail finding still records (title as content)")


class ArtifactFindingsLeadTest(unittest.TestCase):
    def test_findings_section_leads_the_artifact_view(self):
        from secops_agent.ui.runtime import RuntimeState
        from secops_agent.ui.views.panels import build_artifacts_view_lines

        runtime = RuntimeState()
        runtime.add_artifact("Nmap scan result", "tool-result", "raw nmap output", source="nmap_scan")
        runtime.add_artifact(
            "http on 10.10.10.5:80", "finding", "Apache httpd 2.4.51",
            source="nmap_scan", metadata={"kind": "service", "severity": "info"},
        )

        lines = build_artifacts_view_lines(runtime, width=96, height=28)
        text = "\n".join(lines)
        self.assertIn("Findings", text, "the view leads with a Findings section")

        findings_idx = next(i for i, line in enumerate(lines) if "Findings" in line)
        toolresult_idx = next(i for i, line in enumerate(lines) if "Nmap scan result" in line)
        self.assertLess(findings_idx, toolresult_idx, "Findings lead the raw evidence registry")
        # The nav list is intact — every artifact still listed for navigation.
        self.assertIn("Nmap scan result", text)

    def test_no_findings_section_when_none_recorded(self):
        from secops_agent.ui.runtime import RuntimeState
        from secops_agent.ui.views.panels import build_artifacts_view_lines

        runtime = RuntimeState()
        runtime.add_artifact("Nmap scan result", "tool-result", "raw nmap output", source="nmap_scan")
        text = "\n".join(build_artifacts_view_lines(runtime, width=96, height=28))
        self.assertNotIn("Findings", text)


if __name__ == "__main__":
    unittest.main()
