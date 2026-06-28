"""
Conversation memory and session management for the SecOps Agent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from secops_agent.core.llm import Message
from secops_agent.core.output_sanitizer import sanitize_tool_output
from secops_agent.config import settings

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Maximum number of messages kept in the sliding window (user + model + tool).
DEFAULT_MAX_MESSAGES: int = 120

# Maximum characters kept per single tool output stored in memory.
MAX_TOOL_OUTPUT_CHARS: int = 8_000

# Rough chars-per-token ratio used for estimation.
_CHARS_PER_TOKEN: int = 4


def _truncate_output(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate *text* to *limit* chars, appending a marker if cut."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return (
        text[:half]
        + f"\n\n… [truncated {len(text) - limit} chars] …\n\n"
        + text[-half:]
    )


class ConversationMemory:
    def __init__(self, max_messages: int = DEFAULT_MAX_MESSAGES):
        self.messages: List[Message] = []
        self.max_messages: int = max_messages
        # Archive stores messages evicted from the sliding window.
        self._archive: List[Message] = []

    # ------------------------------------------------------------------
    # Adding messages
    # ------------------------------------------------------------------

    def add_user_message(self, content: str, attachments: List[Dict[str, Any]] = None):
        self.messages.append(Message(role="user", content=content, attachments=attachments or []))
        self._enforce_window()

    def add_assistant_message(self, content: str, tool_calls: List[Dict[str, Any]] = None):
        self.messages.append(Message(
            role="model", 
            content=content, 
            tool_calls=tool_calls or []
        ))
        self._enforce_window()

    def add_tool_result(self, tool_name: str, content: str):
        # Truncate large tool outputs, then sanitize against prompt injection
        safe_content = sanitize_tool_output(tool_name, _truncate_output(content))
        self.messages.append(Message(
            role="tool",
            content="",
            tool_results=[{"name": tool_name, "content": safe_content}]
        ))
        self._enforce_window()

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_messages(self, max_messages: Optional[int] = None) -> List[Message]:
        """Return the most recent messages up to *max_messages*.

        When *max_messages* is ``None`` the full sliding window is returned.
        """
        if max_messages is None:
            return self.messages
        return self.messages[-max_messages:]

    def get_all_messages(self) -> List[Message]:
        """Return archive + current window (complete history)."""
        return self._archive + self.messages

    # ------------------------------------------------------------------
    # Token budget helpers
    # ------------------------------------------------------------------

    def estimate_tokens(self, messages: Optional[List[Message]] = None) -> int:
        """Rough token estimate for a list of messages."""
        msgs = messages if messages is not None else self.messages
        total_chars = 0
        for m in msgs:
            total_chars += len(m.content)
            for tr in getattr(m, "tool_results", []) or []:
                total_chars += len(tr.get("content", ""))
        return total_chars // _CHARS_PER_TOKEN

    def trim_to_budget(self, token_budget: int) -> List[Message]:
        """Return the longest suffix of messages that fits within *token_budget*."""
        result: List[Message] = []
        budget_left = token_budget
        for msg in reversed(self.messages):
            chars = len(msg.content)
            for tr in getattr(msg, "tool_results", []) or []:
                chars += len(tr.get("content", ""))
            tokens = chars // _CHARS_PER_TOKEN
            if budget_left - tokens < 0 and result:
                break
            result.append(msg)
            budget_left -= tokens
        result.reverse()
        return result

    # ------------------------------------------------------------------
    # Window management
    # ------------------------------------------------------------------

    def _enforce_window(self) -> None:
        """Evict oldest messages beyond the window size into the archive."""
        while len(self.messages) > self.max_messages:
            evicted = self.messages.pop(0)
            self._archive.append(evicted)

    # ------------------------------------------------------------------
    # Existing API (unchanged)
    # ------------------------------------------------------------------

    def clear(self):
        self._archive.clear()
        self.messages.clear()

    def save_session(
        self,
        name: str,
        structured_memory: Any | None = None,
        metadata: dict[str, Any] | None = None,
        runtime_state: Any | None = None,
    ) -> Path:
        # Save the complete history (archive + window)
        all_msgs = self.get_all_messages()
        messages = [msg.to_dict() for msg in all_msgs]
        if structured_memory is not None and hasattr(structured_memory, "to_dict"):
            session_data: Any = {
                "version": 2,
                "messages": messages,
                "structured_memory": structured_memory.to_dict(),
            }
            if metadata:
                session_data["metadata"] = dict(metadata)
            if runtime_state is not None and hasattr(runtime_state, "to_session_dict"):
                session_data["runtime"] = runtime_state.to_session_dict()
        else:
            session_data = messages
        filename = f"{name}.json" if not name.endswith(".json") else name
        filepath = settings.sessions_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
        return filepath

    def load_session(
        self,
        name: str,
        structured_memory: Any | None = None,
        runtime_state: Any | None = None,
    ) -> bool:
        filename = f"{name}.json" if not name.endswith(".json") else name
        filepath = settings.sessions_dir / filename
        
        if not filepath.exists():
            return False
            
        with open(filepath, "r", encoding="utf-8") as f:
            session_data = json.load(f)

        structured_data: Any | None = None
        if isinstance(session_data, list):
            message_data = session_data
        elif isinstance(session_data, dict):
            message_data = session_data.get("messages", [])
            structured_data = session_data.get("structured_memory")
            runtime_data = session_data.get("runtime")
        else:
            return False

        if not isinstance(message_data, list):
            return False

        all_messages = [Message.from_dict(d) for d in message_data]
        # Put everything in the window then let enforcement archive the overflow
        self._archive.clear()
        self.messages = all_messages
        self._enforce_window()
        if (
            structured_data is not None
            and structured_memory is not None
            and hasattr(structured_memory, "load_dict")
        ):
            structured_memory.load_dict(structured_data)
            if hasattr(structured_memory, "conversation"):
                structured_memory.conversation = self
        if runtime_state is not None and hasattr(runtime_state, "load_session_dict"):
            runtime_state.load_session_dict(runtime_data if isinstance(session_data, dict) else None)
        return True

    def get_stats(self) -> Dict[str, Any]:
        user_msgs = sum(1 for m in self.messages if m.role == "user")
        model_msgs = sum(1 for m in self.messages if m.role == "model")
        tool_msgs = sum(1 for m in self.messages if m.role == "tool")
        
        estimated_tokens = self.estimate_tokens()
        
        return {
            "total_messages": len(self.messages),
            "archived_messages": len(self._archive),
            "user_messages": user_msgs,
            "assistant_messages": model_msgs,
            "tool_messages": tool_msgs,
            "estimated_tokens": estimated_tokens
        }
