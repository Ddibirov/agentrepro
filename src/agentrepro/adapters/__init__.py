"""Session adapters — discover and read coding agent sessions.

Base adapter interface and concrete implementations for Claude Code and Codex CLI.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentrepro.errors import SourceError

logger = logging.getLogger(__name__)


###############################################################################
# Canonical models
###############################################################################


@dataclass
class SessionDescriptor:
    """Description of a discovered session."""

    agent: str  # "claude-code" or "codex-cli"
    session_id: str  # opaque ID for resolving within adapter
    started_at: str | None = None  # RFC3339 UTC or None
    cwd_hint: str | None = None  # original CWD (redacted before bundle)
    agent_version: str | None = None
    source_format: str = ""  # e.g. "claude-project-jsonl", "codex-rollout-jsonl"
    event_count: int = 0


@dataclass
class NormalizedEvent:
    """A single canonical session event.

    Matches spec §4.2 `session.jsonl` format.
    """

    seq: int
    kind: str  # session_start | user_message | assistant_message | tool_call | tool_result | error | session_end
    ts: str | None = None
    agent: str | None = None
    agent_version: str | None = None
    tool: str | None = None
    input: dict[str, Any] | None = None
    output: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    code: str | None = None
    message: str | None = None
    owner: str | None = None  # "user" or "assistant" for messages
    orphaned: bool = False  # True if tool_result has no matching tool_call


@dataclass
class NormalizedSession:
    """Canonical session data for bundle."""

    metadata: dict[str, Any]
    events: list[NormalizedEvent]
    unknown_event_types: int = 0
    source_format: str = ""

    def to_jsonl(self) -> str:
        """Serialize events to JSONL format per spec §4.2."""
        import json
        lines: list[str] = []
        for ev in self.events:
            d: dict[str, Any] = {"seq": ev.seq, "kind": ev.kind}
            if ev.ts is not None:
                d["ts"] = ev.ts
            if ev.agent is not None:
                d["agent"] = ev.agent
            if ev.agent_version is not None:
                d["agent_version"] = ev.agent_version
            if ev.tool is not None:
                d["tool"] = ev.tool
            if ev.input is not None:
                # Per spec §4.2 policy: export only allowlisted scalar fields
                safe_input = _safe_tool_input(ev.input)
                d["input"] = safe_input
            if ev.output is not None:
                # Cap at spec limit
                d["output"] = ev.output[:16 * 1024]
            if ev.exit_code is not None:
                d["exit_code"] = ev.exit_code
            if ev.duration_ms is not None:
                d["duration_ms"] = ev.duration_ms
            if ev.code is not None:
                d["code"] = ev.code
            if ev.message is not None:
                d["message"] = ev.message[:16 * 1024]
            if ev.owner is not None:
                d["owner"] = ev.owner
            if ev.orphaned:
                d["orphaned"] = True
            lines.append(json.dumps(d, ensure_ascii=False))
        return "\n".join(lines) + "\n"


def _safe_tool_input(input_dict: dict[str, Any]) -> dict[str, Any]:
    """Export only allowlisted scalar fields per spec §4.2 item 4."""
    allowlisted_scalars = {"cmd", "path", "query", "arguments"}
    result: dict[str, Any] = {}
    for k, v in input_dict.items():
        if k in allowlisted_scalars and isinstance(v, (str, int, float, bool)):
            result[k] = v
        else:
            result[k] = {"omitted": "non_scalar_tool_input"}
    return result


###############################################################################
# Base adapter
###############################################################################


class SessionAdapter(ABC):
    """Base class for coding agent session adapters."""

    agent_name: str = ""

    @abstractmethod
    def discover(self, selector: str) -> list[SessionDescriptor]:
        """Discover available sessions matching a selector.

        Args:
            selector: 'last' to find most recent session, or a session ID.

        Returns:
            List of SessionDescriptor objects.
        """
        ...

    @abstractmethod
    def resolve(self, session_ref: str) -> SessionDescriptor | None:
        """Resolve a session reference/ID to a descriptor.

        Returns None if not found.
        """
        ...

    @abstractmethod
    def read_normalized(self, descriptor: SessionDescriptor) -> NormalizedSession:
        """Read and normalize a session.

        Returns a NormalizedSession with canonical events.
        """
        ...


###############################################################################
# Claude Code adapter
###############################################################################


CLAUDE_PROJECT_DIR = Path.home() / ".claude" / "projects"
CLAUDE_HISTORY_PATH = Path.home() / ".claude" / "history.jsonl"


class ClaudeAdapter(SessionAdapter):
    """Adapter for Claude Code sessions (~/.claude/projects/*/*.jsonl)."""

    agent_name = "claude-code"

    def discover(self, selector: str) -> list[SessionDescriptor]:
        if not CLAUDE_PROJECT_DIR.is_dir():
            return []

        sessions: list[SessionDescriptor] = []

        for proj_dir in sorted(CLAUDE_PROJECT_DIR.iterdir()):
            if not proj_dir.is_dir():
                continue
            for session_file in sorted(proj_dir.iterdir()):
                if session_file.suffix != ".jsonl":
                    continue
                session_uuid = session_file.stem
                try:
                    event_count, first_event = self._peek_events(session_file)
                except Exception:
                    logger.warning("Failed to peek events in %s", session_file, exc_info=True)
                    continue

                cwd = first_event.get("cwd") if first_event else None
                agent_ver = first_event.get("version") if first_event else None
                ts = first_event.get("timestamp") if first_event else None

                sessions.append(SessionDescriptor(
                    agent=self.agent_name,
                    session_id=session_uuid,
                    started_at=ts,
                    cwd_hint=cwd,
                    agent_version=agent_ver,
                    source_format="claude-project-jsonl",
                    event_count=event_count,
                ))

        # Sort by started_at descending if available
        sessions.sort(key=lambda s: s.started_at or "", reverse=True)

        if selector == "last":
            return sessions[:1]
        return [s for s in sessions if selector in s.session_id]

    def resolve(self, session_ref: str) -> SessionDescriptor | None:
        sessions = self.discover(session_ref)
        return sessions[0] if sessions else None

    def read_normalized(self, descriptor: SessionDescriptor) -> NormalizedSession:
        """Read and normalize a Claude Code session JSONL.

        Mapping per spec §4.3:
        - session start: first event with sessionId, cwd, version
        - user/assistant: type=user|assistant, message.role/content
        - tool call: assistant message.content[].type=tool_use
        - tool result: user message.content[].type=tool_result
        """
        session_file = self._find_session_file(descriptor.session_id)
        if session_file is None:
            raise SourceError(f"Claude session not found: {descriptor.session_id}", code="E_SOURCE_NOT_FOUND")

        import json

        events: list[NormalizedEvent] = []
        unknown_types = 0
        seq = 0
        metadata: dict[str, Any] = {}
        agent_version = descriptor.agent_version or "unknown"

        with open(session_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    unknown_types += 1
                    continue

                event_type = raw.get("type", "")

                if event_type in ("", "last-prompt", "permission-mode", "file-history-snapshot", "attachment"):
                    unknown_types += 1
                    continue

                seq += 1

                if event_type == "system":
                    # First event with session metadata
                    if not metadata:
                        metadata = {
                            "session_id": raw.get("sessionId", descriptor.session_id),
                            "cwd": raw.get("cwd"),
                            "agent_version": raw.get("version", agent_version),
                        }
                    # Don't emit system messages to bundle
                    seq -= 1
                    continue

                ts = raw.get("timestamp")
                msg = raw.get("message") or {}

                if event_type == "user":
                    content = msg.get("content", "")
                    # Claude tool_results come as user messages with tool_use blocks
                    # Check for embedded tool_results
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict):
                                if block.get("type") == "tool_result":
                                    tool_name = block.get("name", "unknown")
                                    tool_output = ""
                                    exit_code = None
                                    content_parts = block.get("content", "")
                                    if isinstance(content_parts, list):
                                        tool_output = " ".join(
                                            c.get("text", "") if isinstance(c, dict) else str(c)
                                            for c in content_parts
                                        )
                                    elif isinstance(content_parts, str):
                                        tool_output = content_parts
                                    events.append(NormalizedEvent(
                                        seq=seq, kind="tool_result",
                                        ts=ts, tool=tool_name,
                                        output=tool_output,
                                        exit_code=exit_code,
                                    ))
                                elif block.get("type") == "text":
                                    events.append(NormalizedEvent(
                                        seq=seq, kind="user_message",
                                        ts=ts, owner="user",
                                        message=block.get("text", ""),
                                    ))
                            seq += 1
                    else:
                        events.append(NormalizedEvent(
                            seq=seq, kind="user_message",
                            ts=ts, owner="user",
                            message=str(content) if content else "",
                        ))

                elif event_type == "assistant":
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict):
                                if block.get("type") == "tool_use":
                                    tool_name = block.get("name", "unknown")
                                    tool_input = block.get("input", {})
                                    events.append(NormalizedEvent(
                                        seq=seq, kind="tool_call",
                                        ts=ts, tool=tool_name,
                                        input=tool_input if isinstance(tool_input, dict) else {},
                                    ))
                                elif block.get("type") == "text":
                                    events.append(NormalizedEvent(
                                        seq=seq, kind="assistant_message",
                                        ts=ts, owner="assistant",
                                        message=block.get("text", ""),
                                    ))
                            seq += 1
                    else:
                        events.append(NormalizedEvent(
                            seq=seq, kind="assistant_message",
                            ts=ts, owner="assistant",
                            message=str(content) if content else "",
                        ))

                elif event_type == "error":
                    events.append(NormalizedEvent(
                        seq=seq, kind="error",
                        ts=ts, message=msg.get("content", str(raw.get("error", ""))),
                    ))

                else:
                    unknown_types += 1
                    seq -= 1

        if not metadata:
            metadata = {"session_id": descriptor.session_id}

        return NormalizedSession(
            metadata=metadata,
            events=events,
            unknown_event_types=unknown_types,
            source_format="claude-project-jsonl",
        )

    def _peek_events(self, path: Path) -> tuple[int, dict[str, Any] | None]:
        """Count events and get first event metadata."""
        import json
        count = 0
        first = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    count += 1
                    if first is None:
                        try:
                            first = json.loads(line)
                        except json.JSONDecodeError:
                            pass
        return count, first

    def _find_session_file(self, session_id: str) -> Path | None:
        if not CLAUDE_PROJECT_DIR.is_dir():
            return None
        for proj_dir in CLAUDE_PROJECT_DIR.iterdir():
            if not proj_dir.is_dir():
                continue
            candidate = proj_dir / f"{session_id}.jsonl"
            if candidate.exists():
                return candidate
        return None


###############################################################################
# Codex CLI adapter
###############################################################################


CODEX_SESSION_DIR = Path.home() / ".codex" / "sessions"


class CodexAdapter(SessionAdapter):
    """Adapter for Codex CLI sessions (~/.codex/sessions/YYYY/MM/DD/*.jsonl)."""

    agent_name = "codex-cli"

    def discover(self, selector: str) -> list[SessionDescriptor]:
        if not CODEX_SESSION_DIR.is_dir():
            return []

        sessions: list[SessionDescriptor] = []

        for y_dir in sorted(CODEX_SESSION_DIR.iterdir()):
            if not y_dir.is_dir() or not y_dir.name.isdigit():
                continue
            for m_dir in sorted(y_dir.iterdir()):
                if not m_dir.is_dir() or not m_dir.name.isdigit():
                    continue
                for d_dir in sorted(m_dir.iterdir()):
                    if not d_dir.is_dir() or not d_dir.name.isdigit():
                        continue
                    for session_file in sorted(d_dir.iterdir()):
                        if session_file.suffix != ".jsonl":
                            continue
                        if not session_file.name.startswith("rollout-"):
                            continue
                        session_id = session_file.stem.replace("rollout-", "", 1)
                        try:
                            meta = self._peek_meta(session_file)
                        except Exception:
                            logger.warning("Failed to peek meta in %s", session_file, exc_info=True)
                            continue

                        if meta:
                            cwd = meta.get("payload", {}).get("cwd")
                            agent_ver = meta.get("payload", {}).get("cli_version")
                            start_ts = meta.get("timestamp") or session_file.stat().st_mtime
                        else:
                            cwd = None
                            agent_ver = None
                            start_ts = session_file.stat().st_mtime

                        sessions.append(SessionDescriptor(
                            agent=self.agent_name,
                            session_id=session_id,
                            started_at=str(start_ts) if start_ts else None,
                            cwd_hint=cwd,
                            agent_version=agent_ver,
                            source_format="codex-rollout-jsonl",
                            event_count=0,
                        ))

        sessions.sort(key=lambda s: s.started_at or "", reverse=True)

        if selector == "last":
            return sessions[:1]
        return [s for s in sessions if selector in s.session_id]

    def resolve(self, session_ref: str) -> SessionDescriptor | None:
        sessions = self.discover(session_ref)
        return sessions[0] if sessions else None

    def read_normalized(self, descriptor: SessionDescriptor) -> NormalizedSession:
        """Read and normalize a Codex CLI session JSONL.

        Mapping per spec §4.3:
        - session start: session_meta.payload
        - tool call: response_item.payload.type=function_call
        - tool result: response_item.payload.type=function_call_output
        - user message: event_msg.user_message (fallback)
        """
        session_file = self._find_session_file(descriptor.session_id)
        if session_file is None:
            raise SourceError(f"Codex session not found: {descriptor.session_id}", code="E_SOURCE_NOT_FOUND")

        import json

        events: list[NormalizedEvent] = []
        unknown_types = 0
        seq = 0
        metadata: dict[str, Any] = {}

        with open(session_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    unknown_types += 1
                    continue

                seq += 1

                # First event: session_meta
                if raw.get("type") == "session_meta" or "session_meta" in raw:
                    payload = raw.get("payload") or raw.get("session_meta", {})
                    if isinstance(payload, dict):
                        metadata = {
                            "session_id": payload.get("id", descriptor.session_id),
                            "cwd": payload.get("cwd"),
                            "cli_version": payload.get("cli_version"),
                            "originator": payload.get("originator"),
                            "model_provider": payload.get("model_provider"),
                        }
                    events.append(NormalizedEvent(
                        seq=seq, kind="session_start",
                        ts=descriptor.started_at,
                        agent=self.agent_name,
                        agent_version=descriptor.agent_version,
                    ))
                    continue

                raw_type = raw.get("type", "")

                if raw_type == "response_item":
                    payload = raw.get("payload", {})
                    payload_type = payload.get("type", "")

                    if payload_type == "message":
                        role = payload.get("role", "")
                        content = payload.get("content", "")
                        kind = "assistant_message" if role == "assistant" else "user_message"
                        events.append(NormalizedEvent(
                            seq=seq, kind=kind,
                            ts=raw.get("timestamp"), owner=role,
                            message=str(content)[:16 * 1024],
                        ))

                    elif payload_type == "function_call":
                        tool_name = payload.get("name", payload.get("function", "unknown"))
                        arguments = payload.get("arguments", {})
                        if isinstance(arguments, str):
                            try:
                                arguments = json.loads(arguments)
                            except json.JSONDecodeError:
                                arguments = {"raw": arguments[:1024]}
                        events.append(NormalizedEvent(
                            seq=seq, kind="tool_call",
                            ts=raw.get("timestamp"), tool=tool_name,
                            input=arguments,
                        ))

                    elif payload_type == "function_call_output":
                        output = payload.get("output", payload.get("content", ""))
                        if isinstance(output, dict):
                            output = json.dumps(output)
                        exit_code = payload.get("exit_code") or raw.get("exit_code")
                        tool_name = payload.get("name", "unknown")
                        events.append(NormalizedEvent(
                            seq=seq, kind="tool_result",
                            ts=raw.get("timestamp"), tool=tool_name,
                            output=str(output)[:16 * 1024],
                            exit_code=exit_code,
                        ))

                    elif payload_type == "reasoning":
                        # Per spec §4.2 item 3: reasoning not exported
                        seq -= 1
                        continue

                    else:
                        unknown_types += 1
                        seq -= 1

                elif raw_type == "event_msg":
                    user_msg = raw.get("user_message", "")
                    if user_msg:
                        events.append(NormalizedEvent(
                            seq=seq, kind="user_message",
                            ts=raw.get("timestamp"), owner="user",
                            message=str(user_msg)[:16 * 1024],
                        ))
                    else:
                        unknown_types += 1
                        seq -= 1

                elif raw_type == "turn_context":
                    seq -= 1  # Not exported per spec
                    continue

                else:
                    unknown_types += 1
                    seq -= 1

        if not metadata:
            metadata = {"session_id": descriptor.session_id}

        return NormalizedSession(
            metadata=metadata,
            events=events,
            unknown_event_types=unknown_types,
            source_format="codex-rollout-jsonl",
        )

    def _peek_meta(self, path: Path) -> dict | None:
        """Get the first session_meta line."""
        import json
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if raw.get("type") == "session_meta" or "session_meta" in raw:
                    return raw
                # Also return first line with payload
                if raw.get("payload"):
                    return raw
        return None

    def _find_session_file(self, session_id: str) -> Path | None:
        if not CODEX_SESSION_DIR.is_dir():
            return None
        for y_dir in CODEX_SESSION_DIR.iterdir():
            if not y_dir.is_dir():
                continue
            for m_dir in y_dir.iterdir():
                if not m_dir.is_dir():
                    continue
                for d_dir in m_dir.iterdir():
                    if not d_dir.is_dir():
                        continue
                    for f in d_dir.iterdir():
                        if f.name.endswith(f"{session_id}.jsonl") or f.name == f"rollout-{session_id}.jsonl":
                            return f
        return None


###############################################################################
# Adapter registry
###############################################################################

ADAPTERS: dict[str, type[SessionAdapter]] = {
    "claude": ClaudeAdapter,
    "claude-code": ClaudeAdapter,
    "codex": CodexAdapter,
    "codex-cli": CodexAdapter,
}


def get_adapter(agent: str) -> SessionAdapter:
    """Get the appropriate adapter for an agent name."""
    cls = ADAPTERS.get(agent.lower())
    if cls is None:
        raise SourceError(f"Unknown agent: {agent}. Supported: {list(ADAPTERS.keys())}", code="E_SOURCE_ADAPTER")
    return cls()
