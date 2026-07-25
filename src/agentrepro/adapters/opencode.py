"""OpenCode session adapter.

OpenCode stores sessions as individual JSON files on disk at
~/.local/share/opencode/storage/.

Storage layout:
  project/*.json                  — project definitions
  session/<project-id>/*.json     — session metadata
  message/<session-id>/*.json     — messages (role: user | assistant)
  part/<message-id>/*.json        — content parts (text, tool, reasoning, etc.)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agentrepro.errors import SourceError

# Lazy import to break circular dependency with adapters/__init__.py
# which imports from this module.
def _get_adapter_base():
    from agentrepro.adapters import (
        NormalizedEvent,
        NormalizedSession,
        SessionAdapter,
        SessionDescriptor,
    )
    return NormalizedEvent, NormalizedSession, SessionAdapter, SessionDescriptor


logger = logging.getLogger(__name__)

OPENCODE_STORAGE_DIR = Path.home() / ".local" / "share" / "opencode" / "storage"


def _import_models():
    """Lazy import of adapter base types (breaks circular import)."""
    from agentrepro.adapters import (
        NormalizedEvent,
        NormalizedSession,
        SessionAdapter,
        SessionDescriptor,
    )
    return NormalizedEvent, NormalizedSession, SessionAdapter, SessionDescriptor


class OpenCodeAdapter:
    """Adapter for OpenCode sessions (~/.local/share/opencode/storage/)."""

    agent_name = "opencode-cli"

    # ── discovery ──────────────────────────────────────────────────────

    def discover(self, selector: str):
        """Discover available OpenCode sessions matching a selector."""
        _, _, _, SessionDescriptor = _import_models()
        storage = OPENCODE_STORAGE_DIR
        if not storage.is_dir():
            return []

        sessions: list = []

        session_root = storage / "session"
        if not session_root.is_dir():
            return []

        for proj_dir in sorted(session_root.iterdir()):
            if not proj_dir.is_dir():
                continue
            for session_file in sorted(proj_dir.iterdir()):
                if session_file.suffix != ".json":
                    continue
                try:
                    data = json.loads(session_file.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    logger.warning("Failed to read session %s", session_file, exc_info=True)
                    continue

                session_id = data.get("id", session_file.stem)
                ts = None
                time_info = data.get("time") or {}
                created_ms = time_info.get("created")
                if created_ms:
                    ts = _ms_to_iso(created_ms)

                cwd = data.get("directory")
                agent_ver = data.get("version")

                event_count = self._count_messages(session_id)

                sessions.append(SessionDescriptor(
                    agent=self.agent_name,
                    session_id=session_id,
                    started_at=ts,
                    cwd_hint=cwd,
                    agent_version=agent_ver,
                    source_format="opencode-json",
                    event_count=event_count,
                ))

        sessions.sort(key=lambda s: s.started_at or "", reverse=True)

        if selector == "last":
            return sessions[:1]
        return [s for s in sessions if selector.lower() in s.session_id.lower()]

    def resolve(self, session_ref: str):
        """Resolve a session reference to a descriptor."""
        _, _, _, SessionDescriptor = _import_models()
        sessions = self.discover(session_ref)
        if sessions:
            return sessions[0]
        # Try exact file match
        storage = OPENCODE_STORAGE_DIR
        if not storage.is_dir():
            return None
        session_root = storage / "session"
        if not session_root.is_dir():
            return None
        for proj_dir in session_root.iterdir():
            if not proj_dir.is_dir():
                continue
            candidate = proj_dir / f"{session_ref}.json"
            if candidate.exists():
                sessions = self.discover(session_ref)
                return sessions[0] if sessions else None
        return None

    # ── read ───────────────────────────────────────────────────────────

    def read_normalized(self, descriptor):
        """Read and normalize an OpenCode session from on-disk JSON storage.

        Mapping:
        - messages with role=user → user_message (with embedded tool_result parts)
        - messages with role=assistant → assistant_message (with embedded tool_call parts)
        - tool part in any message → tool_call / tool_result
        - reasoning part → skipped (not exported per spec §4.2)
        - step-start / step-finish → skipped (internal bookkeeping)
        """
        NormalizedEvent, NormalizedSession, _, _ = _import_models()

        storage = OPENCODE_STORAGE_DIR
        if not storage.is_dir():
            raise SourceError(
                f"OpenCode storage not found at {storage}",
                code="E_SOURCE_NOT_FOUND",
            )

        messages = self._load_messages(descriptor.session_id)
        if messages is None:
            raise SourceError(
                f"OpenCode session not found: {descriptor.session_id}",
                code="E_SOURCE_NOT_FOUND",
            )

        events: list = []
        unknown_types = 0
        seq = 0
        metadata: dict[str, Any] = {}

        session_data = self._load_session_meta(descriptor.session_id)
        if session_data:
            metadata = {
                "session_id": session_data.get("id", descriptor.session_id),
                "directory": session_data.get("directory"),
                "title": session_data.get("title"),
                "agent_version": session_data.get("version", descriptor.agent_version),
            }

        for msg in messages:
            role = msg.get("role", "")
            msg_id = msg.get("id", "")
            parts = self._load_parts(msg_id) or []
            ts = None
            time_info = msg.get("time") or {}
            created_ms = time_info.get("created")
            if created_ms:
                ts = _ms_to_iso(created_ms)

            if role == "user":
                had_tool_result = False
                for part in parts:
                    part_type = part.get("type", "")
                    seq += 1

                    if part_type == "text":
                        text = part.get("text", "")
                        if text:
                            events.append(NormalizedEvent(
                                seq=seq, kind="user_message",
                                ts=ts, owner="user",
                                message=text,
                            ))
                        else:
                            seq -= 1

                    elif part_type == "tool":
                        tool_name = part.get("tool", "unknown")
                        state = part.get("state", {})
                        output = state.get("output", "")
                        if isinstance(output, dict):
                            output = json.dumps(output, ensure_ascii=False)
                        error = state.get("error")
                        exit_code = 1 if error else None

                        if isinstance(output, str) and len(output) > 16 * 1024:
                            output = output[:16 * 1024]

                        events.append(NormalizedEvent(
                            seq=seq, kind="tool_result",
                            ts=ts, tool=tool_name,
                            output=str(output) if output else None,
                            exit_code=exit_code,
                        ))
                        had_tool_result = True

                    elif part_type in ("reasoning", "step-start", "step-finish", "patch"):
                        seq -= 1
                    elif part_type == "Unknown":
                        seq -= 1
                    else:
                        unknown_types += 1
                        seq -= 1

                if not had_tool_result:
                    text_parts = [p.get("text", "") for p in parts if p.get("type") == "text"]
                    text = "\n".join(t for t in text_parts if t)
                    if not text:
                        seq += 1
                        events.append(NormalizedEvent(
                            seq=seq, kind="user_message",
                            ts=ts, owner="user",
                            message="",
                        ))

            elif role == "assistant":
                for part in parts:
                    part_type = part.get("type", "")
                    seq += 1

                    if part_type == "text":
                        text = part.get("text", "")
                        if text:
                            events.append(NormalizedEvent(
                                seq=seq, kind="assistant_message",
                                ts=ts, owner="assistant",
                                message=text,
                            ))
                        else:
                            seq -= 1

                    elif part_type == "tool":
                        tool_name = part.get("tool", "unknown")
                        state = part.get("state", {})
                        tool_input = state.get("input", {})

                        if isinstance(tool_input, str):
                            try:
                                tool_input = json.loads(tool_input)
                            except json.JSONDecodeError:
                                tool_input = {"raw": tool_input[:1024]}

                        events.append(NormalizedEvent(
                            seq=seq, kind="tool_call",
                            ts=ts, tool=tool_name,
                            input=tool_input if isinstance(tool_input, dict) else {},
                        ))

                    elif part_type == "reasoning":
                        seq -= 1
                    elif part_type in ("step-start", "step-finish", "patch"):
                        seq -= 1
                    elif part_type == "Unknown":
                        seq -= 1
                    else:
                        unknown_types += 1
                        seq -= 1

            elif role == "tool":
                for part in parts:
                    part_type = part.get("type", "")
                    seq += 1
                    if part_type == "tool":
                        state = part.get("state", {})
                        output = state.get("output", "")
                        if isinstance(output, dict):
                            output = json.dumps(output, ensure_ascii=False)
                        if isinstance(output, str) and len(output) > 16 * 1024:
                            output = output[:16 * 1024]
                        events.append(NormalizedEvent(
                            seq=seq, kind="tool_result",
                            ts=ts, tool=part.get("tool", "unknown"),
                            output=str(output) if output else None,
                        ))
                    else:
                        seq -= 1

            else:
                unknown_types += 1

        if not metadata:
            metadata = {"session_id": descriptor.session_id}

        if events and events[-1].kind != "session_end":
            seq += 1
            events.append(NormalizedEvent(
                seq=seq, kind="session_end",
                ts=descriptor.started_at,
            ))

        return NormalizedSession(
            metadata=metadata,
            events=events,
            unknown_event_types=unknown_types,
            source_format="opencode-json",
        )

    # ── internal helpers ───────────────────────────────────────────────

    def _load_session_meta(self, session_id: str) -> dict[str, Any] | None:
        storage = OPENCODE_STORAGE_DIR / "session"
        if not storage.is_dir():
            return None
        for proj_dir in storage.iterdir():
            if not proj_dir.is_dir():
                continue
            candidate = proj_dir / f"{session_id}.json"
            if candidate.exists():
                try:
                    return json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    return None
        return None

    def _load_messages(self, session_id: str) -> list[dict[str, Any]] | None:
        msg_dir = OPENCODE_STORAGE_DIR / "message" / session_id
        if not msg_dir.is_dir():
            return None
        messages: list[dict[str, Any]] = []
        for msg_file in sorted(msg_dir.iterdir()):
            if msg_file.suffix != ".json":
                continue
            try:
                data = json.loads(msg_file.read_text(encoding="utf-8", errors="replace"))
                messages.append(data)
            except Exception:
                logger.warning("Failed to read message %s", msg_file, exc_info=True)
        messages.sort(key=lambda m: (m.get("time", {}) or {}).get("created", 0) or 0)
        return messages

    def _load_parts(self, message_id: str) -> list[dict[str, Any]]:
        part_dir = OPENCODE_STORAGE_DIR / "part" / message_id
        if not part_dir.is_dir():
            return []
        parts: list[dict[str, Any]] = []
        for part_file in sorted(part_dir.iterdir()):
            if part_file.suffix != ".json":
                continue
            try:
                data = json.loads(part_file.read_text(encoding="utf-8", errors="replace"))
                parts.append(data)
            except Exception:
                logger.warning("Failed to read part %s", part_file, exc_info=True)
        parts.sort(key=lambda p: p.get("id", ""))
        return parts

    def _find_session_file(self, session_id: str) -> Path | None:
        storage = OPENCODE_STORAGE_DIR / "session"
        if not storage.is_dir():
            return None
        for proj_dir in storage.iterdir():
            if not proj_dir.is_dir():
                continue
            candidate = proj_dir / f"{session_id}.json"
            if candidate.exists():
                return candidate
        return None

    def _count_messages(self, session_id: str) -> int:
        msg_dir = OPENCODE_STORAGE_DIR / "message" / session_id
        if not msg_dir.is_dir():
            return 0
        return len([f for f in msg_dir.iterdir() if f.suffix == ".json"])


def _ms_to_iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
