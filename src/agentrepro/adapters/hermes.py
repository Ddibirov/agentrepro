"""Hermes session adapter.

Hermes stores sessions as JSONL files in ~/.hermes/sessions/*.jsonl.

Each line is a JSON object with a ``role`` field:

- ``{"role": "session_meta", "tools": [...], "provider": "...", "model": "..."}``
  — session start metadata (may be absent in some sessions).
- ``{"role": "user", "content": "..."}`` — user message.
- ``{"role": "assistant", "content": "...", "tool_calls": [...]}``
  — assistant message with optional tool calls.
- ``{"role": "tool", "content": "...", "tool_call_id": "..."}`` — tool result.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agentrepro.errors import SourceError

logger = logging.getLogger(__name__)

HERMES_SESSION_DIR = Path.home() / ".hermes" / "sessions"


def _import_models():
    """Lazy import of adapter base types (breaks circular import)."""
    from agentrepro.adapters import (
        NormalizedEvent,
        NormalizedSession,
        SessionDescriptor,
    )
    return NormalizedEvent, NormalizedSession, SessionDescriptor


class HermesAdapter:
    """Adapter for Hermes sessions (~/.hermes/sessions/*.jsonl)."""

    agent_name = "hermes"

    # ── discovery ──────────────────────────────────────────────────────

    def discover(self, selector: str) -> list:
        """Discover available Hermes sessions matching a selector.

        Scans ``~/.hermes/sessions/*.jsonl``, sorted by mtime descending.

        Args:
            selector: ``"last"`` to return the single most recent session,
                      or a substring to match against the filename stem.

        Returns:
            List of :class:`SessionDescriptor` objects.
        """
        NormalizedEvent, NormalizedSession, SessionDescriptor = _import_models()

        if not HERMES_SESSION_DIR.is_dir():
            return []

        sessions: list = []
        for f in sorted(
            HERMES_SESSION_DIR.iterdir(),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            if f.suffix != ".jsonl":
                continue
            if f.stem.startswith("."):
                continue  # skip temp / hidden files

            session_id = f.stem  # YYYYMMDD_HHMMSS_xxxxx
            mtime = f.stat().st_mtime
            from datetime import datetime, timezone

            started_at = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
            event_count = 0
            provider = None
            model = None

            # Quick peek at the first line for metadata and event count
            try:
                first_meta, event_count = self._peek_meta_and_count(f)
                if first_meta:
                    provider = first_meta.get("provider")
                    model = first_meta.get("model")
            except Exception:
                logger.warning("Failed to peek session %s", f, exc_info=True)

            sessions.append(SessionDescriptor(
                agent=self.agent_name,
                session_id=session_id,
                started_at=started_at,
                cwd_hint=None,
                agent_version=f"{provider or 'unknown'}/{model or 'unknown'}" if provider or model else None,
                source_format="hermes-jsonl",
                event_count=event_count,
            ))

        if selector == "last":
            return sessions[:1]
        # Substring match against filename stem (case-insensitive)
        return [s for s in sessions if selector.lower() in s.session_id.lower()]

    def resolve(self, session_ref: str):
        """Resolve a session reference to a descriptor.

        Matches the *session_ref* as a substring of the filename stem
        (``YYYYMMDD_HHMMSS_xxxxx``). Returns ``None`` if not found.
        """
        _, _, SessionDescriptor = _import_models()
        sessions = self.discover(session_ref)
        if sessions:
            return sessions[0]

        # Direct filename stem match as fallback
        if not HERMES_SESSION_DIR.is_dir():
            return None
        candidate = HERMES_SESSION_DIR / f"{session_ref}.jsonl"
        if candidate.exists():
            sessions = self.discover(session_ref)
            return sessions[0] if sessions else None
        return None

    # ── read ───────────────────────────────────────────────────────────

    def read_normalized(self, descriptor):
        """Read and normalize a Hermes session JSONL.

        Mapping per role:
        - ``session_meta`` → ``session_start`` (metadata extracted)
        - ``user`` → ``user_message``
        - ``assistant``:
          - plain ``assistant_message`` when no ``tool_calls``
          - ``assistant_message`` + one ``tool_call`` per tool call
        - ``tool`` → ``tool_result`` (matched by ``tool_call_id``)
        """
        NormalizedEvent, NormalizedSession, _ = _import_models()

        session_file = HERMES_SESSION_DIR / f"{descriptor.session_id}.jsonl"
        if not session_file.exists():
            raise SourceError(
                f"Hermes session not found: {descriptor.session_id}",
                code="E_SOURCE_NOT_FOUND",
            )

        events: list = []
        unknown_types = 0
        seq = 0
        metadata: dict[str, Any] = {}
        tool_call_map: dict[str, Any] = {}  # call_id -> NormalizedEvent

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

                role = raw.get("role", "")
                ts = raw.get("timestamp")

                if role == "session_meta":
                    if not metadata:
                        metadata = {
                            "session_id": descriptor.session_id,
                            "provider": raw.get("provider"),
                            "model": raw.get("model"),
                            "system_prompt": raw.get("system_prompt", ""),
                        }
                    seq += 1
                    events.append(NormalizedEvent(
                        seq=seq,
                        kind="session_start",
                        ts=ts or descriptor.started_at,
                        agent=self.agent_name,
                        agent_version=descriptor.agent_version,
                    ))
                    continue

                if not role:
                    unknown_types += 1
                    continue

                seq += 1
                content = raw.get("content", "")
                message_text = str(content) if content else ""

                if role == "user":
                    events.append(NormalizedEvent(
                        seq=seq,
                        kind="user_message",
                        ts=ts,
                        owner="user",
                        message=message_text[:16 * 1024] if message_text else "",
                    ))

                elif role == "assistant":
                    reasoning = raw.get("reasoning", "")
                    finish_reason = raw.get("finish_reason", "")
                    tool_calls_raw = raw.get("tool_calls") or []

                    # Emit assistant message if there's content or reasoning
                    if message_text or reasoning:
                        msg = message_text
                        if reasoning:
                            # Attach reasoning as trailing note when no content
                            if not msg:
                                msg = f"[reasoning: {reasoning[:2048]}]"
                        events.append(NormalizedEvent(
                            seq=seq,
                            kind="assistant_message",
                            ts=ts,
                            owner="assistant",
                            message=msg[:16 * 1024] if msg else "",
                        ))
                        seq += 1

                    # Emit individual tool_call events
                    for tc in tool_calls_raw:
                        if not isinstance(tc, dict):
                            unknown_types += 1
                            continue
                        tc_id = tc.get("id") or tc.get("call_id", "")
                        func = tc.get("function", {})
                        tool_name = func.get("name", "unknown") if isinstance(func, dict) else "unknown"
                        arguments_raw = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
                        tool_input: dict = {}
                        if isinstance(arguments_raw, str):
                            try:
                                tool_input = json.loads(arguments_raw)
                            except json.JSONDecodeError:
                                tool_input = {"raw": arguments_raw[:1024]}
                        elif isinstance(arguments_raw, dict):
                            tool_input = arguments_raw

                        ev = NormalizedEvent(
                            seq=seq,
                            kind="tool_call",
                            ts=ts,
                            tool=tool_name,
                            input=tool_input if isinstance(tool_input, dict) else {},
                        )
                        events.append(ev)

                        # Remember for potential tool_result correlation
                        if tc_id:
                            tool_call_map[tc_id] = ev
                        seq += 1

                    # If there were tool_calls but no content/reasoning, undo the extra seq bump
                    if not message_text and not reasoning and tool_calls_raw:
                        seq -= 1  # the assistant_message seq was never used

                elif role == "tool":
                    tc_id = raw.get("tool_call_id", "")
                    tool_output = content

                    # Try to correlate with a known tool_call
                    correlated_tool = "unknown"
                    if tc_id and tc_id in tool_call_map:
                        correlated_tool = tool_call_map[tc_id].tool or "unknown"

                    if isinstance(tool_output, str):
                        # Some tool outputs are JSON strings — try to extract exit_code
                        exit_code = None
                        try:
                            parsed = json.loads(tool_output)
                            if isinstance(parsed, dict):
                                ec = parsed.get("exit_code") or parsed.get("status_code")
                                if ec is not None:
                                    exit_code = int(ec) if isinstance(ec, (int, float)) else None
                        except (json.JSONDecodeError, ValueError, TypeError):
                            pass

                        events.append(NormalizedEvent(
                            seq=seq,
                            kind="tool_result",
                            ts=ts,
                            tool=correlated_tool,
                            output=tool_output[:16 * 1024] if tool_output else None,
                            exit_code=exit_code,
                        ))
                    else:
                        events.append(NormalizedEvent(
                            seq=seq,
                            kind="tool_result",
                            ts=ts,
                            tool=correlated_tool,
                            output=str(tool_output)[:16 * 1024] if tool_output else None,
                        ))

                else:
                    unknown_types += 1
                    seq -= 1

        if not metadata:
            metadata = {"session_id": descriptor.session_id}

        # Emit synthetic session_start if none was emitted from a meta line
        has_session_start = any(ev.kind == "session_start" for ev in events)
        if not has_session_start:
            events.insert(0, NormalizedEvent(
                seq=0,
                kind="session_start",
                ts=descriptor.started_at,
                agent=self.agent_name,
                agent_version=descriptor.agent_version,
            ))
            # Re-number sequences to be contiguous
            for i, ev in enumerate(events, start=1):
                ev.seq = i

        # Append session_end if last event isn't one
        if events and events[-1].kind != "session_end":
            next_seq = len(events) + 1
            events.append(NormalizedEvent(
                seq=next_seq,
                kind="session_end",
                ts=descriptor.started_at,
            ))

        return NormalizedSession(
            metadata=metadata,
            events=events,
            unknown_event_types=unknown_types,
            source_format="hermes-jsonl",
        )

    # ── internal helpers ───────────────────────────────────────────────

    def _peek_meta_and_count(self, path: Path) -> tuple[dict[str, Any] | None, int]:
        """Peek the first session_meta line and count total events."""
        import json

        first_meta = None
        count = 0
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if data.get("role") == "session_meta" and first_meta is None:
                    first_meta = data
        return first_meta, count
