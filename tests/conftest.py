"""Test fixtures for AgentRepro bundle tests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
SCHEMA_DIR = HERE.parent / "schemas"
FIXTURE_DIR = HERE.parent / "tests" / "fixtures"


# ---- Incident fixtures ----


@pytest.fixture
def schema_path() -> Path:
    return SCHEMA_DIR / "agent-incident-1.json"


@pytest.fixture
def bundle_schema_path() -> Path:
    return SCHEMA_DIR / "bundle-manifest-1.json"


@pytest.fixture
def sample_incident() -> dict[str, Any]:
    return {
        "$schema": "https://agentrepro.dev/schemas/agent-incident-1.json",
        "schema_version": "1.0",
        "incident_id": "inc_test_001",
        "source": {
            "producer": "loopbreaker",
            "producer_version": "0.1.0",
            "agent": "claude-code",
        },
        "detector": {
            "rule": "repeated_tool_call",
            "threshold": 5,
            "observed": 5,
        },
        "timestamps": {
            "detected_at": "2026-07-22T12:00:00Z",
        },
        "severity": "warning",
        "status": "open",
    }


@pytest.fixture
def sample_incident_full() -> dict[str, Any]:
    return {
        "$schema": "https://agentrepro.dev/schemas/agent-incident-1.json",
        "schema_version": "1.0",
        "incident_id": "inc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "source": {
            "producer": "loopbreaker",
            "producer_version": "0.1.0",
            "agent": "claude-code",
            "agent_version": "1.2.3",
            "session_ref": "20260722T120000Z_local_session_id",
        },
        "detector": {
            "rule": "repeated_tool_call",
            "threshold": 5,
            "observed": 5,
            "details": "Agent called bash 5 times in 30 seconds",
        },
        "timestamps": {
            "detected_at": "2026-07-22T12:00:00Z",
            "session_started_at": "2026-07-22T11:55:00Z",
            "session_ended_at": "2026-07-22T12:05:00Z",
        },
        "evidence_refs": [
            {"type": "file", "path": "/tmp/session.log", "description": "Session log"},
        ],
        "severity": "error",
        "status": "open",
    }


# ---- Session fixtures ----


@pytest.fixture
def sample_session_jsonl() -> str:
    return (
        '{"ts":"2026-07-22T12:00:01Z","event":"tool_call","tool":"bash","input":"ls","output":"src\\ntests","duration_ms":150}\n'
        '{"ts":"2026-07-22T12:00:02Z","event":"error","error":"Exit code 1","exit_code":1}\n'
    )


@pytest.fixture
def sample_environment_json() -> dict[str, Any]:
    return {
        "os": "linux",
        "os_version": "6.8.0-1014-aws",
        "machine": "x86_64",
        "python_version": "3.11.15",
        "hostname": "<redacted>",
    }


@pytest.fixture
def sample_git_state() -> dict[str, Any]:
    return {
        "commit": "a1b2c3d4e5f67890123456789abcdef0123456789",
        "dirty": False,
        "branch": "main",
    }


# ---- Secret fixtures ----


@pytest.fixture
def seeded_secrets_text() -> str:
    """Text containing all high-confidence secret patterns."""
    return """\
My OpenAI key is sk-proj-abc123def456ghijklmnopqrsT3BlbkFJ.
Anthropic: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH.
AWS key: AKIAIOSFODNN7EXAMPLE.
GitHub token: ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD.
GitLab: glpat-abcdefghijklmnopqrstuvwxyz0123.
Slack: xoxb-123456789012-abcdefghijklmnopqrstuvwxyz.
Stripe live: sk_live_abcdefghijklmnopqrstuvwxyz012345.
JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.djmghjTviXxKABHpMwzINPJXqvY6n8M.
Bearer: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF.
Private key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0OoFh1o2F7hMjV6XzP7s
-----END RSA PRIVATE KEY-----
URL with creds: https://user:password@example.com/path.
Git remote: https://token:x-oauth-basic@github.com/user/repo.git.
Email: user@example.com
Home path: /home/johndoe/project/src/main.py
Windows path: C:\\Users\\johndoe\\AppData
"""


@pytest.fixture
def clean_text() -> str:
    """Text with no secrets (for false-positive testing)."""
    return """\
This is a clean log file.
The project version is 1.2.3.
Error: File not found at ./src/main.py (relative path).
Check the documentation at https://docs.example.com/guide.
Response time: 45ms.
Total files: 127.
"""


# ---- Incident files for integration tests ----


@pytest.fixture
def incident_file(tmp_path: Path, sample_incident) -> Path:
    p = tmp_path / "incident.json"
    p.write_text(json.dumps(sample_incident, indent=2))
    return p


@pytest.fixture
def incident_file_v2(tmp_path) -> Path:
    p = tmp_path / "incident-v2.json"
    p.write_text(json.dumps({
        "schema_version": "2.0",
        "incident_id": "inc_v2",
        "source": {"producer": "test", "producer_version": "1.0", "agent": "test"},
        "detector": {"rule": "test", "threshold": 1, "observed": 1},
        "timestamps": {"detected_at": "2026-07-22T12:00:00Z"},
    }, indent=2))
    return p


@pytest.fixture
def incident_file_with_unknown(tmp_path, sample_incident) -> Path:
    d = dict(sample_incident)
    d["action"] = "stop"
    d["timestamp"] = 1234567890
    d["config_snapshot"] = {"timeout": 60}
    p = tmp_path / "incident-unknown.json"
    p.write_text(json.dumps(d, indent=2))
    return p
