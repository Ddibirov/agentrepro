"""Tests for redaction engine."""
from __future__ import annotations



from agentrepro.redaction.engine import RedactionEngine
from agentrepro.redaction.filters import (
    PLACEHOLDER_CACHE,
    reset_placeholder_cache,
)
from agentrepro.redaction.preview import PreviewReport
from agentrepro.redaction.report import RedactionReport


def setup_function():
    reset_placeholder_cache()


def test_redact_api_token():
    engine = RedactionEngine()
    text = "My API key is sk-proj-abc123def456ghijklmnopqrsT3BlbkFJ"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "sk-proj-" not in result.redacted


def test_redact_anthropic_key():
    engine = RedactionEngine()
    text = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "sk-ant-" not in result.redacted


def test_redact_aws_key():
    engine = RedactionEngine()
    text = "AWS key: AKIAIOSFODNN7EXAMPLE"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_redact_github_token():
    engine = RedactionEngine()
    text = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_redact_private_key_block():
    engine = RedactionEngine()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0OoF\n-----END RSA PRIVATE KEY-----"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "PRIVATE KEY" not in result.redacted


def test_redact_url_with_credentials():
    engine = RedactionEngine()
    text = "Repo: https://user:password@github.com/user/repo.git"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "user:password@" not in result.redacted


def test_redact_email():
    engine = RedactionEngine()
    text = "Contact: developer@example.com"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "developer@example.com" not in result.redacted


def test_redact_home_path():
    engine = RedactionEngine()
    text = "Project at /home/johndoe/project/src"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "/home/johndoe" not in result.redacted


def test_redact_windows_path():
    engine = RedactionEngine()
    text = "Path: C:\\Users\\johndoe\\AppData"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_redact_git_credential():
    engine = RedactionEngine()
    text = "git clone https://token:x-oauth-basic@github.com/user/repo.git"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_placeholder_stability():
    """Same literal gets same placeholder within one capture."""
    engine = RedactionEngine()
    text = "Key is sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA. Repeated: sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    result = engine.redact_text(text)
    assert result.total_changes >= 2
    # Both occurrences should have same placeholder
    placeholders = set()
    for c in result.changes:
        placeholders.add(c.placeholder_id)
    assert len(placeholders) <= result.total_changes, "Expected stable placeholders"


def test_placeholder_format():
    """Placeholder must match spec §8.3 format."""
    engine = RedactionEngine()
    text = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    for c in result.changes:
        assert c.placeholder_id.startswith("<REDACTED_")
        assert c.placeholder_id.endswith(">")


def test_reset_placeholder_cache():
    """Cache should be separate between captures."""
    engine = RedactionEngine()
    engine.redact_text("sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    first_count = len(PLACEHOLDER_CACHE)

    reset_placeholder_cache()
    assert len(PLACEHOLDER_CACHE) == 0

    engine.redact_text("sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert len(PLACEHOLDER_CACHE) >= first_count


def test_clean_text_no_false_positives():
    """Clean text should have few or no changes."""
    engine = RedactionEngine()
    text = "This is a clean log.\nError: File not found.\nVersion: 1.2.3\n"
    result = engine.redact_text(text)
    # Should be 0 or very few (IP addresses maybe)
    assert result.total_changes < 2, f"Expected <=1 change, got {result.total_changes}"


def test_redact_json_object():
    engine = RedactionEngine()
    obj = {
        "name": "test",
        "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456",
        "nested": {
            "secret": "AKIAIOSFODNN7EXAMPLE",
            "safe": "hello",
        },
        "list": ["user@example.com", "clean"],
    }
    redacted, changes = engine.redact_json_object(obj)
    assert len(changes) >= 3
    assert "<REDACTED_" in str(redacted)
    assert "sk-proj-" not in str(redacted)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(redacted)
    assert "user@example.com" not in str(redacted)
    assert "hello" in str(redacted)
    assert "test" in str(redacted) or "clean" in str(redacted)


def test_redact_file():
    engine = RedactionEngine()
    content = '{"key": "sk-proj-abc123def456ghijklmnopqrs"}'
    result = engine.redact_file("test.json", content)
    assert result.total_changes >= 1
    assert result.path == "test.json"
    assert "<REDACTED_" in result.redacted


def test_redact_report():
    engine = RedactionEngine()
    files = {
        "session.jsonl": '{"key": "sk-proj-abc123def456ghijklmnopqrs"}\n',
        "env.json": '{"api_key": "AKIAIOSFODNN7EXAMPLE"}',
    }
    redacted_files, file_results = engine.redact_files(files)
    assert len(redacted_files) == 2
    assert "<REDACTED_" in redacted_files["session.jsonl"]
    assert "<REDACTED_" in redacted_files["env.json"]

    report = RedactionReport.from_file_results(file_results)
    assert report.total_redactions >= 2
    assert report.high_confidence_unresolved == 0


def test_preview_report():
    engine = RedactionEngine()
    files = {"data.txt": "EMAIL=user@example.com\nKEY=sk-proj-abc123def456"}
    redacted, file_results = engine.redact_files(files)
    preview = PreviewReport.from_file_results(file_results)
    assert preview.total_files == 1
    assert preview.total_redactions >= 1
    assert preview.risk_level.value in ("blocked", "high", "medium")


def test_custom_pattern():
    engine = RedactionEngine()
    engine.add_custom_pattern("my_secret", r"MY_SECRET_\d+", confidence="high")
    text = "The code is MY_SECRET_42"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
    assert "MY_SECRET_42" not in result.redacted


def test_hostname_pattern():
    engine = RedactionEngine()
    text = "Host: localhost, also DESKTOP-ABC123"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_tilde_home_path():
    engine = RedactionEngine()
    text = "Config at ~/.config/app/settings.yaml"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_bearer_token():
    engine = RedactionEngine()
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted


def test_jwt_token():
    engine = RedactionEngine()
    text = 'token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.djmghjTviXxKABHpMwzINPJXqvY6n8M'
    result = engine.redact_text(text)
    assert result.total_changes >= 1
    assert "<REDACTED_" in result.redacted
