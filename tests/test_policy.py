"""Tests for collection policy (hard-deny, safe path resolution)."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentrepro.policy import (
    check_hard_deny_resolved,
    check_file_size,
    check_media_type_binary,
    safe_resolve_path,
)


def test_hard_deny_env_file():
    matches = check_hard_deny_resolved("/home/user/.env")
    assert len(matches) > 0
    assert any("deny" in m[1].lower() for m in matches) or any(".env" in m[0] for m in matches)


def test_hard_deny_pem_file():
    matches = check_hard_deny_resolved("/home/user/credentials.pem")
    assert len(matches) > 0


def test_hard_deny_key_file():
    matches = check_hard_deny_resolved("private.key")
    assert len(matches) > 0


def test_hard_deny_ssh_dir():
    matches = check_hard_deny_resolved("/home/user/.ssh/id_rsa")
    assert len(matches) > 0


def test_hard_deny_git_credentials():
    matches = check_hard_deny_resolved("/home/user/.git-credentials")
    assert len(matches) > 0


def test_hard_deny_bash_history():
    matches = check_hard_deny_resolved("/home/user/.bash_history")
    assert len(matches) > 0


def test_hard_deny_aws():
    matches = check_hard_deny_resolved("/home/user/.aws/credentials")
    assert len(matches) > 0


def test_hard_deny_netrc():
    matches = check_hard_deny_resolved("/home/user/.netrc")
    assert len(matches) > 0


def test_hard_deny_secrets_yaml():
    matches = check_hard_deny_resolved("/project/secrets.yaml")
    assert len(matches) > 0


def test_hard_deny_no_match():
    matches = check_hard_deny_resolved("/home/user/project/src/main.py")
    assert len(matches) == 0


def test_hard_deny_no_match_regular_file():
    matches = check_hard_deny_resolved("/tmp/test.txt")
    assert len(matches) == 0


def test_binary_detection():
    assert check_media_type_binary(b"\x00\x01\x02") is True
    assert check_media_type_binary(b"hello world") is False
    assert check_media_type_binary("привет".encode("utf-8")) is False


def test_file_size_check(tmp_path):
    small = tmp_path / "small.txt"
    small.write_text("x" * 100)
    size = check_file_size(small, max_bytes=1000)
    assert size == 100

    big = tmp_path / "big.txt"
    big.write_text("x" * 2000)
    with pytest.raises(Exception, match="E_POLICY_SIZE"):
        check_file_size(big, max_bytes=1000)


def test_safe_resolve_nonexistent(tmp_path):
    with pytest.raises(Exception, match="E_POLICY_NOT_FOUND"):
        safe_resolve_path(tmp_path / "nonexistent.txt")


def test_safe_resolve_directory(tmp_path):
    with pytest.raises(Exception, match="E_POLICY_DIR"):
        safe_resolve_path(tmp_path)
