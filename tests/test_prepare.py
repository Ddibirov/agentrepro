"""Tests for prepare module (spec §10.3)."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agentrepro.bundle.verify import BundleVerify
from agentrepro.bundle.writer import BundleWriter
from agentrepro.prepare import cmd_prepare


@pytest.fixture
def git_repo_with_commit(tmp_path: Path) -> Path:
    """Create a git repo with an initial commit."""
    repo = tmp_path / "source-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)
    readme = repo / "README.md"
    readme.write_text("# Test")
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True)
    return repo


@pytest.fixture
def bundle_with_git_state(tmp_path: Path, git_repo_with_commit: Path) -> Path:
    """Create a bundle that includes git-state.json pointing to the test repo."""
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo_with_commit, capture_output=True, text=True,
    ).stdout.strip()

    bundle = tmp_path / "test-bundle.tar.zst"
    w = BundleWriter(bundle)
    git_state = json.dumps({"commit": commit, "dirty": False, "branch": "master"})
    w.add_payload("git-state.json", git_state, role="git_state")
    w.add_payload("REPRODUCE.md", "# Reproduction test", role="reproduce")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    w.write()
    return bundle


def test_prepare_requires_verify_strict(tmp_path, bundle_with_git_state, git_repo_with_commit):
    """Prepare should verify bundle first with strict=True."""
    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bundle_with_git_state,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 0, f"Prepare failed with code {rc}"
    assert target.is_dir()
    assert (target / "README.md").exists()


def test_prepare_missing_repo(tmp_path, bundle_with_git_state):
    """Prepare should fail with non-existent repo."""
    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bundle_with_git_state,
        repo_path=tmp_path / "nonexistent",
        dir_path=target,
    )
    assert rc == 9


def test_prepare_missing_commit(tmp_path, git_repo_with_commit):
    """Prepare should fail when commit in bundle doesn't exist in repo."""
    bundle = tmp_path / "bad-commit.tar.zst"
    w = BundleWriter(bundle)
    w.add_payload("git-state.json", json.dumps({"commit": "a" * 40, "dirty": False}), role="git_state")
    w.add_payload("REPRODUCE.md", "# Test", role="reproduce")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    w.write()

    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bundle,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 9


def test_prepare_fails_on_nonempty_target(tmp_path, bundle_with_git_state, git_repo_with_commit):
    """Prepare should reject non-empty target directory."""
    target = tmp_path / "occupied"
    target.mkdir()
    (target / "file.txt").write_text("x")

    rc = cmd_prepare(
        bundle_path=bundle_with_git_state,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 9


def test_prepare_does_not_modify_source(tmp_path, bundle_with_git_state, git_repo_with_commit):
    """Prepare must not change the source working tree."""
    before = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo_with_commit, capture_output=True, text=True,
    ).stdout.strip()

    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bundle_with_git_state,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 0

    after = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo_with_commit, capture_output=True, text=True,
    ).stdout.strip()
    assert before == after


def test_prepare_bundle_without_git_state(tmp_path, git_repo_with_commit):
    """Prepare should handle bundles without git-state.json."""
    bundle = tmp_path / "no-git.tar.zst"
    w = BundleWriter(bundle)
    w.add_payload("REPRODUCE.md", "# No git state", role="reproduce")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    w.write()

    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bundle,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 9  # Missing git-state.json should fail


def test_prepare_bundle_verify_failure(tmp_path, git_repo_with_commit):
    """Prepare should reject bundles that fail strict verify."""
    import tarfile, io

    bad_bundle = tmp_path / "bad.tar"
    with tarfile.open(bad_bundle, "w") as tar:
        info = tarfile.TarInfo(name="../etc/passwd")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"root:"))

    target = tmp_path / "worktree"
    rc = cmd_prepare(
        bundle_path=bad_bundle,
        repo_path=git_repo_with_commit,
        dir_path=target,
    )
    assert rc == 9
