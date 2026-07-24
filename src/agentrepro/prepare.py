"""Safe prepare — isolated reproduction worktree creation.

Matches spec §10.3: requires verify --strict success first,
creates only a detached Git worktree, never modifies current tree,
no network, no shell, no auto-patch apply.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from agentrepro.bundle.reader import BundleReader
from agentrepro.bundle.verify import BundleVerify
from agentrepro.errors import PrepareError


def cmd_prepare(
    bundle_path: str | Path,
    repo_path: str | Path,
    dir_path: str | Path,
    yes: bool = False,
) -> int:
    """Prepare a reproduction worktree from a bundle (spec §10.3).

    Returns exit code (0 = success, 9 = error).
    """
    bundle = Path(bundle_path)
    repo = Path(repo_path).resolve()
    target = Path(dir_path).resolve()

    # --- Step 1: require verify --strict ---
    verifier = BundleVerify(strict=True)
    verify_result = verifier.verify(bundle)
    if not verify_result.valid:
        errors = [i for i in verify_result.issues if i.severity == "error"]
        if errors:
            print("Bundle verification failed. Prepare requires strict verification.")
            for i in errors:
                print(f"  [{i.code}] {i.message}")
            return 9

    # --- Step 2: validate repo ---
    if not repo.is_dir():
        print(f"Error: --repo must be an existing directory: {repo}")
        return 9

    git_dir = repo / ".git"
    if not git_dir.is_dir() and not (git_dir.is_file() and repo / ".git"):  # bare repo or worktree
        # Check if it's a git worktree
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=repo, capture_output=True, timeout=10, check=True,
            )
        except Exception:
            print(f"Error: --repo is not a Git repository: {repo}")
            return 9

    # --- Step 3: validate target ---
    if target.exists():
        try:
            contents = list(target.iterdir())
            if contents:
                print(f"Error: --dir must be empty or non-existent: {target}")
                return 9
        except PermissionError:
            print(f"Error: cannot access --dir: {target}")
            return 9
    else:
        target.mkdir(parents=True, exist_ok=True)

    # --- Step 4: read git-state from bundle ---
    try:
        with BundleReader(bundle) as reader:
            git_state = reader.read_json("git-state.json")
    except Exception as e:
        print(f"Cannot read git-state from bundle: {e}")
        return 9

    baseline_commit = (git_state or {}).get("commit", "")
    if not baseline_commit:
        print("Warning: bundle has no baseline commit; using HEAD.")
        baseline_commit = "HEAD"

    # --- Step 5: record original repo state ---
    try:
        original_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo, capture_output=True, timeout=10, text=True,
        ).stdout.strip()
    except Exception as e:
        print(f"Cannot determine original HEAD: {e}")
        return 9

    # --- Step 6: verify baseline commit exists ---
    try:
        subprocess.run(
            ["git", "cat-file", "-e", baseline_commit],
            cwd=repo, capture_output=True, timeout=10, check=True,
        )
    except Exception:
        print(f"Baseline commit not found in repo: {baseline_commit}")
        return 9

    # --- Step 7: create detached worktree (fixed argv, no shell) ---
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(target), baseline_commit],
            cwd=repo, capture_output=True, timeout=30, check=True,
        )
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else str(e)
        print(f"Failed to create worktree: {stderr}")
        # Clean up empty target on failure
        if target.exists() and not list(target.iterdir()):
            target.rmdir()
        return 9

    # --- Step 8: verify original repo is unchanged ---
    try:
        new_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo, capture_output=True, timeout=10, text=True,
        ).stdout.strip()
        if new_head != original_head:
            print(f"ERROR: Original repo HEAD changed! Was {original_head}, now {new_head}")
            return 9
    except Exception:
        pass

    print(f"Worktree created at: {target}")
    print(f"  Baseline commit: {baseline_commit}")
    print()
    print("Suggested commands from REPRODUCE.md (review before executing):")
    print(f"  cd {target}")
    print("  # Review bundle contents and follow REPRODUCE.md instructions")
    print("  # Commands are NOT auto-executed per security policy")

    return 0
