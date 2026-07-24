"""Source collection policy — safe path handling, hard-deny, limits.

Implements the collection policy from the AgentRepro spec §7.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from agentrepro.errors import PolicyError

# ---- Limits (v0.1 defaults) ----

MAX_REGULAR_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_UNCOMPRESSED_PAYLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB
MAX_ARCHIVE_MEMBERS = 100
MAX_SESSION_EVENTS = 200
MAX_SESSION_FIELD_BYTES = 16 * 1024  # 16 KiB
MAX_SESSION_JSONL_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_EVIDENCE_ITEMS = 20
MAX_COMPRESSION_RATIO = 100  # verifier rejects tar bomb


# ---- Hard-deny patterns ----
# Applied to resolved absolute path AND basename before reading bytes.
# Order: most specific first. First match wins.

HARD_DENY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SSH directory", re.compile(r"(^|/)\.ssh/")),
    ("AWS credentials", re.compile(r"(^|/)\.aws/")),
    ("Azure credentials", re.compile(r"(^|/)\.azure/")),
    ("GCloud credentials", re.compile(r"(^|/)\.config/gcloud/")),
    ("GSutil credentials", re.compile(r"(^|/)\.config/gsutil/")),
    ("OCI credentials", re.compile(r"(^|/)\.config/oci/")),
    ("GPG directory", re.compile(r"(^|/)\.gnupg/")),
    ("Password store", re.compile(r"(^|/)\.password-store/")),
    (
        "Agent credentials",
        re.compile(
            r"(^|/)\.claude/credentials|"
            r"(^|/)\.codex/config|"
            r"(^|/)\.config/opencode/credentials"
        ),
    ),
    ("Git credentials file", re.compile(r"(^|/)\.git-credentials$")),
    ("Git config", re.compile(r"(^|/)\.gitconfig$")),
    ("Netrc", re.compile(r"(^|/)\.netrc$")),
    ("PGPass", re.compile(r"(^|/)\.pgpass$")),
    ("My.cnf", re.compile(r"(^|/)\.my\.cnf$")),
    ("Npmrc", re.compile(r"(^|/)\.npmrc$")),
    ("PyPirc", re.compile(r"(^|/)\.pypirc$")),
    ("Bash history", re.compile(r"(^|/)\.bash_history$")),
    ("Zsh history", re.compile(r"(^|/)\.zsh_history$")),
    ("Python history", re.compile(r"(^|/)\.python_history$")),
    ("Fish history", re.compile(r"(^|/)\.local/share/fish/fish_history$")),
    (
        "Shell history (legacy)",
        re.compile(r"(^|/)\.history$"),
    ),
    (
        "Browser cookies",
        re.compile(
            r"(^|/)Cookies$|"
            r"(^|/)Cookies\.db$|"
            r"(^|/)logins\.json$|"
            r"(^|/)Login Data$"
        ),
    ),
    (
        "Environment/credential files",
        re.compile(
            r"(^|/)\.env$|"
            r"(^|/)\.env\.[^. ]+|"
            r"(^|/)\.envrc$|"
            r"(^|/)credentials$|"
            r"(^|/)\.credentials$|"
            r"(^|/)secrets\.yml$|"
            r"(^|/)secrets\.yaml$|"
            r"(^|/)vault\.yml$|"
            r"(^|/)vault\.yaml$"
        ),
    ),
    (
        "Private key extensions",
        re.compile(
            r"\.pem$|\.key$|\.cert$|\.p12$|\.pfx$|"
            r"\.age$|\.enc$|\.encrypted$"
        ),
    ),
]


def check_hard_deny_resolved(resolved_path: str | Path) -> list[tuple[str, str]]:
    """Check a resolved absolute path AND its basename against hard-deny.

    Must be called BEFORE read_bytes/read_text.

    Args:
        resolved_path: The resolved absolute path (after realpath/resolve).

    Returns:
        List of (path_checked, reason) tuples for each match.
        Empty list = no hard-deny match.
    """
    path_str = str(resolved_path)
    basename = os.path.basename(path_str)
    matches: list[tuple[str, str]] = []

    for reason, pattern in HARD_DENY_PATTERNS:
        if pattern.search(path_str) or pattern.search(basename):
            matches.append((path_str, reason))
            break  # First match wins, per spec

    return matches


def safe_resolve_path(
    path: str | Path,
    allowed_root: str | Path | None = None,
) -> Path:
    """Resolve a path safely with symlink checks.

    1. Reject NUL, non-existent, directory, special file, overlong path.
    2. Resolve symlinks; reject if resolved target differs from allowed root.
    3. Check hard-deny on resolved path.
    4. Check hard-deny on basename.

    Returns resolved Path if safe.
    Raises PolicyError on any violation.
    """
    p = Path(path)

    # Reject NUL bytes
    if "\0" in str(p):
        raise PolicyError(f"Path contains NUL byte: {p}", code="E_POLICY_NUL")

    # Must exist
    if not p.exists() and not p.is_symlink():
        raise PolicyError(f"Path does not exist: {p}", code="E_POLICY_NOT_FOUND")

    # Reject directories and special files
    if p.is_dir():
        raise PolicyError(f"Path is a directory, not a file: {p}", code="E_POLICY_DIR")
    if not p.is_file():
        raise PolicyError(f"Not a regular file: {p}", code="E_POLICY_SPECIAL")

    # Path too long
    if len(str(p)) > 4096:
        raise PolicyError(f"Path too long ({len(str(p))} bytes)", code="E_POLICY_PATH_LENGTH")

    # Resolve symlinks
    try:
        resolved = p.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise PolicyError(f"Cannot resolve path: {e}", code="E_POLICY_RESOLVE")

    # If allowed_root specified, check resolved path is within it
    if allowed_root is not None:
        allowed = Path(allowed_root).resolve(strict=True)
        if not str(resolved).startswith(str(allowed)):
            raise PolicyError(
                f"Resolved path {resolved} is outside allowed root {allowed}",
                code="E_POLICY_OUTSIDE_ROOT",
            )

    # Hard-deny check before reading
    deny = check_hard_deny_resolved(resolved)
    if deny:
        _, reason = deny[0]
        raise PolicyError(
            f"Hard-deny: {resolved} matched '{reason}'",
            code="E_POLICY_HARD_DENY",
        )

    return resolved


def check_file_size(file_path: Path, max_bytes: int = MAX_REGULAR_FILE_BYTES) -> int:
    """Check file size is within limit. Returns file size."""
    size = file_path.stat().st_size
    if size > max_bytes:
        raise PolicyError(
            f"File too large: {file_path} ({size} bytes, limit {max_bytes})",
            code="E_POLICY_SIZE",
        )
    return size


def check_media_type_binary(content: bytes) -> bool:
    """Heuristic check: is content likely binary/undecodable?

    Returns True if the content appears to be binary (first 8KB check).
    """
    sample = content[:8192]
    if not sample:
        return False
    # Count null bytes and high bit chars
    nulls = sample.count(b"\x00")
    # If >1% null bytes or undecodable as UTF-8 with errors
    if nulls > 0:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False
