"""AgentRepro error taxonomy.

Every public exit path maps to one of these codes.
"""

from __future__ import annotations

import sys


class AgentReproError(Exception):
    """Base error for all AgentRepro errors."""

    exit_code: int = 1

    def __init__(self, message: str, code: str | None = None) -> None:
        self._code = code or self.__class__.__name__.upper()
        super().__init__(f"[{self._code}] {message}")

    @property
    def code(self) -> str:
        return self._code

    def exit(self) -> None:
        print(f"error [{self.code}]: {self.args[0]}", file=sys.stderr)
        sys.exit(self.exit_code)


class UsageError(AgentReproError):
    """Invalid or incompatible flags."""
    exit_code = 2


class SourceError(AgentReproError):
    """Source unavailable, adapter cannot resolve, unreadable source."""
    exit_code = 3


class SchemaError(AgentReproError):
    """Schema invalid or unsupported major version."""
    exit_code = 4


class PolicyError(AgentReproError):
    """Hard-deny, type/size cap, residual high-risk secret."""
    exit_code = 5


class ConfirmationError(AgentReproError):
    """Preview confirmation required."""
    exit_code = 6


class ArchiveError(AgentReproError):
    """Unsafe/malformed/tar-bomb archive."""
    exit_code = 7


class IntegrityError(AgentReproError):
    """Inventory or checksum mismatch."""
    exit_code = 8


class PrepareError(AgentReproError):
    """Safe isolated preparation impossible."""
    exit_code = 9
