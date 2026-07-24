"""Redaction filter classes — each targets one category of sensitive data.

Placeholders follow the spec §8.3: <REDACTED_<category>_<random-id>>
where random ID has at least 64 bits of CSPRNG entropy.
"""

from __future__ import annotations

import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from .patterns import DEFAULT_REGISTRY, PatternDef, PatternRegistry


@dataclass
class RedactionChange:
    """A single redaction: what was replaced, where.

    SECURITY: The original matched value is deliberately NOT stored here.
    Only category, location, and placeholder ID are recorded.
    """

    placeholder_id: str  # e.g. "<REDACTED_api_token_a1b2c3d4>"
    category: str  # e.g. "api_token", "private_key"
    pattern_name: str  # e.g. "openai_api_key"
    file: str = ""
    line: int = 0  # 1-indexed line
    column: int = 0  # 0-indexed column
    snippet: str = ""  # context around the redaction (shows placeholder)


PLACEHOLDER_CACHE: dict[str, str] = {}
"""Maps original-literal → placeholder for the current capture session.
Cleared between captures. Stable within one bundle."""


def _make_placeholder(category: str) -> str:
    """Generate a random placeholder.

    Format: <REDACTED_<category>_<random-id>>
    random-id: 11 chars of base62 = ~64 bits entropy (CSPRNG).
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    random_part = "".join(secrets.choice(alphabet) for _ in range(11))
    return f"<REDACTED_{category}_{random_part}>"


def reset_placeholder_cache() -> None:
    """Clear the placeholder cache. Call between bundle captures."""
    PLACEHOLDER_CACHE.clear()


class RedactionFilter(ABC):
    """Base class for a redaction filter."""

    category: ClassVar[str] = "unknown"

    def __init__(self, registry: PatternRegistry | None = None):
        self._registry = registry or DEFAULT_REGISTRY

    @property
    @abstractmethod
    def patterns(self) -> list[PatternDef]:
        ...

    def redact(self, text: str) -> tuple[str, list[RedactionChange]]:
        """Find all matches and replace with stable placeholders.

        Same literal in a single capture gets the same placeholder
        across all calls (via PLACEHOLDER_CACHE).
        """
        changes: list[RedactionChange] = []
        result = text

        for pdef in self.patterns:
            result, extra = self._apply_pattern(result, pdef, text)
            changes.extend(extra)

        changes.sort(key=lambda c: (c.line, c.column))
        return result, changes

    def _apply_pattern(
        self, text: str, pdef: PatternDef, original_text: str
    ) -> tuple[str, list[RedactionChange]]:
        changes: list[RedactionChange] = []
        result_parts: list[str] = []
        last_end = 0

        for match in pdef.regex.finditer(text):
            result_parts.append(text[last_end: match.start()])

            matched = match.group(0)
            # Check cache for stable placeholder
            if matched in PLACEHOLDER_CACHE:
                placeholder = PLACEHOLDER_CACHE[matched]
            else:
                placeholder = _make_placeholder(self.category)
                PLACEHOLDER_CACHE[matched] = placeholder

            result_parts.append(placeholder)

            # Position info from original_text
            line = original_text[: match.start()].count("\n") + 1
            last_newline = original_text[: match.start()].rfind("\n")
            col = match.start() - (last_newline + 1)

            # Context snippet
            snippet = self._make_snippet(original_text, match.start(), match.end(), placeholder)

            changes.append(
                RedactionChange(
                    placeholder_id=placeholder,
                    category=self.category,
                    pattern_name=pdef.name,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            )
            last_end = match.end()

        result_parts.append(text[last_end:])
        return "".join(result_parts), changes

    @staticmethod
    def _make_snippet(text: str, start: int, end: int, placeholder: str, context: int = 40) -> str:
        ctx_start = max(0, start - context)
        ctx_end = min(len(text), end + context)
        prefix = text[ctx_start:start]
        suffix = text[end:ctx_end]
        if ctx_start > 0:
            prefix = "..." + prefix[-30:]
        if ctx_end < len(text):
            suffix = suffix[:30] + "..."
        return f"{prefix}{placeholder}{suffix}"


# ---------------------------------------------------------------------------
# Concrete filters
# ---------------------------------------------------------------------------


class ApiTokenFilter(RedactionFilter):
    category = "api_token"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.api_tokens


class PrivateKeyFilter(RedactionFilter):
    category = "private_key"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.private_keys


class UrlCredentialFilter(RedactionFilter):
    category = "url_credential"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.url_credentials


class GitCredentialFilter(RedactionFilter):
    category = "git_credential"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.git_credentials


class EmailFilter(RedactionFilter):
    category = "email"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.emails


class HomePathFilter(RedactionFilter):
    category = "home_path"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.home_paths


class HostnameFilter(RedactionFilter):
    category = "hostname"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.hostnames


class IPv4Filter(RedactionFilter):
    category = "ipv4"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.ipv4


class IPv6Filter(RedactionFilter):
    category = "ipv6"

    @property
    def patterns(self) -> list[PatternDef]:
        return self._registry.ipv6


class CustomRegexFilter(RedactionFilter):
    """A filter for user-supplied custom patterns with name and severity."""

    category = "custom"

    def __init__(
        self,
        custom_patterns: list[tuple[str, re.Pattern, str]],
        registry: PatternRegistry | None = None,
    ):
        super().__init__(registry)
        self._custom_specs = custom_patterns

    @property
    def patterns(self) -> list[PatternDef]:
        return [
            PatternDef(name=name, regex=pat, confidence=conf)
            for name, pat, conf in self._custom_specs
        ]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def default_filters(registry: PatternRegistry | None = None) -> list[RedactionFilter]:
    """Return one instance of every built-in filter.

    Filters are ordered: high-specificity first to minimise collisions.
    """
    return [
        PrivateKeyFilter(registry),
        ApiTokenFilter(registry),
        GitCredentialFilter(registry),
        UrlCredentialFilter(registry),
        EmailFilter(registry),
        HomePathFilter(registry),
        HostnameFilter(registry),
        IPv4Filter(registry),
        IPv6Filter(registry),
    ]
