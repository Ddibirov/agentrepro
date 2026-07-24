"""Compiled regex patterns for all redaction categories.

Each pattern is compiled once at import time.
Patterns are ordered by specificity to minimise false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PatternDef:
    """A named regex pattern with metadata."""

    name: str
    regex: re.Pattern
    confidence: str = "high"  # 'high' (blocks export) or 'medium' (warns)


# ---------------------------------------------------------------------------
# API / Provider tokens
# ---------------------------------------------------------------------------

API_TOKEN_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="openai_api_key",
        regex=re.compile(r'sk-(?:proj-|svc-|)[A-Za-z0-9]{20,}(?:T3BlbkFJ[0-9A-Za-z]{12,})?'),
    ),
    PatternDef(
        name="anthropic_api_key",
        regex=re.compile(r'sk-ant-(?:api|admin|staff)[0-9A-Za-z_-]{40,}'),
    ),
    PatternDef(
        name="aws_access_key",
        regex=re.compile(r'(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}'),
    ),
    PatternDef(
        name="github_token",
        regex=re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
    ),
    PatternDef(
        name="gitlab_token",
        regex=re.compile(r'glpat-[A-Za-z0-9_-]{20,}'),
    ),
    PatternDef(
        name="slack_token",
        regex=re.compile(r'xoxb-[0-9A-Za-z-]{24,}|xoxp-[0-9A-Za-z-]{24,}|xapp-[0-9A-Za-z-]{24,}'),
    ),
    PatternDef(
        name="stripe_live_key",
        regex=re.compile(r'(?:sk|pk|rk)_live_[0-9A-Za-z]{24,}'),
    ),
    PatternDef(
        name="stripe_test_key",
        regex=re.compile(r'(?:sk|pk|rk)_test_[0-9A-Za-z]{24,}'),
        confidence="medium",
    ),
    PatternDef(
        name="jwt_token",
        regex=re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    ),
    PatternDef(
        name="generic_bearer_token",
        regex=re.compile(r'(?:Bearer|bearer|TOKEN|token)\s+[A-Za-z0-9_\-\.]{20,}'),
    ),
    PatternDef(
        name="generic_api_key_header",
        regex=re.compile(r'(?:X-API-Key|api_key|apikey):\s*[A-Za-z0-9_\-]{16,}'),
        confidence="medium",
    ),
    PatternDef(
        name="generic_secret_env",
        regex=re.compile(r'(?:SECRET|PASSWORD|TOKEN|API_KEY|SECRET_KEY)\s*=\s*[A-Za-z0-9_\-\.!@#$%^&*]{16,}'),
        confidence="medium",
    ),
]

# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------

PRIVATE_KEY_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="private_key_block",
        regex=re.compile(
            r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+(?:\w+\s+)*KEY(?:\s+\w+)*-----'
            r'[\s\S]*?'
            r'-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+(?:\w+\s+)*KEY-----',
        ),
    ),
    PatternDef(
        name="ssh_private_key",
        regex=re.compile(r'-----BEGIN\s+SSH2\s+(?:ENCRYPTED\s+)?PRIVATE\s+KEY-----'),
    ),
    PatternDef(
        name="ssh_pem_key",
        regex=re.compile(r'PuTTY-User-Key-File-2:\s+\S+'),
    ),
]

# ---------------------------------------------------------------------------
# URLs with embedded credentials
# ---------------------------------------------------------------------------

URL_CREDENTIAL_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="url_with_credentials",
        regex=re.compile(r'https?://[^\s:@/]+:[^\s:@/]+@[^\s]+'),
    ),
]

# ---------------------------------------------------------------------------
# Git remote credentials
# ---------------------------------------------------------------------------

GIT_CREDENTIAL_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="git_remote_https_credentials",
        regex=re.compile(r'https?://[^\s:@/]+:[^\s:@/]+@[^\s]+?(?:\.git\b|[^\s]*)'),
    ),
    PatternDef(
        name="git_remote_ssh_with_key_path",
        regex=re.compile(r'ssh://[^\s@]+@[^\s]+?(?:\.git\b|[^\s]*)'),
        confidence="medium",
    ),
]

# ---------------------------------------------------------------------------
# Email addresses
# ---------------------------------------------------------------------------

EMAIL_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="email",
        regex=re.compile(r'[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
        confidence="medium",
    ),
]

# ---------------------------------------------------------------------------
# Home paths
# ---------------------------------------------------------------------------

HOME_PATH_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="home_path",
        regex=re.compile(r"""(?:^|[\s"'=,])/(?:home|Users)/([A-Za-z0-9_.-]+)(?:/[^\s"'\]\[:;,;]*)?"""),
        confidence="medium",
    ),
    PatternDef(
        name="tilde_home_path",
        regex=re.compile(r"""(?<![A-Za-z])~/(?:[^\s"'\]\[:;,]*)"""),
        confidence="medium",
    ),
    PatternDef(
        name="windows_home_path",
        regex=re.compile(r"""[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+(?:\\[^\s"'\]\[:;,]*)?"""),
        confidence="medium",
    ),
]

# ---------------------------------------------------------------------------
# Local hostnames
# ---------------------------------------------------------------------------

HOSTNAME_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="local_hostname",
        regex=re.compile(r'\b(?:localhost|hostname|DESKTOP-[A-Z0-9]+|WIN-[A-Z0-9]+)\b'),
        confidence="medium",
    ),
]

# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

IPV4_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="ipv4_address",
        regex=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'),
        confidence="medium",
    ),
]

IPV6_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="ipv6_address",
        regex=re.compile(
            r'(?<![A-Fa-f0-9:])'
            r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,7}:'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}'
            r'|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}'
            r'|:(?::[A-Fa-f0-9]{1,4}){1,7}'
            r'|::(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4}'
            r'|fe80:(?::[A-Fa-f0-9]{0,4}){0,4}%[0-9A-Za-z]{1,}'
            r'|::(?:ffff(?::0{1,4})?)?(?:(?:\d{1,3}\.){3}\d{1,3})'
            r'|(?:[A-Fa-f0-9]{1,4}:){1,4}:(?:(?:\d{1,3}\.){3}\d{1,3})'
            r'(?![A-Fa-f0-9:])',
        ),
        confidence="medium",
    ),
]


# ---------------------------------------------------------------------------
# Combined registry
# ---------------------------------------------------------------------------


@dataclass
class PatternRegistry:
    """Aggregates all pattern categories."""

    api_tokens: list[PatternDef] = field(default_factory=lambda: list(API_TOKEN_PATTERNS))
    private_keys: list[PatternDef] = field(default_factory=lambda: list(PRIVATE_KEY_PATTERNS))
    url_credentials: list[PatternDef] = field(default_factory=lambda: list(URL_CREDENTIAL_PATTERNS))
    git_credentials: list[PatternDef] = field(default_factory=lambda: list(GIT_CREDENTIAL_PATTERNS))
    emails: list[PatternDef] = field(default_factory=lambda: list(EMAIL_PATTERNS))
    home_paths: list[PatternDef] = field(default_factory=lambda: list(HOME_PATH_PATTERNS))
    hostnames: list[PatternDef] = field(default_factory=lambda: list(HOSTNAME_PATTERNS))
    ipv4: list[PatternDef] = field(default_factory=lambda: list(IPV4_PATTERNS))
    ipv6: list[PatternDef] = field(default_factory=lambda: list(IPV6_PATTERNS))
    custom: list[PatternDef] = field(default_factory=list)

    def add_custom(self, name: str, pattern: re.Pattern, confidence: str = "high") -> None:
        """Register a custom redaction pattern."""
        self.custom.append(PatternDef(name=name, regex=pattern, confidence=confidence))

    def all_patterns(self, skip_categories: set[str] | None = None) -> list[tuple[str, PatternDef]]:
        """Return all patterns as (category, PatternDef) tuples."""
        skip = skip_categories or set()
        result: list[tuple[str, PatternDef]] = []
        mapping = [
            ("api_token", self.api_tokens),
            ("private_key", self.private_keys),
            ("url_credential", self.url_credentials),
            ("git_credential", self.git_credentials),
            ("email", self.emails),
            ("home_path", self.home_paths),
            ("hostname", self.hostnames),
            ("ipv4", self.ipv4),
            ("ipv6", self.ipv6),
            ("custom", self.custom),
        ]
        for cat, patterns in mapping:
            if cat not in skip:
                for p in patterns:
                    result.append((cat, p))
        return result


# Singleton for convenience
DEFAULT_REGISTRY = PatternRegistry()
