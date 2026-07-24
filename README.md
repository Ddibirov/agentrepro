# AgentRepro

**Coding agent incident reproduction bundles** — collect, redact, verify.

AgentRepro is a CLI tool that creates minimal, redacted, verifiable incident bundles from coding agent sessions (Claude Code, Codex CLI). It helps you share reproducible bug reports without leaking API keys, credentials, or private paths.

## Features

- **Capture** session excerpts from Claude Code and Codex CLI with one command
- **Redact** API tokens, private keys, URLs, emails, and home paths automatically
- **Preview** redaction results before creating a bundle
- **Verify** bundle integrity and security offline
- **Inspect** bundle metadata without extraction
- **Prepare** detached Git worktrees for safe reproduction
- **Import** incidents from Loopbreaker and other watchdogs via `agent-incident/1` schema

## Quick Start

```bash
# Install
pip install agentrepro

# Capture most recent Claude Code session
agentrepro capture --last --agent claude

# Capture most recent Codex CLI session
agentrepro capture --last --agent codex

# Preview what would be captured (no bundle written)
agentrepro preview --last --agent claude

# Verify a bundle
agentrepro verify bug-20260724.agentrepro.tar.zst

# Inspect bundle metadata
agentrepro inspect bug-20260724.agentrepro.tar.zst

# Prepare a reproduction worktree
agentrepro prepare bug.agentrepro.tar.zst --repo /path/to/repo --dir /tmp/repro
```

## Commands

| Command | Description |
|---------|-------------|
| `capture` | Create an incident reproduction bundle |
| `preview` | Preview redaction results without writing a bundle |
| `inspect` | Show bundle metadata without extraction |
| `verify` | Verify bundle integrity and security (offline) |
| `prepare` | Create a detached Git worktree for safe reproduction |
| `redact test` | Test redaction rules against a fixture file |

## Bundle Format

AgentRepro produces standard POSIX tar archives (`.agentrepro.tar.zst` by default) containing:

- `manifest.json` — bundle metadata and file inventory
- `checksums.txt` — SHA-256 checksums for every payload file
- `REPRODUCE.md` — reproduction instructions
- `session.jsonl` — canonical session transcript (redacted)
- `environment.json` — OS and runtime info (no secrets)
- `git-state.json` — Git commit and dirty state
- `redaction-report.json` — redaction details (no original values)
- `incident.json` — incident record (if imported)
- `schemas/` — JSON Schemas for full offline verification

## Supported Agents

- **Claude Code** — sessions from `~/.claude/projects/*/*.jsonl`
- **Codex CLI** — sessions from `~/.codex/sessions/*/*/*/rollout-*.jsonl`
- **OpenCode** — planned for v0.2

## Security

- Hard-deny prevents `.env`, private keys, SSH directories, and credential files from being read
- Structured redaction replaces sensitive values with stable placeholders (`<REDACTED_api_token_a1b2c3>`)
- Bundle verification is fully offline with no network calls
- `prepare` never modifies the current working tree
- No telemetry, no network calls by default

## License

MIT
