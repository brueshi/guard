---
name: guard
description: Redact secrets (API keys, tokens, JWTs, high-entropy strings) from a file, the clipboard, a staged git diff, or pasted content using the `guard` CLI. Use when the user types `/guard`, asks to "scrub", "sanitize", or "redact" content, asks whether something is safe to share or paste, or wants a pre-commit secret scan before `git commit`.
---

# /guard

Invoke the `guard` CLI to detect and redact secrets in content the user is about to share externally or commit. `guard` reads stdin, writes redacted content to stdout, and writes a report to stderr (so the pipe stays clean).

## Modes

Pick based on what the user passed as args:

| User invocation | Command to run |
|---|---|
| `/guard` (no args) | `pbpaste \| guard --summary \| pbcopy` — clipboard in, redacted clipboard out |
| `/guard <path>` | `cat <path> \| guard --summary` — show what would be redacted |
| `/guard diff` | `git diff --staged \| guard --summary` — pre-commit secret scan |
| `/guard <inline text>` | `printf '%s' '<text>' \| guard --summary` — scan literal text |

Always include `--summary` (or `--json` if the user explicitly wants a machine-readable report) so the user sees what was caught.

## Exit codes

- `0` — clean, no secrets detected
- `1` — redactions were made (this is the *expected* outcome when secrets exist, **not** an error — guard did its job)
- `2` — invocation error

When exit is 1, do **not** treat it as a failure. Read stderr to get the summary, show it to the user, and present the redacted stdout. Bash tooling that conflates non-zero exit with error needs the count to be reported as success-with-findings.

## Pre-commit workflow

When the user is about to `git commit`, proactively suggest `/guard diff` first. If hits are reported, ask the user whether to:

1. Edit the staged files to remove the secrets, then re-stage and commit (recommended — secrets in git history are hard to scrub).
2. Knowingly override and commit anyway.

If guard catches a value the user knows is fine (a fixture, a documented example), suggest, in order of preference:

1. `allow:<substring>` in `.guardignore` — persists across runs and is shared with the repo.
2. A path glob in `.guardignore`, if a whole generated file is the problem.
3. `# noscan` / `// noscan` on the line, for a one-off.
4. `--allow <substring>` for the current invocation only.

A false positive is worth reporting upstream rather than working around silently — the suppression rules are built from measured cases.

## Output handling

- **Clipboard mode**: `pbpaste | guard | pbcopy` puts the redacted version on the clipboard. Confirm "clipboard sanitized" with the count and types of redactions from the stderr summary.
- **File / diff / inline modes**: stdout has the redacted content, stderr has the report. Show the user the report. If the user asked for the redacted body, show that too — but do not echo the *original* values back at any point. Only the placeholders (`[REDACTED:name:N]`) should appear in your reply.

## If `guard` is not installed

Run the install one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/brueshi/guard/main/install.sh | sh
```

Confirm with `which guard`. If `~/.local/bin` is not on PATH, advise the user to add it to their shell profile.

## What `guard` detects

29 provider patterns (Anthropic, OpenAI, Google, GCP, HuggingFace, GitHub classic + fine-grained, GitLab, AWS, DigitalOcean, Stripe secret/webhook, Slack, Docker, npm, Linear, Figma, Postman, Sentry, Brave, Tavily, Heroku, Atlassian, JWT) plus multi-line PEM private keys, passwords embedded in connection-string URIs, and a Shannon-entropy fallback (≥4.5 bits/char, ≥20 chars) for unknown providers. Stable per-pattern counter placeholders so the same secret reuses its index within a run — no content hash, no cross-run linkability.

The entropy fallback only fires on tokens that sit in credential context — in value position, or on a line naming a credential. This is deliberate: it keeps identifier chains, resource paths, integrity digests and URLs quiet. If the user is scanning a bare blob with no surrounding code and wants maximum recall, add `--strict`.

Guard skips generated files (lockfiles, minified bundles, source maps, build dirs) when the input is a diff. Whole-file scans are never path-filtered, so `cat pnpm-lock.yaml | guard` still scans everything.

Source: https://github.com/brueshi/guard
