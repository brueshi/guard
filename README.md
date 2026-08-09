# guard

A Zig-native secrets scanner designed for the moment before you share code. Reads stdin, redacts API keys and high-entropy strings inline, writes the cleaned content to stdout. Reports go to stderr so the pipe stays clean.

```bash
cat src/api/client.ts | guard | pbcopy
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/brueshi/guard/main/install.sh | sh
```

Installs to `$HOME/.local/bin/guard` by default. Override with `GUARD_INSTALL_DIR`.

Pre-built binaries available for `aarch64-macos`, `x86_64-macos`, `x86_64-linux`, and `aarch64-linux`. SHA-256 checksums published with each release.

### Use as a Claude Code skill

Install the `/guard` slash command so Claude Code can run guard on your behalf — over a file, the clipboard, or `git diff --staged` (handy as a pre-commit check):

```bash
mkdir -p ~/.claude/skills/guard && \
  curl -fsSL https://raw.githubusercontent.com/brueshi/guard/main/skills/guard/SKILL.md \
  -o ~/.claude/skills/guard/SKILL.md
```

Then in Claude Code:

| Invocation | What runs |
|---|---|
| `/guard` | `pbpaste \| guard --summary \| pbcopy` (clipboard in, redacted clipboard out) |
| `/guard <path>` | `cat <path> \| guard --summary` |
| `/guard diff` | `git diff --staged \| guard --summary` (pre-commit scan) |
| `/guard <text>` | scan literal text |

## Usage

```bash
# Sanitize before pasting into an LLM
cat src/api/client.ts | guard | pbcopy

# With a human-readable report on stderr
cat src/api/client.ts | guard --summary | pbcopy

# Sanitize a staged diff
git diff --staged | guard | pbcopy

# Machine-readable report (for tooling, CI, agent integration)
cat secrets.env | guard --json
```

`stdout` always carries only the redacted content. `stderr` is for reports. The pipe is never contaminated by either flag combination.

### Shell aliases

```bash
alias llmcopy="guard --summary | pbcopy"
alias diffcopy="git diff --staged | guard --summary | pbcopy"
```

## Detection

29 provider patterns plus a context-gated Shannon-entropy fallback for unknown providers.

| Category | Patterns |
|---|---|
| AI | Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), Google (`AIza`), GCP OAuth (`ya29.`), HuggingFace (`hf_`) |
| Code hosts | GitHub classic (`ghp_`/`gho_`/`ghs_`/`ghu_`), GitHub fine-grained (`github_pat_`), GitLab (`glpat-`) |
| Cloud | AWS (`AKIA`/`ASIA`), DigitalOcean (`dop_v1_`) |
| Payments | Stripe secret (`sk_live_`/`sk_test_`/`rk_*`), Stripe publishable (`pk_*`), Stripe webhook (`whsec_`) |
| Comms / infra | Slack (`xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xapp-`), Docker (`dckr_pat_`), npm (`npm_`), Linear (`lin_api_`), Figma (`figd_`) |
| Standards | JWT (`eyJ` with three base64url segments) |
| Generic | High-entropy strings (≥4.5 bits/char, ≥20 chars) in credential context, tunable via `--entropy-threshold` |

Each provider pattern validates trailing characters against a charset and length range to keep false positives down.

### Keeping the generic rule quiet

Entropy alone is a noisy signal. Shannon entropy measures bits *per character*, so any long span mixing case, digits and punctuation scores high — including things that are obviously not secrets. Guard therefore requires more than a number before reporting an unrecognised token.

**Tokens are decomposed before they are scored.** Because `.`, `/`, `-`, `_` and `=` are all valid inside a credential, a naive scan treats a whole dotted identifier chain or `flag=value` pair as one token, and gluing ordinary words together is enough to clear the threshold on its own:

```
YOUR_BILLING_ACCOUNT_ID                    3.68 bits/char   below
--billing-account=YOUR_BILLING_ACCOUNT_ID  4.57 bits/char   above
```

If every separator-delimited segment is uniformly letters or digits, the span is an identifier or a path, not a key. Real credentials always have at least one segment that mixes the two.

**Generic hits need credential context.** The token has to sit in value position (after `=` or `:`, optionally through a quote) or share a line with a credential-naming word within 64 bytes. An operand in an expression is not a secret. Pass `--strict` to report bare high-entropy tokens too.

**Known non-secret shapes are suppressed.** Integrity digests (`sha512-…`, `h1:…`), URL bodies, `data:` URIs, character-set constants, and fill-me-in placeholders (`YOUR_…`, `…EXAMPLE`, masked runs) never report. Labels that name a digest — `integrity`, `checksum`, `sha256`, `resolved` — suppress their own values.

**Hex is handled separately.** Hex tops out at 4 bits/char, so it can never clear the threshold; a 64-char session secret would be missed entirely. Guard reports hex runs of 32+ characters, but only when a credential keyword is present — otherwise every git SHA and checksum would fire.

**Keys that are public by design are not redacted.** Stripe publishable keys (`pk_live_`/`pk_test_`) are recognised so the entropy fallback leaves them alone, but reported only under `--include-publishable`.

Measured over 394 files of real application code, these rules take the flagged-file count from 24 to 6, with every remaining hit inside a generated build artifact. No known-provider pattern lost recall.

## Stable placeholders

Detected secrets are replaced inline with typed, indexed placeholders:

```
[REDACTED:anthropic-api-key:1]
```

The trailing index is per-pattern, per-run. The same secret in one input always reuses the same index, so an LLM reading the redacted content can tell whether two references point to the same key. There is no content hash and no cross-run linkability — running guard twice on the same input never produces a value an attacker can correlate.

## Escape hatches

- Add `# noscan` or `// noscan` anywhere on a line to skip detection on that line entirely.
- `--allow <substring>` (repeatable) drops any hit whose value contains the substring. Useful for example keys, fixtures, and known-safe values.
- `--strict` goes the other way: report high-entropy tokens even with no credential context around them.

```bash
echo 'AKIAIOSFODNN7EXAMPLE' | guard --allow EXAMPLE   # passes through unchanged
```

## Configuration

Guard reads the nearest `.guardignore`, searching from the working directory upward. Two directives, one per line:

```
# paths to skip — globs, matched against diff paths
**/generated/**
vendor/bundle.js

# substrings that drop a hit, equivalent to a repeated --allow
allow:AKIAIOSFODNN7EXAMPLE
```

Path globs follow gitignore conventions: `*` stays inside a path segment, `**` spans segments, and a pattern with no `/` also matches a basename anywhere in the tree.

Path filtering applies **only to diff input** (anything containing `diff --git`), because that is the only form where guard can tell which file a given byte belongs to. Piping a whole file through guard scans all of it regardless.

Lockfiles, minified bundles, source maps, and build directories are skipped by default — `package-lock.json`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `go.sum`, `*.min.js`, `*.map`, `dist/`, `build/`, `node_modules/`, `*.dSYM/` and friends. A lockfile's integrity hashes alone were enough to produce several hundred hits per file, which is what makes an unfiltered pre-commit hook unusable.

Disable either mechanism with `--no-path-filter` or `--no-config`.

## Flags

| Flag | Description |
|---|---|
| `--summary` | Write a human-readable report to stderr |
| `--json` | Write a machine-readable report to stderr |
| `--entropy-threshold <f>` | Override the entropy cutoff (default `4.5`) |
| `--allow <substring>` | Drop hits containing the substring (repeatable) |
| `--strict` | Also report high-entropy strings with no credential context |
| `--include-publishable` | Report keys that are public by design (Stripe `pk_*`) |
| `--no-path-filter` | Scan generated files in a diff instead of skipping them |
| `--no-config` | Ignore `.guardignore` |
| `-h`, `--help` | Show help |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No secrets detected |
| `1` | One or more secrets redacted |
| `2` | Invocation error |

The non-zero exit on detection makes guard usable as a pre-commit gate or CI check.

## Build from source

Requires Zig 0.16 or newer.

```bash
zig build                          # debug → zig-out/bin/guard
zig build -Doptimize=ReleaseFast   # optimized → zig-out/bin/guard
zig build test                     # run unit tests
```

To produce release tarballs for all four platforms:

```bash
./scripts/release.sh
```

Cross-compilation needs only Zig itself — no separate toolchain per target.

## Design notes

- **Comptime pattern registry.** Each provider pattern is a comptime struct. The detection loop is unrolled at build time via `inline for`, producing a flat match path with no dynamic dispatch.
- **Streaming-shaped, slurp-implemented.** v0.1 reads stdin into memory before scanning. Memory use is proportional to input size; for typical clipboard-and-paste inputs this is negligible. A line-by-line streaming variant is on the roadmap.
- **No regex engine.** Prefix matching plus charset/length validation plus optional structural constraints (e.g. JWT requires ≥2 dots) covers the supported patterns without a regex dependency.
- **Precision is a feature, not a tuning knob.** A scanner that cries wolf gets switched off, and a scanner that is switched off has zero recall. Every suppression rule in `detection/context.zig` and `detection/suppress.zig` was added against a measured false positive from real repositories, and the fixtures in `detection/engine.zig` pin them so they stay fixed.
