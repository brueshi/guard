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

19 provider patterns plus a Shannon-entropy fallback for unknown providers.

| Category | Patterns |
|---|---|
| AI | Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), Google (`AIza`), GCP OAuth (`ya29.`), HuggingFace (`hf_`) |
| Code hosts | GitHub classic (`ghp_`/`gho_`/`ghs_`/`ghu_`), GitHub fine-grained (`github_pat_`), GitLab (`glpat-`) |
| Cloud | AWS (`AKIA`/`ASIA`), DigitalOcean (`dop_v1_`) |
| Payments | Stripe secret (`sk_live_`/`sk_test_`/`rk_*`), Stripe publishable (`pk_*`), Stripe webhook (`whsec_`) |
| Comms / infra | Slack (`xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xapp-`), Docker (`dckr_pat_`), npm (`npm_`), Linear (`lin_api_`), Figma (`figd_`) |
| Standards | JWT (`eyJ` with three base64url segments) |
| Generic | High-entropy strings (≥4.5 bits/char, ≥20 chars), tunable via `--entropy-threshold` |

Each provider pattern validates trailing characters against a charset and length range to keep false positives down.

## Stable placeholders

Detected secrets are replaced inline with typed, indexed placeholders:

```
[REDACTED:anthropic-api-key:1]
```

The trailing index is per-pattern, per-run. The same secret in one input always reuses the same index, so an LLM reading the redacted content can tell whether two references point to the same key. There is no content hash and no cross-run linkability — running guard twice on the same input never produces a value an attacker can correlate.

## Escape hatches

- Add `# noscan` or `// noscan` anywhere on a line to skip detection on that line entirely.
- `--allow <substring>` (repeatable) drops any hit whose value contains the substring. Useful for example keys, fixtures, and known-safe values.

```bash
echo 'AKIAIOSFODNN7EXAMPLE' | guard --allow EXAMPLE   # passes through unchanged
```

## Flags

| Flag | Description |
|---|---|
| `--summary` | Write a human-readable report to stderr |
| `--json` | Write a machine-readable report to stderr |
| `--entropy-threshold <f>` | Override the entropy cutoff (default `4.5`) |
| `--allow <substring>` | Drop hits containing the substring (repeatable) |
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
