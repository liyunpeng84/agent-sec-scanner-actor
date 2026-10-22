# Agent / MCP Security Scanner (Apify Actor)

Offline, **read-only** security linter for AI agent and MCP client configuration files.

Wraps the open-source CLI [`agent-sec-scanner`](https://github.com/liyunpeng84/agent-sec-scanner) (MIT) so you can paste configs in Apify Console / API and get a findings dataset plus a downloadable report.

## What it checks

Examples of issues the ruleset flags (non-exhaustive):

- Tool / prompt injection patterns in MCP tool descriptions (“tool poisoning”)
- Hard-coded secrets and tokens in env / headers
- Over-broad filesystem or shell permissions / auto-approve lists
- Unsafe launch commands (e.g. piping remote scripts, scanning `/`)

**It never starts MCP servers, never installs packages from your config, and never sends your config to a third party beyond this Actor run’s storage.**

## Input

| Field | Required | Description |
|-------|----------|-------------|
| `configText` | one of text / files | Paste a single config body |
| `configFileName` | no | Logical name (default `mcp.json`); extension picks parser |
| `configFiles` | one of text / files | Extra `{name, content}` objects |
| `outputFormat` | no | `markdown` (default), `json`, `sarif`, `text` |
| `failOn` | no | Fail the run if findings ≥ severity (`none` default on Store UI) |
| `minSeverity` | no | Drop findings below this severity |
| `rules` / `ignore` | no | Comma-separated rule ids |

Supported formats: JSON / JSONC, TOML (Python 3.11+), YAML (PyYAML).

## Output

- **Dataset**: one item per finding (`rule_id`, `severity`, `file`, `message`, `fix`, …)
- **Key-value store**
  - `REPORT` — full report in the chosen format
  - `OUTPUT` — summary JSON (`finding_count`, `summary`, `errors`, …)

## Example

Paste a vulnerable MCP desktop config as `configText`, run the Actor, open the dataset. Local equivalents and smoke commands: see `../HOW-TO-RUN.md` in the packaging repo (or the GitHub README for the CLI).

## Store listing

- **Live:** [apify.com/outgoing_refill/agent-sec-scanner](https://apify.com/outgoing_refill/agent-sec-scanner)
- Console: [console.apify.com/actors/FDU8KobkUj6ugW9w8](https://console.apify.com/actors/FDU8KobkUj6ugW9w8)

## Pricing note (honest)

Currently listed as **pay per usage**: users pay Apify for compute/storage; **this account earns $0 developer revenue** until [Monetize Actors](https://docs.apify.com/actors/publishing/monetize) is enabled and payout/billing identity is filled in.

Platform usage follows [Apify pricing](https://apify.com/pricing). Default Console input prefill is a deliberately vulnerable `filesystem` → `/` config so a Try-it run shows findings; `failOn` defaults to `none` so Store auto-tests stay green even when findings exist. Changing `failOn` to `high`/`critical` would make those demo runs fail and can break automatic Store tests.

## Source / license

- Scanner: [liyunpeng84/agent-sec-scanner](https://github.com/liyunpeng84/agent-sec-scanner) — MIT
- This Actor vendors that package under `vendor/agent_sec_scanner/`

## Privacy

Configs you paste are processed inside the Actor run and stored in **your** Apify dataset / key-value store for that run. Do not paste production secrets into public Actor runs you share.
