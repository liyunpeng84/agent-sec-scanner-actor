## What is Agent / MCP Security Scanner?

**Offline, read-only security linter** for AI agent and **MCP** (Model Context Protocol) client configuration files. Paste an `mcp.json`, Claude Desktop config, Cursor MCP servers file, or tools/list export — get a findings dataset plus a downloadable report (Markdown / JSON / SARIF).

It wraps the open-source CLI [`agent-sec-scanner`](https://github.com/liyunpeng84/agent-sec-scanner) (MIT) so you can run the same ruleset from [Apify Console](https://console.apify.com/actors/FDU8KobkUj6ugW9w8), the Apify API, or a schedule — without installing Python locally.

**It never starts MCP servers, never installs packages from your config, and never sends your config to a third party beyond this Actor run’s storage.**

Live Store page: [apify.com/outgoing_refill/agent-sec-scanner](https://apify.com/outgoing_refill/agent-sec-scanner)

## What can this MCP security scanner do?

- Flag **tool poisoning** patterns in MCP tool descriptions (prompt / instruction injection in tool text)
- Find **hard-coded secrets** and tokens in env vars or HTTP headers inside agent configs
- Warn on **over-broad permissions** (filesystem `/`, shell auto-approve, dangerous launch commands)
- Detect unsafe launch patterns (e.g. piping remote scripts into a shell)
- Emit **SARIF 2.1** for CI, or Markdown/JSON for humans and agents

### Who is it for?

- Developers wiring **Claude Desktop**, **Cursor**, or other MCP clients and wanting a quick config audit before enabling tools
- Teams reviewing AI agent / MCP server configs in CI without giving the scanner network or shell access to those tools
- Security folks hunting **MCP tool poisoning** and secret leakage in checked-in configs

## Use cases

### Audit Claude Desktop or Cursor MCP config

Paste `claude_desktop_config.json` or a Cursor MCP servers JSON as **Config content**, set **Config filename** so the parser matches (`.json`), run once, open the dataset.

### Scan for tool poisoning before enabling an MCP server

When a third-party MCP server ships long tool descriptions, export or paste the relevant config / tools metadata and look for instruction-injection style findings before you auto-approve tools.

### CI gate on agent configs

Call the Actor via Apify API with `failOn: high` (or `critical`) so a pipeline fails when high-severity findings appear. Keep Store Try-it / auto-tests on `failOn: none` (default) so demo configs with intentional findings stay green.

## How to use

1. Open [Agent / MCP Security Scanner](https://apify.com/outgoing_refill/agent-sec-scanner) → **Try for free**.
2. Paste a config into **Config content** (default prefill is a deliberately vulnerable Claude-style sample: filesystem `/`, fake GitHub token, and `curl|bash` install — so Try-it shows multiple finding families immediately).
3. Optionally set **Report format** (`markdown` / `json` / `sarif` / `text`) and severity filters.
4. Run. Open the **Dataset** (one row per finding) and key-value store keys `REPORT` + `OUTPUT`.

Local CLI / packaging notes: [liyunpeng84/agent-sec-scanner](https://github.com/liyunpeng84/agent-sec-scanner) and Actor source [liyunpeng84/agent-sec-scanner-actor](https://github.com/liyunpeng84/agent-sec-scanner-actor).

## Example API run (copy-paste)

Replace `YOUR_TOKEN` with an Apify API token. Uses the same vulnerable Claude Desktop sample as the Store example input (`failOn: none` so the run succeeds while findings appear in the dataset).

```bash
curl -sS -X POST \
  'https://api.apify.com/v2/acts/outgoing_refill~agent-sec-scanner/runs?token=YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "configText": "{\"mcpServers\":{\"filesystem\":{\"command\":\"npx\",\"args\":[\"-y\",\"@modelcontextprotocol/server-filesystem\",\"/\"]},\"github\":{\"command\":\"npx\",\"args\":[\"-y\",\"@modelcontextprotocol/server-github@latest\"],\"env\":{\"GITHUB_PERSONAL_ACCESS_TOKEN\":\"ghp_EXAMPLE0fake0token0for0tests0only000\"}}}}",
    "configFileName": "claude_desktop_config.json",
    "outputFormat": "markdown",
    "failOn": "none",
    "minSeverity": "info"
  }'
```

Then open the run’s **Dataset** (one row per finding) and KV keys `REPORT` / `OUTPUT`. Full vulnerable fixtures also live under `examples/vulnerable/` in the Actor source.

## Input

| Field | Required | Description |
|-------|----------|-------------|
| `configText` | one of text / files | Paste a single config body |
| `configFileName` | no | Logical name (default `claude_desktop_config.json` to match Store prefill); extension picks parser |
| `configFiles` | one of text / files | Extra `{name, content}` objects |
| `outputFormat` | no | `markdown` (default), `json`, `sarif`, `text` |
| `failOn` | no | Fail the run if findings ≥ severity (`none` default on Store UI) |
| `minSeverity` | no | Drop findings below this severity |
| `rules` / `ignore` | no | Comma-separated rule ids |

Supported formats: JSON / JSONC, TOML (Python 3.11+), YAML (PyYAML). Typical files: MCP client `mcp.json`, Claude Desktop config, Cursor MCP server lists, Codex TOML, exported tools/list payloads.

## Output

- **Dataset**: one item per finding (`rule_id`, `severity`, `file`, `message`, `line`, …)
- **Key-value store**
  - `REPORT` — full report in the chosen format
  - `OUTPUT` — summary JSON (`finding_count`, `summary`, `errors`, …)

### Example finding (JSON)

```json
{
  "rule_id": "ASC022",
  "severity": "high",
  "file": "mcp.json",
  "message": "Filesystem MCP server rooted at '/' grants broad host access",
  "line": 6
}
```

(Exact `rule_id` / wording depend on the vendored ruleset version; treat this as illustrative.)

## Pricing

Listed as **pay per usage**: you pay Apify for compute and storage used by the run. This listing does **not** currently charge a developer surcharge; developer revenue stays **$0** until monetization / payout identity is configured on the account.

A typical single-config scan finishes in seconds on the default 512 MB memory setting. Platform prices: [Apify pricing](https://apify.com/pricing).

Default Console prefill is a vulnerable sample so Try-it shows findings; `failOn` defaults to `none` so Store automatic tests stay green when findings exist.

## Limitations (honest)

- **Static analysis only** — it does not execute MCP servers, does not fuzz live tools, and does not prove exploitability end-to-end.
- **Not a substitute for** runtime monitoring, human review of third-party MCP servers, or full AppSec / red-team work.
- **False positives / negatives** are possible; rules evolve with the open-source package.
- **Privacy**: pasted configs live in **your** Apify dataset / KV for that run. Do not paste production secrets into public or shared runs.
- **Not affiliated** with Anthropic, Cursor, or the MCP project; “Claude” / “Cursor” / “MCP” refer to config formats users commonly scan.

## FAQ

### Is this an MCP scraper or crawler?

No. It does not scrape websites. It lints **local-style config text** you paste (or pass via API) for AI agent / MCP security issues such as tool poisoning and secrets.

### Does it work with Claude Desktop and Cursor?

Yes for **config file review**: paste the relevant JSON/TOML/YAML. It does not install into Claude or Cursor; run results stay in Apify storage.

### Can I use the results in GitHub Actions / CI?

Yes. Prefer `outputFormat: sarif` or `json`, and set `failOn` to the severity gate you want. Wire the Apify API (or Actor task) from your pipeline.

### Where is the open-source scanner?

- CLI / rules: [github.com/liyunpeng84/agent-sec-scanner](https://github.com/liyunpeng84/agent-sec-scanner)
- This Actor: [github.com/liyunpeng84/agent-sec-scanner-actor](https://github.com/liyunpeng84/agent-sec-scanner-actor)


### How much memory / time does a scan need?

Default Store run options use **512 MB** and a **5-minute** timeout. A single pasted config usually finishes in a few seconds. Raise memory only if you paste unusually large multi-file batches.

### Does my config leave Apify or get sent to the scanner authors?

No third-party webhook. The Actor runs **offline** inside the Apify run: it only writes findings to **your** run Dataset / key-value store. Config text is not sent to the open-source authors. Still avoid pasting live production secrets into shared or public runs.

### How is this different from generic secret scanners?

Secret patterns are one family of rules. The focus is **AI agent / MCP configs**: tool-description poisoning, auto-approve / permission breadth, and unsafe MCP launch commands — areas generic secret scanners usually skip.

## Source and license

- Scanner: [liyunpeng84/agent-sec-scanner](https://github.com/liyunpeng84/agent-sec-scanner) — MIT
- This Actor vendors that package under `vendor/agent_sec_scanner/`
- Actor packaging repo: [liyunpeng84/agent-sec-scanner-actor](https://github.com/liyunpeng84/agent-sec-scanner-actor)

## Categories and discovery keywords

Store categories: **AI**, **Agents**, **Developer tools** (MCP / AI-agent config security focus).

Useful search phrases this Actor targets (honest, product-shaped): MCP security scanner, Claude Desktop mcp.json audit, Cursor MCP servers security, tool poisoning MCP, AI agent config secrets scan, YOLO / auto-approve MCP posture.


## Changelog

### 0.1.10
- README: align Input table default filename with Store prefill (`claude_desktop_config.json`).
- README: document offline privacy guarantee more explicitly in FAQ; add changelog for Store auditors.
- No rule-engine or pricing changes.

### 0.1.9
- Store categories: AI / Agents / Developer tools; default run 512 MB / 300s; FAQ on memory/time.

### 0.1.8
- Store exampleRunInput → vulnerable Claude Desktop sample; richer input prefill + Example API run.

## Support

Issues and rule ideas: open a GitHub issue on the scanner or Actor repo above. For Apify platform run failures, check the run log in Console first.
