"""Output formatters: text, json, markdown, sarif."""
from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .model import SEVERITIES, Finding, sev_rank
from .rules import RULES

COLORS = {"critical": "\033[1;37;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-sev_rank(f.severity), f.source, f.line, f.rule_id))


def summary(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in reversed(SEVERITIES)}


def render_text(findings: list[Finding], scanned: list[str], errors: list[str], color: bool = False) -> str:
    lines = [f"agent-sec-scanner {__version__} — scanned {len(scanned)} file(s), {len(findings)} finding(s)", ""]
    for f in _sorted(findings):
        sev = f.severity.upper()
        sev_s = f"{COLORS[f.severity]}{sev:<8}{RESET}" if color else f"{sev:<8}"
        loc = f"{f.source}:{f.line}" if f.line else f.source
        lines.append(f"{sev_s} {f.rule_id} {f.title}")
        lines.append(f"         at  {loc}  ({f.path})")
        lines.append(f"         {f.message}")
        if f.evidence:
            lines.append(f"         evidence: {f.evidence}")
        lines.append(f"         fix: {f.fix}")
        lines.append("")
    for e in errors:
        lines.append(f"ERROR    {e}")
    s = summary(findings)
    lines.append("Summary: " + ", ".join(f"{k}={v}" for k, v in s.items()))
    return "\n".join(lines)


def render_json(findings: list[Finding], scanned: list[str], errors: list[str]) -> str:
    return json.dumps({
        "tool": "agent-sec-scanner", "version": __version__,
        "scanned_files": scanned, "errors": errors, "summary": summary(findings),
        "findings": [f.to_dict() for f in _sorted(findings)],
    }, indent=2, ensure_ascii=False)


def render_markdown(findings: list[Finding], scanned: list[str], errors: list[str]) -> str:
    s = summary(findings)
    out = [f"## agent-sec-scanner report", "", f"Scanned **{len(scanned)}** file(s): " + ", ".join(f"`{k}` {v}" for k, v in s.items()), ""]
    if findings:
        out += ["| Severity | Rule | Location | Finding | Fix |", "|---|---|---|---|---|"]
        for f in _sorted(findings):
            esc = lambda t: t.replace("|", "\\|").replace("\n", " ")
            out.append(f"| {f.severity} | {f.rule_id} | `{f.source}:{f.line}` | {esc(f.message)} | {esc(f.fix)} |")
    else:
        out.append("No findings. ✅")
    for e in errors:
        out.append(f"\n> ⚠️ {e}")
    return "\n".join(out) + "\n"


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def render_sarif(findings: list[Finding], scanned: list[str], errors: list[str]) -> str:
    rules = [{
        "id": r.id, "name": r.name, "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.description}, "help": {"text": r.fix},
        "helpUri": r.references[0] if r.references else "https://github.com/",
        "properties": {"security-severity": _SARIF_SCORE[r.severity], "tags": ["security", "mcp", "ai-agent"]},
    } for r in RULES]
    results = []
    for f in _sorted(findings):
        region = {"startLine": f.line} if f.line else {"startLine": 1}
        results.append({
            "ruleId": f.rule_id, "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message}. Fix: {f.fix}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.source.lstrip("./")}, "region": region}}],
            "properties": {"severity": f.severity, "location": f.path, "evidence": f.evidence,
                           "security-severity": _SARIF_SCORE[f.severity]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agent-sec-scanner", "version": __version__, "rules": rules}},
                  "results": results}],
    }, indent=2, ensure_ascii=False)


RENDERERS = {"json": render_json, "markdown": render_markdown, "sarif": render_sarif}
