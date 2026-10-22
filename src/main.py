"""Apify Actor entry: wrap agent-sec-scanner as an offline config linter."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Vendored scanner package lives next to src/
_ROOT = Path(__file__).resolve().parents[1]
_VENDOR = _ROOT / "vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

from agent_sec_scanner import __version__ as SCANNER_VERSION  # noqa: E402
from agent_sec_scanner.loader import LoadError, load_text  # noqa: E402
from agent_sec_scanner.model import SEVERITIES, Finding, sev_rank  # noqa: E402
from agent_sec_scanner.report import RENDERERS, render_text, summary  # noqa: E402
from agent_sec_scanner.rules import run_rules  # noqa: E402
from apify import Actor  # noqa: E402


def _split_csv(value: str | None) -> set[str] | None:
    if not value or not str(value).strip():
        return None
    return {x.strip() for x in str(value).split(",") if x.strip()}


def _collect_docs(actor_input: dict[str, Any]) -> tuple[list[Any], list[str]]:
    """Build Documents from pasted config(s). Returns (docs, errors)."""
    docs: list[Any] = []
    errors: list[str] = []

    config_text = (actor_input.get("configText") or "").strip()
    file_name = (actor_input.get("configFileName") or "mcp.json").strip() or "mcp.json"
    if config_text:
        try:
            docs.append(load_text(config_text, name=file_name))
        except LoadError as e:
            errors.append(f"{file_name}: {e}")

    for i, item in enumerate(actor_input.get("configFiles") or []):
        if not isinstance(item, dict):
            errors.append(f"configFiles[{i}]: expected object with name + content")
            continue
        name = str(item.get("name") or f"config-{i}.json").strip() or f"config-{i}.json"
        content = item.get("content")
        if content is None or not str(content).strip():
            errors.append(f"{name}: empty content")
            continue
        try:
            docs.append(load_text(str(content), name=name))
        except LoadError as e:
            errors.append(f"{name}: {e}")

    return docs, errors


def _scan(
    docs: list[Any],
    *,
    only: set[str] | None,
    ignore: set[str] | None,
    min_severity: str,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    scanned: list[str] = []
    for doc in docs:
        scanned.append(doc.source)
        findings.extend(run_rules(doc, only=only, ignore=ignore))
    findings = [f for f in findings if sev_rank(f.severity) >= sev_rank(min_severity)]
    return findings, scanned


def _render(fmt: str, findings: list[Finding], scanned: list[str], errors: list[str]) -> str:
    if fmt == "text":
        return render_text(findings, scanned, errors, color=False)
    if fmt not in RENDERERS:
        fmt = "markdown"
    return RENDERERS[fmt](findings, scanned, errors)


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}

        fail_on = str(actor_input.get("failOn") or "none")
        min_severity = str(actor_input.get("minSeverity") or "info")
        output_format = str(actor_input.get("outputFormat") or "markdown")
        only = _split_csv(actor_input.get("rules"))
        ignore = _split_csv(actor_input.get("ignore"))

        if min_severity not in SEVERITIES:
            await Actor.fail(status_message=f"Invalid minSeverity: {min_severity}")
            return
        if fail_on not in SEVERITIES + ["none"]:
            await Actor.fail(status_message=f"Invalid failOn: {fail_on}")
            return

        docs, errors = _collect_docs(actor_input)
        if not docs and not errors:
            await Actor.fail(
                status_message="No config provided. Paste configText and/or configFiles.",
            )
            return

        findings, scanned = _scan(
            docs, only=only, ignore=ignore, min_severity=min_severity,
        )

        Actor.log.info(
            "agent-sec-scanner %s — scanned %s file(s), %s finding(s), %s error(s)",
            SCANNER_VERSION,
            len(scanned),
            len(findings),
            len(errors),
        )

        for f in findings:
            await Actor.push_data(f.to_dict())

        report = _render(output_format, findings, scanned, errors)
        report_key = "REPORT"
        # Choose a file-ish content type for Console downloads
        content_type = {
            "json": "application/json; charset=utf-8",
            "sarif": "application/sarif+json; charset=utf-8",
            "markdown": "text/markdown; charset=utf-8",
            "text": "text/plain; charset=utf-8",
        }.get(output_format, "text/plain; charset=utf-8")
        await Actor.set_value(report_key, report, content_type=content_type)

        meta = {
            "tool": "agent-sec-scanner",
            "version": SCANNER_VERSION,
            "scanned_files": scanned,
            "errors": errors,
            "summary": summary(findings),
            "finding_count": len(findings),
            "report_key": report_key,
            "output_format": output_format,
            "upstream": "https://github.com/liyunpeng84/agent-sec-scanner",
        }
        await Actor.set_value("OUTPUT", meta)

        if errors and not scanned:
            await Actor.fail(status_message="All configs failed to parse. See OUTPUT.errors.")
            return

        if fail_on != "none" and any(sev_rank(f.severity) >= sev_rank(fail_on) for f in findings):
            await Actor.fail(
                status_message=(
                    f"Findings at or above '{fail_on}' "
                    f"({summary(findings)}). See dataset + REPORT."
                ),
            )
            return

        Actor.log.info("Done. Summary: %s", summary(findings))


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
