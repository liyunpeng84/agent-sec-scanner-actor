"""Command-line interface."""
from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

from . import __version__
from .discovery import discover_default, expand
from .loader import LoadError, load_file
from .model import SEVERITIES, Finding, sev_rank
from .report import RENDERERS, render_text
from .rules import RULES, run_rules


def load_ignore_file(path: Path) -> list[tuple[str, str]]:
    """Lines: `RULE_ID` or `RULE_ID path-glob`; `#` comments."""
    rules: list[tuple[str, str]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                rid, _, glob = line.partition(" ")
                rules.append((rid.strip(), glob.strip() or "*"))
    return rules


def suppressed(f: Finding, ignores: list[tuple[str, str]]) -> bool:
    return any(rid in (f.rule_id, "*") and fnmatch.fnmatch(f.source, glob) for rid, glob in ignores)


def scan_paths(paths: list[Path], only=None, ignore=None) -> tuple[list[Finding], list[str], list[str]]:
    findings: list[Finding] = []
    scanned: list[str] = []
    errors: list[str] = []
    files: list[Path] = []
    for p in paths:
        exp = expand(p)
        if not exp:
            errors.append(f"{p}: not found or no recognised config files")
        files.extend(exp)
    for f in dict.fromkeys(files):
        try:
            doc = load_file(f)
        except LoadError as e:
            errors.append(f"{f}: {e}")
            continue
        scanned.append(str(f))
        findings.extend(run_rules(doc, only=only, ignore=ignore))
    return findings, scanned, errors


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-sec-scan",
        description="Offline, read-only security linter for AI agent & MCP configurations. "
                    "Never starts servers, never sends your config anywhere.",
    )
    p.add_argument("paths", nargs="*", type=Path, help="config files or directories (default: auto-discover known locations)")
    p.add_argument("-f", "--format", choices=["text", "json", "markdown", "sarif"], default="text")
    p.add_argument("-o", "--output", type=Path, help="write report to file instead of stdout")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    p.add_argument("--rules", help="comma-separated rule ids/names to run (default: all)")
    p.add_argument("--ignore", help="comma-separated rule ids/names to skip")
    p.add_argument("--ignore-file", type=Path, default=Path(".agentsecignore"),
                   help="suppression file: lines of `RULE_ID [path-glob]` (default: .agentsecignore)")
    p.add_argument("--list-rules", action="store_true", help="print rules and exit")
    p.add_argument("--list-locations", action="store_true", help="print auto-discovery locations and exit")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"agent-sec-scanner {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for r in RULES:
            print(f"{r.id}  {r.severity:<8} {r.name:<28} {r.title}")
        return 0
    if args.list_locations:
        from .discovery import PROJECT_FILES, user_config_paths
        for label, pth in user_config_paths():
            print(f"{'[found] ' if pth.is_file() else '        '}{label:<28} {pth}")
        print("project files (relative to cwd / scanned dirs): " + ", ".join(PROJECT_FILES))
        return 0

    paths = args.paths
    if not paths:
        found = discover_default()
        if not found:
            print("No agent/MCP config files found in default locations. Pass a path, e.g. `agent-sec-scan ./mcp.json`.",
                  file=sys.stderr)
            return 0
        paths = [p for _, p in found]

    split = lambda s: {x.strip() for x in s.split(",") if x.strip()} if s else None
    findings, scanned, errors = scan_paths(paths, only=split(args.rules), ignore=split(args.ignore))
    ignores = load_ignore_file(args.ignore_file)
    findings = [f for f in findings if not suppressed(f, ignores) and sev_rank(f.severity) >= sev_rank(args.min_severity)]

    if args.format == "text":
        color = not args.no_color and args.output is None and sys.stdout.isatty()
        out = render_text(findings, scanned, errors, color=color)
    else:
        out = RENDERERS[args.format](findings, scanned, errors)
    if args.output:
        args.output.write_text(out + ("" if out.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(out)

    if args.fail_on != "none" and any(sev_rank(f.severity) >= sev_rank(args.fail_on) for f in findings):
        return 1
    return 2 if errors and not scanned else 0
