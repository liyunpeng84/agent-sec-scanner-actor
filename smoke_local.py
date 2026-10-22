#!/usr/bin/env python3
"""Local smoke test WITHOUT Apify cloud or Apify SDK.

Runs the vendored scanner on bundled example configs and asserts
vulnerable examples produce findings and clean examples do not
(at high+ severity).

Usage (from this directory):
  python3 smoke_local.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "vendor"))

from agent_sec_scanner.cli import scan_paths  # noqa: E402
from agent_sec_scanner.model import sev_rank  # noqa: E402


def main() -> int:
    vuln = ROOT / "examples" / "vulnerable"
    clean = ROOT / "examples" / "clean"

    v_findings, v_scanned, v_errors = scan_paths([vuln])
    c_findings, c_scanned, c_errors = scan_paths([clean])

    print(f"vulnerable: {len(v_scanned)} files, {len(v_findings)} findings, {len(v_errors)} errors")
    print(f"clean:      {len(c_scanned)} files, {len(c_findings)} findings, {len(c_errors)} errors")

    if v_errors and not v_scanned:
        print("FAIL: vulnerable examples did not parse", v_errors)
        return 1
    if len(v_findings) < 1:
        print("FAIL: expected findings on vulnerable examples")
        return 1
    high_plus = [f for f in v_findings if sev_rank(f.severity) >= sev_rank("high")]
    if not high_plus:
        print("FAIL: expected at least one high+ finding on vulnerable set")
        return 1

    # Clean set should be quiet at high+ (info/low noise OK)
    clean_high = [f for f in c_findings if sev_rank(f.severity) >= sev_rank("high")]
    if clean_high:
        print("FAIL: clean examples produced high+ findings:", [f.rule_id for f in clean_high])
        return 1

    print("OK — smoke_local passed")
    # Also exercise Actor-style load_text path
    from agent_sec_scanner.loader import load_text
    from agent_sec_scanner.rules import run_rules

    sample = (vuln / "claude_desktop_config.json").read_text(encoding="utf-8")
    doc = load_text(sample, name="claude_desktop_config.json")
    pasted = run_rules(doc)
    print(f"paste path: {len(pasted)} findings from claude_desktop_config.json")
    if not pasted:
        print("FAIL: paste/load_text path returned no findings")
        return 1
    print("OK — load_text path passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
