"""Normalized data model shared by loaders, rules and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Server:
    """One MCP server entry, whatever client format it came from."""

    name: str
    source: str  # file path
    path: str  # JSON-path-like location inside the file, e.g. mcpServers.github
    client: str  # detected client/format, e.g. "claude-desktop/cursor (mcpServers)"
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    auto_approve: list[str] = field(default_factory=list)
    trust: bool = False
    disabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def cmdline(self) -> str:
        return " ".join([self.command, *self.args]).strip()


@dataclass
class Tool:
    """A tool definition (e.g. exported from MCP tools/list)."""

    name: str
    description: str
    source: str
    path: str
    server: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class Document:
    """A parsed config file."""

    source: str
    text: str
    data: Any
    kind: str  # json / toml / yaml
    servers: list[Server] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)  # detected formats in this file


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    source: str
    path: str
    message: str
    evidence: str = ""
    fix: str = ""
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.source,
            "line": self.line,
            "location": self.path,
            "message": self.message,
            "evidence": self.evidence,
            "fix": self.fix,
        }
