"""Parse agent / MCP client configuration files into a normalized model.

Nothing here executes, connects to, or installs anything: files are only read.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .model import Document, Server, Tool

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

try:
    import yaml  # type: ignore[import-untyped]
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    yaml = None


class LoadError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code style JSONC)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def parse_text(text: str, suffix: str) -> tuple[Any, str]:
    suffix = suffix.lower()
    if suffix == ".toml":
        if tomllib is None:
            raise LoadError("TOML support requires Python 3.11+")
        try:
            return tomllib.loads(text), "toml"
        except Exception as e:  # noqa: BLE001
            raise LoadError(f"invalid TOML: {e}") from e
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise LoadError("YAML support requires PyYAML (pip install pyyaml)")
        try:
            return yaml.safe_load(text), "yaml"
        except Exception as e:  # noqa: BLE001
            raise LoadError(f"invalid YAML: {e}") from e
    try:
        return json.loads(text), "json"
    except json.JSONDecodeError:
        try:
            return json.loads(strip_jsonc(text)), "json"
        except json.JSONDecodeError as e:
            raise LoadError(f"invalid JSON/JSONC: {e}") from e


def _as_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _as_str_dict(v: Any) -> dict[str, str]:
    if isinstance(v, dict):
        return {str(k): "" if val is None else str(val) for k, val in v.items()}
    if isinstance(v, list):  # e.g. [{"name": "X", "value": "Y"}] or ["KEY=VAL"]
        out: dict[str, str] = {}
        for item in v:
            if isinstance(item, dict) and "name" in item:
                out[str(item["name"])] = str(item.get("value", ""))
            elif isinstance(item, str) and "=" in item:
                k, _, val = item.partition("=")
                out[k] = val
        return out
    return {}


def _server_from_entry(name: str, entry: Any, source: str, path: str, client: str) -> Server | None:
    if not isinstance(entry, dict):
        return None
    cmd = entry.get("command", "")
    args = _as_str_list(entry.get("args"))
    if isinstance(cmd, list):  # some formats put the whole argv in "command"
        parts = [str(x) for x in cmd]
        cmd, args = (parts[0] if parts else ""), parts[1:] + args
    elif isinstance(cmd, dict):  # Zed: {"command": {"path": ..., "args": ...}}
        args = _as_str_list(cmd.get("args")) + args
        entry = {**entry, "env": entry.get("env") or cmd.get("env")}
        cmd = cmd.get("path", "")
    url = ""
    for key in ("url", "serverUrl", "httpUrl", "endpoint", "uri"):
        if isinstance(entry.get(key), str):
            url = entry[key]
            break
    auto = _as_str_list(entry.get("alwaysAllow")) + _as_str_list(entry.get("autoApprove"))
    return Server(
        name=str(name),
        source=source,
        path=path,
        client=client,
        command=str(cmd or ""),
        args=args,
        env=_as_str_dict(entry.get("env")),
        url=url,
        headers=_as_str_dict(entry.get("headers") or entry.get("http_headers")),
        auto_approve=auto,
        trust=entry.get("trust") is True,
        disabled=entry.get("disabled") is True or entry.get("enabled") is False,
        raw=entry,
    )


# (key path, human label) for container keys that hold MCP servers
_SERVER_CONTAINERS = [
    (("mcpServers",), "mcpServers (Claude Desktop/Code, Cursor, Windsurf, Cline, Gemini CLI, Trae, ...)"),
    (("servers",), "servers (VS Code mcp.json)"),
    (("mcp", "servers"), "mcp.servers (VS Code settings.json)"),
    (("mcp_servers",), "mcp_servers (OpenAI Codex config.toml)"),
    (("context_servers",), "context_servers (Zed)"),
]


def _get(data: Any, keys: tuple[str, ...]) -> Any:
    cur = data
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _collect_tools(tools: Any, source: str, base: str, server: str, out: list[Tool]) -> None:
    if not isinstance(tools, list):
        return
    for i, t in enumerate(tools):
        if not isinstance(t, dict) or "name" not in t:
            continue
        out.append(
            Tool(
                name=str(t.get("name")),
                description=str(t.get("description") or ""),
                source=source,
                path=f"{base}[{i}]",
                server=server,
                input_schema=t.get("inputSchema") or t.get("input_schema") or t.get("parameters") or {},
            )
        )


def normalize(doc: Document) -> Document:
    data = doc.data
    if not isinstance(data, dict):
        if isinstance(data, list):  # bare tools/list array
            _collect_tools(data, doc.source, "$", "", doc.tools)
            if doc.tools:
                doc.formats.append("tools manifest (array)")
        return doc

    # Claude Code ~/.claude.json keeps per-project servers under projects.<dir>.mcpServers
    containers: list[tuple[str, Any, str]] = []
    for keys, label in _SERVER_CONTAINERS:
        val = _get(data, keys)
        if val is not None:
            containers.append((".".join(keys), val, label))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for pname, pval in projects.items():
            if isinstance(pval, dict) and isinstance(pval.get("mcpServers"), dict):
                containers.append((f"projects.{pname}.mcpServers", pval["mcpServers"], "Claude Code (~/.claude.json project scope)"))

    for base, val, label in containers:
        if isinstance(val, dict):
            items = list(val.items())
            fmt = label
        elif isinstance(val, list):  # Continue YAML: mcpServers: [{name: ..., command: ...}]
            items = [(str(e.get("name", f"#{i}")) if isinstance(e, dict) else f"#{i}", e) for i, e in enumerate(val)]
            fmt = label + " [list form, e.g. Continue]"
        else:
            continue
        # VS Code "servers" is too generic a key; require server-looking entries
        if base == "servers" and not any(isinstance(e, dict) and ({"command", "url", "type"} & set(e)) for _, e in items):
            continue
        doc.formats.append(fmt)
        for name, entry in items:
            s = _server_from_entry(name, entry, doc.source, f"{base}.{name}", fmt)
            if s:
                doc.servers.append(s)
                if isinstance(entry, dict) and "tools" in entry:
                    _collect_tools(entry["tools"], doc.source, f"{base}.{name}.tools", s.name, doc.tools)

    # tools/list manifest: {"tools": [...]} or JSON-RPC {"result": {"tools": [...]}}
    for base, val in (("tools", data.get("tools")), ("result.tools", _get(data, ("result", "tools")))):
        if isinstance(val, list):
            _collect_tools(val, doc.source, base, str(data.get("server") or data.get("name") or ""), doc.tools)
            doc.formats.append("MCP tools/list manifest")
    return doc


def load_file(path: str | Path) -> Document:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise LoadError(f"cannot read {p}: {e}") from e
    data, kind = parse_text(text, p.suffix)
    return normalize(Document(source=str(p), text=text, data=data, kind=kind))


def load_text(text: str, name: str = "<memory>.json") -> Document:
    data, kind = parse_text(text, Path(name).suffix or ".json")
    return normalize(Document(source=name, text=text, data=data, kind=kind))
