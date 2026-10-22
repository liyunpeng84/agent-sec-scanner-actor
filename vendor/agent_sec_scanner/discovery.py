"""Locate agent / MCP config files. Read-only; nothing is executed.

Default locations are best-effort and vary by client version and OS. Pass paths explicitly
when in doubt. Entries marked "unverified" are reasonable guesses that have not been checked
against the client's documentation yet.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# filenames recognised when scanning a directory (e.g. a repository in CI)
PROJECT_FILES = [
    ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", "cline_mcp_settings.json",
    ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".claude/settings.json",
    ".claude/settings.local.json", ".codex/config.toml", ".roo/mcp.json", ".trae/mcp.json",
    ".kiro/settings/mcp.json", ".qwen/settings.json", ".continue/config.yaml", ".zed/settings.json",
]
GLOB_NAMES = {Path(p).name for p in PROJECT_FILES} | {"*.mcp.json"}


def _appdata() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def user_config_paths() -> list[tuple[str, Path]]:
    h, ad = Path.home(), _appdata()
    code_user = ad / "Code" / "User"
    return [
        ("Claude Desktop", ad / "Claude" / "claude_desktop_config.json"),
        ("Claude Code (user)", h / ".claude.json"),
        ("Claude Code settings", h / ".claude" / "settings.json"),
        ("Cursor", h / ".cursor" / "mcp.json"),
        ("Windsurf", h / ".codeium" / "windsurf" / "mcp_config.json"),
        ("VS Code", code_user / "mcp.json"),
        ("VS Code settings", code_user / "settings.json"),
        ("Cline", code_user / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"),
        ("Roo Code", code_user / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json"),
        ("Gemini CLI", h / ".gemini" / "settings.json"),
        ("OpenAI Codex", h / ".codex" / "config.toml"),
        ("Kiro", h / ".kiro" / "settings" / "mcp.json"),
        ("Qwen Code (unverified)", h / ".qwen" / "settings.json"),
        ("Trae (unverified)", ad / "Trae" / "User" / "mcp.json"),
        ("Trae CN (unverified)", ad / "Trae CN" / "User" / "mcp.json"),
        ("Continue", h / ".continue" / "config.yaml"),
        ("Zed", h / ".config" / "zed" / "settings.json"),
    ]


def discover_default() -> list[tuple[str, Path]]:
    found = [(label, p) for label, p in user_config_paths() if p.is_file()]
    cwd = Path.cwd()
    for rel in PROJECT_FILES:
        p = cwd / rel
        if p.is_file():
            found.append((f"project ({rel})", p))
    return found


def expand(path: Path, max_depth: int = 6) -> list[Path]:
    """A file is returned as-is; a directory is searched for known config filenames."""
    if path.is_file():
        return [path]
    out: list[Path] = []
    if not path.is_dir():
        return out
    skip = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}
    base_depth = len(path.resolve().parts)
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        if len(Path(root).resolve().parts) - base_depth >= max_depth:
            dirs[:] = []
        for f in files:
            low = f.lower()
            if f in GLOB_NAMES or ("mcp" in low and low.endswith((".json", ".jsonc", ".toml", ".yaml", ".yml"))) \
                    or low.endswith(("-settings.json", "_settings.json", "-config.toml", "_config.toml")) or f.endswith(".mcp.json") or (f == "settings.json" and Path(root).name in (".claude", ".gemini", ".qwen", ".zed")) \
                    or (f == "config.toml" and Path(root).name == ".codex") or (f == "config.yaml" and Path(root).name == ".continue") \
                    or f.endswith(("tools.json", "tools-list.json")):
                out.append(Path(root) / f)
    return sorted(out)
