"""Detection rules. Every rule is a pure function over a parsed Document.

Rules only *read* configuration. They never start servers, open connections,
or send data anywhere.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from .model import Document, Finding, Server
from .secrets import find_secret, redact


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    severity: str  # default / maximum severity
    description: str
    fix: str
    check: Callable[[Document], Iterator[Finding]]
    references: tuple[str, ...] = ()


RULES: list[Rule] = []


def rule(id: str, name: str, title: str, severity: str, description: str, fix: str, references: tuple[str, ...] = ()):
    def deco(fn: Callable[[Document], Iterator[Finding]]):
        RULES.append(Rule(id, name, title, severity, description, fix, fn, references))
        return fn

    return deco


def _finding(r_id: str, doc: Document, path: str, message: str, severity: str | None = None,
             evidence: str = "", fix: str = "", needle: str = "") -> Finding:
    r = next(x for x in RULES if x.id == r_id)
    return Finding(
        rule_id=r.id,
        title=r.title,
        severity=severity or r.severity,
        source=doc.source,
        path=path,
        message=message,
        evidence=evidence,
        fix=fix or r.fix,
        line=find_line(doc.text, needle or path.split(".")[-1]),
    )


def find_line(text: str, needle: str) -> int:
    if not needle:
        return 0
    for cand in (needle, needle.strip('"'), needle[:40]):
        if not cand:
            continue
        idx = text.find(cand)
        if idx == -1:
            # JSON escapes non-ASCII / quotes; try the JSON-encoded form too
            import json

            enc = json.dumps(cand)[1:-1]
            idx = text.find(enc)
        if idx != -1:
            return text.count("\n", 0, idx) + 1
    return 0


def _snippet(text: str, start: int, end: int, width: int = 50) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    s = text[a:b].replace("\n", " ")
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


# ---------------------------------------------------------------------------
# Text sources: tool descriptions + free-text fields anywhere in the config
# ---------------------------------------------------------------------------
TEXT_KEYS = {"description", "instructions", "systemprompt", "system_prompt", "prompt", "title", "usage"}


def _walk(data: Any, path: str = "$") -> Iterator[tuple[str, str, Any]]:
    """Yield (path, key, value) for every leaf."""
    if isinstance(data, dict):
        for k, v in data.items():
            p = f"{path}.{k}" if path != "$" else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk(v, p)
            else:
                yield p, str(k), v
    elif isinstance(data, list):
        for i, v in enumerate(data):
            p = f"{path}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk(v, p)
            else:
                yield p, path.rsplit(".", 1)[-1], v


def text_fields(doc: Document) -> list[tuple[str, str, str]]:
    """(path, label, text) for tool descriptions, schema descriptions and other prose fields."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for t in doc.tools:
        out.append((t.path + ".description", f"tool '{t.name}'", t.description))
        seen.add(t.description)
        for p, k, v in _walk(t.input_schema, t.path + ".inputSchema"):
            if isinstance(v, str) and k.lower() in TEXT_KEYS | {"default", "enum"} and v not in seen:
                out.append((p, f"tool '{t.name}' parameter", v))
                seen.add(v)
    for p, k, v in _walk(doc.data):
        if isinstance(v, str) and k.lower() in TEXT_KEYS and v not in seen:
            out.append((p, k, v))
            seen.add(v)
    return out


# ---------------------------------------------------------------------------
# ASC001 tool poisoning / prompt injection
# ---------------------------------------------------------------------------
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (severity, regex, explanation)
    ("critical", r"\b(ignore|disregard|forget|override)\b.{0,30}\b(all\s+)?(previous|prior|above|earlier|system|other)\b.{0,20}\b(instructions?|prompts?|rules?|messages?)", "instruction override"),
    ("critical", r"(忽略|无视|忘记|忽视|覆盖)(掉)?(之前|以上|上面|先前|此前|所有|其他|系统)的?(所有)?(指令|指示|提示词?|规则|要求|设定)", "instruction override (zh)"),
    ("critical", r"\b(do\s*n[o']?t|never)\b.{0,25}\b(tell|inform|notify|mention|reveal|show|alert)\b.{0,60}\b(the\s+)?user", "concealment from user"),
    ("critical", r"(不要|不得|切勿|别|无需|不必)(向|对|让)?(用户|使用者).{0,6}(透露|告知|告诉|提及|提示|知道|看到|展示)", "concealment from user (zh)"),
    ("critical", r"(不要|不得|切勿|别)(告诉|告知|通知|提醒|提示)(用户|使用者)", "concealment from user (zh)"),
    ("high", r"\bwithout\s+(the\s+)?user'?s?\s+(knowledge|consent|confirmation|approval|noticing)|\bwithout\s+(telling|asking|informing|notifying)\b", "act without user consent"),
    ("high", r"(静默|悄悄|偷偷|秘密|暗中|后台)(地)?(执行|发送|上传|读取|调用|抄送|转发|运行)", "covert action (zh)"),
    ("high", r"\b(silently|secretly|covertly|quietly)\b.{0,30}\b(send|upload|read|call|run|execute|forward|copy|include|exfiltrate)", "covert action"),
    ("high", r"<\s*(important|system|instructions?|admin|secret|hidden)\s*>|\[\s*(system|admin|instructions?)\s*\]|<\|im_start\|>|\[INST\]", "fake system/priority tag"),
    ("high", r"\bbefore\s+(using|calling|invoking|running)\s+(this|any|the\s+\w+)\s+tool\b.{0,60}\b(must|first|always|read|send|call)", "pre-condition hijack"),
    ("high", r"(在|调用|使用)(本|此|任何|其他)?工具(之前|前).{0,20}(必须|务必|先|首先)", "pre-condition hijack (zh)"),
    ("medium", r"\b(you\s+(must|should)\s+(always|first|now))\b|\bfrom\s+now\s+on\b|\byou\s+are\s+now\b|\bact\s+as\b", "behavioural override"),
    ("medium", r"(从现在(开始|起)|你现在是|你必须(始终|总是|首先|先)|请扮演)", "behavioural override (zh)"),
    ("medium", r"<!--.*?-->", "hidden HTML comment"),
    ("medium", r"\b(sidenote|side_note|hidden_param)\b", "covert side-channel parameter"),
]
_INJ = [(sev, re.compile(rx, re.I | re.S), why) for sev, rx, why in INJECTION_PATTERNS]


@rule(
    "ASC001", "tool-poisoning", "Prompt injection / tool poisoning in tool or agent text", "critical",
    "Tool descriptions and other prose fields are fed to the model verbatim. Imperative text aimed at the model "
    "(override instructions, hide actions from the user, fake <IMPORTANT>/<system> tags) is the classic MCP tool-poisoning vector. "
    "Patterns cover English and Chinese.",
    "Do not install/enable this server until the description is reviewed. Descriptions should only describe what the tool does "
    "for a human; remove imperative instructions to the model, hidden tags and comments. Pin the server version so a later update "
    "cannot silently change the text (rug pull).",
    ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
     "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
)
def check_injection(doc: Document) -> Iterator[Finding]:
    for path, label, text in text_fields(doc):
        hits = []
        for sev, rx, why in _INJ:
            m = rx.search(text)
            if m:
                hits.append((sev, why, m))
        if not hits:
            continue
        hits.sort(key=lambda h: ["info", "low", "medium", "high", "critical"].index(h[0]), reverse=True)
        sev, why, m = hits[0]
        reasons = ", ".join(sorted({h[1] for h in hits}))
        yield _finding("ASC001", doc, path, f"{label}: suspicious model-directed instructions ({reasons})",
                       severity=sev, evidence=_snippet(text, m.start(), m.end()), needle=m.group(0))


# ---------------------------------------------------------------------------
# ASC002 hidden unicode
# ---------------------------------------------------------------------------
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")
_ZW = set("\u200b\u200c\u200d\u2060\ufeff\u180e")


def _hidden_chars(s: str) -> list[str]:
    found = []
    for ch in s:
        o = ord(ch)
        if ch in _BIDI:
            found.append(f"U+{o:04X} bidi control")
        elif ch in _ZW:
            found.append(f"U+{o:04X} zero-width")
        elif 0xE0000 <= o <= 0xE007F:
            found.append(f"U+{o:05X} tag character (ASCII smuggling)")
        elif 0xE000 <= o <= 0xF8FF:
            found.append(f"U+{o:04X} private use")
        elif unicodedata.category(ch) == "Cf" and ch not in "\u00ad":
            found.append(f"U+{o:04X} format char")
    return found


@rule(
    "ASC002", "hidden-unicode", "Invisible / bidirectional Unicode characters", "high",
    "Zero-width, bidi-override and Unicode 'tag' characters render invisibly to humans but are read by the model. "
    "They are used to smuggle instructions past reviewers.",
    "Strip non-printing characters (e.g. normalise with a whitelist) and re-review the visible text. Treat the source as untrusted.",
    ("https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/",),
)
def check_hidden_unicode(doc: Document) -> Iterator[Finding]:
    for path, key, v in list(_walk(doc.data)):
        if isinstance(v, str):
            hc = _hidden_chars(v)
            if hc:
                smuggled = "".join(chr(ord(c) - 0xE0000) for c in v if 0xE0020 <= ord(c) <= 0xE007E)
                ev = f"{len(hc)} hidden char(s): {', '.join(sorted(set(hc))[:4])}"
                if smuggled:
                    ev += f"; decoded tag text: {smuggled[:80]!r}"
                yield _finding("ASC002", doc, path, f"field '{key}' contains invisible Unicode", evidence=ev,
                               severity="critical" if smuggled else "high", needle=key)


# ---------------------------------------------------------------------------
# ASC003 sensitive data access / exfiltration hints in tool text
# ---------------------------------------------------------------------------
SENSITIVE_PATHS = re.compile(
    r"(~|\$HOME|%USERPROFILE%)?/?\.(ssh|aws|gnupg|kube|docker)/?[\w\-/.]*|id_(rsa|ed25519|ecdsa)\b|\.env\b|/etc/(passwd|shadow)|"
    r"\.npmrc|\.pypirc|\.git-credentials|\.netrc|credentials\.json|mcp\.json|claude_desktop_config\.json|"
    r"Login Data|Cookies\.sqlite|keychain|wallet\.dat|私钥|助记词",
    re.I,
)
EXFIL = re.compile(
    r"\b(send|upload|post|forward|transmit|exfiltrate|copy|cc|bcc|report)\b.{0,40}(https?://|\b[\w.+-]+@[\w-]+\.[\w.]+|webhook)|"
    r"(发送|上传|抄送|转发|回传|同步).{0,12}(到|至|给).{0,30}(https?://|[\w.+-]+@[\w-]+\.[\w.]+|服务器|邮箱)",
    re.I,
)


@rule(
    "ASC003", "sensitive-data-instruction", "Tool text references credentials or outbound exfiltration", "high",
    "A tool description that mentions SSH keys, cloud credentials, other agents' config files, or tells the model to "
    "send content to a URL / e-mail address is a strong indicator of a data-exfiltration attempt.",
    "Remove the server unless the reference is clearly legitimate (e.g. an SSH-management tool). Never let a tool's text decide "
    "which local files the agent reads; restrict the server's filesystem access and outbound network instead.",
)
def check_sensitive_text(doc: Document) -> Iterator[Finding]:
    for path, label, text in text_fields(doc):
        m = SENSITIVE_PATHS.search(text)
        e = EXFIL.search(text)
        if m and e:
            yield _finding("ASC003", doc, path, f"{label}: references sensitive files AND an outbound destination",
                           severity="critical", evidence=_snippet(text, m.start(), m.end()) + " | " + _snippet(text, e.start(), e.end(), 20),
                           needle=m.group(0))
        elif e:
            yield _finding("ASC003", doc, path, f"{label}: instructs sending data to an external destination",
                           severity="high", evidence=_snippet(text, e.start(), e.end()), needle=e.group(0))
        elif m:
            yield _finding("ASC003", doc, path, f"{label}: references sensitive local files ({m.group(0)})",
                           severity="medium", evidence=_snippet(text, m.start(), m.end()), needle=m.group(0))


# ---------------------------------------------------------------------------
# ASC004 tool shadowing
# ---------------------------------------------------------------------------
@rule(
    "ASC004", "tool-shadowing", "Tool shadowing / cross-tool manipulation", "high",
    "A tool whose description talks about how *other* tools must behave, or two servers exposing the same tool name, "
    "lets one server hijack calls meant for another (cross-origin escalation).",
    "Remove the offending server or rename/namespace the colliding tools. Tools should only describe themselves.",
    ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",),
)
def check_shadowing(doc: Document) -> Iterator[Finding]:
    names: dict[str, list] = {}
    for t in doc.tools:
        names.setdefault(t.name.lower(), []).append(t)
    for n, ts in names.items():
        servers = {t.server for t in ts}
        if len(ts) > 1 and len(servers) > 1:
            yield _finding("ASC004", doc, ts[1].path, f"tool name '{n}' is exposed by multiple servers: {sorted(servers)}",
                           severity="medium", needle=ts[1].name)
    generic = re.compile(r"\b(when|whenever|if)\b.{0,30}\b(using|calling|invoking)\b.{0,20}\b(the\s+)?[`'\"]?(\w+)[`'\"]?\s+tool\b|"
                         r"\binstead\s+of\s+(the\s+)?[`'\"]?\w+[`'\"]?\s+tool\b|(调用|使用)\s*[`'\"]?\w+[`'\"]?\s*工具时", re.I)
    for t in doc.tools:
        others = [o.name for o in doc.tools if o.name != t.name and o.server != t.server and len(o.name) > 3]
        hit = next((o for o in others if re.search(rf"\b{re.escape(o)}\b", t.description)), None)
        m = generic.search(t.description)
        if hit or m:
            ev = f"mentions tool '{hit}' of another server" if hit else _snippet(t.description, m.start(), m.end())
            yield _finding("ASC004", doc, t.path + ".description", f"tool '{t.name}' tries to influence other tools",
                           evidence=ev, needle=hit or (m.group(0) if m else t.name))


# ---------------------------------------------------------------------------
# ASC010 hardcoded secrets
# ---------------------------------------------------------------------------
@rule(
    "ASC010", "hardcoded-secret", "Hard-coded secret / credential in config", "high",
    "Agent and MCP config files are frequently committed, synced, shared in screenshots, or readable by every installed MCP "
    "server and by the agent itself (and therefore by any prompt injection).",
    "Rotate the credential now, then reference it from the environment or a secret manager instead of a literal, e.g. "
    "VS Code: \"${input:token}\" / \"${env:TOKEN}\"; Claude/Cursor: set it in your shell profile or OS keychain and keep only the "
    "variable name in the file. Add the file to .gitignore.",
)
def check_secrets(doc: Document) -> Iterator[Finding]:
    for path, key, v in _walk(doc.data):
        if not isinstance(v, str):
            continue
        hit = find_secret(v, key)
        if hit:
            sev = "critical" if hit.label.startswith(("Private key", "AWS", "Stripe", "Alibaba", "Tencent", "Volcengine")) else "high"
            yield _finding("ASC010", doc, path, (hit.label if hit.label.startswith("High-entropy") else f"{hit.label} stored as a literal in '{key}'"), severity=sev,
                           evidence=redact(hit.match), needle=hit.match[:12])


# ---------------------------------------------------------------------------
# ASC020 dangerous launch command
# ---------------------------------------------------------------------------
DANGEROUS_CMD: list[tuple[str, str, str]] = [
    ("critical", r"\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|powershell|pwsh)\b", "downloads and pipes remote code into an interpreter"),
    ("critical", r"\b(iex|Invoke-Expression)\b|FromBase64String|\s-(e|enc|EncodedCommand)\s+[A-Za-z0-9+/=]{16,}", "PowerShell expression / encoded command"),
    ("high", r"base64\s+(-d|--decode)|\beval\s|\bexec\(", "decodes or evals dynamic code"),
    ("high", r"\bsudo\b|\brunas\b|\bdoas\b", "runs with elevated privileges"),
    ("critical", r"--privileged\b|/var/run/docker\.sock|--pid[= ]host|--cap-add[= ](SYS_ADMIN|ALL)", "container escape-equivalent docker flags"),
    ("high", r"(-v|--volume|--mount)[= ]\s*(type=bind,\s*source=)?(/|~|\$HOME|/home|/Users|C:\\\\?)(:|,|\s|$)", "mounts host root/home into the container"),
    ("medium", r"--net(work)?[= ]host\b", "shares host network namespace"),
    ("high", r"\brm\s+-[a-z]*r[a-z]*f|\bmkfs\b|\bdd\s+if=", "destructive filesystem command"),
    ("medium", r"\b(nc|ncat|netcat)\b.*\s-e\s|/dev/tcp/", "raw socket / reverse-shell style construct"),
]
_DC = [(s, re.compile(rx, re.I), w) for s, rx, w in DANGEROUS_CMD]
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


@rule(
    "ASC020", "dangerous-command", "Unsafe command used to launch an MCP server", "high",
    "stdio MCP servers run as local processes with your user's privileges. Shell one-liners that download and execute code, "
    "elevated privileges, or privileged containers turn any compromise of the package or URL into full machine compromise.",
    "Install the server from a pinned, reviewed package and call its binary directly (no `sh -c`, no `curl | sh`, no sudo). "
    "If you containerise it, drop --privileged/docker.sock and mount only the project directory read-only.",
)
def check_dangerous_command(doc: Document) -> Iterator[Finding]:
    for s in doc.servers:
        line = s.cmdline
        if not line:
            continue
        reported = False
        for sev, rx, why in _DC:
            m = rx.search(line)
            if m:
                reported = True
                yield _finding("ASC020", doc, s.path, f"server '{s.name}' {why}", severity=sev,
                               evidence=_snippet(line, m.start(), m.end(), 40), needle=s.name)
        base = s.command.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if not reported and base in SHELLS and any(a.lower() in ("-c", "/c", "-command", "/k") for a in s.args):
            yield _finding("ASC020", doc, s.path, f"server '{s.name}' is launched through a shell wrapper ({base} -c)",
                           severity="medium", evidence=line[:160], needle=s.name,
                           fix="Call the server executable directly with an argument list; shell wrappers hide what actually runs and enable injection via env/args.")


# ---------------------------------------------------------------------------
# ASC021 unpinned packages (supply chain / rug pull)
# ---------------------------------------------------------------------------
def _first_pkg(args: list[str], skip_values: set[str]) -> str | None:
    it = iter(range(len(args)))
    for i in it:
        a = args[i]
        if a in skip_values:  # option taking a value
            next(it, None)
            continue
        if a.startswith("-"):
            continue
        return a
    return None


@rule(
    "ASC021", "unpinned-package", "MCP server package/image is not version-pinned", "medium",
    "`npx -y pkg`, `uvx pkg`, `pkg@latest` or `image:latest` fetch whatever was published most recently at every launch. "
    "A compromised or malicious update (a 'rug pull') runs automatically with no review.",
    "Pin an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3, docker image@sha256:...) and review changes before bumping.",
)
def check_unpinned(doc: Document) -> Iterator[Finding]:
    for s in doc.servers:
        base = s.command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".cmd").removesuffix(".exe")
        args = s.args
        pkg = None
        pinned = True
        if base in ("npx", "bunx", "pnpx") or (base in ("pnpm", "yarn", "npm") and args[:1] in (["dlx"], ["exec"])):
            pkg = _first_pkg([a for a in args if a not in ("dlx", "exec")], {"-p", "--package"})
            if pkg:
                name_part = pkg[1:] if pkg.startswith("@") else pkg
                pinned = "@" in name_part and not name_part.endswith(("@latest", "@next", "@*"))
        elif base in ("uvx", "pipx") or (base == "uv" and args[:2] in (["tool", "run"],)):
            a2 = args[2:] if base == "uv" else (args[1:] if base == "pipx" and args[:1] == ["run"] else args)
            pkg = _first_pkg(a2, {"--from", "--python", "--with", "-p"})
            if "--from" in a2:
                idx = a2.index("--from")
                pkg = a2[idx + 1] if idx + 1 < len(a2) else pkg
            if pkg:
                pinned = bool(re.search(r"(==|@)[\w.]+", pkg)) and not pkg.endswith("@latest")
        elif base in ("docker", "podman") and args[:1] == ["run"]:
            pkg = _first_pkg(args[1:], {"-e", "--env", "-v", "--volume", "--name", "--network", "--net", "-p", "--mount", "-w", "--env-file", "-u", "--user"})
            if pkg:
                pinned = "@sha256:" in pkg or (":" in pkg.rsplit("/", 1)[-1] and not pkg.endswith(":latest"))
        if pkg and not pinned:
            yield _finding("ASC021", doc, s.path, f"server '{s.name}' runs unpinned '{pkg}' via {base}",
                           evidence=s.cmdline[:160], needle=pkg)
        for a in args:
            if re.match(r"^(git\+)?https://github\.com/[^@#]+(\.git)?$", a):
                yield _finding("ASC021", doc, s.path, f"server '{s.name}' installs from a git URL without a pinned commit",
                               severity="medium", evidence=a, needle=a)


# ---------------------------------------------------------------------------
# ASC022 TLS verification disabled
# ---------------------------------------------------------------------------
@rule(
    "ASC022", "tls-disabled", "TLS certificate verification disabled", "medium",
    "Disabling certificate checks lets anyone on the network path impersonate the MCP endpoint or package registry and "
    "inject tool descriptions or responses.",
    "Remove the flag/variable; if you use a corporate proxy, add its CA to the trust store (NODE_EXTRA_CA_CERTS / SSL_CERT_FILE) instead.",
)
def check_tls(doc: Document) -> Iterator[Finding]:
    bad_env = {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "PYTHONHTTPSVERIFY": "0", "GIT_SSL_NO_VERIFY": "1", "CURL_INSECURE": "1"}
    for s in doc.servers:
        for k, v in s.env.items():
            if k.upper() in bad_env and v.strip().lower() in (bad_env[k.upper()], "true" if bad_env[k.upper()] == "1" else "false"):
                yield _finding("ASC022", doc, f"{s.path}.env.{k}", f"server '{s.name}' sets {k}={v}", evidence=f"{k}={v}", needle=k)
        for a in s.args:
            if a in ("--insecure", "-k", "--no-verify-ssl", "--skip-ssl-verify", "--no-check-certificate", "--ssl-no-verify"):
                yield _finding("ASC022", doc, s.path, f"server '{s.name}' passes {a}", evidence=a, needle=a)


# ---------------------------------------------------------------------------
# ASC030 over-broad filesystem scope
# ---------------------------------------------------------------------------
BROAD_PATHS = {"/": "critical", "/*": "critical", "c:\\": "critical", "c:/": "critical", "c:": "critical",
               "~": "high", "~/": "high", "$home": "high", "${home}": "high", "%userprofile%": "high",
               "/home": "high", "/users": "high", "/etc": "high", "/root": "high", "c:\\users": "high"}


@rule(
    "ASC030", "overbroad-filesystem", "File-system access scope is too broad", "high",
    "Granting a filesystem/terminal server your whole disk or home directory gives every prompt injection access to SSH keys, "
    "browser profiles, cloud credentials and other agents' configs.",
    "Scope the server to the specific project directories it needs (preferably read-only), e.g. "
    "`npx -y @modelcontextprotocol/server-filesystem@<ver> /path/to/project`.",
)
def check_fs_scope(doc: Document) -> Iterator[Finding]:
    for s in doc.servers:
        for a in s.args:
            norm = a.strip().rstrip("/").lower() or "/"
            if a.strip() in ("/", "/*"):
                norm = a.strip()
            if norm in BROAD_PATHS or re.fullmatch(r"(/home/[^/]+|/users/[^/]+|c:\\users\\[^\\]+)", norm):
                sev = BROAD_PATHS.get(norm, "high")
                yield _finding("ASC030", doc, s.path, f"server '{s.name}' is given access to '{a}'", severity=sev,
                               evidence=s.cmdline[:160], needle=s.name)
        if any(k in s.raw for k in ("roots", "allowedDirectories")):
            for r in s.raw.get("roots") or s.raw.get("allowedDirectories") or []:
                rr = str(r.get("uri", r) if isinstance(r, dict) else r).replace("file://", "")
                if rr.rstrip("/").lower() in ("", "~") or rr == "/":
                    yield _finding("ASC030", doc, s.path, f"server '{s.name}' root '{rr}' is too broad", severity="critical", needle=s.name)


# ---------------------------------------------------------------------------
# ASC031 agent posture: auto-approve / sandbox disabled
# ---------------------------------------------------------------------------
EXEC_TOOL = re.compile(r"(exec|shell|bash|terminal|command|run|write|delete|remove|rm|edit|push|deploy|eval|kill|sql|query)", re.I)


@rule(
    "ASC031", "auto-approve", "Human approval or sandbox disabled for agent tool calls", "high",
    "Auto-approving tool calls (YOLO / bypassPermissions / alwaysAllow / approval_policy=never) removes the last human check "
    "between a prompt injection and a real side effect (shell commands, file writes, outbound requests).",
    "Keep confirmation on for exec/write/network tools. Allow-list only narrow, read-only commands (e.g. `Bash(git status)` rather "
    "than `Bash(*)`), keep the sandbox on (Codex: sandbox_mode = \"workspace-write\"), and never trust a whole MCP server.",
)
def check_posture(doc: Document) -> Iterator[Finding]:
    data = doc.data if isinstance(doc.data, dict) else {}
    # Claude Code settings.json
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else None
    if perms:
        if perms.get("defaultMode") == "bypassPermissions":
            yield _finding("ASC031", doc, "permissions.defaultMode", "Claude Code permission prompts are bypassed (bypassPermissions)",
                           severity="critical", evidence="defaultMode: bypassPermissions", needle="bypassPermissions")
        for i, a in enumerate(perms.get("allow") or []):
            a = str(a)
            if re.fullmatch(r"Bash(\((\*|\*:\*|:\*)\))?", a) or a in ("*", "mcp__*"):
                yield _finding("ASC031", doc, f"permissions.allow[{i}]", f"unrestricted allow rule '{a}'",
                               severity="high", evidence=a, needle=a)
            elif re.fullmatch(r"Bash\((curl|wget|python3?|node|sh|bash|npx|rm|sudo)[ :]?\*?\)", a):
                yield _finding("ASC031", doc, f"permissions.allow[{i}]", f"allow rule '{a}' permits arbitrary code/network",
                               severity="medium", evidence=a, needle=a)
    if data.get("enableAllProjectMcpServers") is True:
        yield _finding("ASC031", doc, "enableAllProjectMcpServers",
                       "every MCP server declared in any opened repo's .mcp.json is auto-enabled", severity="medium",
                       needle="enableAllProjectMcpServers")
    # Codex config.toml (top level and profiles)
    scopes = [("", data)] + [(f"profiles.{k}.", v) for k, v in (data.get("profiles") or {}).items() if isinstance(v, dict)]
    for prefix, sc in scopes:
        ap, sb = sc.get("approval_policy"), sc.get("sandbox_mode")
        if ap == "never" and sb == "danger-full-access":
            yield _finding("ASC031", doc, f"{prefix}approval_policy", "Codex runs with no approvals AND no sandbox",
                           severity="critical", evidence="approval_policy=never, sandbox_mode=danger-full-access", needle="danger-full-access")
        elif sb == "danger-full-access":
            yield _finding("ASC031", doc, f"{prefix}sandbox_mode", "Codex sandbox disabled (danger-full-access)",
                           severity="high", evidence="sandbox_mode=danger-full-access", needle="danger-full-access")
        elif ap == "never":
            yield _finding("ASC031", doc, f"{prefix}approval_policy", "Codex never asks for approval", severity="medium",
                           evidence="approval_policy=never", needle="approval_policy")
    # Generic YOLO-style switches (Gemini CLI, VS Code, misc.)
    for path, key, v in _walk(data):
        k = key.lower()
        if v is True and (k in ("yolo", "autoaccept", "dangerouslyskippermissions", "chat.tools.autoapprove",
                                "chat.tools.global.autoapprove", "autoapproveall", "alwaysallowall") or k.endswith("autoapprove")):
            yield _finding("ASC031", doc, path, f"auto-approval switch '{key}' is enabled", severity="high", evidence=f"{key}: true", needle=key)
    # Per-server alwaysAllow / autoApprove / trust (Cline, Roo, Gemini CLI)
    for s in doc.servers:
        if s.trust:
            yield _finding("ASC031", doc, f"{s.path}.trust", f"server '{s.name}' is fully trusted (all confirmations skipped)",
                           severity="high", evidence="trust: true", needle="trust")
        if s.auto_approve:
            risky = [t for t in s.auto_approve if t == "*" or EXEC_TOOL.search(t)]
            yield _finding("ASC031", doc, f"{s.path}.alwaysAllow", f"server '{s.name}' auto-approves tools: {s.auto_approve[:6]}",
                           severity="high" if risky else "low", evidence=f"risky: {risky}" if risky else "",
                           needle=s.auto_approve[0])


# ---------------------------------------------------------------------------
# ASC040 remote endpoints
# ---------------------------------------------------------------------------
TUNNEL_HOSTS = re.compile(
    r"(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|localhost\.run|pinggy\.(io|link)|"
    r"webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|me|live|site|online|pro)|burpcollaborator\.net|"
    r"beeceptor\.com|hookbin\.com|requestcatcher\.com|ptpb|transfer\.sh|pastebin\.com)$",
    re.I,
)


_LOCAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")


def _urls(s: Server) -> list[tuple[str, str]]:
    out = [("url", s.url)] if s.url else []
    for a in s.args:
        for m in re.finditer(r"\b(?:https?|wss?)://[^\s\"'<>]+", a):
            out.append(("args", m.group(0)))
    return out


@rule(
    "ASC040", "suspicious-endpoint", "Insecure or suspicious remote MCP endpoint", "high",
    "Remote MCP servers receive your prompts/tool arguments and control the tool descriptions your agent reads. Plain HTTP, raw "
    "IPs, tunnel/request-catcher domains and punycode hosts are typical of throw-away or attacker-controlled endpoints.",
    "Use HTTPS endpoints operated by the vendor you intend to trust, authenticate with OAuth / scoped tokens, and avoid tunnel or "
    "request-bin domains in shared configs.",
)
def check_endpoints(doc: Document) -> Iterator[Finding]:
    for s in doc.servers:
        for where, u in _urls(s):
            try:
                p = urlparse(u)
            except ValueError:
                continue
            host = (p.hostname or "").lower()
            if not host:
                continue
            local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")
            ip = None
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                pass
            if ip and (ip.is_loopback or any(ip in ipaddress.ip_network(n) for n in _LOCAL_NETS if ip.version == ipaddress.ip_network(n).version)):
                local = True
            if ip and str(ip) in ("169.254.169.254", "100.100.100.200") :
                yield _finding("ASC040", doc, s.path, f"server '{s.name}' points at a cloud metadata address {host}",
                               severity="critical", evidence=u, needle=u[:30])
                continue
            if TUNNEL_HOSTS.search(host):
                yield _finding("ASC040", doc, s.path, f"server '{s.name}' uses a tunnel/request-capture host '{host}'",
                               severity="high", evidence=u, needle=host)
            if p.scheme in ("http", "ws") and not local:
                yield _finding("ASC040", doc, s.path, f"server '{s.name}' uses unencrypted {p.scheme}:// to a non-local host",
                               severity="high", evidence=u, needle=host)
            elif ip and not local:
                yield _finding("ASC040", doc, s.path, f"server '{s.name}' uses a raw public IP address {host}",
                               severity="medium", evidence=u, needle=host)
            if "xn--" in host:
                yield _finding("ASC040", doc, s.path, f"server '{s.name}' uses a punycode (possibly look-alike) host '{host}'",
                               severity="medium", evidence=u, needle=host)


# ---------------------------------------------------------------------------
# ASC041 binding to all interfaces
# ---------------------------------------------------------------------------
@rule(
    "ASC041", "exposed-bind", "Local MCP server exposed on all network interfaces", "medium",
    "A local server bound to 0.0.0.0 / :: is reachable from the LAN (or the internet on a cloud VM). Many MCP servers have no auth.",
    "Bind to 127.0.0.1 and, for remote use, put the server behind authentication (OAuth / token) and TLS.",
)
def check_bind(doc: Document) -> Iterator[Finding]:
    for s in doc.servers:
        line = s.cmdline + " " + " ".join(f"{k}={v}" for k, v in s.env.items())
        m = re.search(r"(--host[= ]|--bind[= ]|HOST=|-H\s)(0\.0\.0\.0|::|\[::\])\b|-p\s+0\.0\.0\.0:", line)
        if m:
            yield _finding("ASC041", doc, s.path, f"server '{s.name}' binds to all interfaces", evidence=m.group(0), needle="0.0.0.0")


# ---------------------------------------------------------------------------
# ASC050 toxic combination ("lethal trifecta" heuristic)
# ---------------------------------------------------------------------------
UNTRUSTED = re.compile(r"(fetch|browser|puppeteer|playwright|web|search|crawl|scrape|firecrawl|tavily|brave|email|gmail|mail|slack|"
                       r"discord|telegram|github|gitlab|jira|notion|rss|youtube|reddit|twitter|(?<![a-z])x-mcp|wechat|feishu|lark|dingtalk)", re.I)
POWERFUL = re.compile(r"(shell|terminal|exec|command|desktop-commander|filesystem|server-filesystem|docker|kubernetes|k8s|ssh|"
                      r"postgres|mysql|sqlite|database|aws|aliyun|gcloud|azure|code-runner|python-repl|computer-use)", re.I)


@rule(
    "ASC050", "toxic-combination", "Untrusted-input + powerful-action servers in the same agent", "medium",
    "When one agent can both read attacker-controllable content (web, e-mail, issues, chat) and run commands / touch files / "
    "databases, a single injected document can drive the powerful tool. Risk is higher when calls are auto-approved.",
    "Split these capabilities into separate agent profiles/workspaces, keep confirmation on for the powerful tools, and scope "
    "credentials to read-only where possible.",
    ("https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",),
)
def check_toxic(doc: Document) -> Iterator[Finding]:
    active = [s for s in doc.servers if not s.disabled]
    def ident(s: Server) -> str:  # the launcher binary (npx/docker/uvx) is not a capability
        return " ".join([s.name, *s.args, s.url])
    src = [s for s in active if UNTRUSTED.search(ident(s))]
    pwr = [s for s in active if POWERFUL.search(ident(s))]
    pairs = [(a, b) for a in src for b in pwr if a is not b]
    if not pairs:
        return
    auto = any(s.trust or s.auto_approve for s in active) or any(
        f.rule_id == "ASC031" for f in check_posture(doc))
    a, b = pairs[0]
    yield _finding("ASC050", doc, b.path,
                   f"'{a.name}' ingests untrusted content and '{b.name}' can act on the system" + (" — and tool calls are auto-approved" if auto else ""),
                   severity="high" if auto else "low",
                   evidence=f"untrusted: {sorted({x.name for x in src})}; powerful: {sorted({x.name for x in pwr})}", needle=b.name)


def run_rules(doc: Document, only: set[str] | None = None, ignore: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for r in RULES:
        if only and r.id not in only and r.name not in only:
            continue
        if ignore and (r.id in ignore or r.name in ignore):
            continue
        out.extend(r.check(doc))
    # de-duplicate identical findings
    seen, uniq = set(), []
    for f in out:
        key = (f.rule_id, f.source, f.path, f.message)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
