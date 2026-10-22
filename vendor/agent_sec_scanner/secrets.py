"""Credential detection with redaction. Patterns are intentionally conservative."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# (label, regex). Order matters: first match wins for a given value.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI project key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}")),
    ("sk- style LLM API key (OpenAI / DeepSeek / DashScope / Moonshot / SiliconFlow ...)", re.compile(r"\bsk-[A-Za-z0-9]{24,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("Alibaba Cloud (Aliyun) AccessKey ID", re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b")),
    ("Tencent Cloud SecretId", re.compile(r"\bAKID[A-Za-z0-9]{32}\b")),
    ("Volcengine (ByteDance) AccessKey", re.compile(r"\bAKLT[A-Za-z0-9_\-]{20,}")),
    ("Baidu Qianfan / BCE API key", re.compile(r"\bbce-v3/ALTAK-[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("Zhipu (BigModel) API key", re.compile(r"\b[a-f0-9]{32}\.[A-Za-z0-9]{16}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Credentials embedded in URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]{3,}@[^\s/]+", re.I)),
]

SECRET_KEY_NAME = re.compile(
    r"(api[_\-]?key|apikey|secret|token|passw(or)?d|pwd|access[_\-]?key|private[_\-]?key|auth|credential|cookie|密钥|令牌|密码)",
    re.I,
)

# Values that are references / placeholders rather than literal secrets
PLACEHOLDER = re.compile(
    r"^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]+\}\}|<[^>]+>|%[A-Z_]+%|"
    r"(your|my|example|placeholder|changeme|xxx+|\*+|todo|replace)[\w\-]*|env:[\w]+|op://.+|keychain:.+)\s*$",
    re.I,
)


@dataclass
class SecretHit:
    label: str
    match: str


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}…{s[-2:]} (len={len(s)})"


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.match(value)) or value.strip() == ""


def find_secret(value: str, key: str = "") -> SecretHit | None:
    if not isinstance(value, str) or is_placeholder(value):
        return None
    for label, rx in PATTERNS:
        m = rx.search(value)
        if m:
            return SecretHit(label, m.group(0))
    # "Bearer <token>" header values
    m = re.match(r"^\s*(Bearer|Basic|token)\s+(\S{12,})\s*$", value, re.I)
    if m and not is_placeholder(m.group(2)):
        return SecretHit(f"{m.group(1)} credential in header", m.group(2))
    # Generic: secret-ish key name + high-entropy literal value
    if key and SECRET_KEY_NAME.search(key):
        v = value.strip()
        if len(v) >= 12 and " " not in v and entropy(v) >= 3.0 and not v.startswith(("/", "~", ".", "http")):
            return SecretHit(f"High-entropy literal value in secret-named field '{key}'", v)
    return None
