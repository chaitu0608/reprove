"""AI-feature analyzer: the new class of vibe-code bugs.

Apps generated today embed LLM calls with user input flowing straight into
prompts and tools. Rules:

  * user input interpolated into system prompts (prompt-injection surface)
  * tool-calling with shell/file/eval capabilities and no allowlist
  * LLM keys used client-side (the call itself ships from the browser)
  * unvalidated model output handed to dangerous sinks
"""

from __future__ import annotations

import re

from ..context import ScanContext, ScanFile, register
from ..models import Category, Confidence, Evidence, Finding, Severity, VerificationMode
from ..util import line_of

LLM_SDK = re.compile(r"new\s+OpenAI\s*\(|new\s+Anthropic\s*\(|@google/generative-ai|generativeai\.|@ai-sdk/|langchain|litellm", re.I)
SYSTEM_PROMPT = re.compile(r"role\s*:\s*['\"]system['\"]|system\s*:\s*(?:`|['\"]|\w)", re.I)
USER_INTERP = re.compile(r"\$\{[^}]*(?:req\.|request\.|input|user|message|prompt|query|body)[^}]*\}|\.\.\.(?:req\.body|inputs|userMessage)", re.I)
SYSTEM_INTERP = re.compile(r"system[^,}]{0,80}[`'\"].*\$\{|\$\{[^}]*\}.*[\"'`][^,}]{0,40}(?:system instruction|You are)", re.I)

TOOL_RISKY = re.compile(r"(?:execute|run|handler)\s*[:=]\s*(?:async\s*)?(?:\([^)]*\)\s*=>|\bfunction\b)[\s\S]{0,300}?\b(exec|execSync|spawn|eval|Function|system|rm\s|fs\.(?:write|unlink|read))", re.I)
TOOL_DEF = re.compile(r"tools\s*[:=]|tool_calls\b|function_call\b", re.I)
RISKY_OP = re.compile(r"\b(exec|execSync|spawn|spawnSync|eval|new\s+Function|child_process)\b")
EXECUTE_FIELD = re.compile(r"execute\s*[:=]", re.I)


def _strip_comments(text: str) -> str:
    """Remove JS/TS comments so prose like 'no allowlist' cannot suppress a rule."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)

CLIENT_LLM = re.compile(r"NEXT_PUBLIC_[A-Z_]*(?:OPENAI|ANTHROPIC|GEMINI|AI)[A-Z_]*|VITE_[A-Z_]*(?:OPENAI|ANTHROPIC|AI)[A-Z_]*", re.I)
CLIENT_FILE = re.compile(r"\.(tsx|jsx|vue|svelte)$|['\"]use client['\"]")

RAW_OUTPUT_HTML = re.compile(r"dangerouslySetInnerHTML\s*[:=][^}]{0,200}(?:completion|message|content|response|result|output)", re.I | re.S)


def _f(f: ScanFile, line: int, rule: str, title: str, sev: Severity, conf: Confidence,
       desc: str, remed: str, evidence: str, tags: list[str] | None = None) -> Finding:
    return Finding(
        rule=rule,
        category=Category.AI_FEATURE,
        title=title,
        severity=sev,
        confidence=conf,
        description=desc,
        remediation=remed,
        location=f"{f.relpath}:{line}",
        evidence=[Evidence(kind="code", detail=evidence, location=f"{f.relpath}:{line}")],
        verification_mode=VerificationMode.RESCAN,
        tags=["ai"] + (tags or []),
    )


@register("ai_calls")
def analyze_ai_calls(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for f in ctx.files:
        if f.is_built or f.path.suffix.lower() not in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".mjs"):
            continue
        text = f.text
        uses_llm = (
            bool(LLM_SDK.search(text))
            or bool(re.search(r"chat\.completions|messages\.create|generateContent|streamText|generateText", text))
            or bool(re.search(r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com", text))
        )
        if not uses_llm:
            continue

        # 1. user input into system/instructions
        for m in USER_INTERP.finditer(text):
            window = text[max(0, m.start() - 250): m.end() + 250]
            if SYSTEM_PROMPT.search(window):
                line = line_of(text, m.start())
                sev = Severity.HIGH if CLIENT_FILE.search(f.relpath) is None else Severity.CRITICAL
                out.append(_f(f, line, "ai/prompt-injection-surface",
                              "User input interpolated into LLM instructions",
                              sev, Confidence.LIKELY,
                              f"At `{f.relpath}:{line}` request-controlled data is interpolated near the "
                              "system/instruction prompt. System prompts are not a security boundary: a user "
                              "who writes \"ignore previous instructions…\" becomes your model's new system "
                              "prompt — and can steer any tool the model can call.",
                              "Keep a fixed system prompt. Put user content in a separate user message, and "
                              "treat model output as untrusted: validate it before acting on it. If tools are "
                              "attached, allowlist tool arguments and require confirmation for destructive actions.",
                              f"interpolation: {m.group(0)[:140]}",
                              tags=["prompt-injection"]))
                break  # one per file is enough signal

        # 2. risky tools
        tm = TOOL_RISKY.search(text) or None
        rm = RISKY_OP.search(text)
        if rm and TOOL_DEF.search(text):
            tm = tm or rm
        if tm:
            line = line_of(text, tm.start())
            window = _strip_comments(text[max(0, tm.start() - 600): tm.end() + 600])
            has_allow = re.search(r"allow(?:list|ed)|whitelist|confirm|approval|permission|sanitiz", window, re.I)
            if not has_allow:
                matched_op = tm.group(1) if tm.re.groups else tm.group(0)
                conf = Confidence.LIKELY if EXECUTE_FIELD.search(text) else Confidence.POSSIBLE
                out.append(_f(f, line, "ai/unsafe-tool-execution",
                              "LLM tool can execute code/shell with no allowlist",
                              Severity.HIGH, conf,
                              f"A tool definition at `{f.relpath}:{line}` wires the model to "
                              f"`{matched_op}`. Prompt injection + this tool = remote code execution on your server.",
                              "Never expose raw exec/eval as tools. Wrap capabilities in narrow, validated "
                              "operations (e.g. 'add todo'), allowlist arguments, and require human approval "
                              "for anything destructive.",
                              f"tool body reaches: {matched_op}"))
        # 3. client-side LLM key/call
        cm = CLIENT_LLM.search(text)
        if cm and CLIENT_FILE.search(f.relpath):
            line = line_of(text, cm.start())
            out.append(_f(f, line, "ai/llm-called-from-client",
                          "LLM API key used in client-side code",
                          Severity.HIGH, Confidence.LIKELY,
                          f"`{cm.group(0)}` at `{f.relpath}:{line}` means the browser itself calls the "
                          "provider — the key ships to every visitor, and anyone can spend your quota or "
                          "worse. Client-side models also mean prompts are inspectable by users.",
                          "Proxy LLM calls through a server route/edge function; the provider key lives only "
                          "server-side. Add per-user rate limits there.",
                          f"client-referenced env var: {cm.group(0)}",
                          tags=["secrets"]))
        # 4. raw model output into HTML
        rm = RAW_OUTPUT_HTML.search(text)
        if rm:
            line = line_of(text, rm.start())
            out.append(_f(f, line, "ai/model-output-to-html",
                          "Model output rendered as raw HTML",
                          Severity.HIGH, Confidence.POSSIBLE,
                          f"At `{f.relpath}:{line}` an LLM response is piped into `dangerouslySetInnerHTML`. "
                          "Models emit attacker-steerable HTML (markdown links, imgs, scripts) — this is XSS "
                          "with the model as the delivery vector.",
                          "Sanitize model output with DOMPurify before any HTML sink, or render it as plain text/markdown with a safe renderer.",
                          f"sink: {rm.group(0)[:140]}"))
    return out
