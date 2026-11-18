"""Alert triage summaries: Claude when an API key is configured, a template otherwise."""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("threatlens.summarizer")

SYSTEM_PROMPT = """You are a senior SOC analyst at a managed detection and response provider.
You write the first triage note for an alert so the next analyst can act in under a minute.

Ground every statement in the alert JSON you are given. Do not invent IPs, hosts, users,
timestamps or counts. If the evidence is ambiguous, say what would confirm or refute it.

Write plain text with exactly these sections:
What happened: 2-3 sentences, concrete entities and numbers.
Why it matters: 1-2 sentences tying it to the MITRE ATT&CK technique and likely attacker goal.
Likely false-positive causes: one short line.
Next steps: 3 numbered, specific actions, most urgent first.
Keep it under 170 words."""

LLM_MODEL = os.getenv("LLM_MODEL", "claude-opus-5-5")


def llm_enabled() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY")) and os.getenv("LLM_DISABLED", "").lower() not in ("1", "true")


def template_summary(alert: dict) -> str:
    ents = {k: v for k, v in (alert.get("entities") or {}).items() if v and v != "null"}
    lines = [
        f"What happened: {alert.get('description') or alert.get('title')}",
        f"Entities: {', '.join(f'{k}={v}' for k, v in ents.items()) or 'n/a'}.",
    ]
    if alert.get("mitre"):
        lines.append(f"Why it matters: maps to {alert['mitre']}.")
    lines.append(f"Risk {alert.get('risk_score')}/100 ({alert.get('severity')}).")
    steps = alert.get("playbook") or []
    if steps:
        lines.append("Next steps:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)))
    return "\n".join(lines)


def summarize(alert: dict) -> tuple[str, str]:
    """Returns (summary, source) where source is 'llm:<model>' or 'template'."""
    if not llm_enabled():
        return template_summary(alert), "template"
    try:
        import anthropic

        client = anthropic.Anthropic()
        response = client.beta.messages.create(
            model=LLM_MODEL,
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": "Alert JSON:\n" + json.dumps(alert, default=str, indent=1)}],
        )
        if response.stop_reason == "refusal":
            log.warning("LLM declined alert %s", alert.get("id"))
            return template_summary(alert), "template"
        text = "".join(b.text for b in response.content if b.type == "text").strip()
        if not text:
            return template_summary(alert), "template"
        return text, f"llm:{response.model}"
    except Exception as exc:  # network, auth, rate limit: never block triage on the LLM
        log.warning("LLM summary failed (%s); using template", exc)
        return template_summary(alert), "template"
