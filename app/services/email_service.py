"""
Sends alert emails over SMTP and exposes the alert as an LLM tool.

Pieces:
  - send_email(...)           generic SMTP sender (supports dry-run)
  - send_critical_alert(...)  builds a formatted incident alert and sends it
  - SEND_ALERT_TOOL           function declaration to give to Gemini (or Claude later)
  - handle_tool_call(...)     runs the tool call returned by the model, with guardrails

Configuration comes from environment variables / a .env file (see .env.example).
"""
from __future__ import annotations

import html
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from langchain.tools import tool

try:  # optional: load .env if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Guardrail: the code decides, not the model. Only these severities may send mail.
EMAIL_SEVERITIES = {"high", "critical"}

# --------------------------------------------------------------------------- #
# Tool declaration (JSON-schema style; works with Gemini function calling)
# --------------------------------------------------------------------------- #
SEND_ALERT_TOOL: dict[str, Any] = {
    "name": "send_critical_alert",
    "description": (
        "Send an email alert to the DevOps team. Call this ONLY when the incident is "
        "high or critical severity and needs human attention."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short incident title."},
            "severity": {"type": "string", "description": "One of: low, medium, high, critical."},
            "affected_service": {"type": "string", "description": "Service that is failing."},
            "root_cause": {"type": "string", "description": "Most likely root cause."},
            "suggested_fix": {"type": "string", "description": "Concrete steps to fix it."},
            "matched_history": {
                "type": "string",
                "description": "ID or summary of a similar past incident, if any.",
            },
            "confidence": {"type": "number", "description": "Confidence from 0 to 1."},
        },
        "required": ["title", "severity", "affected_service", "root_cause", "suggested_fix"],
    },
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _clean_header(value: str) -> str:
    """Remove newlines so log text can never inject extra email headers."""
    return re.sub(r"[\r\n]+", " ", value).strip()[:200]


def _parse_recipients(to: str | list[str] | None) -> list[str]:
    if to is None:
        to = os.getenv("EMAIL_TO", "")
    items = to.split(",") if isinstance(to, str) else list(to)
    cleaned = [item.strip() for item in items if item and item.strip()]
    return [addr for addr in cleaned if _EMAIL_RE.match(addr)]


def _format_confidence(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "n/a"
    return f"{number:.0f}%" if number > 1 else f"{number * 100:.0f}%"


# --------------------------------------------------------------------------- #
# Generic sender
# --------------------------------------------------------------------------- #
def send_email(
    subject: str,
    body: str,
    to: str | list[str] | None = None,
    html_body: str | None = None,
) -> dict[str, Any]:
    """Send an email. Never raises: returns {"status": "sent" | "dry_run" | "failed", ...}."""
    recipients = _parse_recipients(to)
    if not recipients:
        return {"status": "failed", "error": "No valid recipients (set EMAIL_TO)."}

    sender = os.getenv("EMAIL_FROM") or os.getenv("SMTP_USER", "")
    subject = _clean_header(subject)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    if _env_bool("EMAIL_DRY_RUN", True):
        logger.info("[DRY RUN] Email to %s | %s", recipients, subject)
        print(f"\n--- DRY RUN EMAIL ---\nTo: {', '.join(recipients)}\nSubject: {subject}\n\n{body}\n---------------------")
        return {"status": "dry_run", "to": recipients, "subject": subject}

    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")

    try:
        try:
            import certifi

            context = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            context = ssl.create_default_context()

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
            server.starttls(context=context)
        with server:
            if user:
                server.login(user, password)
            server.send_message(msg)
        logger.info("Email sent to %s | %s", recipients, subject)
        return {"status": "sent", "to": recipients, "subject": subject}
    except Exception as exc:  # network/auth errors should not crash the pipeline
        logger.error("Email failed: %s", exc)
        return {"status": "failed", "error": str(exc)}


# --------------------------------------------------------------------------- #
# Incident alert (this is what the LLM tool calls)
# --------------------------------------------------------------------------- #
def send_critical_alert(
    title: str,
    severity: str,
    affected_service: str,
    root_cause: str,
    suggested_fix: str,
    matched_history: str = "",
    confidence: Any = None,
    to: str | list[str] | None = None,
) -> dict[str, Any]:
    """Build a readable incident email (plain text + HTML) and send it."""
    sev = (severity or "unknown").upper()
    subject = f"[{sev}] {affected_service}: {title}"

    fields = [
        ("Severity", sev),
        ("Service", affected_service),
        ("Root cause", root_cause),
        ("Suggested fix", suggested_fix),
        ("Similar past incident", matched_history or "None found"),
        ("Confidence", _format_confidence(confidence)),
    ]

    text_body = f"{title}\n\n" + "\n".join(f"{label}: {value}" for label, value in fields)
    text_body += "\n\nSent automatically by Log Agent. Please verify before acting."

    rows = "".join(
        f"<tr><td style='padding:4px 12px 4px 0;vertical-align:top'><b>{html.escape(label)}</b></td>"
        f"<td style='padding:4px 0'>{html.escape(str(value))}</td></tr>"
        for label, value in fields
    )
    html_body = (
        f"<h3 style='margin:0 0 12px'>{html.escape(title)}</h3>"
        f"<table style='font-family:Arial,sans-serif;font-size:14px'>{rows}</table>"
        "<p style='color:#666;font-size:12px'>Sent automatically by Log Agent. "
        "Please verify before acting.</p>"
    )
    return send_email(subject, text_body, to=to, html_body=html_body)


# --------------------------------------------------------------------------- #
# Tool-call dispatcher (runs what the model asked for, with guardrails)
# --------------------------------------------------------------------------- #
_ALLOWED_ARGS = set(SEND_ALERT_TOOL["parameters"]["properties"])

@tool
def handle_tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a model-requested tool call. Unknown tools and low severity are refused."""
    if name != "send_critical_alert":
        return {"status": "rejected", "error": f"Unknown tool: {name}"}

    clean = {key: value for key, value in (args or {}).items() if key in _ALLOWED_ARGS}
    missing = [key for key in SEND_ALERT_TOOL["parameters"]["required"] if not clean.get(key)]
    if missing:
        return {"status": "rejected", "error": f"Missing fields: {', '.join(missing)}"}

    severity = str(clean["severity"]).lower()
    if severity not in EMAIL_SEVERITIES:
        return {"status": "skipped", "reason": f"Severity '{severity}' does not require an email."}

    return send_critical_alert(**clean)


# Quick manual test:  python -m services.send_email
# if __name__ == "__main__":
#     result = handle_tool_call(
#         "send_critical_alert",
#         {
#             "title": "Payment service failing after v2.3.1 deployment",
#             "severity": "critical",
#             "affected_service": "payment-service",
#             "root_cause": "DB connection pool reduced from 20 to 5 in release v2.3.1",
#             "suggested_fix": "Roll back to v2.3.0 or restore db_pool_size=20",
#             "matched_history": "INC-0001",
#             "confidence": 0.86,
#         },
#     )
#     print(result)