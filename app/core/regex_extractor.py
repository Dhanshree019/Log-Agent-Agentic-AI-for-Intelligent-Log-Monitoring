

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence


# --------------------------------------------------------------------------- #
# Patterns and settings
# --------------------------------------------------------------------------- #
LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"\[(?P<service>[^\]]+)\]\s+"
    r"(?P<message>.*)$"
)


LEVEL_RANK = {"ERROR": 1, "CRITICAL": 2, "FATAL": 3}

# Lines that describe a change (deploy, rollback, restart ...). Useful for
# telling the LLM "errors started right after this release".
CHANGE_RE = re.compile(
    r"\b(deploy(?:ment|ed)?|rollback|restart(?:ed)?|migration|released?|"
    r"config(?:uration)?\s+(?:change|changed|updated|reloaded))\b",
    re.IGNORECASE,
)

# Used only to build a "signature" so identical errors group together.
_NOISY_KV_RE = re.compile(r"\b(?:user|user_id|email|ip|card|token)=\S+", re.IGNORECASE)
_NORMALIZERS = [
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[A-Z]{2,}-\d+\b"), "<ID>"),          # ORD-10240, TXN-88121
    (re.compile(r"(?<![A-Za-z_])\d+(?:\.\d+)?"), "<N>"),  # numbers, 30000ms -> <N>ms
]



DEFAULT_LEVELS = ("ERROR", "CRITICAL", "FATAL")


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass
class ErrorEvent:
    """One error line found in the log."""
    line_no: int
    timestamp: str
    level: str
    service: str
    message: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    stack_trace: list[str] = field(default_factory=list)


@dataclass
class Incident:
    """Many identical error events grouped into one incident."""
    incident_key: str          # short hash of the signature (stable across runs)
    signature: str
    service: str
    level: str                 # highest level seen in the group
    count: int
    first_seen: str
    last_seen: str
    first_line_no: int
    sample_message: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    stack_trace: list[str] = field(default_factory=list)
    related_changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_embedding_text(self) -> str:
        """Text used for embedding and for the LLM prompt. Mask it before sending out."""
        parts = [
            f"Service: {self.service}",
            f"Level: {self.level}",
            f"Occurrences: {self.count} (first {self.first_seen}, last {self.last_seen})",
            f"Error: {self.sample_message}",
        ]
        if self.stack_trace:
            parts += ["Stack trace:", *self.stack_trace]
        if self.related_changes:
            parts += ["Recent changes before the error:", *[f"- {c}" for c in self.related_changes]]
        if self.context_before:
            parts += ["Log lines before the error:", *self.context_before]
        if self.context_after:
            parts += ["Log lines after the error:", *self.context_after]
        return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Core functions
# --------------------------------------------------------------------------- #


def read_log_lines(file_path: str | Path) -> list[str]:
    """Read a log file safely (bad bytes are replaced instead of crashing)."""
    text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    return text.splitlines()


def extract_error_events(
    lines: Sequence[str],
    levels: Sequence[str] = DEFAULT_LEVELS,
    context_lines: int = 5,
    max_trace_lines: int = 15,
) -> list[ErrorEvent]:
    """Find every error line and capture the lines around it."""
    wanted = {lvl.upper() for lvl in levels}
    events: list[ErrorEvent] = []
    total = len(lines)

    for i, raw in enumerate(lines):
        match = LOG_LINE_RE.match(raw)
        if not match or match.group("level") not in wanted:
            continue

        # Lines that don't look like a new log entry belong to this one (stack trace).
        j = i + 1
        trace: list[str] = []
        while j < total and len(trace) < max_trace_lines and not LOG_LINE_RE.match(lines[j]):
            if lines[j].strip():
                trace.append(lines[j])
            j += 1

        events.append(
            ErrorEvent(
                line_no=i + 1,
                timestamp=match.group("timestamp"),
                level=match.group("level"),
                service=match.group("service"),
                message=match.group("message").strip(),
                context_before=list(lines[max(0, i - context_lines):i]),
                context_after=list(lines[j:j + context_lines]),
                stack_trace=trace,
            )
        )
    return events


def make_signature(service: str, message: str) -> str:
    """Normalise a message so 'same error, different IDs/numbers' gets the same signature."""
    text = _NOISY_KV_RE.sub("", message)
    for pattern, placeholder in _NORMALIZERS:
        text = pattern.sub(placeholder, text)
    text = re.sub(r"\s+", " ", text).strip()
    return f"{service}|{text}"


def find_recent_changes(
    lines: Sequence[str], before_index: int, max_items: int = 3, lookback: int = 200
) -> list[str]:
    """Return the latest deploy / restart / rollback lines before a given line index."""
    found: list[str] = []
    start = max(0, before_index - lookback)
    for k in range(before_index - 1, start - 1, -1):
        if CHANGE_RE.search(lines[k]):
            found.append(lines[k])
            if len(found) == max_items:
                break
    return list(reversed(found))


def group_events(events: Sequence[ErrorEvent], lines: Sequence[str]) -> list[Incident]:
    """Group identical errors into incidents, most severe first."""
    groups: dict[str, Incident] = {}

    for ev in events:
        signature = make_signature(ev.service, ev.message)
        incident = groups.get(signature)

        if incident is None:
            groups[signature] = Incident(
                incident_key=hashlib.sha1(signature.encode()).hexdigest()[:10],
                signature=signature,
                service=ev.service,
                level=ev.level,
                count=1,
                first_seen=ev.timestamp,
                last_seen=ev.timestamp,
                first_line_no=ev.line_no,
                sample_message=ev.message,
                context_before=ev.context_before,
                context_after=ev.context_after,
                stack_trace=ev.stack_trace,
                related_changes=find_recent_changes(lines, ev.line_no - 1),
            )
        else:
            incident.count += 1
            incident.last_seen = ev.timestamp
            if LEVEL_RANK.get(ev.level, 0) > LEVEL_RANK.get(incident.level, 0):
                incident.level = ev.level

    return sorted(
        groups.values(),
        key=lambda inc: (-LEVEL_RANK.get(inc.level, 0), inc.first_line_no),
    )


def extract_incidents(
    file_path: str | Path,
    levels: Sequence[str] = DEFAULT_LEVELS,
    context_lines: int = 5,
) -> list[Incident]:
    """Main entry point: log file in, list of grouped incidents out."""
    lines = read_log_lines(file_path)
    events = extract_error_events(lines, levels=levels, context_lines=context_lines)
    return group_events(events, lines)

