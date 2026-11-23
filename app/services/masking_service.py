"""
Removes sensitive data from text BEFORE it is embedded, stored, sent to the
LLM, or emailed.

Masks: JWTs / bearer tokens, API keys, passwords and secrets in key=value form,
emails, credit cards (Luhn-checked or already partly masked), Aadhaar (grouped),
PAN, phone numbers and IP addresses.

Note: regex masking is a safety net, not a guarantee. Review the patterns for
your own log formats before using real client data.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

# Order matters: more specific patterns first.
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("jwt", re.compile(r"\beyJ[\w-]+\.[\w-]+(?:\.[\w-]+)?"), "[TOKEN]"),
    ("cloud_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[API_KEY]"),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{10,}"), r"\1 [TOKEN]"),
    (
        "secret_kv",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)"
            r"(\s*[=:]\s*)(?!\[)(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1\2[SECRET]",
    ),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[EMAIL]"),
    # Cards: candidates are checked with the Luhn algorithm inside the callback.
    ("card_luhn", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), "[CARD]"),
    # Cards that are already partly masked, e.g. 4111-XXXX-XXXX-1111
    ("card_partial", re.compile(r"\b\d{4}[ -]?[Xx*]{4}[ -]?[Xx*]{4}[ -]?\d{4}\b"), "[CARD]"),
    ("aadhaar", re.compile(r"(?<!\d)[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?!\d)"), "[AADHAAR]"),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[PAN]"),
    ("phone_in", re.compile(r"(?<![\d.])(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"), "[PHONE]"),
    ("phone_intl", re.compile(r"(?<![\w])\+\d{1,3}[ -]?\d{4,5}[ -]?\d{4,6}(?!\d)"), "[PHONE]"),
    (
        "ip",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        "[IP]",
    ),
]


def _luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        flip = not flip
    return total % 10 == 0


def mask_text_with_stats(text: str, mask_ips: bool = True) -> tuple[str, dict[str, int]]:
    """Mask a string and report how many items of each type were masked."""
    if not text:
        return text, {}

    stats: Counter[str] = Counter()

    for name, pattern, replacement in _PATTERNS:
        if name == "ip" and not mask_ips:
            continue

        def _sub(match: re.Match, _name: str = name, _rep: str = replacement) -> str:
            if _name == "card_luhn":
                digits = re.sub(r"\D", "", match.group(0))
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    return match.group(0)  # not a real card number, leave it
            stats[_name] += 1
            return match.expand(_rep)

        text = pattern.sub(_sub, text)

    return text, dict(stats)


def mask_text(text: str, mask_ips: bool = True) -> str:
    """Mask a string and return only the cleaned text."""
    return mask_text_with_stats(text, mask_ips=mask_ips)[0]


def mask_lines(lines: list[str], mask_ips: bool = True) -> list[str]:
    return [mask_text(line, mask_ips=mask_ips) for line in lines]


def mask_data(obj: Any, mask_ips: bool = True) -> Any:
    """Recursively mask every string inside dicts, lists and tuples.

    Handy for masking a whole incident:  mask_data(incident.to_dict())
    """
    if isinstance(obj, str):
        return mask_text(obj, mask_ips=mask_ips)
    if isinstance(obj, dict):
        return {key: mask_data(value, mask_ips) for key, value in obj.items()}
    if isinstance(obj, list):
        return [mask_data(item, mask_ips) for item in obj]
    if isinstance(obj, tuple):
        return tuple(mask_data(item, mask_ips) for item in obj)
    return obj


# Quick manual test:  python -m services.data_masking
if __name__ == "__main__":
    sample = (
        "Payment failed user=priya.k@example.com card=4111-XXXX-XXXX-1111 "
        "ip=103.21.44.12 token=eyJhbGciOiJIUzI1NiJ9.abc123 password=Secret@123 "
        "call +91 9876543210 card 4242 4242 4242 4242 order_id=ORD-10241"
    )
    masked, found = mask_text_with_stats(sample)
    print("BEFORE:", sample)
    print("AFTER :", masked)
    print("STATS :", found)