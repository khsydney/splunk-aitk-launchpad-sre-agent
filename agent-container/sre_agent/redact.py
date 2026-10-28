"""Deterministic redaction applied to EVERYTHING that leaves for the model (tool results, incident text).

TukTukPay logs never carry a PAN (primary account number) by design (BIN + last4 only), but a real payment
estate might, and the reviewers asked for the control to exist in code rather than in a sentence. Rules:
  * 13–19 digit runs that pass the Luhn check -> "[PAN]"
  * e-mail addresses -> "[EMAIL]"
  * bearer/JWT/token-looking strings -> "[TOKEN]"
  * optionally hash BINs (SRE_AGENT_HASH_BIN=1) so card-range analysis still works without revealing the range
"""

from __future__ import annotations

import hashlib
import os
import re

_DIGITS = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TOKEN = re.compile(r"(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._-]{16,}|Splunk\s+[A-Za-z0-9-]{20,})")
_BIN_FIELD = re.compile(r'("payment\.card\.bin"\s*:\s*")(\d{6,8})(")')


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _pan(m: re.Match) -> str:
    digits = re.sub(r"[ -]", "", m.group(0))
    return "[PAN]" if luhn_ok(digits) else m.group(0)


def redact(text: str) -> str:
    if not text:
        return text
    out = _DIGITS.sub(_pan, text)
    out = _EMAIL.sub("[EMAIL]", out)
    out = _TOKEN.sub("[TOKEN]", out)
    if os.getenv("SRE_AGENT_HASH_BIN", "0") == "1":
        out = _BIN_FIELD.sub(lambda m: f'{m.group(1)}bin_{hashlib.sha256(m.group(2).encode()).hexdigest()[:8]}{m.group(3)}', out)
    return out
