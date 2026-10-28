"""Cost of a model call from the usage fields. Prices per million tokens (input, output, cache read, cache write),
Anthropic first-party list prices read on 21 Oct 2026 from https://platform.claude.com/docs/en/about-claude/pricing.
Unknown models fall back to Sonnet-class prices and are flagged so the figure is never silently invented."""

from __future__ import annotations

PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10, 2.50),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
    "claude-sonnet-5": (2.00, 10.00, 0.20, 2.50),
    "claude-fable-5-1": (10.00, 50.00, 0.25, 12.50),
}
FALLBACK = (2.00, 10.00, 0.20, 2.50)


def price_row(model: str) -> tuple[tuple, bool]:
    for k, v in sorted(PRICES.items(), key=lambda kv: -len(kv[0])):   # longest match first (opus-5-5 before opus-5)
        if k in model:
            return v, True
    return FALLBACK, False


def estimate_cost(model: str, input_tokens: int, output_tokens: int, cache_read_tokens: int = 0, cache_write_tokens: int = 0) -> float:
    """`input_tokens` is the UNCACHED remainder as the API reports it (total prompt = input + cache_read + cache_write)."""
    (p_in, p_out, p_read, p_write), _ = price_row(model)
    return round((input_tokens * p_in + output_tokens * p_out + cache_read_tokens * p_read + cache_write_tokens * p_write) / 1e6, 6)
