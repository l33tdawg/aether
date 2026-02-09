"""
LLM usage tracking with cost calculation.

Thread-safe singleton that accumulates token usage and costs across all LLM
API calls (OpenAI, Gemini, Anthropic). Existing _call_*_api() methods record
usage as a side-effect after each response; return types are unchanged.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class LLMCallRecord:
    """Single LLM API call record."""
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: float
    caller: str


# Pricing per 1M tokens: (input_per_1M, output_per_1M)
MODEL_PRICING: Dict[str, Tuple[float, float]] = {
    # OpenAI GPT-5
    "gpt-5-chat-latest":        (2.00, 8.00),
    "gpt-5":                    (2.00, 8.00),
    "gpt-5-pro":                (5.00, 20.00),
    "gpt-5-mini":               (0.40, 1.60),
    "gpt-5-nano":               (0.10, 0.40),
    "gpt-5-codex":              (2.00, 8.00),
    # OpenAI GPT-5.3
    "gpt-5.3-chat-latest":      (2.50, 10.00),
    "gpt-5.3-mini":             (0.50, 2.00),
    # OpenAI GPT-4 family
    "gpt-4.1-mini":             (0.40, 1.60),
    "gpt-4.1-mini-2025-04-14":  (0.40, 1.60),
    "gpt-4o":                   (2.50, 10.00),
    "gpt-4o-mini":              (0.15, 0.60),
    "gpt-4-turbo":              (10.00, 30.00),
    "gpt-4":                    (30.00, 60.00),
    "gpt-3.5-turbo":            (0.50, 1.50),
    # Google Gemini
    "gemini-3.0-flash":         (0.10, 0.40),
    "gemini-3.0-pro":           (1.25, 5.00),
    "gemini-2.5-flash":         (0.15, 0.60),
    "gemini-2.5-pro":           (1.25, 5.00),
    "gemini-1.5-pro":           (1.25, 5.00),
    "gemini-1.5-flash":         (0.075, 0.30),
    # Anthropic Claude
    "claude-opus-4-6":              (15.00, 75.00),
    "claude-sonnet-4-5-20250929":   (3.00, 15.00),
    "claude-haiku-4-5-20251001":    (0.80, 4.00),
}

# Provider-family fallback pricing (used when no exact/prefix match)
_PROVIDER_FALLBACK: Dict[str, Tuple[float, float]] = {
    "openai":    (2.00, 8.00),
    "gemini":    (0.15, 0.60),
    "anthropic": (3.00, 15.00),
}


def _get_pricing(model: str, provider: str = "") -> Tuple[float, float]:
    """Get (input_per_1M, output_per_1M) pricing for a model.

    Strategy: exact match -> prefix match -> provider-family fallback.
    """
    # Exact match
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]

    # Prefix match (longest prefix first)
    model_lower = model.lower()
    best_match = ""
    best_pricing = None
    for key, pricing in MODEL_PRICING.items():
        if model_lower.startswith(key) and len(key) > len(best_match):
            best_match = key
            best_pricing = pricing
    if best_pricing is not None:
        return best_pricing

    # Provider-family fallback
    provider_lower = provider.lower()
    if provider_lower in _PROVIDER_FALLBACK:
        return _PROVIDER_FALLBACK[provider_lower]

    # Infer provider from model name
    if model_lower.startswith("gpt-") or model_lower.startswith("o1") or model_lower.startswith("o3"):
        return _PROVIDER_FALLBACK["openai"]
    if model_lower.startswith("gemini"):
        return _PROVIDER_FALLBACK["gemini"]
    if model_lower.startswith("claude"):
        return _PROVIDER_FALLBACK["anthropic"]

    return (1.00, 3.00)  # Unknown model fallback


def _calculate_cost(model: str, input_tokens: int, output_tokens: int, provider: str = "") -> float:
    """Calculate cost in USD for a single API call."""
    input_per_1m, output_per_1m = _get_pricing(model, provider)
    return (input_tokens * input_per_1m + output_tokens * output_per_1m) / 1_000_000


class LLMUsageTracker:
    """Thread-safe singleton that accumulates LLM token usage and costs."""

    _instance: Optional["LLMUsageTracker"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "LLMUsageTracker":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (e.g. at start of a new audit run)."""
        with cls._instance_lock:
            cls._instance = cls()

    def __init__(self):
        self._lock = threading.Lock()
        self._records: List[LLMCallRecord] = []
        self._total_calls = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_cost = 0.0
        self._by_provider: Dict[str, Dict[str, float]] = {}
        self._by_model: Dict[str, Dict[str, float]] = {}

    def record(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        caller: str = "",
    ) -> None:
        """Record a single LLM API call."""
        cost = _calculate_cost(model, input_tokens, output_tokens, provider)
        rec = LLMCallRecord(
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            timestamp=time.time(),
            caller=caller,
        )
        with self._lock:
            self._records.append(rec)
            self._total_calls += 1
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            self._total_cost += cost

            # Per-provider aggregation
            prov = self._by_provider.setdefault(
                provider, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
            )
            prov["calls"] += 1
            prov["input_tokens"] += input_tokens
            prov["output_tokens"] += output_tokens
            prov["cost"] += cost

            # Per-model aggregation
            mdl = self._by_model.setdefault(
                model, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
            )
            mdl["calls"] += 1
            mdl["input_tokens"] += input_tokens
            mdl["output_tokens"] += output_tokens
            mdl["cost"] += cost

    # ── Fast properties for dashboard polling ──

    @property
    def total_cost(self) -> float:
        with self._lock:
            return self._total_cost

    @property
    def total_tokens(self) -> int:
        with self._lock:
            return self._total_input_tokens + self._total_output_tokens

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._total_calls

    def snapshot(self) -> Dict:
        """Return a snapshot of current totals for per-job cost delta calculation.

        Call before and after a job to compute cost_delta = after - before.
        """
        with self._lock:
            return {
                "total_cost": self._total_cost,
                "total_calls": self._total_calls,
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
            }

    # ── Full summary for post-audit display ──

    def get_summary(self) -> Dict:
        with self._lock:
            return {
                "total_calls": self._total_calls,
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "total_tokens": self._total_input_tokens + self._total_output_tokens,
                "total_cost_usd": self._total_cost,
                "by_provider": {k: dict(v) for k, v in self._by_provider.items()},
                "by_model": {k: dict(v) for k, v in self._by_model.items()},
            }
