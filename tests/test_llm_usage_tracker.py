"""Tests for LLM usage tracker singleton, thread-safety, pricing, and aggregation."""

import threading
import unittest

from core.llm_usage_tracker import (
    LLMUsageTracker,
    _calculate_cost,
    _get_pricing,
)


class TestLLMUsageTrackerSingleton(unittest.TestCase):

    def setUp(self):
        LLMUsageTracker.reset()

    def test_singleton_instance(self):
        a = LLMUsageTracker.get_instance()
        b = LLMUsageTracker.get_instance()
        self.assertIs(a, b)

    def test_reset_creates_new(self):
        a = LLMUsageTracker.get_instance()
        a.record("openai", "gpt-4o", 100, 50, "test")
        self.assertEqual(a.call_count, 1)

        LLMUsageTracker.reset()
        b = LLMUsageTracker.get_instance()
        self.assertIsNot(a, b)
        self.assertEqual(b.call_count, 0)


class TestLLMUsageTrackerRecord(unittest.TestCase):

    def setUp(self):
        LLMUsageTracker.reset()
        self.tracker = LLMUsageTracker.get_instance()

    def test_record_single_call(self):
        self.tracker.record("openai", "gpt-4o", 1000, 500, "test")
        self.assertEqual(self.tracker.call_count, 1)
        self.assertEqual(self.tracker.total_tokens, 1500)
        self.assertGreater(self.tracker.total_cost, 0)

    def test_record_multiple_providers(self):
        self.tracker.record("openai", "gpt-4o", 1000, 500, "test")
        self.tracker.record("gemini", "gemini-2.5-flash", 2000, 800, "test")
        self.tracker.record("anthropic", "claude-sonnet-4-5-20250929", 1500, 600, "test")

        summary = self.tracker.get_summary()
        self.assertEqual(summary["total_calls"], 3)
        self.assertEqual(len(summary["by_provider"]), 3)
        self.assertIn("openai", summary["by_provider"])
        self.assertIn("gemini", summary["by_provider"])
        self.assertIn("anthropic", summary["by_provider"])

        # Per-provider call counts
        self.assertEqual(summary["by_provider"]["openai"]["calls"], 1)
        self.assertEqual(summary["by_provider"]["gemini"]["calls"], 1)
        self.assertEqual(summary["by_provider"]["anthropic"]["calls"], 1)

    def test_summary_totals(self):
        self.tracker.record("openai", "gpt-4o", 1000, 200, "a")
        self.tracker.record("openai", "gpt-4o", 3000, 800, "b")

        summary = self.tracker.get_summary()
        self.assertEqual(summary["total_calls"], 2)
        self.assertEqual(summary["total_input_tokens"], 4000)
        self.assertEqual(summary["total_output_tokens"], 1000)
        self.assertEqual(summary["total_tokens"], 5000)


class TestLLMUsageTrackerThreadSafety(unittest.TestCase):

    def setUp(self):
        LLMUsageTracker.reset()

    def test_thread_safety(self):
        tracker = LLMUsageTracker.get_instance()
        num_threads = 10
        calls_per_thread = 100
        barrier = threading.Barrier(num_threads)

        def worker():
            barrier.wait()
            for _ in range(calls_per_thread):
                tracker.record("openai", "gpt-4o", 10, 5, "thread_test")

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(tracker.call_count, num_threads * calls_per_thread)
        self.assertEqual(tracker.total_tokens, num_threads * calls_per_thread * 15)


class TestPricing(unittest.TestCase):

    def test_pricing_known_model(self):
        inp, out = _get_pricing("gpt-4o")
        self.assertEqual(inp, 2.50)
        self.assertEqual(out, 10.00)

    def test_pricing_prefix_fallback(self):
        # "gpt-5-chat-latest-2025" should prefix-match "gpt-5-chat-latest"
        inp, out = _get_pricing("gpt-5-chat-latest-2025")
        self.assertEqual(inp, 2.00)
        self.assertEqual(out, 8.00)

    def test_pricing_provider_fallback(self):
        inp, out = _get_pricing("gpt-99-future", provider="openai")
        self.assertEqual(inp, 2.00)
        self.assertEqual(out, 8.00)

    def test_pricing_inferred_provider(self):
        inp, out = _get_pricing("gemini-99-future")
        self.assertEqual(inp, 0.15)
        self.assertEqual(out, 0.60)

    def test_cost_calculation(self):
        # gpt-4o: $2.50/1M input, $10.00/1M output
        cost = _calculate_cost("gpt-4o", 1_000_000, 1_000_000)
        self.assertAlmostEqual(cost, 12.50, places=2)

    def test_cost_small_request(self):
        # 1000 input + 500 output with gpt-4o
        cost = _calculate_cost("gpt-4o", 1000, 500)
        expected = (1000 * 2.50 + 500 * 10.00) / 1_000_000
        self.assertAlmostEqual(cost, expected, places=6)


if __name__ == "__main__":
    unittest.main()
