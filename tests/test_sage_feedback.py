"""Tests for core.sage_feedback — SAGE feedback loop manager."""

import unittest
from unittest.mock import MagicMock, patch, call

from core.sage_feedback import SageFeedbackManager


class TestRecordFindingOutcome(unittest.TestCase):
    """Tests for recording finding outcomes to SAGE."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.fm = SageFeedbackManager(sage_client=self.mock_client)

    def test_accepted_finding_stored_as_fact(self):
        finding = {
            "vulnerability_type": "reentrancy",
            "severity": "critical",
            "description": "Cross-function reentrancy in withdraw()",
        }
        self.fm.record_finding_outcome(
            finding, "accepted", context={"archetype": "lending_pool"}
        )
        self.mock_client.remember.assert_called_once()
        kw = self.mock_client.remember.call_args[1]
        self.assertEqual(kw["domain"], "audit-lending_pool")
        self.assertEqual(kw["memory_type"], "fact")
        self.assertAlmostEqual(kw["confidence"], 0.90)
        self.assertIn("Confirmed vulnerability", kw["content"])
        self.assertIn("reentrancy", kw["content"])

    def test_rejected_finding_stored_as_fp(self):
        finding = {
            "vulnerability_type": "oracle_manipulation",
            "severity": "high",
            "description": "TWAP oracle can be manipulated",
        }
        self.fm.record_finding_outcome(
            finding, "rejected",
            context={"archetype": "dex_amm", "reason": "oracle uses 30-min TWAP"},
        )
        self.mock_client.remember.assert_called_once()
        kw = self.mock_client.remember.call_args[1]
        self.assertEqual(kw["domain"], "false-positives")
        self.assertEqual(kw["memory_type"], "observation")
        self.assertIn("False positive", kw["content"])
        self.assertIn("30-min TWAP", kw["content"])

    def test_duplicate_finding_not_stored(self):
        finding = {"vulnerability_type": "x", "severity": "medium"}
        self.fm.record_finding_outcome(finding, "duplicate")
        self.mock_client.remember.assert_not_called()

    def test_sage_failure_does_not_raise(self):
        self.mock_client.remember.side_effect = Exception("SAGE down")
        finding = {"vulnerability_type": "x", "severity": "high"}
        # Should not raise
        self.fm.record_finding_outcome(finding, "accepted")


class TestSyncDetectorAccuracy(unittest.TestCase):
    """Tests for syncing detector accuracy to SAGE."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.remember.return_value = {}
        self.mock_client.reflect.return_value = {}
        self.fm = SageFeedbackManager(sage_client=self.mock_client)

    def _make_mock_tracker(self, detector_stats):
        """Create a mock AccuracyTracker with given stats."""
        from core.accuracy_tracker import DetectorStats
        mock_tracker = MagicMock()
        stats_map = {}
        for name, total, precision in detector_stats:
            ds = DetectorStats(detector_name=name)
            ds.total = total
            ds.precision = precision
            ds.accepted = int(total * precision)
            ds.rejected = total - ds.accepted
            stats_map[name] = ds
        mock_tracker.get_detector_accuracy.return_value = stats_map
        return mock_tracker

    def test_high_accuracy_detector_generates_do(self):
        tracker = self._make_mock_tracker([
            ("reentrancy", 20, 0.90),
        ])
        result = self.fm.sync_detector_accuracy(accuracy_tracker=tracker)
        self.assertEqual(result["dos"], 1)
        self.assertEqual(result["donts"], 0)
        # Should remember as fact
        self.mock_client.remember.assert_called_once()
        kw = self.mock_client.remember.call_args[1]
        self.assertIn("high-accuracy", kw["tags"])

    def test_low_accuracy_detector_generates_dont(self):
        tracker = self._make_mock_tracker([
            ("gas_analyzer", 15, 0.30),
        ])
        result = self.fm.sync_detector_accuracy(accuracy_tracker=tracker)
        self.assertEqual(result["dos"], 0)
        self.assertEqual(result["donts"], 1)
        kw = self.mock_client.remember.call_args[1]
        self.assertIn("low-accuracy", kw["tags"])

    def test_mixed_detectors(self):
        tracker = self._make_mock_tracker([
            ("reentrancy", 20, 0.90),
            ("gas_analyzer", 15, 0.30),
            ("new_detector", 5, 0.60),  # too few samples, ignored
        ])
        result = self.fm.sync_detector_accuracy(accuracy_tracker=tracker)
        self.assertEqual(result["dos"], 1)
        self.assertEqual(result["donts"], 1)
        # Should call reflect with both
        self.mock_client.reflect.assert_called_once()
        reflect_kw = self.mock_client.reflect.call_args[1]
        self.assertEqual(len(reflect_kw["dos"]), 1)
        self.assertEqual(len(reflect_kw["donts"]), 1)

    def test_no_significant_detectors(self):
        tracker = self._make_mock_tracker([
            ("new_one", 3, 0.50),  # too few samples
        ])
        result = self.fm.sync_detector_accuracy(accuracy_tracker=tracker)
        self.assertEqual(result["dos"], 0)
        self.assertEqual(result["donts"], 0)
        self.mock_client.reflect.assert_not_called()


class TestRecordAuditCompletion(unittest.TestCase):
    """Tests for audit completion recording."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.remember.return_value = {}
        self.fm = SageFeedbackManager(sage_client=self.mock_client)

    def test_stores_audit_summary(self):
        self.fm.record_audit_completion(
            contract_name="Vault.sol",
            archetype="vault_erc4626",
            findings_summary={"critical": 1, "high": 3, "medium": 5},
        )
        self.mock_client.remember.assert_called_once()
        kw = self.mock_client.remember.call_args[1]
        self.assertEqual(kw["domain"], "audit-history")
        self.assertIn("Vault.sol", kw["content"])
        self.assertIn("vault_erc4626", kw["content"])
        self.assertIn("9 findings", kw["content"])

    def test_includes_fp_rate(self):
        self.fm.record_audit_completion(
            contract_name="Pool.sol",
            archetype="lending_pool",
            findings_summary={"high": 2},
            validation_stats={"filtered": 8, "total_raw": 10},
        )
        kw = self.mock_client.remember.call_args[1]
        self.assertIn("FP rate", kw["content"])

    def test_sage_failure_does_not_raise(self):
        self.mock_client.remember.side_effect = Exception("down")
        self.fm.record_audit_completion("x", "y", {"medium": 1})


class TestGetHistoricalFPPatterns(unittest.TestCase):
    """Tests for recalling FP patterns."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.fm = SageFeedbackManager(sage_client=self.mock_client)

    def test_returns_content_list(self):
        self.mock_client.recall.return_value = [
            {"content": "FP pattern A"},
            {"content": "FP pattern B"},
        ]
        result = self.fm.get_historical_fp_patterns("lending_pool")
        self.assertEqual(len(result), 2)
        self.assertIn("FP pattern A", result)

    def test_empty_when_sage_down(self):
        self.mock_client.recall.side_effect = Exception("down")
        result = self.fm.get_historical_fp_patterns("lending_pool")
        self.assertEqual(result, [])


class TestGetDetectorRecommendations(unittest.TestCase):
    """Tests for detector boost/suppress recommendations."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.fm = SageFeedbackManager(sage_client=self.mock_client)

    def test_returns_boost_and_suppress(self):
        self.mock_client.recall.return_value = [
            {"content": "high-acc detector", "tags": ["high-accuracy", "reentrancy"]},
            {"content": "low-acc detector", "tags": ["low-accuracy", "gas"]},
        ]
        result = self.fm.get_detector_recommendations("vault_erc4626")
        self.assertEqual(len(result["boost"]), 1)
        self.assertEqual(len(result["suppress"]), 1)

    def test_empty_when_sage_down(self):
        self.mock_client.recall.side_effect = Exception("down")
        result = self.fm.get_detector_recommendations("dex_amm")
        self.assertEqual(result, {"boost": [], "suppress": []})


class TestSageFeedbackIntegration(unittest.TestCase):
    """Integration test: full feedback loop flow."""

    def test_full_cycle(self):
        """Simulate: audit → record outcomes → sync accuracy → recall."""
        mock_client = MagicMock()
        mock_client.remember.return_value = {"status": "proposed"}
        mock_client.recall.return_value = [
            {"content": "Previously confirmed reentrancy in lending pools"}
        ]
        mock_client.reflect.return_value = {"status": "ok"}

        fm = SageFeedbackManager(sage_client=mock_client)

        # 1. Record finding outcomes
        fm.record_finding_outcome(
            {"vulnerability_type": "reentrancy", "severity": "critical", "description": "..."},
            "accepted",
            context={"archetype": "lending_pool"},
        )
        fm.record_finding_outcome(
            {"vulnerability_type": "gas_optimization", "severity": "low", "description": "..."},
            "rejected",
            context={"archetype": "lending_pool", "reason": "informational only"},
        )

        # 2. Record audit completion
        fm.record_audit_completion(
            "Pool.sol", "lending_pool",
            {"critical": 1, "low": 0},
            {"filtered": 5, "total_raw": 6},
        )

        # 3. Recall FP patterns for next audit
        fps = fm.get_historical_fp_patterns("lending_pool")
        self.assertEqual(len(fps), 1)

        # Verify total remember calls: 2 outcomes + 1 completion = 3
        self.assertEqual(mock_client.remember.call_count, 3)
        self.assertEqual(mock_client.recall.call_count, 1)


if __name__ == "__main__":
    unittest.main()
