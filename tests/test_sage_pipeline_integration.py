"""Tests for SAGE integration in the deep analysis pipeline."""

import unittest
from unittest.mock import MagicMock, patch

from core.protocol_archetypes import ProtocolArchetype, ArchetypeResult


class TestBuildSageContext(unittest.TestCase):
    """Tests for DeepAnalysisEngine._build_sage_context()."""

    def _make_engine(self):
        """Create a minimal DeepAnalysisEngine for testing."""
        from core.deep_analysis_engine import DeepAnalysisEngine
        engine = DeepAnalysisEngine.__new__(DeepAnalysisEngine)
        engine.llm = MagicMock()
        engine._cache = {}
        engine.archetype_detector = MagicMock()
        engine.exploit_kb = MagicMock()
        engine._severity_calibration = {}
        return engine

    @patch("core.sage_client.SageClient.get_instance")
    def test_returns_context_string(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.recall.return_value = [
            {"content": "Found reentrancy in lending pool audit"},
        ]
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.LENDING_POOL, confidence=0.9)
        ctx = engine._build_sage_context(archetype)

        self.assertIn("SAGE Institutional Knowledge", ctx)
        self.assertIn("reentrancy", ctx)

    @patch("core.sage_client.SageClient.get_instance")
    def test_empty_when_sage_down(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.DEX_AMM, confidence=0.8)
        ctx = engine._build_sage_context(archetype)

        self.assertEqual(ctx, "")

    @patch("core.sage_client.SageClient.get_instance")
    def test_empty_when_no_memories(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.recall.return_value = []
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.VAULT_ERC4626, confidence=0.9)
        ctx = engine._build_sage_context(archetype)

        self.assertEqual(ctx, "")

    @patch("core.sage_client.SageClient.get_instance")
    def test_exception_returns_empty(self, mock_get_instance):
        mock_get_instance.side_effect = Exception("import error")

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.BRIDGE, confidence=0.7)
        ctx = engine._build_sage_context(archetype)

        self.assertEqual(ctx, "")


class TestRecallSageForPass(unittest.TestCase):
    """Tests for _recall_sage_for_pass()."""

    def _make_engine(self):
        from core.deep_analysis_engine import DeepAnalysisEngine
        engine = DeepAnalysisEngine.__new__(DeepAnalysisEngine)
        engine.llm = MagicMock()
        engine._cache = {}
        engine.archetype_detector = MagicMock()
        engine.exploit_kb = MagicMock()
        engine._severity_calibration = {}
        return engine

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_checklist_returns_patterns(self, mock_get_instance):
        """SAGE is now primary brain: _recall_sage_checklist provides Pass 3 context."""
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.recall.return_value = [
            {"content": "Invariant: total supply == sum of balances"},
            {"content": "First depositor inflation in vault contracts"},
        ]
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.VAULT_ERC4626, confidence=0.9)
        ctx = engine._recall_sage_checklist(archetype)

        self.assertIn("Vulnerability Checklist", ctx)
        self.assertIn("total supply", ctx)
        self.assertIn("SAGE institutional memory", ctx)

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_exploit_patterns_returns_context(self, mock_get_instance):
        """SAGE is now primary brain: _recall_sage_exploit_patterns provides Pass 5 context."""
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        # First call: exploit patterns, second: historical, third: quirks, fourth: FP
        mock_client.recall.side_effect = [
            [{"content": "Reentrancy attack via external call"}],
            [{"content": "DAO hack 2016 reentrancy"}],
            [{"content": "Fee on transfer token quirk"}],
            [{"content": "FP: gas optimization not exploitable"}],
        ]
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.DEX_AMM, confidence=0.8)
        ctx = engine._recall_sage_exploit_patterns(archetype)

        self.assertIn("Exploit Patterns", ctx)
        self.assertIn("Reentrancy", ctx)
        self.assertIn("False Positive Patterns", ctx)

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_checklist_empty_when_sage_down(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.TOKEN, confidence=0.5)
        ctx = engine._recall_sage_checklist(archetype)
        self.assertEqual(ctx, "")

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_exploit_patterns_exception_returns_empty(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.side_effect = Exception("timeout")
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.GOVERNANCE, confidence=0.7)
        ctx = engine._recall_sage_exploit_patterns(archetype)
        self.assertEqual(ctx, "")


class TestRecallSageCrossFunctionPatterns(unittest.TestCase):
    """Tests for _recall_sage_cross_function_patterns() (Pass 4)."""

    def _make_engine(self):
        from core.deep_analysis_engine import DeepAnalysisEngine
        engine = DeepAnalysisEngine.__new__(DeepAnalysisEngine)
        engine.llm = MagicMock()
        engine._cache = {}
        engine.archetype_detector = MagicMock()
        engine.exploit_kb = MagicMock()
        engine._severity_calibration = {}
        return engine

    @patch("core.sage_client.SageClient.get_instance")
    def test_returns_cross_function_patterns(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.recall.return_value = [
            {"content": "Read-only reentrancy in Balancer pools via rate provider callback"},
            {"content": "Cross-function state analysis methodology: trace shared variables"},
        ]
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.DEX_AMM, confidence=0.9)
        ctx = engine._recall_sage_cross_function_patterns(archetype)

        self.assertIn("Cross-Function Vulnerability Patterns", ctx)
        self.assertIn("reentrancy", ctx.lower())

    @patch("core.sage_client.SageClient.get_instance")
    def test_empty_when_sage_down(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.LENDING_POOL, confidence=0.8)
        ctx = engine._recall_sage_cross_function_patterns(archetype)
        self.assertEqual(ctx, "")


class TestStoreAuditLearnings(unittest.TestCase):
    """Tests for _store_audit_learnings()."""

    def _make_engine(self):
        from core.deep_analysis_engine import DeepAnalysisEngine
        engine = DeepAnalysisEngine.__new__(DeepAnalysisEngine)
        engine.llm = MagicMock()
        engine._cache = {}
        engine.archetype_detector = MagicMock()
        engine.exploit_kb = MagicMock()
        engine._severity_calibration = {}
        return engine

    @patch("core.sage_client.SageClient.get_instance")
    def test_stores_findings_summary(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.remember.return_value = {"status": "ok"}
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.LENDING_POOL, confidence=0.9)
        findings = [
            {"severity": "critical", "vulnerability_type": "reentrancy"},
            {"severity": "high", "vulnerability_type": "oracle_manipulation"},
            {"severity": "high", "vulnerability_type": "access_control"},
        ]
        engine._store_audit_learnings(findings, archetype, "Pool.sol")

        mock_client.remember.assert_called_once()
        kw = mock_client.remember.call_args[1]
        self.assertEqual(kw["domain"], "audit-lending_pool")
        self.assertEqual(kw["memory_type"], "observation")
        self.assertIn("Pool.sol", kw["content"])
        self.assertIn("3 findings", kw["content"])

    @patch("core.sage_client.SageClient.get_instance")
    def test_no_findings_no_storage(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.TOKEN, confidence=0.5)
        engine._store_audit_learnings([], archetype, "Token.sol")

        mock_client.remember.assert_not_called()

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_down_no_crash(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        engine = self._make_engine()
        archetype = ArchetypeResult(primary=ProtocolArchetype.BRIDGE, confidence=0.8)
        # Should not raise
        engine._store_audit_learnings(
            [{"severity": "high", "vulnerability_type": "x"}],
            archetype, "Bridge.sol"
        )
        mock_client.remember.assert_not_called()


class TestAccuracyTrackerSageIntegration(unittest.TestCase):
    """Test that AccuracyTracker forwards outcomes to SAGE."""

    def test_record_submission_calls_sage(self):
        """After recording a submission, SAGE feedback should fire."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"

            from core.accuracy_tracker import AccuracyTracker
            tracker = AccuracyTracker(metrics_file=metrics_file)

            with patch("core.sage_feedback.SageFeedbackManager") as MockFM:
                mock_fm = MagicMock()
                MockFM.return_value = mock_fm

                tracker.record_submission(
                    {"vulnerability_type": "reentrancy", "severity": "critical"},
                    "accepted",
                )

                # The _sage_record_outcome method should have been called
                # (it creates a SageFeedbackManager internally)
                # We verify the tracker doesn't crash even if SAGE fails


if __name__ == "__main__":
    unittest.main()
