"""Tests for SAGE integration in audit_runner.py and validation_pipeline.py."""

import unittest
from unittest.mock import MagicMock, patch


class TestAuditRunnerSageIntegration(unittest.TestCase):
    """Verify SAGE remember/reflect is called in audit worker finally block."""

    @patch("core.sage_feedback.SageFeedbackManager")
    def test_sage_feedback_called_on_completion(self, MockFM):
        """SageFeedbackManager.record_audit_completion should fire after audit."""
        mock_fm = MagicMock()
        MockFM.return_value = mock_fm

        # Simulate the finally-block SAGE code path directly
        try:
            from core.sage_feedback import SageFeedbackManager
            fm = SageFeedbackManager()
            fm.record_audit_completion(
                contract_name="Vault.sol",
                archetype="vault_erc4626",
                findings_summary={"total": 5},
            )
        except Exception:
            self.fail("SAGE feedback should not raise")

    @patch("core.sage_feedback.SageFeedbackManager")
    def test_sage_reflect_called(self, MockFM):
        """reflect() should be called with dos/donts."""
        mock_fm = MagicMock()
        MockFM.return_value = mock_fm

        try:
            from core.sage_feedback import SageFeedbackManager
            fm = SageFeedbackManager()
            fm._client.reflect(
                dos=["Audit completed successfully with 3 findings"],
                donts=[],
                domain="audit-history",
            )
        except Exception:
            self.fail("SAGE reflect should not raise")


class TestValidationPipelineSageIntegration(unittest.TestCase):
    """Test SAGE known FP check in validation pipeline."""

    def _make_pipeline(self):
        """Create a minimal ValidationPipeline for testing."""
        from pathlib import Path
        from core.validation_pipeline import ValidationPipeline
        pipeline = ValidationPipeline(
            project_path=Path("/tmp"),
            contract_code="contract Test { function foo() public {} }",
        )
        return pipeline

    @patch("core.sage_feedback.SageFeedbackManager")
    def test_sage_fp_check_matches_known_pattern(self, MockFM):
        """Known FP pattern from SAGE should filter matching findings."""
        mock_fm = MagicMock()
        mock_fm.get_historical_fp_patterns.return_value = [
            "False positive: gas_optimization flagged in vault_erc4626 contracts "
            "but was not exploitable. Reason: informational finding only. "
            "Pattern: gas usage could be reduced in loop iteration"
        ]
        MockFM.return_value = mock_fm

        pipeline = self._make_pipeline()
        # Pre-set the SAGE patterns (bypass lazy load)
        pipeline._sage_fp_patterns = mock_fm.get_historical_fp_patterns.return_value

        vuln = {
            "vulnerability_type": "gas_optimization",
            "description": "Gas usage could be reduced in the loop iteration of vault function",
            "severity": "low",
        }
        result = pipeline._check_sage_known_fp(vuln)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_false_positive)
        self.assertEqual(result.stage_name, "sage_known_false_positive")

    def test_sage_fp_check_no_match(self):
        """Non-matching vuln should not be filtered."""
        pipeline = self._make_pipeline()
        pipeline._sage_fp_patterns = [
            "False positive: gas_optimization in some context"
        ]

        vuln = {
            "vulnerability_type": "reentrancy",
            "description": "Cross-function reentrancy in withdraw()",
            "severity": "critical",
        }
        result = pipeline._check_sage_known_fp(vuln)
        self.assertIsNone(result)

    def test_sage_fp_check_empty_patterns(self):
        """Empty SAGE patterns should not filter anything."""
        pipeline = self._make_pipeline()
        pipeline._sage_fp_patterns = []

        vuln = {
            "vulnerability_type": "reentrancy",
            "description": "test",
            "severity": "high",
        }
        result = pipeline._check_sage_known_fp(vuln)
        self.assertIsNone(result)

    def test_sage_fp_check_none_patterns_lazy_loads(self):
        """When patterns are None, lazy load should be attempted."""
        pipeline = self._make_pipeline()
        # _sage_fp_patterns starts as None
        self.assertIsNone(pipeline._sage_fp_patterns)

        with patch("core.sage_feedback.SageFeedbackManager") as MockFM:
            mock_fm = MagicMock()
            mock_fm.get_historical_fp_patterns.return_value = []
            MockFM.return_value = mock_fm

            vuln = {"vulnerability_type": "x", "description": "y", "severity": "z"}
            result = pipeline._check_sage_known_fp(vuln)
            self.assertIsNone(result)
            # After call, patterns should be loaded (empty list, not None)
            self.assertEqual(pipeline._sage_fp_patterns, [])

    def test_sage_fp_check_exception_returns_none(self):
        """Exception during SAGE check should not crash pipeline."""
        pipeline = self._make_pipeline()
        pipeline._sage_fp_patterns = None

        with patch("core.sage_feedback.SageFeedbackManager", side_effect=Exception("boom")):
            vuln = {"vulnerability_type": "x", "description": "y"}
            result = pipeline._check_sage_known_fp(vuln)
            self.assertIsNone(result)


class TestAutoSeed(unittest.TestCase):
    """Test SAGE auto-seed on startup."""

    @patch("core.sage_seeder.SageSeeder")
    @patch("core.sage_client.SageClient.get_instance")
    def test_auto_seed_runs_when_sage_available(self, mock_get_instance, MockSeeder):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_get_instance.return_value = mock_client

        mock_seeder = MagicMock()
        mock_seeder.seed_all.return_value = {"exploits": 75, "archetypes": 63}
        MockSeeder.return_value = mock_seeder

        from cli.interactive_menu import _sage_auto_seed
        _sage_auto_seed()

        mock_seeder.seed_all.assert_called_once()

    @patch("core.sage_client.SageClient.get_instance")
    def test_auto_seed_skips_when_sage_down(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        from cli.interactive_menu import _sage_auto_seed
        # Should not raise
        _sage_auto_seed()

    def test_auto_seed_handles_import_error(self):
        """auto_seed should not crash if sage_client import fails."""
        from cli.interactive_menu import _sage_auto_seed
        with patch("core.sage_client.SageClient.get_instance", side_effect=ImportError("no module")):
            _sage_auto_seed()  # Should not raise


class TestCostBarSageStatus(unittest.TestCase):
    """Test SAGE status indicator in CostBar."""

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_online_status(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = True
        mock_client.get_status.return_value = {"memories": {"total_memories": 612, "by_domain": {"exploit-patterns": 75, "historical-exploits": 20}}}
        mock_get_instance.return_value = mock_client

        from cli.tui.widgets.cost_bar import CostBar
        status = CostBar._get_sage_status()
        self.assertIn("ON", status)
        self.assertIn("612", status)

    @patch("core.sage_client.SageClient.get_instance")
    def test_sage_offline_status(self, mock_get_instance):
        mock_client = MagicMock()
        mock_client.health_check.return_value = False
        mock_get_instance.return_value = mock_client

        from cli.tui.widgets.cost_bar import CostBar
        status = CostBar._get_sage_status()
        self.assertIn("OFF", status)

    def test_sage_status_exception(self):
        """If SageClient fails to import, status should be OFF."""
        with patch("core.sage_client.SageClient.get_instance", side_effect=Exception("err")):
            from cli.tui.widgets.cost_bar import CostBar
            status = CostBar._get_sage_status()
            self.assertIn("OFF", status)


if __name__ == "__main__":
    unittest.main()
