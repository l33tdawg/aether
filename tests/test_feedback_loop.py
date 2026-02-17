#!/usr/bin/env python3
"""
Tests for ML Feedback Loop — per-detector accuracy tracking, weight
computation, severity calibration, and integration with the detector
and deep analysis engine.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.accuracy_tracker import AccuracyTracker, DetectorStats


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


@pytest.fixture
def tracker(temp_dir):
    return AccuracyTracker(Path(temp_dir) / "metrics.json")


def _vuln(vuln_type="reentrancy", severity="high", detector=None, confidence=0.8):
    v = {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "confidence": confidence,
        "contract_name": "Test.sol",
    }
    if detector:
        v["detector"] = detector
    return v


# ---------------------------------------------------------------------------
# DetectorStats dataclass
# ---------------------------------------------------------------------------

class TestDetectorStats:

    def test_defaults(self):
        ds = DetectorStats(detector_name="reentrancy")
        assert ds.total == 0
        assert ds.total_findings == 0
        assert ds.accepted == 0
        assert ds.precision == 0.0
        assert ds.weight == 1.0

    def test_custom_values(self):
        ds = DetectorStats(detector_name="overflow", total=10, accepted=8, accuracy=0.8, weight=1.2)
        assert ds.accuracy == 0.8
        assert ds.weight == 1.2


# ---------------------------------------------------------------------------
# record_outcome
# ---------------------------------------------------------------------------

class TestRecordOutcome:

    def test_records_detector_field(self, tracker):
        tracker.record_outcome(_vuln(), "accepted", detector="reentrancy")
        sub = tracker.metrics["submissions"][-1]
        assert sub["detector"] == "reentrancy"
        assert sub["outcome"] == "accepted"

    def test_records_bounty(self, tracker):
        tracker.record_outcome(_vuln(), "accepted", detector="overflow", bounty_amount=5000.0)
        sub = tracker.metrics["submissions"][-1]
        assert sub["bounty_amount"] == 5000.0

    def test_falls_back_to_vuln_type(self, tracker):
        # When detector is not passed, record_outcome defaults to "unknown"
        # but record_submission picks up from the vulnerability dict's detector field
        tracker.record_outcome(_vuln(vuln_type="flash_loan"), "rejected", detector="flash_loan")
        sub = tracker.metrics["submissions"][-1]
        assert sub["detector"] == "flash_loan"

    def test_persists_to_disk(self, tracker):
        tracker.record_outcome(_vuln(), "accepted", detector="test_det")
        # Reload from disk
        tracker2 = AccuracyTracker(tracker.metrics_file)
        assert len(tracker2.metrics["submissions"]) == 1
        assert tracker2.metrics["submissions"][0]["detector"] == "test_det"


# ---------------------------------------------------------------------------
# get_detector_accuracy / get_detector_weights
# ---------------------------------------------------------------------------

class TestDetectorAccuracy:

    def _seed(self, tracker, det, outcomes):
        for o in outcomes:
            tracker.record_outcome(_vuln(detector=det), o, detector=det)

    def test_empty_returns_empty(self, tracker):
        assert tracker.get_detector_accuracy() == {}
        assert tracker.get_detector_weights() == {}

    def test_single_detector(self, tracker):
        self._seed(tracker, "reent", ["accepted", "accepted", "rejected"])
        stats = tracker.get_detector_accuracy()
        assert "reent" in stats
        ds = stats["reent"]
        assert ds.total == 3
        assert ds.accepted == 2
        assert ds.rejected == 1
        assert abs(ds.accuracy - 2 / 3) < 1e-9

    def test_multiple_detectors(self, tracker):
        # Need >= 20 samples for calibration to activate
        self._seed(tracker, "det_a", ["accepted"] * 20)
        self._seed(tracker, "det_b", ["rejected"] * 20)
        weights = tracker.get_detector_weights()
        assert weights["det_a"] > 1.0  # boosted
        assert weights["det_b"] < 1.0  # penalized

    def test_insufficient_data_stays_at_one(self, tracker):
        self._seed(tracker, "det_c", ["accepted", "rejected"])  # only 2
        weights = tracker.get_detector_weights()
        assert weights["det_c"] == 1.0

    def test_under_threshold_stays_at_one(self, tracker):
        # Even with 19 items (< 20 threshold), weight stays at 1.0
        self._seed(tracker, "almost", ["accepted"] * 19)
        weights = tracker.get_detector_weights()
        assert weights["almost"] == 1.0

    def test_perfect_precision_weight(self, tracker):
        # 20 accepted, 0 rejected -> precision = 1.0 -> weight = 1.5
        self._seed(tracker, "perfect", ["accepted"] * 20)
        weights = tracker.get_detector_weights()
        assert abs(weights["perfect"] - 1.5) < 1e-9

    def test_zero_precision_weight(self, tracker):
        # 0 accepted, 20 rejected -> precision = 0.0 -> weight = 0.5
        self._seed(tracker, "bad", ["rejected"] * 20)
        weights = tracker.get_detector_weights()
        assert abs(weights["bad"] - 0.5) < 1e-9

    def test_mid_range_stays_one(self, tracker):
        # 50% precision -> between 0.33 and 0.66 -> weight = 1.0
        self._seed(tracker, "mid", ["accepted", "rejected"] * 10)
        weights = tracker.get_detector_weights()
        assert weights["mid"] == 1.0

    def test_duplicate_counted(self, tracker):
        self._seed(tracker, "dup_det", ["duplicate", "accepted", "accepted"])
        stats = tracker.get_detector_accuracy()
        ds = stats["dup_det"]
        assert ds.duplicate == 1
        assert ds.total == 3


# ---------------------------------------------------------------------------
# get_severity_calibration
# ---------------------------------------------------------------------------

class TestSeverityCalibration:

    def test_empty(self, tracker):
        assert tracker.get_severity_calibration() == {}

    def test_single_severity(self, tracker):
        tracker.record_outcome(_vuln(severity="high"), "accepted")
        tracker.record_outcome(_vuln(severity="high"), "rejected")
        cal = tracker.get_severity_calibration()
        assert abs(cal["high"] - 0.5) < 1e-9

    def test_multiple_severities(self, tracker):
        tracker.record_outcome(_vuln(severity="critical"), "accepted")
        tracker.record_outcome(_vuln(severity="low"), "rejected")
        cal = tracker.get_severity_calibration()
        assert cal["critical"] == 1.0
        assert cal["low"] == 0.0


# ---------------------------------------------------------------------------
# Integration: EnhancedVulnerabilityDetector weight application
# ---------------------------------------------------------------------------

class TestDetectorWeightIntegration:

    def test_weight_applied_to_vuln(self):
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch

        detector = EnhancedVulnerabilityDetector()
        # Manually inject weights to avoid file I/O dependency
        detector._detector_weights = {"reentrancy": 1.3, "overflow": 0.5}

        vuln_r = VulnerabilityMatch(
            vulnerability_type="reentrancy",
            severity="high",
            confidence=0.8,
            line_number=10,
            description="test",
            code_snippet="",
            category="reentrancy",
        )
        detector._apply_detector_weight(vuln_r)
        assert abs(vuln_r.confidence - min(1.0, 0.8 * 1.3)) < 1e-9

        vuln_o = VulnerabilityMatch(
            vulnerability_type="overflow",
            severity="medium",
            confidence=0.8,
            line_number=20,
            description="test",
            code_snippet="",
            category="overflow",
        )
        detector._apply_detector_weight(vuln_o)
        assert abs(vuln_o.confidence - 0.8 * 0.5) < 1e-9

    def test_no_weights_no_change(self):
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch

        detector = EnhancedVulnerabilityDetector()
        detector._detector_weights = {}
        vuln = VulnerabilityMatch(
            vulnerability_type="test",
            severity="low",
            confidence=0.75,
            line_number=1,
            description="",
            code_snippet="",
        )
        detector._apply_detector_weight(vuln)
        assert vuln.confidence == 0.75

    def test_confidence_clamped_at_one(self):
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch

        detector = EnhancedVulnerabilityDetector()
        detector._detector_weights = {"test": 2.0}
        vuln = VulnerabilityMatch(
            vulnerability_type="test",
            severity="high",
            confidence=0.9,
            line_number=1,
            description="",
            code_snippet="",
        )
        detector._apply_detector_weight(vuln)
        assert vuln.confidence == 1.0

    def test_confidence_clamped_at_floor(self):
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch

        detector = EnhancedVulnerabilityDetector()
        detector._detector_weights = {"test": 0.0}
        vuln = VulnerabilityMatch(
            vulnerability_type="test",
            severity="high",
            confidence=0.5,
            line_number=1,
            description="",
            code_snippet="",
        )
        detector._apply_detector_weight(vuln)
        # Floor is 0.05 to avoid completely silencing any detector
        assert vuln.confidence == 0.05


# ---------------------------------------------------------------------------
# Integration: DeepAnalysisEngine severity calibration
# ---------------------------------------------------------------------------

class TestDeepAnalysisSeverityCalibration:

    def _make_engine(self, calibration=None):
        from core.deep_analysis_engine import DeepAnalysisEngine
        mock_llm = MagicMock()
        engine = DeepAnalysisEngine(mock_llm)
        if calibration is not None:
            engine._severity_calibration = calibration
        return engine

    def test_low_acceptance_penalizes(self):
        engine = self._make_engine({"high": 0.2})
        finding = {"severity": "high", "confidence": 0.8}
        engine._calibrate_finding_severity(finding)
        # 0.8 * (0.6 + 0.2) = 0.64
        assert abs(finding["confidence"] - 0.64) < 1e-9

    def test_high_acceptance_boosts(self):
        engine = self._make_engine({"critical": 0.9})
        finding = {"severity": "critical", "confidence": 0.7}
        engine._calibrate_finding_severity(finding)
        # 0.7 * (1.0 + (0.9 - 0.7) * 0.5) = 0.7 * 1.1 = 0.77
        assert abs(finding["confidence"] - 0.77) < 1e-9

    def test_mid_acceptance_no_change(self):
        engine = self._make_engine({"medium": 0.55})
        finding = {"severity": "medium", "confidence": 0.6}
        engine._calibrate_finding_severity(finding)
        assert finding["confidence"] == 0.6

    def test_empty_calibration_no_change(self):
        engine = self._make_engine({})
        finding = {"severity": "high", "confidence": 0.8}
        engine._calibrate_finding_severity(finding)
        assert finding["confidence"] == 0.8

    def test_unknown_severity_no_change(self):
        engine = self._make_engine({"high": 0.2})
        finding = {"severity": "exotic", "confidence": 0.8}
        engine._calibrate_finding_severity(finding)
        assert finding["confidence"] == 0.8

    def test_confidence_floor(self):
        engine = self._make_engine({"low": 0.0})
        finding = {"severity": "low", "confidence": 0.1}
        engine._calibrate_finding_severity(finding)
        # max(0.1, 0.1 * 0.6) = max(0.1, 0.06) = 0.1
        assert finding["confidence"] == 0.1

    def test_confidence_ceiling(self):
        engine = self._make_engine({"critical": 1.0})
        finding = {"severity": "critical", "confidence": 0.95}
        engine._calibrate_finding_severity(finding)
        # min(1.0, 0.95 * (1.0 + 0.15)) = min(1.0, 1.0925) = 1.0
        assert finding["confidence"] == 1.0


# ---------------------------------------------------------------------------
# Settings screen accuracy dashboard (smoke test)
# ---------------------------------------------------------------------------

class TestAccuracyDashboardSmoke:

    def test_menu_option_present(self):
        from cli.tui.screens.settings import _MENU_OPTIONS
        option_ids = [opt[0] for opt in _MENU_OPTIONS]
        assert "accuracy" in option_ids

    def test_show_accuracy_dashboard_no_crash(self):
        """Ensure _show_accuracy_dashboard runs without error."""
        from cli.tui.screens.settings import SettingsScreen

        screen = SettingsScreen()
        # The method reads from the detail Static widget, so we mock query_one
        mock_static = MagicMock()
        screen.query_one = MagicMock(return_value=mock_static)

        # Patch AccuracyTracker at the import source (lazy import inside the method)
        with patch("core.accuracy_tracker.AccuracyTracker") as MockTracker:
            instance = MockTracker.return_value
            instance.get_accuracy_stats.return_value = {
                "total_submissions": 0, "accepted": 0, "rejected": 0,
                "accuracy_percentage": "N/A",
            }
            instance.get_detector_accuracy.return_value = {}
            instance.get_bounty_stats.return_value = {"bounty_count": 0}
            instance.get_severity_calibration.return_value = {}

            screen._show_accuracy_dashboard()
            mock_static.update.assert_called_once()
            rendered = mock_static.update.call_args[0][0]
            assert "Accuracy Dashboard" in rendered


# ---------------------------------------------------------------------------
# _compute_weight edge cases
# ---------------------------------------------------------------------------

class TestComputeWeight:

    def test_under_threshold(self):
        ds = DetectorStats(detector_name="t", total=19, accepted=19, precision=1.0)
        w = AccuracyTracker._compute_weight(ds)
        assert w == 1.0  # not enough data

    def test_exactly_66_percent(self):
        ds = DetectorStats(detector_name="t", total=20, accepted=14, rejected=7, precision=2/3)
        w = AccuracyTracker._compute_weight(ds)
        assert abs(w - 1.0) < 0.01  # approximately 1.0 at boundary

    def test_exactly_33_percent(self):
        ds = DetectorStats(detector_name="t", total=20, accepted=7, rejected=14, precision=1/3)
        w = AccuracyTracker._compute_weight(ds)
        assert abs(w - 1.0) < 0.01

    def test_high_precision(self):
        ds = DetectorStats(detector_name="t", total=20, accepted=20, precision=1.0)
        w = AccuracyTracker._compute_weight(ds)
        assert abs(w - 1.5) < 1e-9

    def test_zero_precision(self):
        ds = DetectorStats(detector_name="t", total=20, rejected=20, precision=0.0)
        w = AccuracyTracker._compute_weight(ds)
        assert abs(w - 0.5) < 1e-9


# ---------------------------------------------------------------------------
# record_finding_outcome
# ---------------------------------------------------------------------------

class TestRecordFindingOutcome:

    def test_basic_accepted(self, tracker):
        tracker.record_finding_outcome("f1", "reentrancy", "accepted", bounty_amount=5000.0)
        subs = tracker.metrics["submissions"]
        assert len(subs) == 1
        assert subs[0]["outcome"] == "accepted"
        assert subs[0]["detector"] == "reentrancy"
        assert subs[0]["bounty_amount"] == 5000.0

    def test_rejected(self, tracker):
        tracker.record_finding_outcome("f2", "overflow", "rejected")
        assert tracker.metrics["submissions"][0]["outcome"] == "rejected"

    def test_out_of_scope(self, tracker):
        tracker.record_finding_outcome("f3", "dos", "out_of_scope")
        assert tracker.metrics["submissions"][0]["outcome"] == "out_of_scope"

    def test_zero_bounty_no_key(self, tracker):
        tracker.record_finding_outcome("f4", "test", "accepted")
        assert "bounty_amount" not in tracker.metrics["submissions"][0]

    def test_detector_field_set(self, tracker):
        tracker.record_finding_outcome("unique_123", "reentrancy", "accepted")
        sub = tracker.metrics["submissions"][0]
        # record_finding_outcome sets the detector field on the vuln dict
        assert sub.get("detector") == "reentrancy"


# ---------------------------------------------------------------------------
# get_severity_accuracy
# ---------------------------------------------------------------------------

class TestGetSeverityAccuracy:

    def test_empty(self, tracker):
        assert tracker.get_severity_accuracy() == {}

    def test_single_severity(self, tracker):
        tracker.record_submission(_vuln(severity="critical"), "accepted")
        tracker.record_submission(_vuln(severity="critical"), "rejected")
        sev = tracker.get_severity_accuracy()
        assert sev["critical"]["accepted"] == 1
        assert sev["critical"]["rejected"] == 1
        assert sev["critical"]["total"] == 2

    def test_multiple_severities(self, tracker):
        tracker.record_submission(_vuln(severity="critical"), "accepted")
        tracker.record_submission(_vuln(severity="high"), "rejected")
        tracker.record_submission(_vuln(severity="high"), "out_of_scope")
        sev = tracker.get_severity_accuracy()
        assert sev["critical"]["total"] == 1
        assert sev["high"]["total"] == 2
        assert sev["high"]["out_of_scope"] == 1

    def test_out_of_scope_tracked(self, tracker):
        tracker.record_submission(_vuln(severity="low"), "out_of_scope")
        sev = tracker.get_severity_accuracy()
        assert sev["low"]["out_of_scope"] == 1


# ---------------------------------------------------------------------------
# _build_severity_calibration_note (DeepAnalysisEngine)
# ---------------------------------------------------------------------------

class TestBuildSeverityCalibrationNote:

    def _make_engine(self, calibration=None):
        from core.deep_analysis_engine import DeepAnalysisEngine
        mock_llm = MagicMock()
        engine = DeepAnalysisEngine(mock_llm)
        if calibration is not None:
            engine._severity_calibration = calibration
        return engine

    def test_note_for_high_rejection(self):
        engine = self._make_engine({"critical": 0.1})
        note = engine._build_severity_calibration_note()
        assert "CRITICAL" in note
        assert "90%" in note

    def test_no_note_when_good_acceptance(self):
        engine = self._make_engine({"critical": 0.7, "high": 0.6})
        assert engine._build_severity_calibration_note() == ""

    def test_empty_calibration(self):
        engine = self._make_engine({})
        assert engine._build_severity_calibration_note() == ""

    def test_mixed_severities(self):
        engine = self._make_engine({"critical": 0.05, "high": 0.5, "medium": 0.15})
        note = engine._build_severity_calibration_note()
        assert "CRITICAL" in note
        assert "MEDIUM" in note
        # high has 50% acceptance (above 20%), so should NOT appear
        assert "HIGH" not in note
