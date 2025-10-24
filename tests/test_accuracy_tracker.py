#!/usr/bin/env python3
"""
Tests for Accuracy Tracker Module

Tests accuracy tracking and metrics calculation.
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from core.accuracy_tracker import AccuracyTracker


class TestAccuracyTracker:
    """Test cases for AccuracyTracker."""
    
    @pytest.fixture
    def temp_metrics_file(self):
        """Create temporary metrics file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        yield metrics_file
        shutil.rmtree(temp_dir)
    
    def test_initialization(self, temp_metrics_file):
        """Test AccuracyTracker initialization."""
        tracker = AccuracyTracker(temp_metrics_file)
        
        assert tracker.metrics_file == temp_metrics_file
        assert 'submissions' in tracker.metrics
        assert 'false_positives_filtered' in tracker.metrics
        assert 'true_positives' in tracker.metrics
    
    def test_initialization_creates_directory(self):
        """Test that initialization creates parent directory."""
        temp_dir = tempfile.mkdtemp()
        try:
            metrics_file = Path(temp_dir) / 'subdir' / 'metrics.json'
            tracker = AccuracyTracker(metrics_file)
            
            assert metrics_file.parent.exists()
        finally:
            shutil.rmtree(temp_dir)


class TestSubmissionRecording:
    """Test submission recording."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_record_accepted_submission(self, tracker):
        """Test recording accepted submission."""
        vulnerability = {
            'vulnerability_type': 'reentrancy',
            'severity': 'critical',
            'validation_confidence': 0.95,
            'contract_name': 'Vault'
        }
        
        tracker.record_submission(vulnerability, 'accepted', bounty_amount=5000.0)
        
        assert len(tracker.metrics['submissions']) == 1
        submission = tracker.metrics['submissions'][0]
        assert submission['outcome'] == 'accepted'
        assert submission['bounty_amount'] == 5000.0
        assert submission['vulnerability_type'] == 'reentrancy'
    
    def test_record_rejected_submission(self, tracker):
        """Test recording rejected submission."""
        vulnerability = {
            'vulnerability_type': 'access_control',
            'severity': 'high'
        }
        
        tracker.record_submission(vulnerability, 'rejected')
        
        assert len(tracker.metrics['submissions']) == 1
        assert tracker.metrics['submissions'][0]['outcome'] == 'rejected'
    
    def test_record_multiple_submissions(self, tracker):
        """Test recording multiple submissions."""
        vulnerabilities = [
            {'vulnerability_type': 'reentrancy', 'severity': 'critical'},
            {'vulnerability_type': 'overflow', 'severity': 'high'},
            {'vulnerability_type': 'access_control', 'severity': 'medium'}
        ]
        
        for vuln in vulnerabilities:
            tracker.record_submission(vuln, 'accepted')
        
        assert len(tracker.metrics['submissions']) == 3


class TestFilteredRecording:
    """Test filtered false positive recording."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_record_filtered(self, tracker):
        """Test recording filtered false positive."""
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'severity': 'medium',
            'contract_name': 'Token'
        }
        
        tracker.record_filtered(
            vulnerability, 
            'Solidity 0.8+ provides automatic protection',
            stage='builtin_protection'
        )
        
        assert len(tracker.metrics['false_positives_filtered']) == 1
        filtered = tracker.metrics['false_positives_filtered'][0]
        assert filtered['filter_stage'] == 'builtin_protection'
        assert 'automatic protection' in filtered['filter_reason']
    
    def test_record_multiple_filtered(self, tracker):
        """Test recording multiple filtered items."""
        vulnerabilities = [
            {'vulnerability_type': 'overflow', 'severity': 'high'},
            {'vulnerability_type': 'underflow', 'severity': 'medium'},
        ]
        
        for vuln in vulnerabilities:
            tracker.record_filtered(vuln, 'Filtered', stage='test')
        
        assert len(tracker.metrics['false_positives_filtered']) == 2


class TestAccuracyCalculation:
    """Test accuracy statistics calculation."""
    
    @pytest.fixture
    def tracker_with_data(self):
        """Create tracker with sample data."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        
        # Record sample submissions
        tracker.record_submission({'vulnerability_type': 'test1', 'severity': 'high'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 'test2', 'severity': 'high'}, 'rejected')
        tracker.record_submission({'vulnerability_type': 'test3', 'severity': 'medium'}, 'accepted')
        
        # Record filtered items
        tracker.record_filtered({'vulnerability_type': 'test4', 'severity': 'low'}, 'False positive')
        tracker.record_filtered({'vulnerability_type': 'test5', 'severity': 'low'}, 'False positive')
        
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_accuracy_calculation(self, tracker_with_data):
        """Test accuracy calculation."""
        stats = tracker_with_data.get_accuracy_stats()
        
        assert stats['total_submissions'] == 3
        assert stats['accepted'] == 2
        assert stats['rejected'] == 1
        assert stats['accuracy'] == 2/3  # 2 accepted out of 3 total
        assert stats['false_positives_filtered'] == 2
    
    def test_filter_effectiveness(self, tracker_with_data):
        """Test filter effectiveness calculation."""
        stats = tracker_with_data.get_accuracy_stats()
        filter_eff = stats['filter_effectiveness']
        
        # 2 filtered + 1 rejected = 3 total false positives
        # 2 caught before submission = 66.7% catch rate
        assert filter_eff['total_false_positives'] == 3
        assert filter_eff['caught_before_submission'] == 2
        assert filter_eff['submitted_anyway'] == 1
        assert abs(filter_eff['catch_rate'] - 2/3) < 0.01


class TestSeverityBreakdown:
    """Test severity breakdown."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_severity_breakdown(self, tracker):
        """Test severity breakdown calculation."""
        # Record submissions with different severities
        tracker.record_submission({'vulnerability_type': 't1', 'severity': 'critical'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 't2', 'severity': 'critical'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 't3', 'severity': 'high'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 't4', 'severity': 'high'}, 'rejected')
        tracker.record_submission({'vulnerability_type': 't5', 'severity': 'medium'}, 'accepted')
        
        breakdown = tracker.get_severity_breakdown()
        
        assert 'critical' in breakdown
        assert breakdown['critical']['total'] == 2
        assert breakdown['critical']['accepted'] == 2
        assert breakdown['critical']['accuracy'] == 1.0
        
        assert 'high' in breakdown
        assert breakdown['high']['total'] == 2
        assert breakdown['high']['accepted'] == 1
        assert breakdown['high']['accuracy'] == 0.5


class TestVulnerabilityTypeBreakdown:
    """Test vulnerability type breakdown."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_type_breakdown(self, tracker):
        """Test vulnerability type breakdown."""
        tracker.record_submission({'vulnerability_type': 'reentrancy', 'severity': 'critical'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 'reentrancy', 'severity': 'high'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 'overflow', 'severity': 'medium'}, 'rejected')
        tracker.record_submission({'vulnerability_type': 'access_control', 'severity': 'high'}, 'accepted')
        
        breakdown = tracker.get_vulnerability_type_breakdown()
        
        assert 'reentrancy' in breakdown
        assert breakdown['reentrancy']['total'] == 2
        assert breakdown['reentrancy']['accepted'] == 2
        assert breakdown['reentrancy']['accuracy'] == 1.0
        
        assert 'overflow' in breakdown
        assert breakdown['overflow']['total'] == 1
        assert breakdown['overflow']['rejected'] == 1
        assert breakdown['overflow']['accuracy'] == 0.0


class TestBountyStats:
    """Test bounty statistics."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_bounty_stats(self, tracker):
        """Test bounty statistics calculation."""
        tracker.record_submission(
            {'vulnerability_type': 'reentrancy', 'severity': 'critical'}, 
            'accepted', 
            bounty_amount=10000.0
        )
        tracker.record_submission(
            {'vulnerability_type': 'access_control', 'severity': 'high'}, 
            'accepted', 
            bounty_amount=5000.0
        )
        tracker.record_submission(
            {'vulnerability_type': 'overflow', 'severity': 'medium'}, 
            'accepted'  # No bounty
        )
        
        stats = tracker.get_bounty_stats()
        
        assert stats['total_earned'] == 15000.0
        assert stats['bounty_count'] == 2
        assert stats['average_bounty'] == 7500.0


class TestTimeSeriesData:
    """Test time series data."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_recent_activity(self, tracker):
        """Test getting recent activity."""
        # Record recent submissions
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
        tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'Filtered')
        
        # Get last 30 days
        time_series = tracker.get_time_series_data(30)
        
        assert time_series['period_days'] == 30
        assert time_series['submissions'] == 1
        assert time_series['filtered'] == 1
        assert time_series['accepted'] == 1


class TestPersistence:
    """Test metrics persistence."""
    
    @pytest.fixture
    def temp_metrics_file(self):
        """Create temporary metrics file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        yield metrics_file
        shutil.rmtree(temp_dir)
    
    def test_save_and_load(self, temp_metrics_file):
        """Test saving and loading metrics."""
        # Create tracker and add data
        tracker1 = AccuracyTracker(temp_metrics_file)
        tracker1.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
        tracker1.save_metrics()
        
        # Create new tracker and verify data loaded
        tracker2 = AccuracyTracker(temp_metrics_file)
        
        assert len(tracker2.metrics['submissions']) == 1
        assert tracker2.metrics['submissions'][0]['outcome'] == 'accepted'
    
    def test_metrics_file_format(self, temp_metrics_file):
        """Test that metrics file is valid JSON."""
        tracker = AccuracyTracker(temp_metrics_file)
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
        tracker.save_metrics()
        
        # Verify file is valid JSON
        with open(temp_metrics_file) as f:
            data = json.load(f)
        
        assert 'submissions' in data
        assert 'version' in data


class TestExportReport:
    """Test report export."""
    
    @pytest.fixture
    def tracker_with_data(self):
        """Create tracker with sample data."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        
        # Add sample data
        tracker.record_submission({'vulnerability_type': 'reentrancy', 'severity': 'critical'}, 'accepted', bounty_amount=10000)
        tracker.record_submission({'vulnerability_type': 'overflow', 'severity': 'high'}, 'rejected')
        tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'False positive')
        
        yield tracker, temp_dir
        shutil.rmtree(temp_dir)
    
    def test_export_report(self, tracker_with_data):
        """Test exporting detailed report."""
        tracker, temp_dir = tracker_with_data
        output_file = Path(temp_dir) / 'report.json'
        
        tracker.export_report(output_file)
        
        assert output_file.exists()
        
        with open(output_file) as f:
            report = json.load(f)
        
        assert 'generated_at' in report
        assert 'overall_stats' in report
        assert 'severity_breakdown' in report
        assert 'type_breakdown' in report
        assert 'bounty_stats' in report


class TestEmptyMetrics:
    """Test behavior with empty metrics."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_accuracy_with_no_submissions(self, tracker):
        """Test accuracy calculation with no submissions."""
        stats = tracker.get_accuracy_stats()
        
        assert stats['accuracy'] == 0.0
        assert stats['total_submissions'] == 0
        assert 'message' in stats
    
    def test_bounty_stats_with_no_bounties(self, tracker):
        """Test bounty stats with no bounties."""
        stats = tracker.get_bounty_stats()
        
        assert stats['total_earned'] == 0.0
        assert stats['bounty_count'] == 0


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker with temporary file."""
        temp_dir = tempfile.mkdtemp()
        metrics_file = Path(temp_dir) / 'metrics.json'
        tracker = AccuracyTracker(metrics_file)
        yield tracker
        shutil.rmtree(temp_dir)
    
    def test_improving_accuracy_over_time(self, tracker):
        """Test tracking accuracy improvement."""
        # Week 1: 33% accuracy (1/3)
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'rejected')
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'rejected')
        
        stats_week1 = tracker.get_accuracy_stats()
        assert abs(stats_week1['accuracy'] - 1/3) < 0.01
        
        # Week 2: Better filtering, higher accuracy (3/4 = 75%)
        tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'Filtered')
        tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'Filtered')
        tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
        
        stats_week2 = tracker.get_accuracy_stats()
        assert stats_week2['accuracy'] == 2/4  # 50% of submissions accepted
        assert stats_week2['false_positives_filtered'] == 2
    
    def test_bounty_tracking(self, tracker):
        """Test tracking bounty earnings."""
        # Simulate successful bug bounty campaign
        bounties = [
            ('reentrancy', 'critical', 'accepted', 15000),
            ('access_control', 'high', 'accepted', 7500),
            ('oracle', 'high', 'accepted', 5000),
            ('overflow', 'medium', 'rejected', None),
        ]
        
        for vuln_type, severity, outcome, bounty in bounties:
            vuln = {'vulnerability_type': vuln_type, 'severity': severity}
            if bounty:
                tracker.record_submission(vuln, outcome, bounty_amount=bounty)
            else:
                tracker.record_submission(vuln, outcome)
        
        bounty_stats = tracker.get_bounty_stats()
        
        assert bounty_stats['total_earned'] == 27500.0
        assert bounty_stats['bounty_count'] == 3
        assert bounty_stats['average_bounty'] == 27500.0 / 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

