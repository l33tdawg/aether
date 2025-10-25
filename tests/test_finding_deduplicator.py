"""
Tests for Finding Deduplicator

This test suite validates the deduplication and post-processing
of vulnerability findings.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.finding_deduplicator import (
    Finding,
    FindingDeduplicator
)


class TestFinding:
    """Test the Finding dataclass"""
    
    def test_finding_creation(self):
        """Test creating a finding"""
        finding = Finding(
            vulnerability_type='test_vuln',
            severity='high',
            description='Test description',
            line_number=100,
            file_path='test.sol',
            confidence=0.9
        )
        
        assert finding.vulnerability_type == 'test_vuln'
        assert finding.severity == 'high'
        assert finding.line_number == 100
        assert finding.confidence == 0.9
    
    def test_finding_signature(self):
        """Test finding signature generation"""
        finding = Finding(
            vulnerability_type='init',
            severity='high',
            description='Test',
            line_number=92,
            file_path='AccountERC20Tracker.sol',
            confidence=0.9
        )
        
        signature = finding.get_signature()
        assert 'AccountERC20Tracker.sol' in signature
        assert 'init' in signature
    
    def test_is_similar_to_same_finding(self):
        """Test similarity detection for duplicate findings"""
        finding1 = Finding(
            vulnerability_type='unprotected_initialization',
            severity='high',
            description='Test',
            line_number=92,
            file_path='test.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='initialization_frontrun_risk',
            severity='high',
            description='Test',
            line_number=94,  # Within 5 lines
            file_path='test.sol',
            confidence=0.85
        )
        
        assert finding1.is_similar_to(finding2) == True
    
    def test_is_similar_to_different_file(self):
        """Test that findings in different files are not similar"""
        finding1 = Finding(
            vulnerability_type='init',
            severity='high',
            description='Test',
            line_number=92,
            file_path='file1.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='init',
            severity='high',
            description='Test',
            line_number=92,
            file_path='file2.sol',
            confidence=0.9
        )
        
        assert finding1.is_similar_to(finding2) == False
    
    def test_is_similar_to_far_lines(self):
        """Test that findings far apart in lines are not similar (unless same function)"""
        # Non-init findings should not be similar if far apart
        finding1 = Finding(
            vulnerability_type='oracle',
            severity='high',
            description='Oracle issue',
            line_number=10,
            file_path='test.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='oracle',
            severity='high',
            description='Oracle problem',
            line_number=100,  # More than 5 lines apart
            file_path='test.sol',
            confidence=0.9
        )
        
        assert finding1.is_similar_to(finding2) == False
    
    def test_is_similar_init_same_function(self):
        """Test that init findings about same function ARE similar even if far apart"""
        finding1 = Finding(
            vulnerability_type='best_practice_violation',
            severity='high',
            description='init function lacks access control',
            line_number=61,
            file_path='test.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='parameter_validation_issue',
            severity='high',
            description='init parameter validation missing',
            line_number=92,
            file_path='test.sol',
            confidence=0.8
        )
        
        # Both reference init function - should be considered similar
        assert finding1.is_similar_to(finding2) == True


class TestFindingDeduplicator:
    """Test the FindingDeduplicator class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.deduplicator = FindingDeduplicator()
    
    def test_deduplicator_initialization(self):
        """Test deduplicator initializes correctly"""
        assert self.deduplicator is not None
        assert len(self.deduplicator.severity_hierarchy) > 0
    
    def test_deduplicate_no_findings(self):
        """Test deduplication with no findings"""
        result = self.deduplicator.deduplicate_findings([])
        assert result == []
    
    def test_deduplicate_single_finding(self):
        """Test deduplication with single finding"""
        finding = Finding(
            vulnerability_type='test',
            severity='high',
            description='Test',
            line_number=100,
            file_path='test.sol',
            confidence=0.9
        )
        
        result = self.deduplicator.deduplicate_findings([finding])
        assert len(result) == 1
        assert result[0] == finding
    
    def test_deduplicate_duplicate_findings(self):
        """Test deduplication of duplicate findings"""
        finding1 = Finding(
            vulnerability_type='unprotected_initialization',
            severity='high',
            description='Init function lacks access control',
            line_number=92,
            file_path='AccountERC20Tracker.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='parameter_validation_issue',
            severity='high',
            description='Parameter validation issue in init',
            line_number=92,
            file_path='AccountERC20Tracker.sol',
            confidence=0.8
        )
        
        result = self.deduplicator.deduplicate_findings([finding1, finding2])
        
        # Should merge into 1 finding
        assert len(result) == 1
        
        # Should keep highest confidence
        assert result[0].confidence == 0.9
        
        # Should note multiple detectors
        assert 'detected_by' in result[0].context
    
    def test_deduplicate_different_findings(self):
        """Test that different findings are not merged"""
        finding1 = Finding(
            vulnerability_type='init',
            severity='high',
            description='Test',
            line_number=92,
            file_path='test.sol',
            confidence=0.9
        )
        
        finding2 = Finding(
            vulnerability_type='oracle',
            severity='medium',
            description='Oracle issue',
            line_number=150,
            file_path='test.sol',
            confidence=0.8
        )
        
        result = self.deduplicator.deduplicate_findings([finding1, finding2])
        
        # Should keep both findings
        assert len(result) == 2
    
    def test_get_highest_severity(self):
        """Test severity comparison"""
        severities = ['low', 'high', 'medium']
        result = self.deduplicator._get_highest_severity(severities)
        assert result == 'high'
        
        severities2 = ['critical', 'high', 'low']
        result2 = self.deduplicator._get_highest_severity(severities2)
        assert result2 == 'critical'
    
    def test_calibrate_severity_precision_loss(self):
        """Test severity calibration for precision loss"""
        # Severe precision loss (should stay HIGH)
        finding = Finding(
            vulnerability_type='precision_loss_division',
            severity='high',
            description='total value of 0 due to truncation, 100% loss',
            line_number=183,
            file_path='test.sol',
            confidence=1.0
        )
        
        result = self.deduplicator._adjust_severity_by_context(finding)
        assert result.severity == 'high'
        
        # Typical precision loss (should downgrade to MEDIUM)
        finding2 = Finding(
            vulnerability_type='precision_loss_division',
            severity='high',
            description='minor rounding error in calculation',
            line_number=183,
            file_path='test.sol',
            confidence=0.8
        )
        
        result2 = self.deduplicator._adjust_severity_by_context(finding2)
        assert result2.severity == 'medium'
        assert 'severity_adjustment' in result2.context
    
    def test_calibrate_severity_initialization(self):
        """Test severity calibration for initialization issues"""
        finding = Finding(
            vulnerability_type='init_issue',
            severity='medium',
            description='init function with no access control',
            line_number=92,
            file_path='test.sol',
            confidence=0.9
        )
        
        result = self.deduplicator._adjust_severity_by_context(finding)
        
        # Should elevate to HIGH
        assert result.severity == 'high'
        assert 'severity_adjustment' in result.context
    
    def test_calibrate_severity_oracle_delegation(self):
        """Test severity calibration for delegated oracle"""
        finding = Finding(
            vulnerability_type='oracle_manipulation',
            severity='high',
            description='delegates to IValuationHandler without validation',
            line_number=125,
            file_path='test.sol',
            confidence=0.9
        )
        
        result = self.deduplicator._adjust_severity_by_context(finding)
        
        # Should downgrade to MEDIUM (architectural concern)
        assert result.severity == 'medium'
        assert 'severity_adjustment' in result.context
    
    def test_calibrate_severity_loop_admin(self):
        """Test severity calibration for admin-only loop issues"""
        finding = Finding(
            vulnerability_type='loop_gas_issue',
            severity='high',
            description='loop over unbounded array, but only admin can add items',
            line_number=139,
            file_path='test.sol',
            confidence=0.8
        )
        
        result = self.deduplicator._adjust_severity_by_context(finding)
        
        # Should downgrade to MEDIUM (admin trusted)
        assert result.severity == 'medium'
    
    def test_enhance_descriptions(self):
        """Test description enhancement"""
        finding = Finding(
            vulnerability_type='initialization_frontrun_risk',
            severity='high',
            description='init function lacks access control',
            line_number=92,
            file_path='test.sol',
            confidence=0.9
        )
        
        result = self.deduplicator.enhance_descriptions([finding])
        
        assert len(result) == 1
        assert 'exploitability' in result[0].context
    
    def test_assess_exploitability_public(self):
        """Test exploitability assessment for public functions"""
        finding = Finding(
            vulnerability_type='test',
            severity='high',
            description='external function with no access control',
            line_number=100,
            file_path='test.sol',
            confidence=0.9
        )
        
        result = self.deduplicator._assess_exploitability(finding)
        assert 'high' in result.lower() or 'public' in result.lower()
    
    def test_assess_exploitability_admin(self):
        """Test exploitability assessment for admin functions"""
        finding = Finding(
            vulnerability_type='test',
            severity='medium',
            description='issue in admin function',
            line_number=100,
            file_path='test.sol',
            confidence=0.8
        )
        
        result = self.deduplicator._assess_exploitability(finding)
        assert 'low' in result.lower()
    
    def test_sort_findings(self):
        """Test findings sorting"""
        findings = [
            Finding('test1', 'low', 'desc1', 100, 'test.sol', 0.7),
            Finding('test2', 'critical', 'desc2', 50, 'test.sol', 0.9),
            Finding('test3', 'medium', 'desc3', 75, 'test.sol', 0.8),
        ]
        
        result = self.deduplicator.sort_findings(findings)
        
        # Should be sorted by severity
        assert result[0].severity == 'critical'
        assert result[1].severity == 'medium'
        assert result[2].severity == 'low'
    
    def test_sort_findings_by_confidence(self):
        """Test findings sorting by confidence when severity is same"""
        findings = [
            Finding('test1', 'high', 'desc1', 100, 'test.sol', 0.7),
            Finding('test2', 'high', 'desc2', 50, 'test.sol', 0.95),
            Finding('test3', 'high', 'desc3', 75, 'test.sol', 0.85),
        ]
        
        result = self.deduplicator.sort_findings(findings)
        
        # Should be sorted by confidence (highest first)
        assert result[0].confidence == 0.95
        assert result[1].confidence == 0.85
        assert result[2].confidence == 0.7
    
    def test_process_findings_complete(self):
        """Test complete processing pipeline"""
        # Simulate real findings from protocol-onyx
        findings = [
            # Duplicate init findings
            Finding(
                vulnerability_type='best_practice_violation',
                severity='high',
                description='init function lacks access control',
                line_number=61,
                file_path='AccountERC20Tracker.sol',
                confidence=0.9
            ),
            Finding(
                vulnerability_type='parameter_validation_issue',
                severity='high',
                description='init parameter validation missing',
                line_number=92,
                file_path='AccountERC20Tracker.sol',
                confidence=0.8
            ),
            # Precision loss
            Finding(
                vulnerability_type='precision_loss_division',
                severity='high',
                description='total value of 0 in pro-rated calculation',
                line_number=183,
                file_path='LinearCreditDebtTracker.sol',
                confidence=1.0
            ),
            # Oracle issue
            Finding(
                vulnerability_type='oracle_manipulation',
                severity='high',
                description='delegates to handler without validation',
                line_number=125,
                file_path='AccountERC20Tracker.sol',
                confidence=0.92
            ),
        ]
        
        result = self.deduplicator.process_findings(findings)
        
        # Should deduplicate init findings (4 findings total)
        # - 2 init findings on lines 61 and 92 (should merge into 1)
        # - 1 precision loss (stays separate)
        # - 1 oracle issue (stays separate)
        # Expected: 3 findings after dedup
        assert len(result) == 3, f"Expected 3 findings after dedup, got {len(result)}"
        
        # Check that init findings were merged
        init_findings = [f for f in result if 'init' in f.vulnerability_type.lower() or 'init' in f.description.lower()]
        assert len(init_findings) == 1, "Init findings should be merged into 1"
        
        # Should all have exploitability assessed
        for finding in result:
            assert 'exploitability' in finding.context
        
        # Should be sorted by severity (highest first)
        assert result[0].severity in ['critical', 'high']
        
        # Oracle should be downgraded to medium
        oracle_findings = [f for f in result if 'oracle' in f.vulnerability_type.lower()]
        if oracle_findings:
            assert oracle_findings[0].severity == 'medium', "Oracle delegation should be downgraded to medium"
    
    def test_generate_deduplication_report(self):
        """Test deduplication report generation"""
        report = self.deduplicator.generate_deduplication_report(
            original_count=10,
            deduplicated_count=7
        )
        
        assert report['original_findings'] == 10
        assert report['deduplicated_findings'] == 7
        assert report['duplicates_removed'] == 3
        assert report['deduplication_rate'] == 30.0
    
    def test_merge_recommendations(self):
        """Test recommendation merging"""
        recs = [
            'Add access control',
            'Use onlyOwner modifier',
            'Add access control'  # Duplicate
        ]
        
        result = self.deduplicator._merge_recommendations(recs)
        
        # Should remove duplicates
        assert result.count('Add access control') == 1
        assert 'onlyOwner' in result


class TestRealWorldScenarios:
    """Test with real-world scenarios"""
    
    def setup_method(self):
        self.deduplicator = FindingDeduplicator()
    
    def test_protocol_onyx_deduplication(self):
        """Test deduplication with actual protocol-onyx findings"""
        findings = [
            Finding(
                vulnerability_type='best_practice_violation',
                severity='high',
                description='The `init` function (line 99) is missing proper access control, allowing any external caller to initialize the contract.',
                line_number=61,
                file_path='src/components/value/position-trackers/AccountERC20Tracker.sol',
                confidence=0.90
            ),
            Finding(
                vulnerability_type='parameter_validation_issue',
                severity='high',
                description='Lack of access control on the `init` function, allowing any external caller to set the primary `_account`.',
                line_number=92,
                file_path='src/components/value/position-trackers/AccountERC20Tracker.sol',
                confidence=0.80
            ),
        ]
        
        result = self.deduplicator.process_findings(findings)
        
        # Should merge into 1 finding
        assert len(result) == 1
        
        # Should keep highest confidence
        assert result[0].confidence == 0.90
        
        # Should note multiple detectors
        assert 'detected_by' in result[0].context


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

