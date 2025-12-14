#!/usr/bin/env python3
"""
Tests for Enhanced Severity Calibration

Tests the severity calibration functionality that adjusts severity
based on real-world exploit prerequisites.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.impact_analyzer import (
    EnhancedSeverityCalibrator,
    SeverityReductionReason,
    SeverityCalibrationResult,
    FinancialImpactType,
    ImpactAnalyzer
)


class TestEnhancedSeverityCalibrator:
    """Test cases for EnhancedSeverityCalibrator."""
    
    @pytest.fixture
    def calibrator(self):
        """Create calibrator instance."""
        return EnhancedSeverityCalibrator()
    
    def test_user_self_harm_reduction(self, calibrator):
        """Test severity reduction for user self-harm scenarios."""
        finding = {
            'title': 'Invalid Gas Parameter',
            'severity': 'high',
            'description': "User's own transaction fails if they provide invalid gas parameter",
            'vulnerability_type': 'validation_issue'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'low'
        assert result.reduction_reason == SeverityReductionReason.USER_SELF_HARM
    
    def test_malicious_token_reduction(self, calibrator):
        """Test severity reduction for malicious token scenarios."""
        finding = {
            'title': 'Balance Check Bypass',
            'severity': 'high',
            'description': 'A malicious token could manipulate balanceOf to bypass the fee check',
            'vulnerability_type': 'logic_bypass'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'medium'
        assert result.reduction_reason == SeverityReductionReason.REQUIRES_MALICIOUS_TOKEN
    
    def test_privileged_access_reduction(self, calibrator):
        """Test severity reduction for privileged access scenarios."""
        finding = {
            'title': 'Admin Misconfiguration',
            'severity': 'critical',
            'description': 'Admin must set correct parameters or protocol will not function correctly',
            'vulnerability_type': 'admin_issue'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'medium'
        assert result.reduction_reason == SeverityReductionReason.REQUIRES_PRIVILEGED_ACCESS
    
    def test_theoretical_only_reduction(self, calibrator):
        """Test severity reduction for theoretical-only scenarios."""
        finding = {
            'title': 'Edge Case Issue',
            'severity': 'high',
            'description': 'In theory, under specific circumstances, this could lead to issues',
            'vulnerability_type': 'edge_case'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'low'
        assert result.reduction_reason == SeverityReductionReason.THEORETICAL_ONLY
    
    def test_deployment_time_reduction(self, calibrator):
        """Test severity reduction for deployment-time only issues."""
        finding = {
            'title': 'Constructor Vulnerability',
            'severity': 'high',
            'description': 'During deployment, a malicious deployer could set wrong initial values',
            'vulnerability_type': 'initialization'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'low'
        assert result.reduction_reason == SeverityReductionReason.DEPLOYMENT_TIME_ONLY
    
    def test_configuration_concern_reduction(self, calibrator):
        """Test severity reduction for configuration concerns."""
        finding = {
            'title': 'Wrong Parameter',
            'severity': 'high',
            'description': 'Incorrect configuration of the protocol parameters could cause issues',
            'vulnerability_type': 'configuration'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is True
        assert result.adjusted_severity == 'medium'
        assert result.reduction_reason == SeverityReductionReason.CONFIGURATION_CONCERN
    
    def test_no_reduction_real_vulnerability(self, calibrator):
        """Test that real vulnerabilities are not reduced."""
        finding = {
            'title': 'Reentrancy Attack',
            'severity': 'critical',
            'description': 'External attacker can drain all funds through reentrancy',
            'vulnerability_type': 'reentrancy'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        assert result.severity_reduced is False
        assert result.adjusted_severity == 'critical'
        assert result.reduction_reason == SeverityReductionReason.NONE
    
    def test_severity_cap_application(self, calibrator):
        """Test that severity cap is correctly applied."""
        # Critical -> Medium for privileged access
        finding_critical = {
            'severity': 'critical',
            'description': 'Admin must configure correctly'
        }
        
        result = calibrator.calibrate_severity(finding_critical)
        assert result.adjusted_severity == 'medium'
        
        # Low severity should stay low
        finding_low = {
            'severity': 'low',
            'description': 'Admin must configure correctly'
        }
        
        result = calibrator.calibrate_severity(finding_low)
        assert result.adjusted_severity == 'low'


class TestBatchCalibration:
    """Test batch severity calibration."""
    
    @pytest.fixture
    def calibrator(self):
        return EnhancedSeverityCalibrator()
    
    def test_calibrate_findings_batch(self, calibrator):
        """Test batch calibration of multiple findings."""
        findings = [
            {
                'title': 'User Error',
                'severity': 'high',
                'description': "User's own transaction fails with bad input"
            },
            {
                'title': 'Real Vuln',
                'severity': 'high',
                'description': 'Attacker can steal funds from protocol'
            },
            {
                'title': 'Admin Issue',
                'severity': 'critical',
                'description': 'Admin must set correct fee parameters'
            },
        ]
        
        calibrated, stats = calibrator.calibrate_findings_batch(findings)
        
        assert len(calibrated) == 3
        assert stats['total'] == 3
        assert stats['user_self_harm'] == 1
        assert stats['requires_privileged_access'] == 1
        assert stats['unchanged'] == 1
    
    def test_batch_preserves_finding_data(self, calibrator):
        """Test that batch calibration preserves original finding data."""
        findings = [
            {
                'title': 'Test Finding',
                'severity': 'high',
                'description': "User's own transaction fails",
                'line_number': 42,
                'extra_field': 'preserved'
            }
        ]
        
        calibrated, _ = calibrator.calibrate_findings_batch(findings)
        
        assert calibrated[0]['title'] == 'Test Finding'
        assert calibrated[0]['line_number'] == 42
        assert calibrated[0]['extra_field'] == 'preserved'
        assert calibrated[0]['original_severity'] == 'high'
        assert calibrated[0]['severity'] == 'low'


class TestFinancialImpactClassification:
    """Test financial impact classification."""
    
    @pytest.fixture
    def analyzer(self):
        return ImpactAnalyzer()
    
    def test_fund_drain_classification(self, analyzer):
        """Test classification of fund drain vulnerabilities."""
        vuln = {
            'description': 'Attacker can drain all funds from the protocol',
            'vulnerability_type': 'reentrancy'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.FUND_DRAIN
        assert multiplier == 1.0
    
    def test_profit_reduction_classification(self, analyzer):
        """Test classification of profit reduction vulnerabilities."""
        vuln = {
            'description': 'MEV bot can sandwich attack to extract profit from users',
            'vulnerability_type': 'mev'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.PROFIT_REDUCTION
        assert multiplier == 0.6
    
    def test_unfavorable_rate_classification(self, analyzer):
        """Test classification of unfavorable rate vulnerabilities."""
        vuln = {
            'description': 'Price manipulation could lead to incorrect price used in swap',
            'vulnerability_type': 'oracle_manipulation'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.UNFAVORABLE_RATE
        assert multiplier == 0.65
    
    def test_gas_waste_classification(self, analyzer):
        """Test classification of gas waste vulnerabilities."""
        vuln = {
            'description': 'Failed liquidation attempts waste gas fees',
            'vulnerability_type': 'dos'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.GAS_WASTE
        assert multiplier == 0.3
    
    def test_dos_financial_classification(self, analyzer):
        """Test classification of DoS with financial impact."""
        vuln = {
            'description': 'DoS can lock funds and prevent withdrawals',
            'vulnerability_type': 'dos'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.DOS_FINANCIAL
        assert multiplier == 0.4
    
    def test_no_financial_impact(self, analyzer):
        """Test classification of non-financial vulnerabilities."""
        vuln = {
            'description': 'Information disclosure of internal state',
            'vulnerability_type': 'info_leak'
        }
        
        impact_type, multiplier = analyzer.classify_financial_impact(vuln)
        
        assert impact_type == FinancialImpactType.NONE
        assert multiplier == 0.0


class TestSeverityCalibrationResult:
    """Test SeverityCalibrationResult dataclass."""
    
    def test_result_creation(self):
        """Test creating calibration results."""
        result = SeverityCalibrationResult(
            original_severity='high',
            adjusted_severity='medium',
            reduction_reason=SeverityReductionReason.REQUIRES_PRIVILEGED_ACCESS,
            confidence=0.85,
            reasoning='Requires admin access',
            severity_reduced=True
        )
        
        assert result.original_severity == 'high'
        assert result.adjusted_severity == 'medium'
        assert result.severity_reduced is True
    
    def test_no_reduction_result(self):
        """Test result with no severity reduction."""
        result = SeverityCalibrationResult(
            original_severity='high',
            adjusted_severity='high',
            reduction_reason=SeverityReductionReason.NONE,
            confidence=0.7,
            reasoning='No reduction factors detected',
            severity_reduced=False
        )
        
        assert result.original_severity == result.adjusted_severity
        assert result.severity_reduced is False


class TestSeverityMultipliers:
    """Test severity multiplier retrieval."""
    
    @pytest.fixture
    def calibrator(self):
        return EnhancedSeverityCalibrator()
    
    def test_get_severity_multipliers(self, calibrator):
        """Test getting severity multipliers for different reasons."""
        assert calibrator.get_severity_multiplier(SeverityReductionReason.USER_SELF_HARM) == 0.3
        assert calibrator.get_severity_multiplier(SeverityReductionReason.REQUIRES_MALICIOUS_TOKEN) == 0.5
        assert calibrator.get_severity_multiplier(SeverityReductionReason.THEORETICAL_ONLY) == 0.25
        assert calibrator.get_severity_multiplier(SeverityReductionReason.NONE) == 1.0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def calibrator(self):
        return EnhancedSeverityCalibrator()
    
    def test_empty_finding(self, calibrator):
        """Test with empty finding."""
        finding = {}
        
        result = calibrator.calibrate_severity(finding)
        
        # Should handle gracefully
        assert isinstance(result, SeverityCalibrationResult)
    
    def test_missing_severity(self, calibrator):
        """Test with missing severity field."""
        finding = {
            'description': "User's own transaction fails"
        }
        
        result = calibrator.calibrate_severity(finding)
        
        # Should use default severity
        assert result.original_severity == 'medium'
    
    def test_regex_patterns(self, calibrator):
        """Test regex pattern matching."""
        finding = {
            'severity': 'high',
            'description': 'The function requires ADMIN_ROLE to execute properly'
        }
        
        result = calibrator.calibrate_severity(finding)
        
        # Should match "requires.*role" pattern
        assert result.severity_reduced is True
    
    def test_case_insensitivity(self, calibrator):
        """Test case-insensitive keyword matching."""
        finding = {
            'severity': 'high',
            'description': "USER'S OWN TRANSACTION FAILS"  # All caps
        }
        
        result = calibrator.calibrate_severity(finding)
        
        # Should still detect user self-harm
        assert result.reduction_reason == SeverityReductionReason.USER_SELF_HARM


class TestIntegration:
    """Integration tests for severity calibration."""
    
    @pytest.fixture
    def calibrator(self):
        return EnhancedSeverityCalibrator()
    
    def test_real_world_findings(self, calibrator):
        """Test with real-world-like findings from audit report."""
        # Based on the ADI-Stack-Contracts audit validation
        findings = [
            {
                'title': 'Balance Delta Manipulation',
                'severity': 'high',
                'description': 'A malicious token could manipulate its balanceOf function to bypass the fee-on-transfer check',
            },
            {
                'title': 'Missing Gas Parameter Validation',
                'severity': 'medium',
                'description': "User's own transaction fails if they provide invalid _l2TxGasPerPubdataByte parameter",
            },
            {
                'title': 'Missing Access Control',
                'severity': 'high',
                'description': 'The transferFundsFromSharedBridge function lacks access control. Anyone can call to trigger the migration.',
            },
        ]
        
        results = []
        for finding in findings:
            result = calibrator.calibrate_severity(finding)
            results.append(result)
        
        # First finding: malicious token -> medium cap
        assert results[0].adjusted_severity == 'medium'
        
        # Second finding: user self-harm -> low cap (needs explicit "user's own" keyword)
        assert results[1].adjusted_severity == 'low'
        
        # Third finding: might be reduced (access control with migration)
        # This depends on exact keyword matching


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
