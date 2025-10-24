#!/usr/bin/env python3
"""
Tests for Scope Classifier Module

Tests classification of vulnerabilities as in-scope or out-of-scope for bug bounties.
"""

import pytest
from core.scope_classifier import ScopeClassifier, ScopeStatus, ScopeClassification


class TestScopeClassifier:
    """Test cases for ScopeClassifier."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_initialization(self):
        """Test classifier initialization."""
        assert len(self.classifier.OUT_OF_SCOPE_CATEGORIES) > 0
        assert 'admin_only_dos' in self.classifier.OUT_OF_SCOPE_CATEGORIES
        assert 'governance_misconfiguration' in self.classifier.OUT_OF_SCOPE_CATEGORIES
        assert len(self.classifier.ADMIN_MODIFIERS) > 0


class TestAdminOnlyDoSDetection:
    """Test admin-only DoS detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_detects_admin_only_dos(self):
        """Test detection of DoS on admin-only function."""
        contract_code = """
        pragma solidity 0.8.28;
        
        library LibSetters {
            function revokeCollateral(address collateral) internal restricted {
                for (uint256 i; i < length - 1; ++i) {
                    if (collateralListMem[i] == collateral) {
                        ts.collateralList[i] = collateralListMem[length - 1];
                        break;
                    }
                }
                ts.collateralList.pop();
            }
        }
        """
        
        vulnerability = {
            'type': 'unbounded_array_operation_dos',
            'function': 'revokeCollateral',
            'description': 'Unbounded loop could hit gas limit',
            'severity': 'medium'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'LibSetters'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'admin_only_dos'
        assert 'admin' in classification.reason.lower()
    
    def test_user_facing_dos_is_in_scope(self):
        """Test that user-facing DoS is in scope."""
        contract_code = """
        contract Vault {
            function withdraw(uint256 amount) external {
                for (uint256 i = 0; i < users.length; i++) {
                    // Unbounded loop in user function
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'unbounded_loop_dos',
            'function': 'withdraw',
            'description': 'Unbounded loop',
            'severity': 'high'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Vault'
        )
        
        # Should be in scope (user-facing)
        assert classification.status == ScopeStatus.IN_SCOPE


class TestGovernanceMisconfigurationDetection:
    """Test governance misconfiguration detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_detects_governance_parameter_validation(self):
        """Test detection of governance parameter validation issues."""
        contract_code = """
        contract Savings {
            function setMaxRate(uint256 newMaxRate) external restricted {
                maxRate = newMaxRate;  // No validation, but governance-only
            }
        }
        """
        
        vulnerability = {
            'type': 'parameter_validation_issue',
            'function': 'setMaxRate',
            'description': 'Missing validation for newMaxRate parameter',
            'severity': 'medium'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Savings'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'governance_misconfiguration'
    
    def test_user_parameter_validation_is_in_scope(self):
        """Test that user parameter validation is in scope."""
        contract_code = """
        contract Token {
            function transfer(address to, uint256 amount) external {
                _transfer(msg.sender, to, amount);  # No validation
            }
        }
        """
        
        vulnerability = {
            'type': 'parameter_validation',
            'function': 'transfer',
            'description': 'Missing parameter validation',
            'severity': 'medium'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Token'
        )
        
        # Should be in scope (user-facing)
        assert classification.status == ScopeStatus.IN_SCOPE


class TestKnownLimitationDetection:
    """Test known limitation detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_detects_known_issue_comment(self):
        """Test detection of 'known issue' comments."""
        contract_code = """
        contract Protocol {
            // Known limitation: does not support ERC777 tokens
            function deposit(IERC20 token) external {
                token.transferFrom(msg.sender, address(this), amount);
            }
        }
        """
        
        vulnerability = {
            'type': 'token_callback',
            'line': 5,
            'description': 'Does not handle ERC777 callbacks'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Protocol'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'known_limitations'


class TestHypotheticalDetection:
    """Test hypothetical vulnerability detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_detects_hypothetical_vulnerability(self):
        """Test detection of hypothetical vulnerabilities."""
        vulnerability = {
            'type': 'theoretical_attack',
            'description': 'Could potentially be exploited if a malicious token is used and if the attacker controls the oracle',
            'severity': 'medium'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, "contract Test {}", 'Test'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'hypothetical'


class TestDisplayOnlyDetection:
    """Test display-only function detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_detects_view_function_issue(self):
        """Test detection of view function issues."""
        contract_code = """
        contract Protocol {
            function getPrice() external view returns (uint256) {
                return price / 1e18;  // Precision loss in view
            }
        }
        """
        
        vulnerability = {
            'type': 'precision_loss',
            'function': 'getPrice',
            'description': 'Precision loss in price calculation',
            'severity': 'low'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Protocol'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'display_only'


class TestBountyEligibility:
    """Test bounty eligibility assessment."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_in_scope_critical_vulnerability(self):
        """Test bounty eligibility for in-scope critical vulnerability."""
        contract_code = """
        contract Vault {
            function withdraw(uint256 amount) external {
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}("");
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'withdraw',
            'description': 'Reentrancy allows fund theft',
            'severity': 'critical'
        }
        
        eligibility = self.classifier.get_bounty_eligibility(
            vulnerability, contract_code, 'Vault'
        )
        
        assert eligibility['eligible'] is True
        assert eligibility['status'] == 'in_scope'
        assert eligibility['bounty_estimate'] == (50000, 250000)
        assert '✅ Submit' in eligibility['recommendation']
    
    def test_out_of_scope_admin_dos(self):
        """Test bounty eligibility for out-of-scope admin DoS."""
        contract_code = """
        library LibSetters {
            function revokeCollateral() internal restricted {
                for (uint256 i; i < length; i++) {
                    // Unbounded loop
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'unbounded_array_dos',
            'function': 'revokeCollateral',
            'description': 'Unbounded loop DoS',
            'severity': 'medium'
        }
        
        eligibility = self.classifier.get_bounty_eligibility(
            vulnerability, contract_code, 'LibSetters'
        )
        
        assert eligibility['eligible'] is False
        assert eligibility['status'] == 'out_of_scope'
        assert eligibility['bounty_estimate'] is None
        assert '❌ Do not submit' in eligibility['recommendation']


class TestParallelProtocolRegressionCases:
    """Regression tests for Parallel Protocol findings."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_finding_2_governance_parameter(self):
        """Test Finding #2: Parameter validation in setMaxRate."""
        contract_code = """
        contract Savings {
            function setMaxRate(uint256 newMaxRate) external restricted {
                maxRate = newMaxRate;
            }
        }
        """
        
        vulnerability = {
            'type': 'parameter_validation_issue',
            'function': 'setMaxRate',
            'line': 278,
            'description': 'Missing validation for newMaxRate parameter',
            'severity': 'medium'
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, contract_code, 'Savings'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'governance_misconfiguration'
    
    def test_finding_4_admin_dos(self):
        """Test Finding #4: Unbounded array DoS in revokeCollateral."""
        contract_code = """
        library LibSetters {
            function revokeCollateral(address collateral, bool check) internal {
                for (uint256 i; i < length - 1; ++i) {
                    if (collateralListMem[i] == collateral) {
                        ts.collateralList[i] = collateralListMem[length - 1];
                        break;
                    }
                }
                ts.collateralList.pop();
            }
        }
        """
        
        # Note: The function is internal but called only from governance functions
        # The actual public function would have restricted modifier
        vulnerability = {
            'type': 'unbounded_array_operaton_dos',
            'function': 'revokeCollateral',
            'line': 110,
            'description': 'Unbounded loop can cause DoS',
            'severity': 'medium'
        }
        
        # Simulate that this is called from a restricted function
        wrapper_code = """
        contract Setters {
            function revokeCollateral(address collateral) external restricted {
                LibSetters.revokeCollateral(collateral, true);
            }
        }
        """ + contract_code
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, wrapper_code, 'Setters'
        )
        
        assert classification.status == ScopeStatus.OUT_OF_SCOPE
        assert classification.category == 'admin_only_dos'


class TestSeverityToBountyMapping:
    """Test severity to bounty range mapping."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_critical_bounty_range(self):
        """Test critical severity bounty range."""
        vulnerability = {
            'type': 'reentrancy',
            'severity': 'critical',
            'description': 'Critical vulnerability'
        }
        
        eligibility = self.classifier.get_bounty_eligibility(
            vulnerability, "contract Test {}", 'Test'
        )
        
        if eligibility['eligible']:
            assert eligibility['bounty_estimate'] == (50000, 250000)
    
    def test_high_bounty_range(self):
        """Test high severity bounty range."""
        vulnerability = {
            'type': 'access_control',
            'severity': 'high',
            'description': 'High severity vulnerability'
        }
        
        eligibility = self.classifier.get_bounty_eligibility(
            vulnerability, "contract Test {}", 'Test'
        )
        
        if eligibility['eligible']:
            assert eligibility['bounty_estimate'] == (10000, 50000)
    
    def test_medium_bounty_range(self):
        """Test medium severity bounty range."""
        vulnerability = {
            'type': 'oracle',
            'severity': 'medium',
            'description': 'Medium severity vulnerability'
        }
        
        eligibility = self.classifier.get_bounty_eligibility(
            vulnerability, "contract Test {}", 'Test'
        )
        
        if eligibility['eligible']:
            assert eligibility['bounty_estimate'] == (2000, 10000)


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_empty_vulnerability(self):
        """Test with empty vulnerability dict."""
        classification = self.classifier.classify_vulnerability(
            {}, "contract Test {}", 'Test'
        )
        
        # Should not crash
        assert isinstance(classification, ScopeClassification)
    
    def test_missing_function_name(self):
        """Test with missing function name."""
        vulnerability = {
            'type': 'dos',
            'description': 'DoS vulnerability',
            'severity': 'medium'
            # No function name
        }
        
        classification = self.classifier.classify_vulnerability(
            vulnerability, "contract Test {}", 'Test'
        )
        
        # Should not crash
        assert isinstance(classification, ScopeClassification)


class TestRecommendationGeneration:
    """Test recommendation generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.classifier = ScopeClassifier()
    
    def test_in_scope_recommendation(self):
        """Test recommendation for in-scope vulnerability."""
        classification = ScopeClassification(
            status=ScopeStatus.IN_SCOPE,
            reason='User funds at risk',
            confidence=0.9,
            category='standard_vulnerability'
        )
        
        recommendation = self.classifier._get_recommendation(classification)
        
        assert '✅ Submit' in recommendation
        assert 'proof of concept' in recommendation.lower()
    
    def test_out_of_scope_recommendation(self):
        """Test recommendation for out-of-scope vulnerability."""
        classification = ScopeClassification(
            status=ScopeStatus.OUT_OF_SCOPE,
            reason='Admin-only function',
            confidence=0.9,
            category='admin_only_dos'
        )
        
        recommendation = self.classifier._get_recommendation(classification)
        
        assert '❌ Do not submit' in recommendation
        assert 'Admin-only function' in recommendation
    
    def test_edge_case_recommendation(self):
        """Test recommendation for edge case."""
        classification = ScopeClassification(
            status=ScopeStatus.EDGE_CASE,
            reason='Unclear impact',
            confidence=0.5,
            category='unknown'
        )
        
        recommendation = self.classifier._get_recommendation(classification)
        
        assert '⚠️' in recommendation
        assert 'Edge case' in recommendation


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

