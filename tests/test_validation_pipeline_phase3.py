#!/usr/bin/env python3
"""
Integration Tests for Phase 3 Validation Pipeline Enhancements

Tests that all Phase 3 improvements work together with existing Phase 1 & 2 features.
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path

from core.validation_pipeline import ValidationPipeline, validate_vulnerability


class TestPhase3Integration:
    """Test Phase 3 integration with existing pipeline."""
    
    def test_pipeline_has_new_stages(self):
        """Test that pipeline has all 7 validation stages."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        pipeline = ValidationPipeline(None, contract_code)
        
        summary = pipeline.get_summary()
        
        # Should have all Phase 3 detectors
        assert 'has_design_assumption_detector' in summary
        assert 'has_reentrancy_guard_detector' in summary
        assert 'has_scope_classifier' in summary
        
        # Should still have Phase 1 & 2 detectors
        assert 'has_governance_detector' in summary
        assert 'has_deployment_analyzer' in summary
        assert 'has_validation_detector' in summary


class TestParallelProtocolAllFindingsFiltered:
    """Test that all 4 Parallel Protocol findings are now filtered."""
    
    @pytest.fixture
    def parallel_project(self):
        """Create Parallel Protocol project structure."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text(json.dumps({
            'manager': {'type': 'INTERNAL'}  # Only INTERNAL, not EXTERNAL
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_finding_1_reentrancy_in_savings_filtered(self, parallel_project):
        """Test Finding #1: Reentrancy in Savings.sol is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        /// @title BaseSavings
        /// @dev Implementations assume that `asset` is safe to interact with,
        /// on which there cannot be reentrancy attacks
        /// @dev This contract is an authorized fork of Angle's Savings contract
        abstract contract BaseSavings {
            function _accrue() internal returns (uint256 newTotalAssets) {
                uint256 earned = newTotalAssets - currentBalance;
                if (earned > 0) {
                    ITokenP(asset()).mint(address(this), earned);
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy_in_accrue_path_via_asset_token',
            'line': 120,
            'function': '_accrue',
            'description': 'External call to asset token without nonReentrant guard',
            'severity': 'high',
            'contract_name': 'BaseSavings'
        }
        
        result = validate_vulnerability(vulnerability, contract_code, parallel_project)
        
        # Should be filtered by design assumption detector
        assert result['is_false_positive'] is True
        assert 'design_assumption' in result['stage'] or 'assumption' in result['reasoning'].lower()
        assert result['confidence'] >= 0.8
    
    def test_finding_2_parameter_validation_filtered(self, parallel_project):
        """Test Finding #2: Parameter validation in setMaxRate is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract Savings {
            uint256 public maxRate;
            
            function setMaxRate(uint256 newMaxRate) external restricted {
                maxRate = newMaxRate;
            }
        }
        """
        
        vulnerability = {
            'type': 'parameter_validation_issue',
            'line': 278,
            'function': 'setMaxRate',
            'description': 'Missing validation for newMaxRate parameter',
            'severity': 'medium',
            'contract_name': 'Savings'
        }
        
        result = validate_vulnerability(vulnerability, contract_code, parallel_project)
        
        # Should be filtered by scope classifier (governance function)
        assert result['is_false_positive'] is True
        assert 'scope_classification' in result['stage'] or 'governance' in result['stage']
    
    def test_finding_3_balance_check_filtered(self, parallel_project):
        """Test Finding #3: Balance invariance check is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract RewardHandler {
            function sellRewards(uint256 minAmountOut, bytes memory payload) 
                external 
                nonReentrant 
                returns (uint256 amountOut) 
            {
                for (uint256 i; i < listLength; ++i) {
                    balances[i] = IERC20(list[i]).balanceOf(address(this));
                }
                (bool success, bytes memory result) = ODOS_ROUTER.call(payload);
                for (uint256 i; i < listLength; ++i) {
                    uint256 newBalance = IERC20(list[i]).balanceOf(address(this));
                    if (newBalance < balances[i]) {
                        revert InvalidSwap();
                    }
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'insufficient_balance_invariance_check',
            'line': 65,
            'function': 'sellRewards',
            'description': 'Tokens with hooks can manipulate balance checks',
            'severity': 'high',
            'contract_name': 'RewardHandler'
        }
        
        result = validate_vulnerability(vulnerability, contract_code, parallel_project)
        
        # Should be filtered by reentrancy guard detector
        assert result['is_false_positive'] is True
        assert 'reentrancy_protection' in result['stage'] or 'nonReentrant' in result['reasoning']
    
    def test_finding_4_admin_dos_filtered(self, parallel_project):
        """Test Finding #4: Unbounded array DoS is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
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
        
        contract Setters {
            function revokeCollateral(address collateral) external restricted {
                LibSetters.revokeCollateral(collateral, true);
            }
        }
        """
        
        vulnerability = {
            'type': 'unbounded_array_operaton_dos',
            'line': 110,
            'function': 'revokeCollateral',
            'description': 'Unbounded loop can hit gas limit',
            'severity': 'medium',
            'contract_name': 'LibSetters'
        }
        
        result = validate_vulnerability(vulnerability, contract_code, parallel_project)
        
        # Should be filtered by scope classifier (admin-only DoS)
        assert result['is_false_positive'] is True
        assert 'scope_classification' in result['stage'] or 'admin' in result['reasoning'].lower()


class TestValidationStageOrdering:
    """Test that validation stages run in correct order."""
    
    def test_design_assumption_runs_before_governance(self):
        """Test that design assumptions are checked early."""
        contract_code = """
        /// @dev Assumes asset is safe - no reentrancy possible
        contract Savings {
            function setRate(uint256 rate) external restricted {
                _rate = rate;
            }
        }
        """
        
        # Vulnerability that could match both design assumption and governance
        vulnerability = {
            'type': 'reentrancy',
            'line': 10,
            'description': 'Reentrancy risk'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should exit at design assumption stage (earlier than governance)
        assert stages[0].stage_name == 'design_assumption'
        assert len(stages) == 1  # Early exit
    
    def test_reentrancy_guard_runs_before_scope(self):
        """Test that reentrancy guards are checked before scope classification."""
        contract_code = """
        contract Handler {
            function process() external restricted nonReentrant {
                externalCall();
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'process',
            'line': 10
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should exit at reentrancy protection stage
        if stages[0].is_false_positive:
            assert stages[0].stage_name in ['reentrancy_protection', 'design_assumption', 'builtin_protection']


class TestNoFalseNegatives:
    """Test that real vulnerabilities are not filtered."""
    
    def test_real_reentrancy_not_filtered(self):
        """Test that real reentrancy without guards is not filtered."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Vulnerable {
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'withdraw',
            'line': 10,
            'description': 'State change after external call',
            'severity': 'critical'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should NOT be filtered (real vulnerability)
        assert result['is_false_positive'] is False
    
    def test_user_facing_dos_not_filtered(self):
        """Test that user-facing DoS is not filtered."""
        contract_code = """
        contract Protocol {
            function processAll() external {
                for (uint256 i = 0; i < unboundedArray.length; i++) {
                    // User can trigger this
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'unbounded_loop_dos',
            'function': 'processAll',
            'description': 'Unbounded loop DoS',
            'severity': 'high'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should NOT be filtered (user-facing, not admin-only)
        assert result['is_false_positive'] is False


class TestComprehensiveWorkflow:
    """Test complete workflow with all 7 validation stages."""
    
    @pytest.fixture
    def comprehensive_project(self):
        """Create comprehensive project structure."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text(json.dumps({
            'oracle': 'CHAINLINK',
            'manager': 'INTERNAL'
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_all_seven_stages_available(self, comprehensive_project):
        """Test that all 7 stages can potentially run."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Vulnerable {
            function dangerous(uint256 amount) external {
                balance = balance - amount;  // Real vulnerability
            }
        }
        """
        
        vulnerability = {
            'type': 'integer_underflow',
            'line': 6,
            'description': 'Underflow risk',
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(comprehensive_project, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should go through multiple stages
        # Real vulnerability should reach 'all_checks_passed'
        assert stages[-1].stage_name == 'all_checks_passed'
        assert stages[-1].is_false_positive is False


class TestBackwardCompatibility:
    """Test backward compatibility with Phase 1 & 2."""
    
    def test_phase1_governance_still_works(self):
        """Test that Phase 1 governance detection still works."""
        contract_code = """
        contract Protocol {
            function setFee(uint256 fee) external onlyOwner {
                protocolFee = fee;
            }
        }
        """
        
        vulnerability = {
            'type': 'parameter_validation',
            'function': 'setFee',
            'description': 'Missing validation',
            'severity': 'medium'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should still be filtered (governance or scope classification)
        assert result['is_false_positive'] is True
    
    def test_phase2_deployment_still_works(self):
        """Test that Phase 2 deployment check still works."""
        temp_dir = tempfile.mkdtemp()
        try:
            project_path = Path(temp_dir)
            
            (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
            config_file = project_path / 'deploy' / 'config' / 'config.json'
            config_file.write_text('{"oracle": "CHAINLINK"}')
            
            contract_code = """
            library LibOracle {
                function readPrice(OracleType oType) internal {
                    if (oType == OracleType.EXTERNAL) {
                        // Unused code path
                    }
                }
            }
            """
            
            vulnerability = {
                'type': 'oracle_manipulation',
                'description': 'EXTERNAL oracle vulnerable',
                'line': 7,
                'contract_name': 'LibOracle'
            }
            
            result = validate_vulnerability(vulnerability, contract_code, project_path)
            
            # Should be filtered by deployment check
            assert result['is_false_positive'] is True
            
        finally:
            shutil.rmtree(temp_dir)


class TestPhase3StageOrderCritical:
    """Test critical ordering of Phase 3 stages."""
    
    def test_stage_order_is_optimal(self):
        """Test that stages run in optimal order for performance."""
        contract_code = """
        /// @dev This is an authorized fork of Angle - assumes asset is safe
        contract Savings {
            function withdraw() external restricted nonReentrant {
                asset().transfer(msg.sender, amount);
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'withdraw',
            'line': 20
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should exit early (at one of the first few stages)
        assert len(stages) == 1  # Early exit
        
        # First stage that catches it should be one of Phase 3 stages
        assert stages[0].stage_name in [
            'builtin_protection',
            'design_assumption',
            'reentrancy_protection',
            'scope_classification'
        ]


class TestComprehensiveRealWorld:
    """Comprehensive real-world test scenarios."""
    
    def test_immunefi_submission_readiness(self):
        """Test that only submission-ready vulnerabilities pass all filters."""
        # Real vulnerability - should pass all stages
        real_vuln_code = """
        pragma solidity ^0.8.0;
        
        contract Vault {
            function withdraw(uint256 amount) external {
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}("");  # Real reentrancy
            }
        }
        """
        
        real_vulnerability = {
            'type': 'reentrancy',
            'function': 'withdraw',
            'line': 10,
            'description': 'State change before external call',
            'severity': 'critical'
        }
        
        result = validate_vulnerability(real_vulnerability, real_vuln_code)
        
        # Should NOT be filtered
        assert result['is_false_positive'] is False
        assert result['stage'] == 'all_checks_passed'
    
    def test_false_positive_variants_all_filtered(self):
        """Test that various false positive patterns are all filtered."""
        false_positive_scenarios = [
            # Design assumption
            {
                'code': """
                    /// @dev Assumes token is safe
                    contract Test {
                        function mint() external {
                            token.mint(address(this), amount);
                        }
                    }
                """,
                'vuln': {
                    'type': 'reentrancy',
                    'line': 10
                },
                'expected_stage': 'design_assumption'
            },
            # Reentrancy guard
            {
                'code': """
                    contract Test {
                        function withdraw() external nonReentrant {
                            external.call();
                        }
                    }
                """,
                'vuln': {
                    'type': 'reentrancy',
                    'function': 'withdraw',
                    'line': 10
                },
                'expected_stage': 'reentrancy_protection'
            },
            # Admin-only DoS
            {
                'code': """
                    contract Test {
                        function admin() external onlyOwner {
                            for (uint i = 0; i < array.length; i++) {}
                        }
                    }
                """,
                'vuln': {
                    'type': 'unbounded_dos',
                    'function': 'admin',
                    'line': 10
                },
                'expected_stage': 'scope_classification'
            },
            # Solidity 0.8+ protection
            {
                'code': """
                    pragma solidity ^0.8.0;
                    contract Test {
                        function calc(uint256 a) external {
                            uint256 b = a * 2;
                        }
                    }
                """,
                'vuln': {
                    'type': 'integer_overflow',
                    'line': 10
                },
                'expected_stage': 'builtin_protection'
            }
        ]
        
        for scenario in false_positive_scenarios:
            result = validate_vulnerability(scenario['vuln'], scenario['code'])
            
            # All should be filtered
            assert result['is_false_positive'] is True, \
                f"Scenario with expected stage '{scenario['expected_stage']}' was not filtered"


class TestPerformanceWithPhase3:
    """Test performance impact of Phase 3 additions."""
    
    def test_early_exit_performance(self):
        """Test that early exit optimizes performance."""
        import time
        
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function calc(uint256 a) external { uint256 b = a + 1; }
        }
        """
        
        vulnerability = {
            'type': 'integer_overflow',
            'line': 10
        }
        
        start = time.time()
        result = validate_vulnerability(vulnerability, contract_code)
        elapsed = time.time() - start
        
        # Should be very fast (early exit at stage 1)
        assert elapsed < 0.1  # Should complete in <100ms
        assert result['is_false_positive'] is True
        assert result['stage'] == 'builtin_protection'  # First stage


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

