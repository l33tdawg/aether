#!/usr/bin/env python3
"""
Comprehensive tests for Phase 1-3 validation improvements.

Tests cover:
- Phase 1: Code-description mismatch, enhanced access control, parameter origin
- Phase 2: Exploitability scoring and front-running detection
- Phase 3: Realistic impact calculation and severity adjustment
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.validation_pipeline import ValidationPipeline, ValidationStage


class TestPhase1CodeDescriptionMismatch:
    """Test Phase 1: Code-Description Mismatch Detection"""
    
    def test_decode_on_encode_operation(self):
        """Should filter: Claims 'decoding' but code only has abi.encode"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function process(address sender) external {
                bytes memory data = abi.encode(sender, msg.sender);
                emit Event(data);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'unvalidated_decoding',
            'description': 'ABI decode without validation',
            'code_snippet': 'bytes memory data = abi.encode(sender, msg.sender);',
            'line_number': 4,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "code_description_mismatch"
        assert "encoding" in results[0].reasoning.lower()
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_overflow_with_safemath(self):
        """Should filter: Claims overflow but SafeMath is used"""
        contract_code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/utils/math/SafeMath.sol";
        contract Test {
            using SafeMath for uint256;
            function add(uint256 a, uint256 b) external pure returns (uint256) {
                return a.add(b);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Potential overflow in addition',
            'code_snippet': 'return a.add(b);',
            'line_number': 6,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert "SafeMath" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_reentrancy_on_view_function(self):
        """Should filter: Claims reentrancy but function is view"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function getBalance() external view returns (uint256) {
                return address(this).balance;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'reentrancy',
            'description': 'Potential reentrancy attack',
            'code_snippet': 'function getBalance() external view returns (uint256) {',
            'line_number': 3,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert "view" in results[0].reasoning.lower()
        print(f"✓ Test passed: {results[0].reasoning}")


class TestPhase1EnhancedAccessControl:
    """Test Phase 1: Enhanced Access Control Chain Detection"""
    
    def test_custom_restricted_modifier(self):
        """Should filter: Function with 'restricted' modifier"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            modifier restricted() {
                require(_checkCanCall(msg.sender, msg.data), "Unauthorized");
                _;
            }
            
            function setParameter(uint256 value) external restricted {
                parameter = value;
            }
            
            function _checkCanCall(address caller, bytes calldata data) internal view returns (bool) {
                return caller == owner;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'access_control',
            'description': 'Parameter can be set without proper authorization',
            'code_snippet': 'function setParameter(uint256 value) external restricted {',
            'function': 'setParameter',
            'line_number': 8,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "enhanced_access_control"
        assert "restricted" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_onlyTrustedOrRestricted_modifier(self):
        """Should filter: Complex modifier like onlyTrustedOrRestricted"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            modifier onlyTrustedOrRestricted() {
                if (!isTrusted[msg.sender] && !_checkCanCall(msg.sender, msg.data)) {
                    revert NotAuthorized();
                }
                _;
            }
            
            function setTargetExposure(uint64 target) external onlyTrustedOrRestricted {
                targetExposure = target;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'parameter_validation',
            'description': 'Target exposure can be set without validation',
            'code_snippet': 'function setTargetExposure(uint64 target) external onlyTrustedOrRestricted {',
            'function': 'setTargetExposure',
            'line_number': 10,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert "onlyTrustedOrRestricted" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")


class TestPhase1ParameterOrigin:
    """Test Phase 1: Parameter Origin Detection (Admin-Configured vs User-Controlled)"""
    
    def test_admin_configured_yieldBearingAsset(self):
        """Should filter: yieldBearingAsset must be pre-configured by admin"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract GenericHarvester {
            mapping(address => YieldBearingParams) public yieldBearingData;
            
            function setYieldBearingAssetData(
                address yieldBearingAsset,
                address asset,
                uint64 targetExposure
            ) external restricted {
                yieldBearingData[yieldBearingAsset].asset = asset;
                yieldBearingData[yieldBearingAsset].targetExposure = targetExposure;
            }
            
            function harvest(address yieldBearingAsset) public {
                YieldBearingParams memory params = yieldBearingData[yieldBearingAsset];
                // Use params
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'oracle_manipulation',
            'description': 'The harvest function allows users to specify an arbitrary yieldBearingAsset address',
            'code_snippet': 'YieldBearingParams memory params = yieldBearingData[yieldBearingAsset];',
            'function': 'harvest',
            'line_number': 15,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "parameter_origin"
        assert "pre-configured" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_user_controlled_parameter(self):
        """Should NOT filter: Parameter is actually user-controlled"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function transfer(address recipient, uint256 amount) external {
                require(recipient != address(0), "Zero address");
                balances[msg.sender] -= amount;
                balances[recipient] += amount;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'input_validation',
            'description': 'User can pass arbitrary recipient address',
            'code_snippet': 'function transfer(address recipient, uint256 amount) external {',
            'function': 'transfer',
            'line_number': 3,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should NOT be filtered as false positive
        assert len(results) > 0
        # Should pass through all checks
        last_result = results[-1]
        assert last_result.stage_name == "all_checks_passed" or last_result.is_false_positive == False
        print(f"✓ Test passed: User-controlled parameter correctly identified as potentially vulnerable")


class TestPhase2Exploitability:
    """Test Phase 2: Exploitability Scoring and Front-Running Detection"""
    
    def test_trusted_function_not_frontrunnable(self):
        """Should filter: onlyTrusted function without front-running vector (Finding #10)"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract MultiBlockHarvester {
            modifier onlyTrusted() {
                require(isTrusted[msg.sender], "Not trusted");
                _;
            }
            
            function harvest(address yieldBearingAsset) external onlyTrusted {
                try parallelizer.updateOracle(yieldBearingAsset) {} catch {}
                _rebalance(yieldBearingAsset);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'on_chain_oracle_manipulation',
            'description': 'The contract relies on parallelizer.updateOracle which can be manipulated',
            'code_snippet': 'try parallelizer.updateOracle(yieldBearingAsset) {} catch {}',
            'function': 'harvest',
            'line_number': 9,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "exploitability_check"
        assert "onlyTrusted" in results[0].reasoning
        assert "not externally exploitable" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_trusted_function_frontrunnable_balanceOf(self):
        """Should NOT filter: onlyTrusted function IS front-runnable via balanceOf (Finding #11)"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract MultiBlockHarvester {
            modifier onlyTrusted() {
                require(isTrusted[msg.sender], "Not trusted");
                _;
            }
            
            function harvest(address yieldBearingAsset) external onlyTrusted {
                uint256 amountOut = parallelizer.swap(amount);
                if (yieldBearingAsset == USDM) amountOut = IERC20(yieldBearingAsset).balanceOf(address(this));
                _checkSlippage(amountOut);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'oracle_manipulation',
            'description': 'Slippage protection can be bypassed by front-running with USDM tokens',
            'code_snippet': 'amountOut = IERC20(yieldBearingAsset).balanceOf(address(this));',
            'function': 'harvest',
            'line_number': 10,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should NOT be filtered - this is exploitable via front-running
        assert len(results) > 0
        last_result = results[-1]
        assert last_result.is_false_positive == False or last_result.stage_name == "all_checks_passed"
        print(f"✓ Test passed: Front-runnable vulnerability correctly kept (not filtered)")
    
    def test_public_function_no_access_control(self):
        """Should NOT filter: Public function with no access control is directly exploitable"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function withdraw(uint256 amount) external {
                payable(msg.sender).transfer(amount);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'access_control',
            'description': 'Anyone can call withdraw function',
            'code_snippet': 'function withdraw(uint256 amount) external {',
            'function': 'withdraw',
            'line_number': 3,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should NOT be filtered
        assert len(results) > 0
        last_result = results[-1]
        assert last_result.is_false_positive == False
        print(f"✓ Test passed: Unprotected function correctly identified as exploitable")


class TestPhase3RealisticImpact:
    """Test Phase 3: Realistic Impact Calculation"""
    
    def test_precision_loss_with_1e27_divisor(self):
        """Should filter: Precision loss with 1e27 divisor has negligible impact"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            uint256 constant BASE_27 = 1e27;
            
            function calculate(uint256 amount) external view returns (uint256) {
                uint256 normalized = (amount * BASE_27) / total;
                return (normalized * total) / BASE_27;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'precision_loss_division',
            'description': 'Division operation causes precision loss',
            'code_snippet': 'return (normalized * total) / BASE_27;',
            'function': 'calculate',
            'line_number': 7,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "realistic_impact"
        assert "dust amounts" in results[0].reasoning or "negligible" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_view_function_high_severity(self):
        """Should filter: View function marked as high severity"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function computeValue(uint256 input) external view returns (uint256) {
                return input * 2;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'arithmetic',
            'description': 'Potential overflow in multiplication',
            'code_snippet': 'return input * 2;',
            'function': 'computeValue',
            'line_number': 4,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert "view" in results[0].reasoning.lower() or "read-only" in results[0].reasoning.lower()
        print(f"✓ Test passed: {results[0].reasoning}")
    
    def test_solidity_08_overflow_without_unchecked(self):
        """Should filter: Overflow claim in Solidity 0.8+ without unchecked block"""
        contract_code = """
        pragma solidity 0.8.28;
        contract Test {
            function add(uint256 a, uint256 b) external pure returns (uint256) {
                return a + b;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Addition can overflow',
            'code_snippet': 'return a + b;',
            'function': 'add',
            'line_number': 4,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert "0.8" in results[0].reasoning
        print(f"✓ Test passed: {results[0].reasoning}")


class TestRealWorldScenarios:
    """Test with actual vulnerabilities from Parallel audit"""
    
    def test_finding_1_and_2_arbitrary_vault(self):
        """Findings #1 & #2: Should filter - yieldBearingAsset is admin-configured"""
        contract_code = """
        pragma solidity 0.8.28;
        contract GenericHarvester {
            mapping(address => YieldBearingParams) public yieldBearingData;
            
            function setYieldBearingAssetData(
                address yieldBearingAsset,
                address asset,
                uint64 targetExposure
            ) external restricted {
                yieldBearingData[yieldBearingAsset].asset = asset;
            }
            
            modifier restricted() {
                require(_checkCanCall(msg.sender, msg.data), "Unauthorized");
                _;
            }
            
            function harvest(address yieldBearingAsset, uint256 scale, bytes calldata extraData) public {
                YieldBearingParams memory yieldBearingInfo = yieldBearingData[yieldBearingAsset];
                _adjustYieldExposure(yieldBearingInfo);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'oracle_manipulation',
            'description': 'The harvest function allows users to specify an arbitrary IERC4626 vault (tokenOut)',
            'code_snippet': 'YieldBearingParams memory yieldBearingInfo = yieldBearingData[yieldBearingAsset];',
            'function': 'harvest',
            'line_number': 18,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        # Should be caught by parameter_origin check
        assert results[0].stage_name in ["parameter_origin", "enhanced_access_control"]
        print(f"✓ Test passed (Finding #1-2): {results[0].reasoning}")
    
    def test_finding_3_encode_not_decode(self):
        """Finding #3: Should filter - claims decoding but code shows encoding"""
        contract_code = """
        pragma solidity 0.8.28;
        contract Test {
            function flashLoan() external {
                bytes memory data = abi.encode(msg.sender, increase, yieldBearingAsset);
                flashloan.flashLoan(this, tokenP, amount, data);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'unvalidated_decoding',
            'description': 'ABI encode operation',
            'code_snippet': 'abi.encode(msg.sender, increase, yieldBearingAsset)',
            'line_number': 4,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "code_description_mismatch"
        print(f"✓ Test passed (Finding #3): {results[0].reasoning}")
    
    def test_finding_6_precision_loss_1e9(self):
        """Finding #6: Should filter - precision loss with 1e9 is negligible"""
        contract_code = """
        pragma solidity 0.8.28;
        contract BaseHarvester {
            function _computeRebalanceAmount() internal view returns (uint256) {
                uint256 targetExposureScaled = yieldBearingInfo.targetExposure * stablecoinsIssued;
                amount = stablecoinsFromYieldBearingAsset - targetExposureScaled / 1e9;
                return amount;
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'precision_loss_division',
            'description': 'The division targetExposureScaled / 1e9 is prone to precision loss',
            'code_snippet': 'amount = stablecoinsFromYieldBearingAsset - targetExposureScaled / 1e9;',
            'function': '_computeRebalanceAmount',
            'line_number': 5,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name == "realistic_impact"
        print(f"✓ Test passed (Finding #6): {results[0].reasoning}")
    
    def test_finding_10_onlyTrusted_oracle(self):
        """Finding #10: Should filter - onlyTrusted function not externally exploitable"""
        contract_code = """
        pragma solidity 0.8.28;
        contract MultiBlockHarvester {
            mapping(address => bool) public isTrusted;
            
            modifier onlyTrusted() {
                require(isTrusted[msg.sender], "Not trusted");
                _;
            }
            
            function harvest(address yieldBearingAsset, uint256 scale, bytes calldata) external onlyTrusted {
                try parallelizer.updateOracle(yieldBearingAsset) { } catch { }
                _rebalance(increase, yieldBearingAsset, yieldBearingInfo, amount);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'on_chain_oracle_manipulation',
            'description': 'The contract relies on parallelizer.updateOracle which can be manipulated',
            'code_snippet': 'try parallelizer.updateOracle(yieldBearingAsset) { } catch { }',
            'function': 'harvest',
            'line_number': 11,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert results[0].stage_name in ["exploitability_check", "enhanced_access_control"]
        assert "onlyTrusted" in results[0].reasoning or "not externally exploitable" in results[0].reasoning
        print(f"✓ Test passed (Finding #10): {results[0].reasoning}")
    
    def test_finding_11_frontrunnable_balanceOf(self):
        """Finding #11: Should NOT filter - front-runnable via balanceOf manipulation"""
        contract_code = """
        pragma solidity 0.8.28;
        contract MultiBlockHarvester {
            modifier onlyTrusted() {
                require(isTrusted[msg.sender], "Not trusted");
                _;
            }
            
            function harvest() external onlyTrusted {
                uint256 amountOut = parallelizer.swapExactInput(amount, 0, tokenP, yieldBearingAsset, address(this), block.timestamp);
                if (yieldBearingAsset == USDM) amountOut = IERC20(yieldBearingAsset).balanceOf(address(this));
                _checkSlippage(amount, amountOut);
            }
        }
        """
        
        vuln = {
            'vulnerability_type': 'oracle_manipulation',
            'description': 'MultiBlockHarvester can have slippage protection bypassed by front-running with USDM',
            'code_snippet': 'if (yieldBearingAsset == USDM) amountOut = IERC20(yieldBearingAsset).balanceOf(address(this));',
            'function': 'harvest',
            'line_number': 10,
            'severity': 'critical'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should NOT be filtered - front-runnable despite onlyTrusted
        assert len(results) > 0
        last_result = results[-1]
        assert last_result.is_false_positive == False
        print(f"✓ Test passed (Finding #11): Front-runnable vulnerability correctly kept")


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_missing_function_name(self):
        """Should handle gracefully when function name cannot be extracted"""
        contract_code = """
        pragma solidity ^0.8.0;
        contract Test {}
        """
        
        vuln = {
            'vulnerability_type': 'unknown',
            'description': 'Some vulnerability',
            'code_snippet': 'some code',
            'line_number': 2,
            'severity': 'medium'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should complete without error
        assert len(results) > 0
        print(f"✓ Test passed: Handled missing function gracefully")
    
    def test_malformed_contract_code(self):
        """Should handle malformed contract code gracefully"""
        contract_code = "not valid solidity code"
        
        vuln = {
            'vulnerability_type': 'test',
            'description': 'Test vulnerability',
            'code_snippet': 'test',
            'line_number': 1,
            'severity': 'low'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        results = pipeline.validate(vuln)
        
        # Should complete without crashing
        assert len(results) > 0
        print(f"✓ Test passed: Handled malformed code gracefully")


def run_all_tests():
    """Run all test classes and report results."""
    print("=" * 70)
    print("ENHANCED VALIDATION PIPELINE - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    print()
    
    test_classes = [
        ("Phase 1: Code-Description Mismatch", TestPhase1CodeDescriptionMismatch),
        ("Phase 1: Enhanced Access Control", TestPhase1EnhancedAccessControl),
        ("Phase 1: Parameter Origin Detection", TestPhase1ParameterOrigin),
        ("Phase 2: Exploitability Scoring", TestPhase2Exploitability),
        ("Phase 3: Realistic Impact", TestPhase3RealisticImpact),
        ("Edge Cases", TestEdgeCases)
    ]
    
    total_passed = 0
    total_failed = 0
    
    for test_group_name, test_class in test_classes:
        print(f"\n{'=' * 70}")
        print(f"{test_group_name}")
        print(f"{'=' * 70}\n")
        
        test_instance = test_class()
        test_methods = [m for m in dir(test_instance) if m.startswith('test_')]
        
        for test_method_name in test_methods:
            test_method = getattr(test_instance, test_method_name)
            test_display_name = test_method_name.replace('_', ' ').title()
            
            try:
                print(f"Running: {test_display_name}")
                test_method()
                total_passed += 1
                print()
            except AssertionError as e:
                print(f"✗ FAILED: {e}")
                total_failed += 1
                print()
            except Exception as e:
                print(f"✗ ERROR: {e}")
                total_failed += 1
                print()
    
    print("=" * 70)
    print(f"TEST SUMMARY")
    print("=" * 70)
    print(f"Total Passed: {total_passed}")
    print(f"Total Failed: {total_failed}")
    print(f"Success Rate: {total_passed}/{total_passed + total_failed} ({100 * total_passed/(total_passed + total_failed) if (total_passed + total_failed) > 0 else 0:.1f}%)")
    print("=" * 70)
    
    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

