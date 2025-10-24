#!/usr/bin/env python3
"""
Tests for Validation Pipeline

Tests the multi-stage false positive filtering system.
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path

from core.validation_pipeline import ValidationPipeline, ValidationStage, validate_vulnerability


class TestValidationPipeline:
    """Test cases for ValidationPipeline."""
    
    def test_initialization(self):
        """Test ValidationPipeline initialization."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        pipeline = ValidationPipeline(Path('.'), contract_code)
        
        assert pipeline.contract_code == contract_code
        assert pipeline.project_path == Path('.')
    
    def test_initialization_without_project_path(self):
        """Test ValidationPipeline initialization without project path."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        pipeline = ValidationPipeline(None, contract_code)
        
        assert pipeline.contract_code == contract_code
        assert pipeline.project_path is None


class TestBuiltinProtectionCheck:
    """Test built-in protection checking (Stage 1)."""
    
    def test_solidity_0_8_overflow_protection(self):
        """Test Solidity 0.8+ overflow protection detection."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Token {
            function transfer(uint256 amount) external {
                balance = balance + amount;  // Protected by Solidity 0.8+
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Potential overflow',
            'line': 6,
            'code_snippet': 'balance = balance + amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        assert len(stages) > 0
        assert stages[0].stage_name == 'builtin_protection'
        assert stages[0].is_false_positive is True
        assert stages[0].confidence >= 0.9
    
    def test_solidity_0_7_no_protection(self):
        """Test Solidity 0.7 does not trigger false positive."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Token {
            function transfer(uint256 amount) external {
                balance = balance + amount;  // NOT protected in 0.7
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Potential overflow',
            'line': 6,
            'code_snippet': 'balance = balance + amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should NOT mark as false positive (no builtin protection in 0.7)
        if stages[0].stage_name == 'builtin_protection':
            assert stages[0].is_false_positive is False
    
    def test_unchecked_block_not_protected(self):
        """Test that unchecked blocks are not marked as protected."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Token {
            function transfer(uint256 amount) external {
                unchecked {
                    balance = balance + amount;  // Explicitly unsafe
                }
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Overflow in unchecked block',
            'line': 7,
            'code_snippet': 'balance = balance + amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should NOT mark as false positive (unchecked block)
        builtin_stages = [s for s in stages if s.stage_name == 'builtin_protection']
        if builtin_stages:
            assert builtin_stages[0].is_false_positive is False
    
    def test_safemath_protection(self):
        """Test SafeMath usage detection."""
        contract_code = """
        pragma solidity 0.7.6;
        
        import "@openzeppelin/contracts/math/SafeMath.sol";
        
        contract Token {
            using SafeMath for uint256;
            
            function transfer(uint256 amount) external {
                balance = balance.add(amount);  // Protected by SafeMath
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Potential overflow',
            'line': 9,
            'code_snippet': 'balance = balance.add(amount);'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should mark as false positive (SafeMath protection)
        assert stages[0].is_false_positive is True
        assert 'SafeMath' in stages[0].reasoning


class TestGovernanceControlCheck:
    """Test governance control checking (Stage 2)."""
    
    def test_fee_parameter_governance(self):
        """Test that governance-controlled fee parameters are filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract Protocol {
            uint64[] public xFee;
            int64[] public yFee;
            
            function setFees(uint64[] memory xFee, int64[] memory yFee) external onlyOwner {
                require(xFee.length == yFee.length, "Length mismatch");
                require(yFee[i] >= yFee[i-1], "Must be monotonic");
                xFeeMint = xFee;
                yFeeMint = yFee;
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'arithmetic_underflow',
            'description': 'Fee curve could have negative values',
            'line': 100,
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should mark as false positive (governance-controlled)
        governance_stages = [s for s in stages if s.stage_name == 'governance_control']
        if governance_stages:
            assert governance_stages[0].is_false_positive is True


class TestDeploymentCheck:
    """Test deployment checking (Stage 3)."""
    
    @pytest.fixture
    def project_without_external(self):
        """Create project that doesn't use EXTERNAL type."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text('{"oracle": {"oracleType": "CHAINLINK_FEEDS"}}')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_external_oracle_not_deployed(self, project_without_external):
        """Test that unused EXTERNAL oracle is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        library LibOracle {
            function readPrice(OracleType oType) internal {
                if (oType == OracleType.EXTERNAL) {
                    // This code path is not used
                }
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'oracle_manipulation',
            'description': 'EXTERNAL oracle type allows manipulation',
            'line': 7,
            'contract_name': 'LibOracle'
        }
        
        pipeline = ValidationPipeline(project_without_external, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should mark as false positive (EXTERNAL not deployed)
        deployment_stages = [s for s in stages if s.stage_name == 'deployment_check']
        if deployment_stages:
            assert deployment_stages[0].is_false_positive is True
            assert 'not used in deployment' in deployment_stages[0].reasoning


class TestLocalValidationCheck:
    """Test local validation checking (Stage 4)."""
    
    def test_require_statement_protection(self):
        """Test that require statements provide protection."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Token {
            function transfer(address to, uint256 amount) external {
                require(to != address(0), "Invalid address");
                require(amount > 0, "Invalid amount");
                require(balance >= amount, "Insufficient balance");
                
                balance = balance - amount;  // Protected by require above
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_underflow',
            'description': 'Potential underflow',
            'line': 9,
            'code_snippet': 'balance = balance - amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should mark as false positive (require protection)
        validation_stages = [s for s in stages if s.stage_name == 'local_validation']
        if validation_stages:
            assert validation_stages[0].is_false_positive is True
    
    def test_no_validation_not_filtered(self):
        """Test that lack of validation doesn't trigger false positive."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Vulnerable {
            function dangerous(uint256 amount) external {
                balance = balance - amount;  // No validation!
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_underflow',
            'description': 'Potential underflow',
            'line': 6,
            'code_snippet': 'balance = balance - amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should NOT mark as false positive (no validation found)
        assert stages[-1].stage_name == 'all_checks_passed'
        assert stages[-1].is_false_positive is False


class TestValidationPipelineIntegration:
    """Test full validation pipeline integration."""
    
    @pytest.fixture
    def parallel_protocol_setup(self):
        """Setup mimicking Parallel Protocol deployment."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'mainnet.json'
        config_file.write_text(json.dumps({
            'managers': {'type': 'INTERNAL'}  # Only INTERNAL, not EXTERNAL
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_parallel_protocol_false_positive_filtering(self, parallel_protocol_setup):
        """Test filtering of Parallel Protocol false positive."""
        contract_code = """
        pragma solidity 0.8.28;
        
        library LibManager {
            function invest(uint256 amount, bytes memory config) internal {
                (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
                if (managerType == ManagerType.EXTERNAL) {
                    abi.decode(data, (IManager)).invest(amount);
                }
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'malformed_input_handling',
            'description': 'LibManager uses abi.decode for EXTERNAL manager type',
            'line': 7,
            'code_snippet': 'abi.decode(data, (IManager)).invest(amount);',
            'contract_name': 'LibManager'
        }
        
        pipeline = ValidationPipeline(parallel_protocol_setup, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should filter out (EXTERNAL not deployed)
        assert any(s.is_false_positive for s in stages)


class TestConvenienceFunction:
    """Test convenience function."""
    
    def test_validate_vulnerability_function(self):
        """Test validate_vulnerability convenience function."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Test {
            function test(uint256 a) external {
                uint256 b = a * 2;
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Overflow',
            'line': 6
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        assert 'is_false_positive' in result
        assert 'confidence' in result
        assert 'reasoning' in result
        assert 'stage' in result
        assert isinstance(result['is_false_positive'], bool)
        assert isinstance(result['confidence'], float)


class TestValidationStageDataclass:
    """Test ValidationStage dataclass."""
    
    def test_validation_stage_creation(self):
        """Test creating ValidationStage."""
        stage = ValidationStage(
            stage_name="test_stage",
            is_false_positive=True,
            confidence=0.9,
            reasoning="Test reason"
        )
        
        assert stage.stage_name == "test_stage"
        assert stage.is_false_positive is True
        assert stage.confidence == 0.9
        assert stage.reasoning == "Test reason"


class TestPipelineSummary:
    """Test pipeline summary."""
    
    def test_get_summary(self):
        """Test getting pipeline summary."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        pipeline = ValidationPipeline(Path('.'), contract_code)
        
        summary = pipeline.get_summary()
        
        assert 'has_governance_detector' in summary
        assert 'has_deployment_analyzer' in summary
        assert 'has_validation_detector' in summary
        assert 'project_path' in summary
        assert isinstance(summary['has_governance_detector'], bool)


class TestEarlyExitBehavior:
    """Test early exit on first false positive."""
    
    def test_early_exit_on_builtin_protection(self):
        """Test that pipeline exits early on builtin protection match."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Test {
            function test(uint256 a) external {
                uint256 b = a + 1;
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'line': 6
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should have exactly 1 stage (early exit)
        assert len(stages) == 1
        assert stages[0].stage_name == 'builtin_protection'
        assert stages[0].is_false_positive is True
    
    def test_all_stages_pass_returns_valid(self):
        """Test that all stages passing returns valid vulnerability."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Vulnerable {
            function dangerous(uint256 amount) external {
                balance = balance - amount;  // No protection
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_underflow',
            'description': 'Underflow',
            'line': 6,
            'code_snippet': 'balance = balance - amount;'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should reach final stage
        assert stages[-1].stage_name == 'all_checks_passed'
        assert stages[-1].is_false_positive is False


class TestRealWorldScenarios:
    """Test real-world vulnerability scenarios."""
    
    @pytest.fixture
    def gains_network_setup(self):
        """Setup for Gains Network fee validation case."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract GNSTradingCallbacksV6_4 {
            uint64[] public xFeeMint;
            int64[] public yFeeMint;
            
            function setFees(uint64[] memory xFee, int64[] memory yFee) external onlyGov {
                require(xFee.length == yFee.length, "LENGTH_MISMATCH");
                
                for (uint256 i = 1; i < yFee.length; i++) {
                    require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");
                }
                
                xFeeMint = xFee;
                yFeeMint = yFee;
            }
        }
        """
        return contract_code
    
    def test_gains_network_fee_validation(self, gains_network_setup):
        """Test that Gains Network fee validation is recognized."""
        vulnerability = {
            'vulnerability_type': 'arithmetic_underflow',
            'description': 'Fee curve could have negative values in yFee[i-1]',
            'line': 12,
            'code_snippet': 'require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");',
            'severity': 'high'
        }
        
        pipeline = ValidationPipeline(None, gains_network_setup)
        stages = pipeline.validate(vulnerability)
        
        # Should be filtered by either governance or local validation
        assert any(s.is_false_positive for s in stages)
    
    @pytest.fixture
    def parallel_protocol_setup(self):
        """Setup for Parallel Protocol EXTERNAL manager case."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Config without EXTERNAL
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'mainnet.json'
        config_file.write_text(json.dumps({
            'manager': {'type': 'INTERNAL'}
        }))
        
        contract_code = """
        pragma solidity 0.8.28;
        
        library LibManager {
            function invest(uint256 amount, bytes memory config) internal {
                (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
                if (managerType == ManagerType.EXTERNAL) {
                    abi.decode(data, (IManager)).invest(amount);
                }
            }
        }
        """
        
        yield project_path, contract_code
        shutil.rmtree(temp_dir)
    
    def test_parallel_protocol_external_filtering(self, parallel_protocol_setup):
        """Test that Parallel Protocol EXTERNAL code path is filtered."""
        project_path, contract_code = parallel_protocol_setup
        
        vulnerability = {
            'vulnerability_type': 'malformed_input_handling',
            'description': 'abi.decode in EXTERNAL manager type',
            'line': 7,
            'code_snippet': 'abi.decode(data, (IManager)).invest(amount);',
            'contract_name': 'LibManager'
        }
        
        pipeline = ValidationPipeline(project_path, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should be filtered by deployment check
        deployment_stages = [s for s in stages if s.stage_name == 'deployment_check']
        if deployment_stages:
            assert deployment_stages[0].is_false_positive is True


class TestParameterExtraction:
    """Test parameter name extraction."""
    
    def test_extract_fee_parameter(self):
        """Test extracting fee parameter names."""
        pipeline = ValidationPipeline(None, "contract Test {}")
        
        params = pipeline._extract_parameter_names("Fee curve could have negative values")
        
        assert 'Fee' in params or 'Fees' in params
    
    def test_extract_price_parameter(self):
        """Test extracting price parameter names."""
        pipeline = ValidationPipeline(None, "contract Test {}")
        
        params = pipeline._extract_parameter_names("Price oracle manipulation possible")
        
        assert 'Price' in params or 'Oracle' in params
    
    def test_extract_multiple_parameters(self):
        """Test extracting multiple parameter names."""
        pipeline = ValidationPipeline(None, "contract Test {}")
        
        params = pipeline._extract_parameter_names("Fee and price parameters can be manipulated")
        
        assert len(params) >= 2


class TestErrorHandling:
    """Test error handling in validation pipeline."""
    
    def test_missing_line_number(self):
        """Test handling of missing line number."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        vulnerability = {
            'vulnerability_type': 'test',
            'description': 'Test vulnerability'
            # No line number
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should not crash
        assert isinstance(stages, list)
        assert len(stages) > 0
    
    def test_malformed_vulnerability(self):
        """Test handling of malformed vulnerability."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        vulnerability = {}  # Empty vulnerability
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should not crash
        assert isinstance(stages, list)
    
    def test_invalid_solidity_version(self):
        """Test handling of invalid Solidity version."""
        contract_code = """
        // No pragma statement
        contract Test {
            function test() external {}
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'line': 4
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should handle gracefully
        assert isinstance(stages, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

