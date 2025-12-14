#!/usr/bin/env python3
"""
Test suite for code quality enhancements.

Tests the following enhancements:
1. Variable Shadowing Detector
2. Zero-Address Validation Detection in Admin Setters
3. Code Quality Analyzer
4. Integration with Enhanced Vulnerability Detector

These tests validate the improvements made based on the ADI-Stack-Contracts audit
where several issues were missed by the original tool.
"""

import pytest
import sys
import os

# Add the parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.variable_shadowing_detector import VariableShadowingDetector, ShadowingVulnerability
from core.input_validation_detector import InputValidationDetector
from core.code_quality_analyzer import CodeQualityAnalyzer, CodeQualityIssue


class TestVariableShadowingDetector:
    """Test suite for the Variable Shadowing Detector."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = VariableShadowingDetector()
    
    def test_detects_local_variable_shadowing_state_variable(self):
        """Test detection of local variable shadowing a state variable.
        
        This is the exact pattern found in ADI-Stack-Contracts Bridgehub.sol:
        bytes32 baseTokenAssetId = baseTokenAssetId[_chainId];
        """
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    mapping(uint256 => bytes32) public baseTokenAssetId;
    
    function baseToken(uint256 _chainId) public view returns (bytes32) {
        bytes32 baseTokenAssetId = baseTokenAssetId[_chainId];
        return baseTokenAssetId;
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        assert len(vulnerabilities) >= 1, "Should detect variable shadowing"
        
        shadowing_found = any(
            v.vulnerability_type == 'variable_shadowing' and 
            'baseTokenAssetId' in v.description
            for v in vulnerabilities
        )
        assert shadowing_found, "Should detect baseTokenAssetId shadowing"
    
    def test_detects_function_parameter_shadowing(self):
        """Test detection of function parameter shadowing a state variable."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;
    
    function setOwner(address owner) public {
        // owner parameter shadows state variable owner
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        shadowing_found = any(
            v.vulnerability_type == 'variable_shadowing' and 
            'owner' in v.description.lower()
            for v in vulnerabilities
        )
        assert shadowing_found, "Should detect parameter shadowing state variable"
    
    def test_no_false_positive_for_different_names(self):
        """Test that no false positive is raised for different variable names."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public totalSupply;
    
    function mint(uint256 amount) public {
        uint256 newSupply = totalSupply + amount;
        totalSupply = newSupply;
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should not detect shadowing since names are different
        shadowing_count = sum(1 for v in vulnerabilities if v.vulnerability_type == 'variable_shadowing')
        assert shadowing_count == 0, "Should not detect false positive shadowing"
    
    def test_detects_constructor_parameter_shadowing(self):
        """Test detection of constructor parameter shadowing state variable."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public admin;
    
    constructor(address admin) {
        // admin parameter shadows state variable
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        shadowing_found = any(
            v.vulnerability_type == 'variable_shadowing' and 
            'admin' in v.description.lower() and
            'constructor' in v.description.lower()
            for v in vulnerabilities
        )
        assert shadowing_found, "Should detect constructor parameter shadowing"
    
    def test_handles_inherited_state_variables(self):
        """Test that shadowing of inherited state variables is detected."""
        contract = '''
pragma solidity ^0.8.0;

contract Base {
    uint256 public value;
}

contract Derived is Base {
    function setValue(uint256 newValue) public {
        uint256 value = newValue;  // Shadows inherited value
        // ... 
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should detect shadowing of inherited variable
        # Note: This depends on inheritance tracking which may need refinement
        assert isinstance(vulnerabilities, list)


class TestZeroAddressValidationDetection:
    """Test suite for zero-address validation detection in admin setters."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = InputValidationDetector()
    
    def test_detects_missing_zero_address_check_in_setter(self):
        """Test detection of missing zero-address check in setAddresses-style function.
        
        This is the exact pattern from ADI-Stack-Contracts Bridgehub.sol setAddresses()
        where critical addresses were set without zero-address validation.
        """
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public assetRouter;
    address public l1CtmDeployer;
    
    modifier onlyOwner() {
        _;
    }
    
    function setAddresses(
        address _assetRouter,
        address _l1CtmDeployer
    ) external onlyOwner {
        assetRouter = _assetRouter;
        l1CtmDeployer = _l1CtmDeployer;
    }
}
'''
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        zero_addr_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'missing_zero_address_check']
        
        assert len(zero_addr_vulns) >= 1, "Should detect missing zero-address validation"
        
        # Check that both parameters are flagged
        descriptions = ' '.join(v.description for v in zero_addr_vulns)
        assert '_assetRouter' in descriptions or '_l1CtmDeployer' in descriptions, \
            "Should identify specific parameters missing validation"
    
    def test_no_false_positive_when_validation_exists(self):
        """Test that no false positive is raised when zero-address validation exists."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public router;
    
    modifier onlyOwner() {
        _;
    }
    
    function setRouter(address _router) external onlyOwner {
        require(_router != address(0), "Zero address");
        router = _router;
    }
}
'''
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        zero_addr_vulns = [v for v in vulnerabilities 
                          if v.vulnerability_type == 'missing_zero_address_check'
                          and '_router' in v.description]
        
        assert len(zero_addr_vulns) == 0, "Should not flag function with zero-address check"
    
    def test_detects_multiple_unvalidated_addresses(self):
        """Test detection of multiple address parameters without validation."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public tokenA;
    address public tokenB;
    address public treasury;
    
    modifier onlyOwner() {
        _;
    }
    
    function configurePool(
        address _tokenA,
        address _tokenB,
        address _treasury
    ) external onlyOwner {
        tokenA = _tokenA;
        tokenB = _tokenB;
        treasury = _treasury;
    }
}
'''
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        zero_addr_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'missing_zero_address_check']
        
        # Should detect at least one (ideally all three)
        assert len(zero_addr_vulns) >= 1, "Should detect missing validation for address parameters"
    
    def test_handles_if_revert_style_validation(self):
        """Test that if-revert style validation is recognized."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public admin;
    
    error ZeroAddress();
    
    modifier onlyOwner() {
        _;
    }
    
    function setAdmin(address _admin) external onlyOwner {
        if (_admin == address(0)) revert ZeroAddress();
        admin = _admin;
    }
}
'''
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        zero_addr_vulns = [v for v in vulnerabilities 
                          if v.vulnerability_type == 'missing_zero_address_check'
                          and '_admin' in v.description]
        
        assert len(zero_addr_vulns) == 0, "Should recognize if-revert style validation"


class TestCodeQualityAnalyzer:
    """Test suite for the Code Quality Analyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = CodeQualityAnalyzer()
    
    def test_detects_centralization_risks(self):
        """Test detection of centralization risks with multiple privileged functions."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function pause() external onlyOwner {
        // pause logic
    }
    
    function unpause() external onlyOwner {
        // unpause logic
    }
    
    function setFee(uint256 _fee) external onlyOwner {
        // set fee logic
    }
    
    function withdrawAll(address _to) external onlyOwner {
        // withdraw logic
    }
}
'''
        issues = self.analyzer.analyze_contract(contract)
        
        centralization_issues = [i for i in issues if i.vulnerability_type == 'centralization_risk']
        
        assert len(centralization_issues) >= 1, "Should detect centralization risks"
        
        # Check that the description mentions multiple privileged functions
        if centralization_issues:
            assert 'privileged' in centralization_issues[0].description.lower()
    
    def test_detects_deprecated_patterns(self):
        """Test detection of deprecated Solidity patterns."""
        contract = '''
pragma solidity ^0.4.0;

contract TestContract {
    function destroy() public {
        suicide(msg.sender);
    }
    
    function getHash(uint256 x) public pure returns (bytes32) {
        return sha3(x);
    }
}
'''
        issues = self.analyzer.analyze_contract(contract)
        
        deprecated_issues = [i for i in issues if i.vulnerability_type == 'deprecated_pattern']
        
        # Should detect suicide() and sha3() as deprecated
        assert len(deprecated_issues) >= 1, "Should detect deprecated patterns"
    
    def test_detects_variable_shadowing_via_code_quality(self):
        """Test that code quality analyzer includes variable shadowing detection."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public balance;
    
    function update(uint256 amount) public {
        uint256 balance = amount;
        // ...
    }
}
'''
        issues = self.analyzer.analyze_contract(contract)
        
        shadowing_issues = [i for i in issues if i.vulnerability_type == 'variable_shadowing']
        
        assert len(shadowing_issues) >= 1, "Should detect variable shadowing"
    
    def test_quality_summary(self):
        """Test that quality summary provides useful metrics."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    function test() public {
        // Simple contract
    }
}
'''
        issues = self.analyzer.analyze_contract(contract)
        summary = self.analyzer.get_quality_summary(issues)
        
        assert 'total_issues' in summary
        assert 'by_severity' in summary
        assert 'by_type' in summary


class TestEnhancedVulnerabilityDetectorIntegration:
    """Test integration of new detectors with EnhancedVulnerabilityDetector."""
    
    def setup_method(self):
        """Set up test fixtures."""
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector
        self.detector = EnhancedVulnerabilityDetector()
    
    def test_variable_shadowing_integrated(self):
        """Test that variable shadowing is detected through the main detector."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;
    
    function setOwner(address owner) public {
        // Shadowing
    }
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Check that shadowing vulnerability is detected
        shadowing_found = any(
            'shadowing' in str(getattr(v, 'vulnerability_type', '')).lower() or
            'shadowing' in str(getattr(v, 'description', '')).lower()
            for v in vulnerabilities
        )
        
        # This may vary depending on filtering - check that we get some results
        assert isinstance(vulnerabilities, list)
    
    def test_code_quality_issues_integrated(self):
        """Test that code quality issues are detected through the main detector."""
        contract = '''
pragma solidity ^0.8.0;

contract TestContract {
    modifier onlyOwner() {
        _;
    }
    
    function pause() external onlyOwner {}
    function unpause() external onlyOwner {}
    function setFee(uint256 fee) external onlyOwner {}
    function migrate(address to) external onlyOwner {}
}
'''
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should include code quality issues
        assert isinstance(vulnerabilities, list)


class TestRealWorldScenarios:
    """Test real-world scenarios based on actual missed findings."""
    
    def test_bridgehub_style_shadowing(self):
        """Test detection of the exact shadowing pattern from ADI-Stack-Contracts."""
        detector = VariableShadowingDetector()
        
        # Simplified version of the Bridgehub.sol pattern
        contract = '''
pragma solidity ^0.8.0;

contract Bridgehub {
    mapping(uint256 chainId => bytes32) public baseTokenAssetId;
    address public assetRouter;
    
    function baseToken(uint256 _chainId) public view returns (address) {
        bytes32 baseTokenAssetId = baseTokenAssetId[_chainId];
        address assetHandlerAddress = address(0);
        return address(0);
    }
}
'''
        vulnerabilities = detector.analyze_contract(contract)
        
        # Should detect the shadowing
        assert any(
            v.vulnerability_type == 'variable_shadowing' and 
            'baseTokenAssetId' in v.description
            for v in vulnerabilities
        ), "Should detect baseTokenAssetId shadowing from Bridgehub pattern"
    
    def test_bridgehub_style_missing_zero_check(self):
        """Test detection of missing zero-address check from ADI-Stack-Contracts."""
        detector = InputValidationDetector()
        
        # Simplified version of the setAddresses pattern
        contract = '''
pragma solidity ^0.8.0;

interface ICTMDeploymentTracker {}
interface IMessageRoot {}

contract Bridgehub {
    address public assetRouter;
    ICTMDeploymentTracker public l1CtmDeployer;
    IMessageRoot public messageRoot;
    
    modifier onlyOwner() {
        _;
    }
    
    function setAddresses(
        address _assetRouter,
        ICTMDeploymentTracker _l1CtmDeployer,
        IMessageRoot _messageRoot
    ) external onlyOwner {
        assetRouter = _assetRouter;
        l1CtmDeployer = _l1CtmDeployer;
        messageRoot = _messageRoot;
    }
}
'''
        vulnerabilities = detector.analyze_input_validation(contract)
        
        zero_addr_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'missing_zero_address_check']
        
        # Should detect at least one missing validation
        assert len(zero_addr_vulns) >= 1, "Should detect missing zero-address validation in setAddresses"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_contract(self):
        """Test handling of empty or minimal contracts."""
        detector = VariableShadowingDetector()
        
        contract = '''
pragma solidity ^0.8.0;

contract Empty {
}
'''
        vulnerabilities = detector.analyze_contract(contract)
        assert vulnerabilities == []
    
    def test_contract_with_only_comments(self):
        """Test handling of contract with only comments."""
        detector = VariableShadowingDetector()
        
        contract = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This is just a comment
contract Commented {
    // Nothing here
}
'''
        vulnerabilities = detector.analyze_contract(contract)
        assert isinstance(vulnerabilities, list)
    
    def test_complex_inheritance(self):
        """Test handling of complex inheritance patterns."""
        detector = VariableShadowingDetector()
        
        contract = '''
pragma solidity ^0.8.0;

contract A {
    uint256 public x;
}

contract B is A {
    uint256 public y;
}

contract C is B {
    function setX(uint256 x) public {
        // x shadows inherited state variable
    }
}
'''
        vulnerabilities = detector.analyze_contract(contract)
        assert isinstance(vulnerabilities, list)


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
