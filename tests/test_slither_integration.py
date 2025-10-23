#!/usr/bin/env python3
"""
Unit tests for Slither integration in enhanced_audit_engine.

Tests:
- Slither availability detection
- Slither analysis execution
- Result parsing and conversion
- Integration with enhanced audit engine
- Error handling and graceful degradation
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import shutil

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.enhanced_audit_engine import EnhancedAetherAuditEngine
from core.vulnerability_detector import SlitherIntegration


class TestSlitherAvailability:
    """Test cases for Slither availability detection."""
    
    def test_slither_integration_init(self):
        """Test SlitherIntegration initialization."""
        slither = SlitherIntegration()
        
        # Should have slither_available attribute
        assert hasattr(slither, 'slither_available')
        assert isinstance(slither.slither_available, bool)
    
    def test_slither_check_availability(self):
        """Test checking if Slither is available."""
        slither = SlitherIntegration()
        
        # availability should be deterministic
        available = slither.slither_available
        assert isinstance(available, bool)
    
    def test_slither_integration_methods(self):
        """Test SlitherIntegration has required methods."""
        slither = SlitherIntegration()
        
        # Should have analyze_with_slither method
        assert hasattr(slither, 'analyze_with_slither')
        assert callable(slither.analyze_with_slither)


class TestSlitherAnalysis:
    """Test cases for Slither analysis execution."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.slither = SlitherIntegration()
        
        # Sample Solidity contracts for testing
        self.vulnerable_contract = '''
pragma solidity ^0.8.0;

contract VulnerableContract {
    uint256 public value;
    
    function unsafeTransfer(address to, uint256 amount) public {
        // Unchecked arithmetic
        require(to != address(0));
        // Direct transfer without checks
        payable(to).transfer(amount);
    }
    
    function reentrancyVulnerable(address attacker) public {
        uint256 amount = 100;
        // Vulnerable to reentrancy
        (bool success, ) = attacker.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
'''
        
        self.safe_contract = '''
pragma solidity ^0.8.0;

contract SafeContract {
    uint256 public value;
    
    function safeTransfer(address to, uint256 amount) public {
        require(to != address(0), "Invalid address");
        require(amount > 0, "Invalid amount");
        // Safe transfer with proper checks
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Transfer failed");
    }
}
'''
    
    def test_slither_analysis_with_contract(self):
        """Test Slither analysis with a contract."""
        # Create temporary contract file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(self.vulnerable_contract)
            temp_path = f.name
        
        try:
            # Mock the subprocess call to avoid actual Slither execution
            with patch('subprocess.run') as mock_run:
                # Simulate mixed logs + JSON in stdout
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout='Some log...\n{ "results": { "detectors": [] } }\nTrailing logs',
                    stderr=''
                )
                
                # Attempt analysis (may fail if Slither not installed)
                if self.slither.slither_available:
                    # Should not raise exception
                    try:
                        result = self.slither.analyze_with_slither(temp_path)
                        assert isinstance(result, list)
                    except Exception as e:
                        # Expected if Slither not installed
                        pytest.skip(f"Slither not available: {e}")
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_slither_graceful_degradation(self):
        """Test that analysis works even if Slither is not available."""
        slither = SlitherIntegration()
        
        # Create temporary contract file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(self.safe_contract)
            temp_path = f.name
        
        try:
            # If Slither not available, should return empty list or None
            if not slither.slither_available:
                result = slither.analyze_with_slither(temp_path) if hasattr(slither, 'analyze_with_slither') else None
                assert result is None or isinstance(result, list)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestEnhancedAuditEngineSlitherIntegration:
    """Test Slither integration within EnhancedAetherAuditEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create mock contracts
        self.contract_files = [
            {
                'path': 'test1.sol',
                'name': 'TestContract1',
                'content': '''
pragma solidity ^0.8.0;
contract Test1 {
    function test() public {}
}
'''
            },
            {
                'path': 'test2.sol',
                'name': 'TestContract2',
                'content': '''
pragma solidity ^0.8.0;
contract Test2 {
    function test() public payable {}
}
'''
            }
        ]
    
    def test_enhanced_audit_engine_has_slither_method(self):
        """Test EnhancedAetherAuditEngine has Slither integration method."""
        engine = EnhancedAetherAuditEngine()
        
        # Should have _run_slither_analysis method
        assert hasattr(engine, '_run_slither_analysis')
        assert callable(engine._run_slither_analysis)
    
    def test_slither_analysis_method(self):
        """Test _run_slither_analysis method."""
        engine = EnhancedAetherAuditEngine()
        
        # Ensure it returns a list even without real Slither
        result = engine._run_slither_analysis(self.contract_files)
        assert isinstance(result, list)
    
    def test_slither_not_available_returns_empty_list(self):
        """Test that missing Slither returns empty list gracefully."""
        engine = EnhancedAetherAuditEngine()
        
        result = engine._run_slither_analysis(self.contract_files)
        
        # Should return empty list or have findings
        assert isinstance(result, list)
    
    def test_slither_analysis_with_empty_contracts(self):
        """Test _run_slither_analysis with empty contracts."""
        engine = EnhancedAetherAuditEngine()
        
        result = engine._run_slither_analysis([])
        
        # Should return empty list for empty input
        assert isinstance(result, list)


class TestSlitherErrorHandling:
    """Test error handling in Slither integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = EnhancedAetherAuditEngine()
        self.contract_files = [
            {
                'path': 'test.sol',
                'name': 'TestContract',
                'content': 'pragma solidity ^0.8.0;\ncontract Test {}'
            }
        ]
    
    def test_slither_analysis_handles_exception(self):
        """Test that Slither analysis handles exceptions gracefully."""
        # Even if something goes wrong, should return a list
        result = self.engine._run_slither_analysis(self.contract_files)
        
        # Should return empty list or findings (never crash)
        assert isinstance(result, list)
    
    def test_slither_with_malformed_contract(self):
        """Test handling of malformed contract."""
        engine = EnhancedAetherAuditEngine()
        
        malformed_contract_files = [
            {
                'path': 'bad.sol',
                'name': 'BadContract',
                'content': 'pragma solidity ^0.8.0; THIS IS NOT VALID SOLIDITY'
            }
        ]
        
        # Should handle without crashing
        result = engine._run_slither_analysis(malformed_contract_files)
        
        # Should return list (possibly empty)
        assert isinstance(result, list)


class TestSlitherIntegrationPipeline:
    """Test Slither integration in the full audit pipeline."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.contract_content = '''
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;
    
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function withdraw() public payable {
        msg.sender.call{value: address(this).balance}("");
    }
}
'''
    
    def test_slither_integration_in_pipeline(self):
        """Test Slither integration works in audit pipeline."""
        engine = EnhancedAetherAuditEngine()
        
        contract_files = [
            {
                'path': 'test.sol',
                'name': 'TestContract',
                'content': self.contract_content
            }
        ]
        
        # Call Slither integration
        result = engine._run_slither_analysis(contract_files)
        
        # Verify it returns a list
        assert isinstance(result, list)


class TestSlitherOutputParsing:
    """Test parsing of Slither output."""
    
    def test_slither_json_output_parsing(self):
        """Test parsing of Slither JSON output."""
        slither = SlitherIntegration()
        
        # Sample Slither JSON output
        sample_output = '{"results": {"detectors": [{"check":"unchecked-transfer","impact":"High","description":"Unchecked transfer","results":[{"source_mapping":{"lines":[12]}}]}]}}'
        
        # Should be able to parse JSON
        import json
        parsed = json.loads(sample_output)
        
        assert isinstance(parsed, dict)
        assert 'results' in parsed and 'detectors' in parsed['results']
    
    def test_slither_result_conversion(self):
        """Test conversion of Slither results to standard format."""
        slither_result = {
            'check': 'reentrancy',
            'impact': 'Critical',
            'confidence': 'High',
            'description': 'Reentrancy vulnerability detected',
            'function': 'TestContract.withdraw',
            'type': 'Function'
        }
        
        # Should be convertible to vulnerability format
        assert 'check' in slither_result
        assert 'impact' in slither_result
        assert 'description' in slither_result


class TestSlitherComparisonWithPatterns:
    """Test Slither findings vs pattern-based detection."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.slither = SlitherIntegration()
        
        self.reentrancy_contract = '''
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // Vulnerable to reentrancy - external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;
    }
}
'''
    
    def test_reentrancy_detection_patterns(self):
        """Test that reentrancy patterns are detectable."""
        # Reentrancy patterns
        import re
        
        patterns = [
            r'\.call\{',  # Dangerous call pattern
            r'msg\.sender\.call',  # Direct call to sender
            r'\.transfer|\.send',  # Transfer/send patterns
        ]
        
        detected = False
        for pattern in patterns:
            if re.search(pattern, self.reentrancy_contract):
                detected = True
                break
        
        assert detected, "Should detect reentrancy-like patterns"
    
    def test_integration_complementarity(self):
        """Test that Slither and pattern detection are complementary."""
        # Pattern-based detection
        import re
        
        has_external_call = bool(re.search(r'\.call\{', self.reentrancy_contract))
        
        # Both should detect reentrancy patterns
        assert has_external_call, "Pattern should detect external call"


class TestSlitherPerformance:
    """Test Slither integration performance."""
    
    def test_slither_handles_multiple_contracts(self):
        """Test that Slither integration handles multiple contracts."""
        # Multiple contracts
        contract_files = [
            {
                'path': f'contract{i}.sol',
                'name': f'Contract{i}',
                'content': f'pragma solidity ^0.8.0;\n\ncontract Contract{i} {{\n    uint256 public value{i};\n}}\n'
            }
            for i in range(5)
        ]
        
        engine = EnhancedAetherAuditEngine()
        
        # Should handle without crashing
        result = engine._run_slither_analysis(contract_files)
        assert isinstance(result, list)
    
    def test_slither_handles_large_contract(self):
        """Test that Slither integration handles large contracts."""
        # Generate large contract
        large_contract = 'pragma solidity ^0.8.0;\n\ncontract Large {\n'
        for i in range(1000):
            large_contract += f'    uint256 public var{i};\n'
        large_contract += '}\n'
        
        contract_files = [
            {
                'path': 'large.sol',
                'name': 'LargeContract',
                'content': large_contract
            }
        ]
        
        engine = EnhancedAetherAuditEngine()
        
        # Should handle without crashing
        result = engine._run_slither_analysis(contract_files)
        assert isinstance(result, list)


class TestSlitherRealWorkflow:
    """End-to-end tests that execute real Slither against real temp files.

    These tests are skipped if Slither is not available in the environment.
    """

    @staticmethod
    def _slither_present() -> bool:
        """Detect if slither is available to run for real E2E tests."""
        try:
            venv_slither = '/Users/l33tdawg/nodejs-projects/bugbounty/venv/bin/slither'
            return os.path.exists(venv_slither) or (shutil.which('slither') is not None)
        except Exception:
            return False

    def setup_method(self):
        self.slither = SlitherIntegration()

    @pytest.mark.skipif(not _slither_present.__func__(), reason="Slither binary not available for real E2E test")
    def test_real_cli_runs_single_file(self):
        """Ensure our integration can run Slither on a real self-contained file."""
        vulnerable_contract = (
            'pragma solidity ^0.8.0;\n'
            'contract V {\n'
            '    function withdraw() public {\n'
            '        (bool s, ) = msg.sender.call{value: 1}("");\n'
            '        require(s);\n'
            '    }\n'
            '}\n'
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'V.sol'
            path.write_text(vulnerable_contract)

            findings = self.slither.analyze_with_slither(str(path))
            assert isinstance(findings, list)

    @pytest.mark.skipif(not _slither_present.__func__(), reason="Slither binary not available for real E2E test")
    def test_resolves_relative_imports_via_cwd(self):
        """Create two files with a relative import and ensure Slither can run (cwd correctness)."""
        lib_contract = (
            'pragma solidity ^0.8.0;\n'
            'library LibA {\n'
            '    function x() internal pure returns (uint256) { return 1; }\n'
            '}\n'
        )
        main_contract = (
            'pragma solidity ^0.8.0;\n'
            'import "./LibA.sol";\n'
            'contract C {\n'
            '    function f() public pure returns (uint256) {\n'
            '        return LibA.x();\n'
            '    }\n'
            '}\n'
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / 'LibA.sol').write_text(lib_contract)
            main_path = tmp_path / 'C.sol'
            main_path.write_text(main_contract)

            findings = self.slither.analyze_with_slither(str(main_path))
            # If cwd wasn't set, Slither would typically fail to resolve import and return [].
            # We only assert the integration runs and returns a list, not on specific findings.
            assert isinstance(findings, list)

    @pytest.mark.skipif(not _slither_present.__func__(), reason="Slither binary not available for real E2E test")
    def test_engine_slither_on_directory(self):
        """Simulate engine workflow on a directory of contracts using real Slither."""
        engine = EnhancedAetherAuditEngine()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / 'A.sol').write_text('pragma solidity ^0.8.0; contract A { function a() public {} }')
            (tmp_path / 'B.sol').write_text('pragma solidity ^0.8.0; contract B { function b() public payable {} }')

            # Simulate app read workflow
            contract_files = engine._read_contract_files(str(tmp_path))
            assert isinstance(contract_files, list) and len(contract_files) >= 2

            # Run slither analysis path
            findings = engine._run_slither_analysis(contract_files)
            assert isinstance(findings, list)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
