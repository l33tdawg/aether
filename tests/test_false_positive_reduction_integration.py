#!/usr/bin/env python3
"""
Integration Tests for False Positive Reduction System

Tests that all Phase 1 & 2 improvements work together to reduce false positives.
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path

from core.governance_detector import GovernanceDetector, ValidationDetector
from core.deployment_analyzer import DeploymentAnalyzer
from core.validation_pipeline import ValidationPipeline, validate_vulnerability
from core.immunefi_formatter import ImmunefFormatter
from core.accuracy_tracker import AccuracyTracker


class TestEndToEndFalsePositiveReduction:
    """Test complete false positive reduction workflow."""
    
    @pytest.fixture
    def parallel_protocol_project(self):
        """Create project mimicking Parallel Protocol (source of false positives)."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create deployment config WITHOUT EXTERNAL manager
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'mainnet.json'
        config_file.write_text(json.dumps({
            'managers': {
                'primary': 'INTERNAL',
                'secondary': 'INTERNAL'
            }
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_parallel_protocol_libmanager_filtering(self, parallel_protocol_project):
        """
        Test that Parallel Protocol LibManager false positives are filtered.
        
        This was a real false positive that should be caught by deployment analyzer.
        """
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
        
        # This was flagged as "malformed_input_handling"
        vulnerability = {
            'vulnerability_type': 'malformed_input_handling',
            'description': 'LibManager uses abi.decode for EXTERNAL manager type without validation',
            'line': 7,
            'code_snippet': 'abi.decode(data, (IManager)).invest(amount);',
            'contract_name': 'LibManager',
            'severity': 'medium'
        }
        
        # Run through validation pipeline
        result = validate_vulnerability(vulnerability, contract_code, parallel_protocol_project)
        
        # Should be filtered as false positive (EXTERNAL not deployed)
        assert result['is_false_positive'] is True
        assert 'deployment' in result['stage'] or 'not used' in result['reasoning'].lower()
    
    @pytest.fixture
    def gains_network_project(self):
        """Create project mimicking Gains Network."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        (project_path / 'deploy').mkdir(parents=True, exist_ok=True)
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_gains_network_fee_setter_filtering(self, gains_network_project):
        """
        Test that Gains Network fee validation is recognized.
        
        Fee setter has onlyGov + validation, should be filtered.
        """
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
        
        # This was flagged as "arithmetic_underflow"
        vulnerability = {
            'vulnerability_type': 'arithmetic_underflow',
            'description': 'Fee curve could have negative values in yFee[i-1] when i=0',
            'line': 12,
            'code_snippet': 'require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");',
            'severity': 'high'
        }
        
        # Run through validation pipeline
        result = validate_vulnerability(vulnerability, contract_code, gains_network_project)
        
        # Should be filtered by governance or local validation
        # The require statement itself has validation, and the setter is governance-controlled
        assert result['is_false_positive'] is True or result['confidence'] < 0.6


class TestSolidity08Protection:
    """Test Solidity 0.8+ automatic protection detection."""
    
    def test_solidity_08_filters_overflow(self):
        """Test that Solidity 0.8+ code is filtered."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract Token {
            function transfer(uint256 amount) external {
                balance = balance + amount;  // Protected by 0.8+
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Potential overflow',
            'line': 6,
            'code_snippet': 'balance = balance + amount;'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        assert result['is_false_positive'] is True
        assert 'automatic' in result['reasoning'].lower() or '0.8' in result['reasoning']
    
    def test_unchecked_block_not_filtered(self):
        """Test that unchecked blocks are NOT filtered."""
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
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should NOT be filtered (unchecked block is intentionally unsafe)
        assert result['is_false_positive'] is False


class TestWorkflowIntegration:
    """Test complete workflow from detection to submission."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    def test_complete_workflow(self, temp_dir):
        """Test complete workflow: validate → track → format for submission."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Vault {
            mapping(address => uint256) public balances;
            
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}("");  // Reentrancy!
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'reentrancy',
            'description': 'State change before external call allows reentrancy',
            'line': 9,
            'code_snippet': 'msg.sender.call{value: amount}("");',
            'contract_name': 'Vault',
            'severity': 'critical',
            'validation_confidence': 0.95
        }
        
        # Step 1: Validate
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Real vulnerability should pass validation
        assert result['is_false_positive'] is False
        
        # Step 2: Generate Immunefi report
        formatter = ImmunefFormatter()
        report = formatter.generate_report(
            vulnerability,
            deployment_info={
                'contract_address': '0x1234567890123456789012345678901234567890',
                'chain': 'Ethereum'
            }
        )
        
        assert report.severity == 'Critical'
        assert 'Reentrancy' in report.title
        
        # Step 3: Track submission
        tracker = AccuracyTracker(temp_dir / 'metrics.json')
        tracker.record_submission(vulnerability, 'accepted', bounty_amount=15000.0)
        
        stats = tracker.get_accuracy_stats()
        assert stats['accepted'] == 1
        assert stats['accuracy'] == 1.0


class TestPerformanceImprovements:
    """Test performance improvements from caching."""
    
    def test_cache_improves_performance(self):
        """Test that caching improves analysis performance."""
        from core.analysis_cache import AnalysisCache
        import time
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache = AnalysisCache(Path(temp_dir) / 'cache')
            
            contract_code = "pragma solidity ^0.8.0; contract Test { function test() public {} }"
            
            # Simulate expensive analysis
            def expensive_analysis():
                time.sleep(0.01)  # Simulate work
                return {'result': 'analysis complete'}
            
            # First run (cache miss)
            start = time.time()
            result1 = cache.get(contract_code, "test")
            if not result1:
                result1 = expensive_analysis()
                cache.set(contract_code, "test", result1)
            first_run_time = time.time() - start
            
            # Second run (cache hit)
            start = time.time()
            result2 = cache.get(contract_code, "test")
            second_run_time = time.time() - start
            
            # Cache should be faster
            assert result1 == result2
            assert second_run_time < first_run_time
            
        finally:
            shutil.rmtree(temp_dir)


class TestAccuracyMetrics:
    """Test accuracy tracking over time."""
    
    def test_accuracy_improvement_tracking(self):
        """Test tracking accuracy improvements."""
        temp_dir = tempfile.mkdtemp()
        try:
            tracker = AccuracyTracker(Path(temp_dir) / 'metrics.json')
            
            # Simulate Week 1: 33% accuracy (1/3 accepted)
            tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'accepted')
            tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'rejected')
            tracker.record_submission({'vulnerability_type': 'test', 'severity': 'high'}, 'rejected')
            
            stats_week1 = tracker.get_accuracy_stats()
            assert abs(stats_week1['accuracy'] - 1/3) < 0.01
            
            # Simulate Week 2: Better filtering (75% accuracy - 3/4)
            # Filter 2 false positives
            tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'Solidity 0.8+ protection')
            tracker.record_filtered({'vulnerability_type': 'test', 'severity': 'low'}, 'Governance controlled')
            
            # Submit only high-confidence finding
            tracker.record_submission({'vulnerability_type': 'test', 'severity': 'critical'}, 'accepted')
            
            stats_week2 = tracker.get_accuracy_stats()
            
            # Accuracy should improve
            assert stats_week2['accuracy'] >= stats_week1['accuracy']
            assert stats_week2['false_positives_filtered'] == 2
            
        finally:
            shutil.rmtree(temp_dir)


class TestRegressionPrevention:
    """Test that real vulnerabilities are NOT filtered."""
    
    def test_real_reentrancy_not_filtered(self):
        """Test that real reentrancy is not filtered."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Vulnerable {
            mapping(address => uint256) public balances;
            
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                // REAL VULNERABILITY: State change after external call
                msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'reentrancy',
            'description': 'State updated after external call',
            'line': 10,
            'code_snippet': 'balances[msg.sender] -= amount;',
            'severity': 'critical'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should NOT be filtered (real vulnerability)
        assert result['is_false_positive'] is False
    
    def test_real_arithmetic_vulnerability_not_filtered(self):
        """Test that real arithmetic vulnerabilities are not filtered."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Vulnerable {
            uint256 public totalSupply;
            
            function mint(uint256 amount) external {
                // REAL VULNERABILITY: No SafeMath, no protection
                totalSupply = totalSupply + amount;
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'integer_overflow',
            'description': 'Unchecked addition without SafeMath',
            'line': 8,
            'code_snippet': 'totalSupply = totalSupply + amount;',
            'severity': 'high'
        }
        
        result = validate_vulnerability(vulnerability, contract_code)
        
        # Should NOT be filtered (real vulnerability in 0.7.6 without SafeMath)
        assert result['is_false_positive'] is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

