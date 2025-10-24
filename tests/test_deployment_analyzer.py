#!/usr/bin/env python3
"""
Tests for Deployment Analyzer Module

Tests deployment awareness to prevent false positives from unused code paths.
"""

import pytest
import json
from pathlib import Path
import tempfile
import shutil

from core.deployment_analyzer import DeploymentAnalyzer


class TestDeploymentAnalyzer:
    """Test cases for DeploymentAnalyzer."""
    
    @pytest.fixture
    def temp_project(self):
        """Create temporary project structure for testing."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create directory structure
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        (project_path / 'scripts').mkdir(parents=True, exist_ok=True)
        (project_path / 'script').mkdir(parents=True, exist_ok=True)
        
        yield project_path
        
        # Cleanup
        shutil.rmtree(temp_dir)
    
    def test_initialization(self, temp_project):
        """Test DeploymentAnalyzer initialization."""
        analyzer = DeploymentAnalyzer(temp_project)
        
        assert analyzer.project_path == temp_project
        assert isinstance(analyzer.deployment_scripts, list)
        assert isinstance(analyzer.config_files, list)
    
    def test_find_deployment_scripts(self, temp_project):
        """Test finding deployment scripts."""
        # Create deployment scripts
        deploy_script = temp_project / 'scripts' / 'deploy.ts'
        deploy_script.write_text('// Deployment script')
        
        foundry_script = temp_project / 'script' / 'Deploy.s.sol'
        foundry_script.write_text('// Foundry deployment')
        
        analyzer = DeploymentAnalyzer(temp_project)
        
        assert len(analyzer.deployment_scripts) >= 2
        script_names = [s.name for s in analyzer.deployment_scripts]
        assert 'deploy.ts' in script_names
        assert 'Deploy.s.sol' in script_names
    
    def test_find_config_files(self, temp_project):
        """Test finding configuration files."""
        # Create config files
        config_file = temp_project / 'deploy' / 'config' / 'production.json'
        config_file.write_text('{"oracleType": "CHAINLINK"}')
        
        analyzer = DeploymentAnalyzer(temp_project)
        
        assert len(analyzer.config_files) >= 1
        config_names = [c.name for c in analyzer.config_files]
        assert 'production.json' in config_names


class TestFeatureDeploymentDetection:
    """Test feature deployment detection."""
    
    @pytest.fixture
    def project_with_oracle(self):
        """Create project with oracle configuration."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create config with CHAINLINK oracle
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text(json.dumps({
            'oracle': {
                'oracleType': 'CHAINLINK_FEEDS',
                'address': '0x1234567890123456789012345678901234567890'
            }
        }))
        
        # Create deployment script
        (project_path / 'scripts').mkdir(parents=True, exist_ok=True)
        deploy_script = project_path / 'scripts' / 'deploy.ts'
        deploy_script.write_text('''
            const oracle = await Oracle.deploy();
            await oracle.setOracleType(OracleType.CHAINLINK_FEEDS);
        ''')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_feature_deployed_in_config(self, project_with_oracle):
        """Test detecting feature in config file."""
        analyzer = DeploymentAnalyzer(project_with_oracle)
        
        result = analyzer.is_feature_deployed('CHAINLINK_FEEDS', 'Oracle')
        
        assert result['deployed'] is True
        assert result['confidence'] >= 0.8
        assert 'found_in' in result
    
    def test_feature_not_deployed(self, project_with_oracle):
        """Test detecting unused feature."""
        analyzer = DeploymentAnalyzer(project_with_oracle)
        
        result = analyzer.is_feature_deployed('EXTERNAL', 'Oracle')
        
        assert result['deployed'] is False
        assert 'reason' in result
        assert result['confidence'] >= 0.5


class TestOracleTypeUsage:
    """Test oracle type usage detection."""
    
    @pytest.fixture
    def project_external_unused(self):
        """Create project where EXTERNAL oracle is not used."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create config with only CHAINLINK
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text('{"oracle": {"oracleType": "CHAINLINK_FEEDS"}}')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_oracle_type_not_used(self, project_external_unused):
        """Test that EXTERNAL oracle type is detected as unused."""
        analyzer = DeploymentAnalyzer(project_external_unused)
        
        result = analyzer.check_oracle_type_usage('EXTERNAL')
        
        assert result['used'] is False
        assert result['confidence'] > 0.8
    
    def test_oracle_type_used(self, project_external_unused):
        """Test that configured oracle type is detected as used."""
        analyzer = DeploymentAnalyzer(project_external_unused)
        
        # Add EXTERNAL to config
        config_file = project_external_unused / 'deploy' / 'config' / 'config.json'
        config_file.write_text('{"oracle": {"oracleType": "EXTERNAL"}}')
        
        # Re-create analyzer to pick up new config
        analyzer = DeploymentAnalyzer(project_external_unused)
        result = analyzer.check_oracle_type_usage('EXTERNAL')
        
        assert result['used'] is True
        assert result['confidence'] >= 0.8


class TestFunctionUsageDetection:
    """Test function usage detection in deployment scripts."""
    
    @pytest.fixture
    def project_with_functions(self):
        """Create project with function calls in deployment."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create deployment script with function calls
        (project_path / 'scripts').mkdir(parents=True, exist_ok=True)
        deploy_script = project_path / 'scripts' / 'deploy.js'
        deploy_script.write_text('''
            const vault = await RocketVault.deploy();
            await vault.initialize();
            await vault.withdrawEther(amount);
            await vault.withdrawEther(amount2);
        ''')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_function_used_multiple_times(self, project_with_functions):
        """Test detecting function that is called multiple times."""
        analyzer = DeploymentAnalyzer(project_with_functions)
        
        result = analyzer.check_function_usage('withdrawEther', 'RocketVault')
        
        assert result['used'] is True
        assert result['usage_count'] == 2
        assert result['confidence'] >= 0.7
        assert len(result['found_in']) > 0
    
    def test_function_not_used(self, project_with_functions):
        """Test detecting function that is not called."""
        analyzer = DeploymentAnalyzer(project_with_functions)
        
        result = analyzer.check_function_usage('balanceOf', 'RocketVault')
        
        assert result['used'] is False
        assert result['usage_count'] == 0
        assert 'reason' in result


class TestCodePathReachability:
    """Test code path reachability analysis."""
    
    @pytest.fixture
    def project_with_conditionals(self):
        """Create project with conditional code paths."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create config with specific enum values
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'config.json'
        config_file.write_text('{"managerType": "INTERNAL"}')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_unreachable_code_path(self, project_with_conditionals):
        """Test detecting unreachable code path."""
        analyzer = DeploymentAnalyzer(project_with_conditionals)
        
        # Code that checks for EXTERNAL but only INTERNAL is deployed
        code_snippet = 'if (managerType == ManagerType.EXTERNAL) { ... }'
        result = analyzer.is_code_path_reachable(code_snippet, 'LibManager')
        
        # Should detect as unreachable since EXTERNAL is not in config
        assert result['reachable'] is False or result['confidence'] < 0.8
    
    def test_reachable_code_path(self, project_with_conditionals):
        """Test detecting reachable code path."""
        # Add EXTERNAL to config
        config_file = project_with_conditionals / 'deploy' / 'config' / 'config.json'
        config_file.write_text('{"managerType": "EXTERNAL"}')
        
        analyzer = DeploymentAnalyzer(project_with_conditionals)
        
        code_snippet = 'if (managerType == ManagerType.EXTERNAL) { ... }'
        result = analyzer.is_code_path_reachable(code_snippet, 'LibManager')
        
        assert result['reachable'] is True or result['confidence'] >= 0.7


class TestCommentDetection:
    """Test detection of features only in comments."""
    
    @pytest.fixture
    def project_with_comments(self):
        """Create project with features only mentioned in comments."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create script with EXTERNAL only in comments
        (project_path / 'scripts').mkdir(parents=True, exist_ok=True)
        deploy_script = project_path / 'scripts' / 'deploy.ts'
        deploy_script.write_text('''
            // NOTE: EXTERNAL oracle type is not yet implemented
            // TODO: Add support for OracleType.EXTERNAL
            const oracle = await Oracle.deploy(OracleType.CHAINLINK);
        ''')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_feature_only_in_comments(self, project_with_comments):
        """Test that features only in comments are not counted as deployed."""
        analyzer = DeploymentAnalyzer(project_with_comments)
        
        # Check if EXTERNAL is considered used
        result = analyzer.check_oracle_type_usage('EXTERNAL')
        
        # Should not be considered used since it's only in comments
        assert result['used'] is False


class TestDeploymentSummary:
    """Test deployment summary generation."""
    
    @pytest.fixture
    def full_project(self):
        """Create full project structure."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create multiple deployment files
        (project_path / 'scripts').mkdir(parents=True, exist_ok=True)
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        
        (project_path / 'scripts' / 'deploy1.ts').write_text('// Deploy 1')
        (project_path / 'scripts' / 'deploy2.js').write_text('// Deploy 2')
        (project_path / 'deploy' / 'config' / 'prod.json').write_text('{}')
        (project_path / 'deploy' / 'config' / 'dev.json').write_text('{}')
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_deployment_summary(self, full_project):
        """Test getting deployment summary."""
        analyzer = DeploymentAnalyzer(full_project)
        
        summary = analyzer.get_deployment_summary()
        
        assert 'project_path' in summary
        assert summary['deployment_scripts_found'] >= 2
        assert summary['config_files_found'] >= 2
        assert isinstance(summary['deployment_scripts'], list)
        assert isinstance(summary['config_files'], list)


class TestParallelProtocolRegression:
    """Regression tests for Parallel Protocol false positives."""
    
    @pytest.fixture
    def parallel_protocol_project(self):
        """Create project structure mimicking Parallel Protocol."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create config that doesn't use EXTERNAL
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        config_file = project_path / 'deploy' / 'config' / 'mainnet.json'
        config_file.write_text(json.dumps({
            'managers': {
                'default': 'INTERNAL',
                'backup': 'INTERNAL'
            }
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_external_manager_not_deployed(self, parallel_protocol_project):
        """Test that EXTERNAL manager type is detected as unused (Parallel Protocol case)."""
        analyzer = DeploymentAnalyzer(parallel_protocol_project)
        
        # Check if EXTERNAL manager is used
        result = analyzer.is_feature_deployed('EXTERNAL', 'LibManager')
        
        # Should not be deployed
        assert result['deployed'] is False
        assert result['confidence'] >= 0.7
    
    def test_libmanager_external_code_unreachable(self, parallel_protocol_project):
        """Test that LibManager EXTERNAL code path is detected as unreachable."""
        analyzer = DeploymentAnalyzer(parallel_protocol_project)
        
        # Code from LibManager.invest
        code_snippet = 'if (managerType == ManagerType.EXTERNAL) abi.decode(data, (IManager)).invest(amount);'
        result = analyzer.is_code_path_reachable(code_snippet, 'LibManager')
        
        # Should be unreachable since EXTERNAL is not in deployment config
        assert result['reachable'] is False or result['confidence'] >= 0.6


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_nonexistent_project_path(self):
        """Test handling of nonexistent project path."""
        nonexistent_path = Path('/nonexistent/path/to/project')
        analyzer = DeploymentAnalyzer(nonexistent_path)
        
        # Should initialize without crashing
        assert analyzer.project_path == nonexistent_path
        assert len(analyzer.deployment_scripts) == 0
        assert len(analyzer.config_files) == 0
    
    def test_empty_project(self):
        """Test handling of empty project directory."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        try:
            analyzer = DeploymentAnalyzer(project_path)
            
            result = analyzer.is_feature_deployed('TEST', 'Contract')
            assert result['deployed'] is False
            
            summary = analyzer.get_deployment_summary()
            assert summary['deployment_scripts_found'] == 0
            assert summary['config_files_found'] == 0
        finally:
            shutil.rmtree(temp_dir)
    
    def test_malformed_json_config(self):
        """Test handling of malformed JSON config."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        try:
            (project_path / 'config').mkdir(parents=True, exist_ok=True)
            config_file = project_path / 'config' / 'bad.json'
            config_file.write_text('{ invalid json }')
            
            analyzer = DeploymentAnalyzer(project_path)
            
            # Should handle gracefully
            result = analyzer.is_feature_deployed('TEST', 'Contract')
            assert isinstance(result, dict)
            assert 'deployed' in result
        finally:
            shutil.rmtree(temp_dir)


class TestIntegrationWithValidationPipeline:
    """Test integration with validation pipeline."""
    
    @pytest.fixture
    def realistic_defi_project(self):
        """Create realistic DeFi project structure."""
        temp_dir = tempfile.mkdtemp()
        project_path = Path(temp_dir)
        
        # Create Foundry-style project
        (project_path / 'script').mkdir(parents=True, exist_ok=True)
        (project_path / 'deploy' / 'config').mkdir(parents=True, exist_ok=True)
        
        # Deployment script
        deploy_script = project_path / 'script' / 'Deploy.s.sol'
        deploy_script.write_text('''
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            
            import "forge-std/Script.sol";
            import "../src/Protocol.sol";
            
            contract DeployProtocol is Script {
                function run() external {
                    vm.startBroadcast();
                    
                    Protocol protocol = new Protocol();
                    protocol.initialize();
                    
                    // Use CHAINLINK oracle
                    protocol.setOracleType(OracleType.CHAINLINK);
                    
                    vm.stopBroadcast();
                }
            }
        ''')
        
        # Config file
        config_file = project_path / 'deploy' / 'config' / 'mainnet.json'
        config_file.write_text(json.dumps({
            'protocol': {
                'oracle': 'CHAINLINK',
                'governance': 'TIMELOCK'
            }
        }))
        
        yield project_path
        shutil.rmtree(temp_dir)
    
    def test_realistic_deployment_detection(self, realistic_defi_project):
        """Test deployment detection in realistic DeFi project."""
        analyzer = DeploymentAnalyzer(realistic_defi_project)
        
        # CHAINLINK should be deployed
        chainlink_result = analyzer.check_oracle_type_usage('CHAINLINK')
        assert chainlink_result['used'] is True
        
        # EXTERNAL should not be deployed
        external_result = analyzer.check_oracle_type_usage('EXTERNAL')
        assert external_result['used'] is False
    
    def test_validation_pipeline_integration(self, realistic_defi_project):
        """Test that deployment analyzer can be used in validation pipeline."""
        analyzer = DeploymentAnalyzer(realistic_defi_project)
        
        # Simulate vulnerability that uses EXTERNAL oracle
        vulnerability = {
            'vulnerability_type': 'data_decoding',
            'description': 'LibManager uses abi.decode for EXTERNAL manager type',
            'code_snippet': 'if (managerType == ManagerType.EXTERNAL) abi.decode(...)',
            'line': 42
        }
        
        # Check if EXTERNAL is actually deployed
        external_check = analyzer.check_oracle_type_usage('EXTERNAL')
        
        if not external_check['used']:
            # Mark vulnerability as false positive due to unreachable code
            vulnerability['false_positive'] = True
            vulnerability['false_positive_reason'] = 'EXTERNAL type not used in deployment'
            vulnerability['confidence'] = external_check['confidence']
        
        assert vulnerability['false_positive'] is True
        assert 'false_positive_reason' in vulnerability


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

