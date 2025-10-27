#!/usr/bin/env python3
"""
Tests for ProxyPatternFilter - False positive filtering for proxy patterns.
"""

import pytest
from core.proxy_pattern_filter import ProxyPatternFilter, FilterStats, create_filter_report
from core.delegation_analyzer import (
    DelegationFlow,
    ProxyContract,
    ModuleContract,
    DelegationMapping,
    ProxyType,
    DelegationFlowAnalyzer
)


class TestBasicFiltering:
    """Test basic filtering functionality."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_no_proxy_pattern_no_filtering(self):
        """Test that findings are not filtered when no proxy pattern exists."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SimpleContract',
                'function_name': 'adminFunction',
                'description': 'Missing access control',
                'severity': 'high',
            }
        ]
        
        flow = DelegationFlow(has_proxy_pattern=False)
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == len(findings)
        assert not filtered[0].get('is_false_positive', False)
    
    def test_empty_findings_list(self):
        """Test handling of empty findings list."""
        flow = DelegationFlow(has_proxy_pattern=True)
        filtered = self.filter.filter_findings([], flow)
        assert filtered == []
    
    def test_finding_without_function_name(self):
        """Test handling of findings without function names."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Module',
                'description': 'General access control issue',
            }
        ]
        
        proxy = ProxyContract(name='Proxy', file_path='', proxy_type=ProxyType.UUPS)
        module = ModuleContract(name='Module', file_path='', is_library=False)
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy],
            module_contracts=[module]
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        assert len(filtered) == 1  # Should not crash


class TestAccessControlFiltering:
    """Test filtering of access control false positives."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_filter_module_function_protected_at_proxy(self):
        """Test filtering of module functions protected at proxy level."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'ModuleDAO',
                'function_name': 'adminFunction',
                'description': 'Function lacks access control',
                'severity': 'high',
                'confidence': 0.9,
                'file_path': 'contracts/modules/ModuleDAO.sol',
            }
        ]
        
        # Create proxy with protected function
        proxy = ProxyContract(name='MainProxy', file_path='', proxy_type=ProxyType.UUPS)
        proxy.protected_functions = {'adminFunction'}
        proxy.delegations = [
            DelegationMapping(
                function_name='adminFunction',
                proxy_contract='MainProxy',
                module_contract='ModuleDAO',
                module_enum='DAO',
                has_access_control=True,
                access_modifiers=['onlyOwner']
            )
        ]
        
        module = ModuleContract(name='ModuleDAO', file_path='contracts/modules/ModuleDAO.sol', is_library=False)
        module.protected_by_proxy = {'adminFunction'}
        
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy],
            module_contracts=[module],
            protected_at_proxy={'adminFunction'}
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == 1
        assert filtered[0]['is_false_positive'] is True
        assert 'proxy level' in filtered[0]['false_positive_reason'].lower()
        assert filtered[0]['confidence'] < 0.5  # Reduced confidence
    
    def test_keep_genuine_access_control_issues(self):
        """Test that genuine access control issues are not filtered."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'ModuleDAO',
                'function_name': 'unprotectedFunction',
                'description': 'Function lacks access control',
                'severity': 'high',
                'file_path': 'contracts/modules/ModuleDAO.sol',
            }
        ]
        
        # Proxy protects different function
        proxy = ProxyContract(name='MainProxy', file_path='', proxy_type=ProxyType.UUPS)
        proxy.protected_functions = {'adminFunction'}
        
        module = ModuleContract(name='ModuleDAO', file_path='contracts/modules/ModuleDAO.sol', is_library=False)
        module.exposed_functions = {'adminFunction', 'unprotectedFunction'}
        module.protected_by_proxy = {'adminFunction'}
        
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy],
            module_contracts=[module],
            protected_at_proxy={'adminFunction'}
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == 1
        assert not filtered[0].get('is_false_positive', False)
    
    def test_keep_proxy_contract_access_control_issues(self):
        """Test that access control issues in proxy contracts are not filtered."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'MainProxy',
                'function_name': 'criticalFunction',
                'description': 'Function lacks access control',
                'severity': 'critical',
            }
        ]
        
        proxy = ProxyContract(name='MainProxy', file_path='', proxy_type=ProxyType.UUPS)
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy]
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        
        # Should NOT be filtered - proxy functions need protection
        assert len(filtered) == 1
        assert not filtered[0].get('is_false_positive', False)


class TestSSVNetworkPattern:
    """Test filtering with actual SSV Network pattern."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
        
        # Create SSV Network delegation flow
        self.ssv_proxy = ProxyContract(
            name='SSVNetwork.sol',
            file_path='contracts/SSVNetwork.sol',
            proxy_type=ProxyType.UUPS
        )
        self.ssv_proxy.protected_functions = {
            'updateNetworkFee',
            'withdrawNetworkEarnings',
            'updateMaximumOperatorFee'
        }
        self.ssv_proxy.delegations = [
            DelegationMapping(
                function_name='updateNetworkFee',
                proxy_contract='SSVNetwork.sol',
                module_contract='SSVDAO',
                module_enum='SSV_DAO',
                has_access_control=True,
                access_modifiers=['onlyOwner']
            ),
            DelegationMapping(
                function_name='withdrawNetworkEarnings',
                proxy_contract='SSVNetwork.sol',
                module_contract='SSVDAO',
                module_enum='SSV_DAO',
                has_access_control=True,
                access_modifiers=['onlyOwner']
            ),
            DelegationMapping(
                function_name='updateMaximumOperatorFee',
                proxy_contract='SSVNetwork.sol',
                module_contract='SSVDAO',
                module_enum='SSV_DAO',
                has_access_control=True,
                access_modifiers=['onlyOwner']
            )
        ]
        
        self.ssv_dao = ModuleContract(
            name='SSVDAO.sol',
            file_path='contracts/modules/SSVDAO.sol',
            is_library=False
        )
        self.ssv_dao.exposed_functions = {
            'updateNetworkFee',
            'withdrawNetworkEarnings',
            'updateMaximumOperatorFee'
        }
        self.ssv_dao.protected_by_proxy = {
            'updateNetworkFee',
            'withdrawNetworkEarnings',
            'updateMaximumOperatorFee'
        }
        
        self.flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[self.ssv_proxy],
            module_contracts=[self.ssv_dao],
            protected_at_proxy={'updateNetworkFee', 'withdrawNetworkEarnings', 'updateMaximumOperatorFee'}
        )
    
    def test_filter_ssv_dao_false_positives(self):
        """Test filtering of SSV DAO access control false positives."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'updateNetworkFee',
                'description': 'All sensitive protocol parameter update functions are externally callable',
                'severity': 'critical',
                'confidence': 0.95,
                'file_path': 'contracts/modules/SSVDAO.sol',
                'line': 18,
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'withdrawNetworkEarnings',
                'description': 'Critical functions lack access control',
                'severity': 'high',
                'confidence': 0.90,
                'file_path': 'contracts/modules/SSVDAO.sol',
                'line': 26,
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'updateMaximumOperatorFee',
                'description': 'External function lacks access control',
                'severity': 'critical',
                'confidence': 0.80,
                'file_path': 'contracts/modules/SSVDAO.sol',
                'line': 74,
            }
        ]
        
        filtered = self.filter.filter_findings(findings, self.flow)
        
        # All should be marked as false positives
        assert len(filtered) == 3
        for finding in filtered:
            assert finding['is_false_positive'] is True
            assert 'proxy level' in finding['false_positive_reason'].lower()
            assert finding['confidence'] < 0.5
    
    def test_filter_stats_collection(self):
        """Test that filter statistics are collected correctly."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'updateNetworkFee',
                'description': 'Missing access control',
                'severity': 'critical',
                'file_path': 'contracts/modules/SSVDAO.sol',
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'withdrawNetworkEarnings',
                'description': 'Missing access control',
                'severity': 'high',
                'file_path': 'contracts/modules/SSVDAO.sol',
            }
        ]
        
        self.filter.filter_findings(findings, self.flow)
        stats = self.filter.get_filter_stats()
        
        assert stats.total_findings == 2
        assert stats.filtered_findings == 2
        assert len(stats.filtered_by_reason) > 0


class TestInitializationFiltering:
    """Test filtering of initialization-related false positives."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_filter_module_initialization_issues(self):
        """Test filtering of initialization issues in module contracts."""
        findings = [
            {
                'vulnerability_type': 'initialization',
                'contract_name': 'ModuleImpl',
                'function_name': 'initialize',
                'description': 'Unprotected initializer',
                'severity': 'high',
                'file_path': 'contracts/modules/ModuleImpl.sol',
            }
        ]
        
        proxy = ProxyContract(name='UUPSProxy', file_path='', proxy_type=ProxyType.UUPS)
        module = ModuleContract(name='ModuleImpl', file_path='contracts/modules/ModuleImpl.sol', is_library=False)
        
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy],
            module_contracts=[module]
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == 1
        assert filtered[0]['is_false_positive'] is True
        assert 'proxy' in filtered[0]['false_positive_reason'].lower()


class TestQuickFilter:
    """Test quick filtering functionality."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_quick_filter_with_delegation(self):
        """Test quick filter when delegation pattern is present."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Module',
                'function_name': 'adminFunc',
                'description': 'Missing access control',
            }
        ]
        
        contract_files = [
            {
                'name': 'Proxy.sol',
                'content': '''
                    contract Proxy {
                        function adminFunc() external onlyOwner {
                            _delegate(module);
                        }
                    }
                '''
            },
            {
                'name': 'Module.sol',
                'content': '''
                    contract Module {
                        function adminFunc() external {
                            // Implementation
                        }
                    }
                '''
            }
        ]
        
        filtered = self.filter.apply_quick_filter(findings, contract_files)
        
        assert len(filtered) == 1
        assert filtered[0]['is_false_positive'] is True
    
    def test_quick_filter_no_delegation(self):
        """Test quick filter when no delegation pattern is present."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SimpleContract',
                'function_name': 'adminFunc',
                'description': 'Missing access control',
            }
        ]
        
        contract_files = [
            {
                'name': 'SimpleContract.sol',
                'content': '''
                    contract SimpleContract {
                        function adminFunc() external {
                            // No protection
                        }
                    }
                '''
            }
        ]
        
        filtered = self.filter.apply_quick_filter(findings, contract_files)
        
        assert len(filtered) == 1
        assert not filtered[0].get('is_false_positive', False)


class TestModuleContractDetection:
    """Test detection of module contracts."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_detect_module_by_name(self):
        """Test detection of module by contract name."""
        module = ModuleContract(name='MyModule', file_path='', is_library=False)
        flow = DelegationFlow(has_proxy_pattern=True, module_contracts=[module])
        
        assert self.filter._is_module_contract('MyModule', '', flow) is True
    
    def test_detect_module_by_path(self):
        """Test detection of module by file path."""
        module = ModuleContract(name='Contract', file_path='contracts/modules/Contract.sol', is_library=False)
        flow = DelegationFlow(has_proxy_pattern=True, module_contracts=[module])
        
        assert self.filter._is_module_contract('Contract', 'contracts/modules/Contract.sol', flow) is True
    
    def test_detect_module_by_path_pattern(self):
        """Test detection of module by path pattern."""
        flow = DelegationFlow(has_proxy_pattern=True)
        
        assert self.filter._is_module_contract('Unknown', '/modules/Unknown.sol', flow) is True
        assert self.filter._is_module_contract('Unknown', '/implementations/Unknown.sol', flow) is True
        assert self.filter._is_module_contract('Unknown', '/facets/Unknown.sol', flow) is True
    
    def test_not_a_module_proxy_contract(self):
        """Test that proxy contracts are not detected as modules."""
        proxy = ProxyContract(name='ProxyContract', file_path='', proxy_type=ProxyType.UUPS)
        flow = DelegationFlow(has_proxy_pattern=True, proxy_contracts=[proxy])
        
        assert self.filter._is_module_contract('ProxyContract', '', flow) is False


class TestFilterReport:
    """Test filter report generation."""
    
    def test_create_basic_report(self):
        """Test creation of basic filter report."""
        before = [
            {'severity': 'high', 'vulnerability_type': 'access_control'},
            {'severity': 'critical', 'vulnerability_type': 'access_control'},
        ]
        
        after = [
            {'severity': 'high', 'vulnerability_type': 'access_control', 'is_false_positive': True},
            {'severity': 'critical', 'vulnerability_type': 'reentrancy', 'is_false_positive': False},
        ]
        
        stats = FilterStats(total_findings=2, filtered_findings=1)
        stats.filtered_by_reason = {'Protected at proxy level': 1}
        
        report = create_filter_report(before, after, stats)
        
        assert 'PROXY PATTERN FILTER REPORT' in report
        assert 'Total findings before filtering: 2' in report
        assert 'Total findings after filtering: 2' in report
        assert 'Filtered as false positives: 1' in report
        assert 'Protected at proxy level: 1' in report
    
    def test_report_with_severity_breakdown(self):
        """Test report includes severity breakdown."""
        before = []
        after = [
            {'severity': 'high', 'is_false_positive': False},
            {'severity': 'medium', 'is_false_positive': False},
            {'severity': 'high', 'is_false_positive': True},
        ]
        
        stats = FilterStats()
        report = create_filter_report(before, after, stats)
        
        assert 'Remaining findings by severity' in report
        assert 'High: 1' in report
        assert 'Medium: 1' in report


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        self.filter = ProxyPatternFilter(verbose=False)
    
    def test_finding_with_missing_fields(self):
        """Test handling of findings with missing fields."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                # Missing contract_name, function_name, etc.
            }
        ]
        
        flow = DelegationFlow(has_proxy_pattern=True)
        filtered = self.filter.filter_findings(findings, flow)
        
        # Should not crash
        assert len(filtered) == 1
    
    def test_empty_delegation_flow(self):
        """Test handling of empty delegation flow."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Test',
                'function_name': 'test',
            }
        ]
        
        flow = DelegationFlow(has_proxy_pattern=True)  # No proxies or modules
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == 1
    
    def test_multiple_proxies(self):
        """Test handling of multiple proxy contracts."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Module1',
                'function_name': 'func1',
                'file_path': 'modules/Module1.sol',
            }
        ]
        
        proxy1 = ProxyContract(name='Proxy1', file_path='', proxy_type=ProxyType.UUPS)
        proxy1.protected_functions = {'func1'}
        
        proxy2 = ProxyContract(name='Proxy2', file_path='', proxy_type=ProxyType.TRANSPARENT)
        
        module = ModuleContract(name='Module1', file_path='modules/Module1.sol', is_library=False)
        module.protected_by_proxy = {'func1'}
        
        flow = DelegationFlow(
            has_proxy_pattern=True,
            proxy_contracts=[proxy1, proxy2],
            module_contracts=[module],
            protected_at_proxy={'func1'}
        )
        
        filtered = self.filter.filter_findings(findings, flow)
        
        assert len(filtered) == 1
        assert filtered[0]['is_false_positive'] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

