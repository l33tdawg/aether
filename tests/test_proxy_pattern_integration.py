#!/usr/bin/env python3
"""
Integration tests for proxy pattern detection and filtering in the audit pipeline.
Tests the complete flow from delegation analysis through false positive filtering.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from core.delegation_analyzer import DelegationFlowAnalyzer, DelegationFlow, ProxyContract, ModuleContract, ProxyType
from core.proxy_pattern_filter import ProxyPatternFilter
from core.enhanced_audit_engine import EnhancedAetherAuditEngine


class TestSSVNetworkIntegration:
    """Integration tests with SSV Network pattern (the original false positive case)."""
    
    def setup_method(self):
        self.ssv_proxy_content = '''
            pragma solidity 0.8.24;
            import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
            
            contract SSVNetwork is UUPSUpgradeable, Ownable2StepUpgradeable {
                function updateNetworkFee(uint256 fee) external override onlyOwner {
                    _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                }
                
                function withdrawNetworkEarnings(uint256 amount) external override onlyOwner {
                    _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                }
                
                function updateMaximumOperatorFee(uint64 maxFee) external override onlyOwner {
                    _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                }
            }
        '''
        
        self.ssv_dao_content = '''
            pragma solidity 0.8.24;
            
            contract SSVDAO is ISSVDAO {
                function updateNetworkFee(uint256 fee) external override {
                    StorageProtocol storage sp = SSVStorageProtocol.load();
                    sp.updateNetworkFee(fee);
                }
                
                function withdrawNetworkEarnings(uint256 amount) external override {
                    CoreLib.transferBalance(msg.sender, amount);
                }
                
                function updateMaximumOperatorFee(uint64 maxFee) external override {
                    SSVStorageProtocol.load().operatorMaxFee = maxFee;
                }
            }
        '''
        
        self.contract_files = [
            {
                'name': 'SSVNetwork.sol',
                'path': 'contracts/SSVNetwork.sol',
                'content': self.ssv_proxy_content
            },
            {
                'name': 'SSVDAO.sol',
                'path': 'contracts/modules/SSVDAO.sol',
                'content': self.ssv_dao_content
            }
        ]
    
    def test_delegation_flow_analysis(self):
        """Test that delegation flow is correctly analyzed."""
        analyzer = DelegationFlowAnalyzer()
        flow = analyzer.analyze_delegation_flow(self.contract_files)
        
        assert flow.has_proxy_pattern is True
        assert len(flow.proxy_contracts) == 1
        assert flow.proxy_contracts[0].proxy_type == ProxyType.UUPS
        assert len(flow.module_contracts) == 1
        assert 'updateNetworkFee' in flow.protected_at_proxy
        assert 'withdrawNetworkEarnings' in flow.protected_at_proxy
        assert 'updateMaximumOperatorFee' in flow.protected_at_proxy
    
    def test_filter_ssv_false_positives(self):
        """Test that SSV DAO false positives are filtered."""
        # Create typical false positive findings from SSV audit
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'updateNetworkFee',
                'description': 'All sensitive protocol parameter update functions are externally callable',
                'severity': 'critical',
                'confidence': 0.95,
                'file_path': 'contracts/modules/SSVDAO.sol',
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'withdrawNetworkEarnings',
                'description': 'Critical functions lack access control',
                'severity': 'high',
                'confidence': 0.90,
                'file_path': 'contracts/modules/SSVDAO.sol',
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SSVDAO.sol',
                'function_name': 'updateMaximumOperatorFee',
                'description': 'External function lacks access control',
                'severity': 'critical',
                'confidence': 0.80,
                'file_path': 'contracts/modules/SSVDAO.sol',
            }
        ]
        
        # Analyze delegation flow
        analyzer = DelegationFlowAnalyzer()
        flow = analyzer.analyze_delegation_flow(self.contract_files)
        
        # Apply filter
        filter = ProxyPatternFilter(verbose=False)
        filtered = filter.filter_findings(findings, flow, self.contract_files)
        
        # All should be marked as false positives
        assert len(filtered) == 3
        for finding in filtered:
            assert finding['is_false_positive'] is True
            assert 'proxy level' in finding['false_positive_reason'].lower()
            assert finding['confidence'] < 0.5  # Reduced confidence
        
        # Check statistics
        stats = filter.get_filter_stats()
        assert stats.total_findings == 3
        assert stats.filtered_findings == 3


class TestDelegationPatternFullPipeline:
    """Test the complete pipeline with delegation pattern detection."""
    
    def test_quick_filter_identifies_delegation(self):
        """Test that quick filter identifies delegation patterns."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Implementation',
                'function_name': 'adminFunc',
                'description': 'Missing access control',
            }
        ]
        
        contracts = [
            {
                'name': 'Proxy.sol',
                'content': '''
                    contract Proxy {
                        function adminFunc() external onlyOwner {
                            _delegate(implementation);
                        }
                    }
                '''
            },
            {
                'name': 'Implementation.sol',
                'content': '''
                    contract Implementation {
                        function adminFunc() external {
                            // Logic
                        }
                    }
                '''
            }
        ]
        
        filter = ProxyPatternFilter(verbose=False)
        filtered = filter.apply_quick_filter(findings, contracts)
        
        assert len(filtered) == 1
        assert filtered[0]['is_false_positive'] is True


class TestMultiProxyPatterns:
    """Test handling of multiple proxy patterns."""
    
    def test_multiple_modules_single_proxy(self):
        """Test filtering with single proxy and multiple modules."""
        contracts = [
            {
                'name': 'MainProxy.sol',
                'path': 'contracts/MainProxy.sol',
                'content': '''
                    contract MainProxy is UUPSUpgradeable {
                        function funcA() external onlyOwner {
                            _delegate(modules[MODULE_A]);
                        }
                        function funcB() external onlyRole(ADMIN) {
                            _delegate(modules[MODULE_B]);
                        }
                    }
                '''
            },
            {
                'name': 'ModuleA.sol',
                'path': 'contracts/modules/ModuleA.sol',
                'content': '''
                    contract ModuleA {
                        function funcA() external {
                            // Implementation
                        }
                    }
                '''
            },
            {
                'name': 'ModuleB.sol',
                'path': 'contracts/modules/ModuleB.sol',
                'content': '''
                    contract ModuleB {
                        function funcB() external {
                            // Implementation
                        }
                    }
                '''
            }
        ]
        
        analyzer = DelegationFlowAnalyzer()
        flow = analyzer.analyze_delegation_flow(contracts)
        
        assert flow.has_proxy_pattern is True
        assert len(flow.proxy_contracts) == 1
        assert len(flow.module_contracts) == 2
        
        # Both functions should be protected
        assert 'funcA' in flow.protected_at_proxy
        assert 'funcB' in flow.protected_at_proxy


class TestEdgeCasesIntegration:
    """Test edge cases in the integration."""
    
    def test_no_delegation_pattern_no_filtering(self):
        """Test that no filtering occurs when no delegation pattern exists."""
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'SimpleContract',
                'function_name': 'adminFunc',
                'description': 'Missing access control',
            }
        ]
        
        contracts = [
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
        
        analyzer = DelegationFlowAnalyzer()
        flow = analyzer.analyze_delegation_flow(contracts)
        
        filter = ProxyPatternFilter(verbose=False)
        filtered = filter.filter_findings(findings, flow, contracts)
        
        # Should not be filtered
        assert len(filtered) == 1
        assert not filtered[0].get('is_false_positive', False)
    
    def test_mixed_legitimate_and_false_positive(self):
        """Test filtering when some findings are legitimate and some are false positives."""
        contracts = [
            {
                'name': 'Proxy.sol',
                'content': '''
                    contract Proxy is UUPSUpgradeable {
                        function protectedFunc() external onlyOwner {
                            _delegate(module);
                        }
                        
                        function unprotectedFunc() external {
                            // No delegation, no protection
                        }
                    }
                '''
            },
            {
                'name': 'Module.sol',
                'path': 'contracts/modules/Module.sol',
                'content': '''
                    contract Module {
                        function protectedFunc() external {
                            // Implementation
                        }
                    }
                '''
            }
        ]
        
        findings = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Module.sol',
                'function_name': 'protectedFunc',
                'description': 'Missing access control',
                'file_path': 'contracts/modules/Module.sol',
            },
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'Proxy.sol',
                'function_name': 'unprotectedFunc',
                'description': 'Missing access control',
                'file_path': 'contracts/Proxy.sol',
            }
        ]
        
        analyzer = DelegationFlowAnalyzer()
        flow = analyzer.analyze_delegation_flow(contracts)
        
        filter = ProxyPatternFilter(verbose=False)
        filtered = filter.filter_findings(findings, flow, contracts)
        
        assert len(filtered) == 2
        
        # First should be false positive (module function protected at proxy)
        module_finding = next(f for f in filtered if f['contract_name'] == 'Module.sol')
        assert module_finding.get('is_false_positive', False) is True
        
        # Second should be legitimate (proxy function not protected)
        proxy_finding = next(f for f in filtered if f['contract_name'] == 'Proxy.sol')
        assert not proxy_finding.get('is_false_positive', False)


class TestReportingIntegration:
    """Test that filtering results are properly reported."""
    
    def test_filter_stats_collection(self):
        """Test that filter statistics are properly collected."""
        from core.proxy_pattern_filter import create_filter_report, FilterStats
        
        before = [
            {'severity': 'critical', 'vulnerability_type': 'access_control'},
            {'severity': 'high', 'vulnerability_type': 'access_control'},
            {'severity': 'medium', 'vulnerability_type': 'reentrancy'},
        ]
        
        after = [
            {'severity': 'critical', 'vulnerability_type': 'access_control', 'is_false_positive': True},
            {'severity': 'high', 'vulnerability_type': 'access_control', 'is_false_positive': True},
            {'severity': 'medium', 'vulnerability_type': 'reentrancy', 'is_false_positive': False},
        ]
        
        stats = FilterStats(total_findings=3, filtered_findings=2)
        stats.filtered_by_reason = {
            'Function protected at proxy level': 2
        }
        
        report = create_filter_report(before, after, stats)
        
        assert 'PROXY PATTERN FILTER REPORT' in report
        assert 'Total findings before filtering: 3' in report
        assert 'Filtered as false positives: 2' in report
        assert 'Function protected at proxy level: 2' in report
        assert 'Medium: 1' in report  # Only non-FP medium should be counted


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

