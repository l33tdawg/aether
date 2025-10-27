#!/usr/bin/env python3
"""
Proxy Pattern Filter - Removes false positives from proxy delegation patterns.

This module filters out false positive findings that occur when access control
is enforced at the proxy level but not in the delegated module/implementation.

Primary use case: Prevent flagging module functions as "unprotected" when the
proxy contract has proper access control.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from core.delegation_analyzer import DelegationFlow, DelegationFlowAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class FilterStats:
    """Statistics about filtering operation."""
    total_findings: int = 0
    filtered_findings: int = 0
    filtered_by_reason: Dict[str, int] = None
    
    def __post_init__(self):
        if self.filtered_by_reason is None:
            self.filtered_by_reason = {}


class ProxyPatternFilter:
    """Filters false positives caused by proxy delegation patterns."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = FilterStats()
        
        # Vulnerability types that commonly have proxy-related false positives
        self.proxy_sensitive_vuln_types = [
            'access_control',
            'authorization',
            'unprotected_function',
            'missing_access_control',
            'upgrade_authorization',
        ]
    
    def filter_findings(self,
                       findings: List[Dict[str, Any]],
                       delegation_flow: DelegationFlow,
                       contract_files: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Filter out false positives from proxy patterns.
        
        Args:
            findings: List of vulnerability findings
            delegation_flow: Delegation flow analysis result
            contract_files: Optional list of contract files for additional context
            
        Returns:
            Filtered list of findings
        """
        if not delegation_flow.has_proxy_pattern:
            if self.verbose:
                logger.info("No proxy pattern detected - skipping proxy filter")
            return findings
        
        self.stats = FilterStats(total_findings=len(findings))
        filtered = []
        
        if self.verbose:
            logger.info(f"🔍 Filtering {len(findings)} findings for proxy pattern false positives...")
        
        for finding in findings:
            should_filter, reason = self._should_filter_finding(finding, delegation_flow)
            
            if should_filter:
                self.stats.filtered_findings += 1
                self.stats.filtered_by_reason[reason] = self.stats.filtered_by_reason.get(reason, 0) + 1
                
                if self.verbose:
                    vuln_type = finding.get('vulnerability_type', 'unknown')
                    func_name = finding.get('function_name', '')
                    logger.info(f"   ✂️  Filtered: {vuln_type} in {func_name} - {reason}")
                
                # Mark as false positive but keep in findings for transparency
                finding['is_false_positive'] = True
                finding['false_positive_reason'] = reason
                finding['filtered_by'] = 'proxy_pattern_filter'
                finding['confidence'] = max(0.05, finding.get('confidence', 0.5) - 0.7)
                
                # Optionally, completely remove from findings
                # For now, we'll keep it but marked as FP
                filtered.append(finding)
            else:
                filtered.append(finding)
        
        if self.verbose and self.stats.filtered_findings > 0:
            self._print_filter_stats()
        
        return filtered
    
    def _should_filter_finding(self,
                               finding: Dict[str, Any],
                               flow: DelegationFlow) -> tuple[bool, str]:
        """
        Determine if a finding should be filtered as a false positive.
        
        Returns:
            (should_filter, reason)
        """
        vuln_type = finding.get('vulnerability_type', '').lower()
        contract_name = finding.get('contract_name', '')
        file_path = finding.get('file_path', '')
        function_name = finding.get('function_name', '')
        description = finding.get('description', '').lower()
        
        # Filter 1: Access control issues in module contracts
        if any(sensitive in vuln_type for sensitive in ['access', 'authorization', 'unprotected']):
            # Check if this is a module contract
            is_module = self._is_module_contract(contract_name, file_path, flow)
            
            if is_module and function_name:
                # Check if this function is protected at proxy level
                analyzer = DelegationFlowAnalyzer()
                is_protected, protection_reason = analyzer.is_function_protected_at_proxy(
                    function_name,
                    contract_name,
                    flow
                )
                
                if is_protected:
                    return (True, f"Function protected at proxy level: {protection_reason}")
        
        # Filter 2: Initialization issues in module contracts with proxy pattern
        if 'initialization' in vuln_type or 'initializer' in description:
            # If this is a module in a UUPS proxy, initialization is handled at proxy level
            is_module = self._is_module_contract(contract_name, file_path, flow)
            if is_module:
                for proxy in flow.proxy_contracts:
                    if 'UUPS' in proxy.proxy_type.value or 'Upgradeable' in proxy.proxy_type.value:
                        return (True, f"Module initialization handled by {proxy.name} proxy")
        
        # Filter 3: External call warnings in modules that only delegate
        if 'external call' in description and 'module' in file_path.lower():
            # Modules in proxy patterns are expected to have external calls
            # as they're called via delegation
            is_module = self._is_module_contract(contract_name, file_path, flow)
            if is_module:
                # Only filter if the finding is JUST about external calls existing
                if 'delegatecall' not in description and 'reentrancy' not in vuln_type:
                    return (True, "Module contract - external calls expected in proxy pattern")
        
        # Filter 4: Constructor warnings in proxy contracts
        if 'constructor' in description and 'constructor' in function_name.lower():
            for proxy in flow.proxy_contracts:
                if contract_name in proxy.name or proxy.name in contract_name:
                    # Proxy constructors are expected to be minimal
                    if 'disableInitializers' in description or 'disable' in description:
                        return (False, "")  # This is actually correct behavior
                    return (True, "Proxy contract - constructor initialization handled via initializer")
        
        return (False, "")
    
    def _is_module_contract(self, contract_name: str, file_path: str, flow: DelegationFlow) -> bool:
        """Check if a contract is a module/implementation contract."""
        # Check in module contracts list
        for module in flow.module_contracts:
            if contract_name in module.name or module.name in contract_name:
                return True
            if file_path and module.file_path in file_path:
                return True
        
        # Check if it's NOT a proxy contract
        for proxy in flow.proxy_contracts:
            if contract_name in proxy.name or proxy.name in contract_name:
                return False  # It's a proxy, not a module
        
        # Check for common module path patterns
        module_indicators = ['/modules/', '/implementations/', '/facets/', '/libraries/']
        if file_path and any(indicator in file_path for indicator in module_indicators):
            return True
        
        return False
    
    def _print_filter_stats(self):
        """Print filtering statistics."""
        logger.info("\n   📊 Proxy Pattern Filter Stats:")
        logger.info(f"      Total findings: {self.stats.total_findings}")
        logger.info(f"      Filtered as FP: {self.stats.filtered_findings}")
        logger.info(f"      Remaining: {self.stats.total_findings - self.stats.filtered_findings}")
        
        if self.stats.filtered_by_reason:
            logger.info("\n      Filtered by reason:")
            for reason, count in sorted(self.stats.filtered_by_reason.items(), 
                                       key=lambda x: x[1], reverse=True):
                logger.info(f"         • {reason}: {count}")
    
    def get_filter_stats(self) -> FilterStats:
        """Get filtering statistics."""
        return self.stats
    
    def apply_quick_filter(self,
                          findings: List[Dict[str, Any]],
                          contract_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Quick filter that doesn't require full delegation analysis.
        Useful for fast filtering when you just need to catch obvious cases.
        
        Args:
            findings: List of vulnerability findings
            contract_files: List of contract files
            
        Returns:
            Filtered findings
        """
        # Check if ANY contract has delegation patterns
        has_delegation = any(
            '_delegate' in f.get('content', '') or 
            'delegatecall' in f.get('content', '')
            for f in contract_files
        )
        
        if not has_delegation:
            return findings
        
        # Find the main proxy contract (has _delegate calls)
        proxy_contracts = []
        for file in contract_files:
            if '_delegate' in file.get('content', ''):
                proxy_contracts.append(file)
        
        if not proxy_contracts:
            return findings
        
        filtered = []
        for finding in findings:
            # Quick check: if access control issue and contract is not the proxy
            vuln_type = finding.get('vulnerability_type', '').lower()
            contract_name = finding.get('contract_name', '')
            function_name = finding.get('function_name', '')
            
            if 'access' in vuln_type or 'authorization' in vuln_type:
                # Check if this contract is a proxy
                is_proxy = any(
                    contract_name in p.get('name', '') 
                    for p in proxy_contracts
                )
                
                if not is_proxy and function_name:
                    # Check if proxy has this function with protection
                    for proxy in proxy_contracts:
                        proxy_content = proxy.get('content', '')
                        # Simple check: does proxy have "function {name}(...) external ... onlyOwner"
                        if (f"function {function_name}" in proxy_content and
                            'onlyOwner' in proxy_content):
                            # Likely a false positive
                            finding['is_false_positive'] = True
                            finding['false_positive_reason'] = (
                                f"Function appears to be protected at proxy level in {proxy.get('name', 'proxy')}"
                            )
                            finding['filtered_by'] = 'quick_proxy_filter'
                            break
            
            filtered.append(finding)
        
        return filtered


def create_filter_report(before_findings: List[Dict], 
                        after_findings: List[Dict],
                        stats: FilterStats) -> str:
    """
    Create a human-readable report of filtering results.
    
    Args:
        before_findings: Findings before filtering
        after_findings: Findings after filtering
        stats: Filter statistics
        
    Returns:
        Formatted report string
    """
    report_lines = [
        "=" * 60,
        "PROXY PATTERN FILTER REPORT",
        "=" * 60,
        "",
        f"Total findings before filtering: {len(before_findings)}",
        f"Total findings after filtering: {len(after_findings)}",
        f"Filtered as false positives: {stats.filtered_findings}",
        ""
    ]
    
    if stats.filtered_by_reason:
        report_lines.append("Breakdown by filter reason:")
        report_lines.append("-" * 60)
        for reason, count in sorted(stats.filtered_by_reason.items(), 
                                   key=lambda x: x[1], reverse=True):
            report_lines.append(f"  • {reason}: {count}")
        report_lines.append("")
    
    # Count by severity
    if after_findings:
        severity_counts = {}
        for finding in after_findings:
            if not finding.get('is_false_positive', False):
                severity = finding.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            report_lines.append("Remaining findings by severity:")
            report_lines.append("-" * 60)
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    report_lines.append(f"  • {severity.title()}: {severity_counts[severity]}")
    
    report_lines.append("")
    report_lines.append("=" * 60)
    
    return "\n".join(report_lines)


if __name__ == "__main__":
    # Quick test
    from core.delegation_analyzer import DelegationFlowAnalyzer
    
    # Simulate SSV Network findings
    test_findings = [
        {
            'vulnerability_type': 'access_control',
            'contract_name': 'SSVDAO.sol',
            'function_name': 'updateNetworkFee',
            'description': 'Function lacks access control',
            'severity': 'high',
            'confidence': 0.9,
        },
        {
            'vulnerability_type': 'access_control',
            'contract_name': 'SSVDAO.sol',
            'function_name': 'withdrawNetworkEarnings',
            'description': 'Function lacks access control',
            'severity': 'critical',
            'confidence': 0.95,
        },
        {
            'vulnerability_type': 'reentrancy',
            'contract_name': 'SSVClusters.sol',
            'function_name': 'withdraw',
            'description': 'Potential reentrancy',
            'severity': 'high',
            'confidence': 0.8,
        }
    ]
    
    # Simulate SSV contracts
    test_contracts = [
        {
            'name': 'SSVNetwork.sol',
            'path': 'contracts/SSVNetwork.sol',
            'content': '''
                contract SSVNetwork is UUPSUpgradeable {
                    function updateNetworkFee(uint256 fee) external onlyOwner {
                        _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                    }
                    function withdrawNetworkEarnings(uint256 amount) external onlyOwner {
                        _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                    }
                }
            '''
        },
        {
            'name': 'SSVDAO.sol',
            'path': 'contracts/modules/SSVDAO.sol',
            'content': '''
                contract SSVDAO {
                    function updateNetworkFee(uint256 fee) external {
                        // Implementation
                    }
                    function withdrawNetworkEarnings(uint256 amount) external {
                        // Implementation
                    }
                }
            '''
        }
    ]
    
    # Analyze delegation flow
    analyzer = DelegationFlowAnalyzer()
    flow = analyzer.analyze_delegation_flow(test_contracts)
    
    print(analyzer.get_summary(flow))
    print()
    
    # Filter findings
    filter = ProxyPatternFilter(verbose=True)
    filtered_findings = filter.filter_findings(test_findings, flow)
    
    print()
    print(create_filter_report(test_findings, filtered_findings, filter.get_filter_stats()))

