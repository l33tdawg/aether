#!/usr/bin/env python3
"""
Code Quality Analyzer

Detects code quality issues in Solidity smart contracts that could indicate
maintainability problems, potential bugs, or areas that need attention.

This module generalizes to all Solidity contracts and addresses issues like:
- Variable shadowing
- Missing documentation (NatSpec)
- Magic numbers
- Inconsistent naming conventions
- Unused state variables
- Complex function analysis
"""

import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class QualityIssueType(Enum):
    """Types of code quality issues"""
    VARIABLE_SHADOWING = "variable_shadowing"
    MISSING_NATSPEC = "missing_natspec"
    MAGIC_NUMBER = "magic_number"
    NAMING_INCONSISTENCY = "naming_inconsistency"
    UNUSED_STATE_VARIABLE = "unused_state_variable"
    COMPLEX_FUNCTION = "complex_function"
    DEPRECATED_PATTERN = "deprecated_pattern"
    CENTRALIZATION_RISK = "centralization_risk"


@dataclass
class CodeQualityIssue:
    """Represents a code quality issue."""
    vulnerability_type: str
    severity: str
    confidence: float
    line_number: int
    description: str
    code_snippet: str
    swc_id: str = ""
    category: str = "code_quality"
    context: Dict[str, Any] = None
    validation_status: str = "validated"
    recommendation: str = ""
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


class CodeQualityAnalyzer:
    """
    Comprehensive code quality analyzer for Solidity smart contracts.
    
    Detects various code quality issues that could lead to bugs, 
    maintainability problems, or security concerns.
    """
    
    def __init__(self):
        # Import the variable shadowing detector
        from .variable_shadowing_detector import VariableShadowingDetector
        self.shadowing_detector = VariableShadowingDetector()
        
        # Magic numbers to ignore (common acceptable values)
        self.acceptable_magic_numbers = {
            '0', '1', '2', '10', '100', '1000', '1e18', '1e6', '1e9',
            '18', '256', '32', '64', '128',  # Common bit sizes
            '0x0', '0x00', '0xffffffff',  # Common hex values
        }
        
        # Common naming conventions
        self.naming_patterns = {
            'constant': r'^[A-Z][A-Z0-9_]*$',  # SCREAMING_SNAKE_CASE
            'state_variable': r'^[a-z][a-zA-Z0-9]*$|^_[a-z][a-zA-Z0-9]*$',  # camelCase or _camelCase
            'function': r'^[a-z][a-zA-Z0-9]*$',  # camelCase
            'parameter': r'^[a-z][a-zA-Z0-9]*$|^_[a-z][a-zA-Z0-9]*$',  # camelCase or _camelCase
            'event': r'^[A-Z][a-zA-Z0-9]*$',  # PascalCase
        }
        
        # Centralization-related modifiers
        self.centralization_modifiers = [
            'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance',
            'onlyOwnerOrAdmin', 'onlyOperator', 'onlyManager', 'authorized',
            'onlyMinter', 'onlyPauser', 'onlyUpgrader'
        ]
        
        # High-risk privileged actions
        self.high_risk_actions = [
            'pause', 'unpause', 'setAddress', 'upgrade', 'migrate',
            'withdrawAll', 'emergencyWithdraw', 'transferOwnership',
            'renounceOwnership', 'setFee', 'setRate', 'mint', 'burn',
            'blacklist', 'whitelist', 'freeze', 'unfreeze'
        ]
    
    def analyze_contract(self, contract_content: str, file_path: str = "") -> List[CodeQualityIssue]:
        """
        Analyze a Solidity contract for code quality issues.
        
        Args:
            contract_content: The Solidity source code
            file_path: Optional file path for context
            
        Returns:
            List of detected code quality issues
        """
        issues = []
        lines = contract_content.split('\n')
        
        # 1. Variable shadowing detection
        shadowing_issues = self._detect_variable_shadowing(contract_content, file_path)
        issues.extend(shadowing_issues)
        
        # 2. Missing NatSpec documentation
        natspec_issues = self._detect_missing_natspec(contract_content, lines)
        issues.extend(natspec_issues)
        
        # 3. Magic numbers
        magic_number_issues = self._detect_magic_numbers(contract_content, lines)
        issues.extend(magic_number_issues)
        
        # 4. Naming inconsistencies
        naming_issues = self._detect_naming_inconsistencies(contract_content, lines)
        issues.extend(naming_issues)
        
        # 5. Centralization risks
        centralization_issues = self._detect_centralization_risks(contract_content, lines)
        issues.extend(centralization_issues)
        
        # 6. Deprecated patterns
        deprecated_issues = self._detect_deprecated_patterns(contract_content, lines)
        issues.extend(deprecated_issues)
        
        return issues
    
    def _detect_variable_shadowing(self, contract_content: str, file_path: str) -> List[CodeQualityIssue]:
        """Detect variable shadowing issues using the dedicated detector."""
        issues = []
        
        shadowing_vulns = self.shadowing_detector.analyze_contract(contract_content, file_path)
        
        for vuln in shadowing_vulns:
            issues.append(CodeQualityIssue(
                vulnerability_type='variable_shadowing',
                severity=vuln.severity,
                confidence=vuln.confidence,
                line_number=vuln.line_number,
                description=vuln.description,
                code_snippet=vuln.code_snippet,
                swc_id='SWC-119',
                category='code_quality',
                context=vuln.context,
                recommendation='Rename the local variable to avoid confusion with the state variable.'
            ))
        
        return issues
    
    def _detect_missing_natspec(self, contract_content: str, lines: List[str]) -> List[CodeQualityIssue]:
        """Detect public/external functions missing NatSpec documentation."""
        issues = []
        
        # Pattern for public/external functions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)[^{]*\{'
        
        for match in re.finditer(func_pattern, contract_content, re.DOTALL):
            func_name = match.group(1)
            func_start = match.start()
            line_number = contract_content[:func_start].count('\n') + 1
            
            # Check if there's NatSpec documentation before this function
            # Look for /// or /** within 5 lines before the function
            has_natspec = False
            start_search = max(0, line_number - 6)
            
            for i in range(start_search, line_number - 1):
                if i < len(lines):
                    line = lines[i].strip()
                    if line.startswith('///') or line.startswith('/**') or line.startswith('* @'):
                        has_natspec = True
                        break
            
            # Skip internal functions and common patterns that don't need documentation
            skip_functions = [
                'constructor', 'receive', 'fallback', '_', 'test', 'setUp'
            ]
            should_skip = any(func_name.lower().startswith(skip.lower()) for skip in skip_functions)
            
            if not has_natspec and not should_skip:
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                issues.append(CodeQualityIssue(
                    vulnerability_type='missing_natspec',
                    severity='informational',
                    confidence=0.80,
                    line_number=line_number,
                    description=f'Public/external function {func_name}() lacks NatSpec documentation',
                    code_snippet=code_snippet[:100] + '...' if len(code_snippet) > 100 else code_snippet,
                    category='code_quality',
                    recommendation=f'Add /// @notice and /// @param documentation above {func_name}()'
                ))
        
        return issues
    
    def _detect_magic_numbers(self, contract_content: str, lines: List[str]) -> List[CodeQualityIssue]:
        """Detect magic numbers that should be constants."""
        issues = []
        
        # Skip constants, enums, and variable declarations
        skip_contexts = ['constant', 'immutable', 'enum', 'pragma', 'import']
        
        # Pattern for numeric literals (not in acceptable list)
        number_pattern = r'(?<![a-zA-Z0-9_])(\d+(?:e\d+)?|\d+\.\d+)(?![a-zA-Z0-9_])'
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments and certain declarations
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if any(ctx in stripped.lower() for ctx in skip_contexts):
                continue
            
            # Find numeric literals
            for match in re.finditer(number_pattern, line):
                number = match.group(1)
                
                # Skip acceptable magic numbers
                if number in self.acceptable_magic_numbers:
                    continue
                
                # Skip if it's in an array index context with small numbers
                if int(float(number)) < 10:
                    continue
                
                # Skip if it's clearly a time/gas value
                if any(ctx in line.lower() for ctx in ['seconds', 'minutes', 'hours', 'days', 'gas', 'wei', 'gwei', 'ether']):
                    continue
                
                # Check if this looks like a significant magic number
                try:
                    num_val = float(number)
                    if num_val > 100 and num_val not in [256, 1000, 10000, 100000]:
                        issues.append(CodeQualityIssue(
                            vulnerability_type='magic_number',
                            severity='informational',
                            confidence=0.60,
                            line_number=i,
                            description=f'Magic number {number} should be defined as a named constant',
                            code_snippet=stripped[:100] + '...' if len(stripped) > 100 else stripped,
                            category='code_quality',
                            recommendation=f'Define a constant: uint256 constant SOME_NAME = {number};'
                        ))
                except ValueError:
                    pass
        
        return issues
    
    def _detect_naming_inconsistencies(self, contract_content: str, lines: List[str]) -> List[CodeQualityIssue]:
        """Detect naming convention inconsistencies."""
        issues = []
        
        # Check constant naming (should be SCREAMING_SNAKE_CASE)
        constant_pattern = r'(?:uint\d*|int\d*|bytes\d*|address|bool|string)\s+(?:public\s+)?(?:private\s+)?(?:internal\s+)?constant\s+(\w+)'
        
        for match in re.finditer(constant_pattern, contract_content):
            const_name = match.group(1)
            line_number = contract_content[:match.start()].count('\n') + 1
            
            # Check if it follows SCREAMING_SNAKE_CASE
            if not re.match(self.naming_patterns['constant'], const_name):
                issues.append(CodeQualityIssue(
                    vulnerability_type='naming_inconsistency',
                    severity='informational',
                    confidence=0.75,
                    line_number=line_number,
                    description=f'Constant "{const_name}" should use SCREAMING_SNAKE_CASE naming convention',
                    code_snippet=match.group(0)[:80],
                    category='code_quality',
                    recommendation=f'Rename to: {self._to_screaming_snake_case(const_name)}'
                ))
        
        return issues
    
    def _detect_centralization_risks(self, contract_content: str, lines: List[str]) -> List[CodeQualityIssue]:
        """
        Detect centralization risks where a single admin/owner has too much control.
        
        This is important for security audits as it identifies potential single points of failure.
        """
        issues = []
        
        # Track privileged functions
        privileged_functions = []
        
        for mod in self.centralization_modifiers:
            pattern = rf'function\s+(\w+)\s*\([^)]*\)[^{{]*{mod}[^{{]*\{{'
            
            for match in re.finditer(pattern, contract_content, re.DOTALL):
                func_name = match.group(1)
                line_number = contract_content[:match.start()].count('\n') + 1
                
                # Determine if this is a high-risk action
                is_high_risk = any(action in func_name.lower() for action in self.high_risk_actions)
                
                privileged_functions.append({
                    'name': func_name,
                    'modifier': mod,
                    'line': line_number,
                    'high_risk': is_high_risk
                })
        
        # Report if there are many privileged functions
        if len(privileged_functions) >= 3:
            high_risk_count = sum(1 for f in privileged_functions if f['high_risk'])
            
            func_list = ', '.join([f"{f['name']}()" for f in privileged_functions[:5]])
            if len(privileged_functions) > 5:
                func_list += f', ... (+{len(privileged_functions) - 5} more)'
            
            issues.append(CodeQualityIssue(
                vulnerability_type='centralization_risk',
                severity='informational',
                confidence=0.90,
                line_number=1,
                description=f'Contract has {len(privileged_functions)} privileged functions '
                            f'({high_risk_count} high-risk): {func_list}. '
                            f'Consider implementing timelocks or multi-sig for critical operations.',
                code_snippet='Multiple admin functions detected',
                category='centralization',
                context={
                    'total_privileged': len(privileged_functions),
                    'high_risk_count': high_risk_count,
                    'functions': privileged_functions
                },
                recommendation='Consider adding timelocks, multi-sig requirements, or decentralized governance for critical functions.'
            ))
        
        return issues
    
    def _detect_deprecated_patterns(self, contract_content: str, lines: List[str]) -> List[CodeQualityIssue]:
        """Detect usage of deprecated Solidity patterns."""
        issues = []
        
        deprecated_patterns = [
            {
                'pattern': r'\bsuicide\s*\(',
                'description': 'suicide() is deprecated, use selfdestruct()',
                'replacement': 'selfdestruct()'
            },
            {
                'pattern': r'\bblock\.blockhash\s*\(',
                'description': 'block.blockhash() is deprecated, use blockhash()',
                'replacement': 'blockhash()'
            },
            {
                'pattern': r'\bmsg\.gas\b',
                'description': 'msg.gas is deprecated, use gasleft()',
                'replacement': 'gasleft()'
            },
            {
                'pattern': r'\bsha3\s*\(',
                'description': 'sha3() is deprecated, use keccak256()',
                'replacement': 'keccak256()'
            },
            {
                'pattern': r'\bcallcode\s*\(',
                'description': 'callcode() is deprecated, use delegatecall()',
                'replacement': 'delegatecall()'
            },
            {
                'pattern': r'\bthrow\b',
                'description': 'throw is deprecated, use revert() or require()',
                'replacement': 'revert() or require()'
            },
            {
                'pattern': r'constant\s+function',
                'description': 'constant function modifier is deprecated, use view or pure',
                'replacement': 'view or pure'
            },
        ]
        
        for pattern_info in deprecated_patterns:
            for match in re.finditer(pattern_info['pattern'], contract_content):
                line_number = contract_content[:match.start()].count('\n') + 1
                line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                issues.append(CodeQualityIssue(
                    vulnerability_type='deprecated_pattern',
                    severity='low',
                    confidence=0.95,
                    line_number=line_number,
                    description=pattern_info['description'],
                    code_snippet=line_content[:100],
                    swc_id='SWC-111',
                    category='code_quality',
                    recommendation=f"Replace with {pattern_info['replacement']}"
                ))
        
        return issues
    
    def _to_screaming_snake_case(self, name: str) -> str:
        """Convert a name to SCREAMING_SNAKE_CASE."""
        # Insert underscores before uppercase letters
        result = re.sub(r'([A-Z])', r'_\1', name)
        # Remove leading underscore if present
        if result.startswith('_'):
            result = result[1:]
        # Convert to uppercase
        return result.upper()
    
    def get_quality_summary(self, issues: List[CodeQualityIssue]) -> Dict[str, Any]:
        """Get a summary of code quality issues."""
        summary = {
            'total_issues': len(issues),
            'by_severity': {
                'low': 0,
                'informational': 0,
                'medium': 0,
                'high': 0
            },
            'by_type': {},
            'recommendations': []
        }
        
        for issue in issues:
            severity = issue.severity.lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            vuln_type = issue.vulnerability_type
            if vuln_type not in summary['by_type']:
                summary['by_type'][vuln_type] = 0
            summary['by_type'][vuln_type] += 1
            
            if issue.recommendation:
                summary['recommendations'].append({
                    'type': vuln_type,
                    'line': issue.line_number,
                    'recommendation': issue.recommendation
                })
        
        return summary
