"""
Advanced static analysis engine for AetherAudit.
Implements taint analysis, integer overflow detection, and advanced vulnerability detection.
"""

import re
import ast
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict, deque
import math


@dataclass
class TaintSource:
    """Represents a taint source in the code."""
    variable: str
    line_number: int
    source_type: str  # 'user_input', 'external_call', 'block_data', etc.
    confidence: float


@dataclass
class TaintSink:
    """Represents a taint sink in the code."""
    variable: str
    line_number: int
    sink_type: str  # 'external_call', 'state_update', 'arithmetic', etc.
    severity: str


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink."""
    source: TaintSource
    sink: TaintSink
    path: List[str]  # Variables in the taint path
    confidence: float
    vulnerability_type: str


@dataclass
class IntegerOverflow:
    """Represents an integer overflow vulnerability."""
    line_number: int
    operation: str
    variable: str
    overflow_type: str  # 'addition', 'multiplication', 'subtraction', etc.
    confidence: float
    severity: str


@dataclass
class AccessControlBypass:
    """Represents an access control bypass vulnerability."""
    function_name: str
    line_number: int
    bypass_type: str  # 'missing_modifier', 'weak_check', 'tx_origin', etc.
    confidence: float
    severity: str


class AdvancedStaticAnalyzer:
    """Advanced static analysis engine with taint analysis and vulnerability detection."""
    
    def __init__(self):
        self.taint_sources = []
        self.taint_sinks = []
        self.taint_flows = []
        self.integer_overflows = []
        self.access_control_bypasses = []
        
        # Taint analysis configuration
        self.taint_sources_patterns = self._initialize_taint_sources()
        self.taint_sinks_patterns = self._initialize_taint_sinks()
        
        # Integer overflow patterns
        self.overflow_patterns = self._initialize_overflow_patterns()
        
        # Access control patterns
        self.access_control_patterns = self._initialize_access_control_patterns()
        
        # Variable tracking
        self.variable_definitions = {}
        self.variable_uses = {}
        self.function_calls = {}
        
    def _initialize_taint_sources(self) -> Dict[str, List[str]]:
        """Initialize taint source patterns."""
        return {
            'user_input': [
                r'msg\.data',
                r'msg\.value',
                r'msg\.sender',
                r'calldata',
                r'function\s+\w+\s*\([^)]*\)\s*(public|external)',
                r'abi\.decode\s*\(',
                r'abi\.encode\s*\('
            ],
            'external_call': [
                r'\.call\s*\(',
                r'\.delegatecall\s*\(',
                r'\.staticcall\s*\(',
                r'\.send\s*\(',
                r'\.transfer\s*\('
            ],
            'block_data': [
                r'block\.timestamp',
                r'block\.number',
                r'block\.hash\s*\(',
                r'block\.coinbase',
                r'block\.difficulty',
                r'block\.gaslimit'
            ],
            'tx_data': [
                r'tx\.origin',
                r'tx\.gasprice',
                r'tx\.gas',
                r'tx\.value'
            ],
            'oracle_data': [
                r'getAssetPrice\s*\(',
                r'latestAnswer\s*\(',
                r'latestRoundData\s*\(',
                r'chainlink\s*\.\s*price',
                r'oracle\s*\.\s*get'
            ]
        }
    
    def _initialize_taint_sinks(self) -> Dict[str, List[str]]:
        """Initialize taint sink patterns."""
        return {
            'external_call': [
                r'\.call\s*\{[^}]*value\s*:[^}]*\}',
                r'\.send\s*\(',
                r'\.transfer\s*\(',
                r'delegatecall\s*\(',
                r'staticcall\s*\('
            ],
            'state_update': [
                r'balance\s*\[\s*[^]]+\s*\]\s*=',
                r'mapping\s*\(\s*[^)]+\s*\)\s*[^=]*=',
                r'uint256\s+\w+\s*=',
                r'address\s+\w+\s*=',
                r'bool\s+\w+\s*='
            ],
            'arithmetic': [
                r'\+\+|\-\-',
                r'\+=|\-=|\*=|\/=',
                r'balance\s*\[\s*[^]]+\s*\]\s*[\+\-\*\/]?=',
                r'uint256\s+\w+\s*=\s*\w+\s*[\+\-\*\/]\s*\w+'
            ],
            'control_flow': [
                r'require\s*\(',
                r'assert\s*\(',
                r'if\s*\(',
                r'while\s*\(',
                r'for\s*\('
            ],
            'storage_access': [
                r'storage\s*\.\s*\w+',
                r'sload\s*\(',
                r'sstore\s*\('
            ]
        }
    
    def _initialize_overflow_patterns(self) -> Dict[str, List[str]]:
        """Initialize integer overflow patterns."""
        return {
            'addition': [
                r'\w+\s*\+\s*\w+',
                r'\w+\s*\+=\s*\w+',
                r'\+\+',
                r'balance\s*\[\s*[^]]+\s*\]\s*\+=\s*\w+'
            ],
            'multiplication': [
                r'\w+\s*\*\s*\w+',
                r'\w+\s*\*=\s*\w+',
                r'balance\s*\[\s*[^]]+\s*\]\s*\*=\s*\w+'
            ],
            'subtraction': [
                r'\w+\s*-\s*\w+',
                r'\w+\s*-=\s*\w+',
                r'--',
                r'balance\s*\[\s*[^]]+\s*\]\s*-=\s*\w+'
            ],
            'division': [
                r'\w+\s*/\s*\w+',
                r'\w+\s*/=\s*\w+',
                r'balance\s*\[\s*[^]]+\s*\]\s*/=\s*\w+'
            ],
            'exponentiation': [
                r'\w+\s*\*\*\s*\w+',
                r'pow\s*\(',
                r'exp\s*\('
            ]
        }
    
    def _initialize_access_control_patterns(self) -> Dict[str, List[str]]:
        """Initialize access control patterns."""
        return {
            'missing_modifier': [
                r'function\s+\w+\s*\([^)]*\)\s*(public|external)\s*\{',
                r'function\s+\w+\s*\([^)]*\)\s*(public|external)\s*(view|pure)?\s*\{'
            ],
            'weak_check': [
                r'require\s*\(\s*msg\.sender\s*==\s*owner\s*\)',
                r'require\s*\(\s*msg\.sender\s*==\s*admin\s*\)',
                r'require\s*\(\s*msg\.sender\s*==\s*governance\s*\)'
            ],
            'tx_origin': [
                r'tx\.origin\s*==',
                r'require\s*\(\s*tx\.origin\s*==',
                r'if\s*\(\s*tx\.origin\s*=='
            ],
            'timestamp_dependency': [
                r'block\.timestamp\s*[<>=]',
                r'require\s*\(\s*block\.timestamp\s*[<>=]',
                r'if\s*\(\s*block\.timestamp\s*[<>=]'
            ],
            'block_number_dependency': [
                r'block\.number\s*[<>=]',
                r'require\s*\(\s*block\.number\s*[<>=]',
                r'if\s*\(\s*block\.number\s*[<>=]'
            ]
        }
    
    def analyze_contract(self, contract_code: str) -> Dict[str, Any]:
        """Perform comprehensive static analysis on contract code."""
        print("🔍 Starting advanced static analysis...")
        
        # Reset analysis state
        self._reset_analysis_state()
        
        # Parse contract structure
        self._parse_contract_structure(contract_code)
        
        # Perform taint analysis
        self._perform_taint_analysis(contract_code)
        
        # Detect integer overflows
        self._detect_integer_overflows(contract_code)
        
        # Detect access control bypasses
        self._detect_access_control_bypasses(contract_code)
        
        # Analyze control flow
        self._analyze_control_flow(contract_code)
        
        # Analyze state management
        self._analyze_state_management(contract_code)
        
        # Generate analysis report
        report = self._generate_analysis_report()
        
        print(f"✅ Advanced static analysis completed: {len(self.taint_flows)} taint flows, {len(self.integer_overflows)} overflows, {len(self.access_control_bypasses)} access control issues")
        
        return report
    
    def _reset_analysis_state(self):
        """Reset analysis state for new contract."""
        self.taint_sources = []
        self.taint_sinks = []
        self.taint_flows = []
        self.integer_overflows = []
        self.access_control_bypasses = []
        self.variable_definitions = {}
        self.variable_uses = {}
        self.function_calls = {}
    
    def _parse_contract_structure(self, contract_code: str):
        """Parse contract structure and extract variables, functions, etc."""
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line = line.strip()
            
            # Extract variable definitions
            var_match = re.search(r'(uint256|uint|address|bool|mapping|string)\s+(\w+)', line)
            if var_match:
                var_type = var_match.group(1)
                var_name = var_match.group(2)
                self.variable_definitions[var_name] = {
                    'type': var_type,
                    'line': line_num,
                    'scope': 'contract'
                }
            
            # Extract function definitions
            func_match = re.search(r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?', line)
            if func_match:
                func_name = func_match.group(1)
                visibility = func_match.group(2) or 'public'
                self.function_calls[func_name] = {
                    'visibility': visibility,
                    'line': line_num
                }
            
            # Extract variable uses
            var_uses = re.findall(r'\b(\w+)\b', line)
            for var in var_uses:
                if var in self.variable_definitions:
                    if var not in self.variable_uses:
                        self.variable_uses[var] = []
                    self.variable_uses[var].append(line_num)
    
    def _perform_taint_analysis(self, contract_code: str):
        """Perform taint analysis to find data flows from sources to sinks."""
        lines = contract_code.split('\n')
        
        # Identify taint sources
        for i, line in enumerate(lines):
            line_num = i + 1
            for source_type, patterns in self.taint_sources_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Extract variable name from match
                        var_name = self._extract_variable_name(match.group(), line)
                        if var_name:
                            taint_source = TaintSource(
                                variable=var_name,
                                line_number=line_num,
                                source_type=source_type,
                                confidence=0.8
                            )
                            self.taint_sources.append(taint_source)
        
        # Identify taint sinks
        for i, line in enumerate(lines):
            line_num = i + 1
            for sink_type, patterns in self.taint_sinks_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        var_name = self._extract_variable_name(match.group(), line)
                        if var_name:
                            taint_sink = TaintSink(
                                variable=var_name,
                                line_number=line_num,
                                sink_type=sink_type,
                                severity='high' if sink_type in ['external_call', 'state_update'] else 'medium'
                            )
                            self.taint_sinks.append(taint_sink)
        
        # Find taint flows
        self._find_taint_flows(contract_code)
    
    def _extract_variable_name(self, match_text: str, line: str) -> Optional[str]:
        """Extract variable name from match text."""
        # Simple extraction - in production, use AST parsing
        words = match_text.split()
        for word in words:
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', word):
                return word
        return None
    
    def _find_taint_flows(self, contract_code: str):
        """Find taint flows from sources to sinks."""
        lines = contract_code.split('\n')
        
        for source in self.taint_sources:
            for sink in self.taint_sinks:
                # Check if there's a potential flow
                if self._is_taint_flow_possible(source, sink, lines):
                    # Calculate flow confidence
                    confidence = self._calculate_flow_confidence(source, sink, lines)
                    
                    if confidence > 0.5:  # Threshold for considering a flow
                        # Determine vulnerability type
                        vuln_type = self._determine_vulnerability_type(source, sink)
                        
                        # Find the path
                        path = self._find_taint_path(source, sink, lines)
                        
                        taint_flow = TaintFlow(
                            source=source,
                            sink=sink,
                            path=path,
                            confidence=confidence,
                            vulnerability_type=vuln_type
                        )
                        self.taint_flows.append(taint_flow)
    
    def _is_taint_flow_possible(self, source: TaintSource, sink: TaintSink, lines: List[str]) -> bool:
        """Check if a taint flow is possible between source and sink."""
        # Simple check: source comes before sink
        if source.line_number >= sink.line_number:
            return False
        
        # Check if variables are related
        if source.variable == sink.variable:
            return True
        
        # Check for variable assignments between source and sink
        for i in range(source.line_number - 1, min(sink.line_number, len(lines))):
            line = lines[i]
            if f"{source.variable}=" in line or f"={source.variable}" in line:
                return True
        
        return False
    
    def _calculate_flow_confidence(self, source: TaintSource, sink: TaintSink, lines: List[str]) -> float:
        """Calculate confidence score for a taint flow."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on source type
        if source.source_type == 'user_input':
            confidence += 0.3
        elif source.source_type == 'external_call':
            confidence += 0.2
        elif source.source_type == 'block_data':
            confidence += 0.1
        
        # Increase confidence based on sink type
        if sink.sink_type == 'external_call':
            confidence += 0.3
        elif sink.sink_type == 'state_update':
            confidence += 0.2
        elif sink.sink_type == 'arithmetic':
            confidence += 0.1
        
        # Decrease confidence if there are validation checks
        for i in range(source.line_number - 1, min(sink.line_number, len(lines))):
            line = lines[i]
            if 'require(' in line or 'assert(' in line or 'if (' in line:
                confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _determine_vulnerability_type(self, source: TaintSource, sink: TaintSink) -> str:
        """Determine vulnerability type based on source and sink."""
        if source.source_type == 'user_input' and sink.sink_type == 'external_call':
            return 'reentrancy'
        elif source.source_type == 'user_input' and sink.sink_type == 'state_update':
            return 'access_control'
        elif source.source_type == 'block_data' and sink.sink_type == 'arithmetic':
            return 'time_manipulation'
        elif source.source_type == 'oracle_data' and sink.sink_type == 'state_update':
            return 'oracle_manipulation'
        else:
            return 'unknown'
    
    def _find_taint_path(self, source: TaintSource, sink: TaintSink, lines: List[str]) -> List[str]:
        """Find the taint path from source to sink."""
        path = [source.variable]
        
        # Simple path finding - in production, use more sophisticated analysis
        for i in range(source.line_number - 1, min(sink.line_number, len(lines))):
            line = lines[i]
            if f"{source.variable}=" in line:
                # Find assignment target
                assignment_match = re.search(r'(\w+)\s*=\s*', line)
                if assignment_match:
                    target_var = assignment_match.group(1)
                    if target_var not in path:
                        path.append(target_var)
        
        path.append(sink.variable)
        return path
    
    def _detect_integer_overflows(self, contract_code: str):
        """Detect integer overflow vulnerabilities."""
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for overflow_type, patterns in self.overflow_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Check if this is a vulnerable operation
                        if self._is_vulnerable_operation(match.group(), line):
                            var_name = self._extract_variable_name(match.group(), line)
                            
                            overflow = IntegerOverflow(
                                line_number=line_num,
                                operation=match.group(),
                                variable=var_name or 'unknown',
                                overflow_type=overflow_type,
                                confidence=0.7,
                                severity='high' if overflow_type in ['addition', 'multiplication'] else 'medium'
                            )
                            self.integer_overflows.append(overflow)
    
    def _is_vulnerable_operation(self, operation: str, line: str) -> bool:
        """Check if an operation is vulnerable to overflow."""
        # Check for SafeMath usage
        if 'SafeMath' in line or 'safemath' in line.lower():
            return False
        
        # Check for Solidity version (0.8+ has built-in overflow protection)
        if 'pragma solidity' in line and '>=0.8' in line:
            return False
        
        # Check for explicit overflow checks
        if 'require(' in line and ('overflow' in line.lower() or 'underflow' in line.lower()):
            return False
        
        return True
    
    def _detect_access_control_bypasses(self, contract_code: str):
        """Detect access control bypass vulnerabilities."""
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for bypass_type, patterns in self.access_control_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        if self._is_access_control_vulnerable(match.group(), line, bypass_type):
                            func_name = self._extract_function_name(line)
                            
                            bypass = AccessControlBypass(
                                function_name=func_name or 'unknown',
                                line_number=line_num,
                                bypass_type=bypass_type,
                                confidence=0.8,
                                severity='high' if bypass_type in ['missing_modifier', 'tx_origin'] else 'medium'
                            )
                            self.access_control_bypasses.append(bypass)
    
    def _is_access_control_vulnerable(self, match_text: str, line: str, bypass_type: str) -> bool:
        """Check if access control is vulnerable."""
        # Check for existing modifiers
        if bypass_type == 'missing_modifier':
            if 'onlyOwner' in line or 'onlyRole' in line or 'onlyAdmin' in line:
                return False
        
        # Check for proper validation
        if bypass_type == 'weak_check':
            if 'require(' in line and 'msg.sender' in line:
                return True
        
        # Check for tx.origin usage
        if bypass_type == 'tx_origin':
            return True  # tx.origin is always vulnerable
        
        return True
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        """Extract function name from line."""
        func_match = re.search(r'function\s+(\w+)', line)
        if func_match:
            return func_match.group(1)
        return None
    
# Placeholder analysis methods removed - were not implemented
    
    def _generate_analysis_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        return {
            'taint_analysis': {
                'sources_found': len(self.taint_sources),
                'sinks_found': len(self.taint_sinks),
                'flows_found': len(self.taint_flows),
                'flows': [
                    {
                        'source': {
                            'variable': flow.source.variable,
                            'line': flow.source.line_number,
                            'type': flow.source.source_type
                        },
                        'sink': {
                            'variable': flow.sink.variable,
                            'line': flow.sink.line_number,
                            'type': flow.sink.sink_type
                        },
                        'path': flow.path,
                        'confidence': flow.confidence,
                        'vulnerability_type': flow.vulnerability_type
                    }
                    for flow in self.taint_flows
                ]
            },
            'integer_overflows': {
                'count': len(self.integer_overflows),
                'overflows': [
                    {
                        'line': overflow.line_number,
                        'operation': overflow.operation,
                        'variable': overflow.variable,
                        'type': overflow.overflow_type,
                        'confidence': overflow.confidence,
                        'severity': overflow.severity
                    }
                    for overflow in self.integer_overflows
                ]
            },
            'access_control_bypasses': {
                'count': len(self.access_control_bypasses),
                'bypasses': [
                    {
                        'function': bypass.function_name,
                        'line': bypass.line_number,
                        'type': bypass.bypass_type,
                        'confidence': bypass.confidence,
                        'severity': bypass.severity
                    }
                    for bypass in self.access_control_bypasses
                ]
            },
            'summary': {
                'total_vulnerabilities': len(self.taint_flows) + len(self.integer_overflows) + len(self.access_control_bypasses),
                'high_severity': len([v for v in self.taint_flows if v.sink.severity == 'high']) + 
                               len([v for v in self.integer_overflows if v.severity == 'high']) +
                               len([v for v in self.access_control_bypasses if v.severity == 'high']),
                'medium_severity': len([v for v in self.taint_flows if v.sink.severity == 'medium']) + 
                                 len([v for v in self.integer_overflows if v.severity == 'medium']) +
                                 len([v for v in self.access_control_bypasses if v.severity == 'medium'])
            }
        }
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get summary of all detected vulnerabilities."""
        return {
            'taint_flows': len(self.taint_flows),
            'integer_overflows': len(self.integer_overflows),
            'access_control_bypasses': len(self.access_control_bypasses),
            'total_vulnerabilities': len(self.taint_flows) + len(self.integer_overflows) + len(self.access_control_bypasses)
        }
    
    def export_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Export all vulnerabilities in standardized format."""
        vulnerabilities = []
        
        # Export taint flows
        for flow in self.taint_flows:
            vulnerabilities.append({
                'type': 'taint_flow',
                'vulnerability_type': flow.vulnerability_type,
                'severity': flow.sink.severity,
                'confidence': flow.confidence,
                'line_number': flow.sink.line_number,
                'description': f'Taint flow from {flow.source.variable} to {flow.sink.variable}',
                'source': flow.source.variable,
                'sink': flow.sink.variable,
                'path': flow.path
            })
        
        # Export integer overflows
        for overflow in self.integer_overflows:
            vulnerabilities.append({
                'type': 'integer_overflow',
                'vulnerability_type': 'arithmetic',
                'severity': overflow.severity,
                'confidence': overflow.confidence,
                'line_number': overflow.line_number,
                'description': f'Integer {overflow.overflow_type} overflow in {overflow.variable}',
                'operation': overflow.operation,
                'variable': overflow.variable,
                'overflow_type': overflow.overflow_type
            })
        
        # Export access control bypasses
        for bypass in self.access_control_bypasses:
            vulnerabilities.append({
                'type': 'access_control_bypass',
                'vulnerability_type': 'access_control',
                'severity': bypass.severity,
                'confidence': bypass.confidence,
                'line_number': bypass.line_number,
                'description': f'Access control bypass in {bypass.function_name}',
                'function': bypass.function_name,
                'bypass_type': bypass.bypass_type
            })
        
        return vulnerabilities
