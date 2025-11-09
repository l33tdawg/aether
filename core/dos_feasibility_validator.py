"""
DoS Feasibility Validator

Validates whether DoS vulnerabilities are actually exploitable in practice.
Prevents false positives from theoretical gas issues that can't be exploited.

This module addresses the Snowbridge lesson: Don't report DoS vulnerabilities
without verifying:
1. Attacker can control the unbounded input
2. Economic incentives make the attack feasible  
3. Cryptographic protections don't prevent the attack
4. Real-world data supports the vulnerability
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class DoSFeasibility(Enum):
    """Feasibility levels for DoS attacks"""
    EXPLOITABLE = "exploitable"  # Can be exploited profitably
    ECONOMIC_BARRIER = "economic_barrier"  # Attacker must pay significant gas
    CRYPTOGRAPHIC_BARRIER = "cryptographic_barrier"  # Cryptographic protection prevents
    INPUT_NOT_CONTROLLABLE = "input_not_controllable"  # Attacker can't control the input
    THEORETICAL_ONLY = "theoretical_only"  # Only theoretical, no practical attack


@dataclass
class DoSValidationResult:
    """Result of DoS feasibility validation"""
    is_exploitable: bool
    feasibility: DoSFeasibility
    confidence: float
    reasoning: str
    barriers: List[str]
    economic_cost: Optional[str] = None
    recommended_severity: Optional[str] = None


class DoSFeasibilityValidator:
    """Validates whether DoS vulnerabilities are actually exploitable."""
    
    def __init__(self):
        # Cryptographic protection patterns
        self.crypto_patterns = [
            r'verifyMMRLeafProof',
            r'verifySignature',
            r'ecrecover',
            r'MerkleProof\.verify',
            r'\.verify\s*\(',
            r'checkSignature',
            r'validateProof',
        ]
        
        # Input validation patterns
        self.input_validation_patterns = [
            r'require\s*\([^)]*\.length\s*<=',
            r'require\s*\([^)]*\.length\s*<\s*\d+',
            r'if\s*\([^)]*\.length\s*>\s*\w+\)',
        ]
        
        # Economic protection patterns
        self.economic_patterns = [
            r'payable\s*\(',
            r'msg\.value',
            r'tx\.gasprice',
            r'gasleft\(\)',
        ]
    
    def validate_dos_vulnerability(
        self, 
        vulnerability: Dict[str, Any],
        contract_content: str,
        function_context: Optional[str] = None
    ) -> DoSValidationResult:
        """
        Main validation entry point for DoS vulnerabilities.
        
        Args:
            vulnerability: The vulnerability dict
            contract_content: Full contract source code
            function_context: Optional function containing the vulnerability
            
        Returns:
            DoSValidationResult with exploitability assessment
        """
        vuln_type = vulnerability.get('vulnerability_type', '')
        line_number = vulnerability.get('line_number', 0)
        
        # Only validate DoS-related vulnerabilities
        if not self._is_dos_related(vuln_type):
            return DoSValidationResult(
                is_exploitable=True,  # Not DoS, pass through
                feasibility=DoSFeasibility.EXPLOITABLE,
                confidence=1.0,
                reasoning="Not a DoS vulnerability, skipping validation",
                barriers=[]
            )
        
        barriers = []
        reasoning_parts = []
        
        # Check 1: Is the input controllable by an attacker?
        input_check = self._check_input_controllability(
            vulnerability, contract_content, line_number
        )
        
        # Track input check result for reporting
        
        if not input_check['controllable']:
            return DoSValidationResult(
                is_exploitable=False,
                feasibility=DoSFeasibility.INPUT_NOT_CONTROLLABLE,
                confidence=input_check['confidence'],
                reasoning=input_check['reason'],
                barriers=['Input not controllable by attacker'],
                recommended_severity='informational'
            )
        barriers.extend(input_check.get('notes', []))
        
        # Check 2: Are there cryptographic protections?
        crypto_check = self._check_cryptographic_protection(
            contract_content, line_number
        )
        if crypto_check['protected']:
            reasoning_parts.append(crypto_check['reason'])
            barriers.append('Cryptographic validation')
            
            # Still might be exploitable if crypto happens AFTER gas consumption
            if not self._crypto_validates_before_gas_consumption(contract_content, line_number):
                reasoning_parts.append("But crypto validation happens AFTER gas consumption")
            else:
                return DoSValidationResult(
                    is_exploitable=False,
                    feasibility=DoSFeasibility.CRYPTOGRAPHIC_BARRIER,
                    confidence=crypto_check['confidence'],
                    reasoning=' | '.join(reasoning_parts),
                    barriers=barriers,
                    recommended_severity='low'
                )
        
        # Check 3: Economic feasibility - who pays for the attack?
        economic_check = self._check_economic_feasibility(
            contract_content, line_number, function_context
        )
        if not economic_check['feasible']:
            return DoSValidationResult(
                is_exploitable=False,
                feasibility=DoSFeasibility.ECONOMIC_BARRIER,
                confidence=economic_check['confidence'],
                reasoning=economic_check['reason'],
                barriers=barriers + ['Economic barrier'],
                economic_cost=economic_check.get('cost'),
                recommended_severity='low'
            )
        
        # Check 4: Is there input validation that would prevent extreme cases?
        validation_check = self._check_input_validation(
            contract_content, line_number
        )
        if validation_check['has_validation']:
            barriers.append('Input validation present')
            reasoning_parts.append(validation_check['reason'])
            
            # Reduce severity if there's validation
            return DoSValidationResult(
                is_exploitable=True,
                feasibility=DoSFeasibility.EXPLOITABLE,
                confidence=0.6,  # Lower confidence due to validation
                reasoning=' | '.join(reasoning_parts) if reasoning_parts else "Exploitable but with validation",
                barriers=barriers,
                recommended_severity='medium'
            )
        
        # No barriers found - likely exploitable
        return DoSValidationResult(
            is_exploitable=True,
            feasibility=DoSFeasibility.EXPLOITABLE,
            confidence=0.9,
            reasoning="No protective barriers found - appears exploitable",
            barriers=barriers,
            recommended_severity='high'
        )
    
    def _is_dos_related(self, vuln_type: str) -> bool:
        """Check if vulnerability type is DoS-related."""
        dos_keywords = [
            'dos', 'denial', 'gas', 'unbounded', 'loop', 
            'block_gas_limit', 'infinite', 'consumption'
        ]
        vuln_type_lower = vuln_type.lower()
        return any(keyword in vuln_type_lower for keyword in dos_keywords)
    
    def _check_input_controllability(
        self, 
        vulnerability: Dict[str, Any],
        contract_content: str,
        line_number: int
    ) -> Dict[str, Any]:
        """
        Check if the unbounded input is controllable by an attacker.
        
        Key insight from Snowbridge: The digestItems array comes from a 
        ParachainHeader that must pass cryptographic verification. An attacker
        can't arbitrarily set the length without breaking the merkle proof.
        """
        code_snippet = vulnerability.get('code_snippet', '')
        description = vulnerability.get('description', '').lower()
        
        # Extract the array/parameter being looped over
        array_match = re.search(r'for\s*\([^;]*;\s*\w+\s*<\s*(\w+(?:\.\w+)*)\.length', code_snippet)
        if not array_match:
            array_match = re.search(r'(\w+(?:\.\w+)*)\.length', code_snippet)
        
        if not array_match:
            return {
                'controllable': True,  # Can't determine, assume worst case
                'confidence': 0.5,
                'reason': 'Unable to determine input source',
                'notes': []
            }
        
        array_path = array_match.group(1)  # e.g., "digestItems" or "proof.header.digestItems"
        array_name = array_path.split('.')[-1]  # Last part is the array name
        
        # Check if this array comes from calldata (user input)
        function_context = self._get_function_context(contract_content, line_number)
        
        if not function_context:
            # Can't find function - but check the broader contract for validation patterns
            if re.search(r'(?:Proof|Header|verify|Merkle)', contract_content, re.IGNORECASE):
                return {
                    'controllable': False,
                    'confidence': 0.6,
                    'reason': f'Function context not found, but {array_name} appears in validated contract',
                    'notes': ['Validation patterns detected in contract']
                }
            return {
                'controllable': True,
                'confidence': 0.6,
                'reason': 'Unable to extract function context',
                'notes': []
            }
        
        # Check if array is nested inside a struct parameter
        # Pattern: proof.header.digestItems or similar
        if '.' in array_path:
            parts = array_path.split('.')
            if len(parts) > 1:
                # Array is accessed through a struct (e.g., proof.header.digestItems)
                parent_struct = parts[0]
                
                # Look for the parent struct type in function params
                # Match patterns like: "proof: Proof calldata" or "Proof calldata proof"
                struct_patterns = [
                    rf'{parent_struct}\s*:\s*\w*(?:Proof|Header|Commitment|Signature)',
                    rf'\w*(?:Proof|Header|Commitment|Signature)\s+calldata\s+{parent_struct}',
                ]
                
                for pattern in struct_patterns:
                    if re.search(pattern, function_context, re.IGNORECASE):
                        return {
                            'controllable': False,
                            'confidence': 0.85,
                            'reason': f'{array_name} is nested in validated struct {parent_struct}',
                            'notes': ['Part of validated data structure']
                        }
        
        # Look for the array in function parameters (Solidity syntax: Type[] calldata name)
        # Pattern matches: "Order[] calldata orders" or "uint256[] memory items"
        param_patterns = [
            rf'\w+\[\]\s+calldata\s+{array_name}',  # Type[] calldata name
            rf'{array_name}\s*:\s*\w+\[\]\s+calldata',  # name: Type[] calldata (not valid Solidity but check anyway)
        ]
        
        param_match = False
        for pattern in param_patterns:
            if re.search(pattern, function_context, re.IGNORECASE):
                param_match = True
                break
        
        if not param_match:
            # Not a direct calldata parameter - might be storage, local, or struct member
            return {
                'controllable': False,
                'confidence': 0.7,
                'reason': f'{array_name} is not a direct calldata parameter',
                'notes': ['Array not directly controllable']
            }
        
        # Check if the array is part of a larger validated structure
        # Look in the broader contract for how this array is accessed
        array_usage_pattern = rf'\w+\.{array_name}(?:\.length|\[)'
        if re.search(array_usage_pattern, contract_content):
            # Array is accessed via struct member (e.g., proof.header.digestItems)
            # Check if parent has validation indicators
            if re.search(r'Proof|Header|Commitment', contract_content, re.IGNORECASE):
                return {
                    'controllable': False,
                    'confidence': 0.75,
                    'reason': f'{array_name} appears to be part of validated data structure',
                    'notes': ['Struct member of validated type']
                }
        
        # Pattern 1: Look for struct types that suggest validated data in function params
        validated_type_patterns = [
            r'\w*Proof\s+calldata',
            r'\w*Header\s+calldata',
            r'\w*Commitment\s+calldata',
            r'\w*Signature\s+calldata',
        ]
        
        for pattern in validated_type_patterns:
            if re.search(pattern, function_context, re.IGNORECASE):
                return {
                    'controllable': False,
                    'confidence': 0.8,
                    'reason': f'{array_name} is part of cryptographically validated structure',
                    'notes': ['Validated structure detected']
                }
        
        # Pattern 2: Check if the function has cryptographic operations
        # If there's crypto validation in the function, the input is likely protected
        crypto_in_function = False
        for pattern in self.crypto_patterns:
            if re.search(pattern, function_context, re.IGNORECASE):
                crypto_in_function = True
                break
        
        if crypto_in_function:
            # Check if the array is part of the validated data structure
            # Look for the array being used in merkle/validation operations
            # Use simpler patterns without complex regex escaping
            if ('verify' in contract_content.lower() or 
                'merkle' in contract_content.lower() or
                'proof' in contract_content.lower()):
                return {
                    'controllable': False,
                    'confidence': 0.85,
                    'reason': f'{array_name} appears to be used in cryptographic validation',
                    'notes': ['Array likely validated before use']
                }
        
        # If we found calldata parameter without validation, it's controllable
        return {
            'controllable': True,
            'confidence': 0.9,
            'reason': f'{array_name} is a calldata parameter without apparent validation',
            'notes': ['Direct calldata input']
        }
    
    def _check_cryptographic_protection(
        self, 
        contract_content: str,
        line_number: int
    ) -> Dict[str, Any]:
        """Check if there are cryptographic protections in the function."""
        function_context = self._get_function_context(contract_content, line_number)
        if not function_context:
            return {'protected': False, 'confidence': 0.5, 'reason': 'No context'}
        
        # Look for crypto operations
        for pattern in self.crypto_patterns:
            if re.search(pattern, function_context, re.IGNORECASE):
                return {
                    'protected': True,
                    'confidence': 0.9,
                    'reason': f'Cryptographic validation detected: {pattern}'
                }
        
        return {
            'protected': False,
            'confidence': 0.8,
            'reason': 'No cryptographic protection found'
        }
    
    def _crypto_validates_before_gas_consumption(
        self,
        contract_content: str,
        line_number: int
    ) -> bool:
        """
        Check if cryptographic validation happens BEFORE the gas-heavy operation.
        
        This is crucial: If validation happens after gas consumption (like in Snowbridge),
        the DoS is still exploitable even with crypto protection.
        """
        function_context = self._get_function_context(contract_content, line_number)
        if not function_context:
            return False
        
        lines = function_context.split('\n')
        
        # Find the line with gas-heavy operation
        gas_line_idx = None
        for i, line in enumerate(lines):
            if 'for' in line and '.length' in line:
                gas_line_idx = i
                break
        
        if gas_line_idx is None:
            return False
        
        # Check if any crypto validation appears BEFORE this line
        for i in range(gas_line_idx):
            line = lines[i]
            for pattern in self.crypto_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Found validation before gas operation
                    return True
        
        return False
    
    def _check_economic_feasibility(
        self,
        contract_content: str,
        line_number: int,
        function_context: Optional[str]
    ) -> Dict[str, Any]:
        """
        Check if the attack makes economic sense.
        
        Key questions:
        1. Who pays for the gas? Attacker or victim?
        2. Does attacker get value from the DoS?
        3. Is there a cheaper way to achieve the same goal?
        """
        func_ctx = function_context or self._get_function_context(contract_content, line_number)
        if not func_ctx:
            return {'feasible': True, 'confidence': 0.5, 'reason': 'Unable to assess'}
        
        # Check if function is payable - attacker might pay
        if 'payable' in func_ctx:
            # Check if there's value requirement
            if re.search(r'require\s*\(\s*msg\.value\s*>', func_ctx):
                return {
                    'feasible': False,
                    'confidence': 0.8,
                    'reason': 'Attacker must pay ETH to call function',
                    'cost': 'msg.value requirement'
                }
        
        # Check if it's a view/pure function (no state change)
        if re.search(r'function\s+\w+\s*\([^)]*\)\s+(?:external|public)\s+(?:view|pure)', func_ctx):
            return {
                'feasible': False,
                'confidence': 0.9,
                'reason': 'View/pure function - attacker pays gas but no state impact',
                'cost': 'Failed transaction gas'
            }
        
        # Check for transaction revert patterns
        if re.search(r'revert\s*\(|require\s*\(.*?[^,)]+\s*\)|if\s*\([^)]+\)\s*\{[^}]*revert', func_ctx):
            # Likely reverts on invalid input - attacker pays for failed tx
            return {
                'feasible': False,
                'confidence': 0.7,
                'reason': 'Function likely reverts on invalid input - attacker pays gas',
                'cost': 'Estimated 15-20M gas per attack (~$50-200)'
            }
        
        # Default: assume feasible
        return {
            'feasible': True,
            'confidence': 0.6,
            'reason': 'No clear economic barrier detected'
        }
    
    def _check_input_validation(
        self,
        contract_content: str,
        line_number: int
    ) -> Dict[str, Any]:
        """Check if there's input validation that would prevent extreme cases."""
        function_context = self._get_function_context(contract_content, line_number)
        if not function_context:
            return {'has_validation': False, 'reason': 'No context'}
        
        # Look for length checks
        for pattern in self.input_validation_patterns:
            match = re.search(pattern, function_context, re.IGNORECASE)
            if match:
                return {
                    'has_validation': True,
                    'reason': f'Input validation found: {match.group(0)[:50]}'
                }
        
        return {
            'has_validation': False,
            'reason': 'No input validation detected'
        }
    
    def _get_function_context(self, contract_content: str, line_number: int) -> Optional[str]:
        """Extract function context around the vulnerability."""
        lines = contract_content.split('\n')
        if line_number > len(lines) or line_number < 1:
            return None
        
        # Search backwards for function declaration
        start_idx = line_number - 1
        for i in range(start_idx, max(0, start_idx - 50), -1):
            if re.match(r'\s*function\s+\w+', lines[i]):
                start_idx = i
                break
        
        # Search forwards for function end
        end_idx = line_number
        brace_count = 0
        for i in range(start_idx, min(len(lines), start_idx + 200)):
            brace_count += lines[i].count('{') - lines[i].count('}')
            if brace_count == 0 and i > start_idx and '{' in lines[start_idx]:
                end_idx = i
                break
        
        return '\n'.join(lines[start_idx:end_idx + 1])
    
    def suggest_verification_steps(
        self,
        vulnerability: Dict[str, Any],
        validation_result: DoSValidationResult
    ) -> List[str]:
        """
        Suggest manual verification steps based on validation result.
        
        This helps researchers know what to check before submitting to bug bounty.
        """
        steps = []
        
        if validation_result.feasibility == DoSFeasibility.CRYPTOGRAPHIC_BARRIER:
            steps.append("✓ Check if cryptographic validation happens BEFORE gas consumption")
            steps.append("✓ Verify attacker cannot bypass cryptographic checks")
            steps.append("✓ Review merkle proof or signature verification logic")
        
        if validation_result.feasibility == DoSFeasibility.ECONOMIC_BARRIER:
            steps.append("✓ Calculate actual gas cost of attack")
            steps.append("✓ Verify who pays for failed transactions")
            steps.append("✓ Check if attack provides value to attacker")
        
        if validation_result.feasibility == DoSFeasibility.INPUT_NOT_CONTROLLABLE:
            steps.append("✓ Verify input source and controllability")
            steps.append("✓ Check if attacker can manipulate input structure")
            steps.append("✓ Review validation logic for input")
        
        if validation_result.is_exploitable:
            steps.append("✓ Check real-world data for typical input sizes")
            steps.append("✓ Test with mainnet fork against real contract")
            steps.append("✓ Verify full attack path from entry point to vulnerability")
            steps.append("✓ Calculate breaking point (gas limit threshold)")
        
        steps.append("✓ Review protocol documentation for intended behavior")
        steps.append("✓ Check if similar contracts have been exploited")
        
        return steps

