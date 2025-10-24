#!/usr/bin/env python3
"""
Validation Pipeline - Multi-stage false positive filtering

Provides a systematic approach to validate vulnerabilities through multiple stages:
1. Built-in protection check (Solidity 0.8+, SafeMath, etc.)
2. Governance control check (onlyOwner, onlyGovernor, etc.)
3. Deployment check (is feature actually used?)
4. Local validation check (require statements, etc.)
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValidationStage:
    """Result from a validation stage."""
    stage_name: str
    is_false_positive: bool
    confidence: float
    reasoning: str


class ValidationPipeline:
    """Multi-stage validation to filter false positives."""
    
    def __init__(self, project_path: Path, contract_code: str):
        self.project_path = Path(project_path) if project_path else None
        self.contract_code = contract_code
        
        # Initialize validators (lazy loading to avoid circular imports)
        self._governance_detector = None
        self._deployment_analyzer = None
        self._validation_detector = None
    
    @property
    def governance_detector(self):
        """Lazy load governance detector."""
        if self._governance_detector is None:
            try:
                from core.governance_detector import GovernanceDetector
                self._governance_detector = GovernanceDetector()
            except ImportError:
                # Governance detector not available yet
                self._governance_detector = None
        return self._governance_detector
    
    @property
    def deployment_analyzer(self):
        """Lazy load deployment analyzer."""
        if self._deployment_analyzer is None and self.project_path:
            try:
                from core.deployment_analyzer import DeploymentAnalyzer
                self._deployment_analyzer = DeploymentAnalyzer(self.project_path)
            except ImportError:
                # Deployment analyzer not available yet
                self._deployment_analyzer = None
        return self._deployment_analyzer
    
    @property
    def validation_detector(self):
        """Lazy load validation detector."""
        if self._validation_detector is None:
            try:
                from core.validation_patterns import ValidationDetector
                self._validation_detector = ValidationDetector()
            except (ImportError, AttributeError):
                # Validation detector not available or doesn't have this class
                self._validation_detector = None
        return self._validation_detector
    
    def validate(self, vulnerability: Dict) -> List[ValidationStage]:
        """
        Run vulnerability through all validation stages.
        
        Args:
            vulnerability: Vulnerability dict with keys like 'vulnerability_type', 
                         'description', 'line', 'code_snippet', 'contract_name'
        
        Returns:
            List of ValidationStage results (first false positive triggers early exit)
        """
        results = []
        
        # Stage 1: Built-in protection check
        builtin_check = self._check_builtin_protection(vulnerability)
        if builtin_check:
            results.append(builtin_check)
            return results  # Early exit
        
        # Stage 2: Governance control check
        governance_check = self._check_governance_control(vulnerability)
        if governance_check:
            results.append(governance_check)
            return results  # Early exit
        
        # Stage 3: Deployment check
        deployment_check = self._check_deployment(vulnerability)
        if deployment_check:
            results.append(deployment_check)
            return results  # Early exit
        
        # Stage 4: Local validation check
        validation_check = self._check_local_validation(vulnerability)
        if validation_check:
            results.append(validation_check)
            return results  # Early exit
        
        # All stages passed - likely real vulnerability
        results.append(ValidationStage(
            stage_name="all_checks_passed",
            is_false_positive=False,
            confidence=0.8,
            reasoning="No protective mechanisms found"
        ))
        
        return results
    
    def _check_builtin_protection(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if Solidity version provides built-in protection."""
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Check for SafeMath/SafeCast usage first (works for all versions)
        if 'overflow' in vuln_type or 'underflow' in vuln_type:
            code_snippet = vuln.get('code_snippet', '')
            # Check for SafeMath method calls (.add, .sub, .mul, .div)
            if any(method in code_snippet for method in ['.add(', '.sub(', '.mul(', '.div(', 'SafeCast', 'SafeMath']):
                return ValidationStage(
                    stage_name="builtin_protection",
                    is_false_positive=True,
                    confidence=0.9,
                    reasoning="SafeMath/SafeCast provides overflow protection"
                )
        
        # Check Solidity version from contract
        version_match = re.search(r'pragma solidity\s+[\^>=<]*(\d+\.\d+)', self.contract_code)
        if version_match:
            version_str = version_match.group(1)
            version_parts = version_str.split('.')
            major = int(version_parts[0])
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            
            # Solidity 0.8+ has automatic overflow/underflow protection
            if major == 0 and minor >= 8:
                if 'overflow' in vuln_type or 'underflow' in vuln_type:
                    # Check if unsafe operations are used
                    if not self._uses_unsafe_operations(vuln):
                        return ValidationStage(
                            stage_name="builtin_protection",
                            is_false_positive=True,
                            confidence=0.95,
                            reasoning=f"Solidity {version_str} provides automatic overflow/underflow protection"
                        )
        
        return None
    
    def _uses_unsafe_operations(self, vuln: Dict) -> bool:
        """Check if unchecked{} or unsafe operations are used."""
        code_snippet = vuln.get('code_snippet', '')
        
        # Check code snippet first
        if 'unchecked' in code_snippet.lower():
            return True
        
        # Check surrounding context in contract
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        if line_number > 0:
            lines = self.contract_code.split('\n')
            # Check 10 lines before the vulnerability for unchecked block
            context_start = max(0, line_number - 10)
            context = '\n'.join(lines[context_start:line_number])
            
            if 'unchecked' in context.lower():
                return True
        
        return False
    
    def _check_governance_control(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if issue is governance-controlled."""
        if not self.governance_detector:
            return None
        
        description = vuln.get('description', '').lower()
        
        # Check for governance-controlled parameters
        if any(keyword in description for keyword in ['fee', 'parameter', 'config', 'setter']):
            # Extract parameter name
            param_names = self._extract_parameter_names(description)
            
            for param_name in param_names:
                gov_result = self.governance_detector.check_validation_in_setter(
                    param_name, self.contract_code
                )
                
                if gov_result.get('governed'):
                    return ValidationStage(
                        stage_name="governance_control",
                        is_false_positive=True,
                        confidence=gov_result.get('confidence', 0.9),
                        reasoning=gov_result.get('reason', 'Governed by access control')
                    )
        
        return None
    
    def _extract_parameter_names(self, description: str) -> List[str]:
        """Extract potential parameter names from description."""
        # Common patterns: "fee", "Fee", "fees", etc.
        param_patterns = [
            r'\b(fee|fees)\b',
            r'\b(price|oracle)\b',
            r'\b(param|parameter)\b',
            r'\b(config|configuration)\b',
        ]
        
        params = []
        for pattern in param_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            for match in matches:
                # Capitalize first letter
                param_name = match.capitalize()
                if param_name not in params:
                    params.append(param_name)
        
        return params if params else ['Parameter']  # Default fallback
    
    def _check_deployment(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if feature is actually deployed."""
        if not self.deployment_analyzer:
            return None
        
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        
        # Check for EXTERNAL oracle/manager type issues
        if 'external' in vuln_type or 'external' in description:
            # Look for specific feature names
            if 'oracle' in description:
                usage_check = self.deployment_analyzer.check_oracle_type_usage('EXTERNAL')
                if not usage_check['used']:
                    return ValidationStage(
                        stage_name="deployment_check",
                        is_false_positive=True,
                        confidence=usage_check['confidence'],
                        reasoning="EXTERNAL oracle type is not used in deployment configs"
                    )
            
            if 'manager' in description:
                feature_check = self.deployment_analyzer.is_feature_deployed(
                    'EXTERNAL', 
                    vuln.get('contract_name', 'Manager')
                )
                if not feature_check['deployed']:
                    return ValidationStage(
                        stage_name="deployment_check",
                        is_false_positive=True,
                        confidence=feature_check.get('confidence', 0.7),
                        reasoning="EXTERNAL manager type is not used in deployment"
                    )
        
        # Check if function is actually called in deployment
        contract_name = vuln.get('contract_name', '')
        if contract_name:
            # Extract function name from code snippet
            code_snippet = vuln.get('code_snippet', '')
            function_match = re.search(r'function\s+(\w+)\s*\(', code_snippet)
            if function_match:
                function_name = function_match.group(1)
                usage_check = self.deployment_analyzer.check_function_usage(
                    function_name, contract_name
                )
                if not usage_check['used'] and usage_check.get('confidence', 0) > 0.6:
                    return ValidationStage(
                        stage_name="deployment_check",
                        is_false_positive=True,
                        confidence=usage_check['confidence'],
                        reasoning=f"Function {function_name} not called in deployment scripts"
                    )
        
        return None
    
    def _check_local_validation(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check for local validation (require statements, etc.)."""
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Only check validation for arithmetic vulnerabilities
        # Reentrancy, access control, etc. need different checks
        if not any(keyword in vuln_type for keyword in ['overflow', 'underflow', 'division', 'arithmetic']):
            return None
        
        if not self.validation_detector:
            # Fallback to simple pattern matching
            return self._simple_validation_check(vuln)
        
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        if self.validation_detector.check_if_validated(line_number, self.contract_code):
            return ValidationStage(
                stage_name="local_validation",
                is_false_positive=True,
                confidence=0.8,
                reasoning="Validation found before vulnerable operation"
            )
        
        return None
    
    def _simple_validation_check(self, vuln: Dict) -> Optional[ValidationStage]:
        """Simple validation check using pattern matching (only for arithmetic)."""
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Only check validation for arithmetic vulnerabilities
        if not any(keyword in vuln_type for keyword in ['overflow', 'underflow', 'division', 'arithmetic']):
            return None
        
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        if line_number == 0:
            return None
        
        lines = self.contract_code.split('\n')
        if line_number > len(lines):
            return None
        
        # Check 20 lines before vulnerability
        context_start = max(0, line_number - 20)
        context = '\n'.join(lines[context_start:line_number])
        
        # Look for validation patterns relevant to arithmetic
        validation_patterns = [
            r'require\s*\([^)]*>=',  # Bounds check
            r'require\s*\([^)]*<=',  # Upper bounds
            r'if\s*\([^)]*>=\s*[^)]*\)\s*revert',
            r'assert\s*\([^)]*>=',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, context):
                return ValidationStage(
                    stage_name="local_validation",
                    is_false_positive=True,
                    confidence=0.7,
                    reasoning="Bounds validation found before arithmetic operation"
                )
        
        return None
    
    def get_summary(self) -> Dict:
        """Get summary of available validators."""
        return {
            'has_governance_detector': self.governance_detector is not None,
            'has_deployment_analyzer': self.deployment_analyzer is not None,
            'has_validation_detector': self.validation_detector is not None,
            'project_path': str(self.project_path) if self.project_path else None,
        }


def validate_vulnerability(vulnerability: Dict, contract_code: str, project_path: Optional[Path] = None) -> Dict:
    """
    Convenience function to validate a single vulnerability.
    
    Args:
        vulnerability: Vulnerability dict
        contract_code: Full contract source code
        project_path: Optional path to project (for deployment analysis)
    
    Returns:
        Dict with 'is_false_positive', 'confidence', 'reasoning', 'stage'
    """
    pipeline = ValidationPipeline(project_path, contract_code)
    stages = pipeline.validate(vulnerability)
    
    if not stages:
        return {
            'is_false_positive': False,
            'confidence': 0.5,
            'reasoning': 'No validation stages executed',
            'stage': 'none'
        }
    
    # Get first result (early exit means first is most relevant)
    stage = stages[0]
    
    return {
        'is_false_positive': stage.is_false_positive,
        'confidence': stage.confidence,
        'reasoning': stage.reasoning,
        'stage': stage.stage_name
    }

