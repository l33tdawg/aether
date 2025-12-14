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
        self._design_assumption_detector = None
        self._reentrancy_guard_detector = None
        self._scope_classifier = None
        
        # NEW: Advanced analyzers for improved false positive detection
        self._function_context_analyzer = None
        self._impact_analyzer = None
        self._confidence_scorer = None
        self._dos_feasibility_validator = None
        
        # ENHANCED: Multi-strategy false positive filter (Nov 2025 improvements)
        self._enhanced_fp_filter = None
        self._enhanced_fp_analyzed = False
        
        # NEW: Protocol-level protection detector (optional, lazy-loaded)
        self._protocol_protection_detector = None
        
        # NEW: Cross-contract analyzer for external call access control (Dec 2025)
        self._cross_contract_analyzer = None
        
        # NEW: Design pattern detector for safe permissionless patterns (Dec 2025)
        self._design_pattern_detector = None
        
        # NEW: Enhanced severity calibrator (Dec 2025)
        self._severity_calibrator = None
    
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
    
    @property
    def design_assumption_detector(self):
        """Lazy load design assumption detector."""
        if self._design_assumption_detector is None:
            try:
                from core.design_assumption_detector import DesignAssumptionDetector
                self._design_assumption_detector = DesignAssumptionDetector()
            except ImportError:
                self._design_assumption_detector = None
        return self._design_assumption_detector
    
    @property
    def reentrancy_guard_detector(self):
        """Lazy load reentrancy guard detector."""
        if self._reentrancy_guard_detector is None:
            try:
                from core.reentrancy_guard_detector import ReentrancyGuardDetector
                self._reentrancy_guard_detector = ReentrancyGuardDetector()
            except ImportError:
                self._reentrancy_guard_detector = None
        return self._reentrancy_guard_detector
    
    @property
    def scope_classifier(self):
        """Lazy load scope classifier."""
        if self._scope_classifier is None:
            try:
                from core.scope_classifier import ScopeClassifier
                self._scope_classifier = ScopeClassifier()
            except ImportError:
                self._scope_classifier = None
        return self._scope_classifier
    
    @property
    def function_context_analyzer(self):
        """Lazy load function context analyzer."""
        if self._function_context_analyzer is None:
            try:
                from core.function_context_analyzer import FunctionContextAnalyzer
                self._function_context_analyzer = FunctionContextAnalyzer()
            except ImportError:
                self._function_context_analyzer = None
        return self._function_context_analyzer
    
    @property
    def impact_analyzer(self):
        """Lazy load impact analyzer."""
        if self._impact_analyzer is None:
            try:
                from core.impact_analyzer import ImpactAnalyzer
                self._impact_analyzer = ImpactAnalyzer()
            except ImportError:
                self._impact_analyzer = None
        return self._impact_analyzer
    
    @property
    def confidence_scorer(self):
        """Lazy load confidence scorer."""
        if self._confidence_scorer is None:
            try:
                from core.confidence_scorer import ConfidenceScorer
                self._confidence_scorer = ConfidenceScorer()
            except ImportError:
                self._confidence_scorer = None
        return self._confidence_scorer
    
    @property
    def dos_feasibility_validator(self):
        """Lazy load DoS feasibility validator."""
        if self._dos_feasibility_validator is None:
            try:
                from core.dos_feasibility_validator import DoSFeasibilityValidator
                self._dos_feasibility_validator = DoSFeasibilityValidator()
            except ImportError:
                self._dos_feasibility_validator = None
        return self._dos_feasibility_validator
    
    @property
    def protocol_protection_detector(self):
        """Lazy load protocol protection detector."""
        if self._protocol_protection_detector is None:
            try:
                from core.protocol_protection_detector import ProtocolProtectionDetector
                # Check if enabled via config (default: True)
                enabled = True
                try:
                    import yaml
                    config_path = Path(__file__).parent.parent / 'configs' / 'protocol_protection.yaml'
                    if config_path.exists():
                        with open(config_path) as f:
                            config = yaml.safe_load(f)
                            enabled = config.get('protocol_protection', {}).get('enabled', True)
                except Exception:
                    pass
                self._protocol_protection_detector = ProtocolProtectionDetector(enabled=enabled)
            except ImportError:
                self._protocol_protection_detector = None
        return self._protocol_protection_detector
    
    @property
    def enhanced_fp_filter(self):
        """Lazy load enhanced false positive filter."""
        if self._enhanced_fp_filter is None:
            try:
                from core.enhanced_false_positive_filter import EnhancedFalsePositiveFilter
                self._enhanced_fp_filter = EnhancedFalsePositiveFilter()
                # Analyze contract context once
                if not self._enhanced_fp_analyzed and self.contract_code:
                    contract_name = self._extract_contract_name()
                    self._enhanced_fp_filter.analyze_contract_context(
                        self.contract_code, 
                        contract_name
                    )
                    self._enhanced_fp_analyzed = True
            except ImportError:
                self._enhanced_fp_filter = None
        return self._enhanced_fp_filter
    
    @property
    def cross_contract_analyzer(self):
        """Lazy load cross-contract analyzer (Dec 2025)."""
        if self._cross_contract_analyzer is None:
            try:
                from core.cross_contract_analyzer import CrossContractAnalyzer
                self._cross_contract_analyzer = CrossContractAnalyzer(project_root=self.project_path)
            except ImportError:
                self._cross_contract_analyzer = None
        return self._cross_contract_analyzer
    
    @property
    def design_pattern_detector(self):
        """Lazy load design pattern detector (Dec 2025)."""
        if self._design_pattern_detector is None:
            try:
                from core.design_pattern_detector import DesignPatternDetector
                self._design_pattern_detector = DesignPatternDetector()
            except ImportError:
                self._design_pattern_detector = None
        return self._design_pattern_detector
    
    @property
    def severity_calibrator(self):
        """Lazy load enhanced severity calibrator (Dec 2025)."""
        if self._severity_calibrator is None:
            try:
                from core.impact_analyzer import EnhancedSeverityCalibrator
                self._severity_calibrator = EnhancedSeverityCalibrator()
            except ImportError:
                self._severity_calibrator = None
        return self._severity_calibrator
    
    def _extract_contract_name(self) -> str:
        """Extract primary contract name from code."""
        import re
        match = re.search(r'contract\s+(\w+)', self.contract_code)
        return match.group(1) if match else "Unknown"
    
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
        
        # Stage 0: Code-description mismatch check (FAST - catch obvious errors)
        mismatch_check = self._check_code_description_mismatch(vulnerability)
        if mismatch_check and mismatch_check.is_false_positive:
            results.append(mismatch_check)
            return results  # Early exit
        
        # Stage 0.5: Enhanced multi-strategy false positive filter (NEW - Nov 2025)
        # This runs comprehensive checks: guards, inheritance, patterns, severity calibration
        enhanced_check = self._check_enhanced_false_positive(vulnerability)
        if enhanced_check and enhanced_check.is_false_positive:
            results.append(enhanced_check)
            return results  # Early exit
        elif enhanced_check:
            # Not a false positive but may have adjusted severity/confidence
            results.append(enhanced_check)
        
        # Stage 1: Built-in protection check
        builtin_check = self._check_builtin_protection(vulnerability)
        if builtin_check:
            results.append(builtin_check)
            return results  # Early exit
        
        # Stage 1.4: DoS feasibility check (NEW - prevents false positives like Snowbridge)
        dos_check = self._check_dos_feasibility(vulnerability)
        if dos_check and dos_check.is_false_positive:
            results.append(dos_check)
            return results  # Early exit
        
        # Stage 1.5: Constructor context check
        constructor_check = self._check_constructor_context(vulnerability)
        if constructor_check and constructor_check.is_false_positive:
            results.append(constructor_check)
            return results  # Early exit
        
        # Stage 1.6: Function context check (NEW - fast, deterministic)
        context_check = self._check_function_context(vulnerability)
        if context_check and context_check.is_false_positive:
            results.append(context_check)
            return results  # Early exit
        
        # Stage 1.65: Exploitability check FIRST (NEW - Phase 2)
        # This must run before access control check to detect front-running
        exploit_check = self._check_exploitability(vulnerability)
        if exploit_check and exploit_check.is_false_positive:
            results.append(exploit_check)
            return results  # Early exit
        
        # Stage 1.66: Bug bounty relevance check - REMOVED
        # Bug bounty assessment now happens AFTER LLM validation (in llm_false_positive_filter.py)
        # This allows all findings to be assessed by LLM first, then marked for bug bounty relevance
        # No early filtering here - let LLM do its job first
        
        # Stage 1.7: Enhanced access control chain check (AFTER exploitability)
        # Only filter if not front-runnable
        access_control_check = self._check_enhanced_access_control(vulnerability)
        if access_control_check and access_control_check.is_false_positive:
            results.append(access_control_check)
            return results  # Early exit
        
        # Stage 1.75: Cross-contract access control check (NEW - Dec 2025)
        # Check if external calls enforce access control that protects this function
        cross_contract_check = self._check_cross_contract_access_control(vulnerability)
        if cross_contract_check and cross_contract_check.is_false_positive:
            results.append(cross_contract_check)
            return results  # Early exit
        
        # Stage 1.76: Safe design pattern check (NEW - Dec 2025)
        # Check for intentionally permissionless patterns (migration helpers, pull payments, etc.)
        design_pattern_check = self._check_safe_design_pattern(vulnerability)
        if design_pattern_check and design_pattern_check.is_false_positive:
            results.append(design_pattern_check)
            return results  # Early exit
        
        # Stage 1.8: Parameter origin check (NEW - admin-configured vs user-controlled)
        param_origin_check = self._check_parameter_origin(vulnerability)
        if param_origin_check and param_origin_check.is_false_positive:
            results.append(param_origin_check)
            return results  # Early exit
        
        # Stage 1.9: Impact analysis check (NEW - fast, deterministic)
        impact_check = self._check_impact_alignment(vulnerability)
        if impact_check and impact_check.is_false_positive:
            results.append(impact_check)
            return results  # Early exit
        
        # Stage 2: Design assumption check
        design_check = self._check_design_assumptions(vulnerability)
        if design_check:
            results.append(design_check)
            return results  # Early exit
        
        # Stage 3: Reentrancy guard check
        reentrancy_check = self._check_reentrancy_protection(vulnerability)
        if reentrancy_check:
            results.append(reentrancy_check)
            return results  # Early exit
        
        # Stage 4: Scope classification (admin-only, etc.)
        scope_check = self._check_scope_classification(vulnerability)
        if scope_check:
            results.append(scope_check)
            return results  # Early exit
        
        # Stage 5: Governance control check
        governance_check = self._check_governance_control(vulnerability)
        if governance_check:
            results.append(governance_check)
            return results  # Early exit
        
        # Stage 6: Deployment check
        deployment_check = self._check_deployment(vulnerability)
        if deployment_check:
            results.append(deployment_check)
            return results  # Early exit
        
        # Stage 6.5: Protocol-level protection check (NEW - protocol architecture analysis)
        protocol_check = self._check_protocol_protections(vulnerability)
        if protocol_check:
            results.append(protocol_check)
            # Don't early exit - may adjust severity instead of filtering
        
        # Stage 7: Local validation check
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
    
    def _check_enhanced_false_positive(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Enhanced multi-strategy false positive check (Nov 2025 improvements).
        
        Checks:
        1. Control flow guards (timing constraints, access controls)
        2. Inheritance verification (catches false claims)
        3. DeFi pattern recognition (vesting, ERC4626, etc.)
        4. Severity calibration (adjusts based on pattern)
        5. Impact quantification (checks for real exploit paths)
        """
        if not self.enhanced_fp_filter:
            return None
        
        try:
            result = self.enhanced_fp_filter.validate_finding(vuln)
            
            # If false positive, return immediately
            if result.is_false_positive:
                reasoning_text = "\n".join(result.reasoning)
                return ValidationStage(
                    stage_name="enhanced_false_positive_filter",
                    is_false_positive=True,
                    confidence=0.90,
                    reasoning=reasoning_text
                )
            
            # If severity adjusted or has recommendations, return non-blocking result
            if result.adjusted_severity or result.recommendations:
                reasoning_parts = []
                
                if result.adjusted_severity:
                    reasoning_parts.append(
                        f"Severity adjusted: {result.original_severity} → {result.adjusted_severity}"
                    )
                
                reasoning_parts.extend(result.reasoning)
                
                if result.recommendations:
                    reasoning_parts.append("Recommendations:")
                    reasoning_parts.extend(f"  - {rec}" for rec in result.recommendations)
                
                reasoning_text = "\n".join(reasoning_parts)
                
                # Apply adjustments to vulnerability
                if result.adjusted_severity:
                    vuln['severity'] = result.adjusted_severity
                if result.confidence_adjustment:
                    current_conf = vuln.get('confidence', 0.7)
                    vuln['confidence'] = max(0.0, min(1.0, current_conf + result.confidence_adjustment))
                
                return ValidationStage(
                    stage_name="enhanced_false_positive_filter",
                    is_false_positive=False,
                    confidence=vuln.get('confidence', 0.7),
                    reasoning=reasoning_text
                )
            
            return None
            
        except Exception as e:
            # Don't fail the entire validation if enhanced filter has issues
            import logging
            logging.warning(f"Enhanced FP filter error: {e}")
            return None
    
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
    
    def _check_dos_feasibility(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if DoS vulnerability is actually exploitable.
        
        Validates DoS-related vulnerabilities to prevent false positives like:
        - Unbounded loops over cryptographically validated data
        - View functions with high gas costs (attacker pays)
        - Operations with economic barriers
        """
        if not self.dos_feasibility_validator:
            return None
        
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Only validate DoS-related vulnerabilities
        dos_keywords = ['dos', 'denial', 'gas', 'unbounded', 'loop', 'block_gas_limit']
        if not any(keyword in vuln_type for keyword in dos_keywords):
            return None
        
        line_number = vuln.get('line_number', vuln.get('line', 0))
        
        validation_result = self.dos_feasibility_validator.validate_dos_vulnerability(
            vuln,
            self.contract_code,
            function_context=None
        )
        
        if not validation_result.is_exploitable:
            return ValidationStage(
                stage_name='dos_feasibility',
                is_false_positive=True,
                confidence=validation_result.confidence,
                reasoning=f"{validation_result.feasibility.value}: {validation_result.reasoning}"
            )
        
        # If exploitable but severity should be downgraded
        if validation_result.recommended_severity and validation_result.recommended_severity != vuln.get('severity', ''):
            # Update severity in the vuln dict (in-place modification)
            vuln['severity'] = validation_result.recommended_severity
            vuln['dos_validation_note'] = validation_result.reasoning
        
        return None
    
    def _check_constructor_context(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if vulnerability is in constructor (deployment-time only).
        
        Constructor vulnerabilities are typically deployment concerns, not runtime exploits.
        """
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        
        if line_number == 0:
            return None  # Can't determine context without line number
        
        # Check if this line is inside constructor
        in_constructor = self._is_inside_constructor(line_number, self.contract_code)
        
        if in_constructor:
            # Check if there's proper initialization pattern
            has_initializer = self._has_initialization_function(self.contract_code)
            
            if has_initializer:
                return ValidationStage(
                    stage_name="constructor_context",
                    is_false_positive=True,
                    confidence=0.9,
                    reasoning="Vulnerability in constructor with proper initialization pattern - deployment-time only, not runtime exploitable"
                )
            else:
                # Constructor without initializer - could be deployment concern but flag for review
                return ValidationStage(
                    stage_name="constructor_context",
                    is_false_positive=False,
                    confidence=0.6,
                    reasoning="Constructor issue with no clear initialization pattern - needs manual review"
                )
        
        return None  # Not in constructor
    
    def _is_inside_constructor(self, line_num: int, code: str) -> bool:
        """Check if line is inside constructor."""
        lines = code.split('\n')
        
        # Find constructor start
        constructor_pattern = r'constructor\s*\('
        
        brace_depth = 0
        in_constructor = False
        
        for i, line in enumerate(lines, 1):
            if re.search(constructor_pattern, line):
                in_constructor = True
                
            if in_constructor:
                brace_depth += line.count('{') - line.count('}')
                
                if i == line_num:
                    return True
                    
                if brace_depth == 0 and i > 1:  # Constructor ended
                    in_constructor = False
        
        return False
    
    def _has_initialization_function(self, code: str) -> bool:
        """Check if contract has an initialization function (initializer/reinitializer)."""
        # Check for common initialization patterns
        init_patterns = [
            r'function\s+initialize\s*\(',
            r'function\s+init\s*\(',
            r'\binitializer\b',
            r'\breinitializer\b',
            r'__\w+_init\(',  # OpenZeppelin style
        ]
        
        for pattern in init_patterns:
            if re.search(pattern, code):
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
    
    def _check_protocol_protections(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if vulnerability is mitigated by protocol-level protections.
        
        This checks for:
        - Off-chain observer validation
        - Legacy contract status
        - Multi-component security boundaries
        """
        if not self.protocol_protection_detector:
            return None
        
        try:
            # Get contract path if available
            contract_path = None
            if self.project_path:
                # Try to find contract file
                contract_name = vuln.get('contract_name', '')
                if contract_name:
                    # Search for .sol file with this contract name
                    for sol_file in self.project_path.rglob('*.sol'):
                        try:
                            content = sol_file.read_text(encoding='utf-8', errors='ignore')
                            if f'contract {contract_name}' in content or f'contract {contract_name} ' in content:
                                contract_path = sol_file
                                break
                        except Exception:
                            continue
            
            # Validate finding
            validation_result = self.protocol_protection_detector.validate_finding(
                vulnerability=vuln,
                contract_code=self.contract_code,
                contract_path=contract_path,
                project_root=self.project_path
            )
            
            if not validation_result:
                return None
            
            # If mitigated, create validation stage
            if validation_result.is_mitigated:
                # Determine if this should be filtered or just severity-adjusted
                # For off-chain validation that prevents exploit but not user error,
                # we adjust severity rather than filter completely
                if validation_result.mitigation_type and validation_result.mitigation_type.value == 'off_chain_validation':
                    # Adjust severity but don't filter (user errors still possible)
                    return ValidationStage(
                        stage_name="protocol_protection",
                        is_false_positive=False,  # Not a false positive, but severity adjusted
                        confidence=validation_result.confidence,
                        reasoning=f"Protocol-level protection detected: {validation_result.reasoning}"
                    )
                else:
                    # Other mitigations might be false positives
                    return ValidationStage(
                        stage_name="protocol_protection",
                        is_false_positive=True,
                        confidence=validation_result.confidence,
                        reasoning=validation_result.reasoning
                    )
            
            # If severity was adjusted, return stage with adjustment info
            if validation_result.adjusted_severity:
                return ValidationStage(
                    stage_name="protocol_protection",
                    is_false_positive=False,
                    confidence=validation_result.confidence,
                    reasoning=f"Severity adjusted due to protocol context: {validation_result.reasoning}"
                )
        
        except Exception:
            # Fail silently to not break existing functionality
            return None
        
        return None
    
    def _check_local_validation(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check for local validation (require statements, etc.) with enhanced context awareness."""
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # ENHANCED: Check validation for ALL vulnerability types, not just arithmetic
        # This catches cases like token validation before cast, balance checks before calls, etc.
        
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        if line_number == 0:
            return None
        
        # NEW: Context-aware validation detection
        nearby_validations = self._check_nearby_validations(vuln, window=10)
        if nearby_validations:
            validation_list = '\n'.join(nearby_validations[:3])  # Show top 3
            return ValidationStage(
                stage_name="local_validation",
                is_false_positive=True,
                confidence=0.85,
                reasoning=f"Validation found near vulnerable line:\n{validation_list}"
            )
        
        # Legacy checks for backward compatibility
        if any(keyword in vuln_type for keyword in ['overflow', 'underflow', 'division', 'arithmetic']):
            if not self.validation_detector:
                # Fallback to simple pattern matching
                return self._simple_validation_check(vuln)
            
            if self.validation_detector.check_if_validated(line_number, self.contract_code):
                return ValidationStage(
                    stage_name="local_validation",
                    is_false_positive=True,
                    confidence=0.8,
                    reasoning="Validation found before vulnerable operation"
                )
        
        return None
    
    def _check_nearby_validations(self, vuln: Dict, window: int = 10) -> List[str]:
        """
        Check for require/revert/if statements within N lines of vulnerability.
        
        This catches cases like:
        - Line 213: require(_token == expected, "Invalid token");
        - Line 216: IERC20(_token).approve(...);  // Flagged but protected
        
        Args:
            vuln: Vulnerability dictionary
            window: Number of lines to check before/after (default 10)
            
        Returns:
            List of validation statements found (e.g., ["Line 213: require(_token == ...)"])
        """
        line_number = vuln.get('line', 0) or vuln.get('line_number', 0)
        if line_number == 0:
            return []
        
        lines = self.contract_code.split('\n')
        if line_number > len(lines):
            return []
        
        # Extract suspect variables from vulnerability description or code snippet
        suspect_vars = self._extract_suspect_variables(vuln)
        if not suspect_vars:
            # No specific variables to validate, use generic patterns
            suspect_vars = ['']  # Empty string will match all validations
        
        validations = []
        
        # Check window BEFORE the vulnerable line (where validations usually are)
        context_start = max(0, line_number - window - 1)  # -1 for 0-based indexing
        context_end = line_number - 1
        
        for i in range(context_start, context_end):
            if i >= len(lines):
                break
            
            line_text = lines[i].strip()
            
            # Skip empty lines and comments
            if not line_text or line_text.startswith('//'):
                continue
            
            # Check for validation patterns
            for var in suspect_vars:
                # Require statements
                if var:
                    # Look for require with the specific variable
                    if re.search(rf'\brequire\s*\([^)]*\b{re.escape(var)}\b', line_text, re.IGNORECASE):
                        validations.append(f"Line {i+1}: {line_text[:80]}")
                        continue
                    # Look for if + revert with the variable
                    if re.search(rf'\bif\s*\([^)]*\b{re.escape(var)}\b', line_text, re.IGNORECASE):
                        # Check if next few lines have revert
                        for j in range(i+1, min(i+3, len(lines))):
                            if 'revert' in lines[j].lower():
                                validations.append(f"Line {i+1}-{j+1}: if({var}...) revert")
                                break
                else:
                    # Generic validation patterns (when no specific variable)
                    if re.search(r'\brequire\s*\(', line_text):
                        validations.append(f"Line {i+1}: {line_text[:80]}")
        
        # Also check a few lines AFTER for post-condition checks
        context_after_start = line_number
        context_after_end = min(len(lines), line_number + 5)
        
        for i in range(context_after_start, context_after_end):
            if i >= len(lines):
                break
            
            line_text = lines[i].strip()
            
            # Check for balance assertions (common protection pattern)
            if re.search(r'\brequire\s*\([^)]*balance.*>=', line_text, re.IGNORECASE):
                validations.append(f"Line {i+1} (post-check): {line_text[:80]}")
        
        return validations
    
    def _extract_suspect_variables(self, vuln: Dict) -> List[str]:
        """
        Extract variable names that might be validated from vulnerability context.
        
        For example:
        - Description: "Token contract cast without validation"
        - Code snippet: "IERC20(_token).approve(...)"
        - Extract: ["_token"]
        """
        variables = []
        
        # Try to extract from code snippet
        code_snippet = vuln.get('code_snippet', '') or vuln.get('code', '')
        
        # Look for parameter-like variables (_token, _amount, etc.)
        param_pattern = r'\b(_\w+)\b'
        params = re.findall(param_pattern, code_snippet)
        variables.extend(params)
        
        # Look for cast patterns like IERC20(someVar)
        cast_pattern = r'\b(?:IERC20|IERC721|IUniswap\w+|I\w+)\s*\(\s*(\w+)\s*\)'
        casts = re.findall(cast_pattern, code_snippet)
        variables.extend(casts)
        
        # Look for common parameter names in description
        description = vuln.get('description', '').lower()
        if 'token' in description and 'token' not in variables:
            # Search for token-related variables in code
            token_vars = re.findall(r'\b(_?token\w*)\b', code_snippet, re.IGNORECASE)
            variables.extend(token_vars)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_vars = []
        for var in variables:
            if var and var not in seen:
                seen.add(var)
                unique_vars.append(var)
        
        return unique_vars[:5]  # Limit to top 5 most relevant
    
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
    
    def _check_design_assumptions(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if vulnerability is a documented design assumption."""
        if not self.design_assumption_detector:
            return None
        
        contract_name = vuln.get('contract_name', '')
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # NEW: Check for personal deployment pattern (centralization by design)
        if any(keyword in vuln_type for keyword in ['centralization', 'privileged', 'access control']):
            personal_deployment = self.design_assumption_detector.detect_personal_deployment_pattern(
                self.contract_code,
                contract_name
            )
            
            if personal_deployment and personal_deployment['is_personal_deployment']:
                return ValidationStage(
                    stage_name="personal_deployment_by_design",
                    is_false_positive=True,
                    confidence=personal_deployment['confidence'],
                    reasoning=personal_deployment['reasoning']
                )
        
        # Detect all design assumptions in contract
        assumptions = self.design_assumption_detector.detect_assumptions(
            self.contract_code,
            contract_name
        )
        
        # Check if this vulnerability is covered by an assumption
        if self.design_assumption_detector.is_vulnerability_assumed_safe(vuln, assumptions):
            matching_assumption = None
            for assumption in assumptions:
                if self.design_assumption_detector.is_vulnerability_assumed_safe(vuln, [assumption]):
                    matching_assumption = assumption
                    break
            
            if matching_assumption:
                reason = self.design_assumption_detector.generate_filter_reason(vuln, matching_assumption)
                return ValidationStage(
                    stage_name="design_assumption",
                    is_false_positive=True,
                    confidence=0.85,
                    reasoning=reason
                )
        
        return None
    
    def _check_reentrancy_protection(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if function has reentrancy protection."""
        if not self.reentrancy_guard_detector:
            return None
        
        vuln_type = vuln.get('type', '').lower()
        
        # Only check reentrancy-related vulnerabilities
        if 'reentr' not in vuln_type and 'callback' not in vuln_type:
            return None
        
        contract_name = vuln.get('contract_name', '')
        should_filter, reason = self.reentrancy_guard_detector.should_filter_reentrancy_vuln(
            vuln,
            self.contract_code,
            contract_name
        )
        
        if should_filter:
            return ValidationStage(
                stage_name="reentrancy_protection",
                is_false_positive=True,
                confidence=0.9,
                reasoning=reason
            )
        
        return None
    
    def _check_scope_classification(self, vuln: Dict) -> Optional[ValidationStage]:
        """Check if vulnerability is out of bug bounty scope."""
        if not self.scope_classifier:
            return None
        
        contract_name = vuln.get('contract_name', '')
        classification = self.scope_classifier.classify_vulnerability(
            vuln,
            self.contract_code,
            contract_name
        )
        
        # Filter out-of-scope vulnerabilities
        from core.scope_classifier import ScopeStatus
        if classification.status == ScopeStatus.OUT_OF_SCOPE:
            return ValidationStage(
                stage_name="scope_classification",
                is_false_positive=True,
                confidence=classification.confidence,
                reasoning=f"Out of scope: {classification.reason} (Category: {classification.category})"
            )
        
        return None
    
    def _check_function_context(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if finding misaligns with function context (NEW STAGE).
        
        Example: High severity finding claiming fund impact on a view function.
        """
        if not self.function_context_analyzer:
            return None
        
        # Extract function code from contract
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        # Find function in contract code
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        # Analyze function context
        context = self.function_context_analyzer.analyze_function(function_code, function_name, self.contract_code)
        
        # Check for false positive based on context
        vuln_type = vuln.get('vulnerability_type', '')
        description = vuln.get('description', '')
        
        is_fp, reason = self.function_context_analyzer.is_false_positive(vuln_type, description, context)
        
        if is_fp:
            return ValidationStage(
                stage_name="function_context",
                is_false_positive=True,
                confidence=context.confidence,
                reasoning=reason
            )
        
        # Check if severity should be adjusted (not a false positive, but wrong severity)
        severity = vuln.get('severity', 'medium')
        adjusted_severity, adjustment_reason = self.function_context_analyzer.adjust_finding_severity(
            vuln_type, severity, context
        )
        
        # If severity would be downgraded to 'info', treat as false positive
        if adjusted_severity == 'info' and severity in ['high', 'critical']:
            return ValidationStage(
                stage_name="function_context",
                is_false_positive=True,
                confidence=0.85,
                reasoning=f"Severity downgraded to 'info': {adjustment_reason}"
            )
        
        return None
    
    def _check_impact_alignment(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if claimed impact aligns with actual function capabilities (NEW STAGE).
        
        Example: Finding claims fund theft but function is read-only.
        """
        if not self.impact_analyzer or not self.function_context_analyzer:
            return None
        
        # Extract function context
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        context = self.function_context_analyzer.analyze_function(function_code, function_name, self.contract_code)
        
        # Analyze impact
        impact_analysis = self.impact_analyzer.calculate_impact(vuln, context)
        
        # If no real impact, it's a false positive
        if not impact_analysis.should_report:
            return ValidationStage(
                stage_name="impact_analysis",
                is_false_positive=True,
                confidence=impact_analysis.confidence,
                reasoning=impact_analysis.reasoning
            )
        
        return None
    
    def _extract_function_name_from_vuln(self, vuln: Dict) -> str:
        """Extract function name from vulnerability description or code snippet."""
        # Try to extract from description
        description = vuln.get('description', '')
        code_snippet = vuln.get('code_snippet', '')
        
        # Look for function pattern in description
        func_match = re.search(r'function\s+(\w+)', description)
        if func_match:
            return func_match.group(1)
        
        # Look for function name followed by parentheses
        func_match = re.search(r'`?(\w+)\s*\(', description)
        if func_match:
            return func_match.group(1)
        
        # Look in code snippet
        func_match = re.search(r'function\s+(\w+)', code_snippet)
        if func_match:
            return func_match.group(1)
        
        return ""
    
    def _extract_function_code(self, function_name: str) -> str:
        """Extract function code from contract."""
        # Find function definition
        pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{'
        match = re.search(pattern, self.contract_code)
        
        if not match:
            return ""
        
        # Extract function body (simplified - just get next few lines)
        start = match.start()
        end = self._find_function_end(match.end(), self.contract_code)
        
        return self.contract_code[start:end]
    
    def _find_function_end(self, start: int, code: str) -> int:
        """Find end of function by matching braces."""
        depth = 1  # Already entered first brace
        i = start
        
        while i < len(code) and depth > 0:
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
            i += 1
        
        return i
    
    def _check_code_description_mismatch(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if vulnerability description matches the actual code.
        Catches obvious false positives like claiming "decode" on encode operations.
        """
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        code_snippet = vuln.get('code_snippet', '')
        
        # Pattern 1: Claims decoding but only encoding present
        if ('decoding' in description or 'decode' in vuln_type or 'unvalidated_decoding' in vuln_type):
            if 'abi.encode(' in code_snippet and 'abi.decode(' not in code_snippet:
                return ValidationStage(
                    stage_name="code_description_mismatch",
                    is_false_positive=True,
                    confidence=0.98,
                    reasoning="Vulnerability claims 'decoding' but code only shows abi.encode() - this is encoding, not decoding"
                )
        
        # Pattern 2: Claims overflow but SafeMath/SafeCast present
        if 'overflow' in vuln_type or 'underflow' in vuln_type:
            if ('SafeMath' in code_snippet or 'SafeCast' in code_snippet) and 'unchecked' not in code_snippet:
                return ValidationStage(
                    stage_name="code_description_mismatch",
                    is_false_positive=True,
                    confidence=0.95,
                    reasoning="Claims overflow/underflow but code uses SafeMath/SafeCast which prevents this"
                )
        
        # Pattern 3: Claims reentrancy but function is view/pure
        if 'reentr' in vuln_type:
            # Extract function signature from code
            if re.search(r'function\s+\w+\([^)]*\)\s+(external|public)\s+view', code_snippet):
                return ValidationStage(
                    stage_name="code_description_mismatch",
                    is_false_positive=True,
                    confidence=0.99,
                    reasoning="Claims reentrancy but function is view (read-only) - cannot have reentrancy"
                )
            if re.search(r'function\s+\w+\([^)]*\)\s+(external|public)\s+pure', code_snippet):
                return ValidationStage(
                    stage_name="code_description_mismatch",
                    is_false_positive=True,
                    confidence=0.99,
                    reasoning="Claims reentrancy but function is pure - cannot have reentrancy"
                )
        
        return None
    
    def _check_enhanced_access_control(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Enhanced access control check that traces full modifier chains.
        Catches cases like onlyTrustedOrRestricted calling _checkCanCall().
        
        NOTE: This should only filter if NOT front-runnable AND not a validation/DoS bug.
        """
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Extract function from vulnerability
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        # Check if front-runnable FIRST - if yes, don't filter on access control alone
        if self._is_front_runnable(vuln, function_code):
            # Front-runnable vulnerabilities should NOT be filtered just because they have access control
            return None
        
        # Check if it's a validation/DoS bug in privileged function - these are still real bugs
        if any(keyword in vuln_type for keyword in ['validation', 'dos', 'overflow', 'underflow', 'parameter']):
            # Don't filter validation issues even if access controlled
            return None
        
        # Analyze access control chain
        access_analysis = self._analyze_access_control_chain(function_code, self.contract_code)
        
        if access_analysis['has_access_control']:
            return ValidationStage(
                stage_name="enhanced_access_control",
                is_false_positive=True,
                confidence=access_analysis['confidence'],
                reasoning=access_analysis['reasoning']
            )
        
        return None
    
    def _analyze_access_control_chain(self, function_code: str, contract_code: str) -> Dict:
        """
        Trace full access control chain including:
        1. Direct modifiers (onlyOwner, onlyGovernor, restricted, etc.)
        2. Inherited modifiers from parent contracts
        3. Custom access patterns (_checkCanCall, etc.)
        4. Modifier chains (modifier A calls modifier B)
        """
        # Extract modifiers from function signature
        modifiers = self._extract_modifiers_from_function(function_code)
        
        access_info = {
            'has_access_control': False,
            'modifiers': [],
            'custom_checks': [],
            'confidence': 0.0,
            'reasoning': ''
        }
        
        # Known access control modifiers
        known_modifiers = [
            'onlyOwner', 'onlyGovernor', 'onlyGuardian', 'onlyAdmin',
            'restricted', 'onlyRole', 'onlyAuthorized', 'onlyManager',
            'onlyTrusted', 'onlyTrustedOrRestricted', 'onlyGovernance',
            'requiresAuth', 'auth', 'onlyOwnerOrGuardian'
        ]
        
        for modifier in modifiers:
            # Check if it's a known access control modifier
            if modifier in known_modifiers:
                access_info['has_access_control'] = True
                access_info['modifiers'].append(modifier)
                continue
            
            # Check if modifier contains access control logic
            modifier_def = self._find_modifier_definition(modifier, contract_code)
            if modifier_def:
                # Look for _checkCanCall or similar patterns
                if '_checkCanCall' in modifier_def:
                    access_info['has_access_control'] = True
                    access_info['custom_checks'].append(f"{modifier} contains _checkCanCall")
                
                # Look for require(msg.sender == ...)
                if re.search(r'require\s*\([^)]*msg\.sender', modifier_def):
                    access_info['has_access_control'] = True
                    access_info['custom_checks'].append(f"{modifier} checks msg.sender")
                
                # Look for if (!condition) revert pattern
                if re.search(r'if\s*\([^)]*\)\s*revert', modifier_def):
                    access_info['has_access_control'] = True
                    access_info['custom_checks'].append(f"{modifier} has conditional revert")
        
        # Build reasoning
        if access_info['has_access_control']:
            reasons = []
            if access_info['modifiers']:
                reasons.append(f"Protected by {', '.join(access_info['modifiers'])}")
            if access_info['custom_checks']:
                reasons.append(f"Custom checks: {'; '.join(access_info['custom_checks'])}")
            
            access_info['reasoning'] = ' | '.join(reasons) + " - Not externally exploitable by arbitrary users"
            access_info['confidence'] = 0.92
        
        return access_info
    
    def _extract_modifiers_from_function(self, function_code: str) -> List[str]:
        """Extract modifiers from function signature."""
        # Match: function name(...) modifier1 modifier2 returns (...)
        # or: function name(...) modifier1 modifier2 {...
        pattern = r'function\s+\w+\s*\([^)]*\)\s+((?:(?:public|external|internal|private|view|pure|payable|virtual|override|\w+)\s+)+)'
        match = re.search(pattern, function_code)
        
        if not match:
            return []
        
        modifier_string = match.group(1)
        
        # Filter out visibility/mutability keywords
        keywords_to_ignore = {'public', 'external', 'internal', 'private', 'view', 'pure', 'payable', 'virtual', 'override', 'returns'}
        
        modifiers = []
        for word in modifier_string.split():
            word = word.strip()
            if word and word not in keywords_to_ignore:
                modifiers.append(word)
        
        return modifiers
    
    def _find_modifier_definition(self, modifier_name: str, contract_code: str) -> str:
        """Find modifier definition in contract code."""
        pattern = rf'modifier\s+{re.escape(modifier_name)}\s*\([^)]*\)\s*\{{'
        match = re.search(pattern, contract_code)
        
        if not match:
            return ""
        
        # Extract modifier body (simplified)
        start = match.start()
        end = self._find_function_end(match.end(), contract_code)
        
        return contract_code[start:end]
    
    def _check_cross_contract_access_control(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check for cross-contract access control (Dec 2025).
        
        Some functions appear permissionless but are actually protected by
        access control enforced in external contracts they call.
        
        Example: transferFundsFromSharedBridge() is permissionless but calls
        L1_NULLIFIER.transferTokenToNTV() which requires onlyL1NTV modifier.
        """
        if not self.cross_contract_analyzer:
            return None
        
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        
        # Only apply to access control related findings
        if not any(kw in vuln_type or kw in description 
                   for kw in ['access control', 'permission', 'authorization', 'missing modifier']):
            return None
        
        # Extract function code
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        try:
            # Check if function is permissionless but protected by external calls
            is_safe, reasoning = self.cross_contract_analyzer.is_permissionless_but_safe(
                function_code,
                self.contract_code,
                self.project_path
            )
            
            if is_safe:
                return ValidationStage(
                    stage_name="cross_contract_access_control",
                    is_false_positive=True,
                    confidence=0.88,
                    reasoning=f"Cross-contract protection: {reasoning}"
                )
            
            # Also try the enhanced access control check
            result = self.cross_contract_analyzer.enhance_access_control_check(
                vuln,
                function_code,
                self.contract_code,
                self.project_path
            )
            
            if result.has_access_control and result.confidence >= 0.85:
                return ValidationStage(
                    stage_name="cross_contract_access_control",
                    is_false_positive=True,
                    confidence=result.confidence,
                    reasoning=result.reasoning
                )
        except Exception as e:
            # Don't fail validation pipeline if cross-contract analysis fails
            pass
        
        return None
    
    def _check_safe_design_pattern(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check for safe permissionless design patterns (Dec 2025).
        
        Some functions are intentionally permissionless by design:
        - Migration helpers
        - Pull payments
        - Factory deployments
        - Sync operations
        - Bridge relays
        
        These should not be flagged as access control vulnerabilities.
        """
        if not self.design_pattern_detector:
            return None
        
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        
        # Only apply to access control related findings
        if not any(kw in vuln_type or kw in description 
                   for kw in ['access control', 'permission', 'authorization', 'missing modifier']):
            return None
        
        # Extract function info
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        try:
            # Check if finding should be filtered due to safe design pattern
            should_filter, reasoning = self.design_pattern_detector.should_filter_access_control_finding(
                vuln,
                function_name,
                function_code,
                self.contract_code
            )
            
            if should_filter:
                return ValidationStage(
                    stage_name="safe_design_pattern",
                    is_false_positive=True,
                    confidence=0.85,
                    reasoning=f"Safe design pattern: {reasoning}"
                )
        except Exception as e:
            # Don't fail validation pipeline if pattern detection fails
            pass
        
        return None
    
    def _check_parameter_origin(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Check if parameters are admin-configured vs user-controlled.
        Filters false positives where users can't actually pass arbitrary values.
        """
        description = vuln.get('description', '').lower()
        code_snippet = vuln.get('code_snippet', '')
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Look for patterns indicating user can pass arbitrary addresses/values
        if not any(keyword in description for keyword in ['arbitrary', 'user', 'attacker', 'malicious', 'untrusted']):
            return None
        
        # Extract potential parameter names
        param_candidates = self._extract_parameter_candidates(description, code_snippet)
        
        for param_name in param_candidates:
            origin_info = self._analyze_param_origin(param_name, code_snippet, self.contract_code)
            
            if origin_info['origin'] == 'admin_configured':
                return ValidationStage(
                    stage_name="parameter_origin",
                    is_false_positive=True,
                    confidence=origin_info['confidence'],
                    reasoning=origin_info['reasoning']
                )
        
        return None
    
    def _extract_parameter_candidates(self, description: str, code_snippet: str) -> List[str]:
        """Extract potential parameter names from description and code."""
        candidates = []
        
        # Look for common parameter names in description
        param_patterns = [
            r'\b(\w+Asset)\b',
            r'\b(\w+Address)\b',
            r'\b(\w+Token)\b',
            r'\b(\w+Vault)\b',
            r'`(\w+)`',
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            candidates.extend(matches)
        
        # Extract from function parameters in code
        func_param_pattern = r'function\s+\w+\s*\([^)]*address\s+(\w+)'
        matches = re.findall(func_param_pattern, code_snippet)
        candidates.extend(matches)
        
        return list(set(candidates))  # Deduplicate
    
    def _analyze_param_origin(self, param_name: str, code_snippet: str, contract_code: str) -> Dict:
        """
        Determine if parameter is admin-configured or user-controlled.
        """
        # Check if parameter is used as mapping/array key
        if re.search(rf'(\w+Data)\[{re.escape(param_name)}\]', code_snippet):
            # It's looking up data that must be pre-configured
            mapping_name = re.search(rf'(\w+Data)\[{re.escape(param_name)}\]', code_snippet).group(1)
            
            # Find setters for this mapping
            setter_pattern = rf'function\s+set{mapping_name.replace("Data", "")}\w*\s*\([^)]*\)\s*\w*\s*(restricted|onlyOwner|onlyGovernor|onlyGuardian)'
            
            if re.search(setter_pattern, contract_code, re.IGNORECASE):
                return {
                    'origin': 'admin_configured',
                    'confidence': 0.93,
                    'reasoning': f"Parameter {param_name} must be pre-configured via admin-restricted setter function - users cannot pass arbitrary values"
                }
        
        # Check for yieldBearingData pattern (common in DeFi)
        if 'yieldBearing' in param_name or 'collateral' in param_name:
            if re.search(r'yieldBearingData\[', code_snippet) or re.search(r'collateralData\[', code_snippet):
                return {
                    'origin': 'admin_configured',
                    'confidence': 0.95,
                    'reasoning': f"{param_name} must exist in admin-configured whitelist mapping - arbitrary addresses cannot be used"
                }
        
        # Check if there's validation against a whitelist
        if re.search(rf'require\s*\([^)]*{re.escape(param_name)}[^)]*!=\s*address\(0\)', code_snippet):
            # Just a zero-check, not admin configuration
            return {
                'origin': 'user_controlled',
                'confidence': 0.7,
                'reasoning': 'Only basic validation, appears user-controlled'
            }
        
        return {
            'origin': 'unknown',
            'confidence': 0.5,
            'reasoning': 'Cannot determine parameter origin'
        }
    
    # _check_bug_bounty_relevance method REMOVED
    # Bug bounty assessment now happens AFTER LLM validation in llm_false_positive_filter.py
    # This allows all findings to be assessed by LLM first, then marked for bug bounty relevance
    
    def _check_exploitability(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Phase 2: Check if vulnerability is actually exploitable by external attackers.
        Filters findings that require privileged access and aren't front-runnable.
        """
        # Extract function information
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        # Calculate exploitability score
        exploit_analysis = self._calculate_exploitability_score(vuln, function_code, self.contract_code)
        
        if not exploit_analysis['exploitable']:
            return ValidationStage(
                stage_name="exploitability_check",
                is_false_positive=True,
                confidence=exploit_analysis['confidence'],
                reasoning=exploit_analysis['reasoning']
            )
        
        return None
    
    def _calculate_exploitability_score(self, vuln: Dict, function_code: str, contract_code: str) -> Dict:
        """
        Determine if vulnerability is ACTUALLY exploitable by external attackers.
        
        Returns:
            - exploitable: bool
            - attack_type: 'direct' | 'front_run' | 'governance' | 'privileged_bug'
            - reasoning: str
            - confidence: float
        """
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Check function access control
        access_analysis = self._analyze_access_control_chain(function_code, contract_code)
        
        # If function has access control, check if it's front-runnable
        if access_analysis['has_access_control']:
            # Check if it's front-runnable
            if self._is_front_runnable(vuln, function_code):
                return {
                    'exploitable': True,
                    'attack_type': 'front_run',
                    'reasoning': f"Trusted function can be front-run by attackers manipulating external state",
                    'confidence': 0.85
                }
            # Check if it's a validation/DoS issue in privileged function
            elif any(keyword in vuln_type for keyword in ['validation', 'dos', 'overflow', 'underflow']):
                # These are real bugs even in privileged functions (can cause DoS)
                return {
                    'exploitable': True,
                    'attack_type': 'privileged_bug',
                    'reasoning': f"Validation/DoS issue in privileged function - real bug but requires {', '.join(access_analysis['modifiers'])} access",
                    'confidence': 0.75
                }
            else:
                return {
                    'exploitable': False,
                    'attack_type': 'governance',
                    'reasoning': f"Only accessible to {', '.join(access_analysis['modifiers'])} - not externally exploitable by arbitrary users",
                    'confidence': 0.93
                }
        
        # No access control - directly exploitable
        return {
            'exploitable': True,
            'attack_type': 'direct',
            'reasoning': 'Function is public/external with no access control - directly exploitable',
            'confidence': 0.95
        }
    
    def _is_front_runnable(self, vuln: Dict, function_code: str) -> bool:
        """
        Check if vulnerability can be exploited via front-running.
        
        Front-runnable patterns:
        1. Uses balanceOf() that can be manipulated by sending tokens
        2. Uses getReserves() from AMM  
        3. Reads external state that attacker can modify before execution
        """
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        code_snippet = vuln.get('code_snippet', '')
        
        # Pattern 1: balanceOf manipulation (like Finding #11)
        # Check both function code and code snippet
        balanceof_patterns = [
            r'\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
            r'IERC20\s*\([^)]+\)\s*\.balanceOf',
            r'\.balanceOf\s*\(',
        ]
        
        has_balanceof = any(re.search(pattern, function_code) or re.search(pattern, code_snippet) 
                           for pattern in balanceof_patterns)
        
        if has_balanceof:
            # Check if it's used in a security-sensitive context
            if any(keyword in description for keyword in ['slippage', 'manipulation', 'bypass', 'front-run', 'check']):
                return True
            if any(keyword in vuln_type for keyword in ['manipulation', 'slippage', 'oracle']):
                return True
        
        # Pattern 2: AMM reserves manipulation
        if re.search(r'\.getReserves\s*\(', function_code):
            if 'oracle' in vuln_type or 'price' in description or 'manipulation' in description:
                return True
        
        # Pattern 3: Check if description explicitly mentions front-running
        if 'front-run' in description or 'front run' in description or 'frontrun' in description:
            return True
        
        return False
    
    def _check_realistic_impact(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Phase 3: Calculate REALISTIC impact, not theoretical maximum.
        Downgrade severity for low-impact findings.
        """
        vuln_type = vuln.get('vulnerability_type', '').lower()
        description = vuln.get('description', '').lower()
        severity = vuln.get('severity', 'medium').lower()
        code_snippet = vuln.get('code_snippet', '')
        
        # Get function context for better analysis
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if function_name:
            function_code = self._extract_function_code(function_name)
            if function_code:
                impact_analysis = self._calculate_realistic_impact_score(
                    vuln_type, description, severity, function_code, code_snippet
                )
                
                if impact_analysis['should_filter']:
                    return ValidationStage(
                        stage_name="realistic_impact",
                        is_false_positive=True,
                        confidence=impact_analysis['confidence'],
                        reasoning=impact_analysis['reasoning']
                    )
        
        return None
    
    def _calculate_realistic_impact_score(
        self, 
        vuln_type: str, 
        description: str, 
        severity: str,
        function_code: str,
        code_snippet: str
    ) -> Dict:
        """
        Calculate REALISTIC impact with specific patterns.
        """
        # Pattern 1: Precision loss with large divisors
        if 'precision' in vuln_type or 'rounding' in description:
            # Extract division values
            if 'BASE_27' in function_code or '1e27' in function_code or '1e18' in function_code:
                return {
                    'should_filter': True,
                    'impact': 'negligible',
                    'confidence': 0.88,
                    'reasoning': 'Precision loss with 1e27/1e18 divisor affects only dust amounts (< 0.000001%) - negligible real-world impact'
                }
            elif 'BASE_9' in function_code or '1e9' in function_code:
                if severity in ['high', 'critical']:
                    return {
                        'should_filter': True,
                        'impact': 'low',
                        'confidence': 0.82,
                        'reasoning': 'Precision loss with 1e9 divisor - affects small amounts only, not high/critical severity'
                    }
        
        # Pattern 2: SafeCast "overflow" - actually a revert, not silent overflow
        if 'SafeCast' in code_snippet and ('overflow' in vuln_type or 'underflow' in vuln_type):
            return {
                'should_filter': False,  # Keep it but note it's DoS
                'impact': 'dos',
                'confidence': 0.90,
                'reasoning': 'SafeCast reverts on overflow - this is DoS (denial of service), not fund theft'
            }
        
        # Pattern 3: View/pure function "vulnerabilities"
        if re.search(r'function\s+\w+\([^)]*\)\s+(external|public)\s+view', function_code):
            if severity in ['high', 'critical']:
                return {
                    'should_filter': True,
                    'impact': 'info',
                    'confidence': 0.95,
                    'reasoning': 'View function (read-only) cannot steal funds or modify state - informational only'
                }
        
        # Pattern 4: Integer overflow in Solidity 0.8+ without unchecked
        if ('overflow' in vuln_type or 'underflow' in vuln_type) and 'unchecked' not in code_snippet:
            # Check Solidity version
            version_match = re.search(r'pragma solidity\s+[\^>=<]*(\d+\.\d+)', self.contract_code)
            if version_match:
                version_str = version_match.group(1)
                if version_str >= '0.8':
                    return {
                        'should_filter': True,
                        'impact': 'none',
                        'confidence': 0.97,
                        'reasoning': f'Solidity {version_str} auto-reverts on overflow - not a vulnerability without unchecked{{}}'
                    }
        
        # No filtering needed
        return {
            'should_filter': False,
            'impact': severity,
            'confidence': 0.5,
            'reasoning': 'Standard impact analysis'
        }
    
    def _check_impact_alignment(self, vuln: Dict) -> Optional[ValidationStage]:
        """
        Enhanced impact alignment check that uses realistic impact calculation.
        IMPORTANT: Don't filter front-runnable vulnerabilities.
        """
        # Check if this is front-runnable first
        function_name = vuln.get('function', '') or self._extract_function_name_from_vuln(vuln)
        if function_name:
            function_code = self._extract_function_code(function_name)
            if function_code and self._is_front_runnable(vuln, function_code):
                # Front-runnable = real impact via external manipulation
                return None
        
        # First try realistic impact check
        realistic_check = self._check_realistic_impact(vuln)
        if realistic_check:
            return realistic_check
        
        # Fall back to original impact alignment if available
        if not self.impact_analyzer or not self.function_context_analyzer:
            return None
        
        # Extract function context
        if not function_name:
            return None
        
        function_code = self._extract_function_code(function_name)
        if not function_code:
            return None
        
        context = self.function_context_analyzer.analyze_function(function_code, function_name, self.contract_code)
        
        # Analyze impact
        impact_analysis = self.impact_analyzer.calculate_impact(vuln, context)
        
        # If no real impact, it's a false positive
        if not impact_analysis.should_report:
            return ValidationStage(
                stage_name="impact_analysis",
                is_false_positive=True,
                confidence=impact_analysis.confidence,
                reasoning=impact_analysis.reasoning
            )
        
        return None
    
    def get_summary(self) -> Dict:
        """Get summary of available validators."""
        return {
            'has_governance_detector': self.governance_detector is not None,
            'has_deployment_analyzer': self.deployment_analyzer is not None,
            'has_validation_detector': self.validation_detector is not None,
            'has_function_context_analyzer': self.function_context_analyzer is not None,
            'has_impact_analyzer': self.impact_analyzer is not None,
            'has_confidence_scorer': self.confidence_scorer is not None,
            'has_design_assumption_detector': self.design_assumption_detector is not None,
            'has_reentrancy_guard_detector': self.reentrancy_guard_detector is not None,
            'has_scope_classifier': self.scope_classifier is not None,
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

