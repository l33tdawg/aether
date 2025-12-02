"""
Enhanced False Positive Filter

Integrates multiple validation strategies to significantly reduce false positives:
1. Control flow guard detection
2. Inheritance verification  
3. DeFi pattern recognition
4. Impact quantification
5. Severity calibration
6. Modifier-based validation detection (NEW Dec 2025)
7. Intentional design pattern recognition (NEW Dec 2025)
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .control_flow_guard_detector import ControlFlowGuardDetector
from .inheritance_verifier import InheritanceVerifier
from .defi_pattern_recognizer import DeFiPatternRecognizer, PatternType

logger = logging.getLogger(__name__)


@dataclass
class EnhancedValidationResult:
    """Result of enhanced validation."""
    is_false_positive: bool
    original_severity: str
    adjusted_severity: Optional[str]
    confidence_adjustment: float  # +/- adjustment to confidence
    reasoning: List[str]  # Multiple reasoning steps
    recommendations: List[str]  # What to do about this finding


class EnhancedFalsePositiveFilter:
    """
    Enhanced false positive filtering using multiple strategies.
    
    Significantly reduces false positives by:
    - Understanding control flow and guards
    - Verifying inheritance claims
    - Recognizing standard DeFi patterns
    - Calibrating severity based on context
    - Detecting modifier-based validation (NEW)
    - Recognizing intentional design patterns (NEW)
    """
    
    def __init__(self):
        self.guard_detector = ControlFlowGuardDetector()
        self.inheritance_verifier = InheritanceVerifier()
        self.pattern_recognizer = DeFiPatternRecognizer()
        
        # New components for enhanced false positive detection
        self._modifier_analyzer = None
        self._intentional_design_detector = None
        
        # Initialize with contract code
        self.contract_analyzed = False
    
    def _get_modifier_analyzer(self):
        """Lazy load modifier analyzer."""
        if self._modifier_analyzer is None:
            from .modifier_semantic_analyzer import ModifierSemanticAnalyzer
            self._modifier_analyzer = ModifierSemanticAnalyzer()
        return self._modifier_analyzer
    
    def _get_intentional_design_detector(self):
        """Lazy load intentional design detector."""
        if self._intentional_design_detector is None:
            from .intentional_design_detector import IntentionalDesignDetector
            self._intentional_design_detector = IntentionalDesignDetector()
        return self._intentional_design_detector
        
    def analyze_contract_context(self, contract_code: str, contract_name: str = "Unknown"):
        """Analyze contract context before validating findings."""
        logger.info(f"Analyzing contract context for {contract_name}")
        
        # Analyze inheritance
        self.inheritance_verifier.analyze_contract(contract_code, contract_name)
        
        # Detect DeFi patterns
        self.pattern_recognizer.analyze_contract(contract_code)
        
        # Log detected patterns
        patterns = self.pattern_recognizer.patterns
        if patterns:
            logger.info(f"Detected {len(patterns)} DeFi patterns:")
            for p in patterns:
                logger.info(f"  - {p.pattern_type.value} (confidence: {p.confidence:.0%})")
        
        # NEW: Analyze modifiers in the contract
        try:
            modifier_analyzer = self._get_modifier_analyzer()
            modifier_defs = modifier_analyzer.analyze_contract(contract_code)
            if modifier_defs:
                logger.info(f"Detected {len(modifier_defs)} custom modifiers:")
                for name, mod_def in modifier_defs.items():
                    validation_info = []
                    if mod_def.is_access_control:
                        validation_info.append("access_control")
                    if mod_def.validated_params:
                        validation_info.append(f"validates: {', '.join(mod_def.validated_params)}")
                    if validation_info:
                        logger.info(f"  - {name}: {', '.join(validation_info)}")
        except Exception as e:
            logger.debug(f"Modifier analysis failed (non-critical): {e}")
        
        self.contract_analyzed = True
        self.contract_code = contract_code
        self.contract_name = contract_name
    
    def validate_finding(self, finding: Dict[str, Any]) -> EnhancedValidationResult:
        """
        Validate a single finding with multiple strategies.
        
        Args:
            finding: Vulnerability finding to validate
        
        Returns:
            EnhancedValidationResult with adjusted severity and reasoning
        """
        if not self.contract_analyzed:
            logger.warning("Contract context not analyzed, validation may be incomplete")
        
        reasoning = []
        is_false_positive = False
        adjusted_severity = None
        confidence_adjustment = 0.0
        recommendations = []
        
        vuln_type = finding.get('vulnerability_type', '')
        severity = finding.get('severity', 'unknown')
        line_num = finding.get('line', 0)
        description = finding.get('description', '')
        
        # === STRATEGY 1: Control Flow Guard Detection ===
        guard_result = self._check_guards(finding, line_num)
        if guard_result:
            reasoning.extend(guard_result['reasoning'])
            if guard_result['is_protected']:
                is_false_positive = True
                recommendations.append("Finding is protected by guards - not exploitable")
        
        # === STRATEGY 2: Inheritance Verification ===
        inheritance_result = self._verify_inheritance_claims(finding, description)
        if inheritance_result:
            reasoning.extend(inheritance_result['reasoning'])
            if inheritance_result['has_false_claim']:
                is_false_positive = True
                adjusted_severity = 'informational'
                recommendations.append("Contains false claims about contract inheritance")
        
        # === STRATEGY 3: DeFi Pattern Recognition ===
        pattern_result = self._check_defi_patterns(finding, vuln_type)
        if pattern_result:
            reasoning.extend(pattern_result['reasoning'])
            if pattern_result['is_expected_behavior']:
                # Not necessarily false positive, but reduce severity
                adjusted_severity = self._reduce_severity(severity)
                confidence_adjustment = -0.3
                recommendations.append(f"This is expected behavior for {pattern_result['pattern_name']} pattern")
        
        # === STRATEGY 4: Severity Calibration ===
        calibration_result = self._calibrate_severity(finding, vuln_type, severity)
        if calibration_result:
            reasoning.extend(calibration_result['reasoning'])
            if calibration_result['should_adjust']:
                adjusted_severity = calibration_result['new_severity']
                confidence_adjustment += calibration_result['confidence_adj']
                recommendations.extend(calibration_result['recommendations'])
        
        # === STRATEGY 5: Impact Quantification ===
        impact_result = self._quantify_impact(finding)
        if impact_result:
            reasoning.extend(impact_result['reasoning'])
            if impact_result['has_no_impact']:
                is_false_positive = True
                recommendations.append("No realistic attack path or impact identified")
        
        # === STRATEGY 6: Modifier-Based Validation (NEW) ===
        modifier_result = self._check_modifier_validations(finding, line_num, description)
        if modifier_result:
            reasoning.extend(modifier_result['reasoning'])
            if modifier_result['is_validated']:
                is_false_positive = True
                recommendations.append(f"Parameter validated by modifier: {modifier_result['modifier']}")
        
        # === STRATEGY 7: Intentional Design Detection (NEW) ===
        design_result = self._check_intentional_design(finding, line_num, description)
        if design_result:
            reasoning.extend(design_result['reasoning'])
            if design_result['is_intentional']:
                is_false_positive = True
                recommendations.append(f"Intentional design: {design_result['pattern']}")
        
        return EnhancedValidationResult(
            is_false_positive=is_false_positive,
            original_severity=severity,
            adjusted_severity=adjusted_severity,
            confidence_adjustment=confidence_adjustment,
            reasoning=reasoning,
            recommendations=recommendations
        )
    
    def _check_guards(self, finding: Dict[str, Any], line_num: int) -> Optional[Dict[str, Any]]:
        """Check if finding is protected by guards."""
        if not hasattr(self, 'contract_code'):
            return None
        
        # Extract function containing this line
        function_code = self._extract_function_at_line(line_num)
        if not function_code:
            return None
        
        # Analyze guards
        self.guard_detector.analyze_function(function_code['code'], function_code['start_line'])
        
        # Check if line is protected
        is_protected, guards = self.guard_detector.is_line_protected(line_num)
        
        if is_protected:
            timing_guards = [g for g in guards if g.guard_type == 'timing']
            if timing_guards:
                return {
                    'is_protected': True,
                    'reasoning': [
                        f"Line {line_num} is protected by timing constraints",
                        f"Guard at line {timing_guards[0].line_number}: {timing_guards[0].condition}",
                        "Code path is only reachable under specific time conditions"
                    ]
                }
            else:
                return {
                    'is_protected': True,
                    'reasoning': [
                        f"Line {line_num} is protected by {len(guards)} guard(s)",
                        self.guard_detector.explain_protection(line_num)
                    ]
                }
        
        return None
    
    def _verify_inheritance_claims(self, finding: Dict[str, Any], description: str) -> Optional[Dict[str, Any]]:
        """Verify any inheritance claims made in the finding."""
        # Look for inheritance claims in description
        inheritance_keywords = ['inherits', 'inherited', 'extends', 'derived from']
        
        if not any(kw in description.lower() for kw in inheritance_keywords):
            return None
        
        # Common false claims
        false_claims = []
        
        # Check for ReentrancyGuard claim
        if 'reentrancyguard' in description.lower():
            inherits = self.inheritance_verifier.inherits_from(self.contract_name, 'ReentrancyGuard')
            if not inherits:
                false_claims.append("Claims contract inherits ReentrancyGuard but it doesn't")
        
        if false_claims:
            return {
                'has_false_claim': True,
                'reasoning': [
                    "Finding contains factually incorrect information about inheritance",
                    *false_claims,
                    self.inheritance_verifier.get_inheritance_summary(self.contract_name)
                ]
            }
        
        return None
    
    def _check_defi_patterns(self, finding: Dict[str, Any], vuln_type: str) -> Optional[Dict[str, Any]]:
        """Check if vulnerability is actually expected behavior for a DeFi pattern."""
        # Check if this vuln type should be downgraded given detected patterns
        if self.pattern_recognizer.should_reduce_severity(vuln_type):
            # Find which pattern applies
            applicable_pattern = None
            for pattern in self.pattern_recognizer.patterns:
                if pattern.pattern_type == PatternType.LINEAR_VESTING and 'overwrite' in vuln_type.lower():
                    applicable_pattern = pattern
                    break
                elif pattern.pattern_type == PatternType.SHARE_CALCULATION and ('division' in vuln_type.lower() or 'precision' in vuln_type.lower()):
                    applicable_pattern = pattern
                    break
            
            if applicable_pattern:
                return {
                    'is_expected_behavior': True,
                    'pattern_name': applicable_pattern.pattern_type.value,
                    'reasoning': [
                        f"This behavior is expected for {applicable_pattern.pattern_type.value} pattern",
                        applicable_pattern.description,
                        f"Similar implementations: {', '.join(applicable_pattern.example_protocols[:3])}"
                    ]
                }
        
        return None
    
    def _calibrate_severity(self, finding: Dict[str, Any], vuln_type: str, severity: str) -> Optional[Dict[str, Any]]:
        """Calibrate severity based on common Solidity patterns."""
        # Integer division precision loss
        if 'division' in vuln_type.lower() or 'precision' in vuln_type.lower() or 'rounding' in vuln_type.lower():
            if severity in ['high', 'critical']:
                return {
                    'should_adjust': True,
                    'new_severity': 'medium',
                    'confidence_adj': -0.2,
                    'reasoning': [
                        "Integer division precision loss is ubiquitous in Solidity",
                        "Standard in all DeFi protocols (Aave, Uniswap, Compound)",
                        "Usually amounts to dust (< 1 wei) per transaction",
                        "Only exploitable if precision loss compounds significantly"
                    ],
                    'recommendations': [
                        "Calculate actual exploitable amount",
                        "Compare to similar protocols",
                        "Check if precision loss is bounded"
                    ]
                }
        
        # Permissionless functions (may be intentional)
        if 'permissionless' in vuln_type.lower() or 'access control' in vuln_type.lower():
            description = finding.get('description', '')
            if 'anyone can call' in description.lower() and 'notify' in description.lower():
                return {
                    'should_adjust': True,
                    'new_severity': 'low',
                    'confidence_adj': -0.2,
                    'reasoning': [
                        "Permissionless notify/update functions are sometimes intentional",
                        "Check if caller can extract value from calling this",
                        "Temporary balance manipulation may not enable theft"
                    ],
                    'recommendations': [
                        "Verify if there's a profit path for attacker",
                        "Check if function can be griefed or DoS'd"
                    ]
                }
        
        return None
    
    def _quantify_impact(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Try to quantify the actual impact of the vulnerability."""
        description = finding.get('description', '').lower()
        
        # Check for vague impact statements
        vague_impacts = ['may lead to', 'could result in', 'potentially', 'might allow']
        has_vague_impact = any(phrase in description for phrase in vague_impacts)
        
        # Check for concrete impact statements
        concrete_impacts = ['attacker steals', 'drain', 'loss of', 'tokens are lost', 'funds are']
        has_concrete_impact = any(phrase in description for phrase in concrete_impacts)
        
        # Check for profit path
        has_profit_path = any(word in description for word in ['profit', 'gain', 'steal', 'drain', 'extract'])
        
        if has_vague_impact and not (has_concrete_impact or has_profit_path):
            return {
                'has_no_impact': True,
                'reasoning': [
                    "Finding describes only theoretical risk with no concrete impact",
                    "No clear profit path or loss mechanism identified",
                    "May be a code quality issue rather than vulnerability"
                ]
            }
        
        return None
    
    def _check_modifier_validations(
        self, 
        finding: Dict[str, Any], 
        line_num: int,
        description: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if finding is about a parameter validated by modifiers.
        
        This addresses false positives like:
        - "unlockToken lacks validation" when onlyRegisteredToken validates it
        - "deregisterToken missing validation" when modifier checks it
        """
        if not hasattr(self, 'contract_code'):
            return None
        
        # Check if this is a validation-related finding
        validation_keywords = [
            'lacks validation', 'missing validation', 'no validation',
            'unvalidated', 'without validation', 'input validation',
            'parameter validation', 'address validation'
        ]
        
        is_validation_finding = any(kw in description.lower() for kw in validation_keywords)
        if not is_validation_finding:
            return None
        
        try:
            # Extract the function containing this line
            function_code = self._extract_function_at_line(line_num)
            if not function_code:
                return None
            
            modifier_analyzer = self._get_modifier_analyzer()
            
            # Ensure contract is analyzed
            if not modifier_analyzer.modifier_definitions:
                modifier_analyzer.analyze_contract(self.contract_code)
            
            # Get modifiers on this function
            usages = modifier_analyzer.get_function_modifier_usages(function_code['code'])
            
            if not usages:
                return None
            
            # Check each modifier for validation
            for usage in usages:
                if usage.modifier_name in modifier_analyzer.modifier_definitions:
                    mod_def = modifier_analyzer.modifier_definitions[usage.modifier_name]
                    
                    # If modifier validates parameters, it's likely a false positive
                    if mod_def.validated_params:
                        return {
                            'is_validated': True,
                            'modifier': usage.modifier_name,
                            'validated_params': list(mod_def.validated_params),
                            'reasoning': [
                                f"Function has modifier '{usage.modifier_name}' that validates parameters",
                                f"Modifier validates: {', '.join(mod_def.validated_params)}",
                                "The 'missing validation' finding is a false positive"
                            ]
                        }
            
            return None
            
        except Exception as e:
            logger.debug(f"Modifier validation check failed: {e}")
            return None
    
    def _check_intentional_design(
        self, 
        finding: Dict[str, Any],
        line_num: int,
        description: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if finding is about intentionally designed behavior.
        
        This addresses false positives like:
        - "chargeWithoutEvent lacks access control" when it's intentionally permissionless
        - "anyone can call notify()" when it's a permissionless sync function
        """
        if not hasattr(self, 'contract_code'):
            return None
        
        # Check if this might be about missing access control or similar
        design_keywords = [
            'lacks access control', 'missing access control', 'anyone can call',
            'permissionless', 'no authorization', 'public function',
            'without event', 'no event'
        ]
        
        is_design_finding = any(kw in description.lower() for kw in design_keywords)
        if not is_design_finding:
            return None
        
        try:
            # Extract the function containing this line
            function_code = self._extract_function_at_line(line_num)
            if not function_code:
                return None
            
            detector = self._get_intentional_design_detector()
            
            # Get surrounding comments
            surrounding_comments = detector.get_function_intent_context(
                self.contract_code, 
                function_code['start_line']
            )
            
            # Analyze for intentional design
            result = detector.analyze_function(
                function_code['code'],
                surrounding_comments=surrounding_comments
            )
            
            if result.is_intentional:
                return {
                    'is_intentional': True,
                    'pattern': result.pattern.name if result.pattern else 'comment_indicated',
                    'confidence': result.confidence,
                    'reasoning': [
                        result.reasoning,
                        f"Confidence: {result.confidence:.0%}",
                        "This behavior is intentional, not a vulnerability"
                    ]
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Intentional design check failed: {e}")
            return None
    
    def _reduce_severity(self, severity: str) -> str:
        """Reduce severity by one level."""
        severity_order = ['informational', 'low', 'medium', 'high', 'critical']
        try:
            idx = severity_order.index(severity.lower())
            if idx > 0:
                return severity_order[idx - 1]
        except (ValueError, IndexError):
            pass
        return severity
    
    def _extract_function_at_line(self, line_num: int) -> Optional[Dict[str, Any]]:
        """Extract function code containing a specific line."""
        if not hasattr(self, 'contract_code'):
            return None
        
        lines = self.contract_code.split('\n')
        
        # Find function start
        func_start = None
        for i in range(line_num - 1, -1, -1):
            if i < len(lines) and 'function ' in lines[i]:
                func_start = i + 1  # Convert to 1-based
                break
        
        if func_start is None:
            return None
        
        # Find function end (closing brace at same indentation)
        func_end = line_num
        for i in range(line_num, min(len(lines), line_num + 100)):
            if i < len(lines) and '}' in lines[i]:
                func_end = i + 1
                break
        
        function_code = '\n'.join(lines[func_start-1:func_end])
        
        return {
            'code': function_code,
            'start_line': func_start,
            'end_line': func_end
        }


def test_enhanced_filter():
    """Test the enhanced filter with Cap contracts example."""
    
    # Sample contract code
    contract_code = '''
contract StakedCap is UUPSUpgradeable, ERC4626Upgradeable, Access {
    function notify() external {
        StakedCapStorage storage $ = getStakedCapStorage();
        if ($.lastNotify + $.lockDuration > block.timestamp) revert StillVesting();
        
        uint256 total = IERC20(asset()).balanceOf(address(this));
        if (total > $.storedTotal) {
            uint256 diff = total - $.storedTotal;
            $.totalLocked = diff;  // Line 57
            $.storedTotal = total;
            $.lastNotify = block.timestamp;
        }
    }
    
    function lockedProfit() public view returns (uint256 locked) {
        StakedCapStorage storage $ = getStakedCapStorage();
        uint256 elapsed = block.timestamp - $.lastNotify;
        uint256 remaining = elapsed < $.lockDuration ? $.lockDuration - elapsed : 0;
        locked = $.totalLocked * remaining / $.lockDuration;  // Line 69
    }
}
    '''
    
    # Test findings
    findings = [
        {
            'vulnerability_type': 'state_variable_overwrite',
            'severity': 'high',
            'line': 57,
            'description': 'totalLocked is overwritten instead of incremented, allowing attacker to prematurely unlock vesting'
        },
        {
            'vulnerability_type': 'integer_division_precision_loss',
            'severity': 'medium',
            'line': 69,
            'description': 'Integer division may lead to precision loss in lockedProfit calculation'
        },
        {
            'vulnerability_type': 'reentrancy',
            'severity': 'high',
            'line': 49,
            'description': 'Contract inherits ReentrancyGuardUpgradeable but notify() function does not use nonReentrant modifier'
        }
    ]
    
    # Initialize filter
    filter = EnhancedFalsePositiveFilter()
    filter.analyze_contract_context(contract_code, "StakedCap")
    
    print("=== Enhanced False Positive Filter Results ===\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"Finding {i}: {finding['vulnerability_type']}")
        print(f"Original Severity: {finding['severity']}")
        
        result = filter.validate_finding(finding)
        
        print(f"Is False Positive: {result.is_false_positive}")
        if result.adjusted_severity:
            print(f"Adjusted Severity: {result.original_severity} → {result.adjusted_severity}")
        if result.confidence_adjustment:
            print(f"Confidence Adjustment: {result.confidence_adjustment:+.0%}")
        
        print("\nReasoning:")
        for reason in result.reasoning:
            print(f"  • {reason}")
        
        if result.recommendations:
            print("\nRecommendations:")
            for rec in result.recommendations:
                print(f"  → {rec}")
        
        print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    test_enhanced_filter()

