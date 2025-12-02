"""
Intentional Design Detector

Detects functions and patterns that are intentionally designed without 
certain checks or controls. This helps reduce false positives by recognizing
when "missing" functionality is actually by design.

Key improvements:
1. Function naming conventions (chargeWithoutEvent, etc.)
2. Comment-based intent detection
3. Bridge/DeFi liquidity patterns
4. Permissionless update patterns
"""

import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum


class IntentionalPatternType(Enum):
    """Types of intentional design patterns."""
    NO_EVENT = "no_event"                    # Intentionally no event emission
    PERMISSIONLESS = "permissionless"         # Intentionally callable by anyone
    LIQUIDITY_DEPOSIT = "liquidity_deposit"   # Bridge/vault liquidity functions
    STATE_SYNC = "state_sync"                 # Permissionless state update triggers
    FALLBACK_RECEIVE = "fallback_receive"     # ETH receive functions
    SIMPLE_GETTER = "simple_getter"           # View functions returning data


@dataclass
class IntentionalPattern:
    """Represents an intentional design pattern."""
    name: str
    pattern_type: IntentionalPatternType
    regex_pattern: str
    description: str
    typically_missing: List[str]  # What's typically "missing" in this pattern
    confidence: float
    requires_comment: bool = False  # Whether comment confirmation is needed


@dataclass
class IntentionalDesignResult:
    """Result of intentional design analysis."""
    is_intentional: bool
    pattern: Optional[IntentionalPattern]
    matched_patterns: List[IntentionalPattern]
    confidence: float
    reasoning: str
    comment_context: Optional[str]


class IntentionalDesignDetector:
    """Detects functions that are intentionally designed without certain checks."""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.comment_intent_phrases = self._initialize_intent_phrases()
    
    def _initialize_patterns(self) -> List[IntentionalPattern]:
        """Initialize intentional design patterns."""
        return [
            # Functions explicitly named "WithoutEvent" or similar
            IntentionalPattern(
                name='no_event_function',
                pattern_type=IntentionalPatternType.NO_EVENT,
                regex_pattern=r'function\s+\w*[Ww]ithout[Ee]vent\s*\(',
                description='Function explicitly designed without events',
                typically_missing=['event_emission'],
                confidence=0.95
            ),
            
            # Bridge/vault charge functions for adding liquidity
            IntentionalPattern(
                name='charge_liquidity_function',
                pattern_type=IntentionalPatternType.LIQUIDITY_DEPOSIT,
                regex_pattern=r'function\s+charge\w*\s*\(\s*\)\s*(?:external|public)\s*payable',
                description='Bridge/vault charge function for adding liquidity',
                typically_missing=['access_control', 'return_value', 'event_emission'],
                confidence=0.90
            ),
            
            # Permissionless notify/poke/sync functions
            IntentionalPattern(
                name='permissionless_sync',
                pattern_type=IntentionalPatternType.STATE_SYNC,
                regex_pattern=r'function\s+(notify|poke|sync|accrue|update|refresh|rebalance)\s*\(',
                description='Permissionless state synchronization function',
                typically_missing=['access_control'],
                confidence=0.85
            ),
            
            # receive() and fallback() functions
            IntentionalPattern(
                name='receive_fallback',
                pattern_type=IntentionalPatternType.FALLBACK_RECEIVE,
                regex_pattern=r'(receive|fallback)\s*\(\s*\)\s*external\s*payable',
                description='ETH receive/fallback function - intentionally permissionless',
                typically_missing=['access_control', 'validation'],
                confidence=0.95
            ),
            
            # Simple deposit functions without complex logic
            IntentionalPattern(
                name='simple_deposit',
                pattern_type=IntentionalPatternType.LIQUIDITY_DEPOSIT,
                regex_pattern=r'function\s+(deposit|donate|contribute|fund)\s*\(\s*\)\s*(?:external|public)\s*payable\s*\{[^}]{0,100}\}',
                description='Simple deposit function for adding funds',
                typically_missing=['access_control'],
                confidence=0.80
            ),
            
            # View/pure functions (getters)
            IntentionalPattern(
                name='getter_function',
                pattern_type=IntentionalPatternType.SIMPLE_GETTER,
                regex_pattern=r'function\s+(?:get|is|has|can|should|check)\w*\s*\([^)]*\)\s*(?:external|public|internal)?\s*(?:view|pure)',
                description='Getter function - returns data without validation requirement',
                typically_missing=['input_validation', 'access_control'],
                confidence=0.75
            ),
            
            # Keeper/bot callable functions
            IntentionalPattern(
                name='keeper_function',
                pattern_type=IntentionalPatternType.PERMISSIONLESS,
                regex_pattern=r'function\s+(harvest|compound|claim|distribute|execute|perform|run)\w*\s*\(',
                description='Keeper/bot callable function - often permissionless by design',
                typically_missing=['access_control'],
                confidence=0.70,
                requires_comment=True  # Need comment confirmation for lower confidence
            ),
        ]
    
    def _initialize_intent_phrases(self) -> Dict[str, List[str]]:
        """Initialize phrases that indicate intentional design."""
        return {
            'permissionless': [
                'anyone can call',
                'permissionless',
                'callable by anyone',
                'no access control',
                'intentionally public',
                'by design',
                'keeper can call',
                'bot can call',
            ],
            'no_event': [
                'without event',
                'no event',
                'skip event',
                'silent',
            ],
            'liquidity': [
                'for increasing',
                'add liquidity',
                'charge',
                'top up',
                'fund the contract',
                'withdrawal limit',
            ],
            'intentional': [
                'intentionally',
                'by design',
                'on purpose',
                'deliberately',
                'this is expected',
                'meant to be',
            ],
        }
    
    def analyze_function(
        self,
        function_code: str,
        function_name: str = "",
        surrounding_comments: str = ""
    ) -> IntentionalDesignResult:
        """
        Analyze a function to determine if missing checks are intentional.
        
        Args:
            function_code: The full function code including signature
            function_name: Name of the function (optional, extracted if not provided)
            surrounding_comments: Comments before/within the function
        
        Returns:
            IntentionalDesignResult with analysis
        """
        matched_patterns = []
        best_pattern = None
        best_confidence = 0.0
        
        # Extract function name if not provided
        if not function_name:
            name_match = re.search(r'function\s+(\w+)', function_code)
            if name_match:
                function_name = name_match.group(1)
        
        # Check each pattern
        for pattern in self.patterns:
            if re.search(pattern.regex_pattern, function_code, re.IGNORECASE | re.DOTALL):
                # Pattern matched
                confidence = pattern.confidence
                
                # Adjust confidence based on comment context
                if pattern.requires_comment:
                    if self._has_intent_comment(surrounding_comments, pattern.pattern_type):
                        confidence += 0.15
                    else:
                        confidence -= 0.20
                
                # Boost confidence if comment confirms intent
                if self._has_intent_comment(surrounding_comments, pattern.pattern_type):
                    confidence = min(1.0, confidence + 0.10)
                
                matched_patterns.append(pattern)
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_pattern = pattern
        
        # Also check for general intentional design comments
        if not matched_patterns:
            general_confidence = self._check_general_intent_comments(surrounding_comments)
            if general_confidence > 0.5:
                best_confidence = general_confidence
        
        # Build reasoning
        reasoning = self._build_reasoning(
            matched_patterns, 
            best_pattern, 
            function_name,
            surrounding_comments
        )
        
        return IntentionalDesignResult(
            is_intentional=best_confidence >= 0.70,
            pattern=best_pattern,
            matched_patterns=matched_patterns,
            confidence=best_confidence,
            reasoning=reasoning,
            comment_context=surrounding_comments if surrounding_comments else None
        )
    
    def _has_intent_comment(
        self, 
        comments: str, 
        pattern_type: IntentionalPatternType
    ) -> bool:
        """Check if comments indicate intentional design for a pattern type."""
        if not comments:
            return False
        
        comments_lower = comments.lower()
        
        # Map pattern types to phrase categories
        type_to_phrases = {
            IntentionalPatternType.PERMISSIONLESS: ['permissionless', 'intentional'],
            IntentionalPatternType.NO_EVENT: ['no_event', 'intentional'],
            IntentionalPatternType.LIQUIDITY_DEPOSIT: ['liquidity', 'intentional'],
            IntentionalPatternType.STATE_SYNC: ['permissionless', 'intentional'],
            IntentionalPatternType.FALLBACK_RECEIVE: ['intentional'],
            IntentionalPatternType.SIMPLE_GETTER: ['intentional'],
        }
        
        categories = type_to_phrases.get(pattern_type, ['intentional'])
        
        for category in categories:
            phrases = self.comment_intent_phrases.get(category, [])
            for phrase in phrases:
                if phrase in comments_lower:
                    return True
        
        return False
    
    def _check_general_intent_comments(self, comments: str) -> float:
        """Check comments for general intentional design indicators."""
        if not comments:
            return 0.0
        
        comments_lower = comments.lower()
        confidence = 0.0
        
        # Check all intent phrase categories
        for category, phrases in self.comment_intent_phrases.items():
            for phrase in phrases:
                if phrase in comments_lower:
                    confidence += 0.25
        
        return min(confidence, 0.90)
    
    def _build_reasoning(
        self,
        matched_patterns: List[IntentionalPattern],
        best_pattern: Optional[IntentionalPattern],
        function_name: str,
        comments: str
    ) -> str:
        """Build human-readable reasoning for the analysis."""
        if not matched_patterns:
            if comments:
                return f"No patterns matched, but comments may indicate intent"
            return f"Function '{function_name}' does not match known intentional design patterns"
        
        if best_pattern:
            reason = f"Function '{function_name}' matches '{best_pattern.name}' pattern: {best_pattern.description}"
            reason += f". Typically missing: {', '.join(best_pattern.typically_missing)}"
            return reason
        
        return f"Function '{function_name}' matches {len(matched_patterns)} intentional design patterns"
    
    def is_missing_check_intentional(
        self,
        function_code: str,
        missing_check: str,
        surrounding_comments: str = ""
    ) -> Tuple[bool, float, str]:
        """
        Check if a specific missing check is intentional.
        
        Args:
            function_code: The function code
            missing_check: Type of check that's missing (e.g., 'access_control', 'event_emission')
            surrounding_comments: Comments around the function
        
        Returns:
            (is_intentional, confidence, reasoning)
        """
        result = self.analyze_function(function_code, surrounding_comments=surrounding_comments)
        
        if not result.is_intentional:
            return False, 0.0, "No intentional design pattern detected"
        
        # Check if the missing check is in the typically_missing list for matched patterns
        for pattern in result.matched_patterns:
            if missing_check in pattern.typically_missing:
                return True, result.confidence, (
                    f"Missing '{missing_check}' is expected for '{pattern.name}' pattern: "
                    f"{pattern.description}"
                )
        
        # Check if comments explicitly mention the missing check
        if surrounding_comments:
            check_terms = {
                'access_control': ['permissionless', 'anyone can', 'no access control'],
                'event_emission': ['without event', 'no event', 'silent'],
                'input_validation': ['no validation', 'accepts any'],
                'return_value': ['no return', 'void'],
            }
            
            terms = check_terms.get(missing_check, [])
            comments_lower = surrounding_comments.lower()
            
            for term in terms:
                if term in comments_lower:
                    return True, 0.80, f"Comments indicate intentional missing '{missing_check}'"
        
        return False, 0.0, f"Missing '{missing_check}' not explained by detected patterns"
    
    def get_function_intent_context(self, contract_content: str, function_line: int) -> str:
        """Extract comments near a function that might explain design intent."""
        lines = contract_content.split('\n')
        
        # Get lines before the function (comments)
        comment_lines = []
        for i in range(max(0, function_line - 5), function_line):
            if i < len(lines):
                line = lines[i].strip()
                if line.startswith('//') or line.startswith('/*') or line.startswith('*'):
                    comment_lines.append(line)
                elif line and not line.startswith('function'):
                    # Non-comment, non-function line breaks the comment block
                    comment_lines = []
        
        # Also check for inline comments in the function
        func_start = function_line
        func_end = min(function_line + 20, len(lines))
        
        for i in range(func_start, func_end):
            if i < len(lines):
                line = lines[i]
                # Extract inline comments
                inline_match = re.search(r'//(.+)$', line)
                if inline_match:
                    comment_lines.append(inline_match.group(1).strip())
        
        return ' '.join(comment_lines)
    
    def should_suppress_finding(
        self,
        finding_type: str,
        function_code: str,
        surrounding_comments: str = ""
    ) -> Tuple[bool, str]:
        """
        Check if a specific finding type should be suppressed due to intentional design.
        
        Args:
            finding_type: Type of finding (e.g., 'missing_access_control', 'missing_validation')
            function_code: The function code
            surrounding_comments: Comments around the function
        
        Returns:
            (should_suppress, reason)
        """
        # Map finding types to check types
        finding_to_check = {
            'missing_access_control': 'access_control',
            'missing_input_validation': 'input_validation',
            'missing_event': 'event_emission',
            'permissionless_function': 'access_control',
            'anyone_can_call': 'access_control',
            'no_validation': 'input_validation',
            'missing_zero_check': 'input_validation',
        }
        
        check_type = finding_to_check.get(finding_type.lower())
        if not check_type:
            return False, "Unknown finding type"
        
        is_intentional, confidence, reason = self.is_missing_check_intentional(
            function_code, 
            check_type, 
            surrounding_comments
        )
        
        if is_intentional and confidence >= 0.70:
            return True, reason
        
        return False, reason

