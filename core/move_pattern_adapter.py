"""
Move Pattern Adapter

This module translates Move-specific vulnerability patterns to Solidity/EVM equivalents,
enabling the use of Move vulnerability database patterns for Solidity contract analysis.

Pattern Mappings:
- Move generic<T> validation → Solidity token address validation
- Move UID validation → Solidity address/identifier validation  
- Move assert!() → Solidity require()/revert()
- Move resource state → Solidity storage variables
- Move capability system → Solidity access control modifiers
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class MovePatternType(Enum):
    """Types of Move patterns"""
    GENERIC_VALIDATION = "generic_validation"
    UID_VALIDATION = "uid_validation"
    ASSERT_STATEMENT = "assert_statement"
    RESOURCE_STATE = "resource_state"
    CAPABILITY_CHECK = "capability_check"
    COIN_TYPE_CHECK = "coin_type_check"


@dataclass
class PatternMapping:
    """Mapping between Move and Solidity patterns"""
    move_pattern: str
    solidity_pattern: str
    pattern_type: str
    description: str
    confidence: float


class MovePatternAdapter:
    """Adapts Move vulnerability patterns to Solidity equivalents"""
    
    def __init__(self):
        self.pattern_mappings = self._initialize_pattern_mappings()
        self.syntax_translations = self._initialize_syntax_translations()
        self.concept_mappings = self._initialize_concept_mappings()
    
    def _initialize_pattern_mappings(self) -> List[PatternMapping]:
        """Initialize Move to Solidity pattern mappings"""
        return [
            PatternMapping(
                move_pattern=r'assert!\s*\(',
                solidity_pattern=r'require\s*\(',
                pattern_type='assert_statement',
                description='Move assert! maps to Solidity require',
                confidence=0.95
            ),
            PatternMapping(
                move_pattern=r'<(\w+)>',
                solidity_pattern=r'address\s+\1',
                pattern_type='generic_validation',
                description='Move generics map to Solidity address types',
                confidence=0.85
            ),
            PatternMapping(
                move_pattern=r'UID',
                solidity_pattern=r'uint256\s+id',
                pattern_type='uid_validation',
                description='Move UID maps to Solidity uint256 identifier',
                confidence=0.9
            ),
            PatternMapping(
                move_pattern=r'&mut\s+',
                solidity_pattern=r'storage\s+',
                pattern_type='resource_state',
                description='Move mutable reference maps to Solidity storage',
                confidence=0.8
            ),
            PatternMapping(
                move_pattern=r'has\s+key',
                solidity_pattern=r'mapping\s*\([^)]+\)',
                pattern_type='resource_state',
                description='Move resource with key maps to Solidity mapping',
                confidence=0.75
            )
        ]
    
    def _initialize_syntax_translations(self) -> Dict[str, str]:
        """Initialize syntax translations from Move to Solidity"""
        return {
            # Move → Solidity
            'assert!': 'require',
            'abort': 'revert',
            'move_to': 'storage assignment',
            'borrow_global': 'mapping access',
            'exists': 'mapping check',
            'vector': 'array',
            'Coin<T>': 'IERC20',
            'signer': 'msg.sender',
            '&signer': 'address',
            'acquires': 'reads storage',
            'public entry': 'external',
            'public fun': 'public function'
        }
    
    def _initialize_concept_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Initialize concept mappings between Move and Solidity"""
        return {
            'generic_type_validation': {
                'move': 'Checking CoinType matches expected type',
                'solidity': 'Checking token address matches expected address',
                'vulnerability': 'Missing token address validation',
                'detection_pattern': r'IERC20\s*\(\s*(\w+)\s*\)(?!.*?require\([^)]*\1)',
                'severity': 'critical'
            },
            'uid_validation': {
                'move': 'Checking UID matches expected object',
                'solidity': 'Checking ID matches expected entity',
                'vulnerability': 'Missing identifier validation',
                'detection_pattern': r'mapping\s*\([^)]+\)\s+\w+;\s*.*?(\w+)\s*=\s*\w+\[id\](?!.*?require)',
                'severity': 'high'
            },
            'capability_check': {
                'move': 'Verifying capability/permission to execute',
                'solidity': 'Checking access control modifiers',
                'vulnerability': 'Missing access control',
                'detection_pattern': r'function\s+\w+\s*\([^)]*\)\s*(public|external)(?!.*?(onlyOwner|onlyRole|require\([^)]*msg\.sender))',
                'severity': 'critical'
            },
            'resource_state_update': {
                'move': 'Updating resource state after operation',
                'solidity': 'Updating storage variables after operation',
                'vulnerability': 'Missing state update',
                'detection_pattern': r'function\s+\w+\s*\([^)]*\).*?external.*?\{(?!.*?(\w+State|\w+Balance)\s*=)',
                'severity': 'high'
            },
            'coin_type_mismatch': {
                'move': 'Using wrong Coin<T> type in operation',
                'solidity': 'Using wrong token address in operation',
                'vulnerability': 'Token type mismatch',
                'detection_pattern': r'transfer\s*\([^)]*tokenA[^)]*\).*?transfer\s*\([^)]*tokenB[^)]*\)',
                'severity': 'critical'
            }
        }
    
    def translate_move_vulnerability(self, move_vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Translate a Move vulnerability to Solidity equivalent"""
        description = move_vuln.get('description', '')
        
        # Apply concept mapping
        solidity_vuln = {
            'original_description': description,
            'adapted_description': self._adapt_description(description),
            'vulnerability_type': self._map_vulnerability_type(move_vuln.get('type', '')),
            'severity': move_vuln.get('severity', 'medium'),
            'confidence': 0.7,  # Lower confidence for adapted patterns
            'source': 'Move Vulnerability Database (Adapted)',
            'detection_patterns': []
        }
        
        # Find applicable Solidity patterns
        for concept_name, concept_data in self.concept_mappings.items():
            if self._description_matches_concept(description, concept_data):
                solidity_vuln['detection_patterns'].append({
                    'pattern': concept_data['detection_pattern'],
                    'description': concept_data['solidity'],
                    'severity': concept_data['severity']
                })
        
        return solidity_vuln
    
    def _adapt_description(self, move_description: str) -> str:
        """Adapt Move-specific description to Solidity context"""
        adapted = move_description
        
        # Apply syntax translations
        for move_syntax, solidity_syntax in self.syntax_translations.items():
            adapted = adapted.replace(move_syntax, solidity_syntax)
        
        # Replace Move-specific terms
        replacements = {
            'generic type': 'token address',
            'CoinType': 'token contract',
            'UID': 'identifier',
            'resource': 'storage state',
            'capability': 'access control',
            'signer': 'msg.sender',
            'module': 'contract',
            'entry function': 'external function',
            'public function': 'public function'
        }
        
        for move_term, solidity_term in replacements.items():
            # Case-insensitive replacement
            adapted = re.sub(f'\\b{move_term}\\b', solidity_term, adapted, flags=re.IGNORECASE)
        
        return adapted
    
    def _map_vulnerability_type(self, move_type: str) -> str:
        """Map Move vulnerability type to Solidity equivalent"""
        type_mappings = {
            'missing_generic_check': 'missing_token_validation',
            'missing_uid_validation': 'missing_identifier_validation',
            'capability_bypass': 'access_control_bypass',
            'resource_not_updated': 'state_not_updated',
            'coin_type_mismatch': 'token_address_mismatch',
            'assert_failure': 'require_failure',
            'abort_condition': 'revert_condition'
        }
        
        return type_mappings.get(move_type, move_type)
    
    def _description_matches_concept(self, description: str, concept_data: Dict[str, Any]) -> bool:
        """Check if description matches a concept"""
        move_concept = concept_data['move'].lower()
        description_lower = description.lower()
        
        # Check for key terms
        key_terms = move_concept.split()
        matches = sum(1 for term in key_terms if term in description_lower)
        
        return matches >= len(key_terms) // 2  # At least half the terms match
    
    def get_solidity_patterns_for_move_category(self, move_category: str) -> List[Dict[str, Any]]:
        """Get Solidity detection patterns for a Move vulnerability category"""
        patterns = []
        
        category_mappings = {
            'Input Validation': [
                {
                    'pattern': r'function\s+\w+\s*\([^)]*address\s+token[^)]*\)(?!.*?require\([^)]*token\s*!=\s*address\(0\)))',
                    'description': 'Missing token address validation (from Move generic validation)',
                    'severity': 'high'
                },
                {
                    'pattern': r'function\s+\w+\s*\([^)]*uint256\s+\w*[Ii]d\w*[^)]*\)(?!.*?require)',
                    'description': 'Missing ID validation (from Move UID validation)',
                    'severity': 'high'
                }
            ],
            'Business Logic': [
                {
                    'pattern': r'require\s*\(\s*!\s*(\w+)',
                    'description': 'Backwards validation logic (from Move assert patterns)',
                    'severity': 'high'
                },
                {
                    'pattern': r'(\w+)\s*==\s*\1',
                    'description': 'Self-comparison bug (from Move validation errors)',
                    'severity': 'critical'
                }
            ],
            'State Management': [
                {
                    'pattern': r'function\s+\w+\s*\([^)]*\).*?external.*?\{(?!.*?(\w+State|\w+Balance)\s*=)',
                    'description': 'Missing state update (from Move resource state)',
                    'severity': 'high'
                },
                {
                    'pattern': r'delete\s+\w+\[(\w+)\](?!.*?count\s*-=)',
                    'description': 'State deleted without updating count (from Move resource management)',
                    'severity': 'medium'
                }
            ],
            'Access Control': [
                {
                    'pattern': r'function\s+\w+\s*\([^)]*\)\s*external(?!.*?(onlyOwner|onlyRole|require\([^)]*msg\.sender))',
                    'description': 'Missing access control (from Move capability checks)',
                    'severity': 'critical'
                }
            ]
        }
        
        return category_mappings.get(move_category, [])
    
    def generate_detection_pattern(self, move_pattern_description: str) -> Optional[str]:
        """Generate a Solidity detection pattern from Move pattern description"""
        # Use simple heuristics to generate patterns
        if 'generic' in move_pattern_description.lower() or 'cointype' in move_pattern_description.lower():
            return r'IERC20\s*\(\s*(\w+)\s*\)(?!.*?require\([^)]*\1\s*!=\s*address\(0\)))'
        
        if 'uid' in move_pattern_description.lower() or 'id' in move_pattern_description.lower():
            return r'mapping\s*\([^)]+\)\s+\w+;.*?(\w+)\s*=\s*\w+\[id\](?!.*?require)'
        
        if 'assert' in move_pattern_description.lower():
            return r'require\s*\(\s*!\s*(\w+)'
        
        if 'capability' in move_pattern_description.lower():
            return r'function\s+\w+\s*\([^)]*\)\s*external(?!.*?only)'
        
        if 'resource' in move_pattern_description.lower() or 'state' in move_pattern_description.lower():
            return r'function\s+\w+\s*\([^)]*\).*?\{(?!.*?(\w+State|\w+Balance)\s*=)'
        
        return None
    
    def get_adaptation_summary(self) -> Dict[str, Any]:
        """Get summary of pattern adaptations"""
        return {
            'total_mappings': len(self.pattern_mappings),
            'syntax_translations': len(self.syntax_translations),
            'concept_mappings': len(self.concept_mappings),
            'supported_categories': list(self.concept_mappings.keys()),
            'mapping_details': [
                {
                    'move_pattern': m.move_pattern,
                    'solidity_pattern': m.solidity_pattern,
                    'type': m.pattern_type,
                    'confidence': m.confidence
                }
                for m in self.pattern_mappings
            ]
        }

