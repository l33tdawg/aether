"""
Architectural Pattern Recognizer for DeFi Protocols
Recognizes common DeFi patterns to reduce false positives in vulnerability detection.
"""

import re
import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

@dataclass
class DeFiPattern:
    name: str
    description: str
    contracts: List[str]
    trust_relationships: Dict[str, List[str]]
    validation_rules: Dict[str, Any]

@dataclass
class ValidationRule:
    description: str
    reason: str
    vulnerability_patterns: List[str]  # What vuln types this rule applies to
    code_patterns: Optional[List[str]] = None  # Regex patterns to match in code
    function_patterns: Optional[List[str]] = None  # Function name patterns

class ArchitecturalPatternRecognizer:
    """Recognizes DeFi architectural patterns to improve vulnerability analysis."""

    def __init__(self, patterns_file: Optional[str] = None):
        self.patterns_file = patterns_file or self._get_default_patterns_file()
        self.patterns = self._load_patterns()
        self.validation_rules = self._load_validation_rules()

    def _get_default_patterns_file(self) -> str:
        """Get the default patterns configuration file path."""
        return os.path.join(os.path.dirname(__file__), 'config', 'architectural_patterns.json')

    def _load_patterns(self) -> Dict[str, DeFiPattern]:
        """Load patterns from configuration file."""
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, 'r') as f:
                    data = json.load(f)

                patterns = {}
                for name, pattern_data in data.items():
                    patterns[name] = DeFiPattern(
                        name=name,
                        description=pattern_data['description'],
                        contracts=pattern_data['contracts'],
                        trust_relationships=pattern_data['trust_relationships'],
                        validation_rules=pattern_data['validation_rules']
                    )
                return patterns
            except Exception as e:
                print(f"Warning: Could not load patterns file {self.patterns_file}: {e}")
                return self._get_default_patterns()
        else:
            return self._get_default_patterns()

    def _get_default_patterns(self) -> Dict[str, DeFiPattern]:
        """Get default hardcoded patterns as fallback."""
        return {
            'vault_manager_separation': DeFiPattern(
                name='vault_manager_separation',
                description='ERC-7540 style async vaults with separate manager contracts',
                contracts=['*Vault*', '*Manager*', '*RequestManager*'],
                trust_relationships={
                    'vault': ['manager', 'request_manager'],
                    'manager': ['vault', 'escrow', 'registry'],
                    'request_manager': ['vault', 'manager']
                },
                validation_rules=['external_calls_to_manager', 'claim_functions']
            )
        }

    def _load_validation_rules(self) -> Dict[str, ValidationRule]:
        """Load validation rules from configuration."""
        rules_file = self.patterns_file.replace('architectural_patterns.json', 'validation_rules.json')
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    data = json.load(f)

                rules = {}
                for name, rule_data in data.items():
                    rules[name] = ValidationRule(
                        description=rule_data['description'],
                        reason=rule_data['reason'],
                        vulnerability_patterns=rule_data['vulnerability_patterns'],
                        code_patterns=rule_data.get('code_patterns'),
                        function_patterns=rule_data.get('function_patterns')
                    )
                return rules
            except Exception as e:
                print(f"Warning: Could not load validation rules file {rules_file}: {e}")

        return self._get_default_validation_rules()

    def _get_default_validation_rules(self) -> Dict[str, ValidationRule]:
        """Get default validation rules."""
        return {
            'external_calls_to_manager': ValidationRule(
                description='Calls to manager contracts should not be flagged as unvalidated',
                reason='Manager contracts perform their own validation and return validated results',
                vulnerability_patterns=['external_call', 'unvalidated_call', 'unchecked_return'],
                code_patterns=[
                    r'asyncManager\(\)\.(deposit|mint|withdraw|redeem)',
                    r'manager\.(requestDeposit|requestRedeem|cancelDepositRequest|cancelRedeemRequest)',
                    r'asyncManager\(\)\.(claimCancelDepositRequest|claimCancelRedeemRequest)'
                ]
            ),
            'claim_functions': ValidationRule(
                description='Claim functions may delegate state changes to manager',
                reason='Manager handles the actual claiming logic and state updates',
                vulnerability_patterns=['claim_without_marking', 'state_change'],
                function_patterns=[
                    r'claimCancelDepositRequest',
                    r'claimCancelRedeemRequest'
                ]
            )
        }

    def detect_pattern(self, contract_files: List[Dict[str, Any]]) -> Optional[str]:
        """
        Detect which architectural pattern this protocol follows.
        Returns the pattern name if detected, None otherwise.
        """
        contract_names = [self._extract_contract_name(cf['path']) for cf in contract_files]

        for pattern_name, pattern in self.patterns.items():
            if self._matches_pattern(contract_names, pattern):
                return pattern_name

        return None

    def _matches_pattern(self, contract_names: List[str], pattern: DeFiPattern) -> bool:
        """Check if the contract names match the pattern."""
        matched_contracts = 0
        required_matches = max(1, len(pattern.contracts) // 2)  # Need at least half to match, minimum 1

        for contract_pattern in pattern.contracts:
            # Convert glob pattern to regex
            regex_pattern = contract_pattern.replace('*', '.*')
            if any(re.search(regex_pattern, name, re.IGNORECASE) for name in contract_names):
                matched_contracts += 1

        return matched_contracts >= required_matches

    def get_pattern_description(self, pattern_name: str) -> str:
        """Get description of detected pattern."""
        if pattern_name in self.patterns:
            return self.patterns[pattern_name].description
        return "Unknown pattern"

    def should_skip_vulnerability(self, vulnerability_type: str, context: Dict[str, Any],
                                pattern_name: str) -> Tuple[bool, str]:
        """
        Determine if a vulnerability should be skipped based on architectural pattern.
        Returns (should_skip, reason)
        """
        if pattern_name not in self.patterns:
            return False, ""

        pattern = self.patterns[pattern_name]

        # Check validation rules for this pattern
        for rule_name in pattern.validation_rules:
            if rule_name in self.validation_rules:
                rule = self.validation_rules[rule_name]
                if self._vulnerability_matches_rule(vulnerability_type, context, rule):
                    return True, rule.reason

        return False, ""

    def _vulnerability_matches_rule(self, vuln_type: str, context: Dict[str, Any], rule: ValidationRule) -> bool:
        """Check if vulnerability matches a validation rule."""
        code_snippet = context.get('code_snippet', '')
        function_name = context.get('function_name', '')

        # Check if vulnerability type matches any of the rule's patterns
        vuln_type_lower = vuln_type.lower()
        if not any(pattern in vuln_type_lower for pattern in rule.vulnerability_patterns):
            return False

        # Check code patterns
        if rule.code_patterns:
            for pattern in rule.code_patterns:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    return True

        # Check function name patterns
        if rule.function_patterns:
            for pattern in rule.function_patterns:
                if re.search(pattern, function_name, re.IGNORECASE):
                    return True

        return False

    def _extract_contract_name(self, file_path: str) -> str:
        """Extract contract name from file path."""
        import os
        filename = os.path.basename(file_path)
        return filename.replace('.sol', '')

    def get_trust_relationships(self, pattern_name: str) -> Dict[str, List[str]]:
        """Get trust relationships for a pattern."""
        if pattern_name in self.patterns:
            return self.patterns[pattern_name].trust_relationships
        return {}

    def is_trusted_call(self, caller_contract: str, callee_contract: str, pattern_name: str) -> bool:
        """Check if call between contracts is trusted within the pattern."""
        if pattern_name not in self.patterns:
            return False

        trust_relationships = self.patterns[pattern_name].trust_relationships

        # Normalize contract names
        caller_type = self._classify_contract(caller_contract, pattern_name)
        callee_type = self._classify_contract(callee_contract, pattern_name)

        if caller_type in trust_relationships:
            return callee_type in trust_relationships[caller_type]

        return False

    def _classify_contract(self, contract_name: str, pattern_name: str) -> str:
        """Classify contract type within pattern."""
        pattern = self.patterns.get(pattern_name)
        if not pattern:
            return 'unknown'

        # Simple classification based on naming
        if 'vault' in contract_name.lower():
            return 'vault'
        elif 'manager' in contract_name.lower():
            return 'manager'
        elif 'hub' in contract_name.lower():
            return 'hub'
        elif 'spoke' in contract_name.lower():
            return 'spoke'
        elif 'token' in contract_name.lower():
            return 'token'
        elif 'hook' in contract_name.lower():
            return 'hook'
        elif 'escrow' in contract_name.lower():
            return 'escrow'

        return 'unknown'
