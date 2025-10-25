"""
Finding Deduplicator and Post-Processor

This module consolidates duplicate findings, calibrates severity levels,
and groups related vulnerabilities for cleaner reporting.
"""

from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import re


@dataclass
class Finding:
    """Standardized finding representation"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    file_path: str
    confidence: float
    code_snippet: str = ""
    recommendation: str = ""
    swc_id: str = ""
    category: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    
    def get_signature(self) -> str:
        """Get a signature for deduplication matching"""
        # Normalize line number to range (±5 lines)
        line_range = self.line_number // 5
        return f"{self.file_path}:{line_range}:{self.vulnerability_type}"
    
    def is_similar_to(self, other: 'Finding', line_tolerance: int = 5) -> bool:
        """Check if two findings are similar (likely duplicates)"""
        # Same file
        if self.file_path != other.file_path:
            return False
        
        # Related vulnerability types (check this first)
        if not self._are_related_types(self.vulnerability_type, other.vulnerability_type):
            return False
        
        # For initialization vulnerabilities, check if they reference the same function
        if self._is_init_vulnerability() and other._is_init_vulnerability():
            # Both are init vulnerabilities - check if same function mentioned
            if self._extract_function_name() == other._extract_function_name():
                # Same function, likely same bug from different detectors
                return True
        
        # For other types, use line number proximity
        if abs(self.line_number - other.line_number) <= line_tolerance:
            return True
        
        return False
    
    def _is_init_vulnerability(self) -> bool:
        """Check if this is an initialization-related vulnerability"""
        vuln_type_lower = self.vulnerability_type.lower()
        desc_lower = self.description.lower()
        
        # Check vulnerability type
        if 'init' in vuln_type_lower or 'initialization' in vuln_type_lower:
            return True
        
        # Check description for init-related content
        # Use more flexible matching (both "init" and "function" present)
        has_init_word = any(word in desc_lower for word in ['init', 'initialize', 'initializer'])
        has_function_word = 'function' in desc_lower or 'parameter' in desc_lower
        
        if has_init_word and has_function_word:
            return True
        
        # Also check for specific init patterns
        init_patterns = [
            '__isinit',
            'initialization',
            'initializer',
        ]
        
        return any(pattern in desc_lower for pattern in init_patterns)
    
    def _extract_function_name(self) -> str:
        """Extract function name from description"""
        # Look for common patterns like `init` or "init(" or init function
        import re
        patterns = [
            r'`(\w+)`\s+function',    # `init` function
            r'function\s+`?(\w+)`?',   # function init or function `init`
            r'(\w+)\s+function',       # init function
            r'function\s*\(\s*line\s+\d+\)',  # Look for line references
            r'the\s+`?(\w+)`?\s+parameter', # parameter name
        ]
        
        for pattern in patterns:
            match = re.search(pattern, self.description, re.IGNORECASE)
            if match and match.lastindex >= 1:
                func_name = match.group(1).lower()
                # Check if it's an init-related name
                if 'init' in func_name:
                    return func_name
        
        # Fallback: if description contains "init" and this is an init vulnerability
        if self._is_init_vulnerability():
            # Look for any init-related word
            init_words = ['init', 'initialize', 'setup', 'constructor']
            for word in init_words:
                if word in self.description.lower():
                    return word
        
        return ""
    
    def _are_related_types(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are related"""
        # Exact match
        if type1 == type2:
            return True
        
        # Related patterns
        related_groups = [
            {'unprotected_initialization', 'initialization_frontrun_risk', 
             'parameter_validation_issue', 'best_practice_violation'},
            {'precision_loss_division', 'rounding_error', 'precision_loss'},
            {'oracle_manipulation', 'on_chain_oracle_price_manipulation'},
            {'loop_gas_issue', 'unbounded_loop_dos', 'gas_optimization'},
            {'reentrancy', 'reentrancy_vulnerability', 'reentrancy_attack'},
        ]
        
        # Check if both types are in the same group
        for group in related_groups:
            if type1 in group and type2 in group:
                return True
        
        # Check for partial matches in type names
        type1_lower = type1.lower()
        type2_lower = type2.lower()
        
        # Extract key words
        key_words = ['init', 'reentrancy', 'oracle', 'precision', 
                     'loop', 'gas', 'access', 'validation']
        
        for word in key_words:
            if word in type1_lower and word in type2_lower:
                return True
        
        return False


class FindingDeduplicator:
    """Deduplicates and post-processes vulnerability findings"""
    
    def __init__(self):
        self.severity_hierarchy = ['critical', 'high', 'medium', 'low', 'informational']
    
    def process_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Main entry point for post-processing findings.
        
        Steps:
        1. Deduplicate similar findings
        2. Calibrate severity levels
        3. Group by root cause
        4. Enhance descriptions
        """
        if not findings:
            return []
        
        # Step 1: Deduplicate
        deduplicated = self.deduplicate_findings(findings)
        
        # Step 2: Calibrate severity
        calibrated = self.calibrate_severity(deduplicated)
        
        # Step 3: Enhance descriptions
        enhanced = self.enhance_descriptions(calibrated)
        
        # Step 4: Sort by severity and confidence
        sorted_findings = self.sort_findings(enhanced)
        
        return sorted_findings
    
    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate findings that represent the same vulnerability.
        Keep the highest confidence version with merged information.
        """
        if not findings:
            return []
        
        # Group similar findings
        groups = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # Start a new group
            group = [finding]
            processed.add(i)
            
            # Find all similar findings
            for j, other in enumerate(findings[i+1:], start=i+1):
                if j in processed:
                    continue
                
                if finding.is_similar_to(other):
                    group.append(other)
                    processed.add(j)
            
            groups.append(group)
        
        # Merge each group into a single finding
        deduplicated = []
        for group in groups:
            merged = self._merge_findings(group)
            deduplicated.append(merged)
        
        return deduplicated
    
    def _merge_findings(self, findings: List[Finding]) -> Finding:
        """
        Merge multiple findings into one, keeping the best information.
        """
        if len(findings) == 1:
            return findings[0]
        
        # Sort by confidence (highest first)
        sorted_findings = sorted(findings, key=lambda f: f.confidence, reverse=True)
        
        # Use the highest confidence finding as base
        merged = sorted_findings[0]
        
        # Collect all unique vulnerability types
        all_types = [f.vulnerability_type for f in sorted_findings]
        unique_types = list(dict.fromkeys(all_types))  # Preserve order, remove duplicates
        
        # If multiple types, use the most specific one or combine
        if len(unique_types) > 1:
            # Prefer more specific types
            merged.vulnerability_type = self._select_best_type(unique_types)
            
            # Add note about detection by multiple analyzers
            if 'detected_by' not in merged.context:
                merged.context['detected_by'] = unique_types
                merged.context['detection_confidence'] = 'high (multiple detectors agree)'
        
        # Merge descriptions if they provide different information
        descriptions = [f.description for f in sorted_findings]
        if len(set(descriptions)) > 1:
            # Combine unique parts
            merged.description = self._merge_descriptions(descriptions)
        
        # Use the most severe severity
        severities = [f.severity for f in sorted_findings]
        merged.severity = self._get_highest_severity(severities)
        
        # Use highest confidence
        merged.confidence = max(f.confidence for f in sorted_findings)
        
        # Merge recommendations
        recommendations = [f.recommendation for f in sorted_findings if f.recommendation]
        if recommendations:
            merged.recommendation = self._merge_recommendations(recommendations)
        
        return merged
    
    def _select_best_type(self, types: List[str]) -> str:
        """Select the most specific/appropriate vulnerability type"""
        # Preference order (more specific types)
        preference = [
            'initialization_frontrun_risk',
            'unprotected_initialization',
            'precision_loss_division',
            'oracle_manipulation',
            'unbounded_loop_dos',
            'reentrancy_vulnerability',
        ]
        
        for preferred_type in preference:
            if preferred_type in types:
                return preferred_type
        
        # If no preferred type, use the first one
        return types[0]
    
    def _merge_descriptions(self, descriptions: List[str]) -> str:
        """Merge descriptions intelligently"""
        if len(descriptions) == 1:
            return descriptions[0]
        
        # Use the longest description as base (usually most detailed)
        base = max(descriptions, key=len)
        
        # Add a note about multiple detection
        note = " [Note: This vulnerability was detected by multiple analyzers, increasing confidence in the finding.]"
        
        if note not in base:
            return base + note
        
        return base
    
    def _merge_recommendations(self, recommendations: List[str]) -> str:
        """Merge recommendations, removing duplicates"""
        unique_recs = list(dict.fromkeys(recommendations))
        
        if len(unique_recs) == 1:
            return unique_recs[0]
        
        # Combine multiple recommendations
        return " Additionally: ".join(unique_recs)
    
    def _get_highest_severity(self, severities: List[str]) -> str:
        """Get the highest severity from a list"""
        severity_order = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'informational': 4
        }
        
        # Normalize severity strings
        normalized = [s.lower() for s in severities]
        
        # Find highest severity
        highest = min(normalized, key=lambda s: severity_order.get(s, 999))
        
        return highest
    
    def calibrate_severity(self, findings: List[Finding]) -> List[Finding]:
        """
        Calibrate severity levels based on context and actual impact.
        """
        calibrated = []
        
        for finding in findings:
            # Check if severity needs adjustment
            adjusted = self._adjust_severity_by_context(finding)
            calibrated.append(adjusted)
        
        return calibrated
    
    def _adjust_severity_by_context(self, finding: Finding) -> Finding:
        """
        Adjust severity based on vulnerability context.
        """
        vuln_type = finding.vulnerability_type.lower()
        description = finding.description.lower()
        
        # Precision loss severity adjustment
        if 'precision' in vuln_type or 'rounding' in vuln_type:
            # Check if it's a severe case
            severe_indicators = [
                'total value of 0',
                '100% loss',
                'entire fractional component',
                'vesting',
                'fee accrual'
            ]
            
            is_severe = any(indicator in description for indicator in severe_indicators)
            
            if is_severe and finding.severity == 'high':
                # Keep HIGH severity
                finding.context['severity_justification'] = 'High impact on financial calculations'
            elif not is_severe and finding.severity == 'high':
                # Downgrade to MEDIUM for typical cases
                finding.severity = 'medium'
                finding.context['severity_adjustment'] = 'Downgraded from HIGH to MEDIUM based on typical impact'
        
        # Initialization vulnerabilities are always high/critical
        if 'init' in vuln_type and 'access' in description:
            if finding.severity not in ['critical', 'high']:
                finding.severity = 'high'
                finding.context['severity_adjustment'] = 'Elevated to HIGH due to initialization front-running risk'
        
        # Oracle manipulation depends on context
        if 'oracle' in vuln_type:
            if 'delegat' in description or 'handler' in description:
                # Architectural concern, not direct vulnerability
                if finding.severity == 'high':
                    finding.severity = 'medium'
                    finding.context['severity_adjustment'] = 'Architectural concern - depends on handler implementation'
        
        # Loop gas issues
        if 'loop' in vuln_type or 'gas' in vuln_type:
            if 'external call' in description and 'unbounded' in description:
                # High severity if unbounded with external calls
                if finding.severity != 'high':
                    finding.severity = 'high'
            elif 'admin' in description or 'owner' in description:
                # Lower severity if only admin can trigger
                if finding.severity == 'high':
                    finding.severity = 'medium'
                    finding.context['severity_adjustment'] = 'Admin/owner trusted - reduced to MEDIUM'
        
        return finding
    
    def enhance_descriptions(self, findings: List[Finding]) -> List[Finding]:
        """
        Enhance finding descriptions with additional context.
        """
        enhanced = []
        
        for finding in findings:
            # Add impact statement if missing
            if 'impact:' not in finding.description.lower():
                impact = self._generate_impact_statement(finding)
                if impact:
                    finding.description = f"{finding.description}\n\nImpact: {impact}"
            
            # Add exploitation difficulty assessment
            if 'exploitability' not in finding.context:
                finding.context['exploitability'] = self._assess_exploitability(finding)
            
            enhanced.append(finding)
        
        return enhanced
    
    def _generate_impact_statement(self, finding: Finding) -> str:
        """Generate an impact statement based on vulnerability type"""
        vuln_type = finding.vulnerability_type.lower()
        severity = finding.severity.lower()
        
        impact_templates = {
            'init': "Attacker can front-run initialization and set critical state variables, potentially compromising the entire contract.",
            'precision': "Financial calculations may be incorrect, leading to loss of funds for users or protocol.",
            'oracle': "Manipulated price data could result in incorrect valuations and potential protocol exploitation.",
            'loop': "Function may become unusable due to gas limits, causing denial of service.",
            'reentrancy': "Attacker can drain funds by exploiting state inconsistencies during external calls.",
        }
        
        for keyword, template in impact_templates.items():
            if keyword in vuln_type:
                return template
        
        return ""
    
    def _assess_exploitability(self, finding: Finding) -> str:
        """Assess how easy it is to exploit the vulnerability"""
        vuln_type = finding.vulnerability_type.lower()
        description = finding.description.lower()
        
        # Easy to exploit
        if 'external' in description and 'no access control' in description:
            return "High - publicly exploitable"
        
        if 'front-run' in description or 'frontrun' in description:
            return "Medium - requires front-running capability"
        
        # Requires specific conditions
        if 'admin' in description or 'owner' in description:
            return "Low - requires privileged access"
        
        # Complex exploitation
        if 'flash loan' in description or 'manipulation' in description:
            return "Medium - requires significant capital or complexity"
        
        return "Medium"
    
    def sort_findings(self, findings: List[Finding]) -> List[Finding]:
        """Sort findings by severity and confidence"""
        severity_order = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'informational': 4
        }
        
        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.severity.lower(), 999),
                -f.confidence,  # Higher confidence first
                f.line_number
            )
        )
    
    def generate_deduplication_report(self, original_count: int, deduplicated_count: int) -> Dict[str, Any]:
        """Generate a report on the deduplication process"""
        return {
            'original_findings': original_count,
            'deduplicated_findings': deduplicated_count,
            'duplicates_removed': original_count - deduplicated_count,
            'deduplication_rate': round((original_count - deduplicated_count) / original_count * 100, 1) if original_count > 0 else 0
        }

