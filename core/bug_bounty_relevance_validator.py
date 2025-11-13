#!/usr/bin/env python3
"""
Bug Bounty Relevance Validator

Filters vulnerabilities to only include findings that would be accepted
by bug bounty programs - i.e., exploitable vulnerabilities with real impact.

This validator ensures that flagged vulnerabilities:
1. Can actually be exploited (not just fail safely)
2. Cause real impact (fund loss, unauthorized access, etc.)
3. Are exploitable by external users (not admin-only)
4. Would qualify for bug bounty submission
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class BugBountyRelevance(Enum):
    """Bug bounty relevance levels."""
    ACCEPT = "accept"  # Definitely worth submitting
    REVIEW = "review"  # Borderline - needs manual review
    REJECT = "reject"  # Not suitable for bug bounty
    CODE_QUALITY = "code_quality"  # Code quality issue, not security


@dataclass
class BugBountyAssessment:
    """Assessment of bug bounty relevance."""
    is_relevant: bool
    relevance_level: BugBountyRelevance
    reasoning: List[str]
    impact_type: str  # "fund_loss", "unauthorized_access", "logic_bypass", "none"
    exploitability_score: float  # 0.0 - 1.0
    would_qualify: bool  # Would bug bounty accept this?
    downgrade_to: Optional[str] = None  # If not relevant, what severity should it be?


class BugBountyRelevanceValidator:
    """
    Validates whether a vulnerability finding is suitable for bug bounty submission.
    
    Criteria for acceptance:
    1. Exploitable by external users (not admin-only)
    2. Causes real impact (fund loss, unauthorized access, etc.)
    3. Not a failsafe issue (constructor fails, etc.)
    4. Not just code quality / best practice
    """
    
    def __init__(self):
        # Patterns that indicate non-exploitable issues
        self.failsafe_patterns = [
            r"constructor.*fail|revert",
            r"internal.*function.*only.*called.*from.*protected",
            r"view.*pure.*function.*cannot.*affect.*state",
            r"function.*will.*fail.*if.*invalid.*input",
        ]
        
        # Patterns that indicate code quality issues (not security)
        self.code_quality_patterns = [
            r"missing.*validation.*but.*constructor.*fail",
            r"best.*practice.*violation",
            r"developer.*experience",
            r"gas.*optimization",
            r"code.*quality",
            r"unclear.*error.*message",
        ]
        
        # Patterns that indicate admin-only issues
        self.admin_only_patterns = [
            r"admin.*only|owner.*only|governance.*only",
            r"only.*called.*by.*deployer",
            r"deployment.*script",
            r"internal.*function.*no.*external.*access",
        ]
        
        # Impact types that qualify for bug bounty
        self.acceptable_impacts = [
            "fund_loss",
            "fund_theft",
            "unauthorized_access",
            "privilege_escalation",
            "logic_bypass",
            "reentrancy_exploit",
            "oracle_manipulation",  # Active oracle manipulation
            "access_control_bypass",
        ]
        
        # Impact types that are borderline (resilience issues, not active exploits)
        self.borderline_impacts = [
            "oracle_stale_price",  # Passive - requires external failure
        ]
        
        # Impact types that don't qualify
        self.unacceptable_impacts = [
            "gas_waste",
            "unclear_error",
            "code_quality",
            "best_practice",
            "developer_experience",
            "failsafe_failure",
        ]
    
    def validate(self, finding: Dict[str, Any], contract_code: str = "") -> BugBountyAssessment:
        """
        Validate if a finding is suitable for bug bounty submission.
        
        Args:
            finding: Vulnerability finding dictionary
            contract_code: Full contract code for context analysis
            
        Returns:
            BugBountyAssessment with relevance determination
        """
        reasoning = []
        impact_type = self._extract_impact_type(finding)
        exploitability_score = self._calculate_exploitability_score(finding, contract_code)
        
        # Check 1: Is it a failsafe issue?
        if self._is_failsafe_issue(finding, contract_code):
            reasoning.append("Issue fails safely - constructor/function will revert, preventing exploitation")
            return BugBountyAssessment(
                is_relevant=False,
                relevance_level=BugBountyRelevance.REJECT,
                reasoning=reasoning,
                impact_type="failsafe_failure",
                exploitability_score=0.0,
                would_qualify=False,
                downgrade_to="informational"
            )
        
        # Check 2: Is it admin-only / internal?
        if self._is_admin_only(finding, contract_code):
            reasoning.append("Issue requires admin/owner privileges or is internal-only")
            return BugBountyAssessment(
                is_relevant=False,
                relevance_level=BugBountyRelevance.REJECT,
                reasoning=reasoning,
                impact_type="admin_only",
                exploitability_score=0.0,
                would_qualify=False,
                downgrade_to="informational"
            )
        
        # Check 3: Is it just code quality?
        if self._is_code_quality_issue(finding):
            reasoning.append("Issue is code quality / best practice, not exploitable vulnerability")
            return BugBountyAssessment(
                is_relevant=False,
                relevance_level=BugBountyRelevance.CODE_QUALITY,
                reasoning=reasoning,
                impact_type="code_quality",
                exploitability_score=0.0,
                would_qualify=False,
                downgrade_to="informational"
            )
        
        # Check 4: Does it have real impact?
        if impact_type in self.unacceptable_impacts:
            reasoning.append(f"Impact type '{impact_type}' is not suitable for bug bounty")
            return BugBountyAssessment(
                is_relevant=False,
                relevance_level=BugBountyRelevance.REJECT,
                reasoning=reasoning,
                impact_type=impact_type,
                exploitability_score=exploitability_score,
                would_qualify=False,
                downgrade_to="low"
            )
        
        # Check 5: Is it exploitable?
        # ONLY filter if exploitability is VERY low (< 0.3) - let LLM handle borderline cases
        if exploitability_score < 0.3:
            reasoning.append(f"Exploitability score {exploitability_score:.2f} is very low (< 0.3)")
            return BugBountyAssessment(
                is_relevant=False,
                relevance_level=BugBountyRelevance.REJECT,
                reasoning=reasoning,
                impact_type=impact_type,
                exploitability_score=exploitability_score,
                would_qualify=False,
                downgrade_to="informational"
            )
        
        # Check 6: Can it cause fund loss or unauthorized access?
        if impact_type in self.acceptable_impacts and exploitability_score >= 0.6:
            reasoning.append(f"Exploitable vulnerability with {impact_type} impact - suitable for bug bounty")
            return BugBountyAssessment(
                is_relevant=True,
                relevance_level=BugBountyRelevance.ACCEPT,
                reasoning=reasoning,
                impact_type=impact_type,
                exploitability_score=exploitability_score,
                would_qualify=True
            )
        
        # NEW: Check for borderline impacts (resilience issues)
        if impact_type in self.borderline_impacts:
            if exploitability_score < 0.4:
                reasoning.append(f"Resilience issue ({impact_type}) with low exploitability ({exploitability_score:.2f}) - requires external failure")
                return BugBountyAssessment(
                    is_relevant=False,
                    relevance_level=BugBountyRelevance.REVIEW,
                    reasoning=reasoning,
                    impact_type=impact_type,
                    exploitability_score=exploitability_score,
                    would_qualify=False,
                    downgrade_to="informational"
                )
            else:
                reasoning.append(f"Resilience issue ({impact_type}) - borderline case, passing to LLM validation")
                return BugBountyAssessment(
                    is_relevant=True,
                    relevance_level=BugBountyRelevance.REVIEW,
                    reasoning=reasoning,
                    impact_type=impact_type,
                    exploitability_score=exploitability_score,
                    would_qualify=False
                )
        
        # Borderline case - DON'T filter, let LLM validation handle it
        # This allows LLM to make the final decision on unclear cases
        reasoning.append("Borderline case - passing to LLM validation for final assessment")
        return BugBountyAssessment(
            is_relevant=True,  # Changed: Don't filter borderline cases
            relevance_level=BugBountyRelevance.REVIEW,
            reasoning=reasoning,
            impact_type=impact_type,
            exploitability_score=exploitability_score,
            would_qualify=False  # But mark as needing review
        )
    
    def _is_failsafe_issue(self, finding: Dict[str, Any], contract_code: str) -> bool:
        """Check if the issue fails safely (constructor/function will revert)."""
        description = finding.get('description', '').lower()
        code_snippet = finding.get('code_snippet', '').lower()
        vulnerability_type = finding.get('vulnerability_type', '').lower()
        
        # Check description for failsafe indicators
        failsafe_indicators = [
            'constructor will fail',
            'constructor will revert',
            'will fail if',
            'will revert if',
            'fails safely',
            'no broken contract',
            'cannot be deployed',
            'deployment fails',
        ]
        
        for indicator in failsafe_indicators:
            if indicator in description:
                return True
        
        # Check if it's about missing validation but constructor fails
        if 'missing validation' in description or 'zero address' in description:
            if 'constructor' in description or 'deployment' in description:
                # Check if constructor actually validates
                if self._constructor_validates(contract_code, finding):
                    return True
        
        return False
    
    def _constructor_validates(self, contract_code: str, finding: Dict[str, Any]) -> bool:
        """Check if constructor actually validates inputs (will fail if invalid)."""
        # Look for constructor calls that would fail on invalid input
        # E.g., IERC20Metadata(address(0)).decimals() will revert
        
        line_num = finding.get('line', 0)
        if line_num == 0:
            return False
        
        # Extract code around the finding
        lines = contract_code.split('\n')
        if line_num <= len(lines):
            # Look for constructor or function that uses the parameter
            # If it calls methods on the address, it will fail
            context_start = max(0, line_num - 10)
            context_end = min(len(lines), line_num + 10)
            context = '\n'.join(lines[context_start:context_end])
            
            # Check if constructor calls methods on the address parameter
            # This would fail if address is zero
            if re.search(r'IERC20Metadata\(.*\)\.(decimals|balanceOf|transfer)', context):
                return True
            if re.search(r'\.forceApprove\(.*\)', context):
                return True
        
        return False
    
    def _is_admin_only(self, finding: Dict[str, Any], contract_code: str) -> bool:
        """Check if issue requires admin/owner privileges."""
        description = finding.get('description', '').lower()
        code_snippet = finding.get('code_snippet', '').lower()
        vulnerability_type = finding.get('vulnerability_type', '').lower()
        
        # Check for admin-only indicators
        admin_indicators = [
            'admin only',
            'owner only',
            'governance only',
            'deployment script',
            'internal function',
            'only called by deployer',
            'access-controlled',
        ]
        
        for indicator in admin_indicators:
            if indicator in description:
                return True
        
        # Check function visibility
        if 'internal' in code_snippet and 'function' in code_snippet:
            # Check if it's only called from protected functions
            if self._is_only_called_from_protected(contract_code, finding):
                return True
        
        return False
    
    def _is_only_called_from_protected(self, contract_code: str, finding: Dict[str, Any]) -> bool:
        """Check if function is only called from access-controlled functions."""
        # This is a simplified check - in practice, would need call graph analysis
        # For now, check if function is internal and description mentions protection
        description = finding.get('description', '').lower()
        if 'internal' in description and ('protected' in description or 'access-controlled' in description):
            return True
        return False
    
    def _is_code_quality_issue(self, finding: Dict[str, Any]) -> bool:
        """Check if issue is code quality / best practice, not security."""
        description = finding.get('description', '').lower()
        vulnerability_type = finding.get('vulnerability_type', '').lower()
        
        # For best_practice_violation: Only filter if it's CLEARLY code quality
        # (multiple indicators, or explicitly says "code quality" / "developer experience")
        # Don't filter borderline cases - let LLM decide
        if 'best_practice' in vulnerability_type:
            # Only filter if it has MULTIPLE clear code quality indicators
            clear_quality_terms = ['code quality', 'developer experience', 'gas optimization', 'unclear error', 'better error message']
            quality_term_count = sum(1 for term in clear_quality_terms if term in description)
            
            # If it has 2+ quality terms AND no security terms, filter it
            security_terms = ['exploit', 'attack', 'drain', 'bypass', 'theft', 'unauthorized', 'vulnerability', 'security']
            has_security_terms = any(term in description for term in security_terms)
            
            if quality_term_count >= 2 and not has_security_terms:
                return True
            
            # If it explicitly says "code quality" or "developer experience" as the main issue
            if ('code quality' in description or 'developer experience' in description) and not has_security_terms:
                return True
            
            # Otherwise, let it pass through (borderline case)
            return False
        
        code_quality_indicators = [
            'code quality',
            'developer experience',
            'gas optimization',
            'unclear error',
            'better error message',
            'code style',
        ]
        
        # Only filter if MULTIPLE indicators suggest code quality
        indicator_count = sum(1 for indicator in code_quality_indicators if indicator in description)
        if indicator_count >= 2:
            return True
        
        # Check if impact is just gas waste or unclear errors (with no security implication)
        impact = self._extract_impact_type(finding)
        if impact in ['gas_waste', 'unclear_error', 'developer_experience']:
            # Double-check: if it mentions security implications, don't filter
            if not any(term in description for term in ['security', 'exploit', 'attack', 'vulnerability']):
                return True
        
        return False
    
    def _extract_impact_type(self, finding: Dict[str, Any]) -> str:
        """Extract the type of impact from the finding."""
        description = finding.get('description', '').lower()
        vulnerability_type = finding.get('vulnerability_type', '').lower()
        
        # Fund loss indicators
        if any(term in description for term in ['fund loss', 'fund theft', 'drain', 'steal', 'theft']):
            return 'fund_loss'
        
        # Unauthorized access indicators
        if any(term in description for term in ['unauthorized access', 'privilege escalation', 'access control bypass']):
            return 'unauthorized_access'
        
        # Logic bypass indicators
        if any(term in description for term in ['bypass', 'circumvent', 'logic error']):
            return 'logic_bypass'
        
        # Reentrancy
        if 'reentrancy' in vulnerability_type or 'reentrancy' in description:
            return 'reentrancy_exploit'
        
        # Oracle manipulation (active)
        if any(term in description for term in ['oracle manipulation', 'price manipulation', 'oracle attack']):
            # Check if it's passive (stale price) vs active (manipulation)
            if any(term in description for term in ['stale', 'oracle failure', 'oracle stops', 'feed stops']):
                return 'oracle_stale_price'  # Passive - resilience issue
            return 'oracle_manipulation'  # Active - exploitable
        
        # Stale price / oracle resilience (passive)
        if any(term in description for term in ['stale price', 'stale data', 'oracle failure', 'feed stops updating']):
            return 'oracle_stale_price'
        
        # Gas waste
        if any(term in description for term in ['gas waste', 'wasted gas', 'gas optimization']):
            return 'gas_waste'
        
        # Code quality
        if any(term in description for term in ['code quality', 'best practice', 'developer experience']):
            return 'code_quality'
        
        # Unclear error
        if any(term in description for term in ['unclear error', 'better error message']):
            return 'unclear_error'
        
        # Failsafe failure
        if any(term in description for term in ['will fail', 'will revert', 'fails safely']):
            return 'failsafe_failure'
        
        return 'unknown'
    
    def _calculate_exploitability_score(self, finding: Dict[str, Any], contract_code: str) -> float:
        """
        Calculate exploitability score (0.0 - 1.0).
        
        Higher score = more exploitable.
        
        Now includes detection of:
        - External dependencies (oracle failures, network issues)
        - Passive vs active exploits
        - Attacker control over trigger conditions
        """
        score = 0.5  # Base score
        
        description = finding.get('description', '').lower()
        vulnerability_type = finding.get('vulnerability_type', '').lower()
        severity = finding.get('severity', '').lower()
        
        # Severity boost
        if severity == 'critical':
            score += 0.3
        elif severity == 'high':
            score += 0.2
        elif severity == 'medium':
            score += 0.1
        
        # NEW: Check for external dependencies (passive exploits)
        external_dependency_keywords = [
            'requires external',
            'oracle failure',
            'oracle outage',
            'feed stops updating',
            'feed stops',
            'oracle stops',
            'network issue',
            'external event',
            'out of attacker control',
            'attacker cannot trigger',
            'attacker cannot cause',
            'requires chainlink',
            'requires oracle',
            'if the oracle',
            'if oracle',
            'when oracle',
            'when the oracle',
            'passive exploitation',
            'waiting for',
            'depends on external',
            'external dependency',
            'external failure',
            'third-party failure',
            'infrastructure failure',
        ]
        
        has_external_dependency = any(keyword in description for keyword in external_dependency_keywords)
        
        # NEW: Check for active exploit indicators
        active_exploit_keywords = [
            'attacker can',
            'attacker can directly',
            'can be triggered',
            'can trigger',
            'directly exploitable',
            'active exploit',
            'attacker controls',
            'attacker manipulates',
            'attacker causes',
            'attacker forces',
            'attacker initiates',
        ]
        
        has_active_exploit = any(keyword in description for keyword in active_exploit_keywords)
        
        # NEW: Apply external dependency penalty
        if has_external_dependency:
            # Strong penalty for passive exploits
            score -= 0.4
            logger.debug(f"External dependency detected - reducing exploitability by 0.4")
        
        # NEW: Apply active exploit boost (only if no external dependency)
        if has_active_exploit and not has_external_dependency:
            score += 0.2
            logger.debug(f"Active exploit detected - boosting exploitability by 0.2")
        
        # Exploitability indicators (existing logic)
        if any(term in description for term in ['can be exploited', 'exploitable', 'attack vector']):
            # Only boost if it's an active exploit, not passive
            if not has_external_dependency:
                score += 0.2
            else:
                # Small boost for passive exploits (they're still exploitable, just not actively)
                score += 0.05
        
        # External access boost (existing logic)
        if 'external' in description or 'public' in description:
            if 'admin' not in description and 'owner' not in description:
                # Only boost if no external dependency (external access doesn't help if attacker can't trigger condition)
                if not has_external_dependency:
                    score += 0.2
                else:
                    # Small boost - external access helps but condition still requires external event
                    score += 0.05
        
        # Internal function penalty (existing logic)
        if 'internal' in description:
            score -= 0.3
        
        # Admin-only penalty (existing logic)
        if any(term in description for term in ['admin', 'owner', 'governance']):
            score -= 0.4
        
        # Failsafe penalty (existing logic)
        if any(term in description for term in ['will fail', 'will revert', 'fails safely']):
            score -= 0.5
        
        # Code quality penalty (existing logic)
        if any(term in description for term in ['code quality', 'best practice', 'developer experience']):
            score -= 0.4
        
        # NEW: Additional penalty if description explicitly says attacker cannot trigger
        cannot_trigger_keywords = [
            'attacker cannot trigger',
            'attacker cannot cause',
            'attacker has no control',
            'requires external failure',
            'cannot be actively exploited',
            'passive only',
        ]
        
        if any(keyword in description for keyword in cannot_trigger_keywords):
            score -= 0.3
            logger.debug(f"Attacker cannot trigger condition - reducing exploitability by 0.3")
        
        # Ensure score is within bounds
        final_score = max(0.0, min(1.0, score))
        
        # Log reasoning for debugging
        if has_external_dependency:
            logger.debug(f"Exploitability score: {final_score:.2f} (external dependency detected - passive exploit)")
        elif has_active_exploit:
            logger.debug(f"Exploitability score: {final_score:.2f} (active exploit detected)")
        else:
            logger.debug(f"Exploitability score: {final_score:.2f}")
        
        return final_score
    
    def filter_findings(self, findings: List[Dict[str, Any]], contract_code: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter findings into bug-bounty-worthy and non-worthy.
        
        Returns:
            Tuple of (bug_bounty_worthy_findings, filtered_out_findings)
        """
        bug_bounty_worthy = []
        filtered_out = []
        
        for finding in findings:
            assessment = self.validate(finding, contract_code)
            
            if assessment.is_relevant and assessment.would_qualify:
                # Add assessment metadata to finding
                finding['bug_bounty_assessment'] = {
                    'is_relevant': True,
                    'relevance_level': assessment.relevance_level.value,
                    'impact_type': assessment.impact_type,
                    'exploitability_score': assessment.exploitability_score,
                }
                bug_bounty_worthy.append(finding)
            else:
                # Add assessment metadata and downgrade if needed
                finding['bug_bounty_assessment'] = {
                    'is_relevant': False,
                    'relevance_level': assessment.relevance_level.value,
                    'impact_type': assessment.impact_type,
                    'exploitability_score': assessment.exploitability_score,
                    'reasoning': assessment.reasoning,
                    'downgrade_to': assessment.downgrade_to,
                }
                
                # Downgrade severity if recommended
                if assessment.downgrade_to:
                    original_severity = finding.get('severity', 'unknown')
                    finding['severity'] = assessment.downgrade_to
                    finding['severity_downgrade_reason'] = f"Downgraded from {original_severity}: {', '.join(assessment.reasoning)}"
                
                filtered_out.append(finding)
        
        return bug_bounty_worthy, filtered_out

