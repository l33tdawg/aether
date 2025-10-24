"""
Confidence Scorer - Multi-factor confidence scoring for findings.

This module combines multiple signals to determine the overall confidence
that a finding is a true positive. It considers LLM confidence, function context,
attack scenario quality, and historical patterns.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from core.function_context_analyzer import FunctionContext, RiskLevel
from core.impact_analyzer import ImpactAnalysis, ImpactType

logger = logging.getLogger(__name__)


@dataclass
class CompositeScore:
    """Result of composite confidence scoring."""
    composite_score: float  # 0.0 to 1.0
    should_report: bool
    confidence_factors: Dict[str, float]
    reasoning: str


class ConfidenceScorer:
    """Multi-factor confidence scoring for vulnerability findings."""
    
    def __init__(self, database_manager=None):
        """
        Initialize confidence scorer.
        
        Args:
            database_manager: Optional database manager for historical pattern analysis
        """
        self.db = database_manager
        
        # Severity-based reporting thresholds
        self.severity_thresholds = {
            'critical': 0.70,
            'high': 0.75,
            'medium': 0.65,
            'low': 0.55,
            'info': 0.50
        }
    
    def calculate_composite_score(self,
                                  finding: Dict,
                                  function_context: Optional[FunctionContext] = None,
                                  impact_analysis: Optional[ImpactAnalysis] = None) -> CompositeScore:
        """
        Calculate composite confidence score combining multiple factors.
        
        Args:
            finding: Vulnerability finding dictionary
            function_context: Optional function context analysis
            impact_analysis: Optional impact analysis result
        
        Returns:
            CompositeScore with overall assessment
        """
        
        scores = {}
        
        # Factor 1: LLM-reported confidence (30% weight)
        llm_confidence = finding.get('confidence', 0.5)
        scores['llm_confidence'] = llm_confidence
        
        # Factor 2: Function context alignment (30% weight)
        context_score = self._calculate_context_alignment(finding, function_context)
        scores['context_alignment'] = context_score
        
        # Factor 3: Attack scenario quality (20% weight)
        scenario_score = self._calculate_scenario_quality(finding)
        scores['scenario_quality'] = scenario_score
        
        # Factor 4: Impact analysis confidence (10% weight)
        impact_score = self._calculate_impact_confidence(finding, impact_analysis)
        scores['impact_confidence'] = impact_score
        
        # Factor 5: Historical pattern matching (10% weight)
        historical_score = self._calculate_historical_score(finding)
        scores['historical_pattern'] = historical_score
        
        # Calculate weighted composite score
        weights = {
            'llm_confidence': 0.30,
            'context_alignment': 0.30,
            'scenario_quality': 0.20,
            'impact_confidence': 0.10,
            'historical_pattern': 0.10
        }
        
        composite = sum(scores[k] * weights[k] for k in scores.keys())
        
        # Determine if should report
        severity = finding.get('severity', 'medium')
        should_report = self.should_report(composite, severity)
        
        # Build reasoning
        reasoning = self._build_reasoning(scores, weights, composite, should_report)
        
        return CompositeScore(
            composite_score=composite,
            should_report=should_report,
            confidence_factors=scores,
            reasoning=reasoning
        )
    
    def _calculate_context_alignment(self,
                                    finding: Dict,
                                    context: Optional[FunctionContext]) -> float:
        """Calculate how well the finding aligns with function context."""
        
        if not context:
            return 0.5  # Neutral score if no context
        
        severity = finding.get('severity', 'medium')
        finding_type = finding.get('vulnerability_type', '').lower()
        
        score = 0.5  # Base score
        
        # High severity finding in low-risk function = alignment issue
        if severity in ['critical', 'high'] and context.risk_level == RiskLevel.LOW:
            score = 0.2  # Poor alignment
        
        # High severity finding in high-risk function = good alignment
        elif severity in ['critical', 'high'] and context.risk_level == RiskLevel.HIGH:
            score = 0.9  # Good alignment
        
        # Critical function with critical finding = excellent alignment
        elif severity == 'critical' and context.risk_level == RiskLevel.CRITICAL:
            score = 1.0  # Excellent alignment
        
        # Low severity in low risk = acceptable alignment
        elif severity == 'low' and context.risk_level == RiskLevel.LOW:
            score = 0.7
        
        # Medium severity in medium risk = good alignment
        elif severity == 'medium' and context.risk_level == RiskLevel.MEDIUM:
            score = 0.8
        
        # State impact alignment
        if 'parameter_validation' in finding_type:
            if context.state_impact.value == 'read-only':
                score *= 0.5  # Parameter validation on getters is less critical
            elif context.state_impact.value == 'critical':
                score *= 1.3  # Parameter validation on critical functions is more important
        
        # Reentrancy alignment
        if 'reentrancy' in finding_type:
            if not context.has_external_call:
                score = 0.1  # Very poor alignment - reentrancy without external calls
            elif context.state_impact.value == 'read-only':
                score = 0.2  # Poor alignment - reentrancy on view function
            else:
                score = 0.9  # Good alignment
        
        return min(1.0, max(0.0, score))
    
    def _calculate_scenario_quality(self, finding: Dict) -> float:
        """Calculate quality of attack scenario description."""
        
        attack_scenario = finding.get('attack_scenario', '')
        description = finding.get('description', '')
        
        score = 0.3  # Base score
        
        # Check for attack scenario presence and quality
        if attack_scenario:
            # Check for numbered steps
            if any(marker in attack_scenario for marker in ['1.', '2.', 'step', 'first', 'then']):
                score += 0.2
            
            # Check for outcome description
            if any(word in attack_scenario.lower() 
                   for word in ['result', 'lead', 'cause', 'impact', 'loss', 'theft']):
                score += 0.2
            
            # Check for detail/length
            if len(attack_scenario) > 100:
                score += 0.2
            if len(attack_scenario) > 200:
                score += 0.1
        
        # Check description quality
        if description:
            # Technical detail = higher quality
            if any(term in description.lower() 
                   for term in ['require', 'revert', 'storage', 'state', 'external call']):
                score += 0.1
            
            # Specific function names = higher quality
            if any(char in description for char in ['(', ')']):
                score += 0.1
        
        return min(1.0, max(0.0, score))
    
    def _calculate_impact_confidence(self,
                                    finding: Dict,
                                    impact: Optional[ImpactAnalysis]) -> float:
        """Calculate confidence from impact analysis."""
        
        if not impact:
            return 0.5  # Neutral if no impact analysis
        
        # Use impact analysis confidence directly
        score = impact.confidence
        
        # Adjust based on impact type
        if impact.impact_type == ImpactType.NONE:
            score = 0.0  # No impact = no confidence
        elif impact.impact_type == ImpactType.FUNDS:
            score = min(1.0, score * 1.2)  # Fund impact = higher confidence
        elif impact.impact_type == ImpactType.INFO_LEAK:
            score = max(0.0, score * 0.7)  # Info leak = lower confidence
        
        # Plausible attack scenario boosts confidence
        if impact.attack_scenario_plausible:
            score = min(1.0, score * 1.1)
        else:
            score = max(0.0, score * 0.8)
        
        return score
    
    def _calculate_historical_score(self, finding: Dict) -> float:
        """Calculate score based on historical pattern matching."""
        
        if not self.db:
            return 0.5  # Neutral if no database
        
        try:
            vuln_type = finding.get('vulnerability_type', '')
            
            # Query similar findings from database
            # This is a simplified version - would need actual DB implementation
            similar_findings = self._get_similar_findings(vuln_type)
            
            if not similar_findings:
                return 0.5  # No historical data
            
            # Calculate false positive rate from history
            total = len(similar_findings)
            false_positives = sum(1 for f in similar_findings if f.get('is_false_positive'))
            
            # Inverse of false positive rate = confidence
            false_positive_rate = false_positives / total
            confidence = 1.0 - false_positive_rate
            
            return confidence
            
        except Exception as e:
            logger.warning(f"Error calculating historical score: {e}")
            return 0.5
    
    def _get_similar_findings(self, vuln_type: str) -> List[Dict]:
        """Get similar findings from database."""
        
        # This would query the database for similar vulnerability types
        # For now, return empty list (no historical data)
        return []
    
    def should_report(self, composite_score: float, severity: str) -> bool:
        """
        Determine if finding should be reported based on composite score and severity.
        
        Higher severity findings require higher confidence to avoid false positives.
        """
        
        threshold = self.severity_thresholds.get(severity.lower(), 0.7)
        return composite_score >= threshold
    
    def _build_reasoning(self,
                        scores: Dict[str, float],
                        weights: Dict[str, float],
                        composite: float,
                        should_report: bool) -> str:
        """Build human-readable reasoning for the score."""
        
        parts = []
        
        # Overall score
        parts.append(f"Composite confidence: {composite:.2f}")
        
        # Top contributing factors
        sorted_factors = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_3 = sorted_factors[:3]
        
        parts.append("Top factors:")
        for factor, score in top_3:
            weight = weights[factor]
            contribution = score * weight
            parts.append(f"  - {factor}: {score:.2f} (weight: {weight:.0%}, contribution: {contribution:.2f})")
        
        # Recommendation
        if should_report:
            parts.append("Recommendation: REPORT (confidence above threshold)")
        else:
            parts.append("Recommendation: FILTER (confidence below threshold)")
        
        return "; ".join(parts)
    
    def get_confidence_breakdown(self, 
                                finding: Dict,
                                function_context: Optional[FunctionContext] = None,
                                impact_analysis: Optional[ImpactAnalysis] = None) -> Dict:
        """
        Get detailed confidence breakdown for analysis.
        
        Useful for debugging and understanding why findings are filtered or reported.
        """
        
        result = self.calculate_composite_score(finding, function_context, impact_analysis)
        
        return {
            'composite_score': result.composite_score,
            'should_report': result.should_report,
            'factors': result.confidence_factors,
            'reasoning': result.reasoning,
            'threshold': self.severity_thresholds.get(finding.get('severity', 'medium'), 0.7)
        }


if __name__ == "__main__":
    # Example usage
    from core.function_context_analyzer import FunctionContextAnalyzer
    from core.impact_analyzer import ImpactAnalyzer
    
    # Create analyzers
    func_analyzer = FunctionContextAnalyzer()
    impact_analyzer = ImpactAnalyzer()
    scorer = ConfidenceScorer()
    
    # Test case: Parameter validation on getter
    getter_code = """
    function getCollateralMintFees(address collateral)
        external
        view
        returns (uint64[] memory xFeeMint, int64[] memory yFeeMint)
    {
        return (collatInfo.xFeeMint, collatInfo.yFeeMint);
    }
    """
    
    context = func_analyzer.analyze_function(getter_code, "getCollateralMintFees")
    
    finding = {
        'vulnerability_type': 'parameter_validation_issue',
        'severity': 'high',
        'confidence': 0.80,
        'description': 'Function does not validate collateral address',
        'attack_scenario': ''
    }
    
    impact = impact_analyzer.calculate_impact(finding, context)
    
    score = scorer.calculate_composite_score(finding, context, impact)
    
    print("Confidence Scoring Example:")
    print(f"  Composite Score: {score.composite_score:.2f}")
    print(f"  Should Report: {score.should_report}")
    print(f"  Reasoning: {score.reasoning}")

