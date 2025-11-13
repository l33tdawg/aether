#!/usr/bin/env python3
"""
Test the improved bug bounty validator with external dependency detection.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bug_bounty_relevance_validator import BugBountyRelevanceValidator


def test_stale_price_oracle():
    """Test that stale price oracle gets lower exploitability score."""
    validator = BugBountyRelevanceValidator()
    
    finding = {
        'description': 'The contract\'s `_getValidatedOracleData()` function performs insufficient validation on Chainlink data. While it includes a basic check (`answeredInRound >= roundId`) to ensure the answer is not from an older round, it critically omits a freshness check comparing `block.timestamp` with the `updatedAt` timestamp from the Chainlink feed. This allows the oracle to return significantly stale prices if the Chainlink feed stops updating, even if the last reported price is positive and within the defined bounds. In a scenario where the primary or fallback aggregator experiences an outage or ceases updates, the system could continue using outdated data for extended periods, leading to incorrect asset valuations, potential liquidations, or other financial exploits.',
        'severity': 'high',
        'vulnerability_type': 'stale_or_invalid_price_adoption',
        'line_number': 180,
        'confidence': 0.87
    }
    
    assessment = validator.validate(finding, "")
    exploitability_score = assessment.exploitability_score
    
    print(f"\n=== Stale Price Oracle Test ===")
    print(f"Exploitability Score: {exploitability_score:.2f}")
    print(f"Expected: ~0.2-0.3 (was 0.7 before fix)")
    print(f"Assessment: {assessment.relevance_level.value}")
    print(f"Reasoning: {assessment.reasoning}")
    
    # Should be much lower than 0.7
    assert exploitability_score < 0.5, f"Score {exploitability_score} should be < 0.5"
    assert exploitability_score >= 0.2, f"Score {exploitability_score} should be >= 0.2"
    
    print("✅ PASS: Stale price oracle correctly identified as low exploitability")


def test_active_reentrancy():
    """Test that active exploits still get high exploitability score."""
    validator = BugBountyRelevanceValidator()
    
    finding = {
        'description': 'The `doTransferIn` and `doTransferOut` functions directly invoke `transferFrom` and `transfer` on the underlying ERC20 token without any reentrancy guard. If the underlying token is malicious (implements ERC777-like hooks or reentrant callbacks), an attacker can re-enter back into the lending functions `mint`, `redeem`, or `borrow` via the fallback paths, potentially manipulating protocol state mid-execution. This can cause accounting corruption or draining of the pool. Attacker can drain funds by exploiting state inconsistencies during external calls.',
        'severity': 'high',
        'vulnerability_type': 'reentrancy',
        'line_number': 200,
        'confidence': 0.90
    }
    
    assessment = validator.validate(finding, "")
    exploitability_score = assessment.exploitability_score
    
    print(f"\n=== Active Reentrancy Test ===")
    print(f"Exploitability Score: {exploitability_score:.2f}")
    print(f"Expected: ~0.7-0.9 (active exploit)")
    print(f"Assessment: {assessment.relevance_level.value}")
    print(f"Reasoning: {assessment.reasoning}")
    
    # Should be high (active exploit)
    assert exploitability_score >= 0.6, f"Score {exploitability_score} should be >= 0.6"
    
    print("✅ PASS: Active reentrancy correctly identified as high exploitability")


def test_external_dependency_detection():
    """Test that external dependencies are detected."""
    validator = BugBountyRelevanceValidator()
    
    test_cases = [
        {
            'name': 'Oracle failure',
            'description': 'If the Chainlink feed stops updating, the oracle can return stale prices',
            'expected_low': True
        },
        {
            'name': 'Network issue',
            'description': 'When network issues occur, the system may use outdated data',
            'expected_low': True
        },
        {
            'name': 'Attacker can trigger',
            'description': 'An attacker can directly manipulate the price by calling the function',
            'expected_low': False
        },
        {
            'name': 'Active exploit',
            'description': 'Attacker can drain funds by exploiting the vulnerability',
            'expected_low': False
        }
    ]
    
    print(f"\n=== External Dependency Detection Test ===")
    
    for test_case in test_cases:
        finding = {
            'description': test_case['description'],
            'severity': 'high',
            'vulnerability_type': 'test',
        }
        
        score = validator._calculate_exploitability_score(finding, "")
        
        print(f"\n{test_case['name']}:")
        print(f"  Description: {test_case['description']}")
        print(f"  Score: {score:.2f}")
        print(f"  Expected low: {test_case['expected_low']}")
        
        if test_case['expected_low']:
            assert score < 0.5, f"Score {score} should be < 0.5 for external dependency"
            print(f"  ✅ PASS: Correctly identified as low exploitability")
        else:
            assert score >= 0.5, f"Score {score} should be >= 0.5 for active exploit"
            print(f"  ✅ PASS: Correctly identified as higher exploitability")


if __name__ == '__main__':
    print("Testing improved bug bounty validator...")
    
    test_stale_price_oracle()
    test_active_reentrancy()
    test_external_dependency_detection()
    
    print("\n" + "="*50)
    print("✅ All tests passed!")
    print("="*50)

