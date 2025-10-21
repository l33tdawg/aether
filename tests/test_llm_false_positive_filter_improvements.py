#!/usr/bin/env python3
"""
Test to verify improved LLM false positive filter catches SafeCast and inherited access control patterns.
"""

import asyncio
import sys
from pathlib import Path

# Add core to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.llm_false_positive_filter import LLMFalsePositiveFilter
from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer
from core.validation_patterns import is_likely_false_positive

def test_safecast_pattern_detection():
    """Test that SafeCast patterns are identified as likely false positives."""
    print("\n🧪 TEST 1: SafeCast Pattern Detection")
    print("=" * 60)
    
    vuln_type = "integer_overflow_underflow"
    description = "The contract narrows uint256 amounts to uint96 using SafeCast.toUint96, which reverts if values exceed 2^96-1. This prevents silent overflow but can cause transactions involving large amounts to revert, potentially leading to denial-of-service."
    
    is_fp, reason = is_likely_false_positive(vuln_type, description)
    
    print(f"Vulnerability Type: {vuln_type}")
    print(f"Description (truncated): {description[:100]}...")
    print(f"\nResult: is_false_positive={is_fp}, reason='{reason}'")
    
    if is_fp:
        print("✅ PASS: SafeCast pattern correctly identified as likely false positive")
        return True
    else:
        print("❌ FAIL: SafeCast pattern NOT identified as false positive")
        return False

def test_inherited_access_control_pattern():
    """Test that inherited access control patterns are identified as likely false positives."""
    print("\n🧪 TEST 2: Inherited Access Control Pattern Detection")
    print("=" * 60)
    
    vuln_type = "access_control"
    description = "The contract inherits MisfundRecovery and ERC20WithPermit, which expose privileged functions such as token rescue and minting. These functions must be properly restricted with onlyOwner or role-based access control to prevent unauthorized access."
    
    is_fp, reason = is_likely_false_positive(vuln_type, description)
    
    print(f"Vulnerability Type: {vuln_type}")
    print(f"Description (truncated): {description[:100]}...")
    print(f"\nResult: is_false_positive={is_fp}, reason='{reason}'")
    
    if is_fp:
        print("✅ PASS: Inherited access control pattern correctly identified as likely false positive")
        return True
    else:
        print("❌ FAIL: Inherited access control pattern NOT identified as false positive")
        return False

def test_validation_prompt_improvements():
    """Test that the validation prompt contains necessary false positive guidance."""
    print("\n🧪 TEST 3: Validation Prompt Improvements")
    print("=" * 60)
    
    filter = LLMFalsePositiveFilter()
    
    # Create a test context
    context = {
        'contract_name': 'T',
        'vulnerability_type': 'integer_overflow_underflow',
        'severity': 'medium',
        'line_number': 103,
        'description': 'SafeCast.toUint96() test',
        'code_context': 'uint96 safeAmount = SafeCast.toUint96(amount);'
    }
    
    prompt = filter._create_validation_prompt(context)
    
    # Check for key guidance in prompt
    required_keywords = [
        "SafeCast",
        "FALSE POSITIVE PATTERNS",
        "Inherited Access Control",
        "revert-on-overflow",
        "parent contract"
    ]
    
    missing = [kw for kw in required_keywords if kw not in prompt]
    
    if not missing:
        print("✅ PASS: All critical guidance keywords present in validation prompt")
        print(f"   Keywords checked: {', '.join(required_keywords)}")
        return True
    else:
        print(f"❌ FAIL: Missing keywords in validation prompt: {missing}")
        return False

def test_analyzer_prompt_improvements():
    """Test that the analyzer prompt contains pattern recognition guidance."""
    print("\n🧪 TEST 4: Analyzer Prompt Pattern Recognition")
    print("=" * 60)
    
    analyzer = EnhancedLLMAnalyzer()
    
    # Create test prompt
    prompt = analyzer._create_enhanced_analysis_prompt("contract Test {}", {})
    
    # Check for pattern recognition section
    required_sections = [
        "PATTERN RECOGNITION",
        "SafeCast Type Narrowing",
        "Inherited Access Control",
        "Type Narrowing for Storage",
        "External Package Trust"
    ]
    
    missing = [sec for sec in required_sections if sec not in prompt]
    
    if not missing:
        print("✅ PASS: Pattern recognition section present in analyzer prompt")
        print(f"   Sections checked: {', '.join(required_sections)}")
        return True
    else:
        print(f"❌ FAIL: Missing pattern recognition sections: {missing}")
        return False

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("LLM False Positive Filter Improvements Test Suite")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(("SafeCast Pattern Detection", test_safecast_pattern_detection()))
    except Exception as e:
        print(f"❌ ERROR in test 1: {e}")
        results.append(("SafeCast Pattern Detection", False))
    
    try:
        results.append(("Inherited Access Control Pattern", test_inherited_access_control_pattern()))
    except Exception as e:
        print(f"❌ ERROR in test 2: {e}")
        results.append(("Inherited Access Control Pattern", False))
    
    try:
        results.append(("Validation Prompt Improvements", test_validation_prompt_improvements()))
    except Exception as e:
        print(f"❌ ERROR in test 3: {e}")
        results.append(("Validation Prompt Improvements", False))
    
    try:
        results.append(("Analyzer Prompt Pattern Recognition", test_analyzer_prompt_improvements()))
    except Exception as e:
        print(f"❌ ERROR in test 4: {e}")
        results.append(("Analyzer Prompt Pattern Recognition", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print(f"\nTotal: {total_passed}/{total_tests} tests passed")
    
    if total_passed == total_tests:
        print("\n🎉 All tests passed! LLM false positive filter improvements are working correctly.")
        sys.exit(0)
    else:
        print(f"\n⚠️ {total_tests - total_passed} test(s) failed.")
        sys.exit(1)
