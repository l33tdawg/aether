"""
Test DoS Feasibility Validator

Tests that the validator correctly identifies non-exploitable DoS issues
like the Snowbridge false positive.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dos_feasibility_validator import DoSFeasibilityValidator, DoSFeasibility


def test_snowbridge_false_positive():
    """
    Test that the validator correctly identifies the Snowbridge issue
    as NOT exploitable due to cryptographic barriers.
    """
    validator = DoSFeasibilityValidator()
    
    # Snowbridge contract snippet
    snowbridge_code = """
    function verifyCommitment(
        address beefyClient,
        bytes4 encodedParaID,
        bytes32 commitment,
        Proof calldata proof,
        bool isV2
    ) external view returns (bool) {
        // Verify that parachain header contains the commitment
        if (!isCommitmentInHeaderDigest(commitment, proof.header, isV2)) {
            return false;
        }

        if (proof.headProof.pos >= proof.headProof.width) {
            return false;
        }

        // Compute the merkle leaf hash of our parachain
        bytes32 parachainHeadHash = createParachainHeaderMerkleLeaf(encodedParaID, proof.header);

        // Compute the merkle root hash of all parachain heads
        bytes32 parachainHeadsRoot = SubstrateMerkleProof.computeRoot(
            parachainHeadHash, proof.headProof.pos, proof.headProof.width, proof.headProof.proof
        );

        bytes32 leafHash = createMMRLeaf(proof.leafPartial, parachainHeadsRoot);

        // Verify that the MMR leaf is part of the MMR maintained by the BEEFY light client
        return BeefyClient(beefyClient).verifyMMRLeafProof(
            leafHash, proof.leafProof, proof.leafProofOrder
        );
    }
    
    function encodeDigestItems(DigestItem[] calldata digestItems)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory accum = hex"";
        for (uint256 i = 0; i < digestItems.length; i++) {
            accum = bytes.concat(accum, encodeDigestItem(digestItems[i]));
        }
        return bytes.concat(encodeCompactU32(digestItems.length), accum);
    }
    """
    
    vulnerability = {
        'vulnerability_type': 'unbounded_loop_gas',
        'description': 'Loop iterating over digestItems.length without bounds',
        'line_number': 50,
        'code_snippet': 'for (uint256 i = 0; i < digestItems.length; i++)',
        'severity': 'high',
        'confidence': 0.9
    }
    
    result = validator.validate_dos_vulnerability(
        vulnerability, 
        snowbridge_code,
        function_context=None
    )
    
    print("\n=== Snowbridge DoS Validation ===")
    print(f"Exploitable: {result.is_exploitable}")
    print(f"Feasibility: {result.feasibility.value}")
    print(f"Confidence: {result.confidence}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Barriers: {', '.join(result.barriers)}")
    print(f"Recommended Severity: {result.recommended_severity}")
    
    # Should NOT be exploitable due to:
    # 1. Input is part of cryptographically validated structure
    # 2. Function would revert on invalid proof
    # 3. Attacker pays gas for failed transaction
    
    assert not result.is_exploitable or result.recommended_severity in ['low', 'informational'], \
        "Snowbridge issue should be non-exploitable or low severity"
    
    print("\n✓ PASS: Correctly identified as non-exploitable/low severity")
    return True


def test_actual_exploitable_dos():
    """
    Test that the validator still catches REAL DoS vulnerabilities.
    """
    validator = DoSFeasibilityValidator()
    
    # Vulnerable contract with no protections
    vulnerable_code = """
    function processOrders(Order[] calldata orders) external {
        for (uint256 i = 0; i < orders.length; i++) {
            _processOrder(orders[i]);
        }
    }
    
    function _processOrder(Order calldata order) internal {
        // Process order (state changes)
        orderBook[order.id] = order;
    }
    """
    
    vulnerability = {
        'vulnerability_type': 'unbounded_loop',
        'description': 'Unbounded loop over user-provided array',
        'line_number': 3,
        'code_snippet': 'for (uint256 i = 0; i < orders.length; i++)',
        'severity': 'high',
        'confidence': 0.9
    }
    
    result = validator.validate_dos_vulnerability(
        vulnerability,
        vulnerable_code,
        function_context=None
    )
    
    print("\n=== Real Exploitable DoS Validation ===")
    print(f"Exploitable: {result.is_exploitable}")
    print(f"Feasibility: {result.feasibility.value}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Recommended Severity: {result.recommended_severity}")
    
    # Should BE exploitable
    assert result.is_exploitable, "Should detect real DoS vulnerability"
    assert result.feasibility == DoSFeasibility.EXPLOITABLE
    
    print("\n✓ PASS: Correctly identified as exploitable")
    return True


def test_economic_barrier():
    """
    Test detection of economic barriers (view functions).
    """
    validator = DoSFeasibilityValidator()
    
    code = """
    function computeExpensiveCalculation(uint256[] calldata data) external view returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < data.length; i++) {
            result += expensiveComputation(data[i]);
        }
        return result;
    }
    """
    
    vulnerability = {
        'vulnerability_type': 'unbounded_loop',
        'description': 'Unbounded loop in view function',
        'line_number': 4,
        'code_snippet': 'for (uint256 i = 0; i < data.length; i++)',
        'severity': 'high',
        'confidence': 0.8
    }
    
    result = validator.validate_dos_vulnerability(
        vulnerability,
        code,
        function_context=None
    )
    
    print("\n=== Economic Barrier (View Function) ===")
    print(f"Exploitable: {result.is_exploitable}")
    print(f"Feasibility: {result.feasibility.value}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Economic Cost: {result.economic_cost}")
    
    # View function - attacker pays gas but no state impact
    assert not result.is_exploitable or result.feasibility == DoSFeasibility.ECONOMIC_BARRIER
    
    print("\n✓ PASS: Correctly identified economic barrier")
    return True


def test_validation_suggestions():
    """
    Test that validator provides helpful verification steps.
    """
    validator = DoSFeasibilityValidator()
    
    vulnerability = {
        'vulnerability_type': 'unbounded_loop',
        'description': 'Test',
        'line_number': 1
    }
    
    from core.dos_feasibility_validator import DoSValidationResult, DoSFeasibility
    
    # Test crypto barrier suggestions
    result = DoSValidationResult(
        is_exploitable=False,
        feasibility=DoSFeasibility.CRYPTOGRAPHIC_BARRIER,
        confidence=0.9,
        reasoning="Test",
        barriers=[]
    )
    
    steps = validator.suggest_verification_steps(vulnerability, result)
    
    print("\n=== Verification Steps for Crypto Barrier ===")
    for step in steps:
        print(f"  {step}")
    
    assert any('cryptographic' in step.lower() for step in steps)
    assert any('validation' in step.lower() for step in steps)
    
    print("\n✓ PASS: Provides helpful verification steps")
    return True


if __name__ == "__main__":
    print("=" * 70)
    print("Testing DoS Feasibility Validator")
    print("=" * 70)
    
    results = []
    
    # Test 1: Snowbridge false positive
    results.append(("Snowbridge False Positive", test_snowbridge_false_positive()))
    
    # Test 2: Real exploitable DoS
    results.append(("Real Exploitable DoS", test_actual_exploitable_dos()))
    
    # Test 3: Economic barrier
    results.append(("Economic Barrier Detection", test_economic_barrier()))
    
    # Test 4: Verification suggestions
    results.append(("Verification Suggestions", test_validation_suggestions()))
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    total = len(results)
    passed_count = sum(1 for _, p in results if p)
    
    print(f"\nTotal: {passed_count}/{total} tests passed")
    
    if passed_count == total:
        print("\n🎉 All tests passed! DoS validation working correctly.")
        sys.exit(0)
    else:
        print(f"\n❌ {total - passed_count} test(s) failed.")
        sys.exit(1)

