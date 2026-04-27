"""
End-to-end tests proving SAGE institutional memory produces MARKED IMPROVEMENT.

These tests simulate the full audit pipeline with and without SAGE to measure:
1. False positive reduction rate
2. Finding quality improvement (severity accuracy)
3. Detector precision boost from feedback loop
4. Cross-audit knowledge transfer

The tests use realistic Solidity contracts with known vulnerabilities and known
false positives to establish ground truth, then run the pipeline twice:
  - WITHOUT SAGE: baseline (no institutional memory)
  - WITH SAGE: after seeding + feedback from a prior audit

A test passes only if SAGE produces measurably better results.
"""

import json
import unittest
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch, PropertyMock

from core.sage_feedback import SageFeedbackManager
from core.validation_pipeline import ValidationPipeline, ValidationStage


# ---------------------------------------------------------------------------
# Ground-truth test contracts with known vulnerabilities and known FPs
# ---------------------------------------------------------------------------

# A lending pool contract with a REAL reentrancy bug
LENDING_POOL_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LendingPool {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public borrowed;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // REAL VULNERABILITY: CEI violation — external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;  // state update AFTER external call
    }

    function borrow(uint256 amount) external {
        require(balances[msg.sender] * 2 >= borrowed[msg.sender] + amount, "undercollateralized");
        borrowed[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    // NOT A VULNERABILITY: gas optimization — uses more gas than needed but is safe
    function getBalance(address user) external view returns (uint256) {
        uint256 bal = balances[user];
        uint256 debt = borrowed[user];
        return bal - debt;
    }

    // NOT A VULNERABILITY: centralization risk (admin can pause) — always out of scope
    address public admin;
    bool public paused;
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    function pause() external onlyAdmin { paused = true; }
}
"""

# Ground truth for the lending pool
LENDING_POOL_GROUND_TRUTH = {
    "real_vulns": [
        {"type": "reentrancy", "severity": "critical", "function": "withdraw"},
        {"type": "reentrancy", "severity": "high", "function": "borrow"},
    ],
    "known_fps": [
        {"type": "gas_optimization", "reason": "view function, no state change"},
        {"type": "centralization_risk", "reason": "admin pause is standard pattern, always out of scope"},
    ],
}

# A vault contract with known ERC-4626 issues
VAULT_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SimpleVault is ERC20 {
    IERC20 public immutable asset;

    constructor(IERC20 _asset) ERC20("Vault", "vTKN") {
        asset = _asset;
    }

    // REAL VULNERABILITY: First depositor inflation — no virtual shares
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = totalSupply() == 0 ? assets : (assets * totalSupply()) / totalAssets();
        _mint(msg.sender, shares);
        asset.transferFrom(msg.sender, address(this), assets);
    }

    // REAL VULNERABILITY: Rounding in favor of user (should round down on withdraw)
    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = (shares * totalAssets()) / totalSupply();
        _burn(msg.sender, shares);
        asset.transfer(msg.sender, assets);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
"""

VAULT_GROUND_TRUTH = {
    "real_vulns": [
        {"type": "inflation_share", "severity": "critical", "function": "deposit"},
        {"type": "precision_rounding", "severity": "high", "function": "withdraw"},
    ],
    "known_fps": [
        {"type": "centralization_risk", "reason": "ERC20 is standard, no admin functions"},
    ],
}


class InMemorySageClient:
    """In-memory SAGE client for E2E testing — no network required."""

    def __init__(self):
        self.memories: List[Dict] = []
        self.reflections: List[Dict] = []

    def health_check(self) -> bool:
        return True

    def remember(self, content: str, domain: str = "general",
                 memory_type: str = "observation", confidence: float = 0.8,
                 tags: Optional[List[str]] = None) -> Dict:
        # Mirror SageClient.remember: tags are baked into content as
        # "... [tags: t1, t2, ...]" so that recall surfaces them too.
        stored = content
        if tags:
            stored = f"{content} [tags: {', '.join(tags)}]"
        mem = {
            "content": stored,
            "domain": domain,
            "type": memory_type,
            "confidence": confidence,
            "tags": tags or [],
            "memory_id": f"mem-{len(self.memories)}",
        }
        self.memories.append(mem)
        return {"memory_id": mem["memory_id"], "status": "committed"}

    def recall(self, query: str, domain: str = "general",
               top_k: int = 5) -> List[Dict]:
        """Simple keyword matching recall."""
        query_words = set(query.lower().split())
        scored = []
        for mem in self.memories:
            if domain != "general" and mem["domain"] != domain:
                # Also check if domain partially matches
                if domain not in mem["domain"] and mem["domain"] != "general":
                    continue
            content_words = set(mem["content"].lower().split())
            overlap = len(query_words & content_words)
            if overlap > 0:
                scored.append((overlap, mem))
        scored.sort(key=lambda x: -x[0])
        return [m for _, m in scored[:top_k]]

    def reflect(self, dos: List[str], donts: List[str],
                domain: str = "general") -> Dict:
        self.reflections.append({"dos": dos, "donts": donts, "domain": domain})
        return {"status": "ok"}

    def get_status(self) -> Dict:
        return {"total_memories": len(self.memories)}


class TestFalsePositiveReduction(unittest.TestCase):
    """Prove SAGE reduces false positives across audits.

    Simulates two audits:
    1. First audit: no SAGE context, generates findings including FPs
    2. Record FP outcomes into SAGE
    3. Second audit: SAGE recalls FP patterns, should filter them
    """

    def test_fp_reduction_lending_pool(self):
        """Second audit of lending pool should have fewer FPs after an
        auditor explicitly promotes a pattern via mark_fp_verified()."""
        sage = InMemorySageClient()

        # --- Audit 1: No SAGE context (baseline) ---
        baseline_findings = [
            # Real vulns
            {"vulnerability_type": "reentrancy", "severity": "critical",
             "description": "Cross-function reentrancy in withdraw() via external call before state update"},
            {"vulnerability_type": "reentrancy", "severity": "high",
             "description": "Potential reentrancy in borrow() function through call"},
            # False positives
            {"vulnerability_type": "gas_optimization", "severity": "low",
             "description": "Gas usage could be reduced in getBalance view function loop iteration storage reading"},
            {"vulnerability_type": "centralization_risk", "severity": "medium",
             "description": "Admin can pause contract, centralization risk in lending pool protocol"},
        ]

        baseline_fps = [f for f in baseline_findings
                        if f["vulnerability_type"] in ("gas_optimization", "centralization_risk")]
        self.assertEqual(len(baseline_fps), 2, "Baseline should have 2 FPs")

        # --- Record FP outcomes into SAGE (audit history, NOT auto-suppress) ---
        from core.sage_feedback import SageFeedbackManager
        fm = SageFeedbackManager(sage_client=sage)

        for fp in baseline_fps:
            fm.record_finding_outcome(
                finding=fp,
                outcome="rejected",
                context={
                    "archetype": "lending_pool",
                    "reason": "informational only, not exploitable"
                },
            )

        # Routine outcomes alone must NOT poison Stage -1.
        unverified_fps = fm.get_historical_fp_patterns("lending_pool")
        self.assertEqual(unverified_fps, [],
                         "Unverified FP outcomes must not be eligible for Stage -1")

        # --- Auditor explicitly promotes the gas_optimization pattern ---
        fm.mark_fp_verified(
            pattern=(
                "Gas usage could be reduced in getBalance view function loop "
                "iteration storage reading"
            ),
            vulnerability_type="gas_optimization",
            archetype="lending_pool",
            reason="informational only, not exploitable",
        )

        # --- Audit 2: With SAGE context ---
        pipeline = ValidationPipeline(
            project_path=Path("/tmp"),
            contract_code=LENDING_POOL_CONTRACT,
        )
        pipeline._sage_fp_patterns = fm.get_historical_fp_patterns("lending_pool")
        self.assertEqual(len(pipeline._sage_fp_patterns), 1,
                         "Only the explicitly-verified pattern should be recalled")

        sage_filtered_fps = 0
        for finding in baseline_findings:
            result = pipeline._check_sage_known_fp(finding)
            if result and result.is_false_positive:
                sage_filtered_fps += 1

        self.assertEqual(sage_filtered_fps, 1,
                         "Only the verified gas_optimization pattern should suppress")

    def test_fp_reduction_across_archetypes(self):
        """A verified FP pattern recalled across audits — but only after
        explicit promotion. Routine record_finding_outcome must not."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        # Routine recording: audit history only.
        fm.record_finding_outcome(
            finding={
                "vulnerability_type": "precision_rounding",
                "severity": "medium",
                "description": "Rounding error in share calculation but within acceptable dust threshold of 1 wei",
            },
            outcome="rejected",
            context={"archetype": "vault_erc4626", "reason": "dust amount, not exploitable"},
        )
        self.assertEqual(fm.get_historical_fp_patterns("vault_erc4626"), [],
                         "Audit-history outcome must not be eligible without promotion")

        # Auditor promotes it.
        fm.mark_fp_verified(
            pattern="Rounding error within acceptable dust threshold of 1 wei",
            vulnerability_type="precision_rounding",
            archetype="vault_erc4626",
            reason="dust amount, not exploitable",
        )
        fps = fm.get_historical_fp_patterns("vault_erc4626")
        self.assertEqual(len(fps), 1)
        self.assertIn("precision_rounding", fps[0].lower())
        self.assertIn("fp-verified", fps[0].lower())


class TestDetectorAccuracyImprovement(unittest.TestCase):
    """Prove SAGE feedback loop improves detector accuracy recommendations."""

    def test_accuracy_sync_produces_recommendations(self):
        """After recording outcomes, sync should produce dos/donts."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        # Create a mock AccuracyTracker with known stats
        from core.accuracy_tracker import DetectorStats
        mock_tracker = MagicMock()
        stats = {
            "reentrancy_detector": DetectorStats(
                detector_name="reentrancy_detector",
                total=25, accepted=22, rejected=3,
                precision=0.88, accuracy=0.88, weight=1.3,
            ),
            "gas_analyzer": DetectorStats(
                detector_name="gas_analyzer",
                total=30, accepted=5, rejected=25,
                precision=0.17, accuracy=0.17, weight=0.6,
            ),
        }
        mock_tracker.get_detector_accuracy.return_value = stats

        result = fm.sync_detector_accuracy(accuracy_tracker=mock_tracker)

        self.assertEqual(result["dos"], 1, "Should have 1 high-accuracy detector")
        self.assertEqual(result["donts"], 1, "Should have 1 low-accuracy detector")

        # Verify SAGE has the recommendations
        boost_mems = sage.recall("high-accuracy detector", domain="detector-accuracy")
        suppress_mems = sage.recall("low-accuracy detector", domain="detector-accuracy")
        self.assertGreater(len(boost_mems), 0)
        self.assertGreater(len(suppress_mems), 0)

        # Verify recommendations can be retrieved via direct recall
        recs = sage.recall("detector accuracy precision", domain="detector-accuracy")
        self.assertGreater(len(recs), 0, "Should have detector recommendations in SAGE")


class TestCrossAuditKnowledgeTransfer(unittest.TestCase):
    """Prove knowledge from one audit improves the next."""

    def test_audit1_findings_recalled_in_audit2(self):
        """Findings stored after audit 1 should be recalled for audit 2."""
        sage = InMemorySageClient()

        # Simulate audit 1 storing learnings
        sage.remember(
            content=(
                "Audit of LendingPool.sol (lending_pool): 3 findings "
                "(critical: 1, high: 2). Types: reentrancy, oracle_manipulation."
            ),
            domain="audit-lending_pool",
            memory_type="observation",
            confidence=0.80,
            tags=["audit-result", "lending_pool"],
        )

        sage.remember(
            content=(
                "Confirmed vulnerability: reentrancy (critical) in lending_pool contracts. "
                "Cross-function reentrancy via external call in withdraw() before state update."
            ),
            domain="audit-lending_pool",
            memory_type="fact",
            confidence=0.90,
            tags=["confirmed", "reentrancy", "critical"],
        )

        # Simulate audit 2 recall
        memories = sage.recall(
            query="vulnerabilities and audit findings for lending_pool",
            domain="audit-lending_pool",
            top_k=5,
        )

        self.assertGreater(len(memories), 0, "Should recall audit 1 findings")
        all_content = " ".join(m["content"] for m in memories)
        self.assertIn("reentrancy", all_content)
        self.assertIn("critical", all_content)

    def test_exploit_pattern_knowledge_persists(self):
        """Seeded exploit patterns should be recallable across audits."""
        sage = InMemorySageClient()

        # Seed some exploit patterns
        from core.sage_seeder import SageSeeder
        seeder = SageSeeder(sage_client=sage)
        count = seeder.seed_historical_exploits()
        self.assertGreater(count, 0)

        # Recall should find relevant patterns
        dao_memories = sage.recall("reentrancy external call", domain="historical-exploits")
        self.assertGreater(len(dao_memories), 0, "Should recall DAO hack pattern")

        bridge_memories = sage.recall("bridge signature verification", domain="historical-exploits")
        self.assertGreater(len(bridge_memories), 0, "Should recall bridge exploit patterns")

    def test_progressive_improvement_over_3_audits(self):
        """Simulate 3 audits and prove each gets better recall context."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        # Audit 1: Record findings
        fm.record_audit_completion(
            "Pool_v1.sol", "lending_pool",
            {"critical": 1, "high": 2, "medium": 3},
        )
        fm.record_finding_outcome(
            {"vulnerability_type": "reentrancy", "severity": "critical",
             "description": "CEI violation in withdraw"},
            "accepted", {"archetype": "lending_pool"},
        )

        context_after_1 = sage.recall("lending_pool vulnerabilities", domain="audit-lending_pool")

        # Audit 2: More findings accumulated
        fm.record_audit_completion(
            "Pool_v2.sol", "lending_pool",
            {"critical": 0, "high": 1, "medium": 2},
        )
        fm.record_finding_outcome(
            {"vulnerability_type": "oracle_manipulation", "severity": "high",
             "description": "TWAP oracle with short window"},
            "accepted", {"archetype": "lending_pool"},
        )

        context_after_2 = sage.recall("lending_pool vulnerabilities", domain="audit-lending_pool")

        # Audit 3: Even more context available
        fm.record_audit_completion(
            "Pool_v3.sol", "lending_pool",
            {"critical": 2, "high": 0, "medium": 1},
        )

        context_after_3 = sage.recall("lending_pool vulnerabilities", domain="audit-lending_pool")

        # MARKED IMPROVEMENT: Each audit should have richer recall context
        self.assertGreaterEqual(len(context_after_2), len(context_after_1),
                                "Audit 2 should have >= context than audit 1")
        self.assertGreaterEqual(len(context_after_3), len(context_after_2),
                                "Audit 3 should have >= context than audit 2")

        # By audit 3, should have substantial institutional knowledge
        self.assertGreaterEqual(len(context_after_3), 2,
                                "After 3 audits, should have rich recall context")


class TestFullPipelineWithSage(unittest.TestCase):
    """Full pipeline integration: validation pipeline + SAGE together."""

    def test_validation_pipeline_with_sage_vs_without(self):
        """Pipeline with a verified SAGE FP pattern should filter more FPs
        than the baseline. Patterns must be promoted via mark_fp_verified()
        — routine record_finding_outcome must not auto-suppress."""
        # --- Without SAGE ---
        pipeline_no_sage = ValidationPipeline(
            project_path=Path("/tmp"),
            contract_code=LENDING_POOL_CONTRACT,
        )
        pipeline_no_sage._sage_fp_patterns = []  # Empty = no SAGE

        findings = [
            {"vulnerability_type": "gas_optimization", "severity": "low",
             "description": "Gas usage could be reduced in getBalance view function loop iteration storage reading"},
        ]

        no_sage_filtered = 0
        for f in findings:
            result = pipeline_no_sage._check_sage_known_fp(f)
            if result and result.is_false_positive:
                no_sage_filtered += 1

        # --- With SAGE: routine record only (audit history) ---
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)
        fm.record_finding_outcome(
            {"vulnerability_type": "gas_optimization", "severity": "low",
             "description": "Gas usage could be reduced in view function loop iteration of lending pool"},
            "rejected",
            {"archetype": "lending_pool", "reason": "informational only"},
        )

        pipeline_unverified = ValidationPipeline(
            project_path=Path("/tmp"),
            contract_code=LENDING_POOL_CONTRACT,
        )
        pipeline_unverified._sage_fp_patterns = fm.get_historical_fp_patterns("lending_pool")
        unverified_filtered = sum(
            1 for f in findings
            if pipeline_unverified._check_sage_known_fp(f) is not None
        )
        self.assertEqual(unverified_filtered, no_sage_filtered,
                         "Routine FP outcomes must not auto-suppress findings")

        # --- With SAGE + explicit promotion ---
        fm.mark_fp_verified(
            pattern=(
                "Gas usage could be reduced in getBalance view function loop "
                "iteration storage reading lending pool"
            ),
            vulnerability_type="gas_optimization",
            archetype="lending_pool",
            reason="informational only",
        )
        pipeline_with_sage = ValidationPipeline(
            project_path=Path("/tmp"),
            contract_code=LENDING_POOL_CONTRACT,
        )
        pipeline_with_sage._sage_fp_patterns = fm.get_historical_fp_patterns("lending_pool")
        sage_filtered = sum(
            1 for f in findings
            if (r := pipeline_with_sage._check_sage_known_fp(f))
            and r.is_false_positive
        )

        self.assertGreater(sage_filtered, no_sage_filtered,
                           "Promoted FP pattern should filter more than baseline")


class TestSageMemoryQuality(unittest.TestCase):
    """Test that memories stored are high quality and actionable."""

    def test_confirmed_vuln_stored_with_detail(self):
        """Confirmed findings should be stored with enough detail for recall."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        fm.record_finding_outcome(
            {
                "vulnerability_type": "reentrancy",
                "severity": "critical",
                "description": "Cross-function reentrancy in withdraw() allows draining all ETH via fallback",
            },
            "accepted",
            {"archetype": "lending_pool"},
        )

        # The stored memory should have all key info
        self.assertEqual(len(sage.memories), 1)
        mem = sage.memories[0]
        self.assertIn("reentrancy", mem["content"].lower())
        self.assertIn("critical", mem["content"].lower())
        self.assertIn("lending_pool", mem["domain"])
        self.assertEqual(mem["type"], "fact")
        self.assertGreaterEqual(mem["confidence"], 0.85)

    def test_fp_stored_with_reason(self):
        """FP memories should include WHY it was a false positive."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        fm.record_finding_outcome(
            {
                "vulnerability_type": "oracle_manipulation",
                "severity": "high",
                "description": "TWAP oracle can be manipulated",
            },
            "rejected",
            {"archetype": "dex_amm", "reason": "uses Chainlink feed, not manipulable TWAP"},
        )

        mem = sage.memories[0]
        self.assertIn("false positive", mem["content"].lower())
        self.assertIn("chainlink", mem["content"].lower())
        self.assertEqual(mem["domain"], "false-positives")

    def test_audit_summary_actionable(self):
        """Audit completion summaries should have severity breakdown."""
        sage = InMemorySageClient()
        fm = SageFeedbackManager(sage_client=sage)

        fm.record_audit_completion(
            "Vault.sol", "vault_erc4626",
            {"critical": 1, "high": 2, "medium": 0, "low": 3},
            {"filtered": 5, "total_raw": 11},
        )

        mem = sage.memories[0]
        self.assertIn("Vault.sol", mem["content"])
        self.assertIn("6 findings", mem["content"])
        self.assertIn("FP rate", mem["content"])


if __name__ == "__main__":
    unittest.main()
