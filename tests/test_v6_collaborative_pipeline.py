"""Tests for v6.0 Collaborative Agent Pipeline with Shared SAGE Memory.

Tests the SAGE session memory integration in the deep analysis pipeline:
  - Session store and recall between passes
  - Dismissal propagation preventing re-flagging
  - Challenge mechanism overriding dismissals
  - Confirmation boosting finding confidence
  - SAGE required — fail fast when unavailable
  - Session context formatting for LLM prompts
  - Cross-contract mitigation propagation
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from core.deep_analysis_engine import (
    DeepAnalysisEngine,
    DeepAnalysisResult,
    PassResult,
    _build_pass3_prompt,
    _build_pass3_5_prompt,
    _build_pass4_prompt,
    _build_pass5_prompt,
    _content_hash,
)
from core.protocol_archetypes import (
    ArchetypeResult,
    ProtocolArchetype,
)


SAMPLE_CONTRACT = """
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SimpleVault is ERC4626 {
    constructor(IERC20 asset_) ERC4626(asset_) ERC20("Vault", "vTKN") {}

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        return super.deposit(assets, receiver);
    }
}
"""


def _make_pass_response(findings=None, dismissals=None, protections=None,
                         challenges=None, confirmations=None):
    """Helper to build a valid LLM pass response JSON string."""
    data = {"findings": findings or []}
    if dismissals is not None:
        data["dismissals"] = dismissals
    if protections is not None:
        data["protections_verified"] = protections
    if challenges is not None:
        data["challenges"] = challenges
    if confirmations is not None:
        data["confirmations"] = confirmations
    return json.dumps(data)


def _mock_sage_client(healthy=True):
    """Create a mock SageClient with controllable health and session storage."""
    client = MagicMock()
    client.health_check.return_value = healthy
    client._session_store = {}  # domain -> list of content strings

    def remember_session(content, session_domain):
        if session_domain not in client._session_store:
            client._session_store[session_domain] = []
        client._session_store[session_domain].append(content)
        return {"memory_id": f"mem-{len(client._session_store[session_domain])}", "status": "proposed"}

    def recall_session(session_domain):
        contents = client._session_store.get(session_domain, [])
        return [
            {"content": c, "confidence": 0.9, "memory_id": f"mem-{i}", "domain": session_domain}
            for i, c in enumerate(contents)
        ]

    client.remember_session.side_effect = remember_session
    client.recall_session.side_effect = recall_session
    # Also mock the standard recall for _build_sage_context
    client.recall.return_value = []
    return client


class TestSessionStoreAndRecall(unittest.TestCase):
    """Test that pass results are stored in SAGE and recalled by subsequent passes."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-test123"

    def test_store_findings_in_session(self):
        """After a finding pass, findings should be stored in SAGE session."""
        raw_response = _make_pass_response(
            findings=[{
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.85,
                "title": "Reentrancy in withdraw",
                "description": "Missing nonReentrant guard",
                "affected_functions": ["withdraw"],
                "line": 42,
            }],
            dismissals=[{
                "concern": "reentrancy in getBalance",
                "vuln_type": "reentrancy",
                "affected_functions": ["getBalance"],
                "reason": "view function",
                "protections_found": ["view modifier"],
                "confidence_in_dismissal": 0.95,
            }],
            protections=[{
                "type": "access_control",
                "mechanism": "onlyOwner on setFee",
                "functions": ["setFee"],
                "bypassed": False,
            }],
        )

        findings = self.engine._extract_findings(raw_response, "pass3")
        self.engine._store_pass_session("pass3", raw_response, findings)

        # Verify SAGE was called with session domain
        self.assertTrue(self.sage.remember_session.called)
        stored = self.sage._session_store["audit-session-test123"]
        self.assertEqual(len(stored), 1)

        record = json.loads(stored[0])
        self.assertEqual(record["pass"], "pass3")
        self.assertEqual(len(record["findings"]), 1)
        self.assertEqual(record["findings"][0]["vuln_type"], "reentrancy")
        self.assertEqual(len(record["dismissals"]), 1)
        self.assertEqual(record["dismissals"][0]["dismissed_concern"], "reentrancy in getBalance")
        self.assertEqual(len(record["protections"]), 1)
        self.assertEqual(record["protections"][0]["mechanism"], "onlyOwner on setFee")

    def test_recall_session_context(self):
        """Session context should be formatted from stored records."""
        # Pre-populate session store
        record = {
            "pass": "pass3",
            "findings": [{
                "record_type": "finding",
                "finding_id": "pass3-001",
                "vuln_type": "reentrancy",
                "severity": "high",
                "confidence": 0.85,
                "affected_functions": ["withdraw"],
                "title": "Reentrancy in withdraw",
                "summary": "Missing nonReentrant",
            }],
            "dismissals": [{
                "record_type": "dismissal",
                "pass": "pass3",
                "dismissed_concern": "reentrancy in getBalance",
                "vuln_type": "reentrancy",
                "reason": "view function",
                "protections_found": ["view modifier"],
                "confidence_in_dismissal": 0.95,
                "affected_functions": ["getBalance"],
            }],
            "protections": [{
                "record_type": "protection",
                "pass": "pass3",
                "protection_type": "access_control",
                "mechanism": "onlyOwner on setFee",
                "scope": ["setFee"],
                "bypassed": False,
            }],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-test123"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass4")
        self.assertIn("Prior Pass Intelligence", context)
        self.assertIn("Confirmed Findings", context)
        self.assertIn("Reentrancy in withdraw", context)
        self.assertIn("DO NOT re-report", context)
        self.assertIn("Dismissed Concerns", context)
        self.assertIn("reentrancy in getBalance", context)
        self.assertIn("DO NOT re-flag", context)
        self.assertIn("Verified Protections", context)
        self.assertIn("onlyOwner on setFee", context)


class TestDismissalPreventsReflag(unittest.TestCase):
    """Test that a Pass 3 dismissal is surfaced to Pass 5 with instructions not to re-flag."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-dismiss"

    def test_dismissal_in_session_context(self):
        """Dismissals should appear with 'DO NOT re-flag' instruction."""
        record = {
            "pass": "pass3",
            "findings": [],
            "dismissals": [{
                "record_type": "dismissal",
                "pass": "pass3",
                "dismissed_concern": "Oracle manipulation via Chainlink",
                "vuln_type": "oracle_manipulation",
                "reason": "Off-chain oracle with staleness check present",
                "protections_found": ["staleness check: require(block.timestamp - updatedAt < 3600)"],
                "confidence_in_dismissal": 0.92,
                "affected_functions": ["getPrice"],
            }],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-dismiss"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass5")
        self.assertIn("Oracle manipulation via Chainlink", context)
        self.assertIn("DO NOT re-flag", context)
        self.assertIn("92%", context)  # confidence formatted as percentage


class TestChallengeOverridesDismissal(unittest.TestCase):
    """Test that a later pass can challenge and override an earlier dismissal."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-challenge"

    def test_challenge_marks_dismissal_as_overridden(self):
        """When Pass 4 challenges a Pass 3 dismissal, it should appear as overridden."""
        # Pass 3 record with a dismissal
        pass3_record = {
            "pass": "pass3",
            "findings": [],
            "dismissals": [{
                "record_type": "dismissal",
                "pass": "pass3",
                "dismissed_concern": "reentrancy in deposit",
                "vuln_type": "reentrancy",
                "reason": "CEI pattern followed",
                "protections_found": ["CEI ordering"],
                "confidence_in_dismissal": 0.80,
                "affected_functions": ["deposit"],
            }],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }

        # Pass 4 record with a challenge
        pass4_record = {
            "pass": "pass4",
            "findings": [{
                "record_type": "finding",
                "finding_id": "pass4-001",
                "vuln_type": "reentrancy",
                "severity": "high",
                "confidence": 0.88,
                "affected_functions": ["deposit"],
                "title": "Cross-function reentrancy via deposit callback",
                "summary": "ERC-777 callback in deposit violates CEI across functions",
            }],
            "dismissals": [],
            "protections": [],
            "challenges": [{
                "target_concern": "reentrancy in deposit",
                "new_evidence": "ERC-777 callback before state update enables cross-function reentrancy",
                "proposed_change": "re-flag as high severity finding",
            }],
            "confirmations": [],
        }

        self.sage._session_store["audit-session-challenge"] = [
            json.dumps(pass3_record),
            json.dumps(pass4_record),
        ]

        # Build context for Pass 5 — the challenged dismissal should be marked
        context = self.engine._build_session_context("pass5")
        self.assertIn("Challenged Dismissals", context)
        self.assertIn("reentrancy in deposit", context)
        self.assertIn("OVERRIDDEN", context)

    def test_resolve_challenges_processes_challenges(self):
        """_resolve_challenges should process challenge records."""
        pass4_record = {
            "pass": "pass4",
            "findings": [],
            "dismissals": [],
            "protections": [],
            "challenges": [{
                "target_concern": "reentrancy in deposit",
                "new_evidence": "ERC-777 callback enables reentrancy",
                "proposed_change": "re-flag as finding",
            }],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-challenge"] = [json.dumps(pass4_record)]

        findings = [{"title": "other bug", "confidence": 0.7, "severity": "medium"}]
        result = self.engine._resolve_challenges(findings)
        # The findings list should be returned (challenges are informational,
        # the actual finding was created in pass4's finding-producing pass)
        self.assertEqual(len(result), 1)


class TestConfirmationBoostsConfidence(unittest.TestCase):
    """Test that when Pass 5 confirms a Pass 3 finding, confidence increases."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-confirm"

    def test_confirmation_boosts_confidence(self):
        """Confirmed findings should get a 15% confidence boost."""
        pass5_record = {
            "pass": "pass5",
            "findings": [],
            "dismissals": [],
            "protections": [],
            "challenges": [],
            "confirmations": ["First Depositor Attack"],
        }
        self.sage._session_store["audit-session-confirm"] = [json.dumps(pass5_record)]

        findings = [
            {"title": "First Depositor Attack", "confidence": 0.80, "severity": "critical"},
            {"title": "Unrelated Bug", "confidence": 0.60, "severity": "medium"},
        ]

        result = self.engine._resolve_challenges(findings)

        # First finding should be boosted
        confirmed_finding = next(f for f in result if f["title"] == "First Depositor Attack")
        self.assertAlmostEqual(confirmed_finding["confidence"], min(1.0, 0.80 * 1.15), places=3)
        self.assertTrue(confirmed_finding.get("cross_confirmed"))

        # Second finding should be unchanged
        unrelated = next(f for f in result if f["title"] == "Unrelated Bug")
        self.assertAlmostEqual(unrelated["confidence"], 0.60, places=3)
        self.assertFalse(unrelated.get("cross_confirmed", False))


class TestSageRequiredFailsFast(unittest.TestCase):
    """Test that when SAGE is down, the audit fails with a clear message."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)

    @patch('core.deep_analysis_engine.SageClient', create=True)
    def test_sage_unavailable_raises_runtime_error(self, mock_sage_cls):
        """Pipeline should raise RuntimeError when SAGE health check fails."""
        mock_sage = MagicMock()
        mock_sage.health_check.return_value = False

        with patch('core.sage_client.SageClient.get_instance', return_value=mock_sage):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(self.engine.analyze(
                    SAMPLE_CONTRACT,
                    [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
                    {'vulnerabilities': []},
                ))
            self.assertIn("SAGE institutional memory is required", str(ctx.exception))
            self.assertIn("docker compose up -d", str(ctx.exception))

    @patch('core.sage_client.SageClient.get_instance')
    def test_sage_sdk_missing_raises_runtime_error(self, mock_get_instance):
        """Pipeline should raise RuntimeError when sage-agent-sdk is not installed."""
        mock_get_instance.side_effect = ImportError("No module named 'sage_sdk'")

        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(self.engine.analyze(
                SAMPLE_CONTRACT,
                [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
                {'vulnerabilities': []},
            ))
        self.assertIn("SAGE institutional memory is required", str(ctx.exception))


class TestSessionContextFormatting(unittest.TestCase):
    """Test that the Prior Pass Intelligence section is well-formatted."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-format"

    def test_empty_session_returns_empty_string(self):
        """No session records should produce empty context."""
        context = self.engine._build_session_context("pass4")
        self.assertEqual(context, "")

    def test_findings_section_format(self):
        """Findings should show ID, severity, title, affected functions."""
        record = {
            "pass": "pass3",
            "findings": [{
                "finding_id": "pass3-001",
                "vuln_type": "reentrancy",
                "severity": "critical",
                "confidence": 0.92,
                "affected_functions": ["withdraw", "deposit"],
                "title": "CEI violation in withdraw",
                "summary": "Missing checks-effects-interactions pattern",
            }],
            "dismissals": [],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-format"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass4")
        self.assertIn("[pass3-001]", context)
        self.assertIn("[CRITICAL]", context)
        self.assertIn("CEI violation in withdraw", context)
        self.assertIn("withdraw, deposit", context)
        self.assertIn("92%", context)

    def test_protections_format(self):
        """Protections should show mechanism, scope, and HOLDS/BYPASSED status."""
        record = {
            "pass": "pass3",
            "findings": [],
            "dismissals": [],
            "protections": [
                {"mechanism": "nonReentrant on deposit", "scope": ["deposit"], "bypassed": False},
                {"mechanism": "onlyOwner on setFee", "scope": ["setFee"], "bypassed": True},
            ],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-format"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass4")
        self.assertIn("nonReentrant on deposit", context)
        self.assertIn("HOLDS", context)
        self.assertIn("BYPASSED", context)

    def test_multiple_passes_accumulate(self):
        """Session context should include records from all prior passes."""
        pass3_record = {
            "pass": "pass3",
            "findings": [{"finding_id": "pass3-001", "severity": "high",
                          "title": "Bug A", "affected_functions": ["a"], "confidence": 0.8}],
            "dismissals": [],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }
        pass35_record = {
            "pass": "pass3.5",
            "findings": [{"finding_id": "pass3.5-001", "severity": "medium",
                          "title": "Bug B", "affected_functions": ["b"], "confidence": 0.7}],
            "dismissals": [{"dismissed_concern": "false alarm X", "pass": "pass3.5",
                            "reason": "safe", "confidence_in_dismissal": 0.9,
                            "affected_functions": ["x"]}],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-format"] = [
            json.dumps(pass3_record), json.dumps(pass35_record),
        ]

        context = self.engine._build_session_context("pass4")
        self.assertIn("Bug A", context)
        self.assertIn("Bug B", context)
        self.assertIn("false alarm X", context)

    def test_budget_truncation(self):
        """Very large session contexts should be truncated to budget."""
        huge_findings = []
        for i in range(500):
            huge_findings.append({
                "finding_id": f"pass3-{i:03d}",
                "severity": "high",
                "title": f"Finding number {i} with a very long title to inflate the context size significantly beyond the budget",
                "affected_functions": [f"func_{i}"],
                "confidence": 0.8,
                "summary": "x" * 200,
            })
        record = {
            "pass": "pass3",
            "findings": huge_findings,
            "dismissals": [],
            "protections": [],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-format"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass4")
        # Should be truncated to 40K chars
        self.assertLessEqual(len(context), 41000)  # Some slack for truncation message


class TestCrossContractMitigationPropagation(unittest.TestCase):
    """Test that Pass 3.5 mitigations propagate to Pass 4 via session context."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-crosscontract"

    def test_cross_contract_protection_reaches_pass4(self):
        """Pass 3.5 cross-contract protection should appear in Pass 4 context."""
        pass35_record = {
            "pass": "pass3.5",
            "findings": [],
            "dismissals": [{
                "record_type": "dismissal",
                "pass": "pass3.5",
                "dismissed_concern": "read-only reentrancy via PriceOracle",
                "vuln_type": "cross_contract_reentrancy",
                "reason": "Oracle uses snapshot values updated before external call",
                "protections_found": ["snapshot pattern in oracle"],
                "confidence_in_dismissal": 0.88,
                "affected_functions": ["PriceOracle.getSharePrice"],
            }],
            "protections": [{
                "record_type": "protection",
                "pass": "pass3.5",
                "protection_type": "reentrancy_guard",
                "mechanism": "shared ReentrancyGuard across Vault and Router",
                "scope": ["Vault.withdraw", "Router.swap"],
                "bypassed": False,
            }],
            "challenges": [],
            "confirmations": [],
        }
        self.sage._session_store["audit-session-crosscontract"] = [
            json.dumps(pass35_record),
        ]

        context = self.engine._build_session_context("pass4")
        self.assertIn("read-only reentrancy via PriceOracle", context)
        self.assertIn("shared ReentrancyGuard across Vault and Router", context)
        self.assertIn("HOLDS", context)


class TestPromptBuilderSessionContext(unittest.TestCase):
    """Test that prompt builders correctly incorporate session_context parameter."""

    def test_pass3_prompt_includes_session_context(self):
        """Pass 3 prompt should include session context when provided."""
        archetype = ArchetypeResult(primary=ProtocolArchetype.VAULT_ERC4626, confidence=0.8)
        prompt = _build_pass3_prompt(
            "contract Test {}", "{}", "{}",
            "## Checklist\n- Item 1",
            session_context="## Prior Pass Intelligence\n- Finding 1",
        )
        self.assertIn("Prior Pass Intelligence", prompt)
        self.assertIn("Finding 1", prompt)

    def test_pass3_prompt_without_session_context(self):
        """Pass 3 prompt should work without session context."""
        prompt = _build_pass3_prompt(
            "contract Test {}", "{}", "{}",
            "## Checklist\n- Item 1",
        )
        self.assertNotIn("Prior Pass Intelligence", prompt)
        self.assertIn("Checklist", prompt)

    def test_pass35_prompt_includes_session_context(self):
        """Pass 3.5 prompt should include session context when provided."""
        prompt = _build_pass3_5_prompt(
            "contract Test {}", "{}", "{}",
            "findings", "cc_context",
            session_context="## Session data here",
        )
        self.assertIn("Session data here", prompt)

    def test_pass4_prompt_includes_session_and_challenge(self):
        """Pass 4 prompt should include session context AND challenge protocol."""
        prompt = _build_pass4_prompt(
            "contract Test {}", "{}", "{}",
            session_context="## Prior Pass Intelligence\n- Some finding",
        )
        self.assertIn("Prior Pass Intelligence", prompt)
        self.assertIn("Challenge Protocol", prompt)
        self.assertIn("DISAGREE with a prior dismissal", prompt)

    def test_pass4_prompt_without_session_no_challenge(self):
        """Pass 4 prompt should NOT include challenge protocol when no session."""
        prompt = _build_pass4_prompt("contract Test {}", "{}", "{}")
        self.assertNotIn("Challenge Protocol", prompt)

    def test_pass5_prompt_includes_session_and_challenge(self):
        """Pass 5 prompt should include session context AND challenge protocol."""
        prompt = _build_pass5_prompt(
            "contract Test {}", "{}", "{}", "", "", "",
            session_context="## Prior Pass Intelligence\n- Some finding",
        )
        self.assertIn("Prior Pass Intelligence", prompt)
        self.assertIn("Challenge Protocol", prompt)

    def test_pass5_prompt_without_session_no_challenge(self):
        """Pass 5 prompt should NOT include challenge protocol when no session."""
        prompt = _build_pass5_prompt("contract Test {}", "{}", "{}", "", "", "")
        self.assertNotIn("Challenge Protocol", prompt)


class TestOutputSchemaFields(unittest.TestCase):
    """Test that prompt output schemas include dismissals, protections, challenges."""

    def test_pass3_schema_includes_dismissals(self):
        """Pass 3 prompt should request dismissals in output schema."""
        prompt = _build_pass3_prompt("contract Test {}", "{}", "{}", "checklist")
        self.assertIn('"dismissals"', prompt)
        self.assertIn('"protections_verified"', prompt)
        self.assertIn("confidence_in_dismissal", prompt)

    def test_pass4_schema_includes_challenges(self):
        """Pass 4 prompt should request challenges in output schema."""
        prompt = _build_pass4_prompt(
            "contract Test {}", "{}", "{}",
            session_context="some context",
        )
        self.assertIn('"challenges"', prompt)
        self.assertIn('"confirmations"', prompt)

    def test_pass5_schema_includes_challenges(self):
        """Pass 5 prompt should request challenges in output schema."""
        prompt = _build_pass5_prompt(
            "contract Test {}", "{}", "{}", "", "", "",
            session_context="some context",
        )
        self.assertIn('"challenges"', prompt)
        self.assertIn('"confirmations"', prompt)


class TestStorePassSessionEdgeCases(unittest.TestCase):
    """Test edge cases in _store_pass_session."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-edge"

    def test_store_empty_findings(self):
        """Storing a pass with no findings should still record dismissals/protections."""
        raw_response = _make_pass_response(
            findings=[],
            dismissals=[{
                "concern": "some concern",
                "vuln_type": "reentrancy",
                "affected_functions": ["func"],
                "reason": "safe",
                "protections_found": ["guard"],
                "confidence_in_dismissal": 0.9,
            }],
        )
        self.engine._store_pass_session("pass3", raw_response, [])

        stored = self.sage._session_store["audit-session-edge"]
        self.assertEqual(len(stored), 1)
        record = json.loads(stored[0])
        self.assertEqual(len(record["findings"]), 0)
        self.assertEqual(len(record["dismissals"]), 1)

    def test_store_with_no_session_domain(self):
        """Should silently skip if session domain is not set."""
        self.engine._session_domain = ""
        self.engine._store_pass_session("pass3", '{"findings": []}', [])
        self.assertFalse(self.sage.remember_session.called)

    def test_store_with_no_sage_client(self):
        """Should silently skip if SAGE client is None."""
        self.engine._sage_client = None
        self.engine._store_pass_session("pass3", '{"findings": []}', [])

    def test_store_invalid_json_response(self):
        """Should handle invalid JSON gracefully."""
        self.engine._store_pass_session("pass3", "not valid json", [{"type": "vuln", "severity": "high"}])
        # Should still store the findings even if raw response parsing fails
        stored = self.sage._session_store["audit-session-edge"]
        self.assertEqual(len(stored), 1)

    def test_store_finding_ids_are_unique_per_pass(self):
        """Each finding in a pass should get a unique finding_id."""
        findings = [
            {"type": "vuln1", "severity": "high", "confidence": 0.8, "title": "Bug A",
             "description": "desc", "affected_functions": ["a"], "line": 1},
            {"type": "vuln2", "severity": "medium", "confidence": 0.7, "title": "Bug B",
             "description": "desc", "affected_functions": ["b"], "line": 2},
        ]
        raw = _make_pass_response([
            {"type": "vuln1", "severity": "high", "confidence": 0.8, "title": "Bug A",
             "description": "desc", "affected_functions": ["a"], "line": 1},
            {"type": "vuln2", "severity": "medium", "confidence": 0.7, "title": "Bug B",
             "description": "desc", "affected_functions": ["b"], "line": 2},
        ])
        self.engine._store_pass_session("pass3", raw, findings)

        stored = json.loads(self.sage._session_store["audit-session-edge"][0])
        ids = [f["finding_id"] for f in stored["findings"]]
        self.assertEqual(len(set(ids)), 2)
        self.assertIn("pass3-001", ids)
        self.assertIn("pass3-002", ids)


class TestBuildSessionContextEdgeCases(unittest.TestCase):
    """Test edge cases in _build_session_context."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.sage = _mock_sage_client()
        self.engine._sage_client = self.sage
        self.engine._session_domain = "audit-session-ctx-edge"

    def test_context_with_no_domain(self):
        """No session domain should return empty string."""
        self.engine._session_domain = ""
        self.assertEqual(self.engine._build_session_context("pass4"), "")

    def test_context_with_no_client(self):
        """No SAGE client should return empty string."""
        self.engine._sage_client = None
        self.assertEqual(self.engine._build_session_context("pass4"), "")

    def test_context_with_corrupt_json(self):
        """Should skip records with invalid JSON."""
        self.sage._session_store["audit-session-ctx-edge"] = [
            "not json",
            json.dumps({
                "pass": "pass3", "findings": [{"finding_id": "p3-001", "severity": "high",
                "title": "Real Bug", "affected_functions": ["f"], "confidence": 0.9}],
                "dismissals": [], "protections": [], "challenges": [], "confirmations": [],
            }),
        ]
        context = self.engine._build_session_context("pass4")
        self.assertIn("Real Bug", context)

    def test_confirmed_findings_get_tag(self):
        """Findings confirmed by later passes should get [CROSS-CONFIRMED] tag."""
        record = {
            "pass": "pass3",
            "findings": [{"finding_id": "p3-001", "severity": "high",
                          "title": "Share Inflation", "affected_functions": ["deposit"],
                          "confidence": 0.85}],
            "dismissals": [],
            "protections": [],
            "challenges": [],
            "confirmations": ["Share Inflation"],  # Same title
        }
        self.sage._session_store["audit-session-ctx-edge"] = [json.dumps(record)]

        context = self.engine._build_session_context("pass4")
        self.assertIn("CROSS-CONFIRMED", context)


class TestRunFindingPassV6(unittest.TestCase):
    """Test the _run_finding_pass_v6 method returns (findings, raw_response)."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)
        self.engine._pipeline_start = 0  # Avoid time budget skip

    def test_returns_tuple(self):
        """Should return (findings, raw_response) tuple."""
        response = _make_pass_response(findings=[
            {"type": "vuln", "severity": "high", "confidence": 0.8,
             "description": "test", "line": 1},
        ])
        self.mock_llm._call_llm.return_value = response
        import time
        self.engine._pipeline_start = time.time()

        result = DeepAnalysisResult(
            archetype=ArchetypeResult(primary=ProtocolArchetype.UNKNOWN, confidence=0.0)
        )
        findings, raw = asyncio.run(
            self.engine._run_finding_pass_v6("Test Pass", "prompt", "model", result)
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(raw, response)

    def test_returns_empty_on_failure(self):
        """Should return ([], '') when LLM returns None."""
        self.mock_llm._call_llm.return_value = None
        import time
        self.engine._pipeline_start = time.time()

        result = DeepAnalysisResult(
            archetype=ArchetypeResult(primary=ProtocolArchetype.UNKNOWN, confidence=0.0)
        )
        findings, raw = asyncio.run(
            self.engine._run_finding_pass_v6("Test Pass", "prompt", "model", result)
        )
        self.assertEqual(findings, [])
        self.assertEqual(raw, "")


class TestSageClientSessionMethods(unittest.TestCase):
    """Test the SageClient session convenience methods."""

    def test_remember_session_calls_remember(self):
        """remember_session should delegate to remember with correct params."""
        from core.sage_client import SageClient
        SageClient.reset_instance()

        client = SageClient()
        client._sdk_checked = True
        client._sdk_client = MagicMock()
        client._sdk_client.propose.return_value = MagicMock(
            memory_id="test-mem", tx_hash="0xabc"
        )

        result = client.remember_session(
            content='{"test": true}',
            session_domain="audit-session-abc",
        )
        self.assertEqual(result["status"], "proposed")
        client._sdk_client.propose.assert_called_once()
        call_kwargs = client._sdk_client.propose.call_args
        self.assertEqual(call_kwargs.kwargs.get("domain_tag") or call_kwargs[1].get("domain_tag", ""),
                         "audit-session-abc")

    def test_recall_session_raises_when_sage_unavailable(self):
        """recall_session should raise RuntimeError when SDK is not available."""
        from core.sage_client import SageClient
        SageClient.reset_instance()

        client = SageClient()
        client._sdk_checked = True
        client._sdk_client = None  # Simulates SDK not available

        with self.assertRaises(RuntimeError) as ctx:
            client.recall_session("audit-session-abc")
        self.assertIn("SAGE institutional memory is required", str(ctx.exception))

    def test_recall_session_returns_memories(self):
        """recall_session should return all memories in the session domain."""
        from core.sage_client import SageClient
        SageClient.reset_instance()

        client = SageClient()
        client._sdk_checked = True

        mock_mem1 = MagicMock()
        mock_mem1.content = '{"pass": "pass3", "findings": []}'
        mock_mem1.confidence_score = 0.9
        mock_mem1.domain_tag = "audit-session-xyz"
        mock_mem1.memory_id = "mem-1"

        mock_mem2 = MagicMock()
        mock_mem2.content = '{"pass": "pass4", "findings": []}'
        mock_mem2.confidence_score = 0.88
        mock_mem2.domain_tag = "audit-session-xyz"
        mock_mem2.memory_id = "mem-2"

        mock_result = MagicMock()
        mock_result.memories = [mock_mem1, mock_mem2]
        client._sdk_client = MagicMock()
        client._sdk_client.list_memories.return_value = mock_result

        memories = client.recall_session("audit-session-xyz")
        self.assertEqual(len(memories), 2)
        self.assertEqual(memories[0]["content"], '{"pass": "pass3", "findings": []}')
        self.assertEqual(memories[1]["content"], '{"pass": "pass4", "findings": []}')


class TestFullPipelineWithSageMocked(unittest.TestCase):
    """Integration test: full pipeline with mocked SAGE and LLM."""

    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)

    @patch('core.sage_client.SageClient.get_instance')
    def test_pipeline_stores_and_recalls_session(self, mock_get_instance):
        """Full pipeline should store session data after each pass and recall before next."""
        sage = _mock_sage_client(healthy=True)
        mock_get_instance.return_value = sage

        pass1_response = json.dumps({
            "protocol_archetype": "vault_erc4626",
            "core_purpose": "ERC-4626 vault",
            "value_flows": [],
            "invariants": [{"id": "INV-1", "description": "totalAssets >= totalSupply",
                            "related_state": ["totalAssets"], "critical": True}],
            "trust_assumptions": [],
            "state_variables": [],
            "external_dependencies": [],
        })
        pass2_response = json.dumps({
            "functions": [{"name": "deposit", "visibility": "public"}],
            "state_dependency_graph": [],
            "privileged_operations": [],
        })
        pass3_response = _make_pass_response(
            findings=[{
                "type": "first_depositor_inflation",
                "severity": "critical",
                "confidence": 0.9,
                "title": "First Depositor Attack",
                "description": "No virtual shares protection",
                "affected_functions": ["deposit"],
                "line": 10,
            }],
            dismissals=[{
                "concern": "reentrancy in totalAssets",
                "vuln_type": "reentrancy",
                "affected_functions": ["totalAssets"],
                "reason": "view function, no state modification",
                "protections_found": ["view modifier"],
                "confidence_in_dismissal": 0.95,
            }],
            protections=[{
                "type": "access_control",
                "mechanism": "ERC4626 standard deposit flow",
                "functions": ["deposit"],
                "bypassed": False,
            }],
        )
        pass4_response = _make_pass_response(
            findings=[],
            confirmations=["First Depositor Attack"],
        )
        pass5_response = _make_pass_response(
            findings=[{
                "type": "donation_attack",
                "severity": "high",
                "confidence": 0.7,
                "title": "Share Price Manipulation",
                "description": "Direct donation inflates totalAssets",
                "affected_functions": ["totalAssets"],
                "line": 9,
            }],
            confirmations=["First Depositor Attack"],
        )

        self.mock_llm._call_llm.side_effect = [
            pass1_response, pass2_response, pass3_response,
            pass4_response, pass5_response,
        ]

        result = asyncio.run(self.engine.analyze(
            SAMPLE_CONTRACT,
            [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
            {'vulnerabilities': []},
        ))

        self.assertIsInstance(result, DeepAnalysisResult)

        # Verify session domain was set
        self.assertTrue(self.engine._session_domain.startswith("audit-session-"))

        # Verify session records were stored (pass3 + pass4 + pass5 = 3 stores)
        domain = self.engine._session_domain
        self.assertEqual(len(sage._session_store.get(domain, [])), 3)

        # Verify findings include the confirmed one with boosted confidence
        critical_findings = [f for f in result.all_findings if f.get("title") == "First Depositor Attack"]
        self.assertTrue(len(critical_findings) >= 1)
        # Confidence should have been boosted by confirmation
        for f in critical_findings:
            if f.get("cross_confirmed"):
                self.assertGreater(f["confidence"], 0.9)


if __name__ == '__main__':
    unittest.main()
