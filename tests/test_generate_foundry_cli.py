import asyncio
import json
import os
from pathlib import Path

import pytest

from cli.main import AetherCLI
from core.llm_foundry_generator import FoundryTestSuite


@pytest.mark.asyncio
async def test_generate_from_results_creates_manifest(tmp_path, monkeypatch):
    # Arrange: create results.json and a minimal Solidity contract
    out_dir = tmp_path / "gen"
    out_dir.mkdir(parents=True, exist_ok=True)

    contracts_dir = tmp_path / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)

    vuln_sol = contracts_dir / "Vuln.sol"
    vuln_sol.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vuln {
    function foo() public {}
}
""".strip()
    )

    results = {
        "audit": {
            "vulnerabilities": [
                {
                    "title": "Reentrancy",
                    "severity": "high",
                    "file": str(vuln_sol),
                    "line": 42,
                    "description": "Example"
                }
            ]
        }
    }
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(results))

    async def fake_generate_multiple_tests(self, vulnerabilities, contract_code, contract_name, output_dir):
        # Emit a dummy suite pointing to files in output_dir
        test_file = str(Path(output_dir) / f"{contract_name}_test.t.sol")
        exploit_file = str(Path(output_dir) / f"{contract_name}Exploit.sol")
        # touch files
        Path(test_file).parent.mkdir(parents=True, exist_ok=True)
        Path(test_file).write_text("// test")
        Path(exploit_file).write_text("// exploit")
        return [FoundryTestSuite(
            test_file=test_file,
            exploit_contract=exploit_file,
            mock_contracts=[],
            setup_script="",
            validation_tests=[],
            gas_analysis={}
        )]

    # Patch generator to avoid network/LLM
    monkeypatch.setattr(
        "cli.main.LLMFoundryGenerator.generate_multiple_tests",
        fake_generate_multiple_tests,
        raising=True,
    )

    cli = AetherCLI()
    rc = await cli.run_generate_foundry(
        from_results=str(results_path),
        from_report=None,
        out_dir=str(out_dir),
        max_items=5,
        min_severity="low",
        types_filter=None,
        only_consensus=False,
        verbose=False,
    )

    assert rc == 0
    manifest = out_dir / "generated_tests.json"
    assert manifest.exists(), "generated_tests.json should be created"
    data = json.loads(manifest.read_text())
    assert data.get("suites"), "manifest should contain suites"


@pytest.mark.asyncio
async def test_generate_from_report_parses_vulns(tmp_path, monkeypatch):
    # Arrange: create a minimal audit_report.md
    report_dir = tmp_path / "output"
    report_dir.mkdir(parents=True, exist_ok=True)

    contracts_dir = tmp_path / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    vuln_path = contracts_dir / "Wallet.sol"
    vuln_path.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Wallet {
    function deposit() public payable {}
}
""".strip()
    )

    md = f"""# AetherAudit Report

**Generated on:** 2025-10-14 12:00:00

## Vulnerabilities Found

### 1. Missing Access Control

**Severity:** High
**Confidence:** 0.9
**Tool:** AI Ensemble
**Location:** {vuln_path}:{123}

**Description:**
Unprotected function.

**Category:** Access Control (SWC-105)

---
"""
    report_path = report_dir / "audit_report.md"
    report_path.write_text(md)

    async def fake_generate_multiple_tests(self, vulnerabilities, contract_code, contract_name, output_dir):
        test_file = str(Path(output_dir) / f"{contract_name}_test.t.sol")
        exploit_file = str(Path(output_dir) / f"{contract_name}Exploit.sol")
        Path(test_file).parent.mkdir(parents=True, exist_ok=True)
        Path(test_file).write_text("// test")
        Path(exploit_file).write_text("// exploit")
        return [FoundryTestSuite(
            test_file=test_file,
            exploit_contract=exploit_file,
            mock_contracts=[],
            setup_script="",
            validation_tests=[],
            gas_analysis={}
        )]

    monkeypatch.setattr(
        "cli.main.LLMFoundryGenerator.generate_multiple_tests",
        fake_generate_multiple_tests,
        raising=True,
    )

    out_dir = tmp_path / "gen2"
    cli = AetherCLI()
    rc = await cli.run_generate_foundry(
        from_results=None,
        from_report=str(report_path),
        out_dir=str(out_dir),
        max_items=5,
        min_severity="low",
        types_filter=None,
        only_consensus=False,
        verbose=False,
    )

    assert rc == 0
    manifest = out_dir / "generated_tests.json"
    assert manifest.exists(), "generated_tests.json should be created from report"
    data = json.loads(manifest.read_text())
    assert data.get("suites"), "manifest should contain suites from report parsing"


