import json
import os
from pathlib import Path

import pytest

from cli.main import AetherCLI
from core.llm_foundry_generator import LLMFoundryGenerator


class DummySuite:
    def __init__(self, test_file, exploit_contract):
        self.test_file = test_file
        self.exploit_contract = exploit_contract
        self.mock_contracts = []
        self.setup_script = ""
        self.validation_tests = []
        self.gas_analysis = {}


def _write_artifact(out_root: Path, contract_name: str, abi: list):
    contract_dir = out_root / f"{contract_name}.sol"
    contract_dir.mkdir(parents=True, exist_ok=True)
    (contract_dir / f"{contract_name}.json").write_text(json.dumps({"abi": abi}))


@pytest.mark.asyncio
async def test_llm_generator_context_overrides_applied():
    gen = LLMFoundryGenerator()

    vuln = {
        'vulnerability_type': 'access_control',
        'line_number': 10,
        'severity': 'high',
        'description': 'desc'
    }
    code = "pragma solidity 0.8.19; contract C { function foo() public {} }"

    overrides = {
        'contract_functions': ['bar', 'baz'],
        'function_signatures': ['bar(uint256)', 'baz()'],
        'events': ['E1(uint256)'],
        'modifiers': ['onlyOwner'],
        'solc_version': '0.8.26',
        'abi': [{"type": "function", "name": "bar"}]
    }

    # Call the internal context method directly to validate override application
    context = gen._prepare_test_context(vuln, code, 'C', overrides)

    assert context['contract_functions'] == overrides['contract_functions']
    assert context['function_signatures'] == overrides['function_signatures']
    assert context['events'] == overrides['events']
    assert context['modifiers'] == overrides['modifiers']
    assert context['abi'] == overrides['abi']
    assert context['solc_version'] == '0.8.26'


@pytest.mark.asyncio
async def test_generate_foundry_enriches_with_abi_and_slither(tmp_path, monkeypatch):
    # Arrange: contract and artifact
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    contract_file = contract_dir / "MyToken.sol"
    contract_file.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract MyToken { function transfer(address to, uint256 amount) public {} }
""".strip()
    )

    # Create Foundry artifact under cwd/out
    monkeypatch.chdir(tmp_path)
    out_root = tmp_path / "out"
    _write_artifact(out_root, "MyToken", [{"type": "function", "name": "transfer"}])

    # Capture the context_overrides passed to generator
    captured = {}

    async def fake_generate_multiple_tests(self, vulns, contract_code, contract_name, output_dir, context_overrides=None):
        captured['context'] = dict(context_overrides or {})
        # write dummy files so manifest creation passes
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        tf = Path(output_dir) / f"{contract_name}_test.t.sol"
        ef = Path(output_dir) / f"{contract_name}Exploit.sol"
        tf.write_text("// test")
        ef.write_text("// exploit")
        return [DummySuite(str(tf), str(ef))]

    # Monkeypatch generator
    monkeypatch.setattr(
        "cli.main.LLMFoundryGenerator.generate_multiple_tests",
        fake_generate_multiple_tests,
        raising=True,
    )

    # Monkeypatch Slither to provide symbols
    class _Fn:
        def __init__(self, name, vis, sig):
            self.name = name
            self.visibility = vis
            self.signature_str = sig

    class _Ev:
        def __init__(self, name):
            self.name = name

    class _Mod:
        def __init__(self, name):
            self.name = name

    class _Contract:
        def __init__(self, name):
            self.name = name
            self.functions_declared = [_Fn("transfer", "public", "transfer(address,uint256)")]
            self.events_declared = [_Ev("Transfer")]
            self.modifiers_declared = [_Mod("onlyOwner")]

    class _Slither:
        def __init__(self, path):
            self.contracts = [_Contract("MyToken")]

    monkeypatch.setattr("cli.main.Slither", _Slither, raising=True)

    # Prepare results.json
    results = {
        "audit": {
            "vulnerabilities": [
                {
                    "title": "Access Control",
                    "severity": "medium",
                    "file": str(contract_file),
                    "line": 12,
                    "description": "desc",
                }
            ]
        }
    }
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(results))

    out_dir = tmp_path / "gen"
    cli = AetherCLI()
    rc = await cli.run_generate_foundry(
        from_results=str(results_path),
        from_report=None,
        out_dir=str(out_dir),
        max_items=5,
        min_severity="low",
        types_filter=None,
        only_consensus=False,
        project_id=None,
        scope_id=None,
        verbose=False,
    )

    assert rc == 0
    ctx = captured.get('context', {})
    # ABI should be picked up from artifact
    assert isinstance(ctx.get('abi'), list) and ctx['abi']
    # Slither-derived symbols
    assert 'contract_functions' in ctx and 'transfer' in ctx['contract_functions']
    assert 'function_signatures' in ctx and any('transfer' in s for s in ctx['function_signatures'])
    assert 'events' in ctx and 'Transfer' in ctx['events']
    assert 'modifiers' in ctx and 'onlyOwner' in ctx['modifiers']


@pytest.mark.asyncio
async def test_generate_foundry_db_path_uses_solc_from_db(tmp_path, monkeypatch):
    # Setup a fake AetherDatabase with scope and analysis results
    class _FakeConn:
        def __init__(self, project_id, contract_path, findings_json):
            self._project_id = project_id
            self._contract_path = contract_path
            self._findings_json = findings_json

        def execute(self, sql, params=()):
            sql_s = str(sql).lower()
            if 'select id from contracts' in sql_s:
                class _Row:
                    def __init__(self):
                        self.id = 1
                    def __getitem__(self, i):
                        return self.id
                return type('Cur', (), {'fetchone': lambda self: _Row()})()
            if 'select findings, status from analysis_results' in sql_s:
                findings_json = self._findings_json
                class _Row:
                    def __init__(self):
                        self.findings = findings_json
                        self.status = 'success'
                    def __getitem__(self, i):
                        return [self.findings, self.status][i]
                return type('Cur', (), {'fetchone': lambda self: _Row()})()
            if 'select selected_contracts from audit_scopes' in sql_s:
                class _Row:
                    def __init__(self, contract_path):
                        self.selected_contracts = json.dumps([contract_path])
                    def __getitem__(self, i):
                        return self.selected_contracts
                cp = self._contract_path
                return type('Cur', (), {'fetchone': lambda self: _Row(cp)})()
            return type('Cur', (), {'fetchone': lambda self: None})()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class _FakeADB:
        def __init__(self, *args, **kwargs):
            pass

        def _connect(self):
            findings = json.dumps({
                'audit': {
                    'vulnerabilities': [
                        {"title": "Reentrancy", "severity": "high", "file": str(contract_file), "line": 42, "description": "x"}
                    ]
                }
            })
            return _FakeConn(1, str(contract_file), findings)

        def get_active_scope(self, project_id: int):
            return {'id': 99, 'project_id': project_id, 'selected_contracts': [str(contract_file)]}

        def get_build_artifacts(self, project_id: int):
            return {'solc_version': '0.8.26'}

    # Prepare contract file
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    contract_file = contract_dir / "Vault.sol"
    contract_file.write_text("pragma solidity ^0.8.19; contract Vault { function w() public {} }")

    # Capture context_overrides
    captured = {}

    async def fake_generate_multiple_tests(self, vulns, contract_code, contract_name, output_dir, context_overrides=None):
        captured['context'] = dict(context_overrides or {})
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        tf = Path(output_dir) / f"{contract_name}_test.t.sol"
        ef = Path(output_dir) / f"{contract_name}Exploit.sol"
        tf.write_text("// test")
        ef.write_text("// exploit")
        return [DummySuite(str(tf), str(ef))]

    monkeypatch.setattr("cli.main.AetherDatabase", _FakeADB, raising=True)
    monkeypatch.setattr(
        "cli.main.LLMFoundryGenerator.generate_multiple_tests",
        fake_generate_multiple_tests,
        raising=True,
    )

    out_dir = tmp_path / "dbgen"
    cli = AetherCLI()
    rc = await cli.run_generate_foundry(
        from_results=None,
        from_report=None,
        out_dir=str(out_dir),
        max_items=10,
        min_severity="low",
        types_filter=None,
        only_consensus=False,
        project_id=1,
        scope_id=99,
        verbose=False,
    )

    assert rc == 0
    ctx = captured.get('context', {})
    assert ctx.get('solc_version') == '0.8.26'


