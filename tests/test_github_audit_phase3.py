#!/usr/bin/env python3
"""
Phase 3 tests:
- AuditResultFormatter output modes
- SequentialAnalyzer caching vs reanalyze
"""

from pathlib import Path
from unittest.mock import patch

from core.audit_result_formatter import AuditResultFormatter
from core.database_manager import AetherDatabase
from core.discovery import ContractDiscovery
from core.sequential_analyzer import SequentialAnalyzer


class TestFormatter:
    def test_display_and_json_and_immunefi(self):
        fmt = AuditResultFormatter()
        findings = [
            {'contract': 'src/A.sol', 'analysis_type': 'basic_static', 'summary': {'line': 10, 'severity': 'low'}}
        ]
        disp = fmt.format_for_display(findings)
        assert 'A.sol' in disp or 'src/A.sol' in disp
        js = fmt.format_for_json(findings)
        assert js['total_findings'] == 1
        md = fmt.format_for_immunefi(findings, {'url': 'https://github.com/o/r', 'repo_name': 'r', 'framework': 'foundry'})
        assert '# Immunefi Submission' in md


class TestCaching:
    def test_caching_and_force_reanalyze(self, tmp_path: Path):
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        repo = tmp_path / 'repo'
        (repo / 'src').mkdir(parents=True)
        (repo / 'src' / 'A.sol').write_text('pragma solidity ^0.8.0; contract A {}')
        project = db.create_project(url='https://github.com/o/r', repo_name='r', owner='o', framework='foundry', cache_path=str(repo))
        d = ContractDiscovery(db)
        d.discover(project['id'], repo)
        a = SequentialAnalyzer(db)
        # first run writes cache
        outcomes1 = a.analyze_contracts(project['id'], repo, ['src/A.sol'])
        assert outcomes1 and outcomes1[0].status == 'success'
        # second run uses cache
        outcomes2 = a.analyze_contracts(project['id'], repo, ['src/A.sol'])
        assert outcomes2 and outcomes2[0].status == 'cached'
        # force reanalyze
        outcomes3 = a.analyze_contracts(project['id'], repo, ['src/A.sol'], force=True)
        assert outcomes3 and outcomes3[0].status == 'success'


