#!/usr/bin/env python3
"""
Phase 2 tests:
- ProjectBuilder: Foundry/Hardhat build flows (mocked)
- ContractDiscovery: discovers .sol files and saves metadata
- SequentialAnalyzer: runs basic static checks and persists
- Orchestrator wiring: end-to-end build->discover->analyze with mocks
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from core.database_manager import AetherDatabase
from core.builder import ProjectBuilder, BuildResult
from core.discovery import ContractDiscovery
from core.sequential_analyzer import SequentialAnalyzer
from core.github_auditor import GitHubAuditor, AuditOptions


class TestBuilder:
    @patch('core.builder._run')
    def test_foundry_build_success(self, mock_run, tmp_path: Path):
        mock_run.return_value = (0, 'ok', '')
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        proj = tmp_path / 'repo'
        (proj / 'out').mkdir(parents=True)
        (proj / 'foundry.toml').write_text('solc_version = "0.8.23"')
        b = ProjectBuilder(db)
        project = db.create_project(url='https://github.com/o/r', repo_name='r', owner='o', framework='foundry', cache_path=str(proj))
        res = b.build('foundry', proj, project_id=project['id'])
        assert res.success
        assert 'ok' in res.log

    @patch('core.builder._run')
    def test_hardhat_build_success(self, mock_run, tmp_path: Path):
        mock_run.return_value = (0, 'ok', '')
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        proj = tmp_path / 'repo'
        (proj / 'artifacts').mkdir(parents=True)
        (proj / 'hardhat.config.json').write_text('{"solidity": {"version": "0.8.20"}}')
        b = ProjectBuilder(db)
        project = db.create_project(url='https://github.com/o/r2', repo_name='r2', owner='o', framework='hardhat', cache_path=str(proj))
        res = b.build('hardhat', proj, project_id=project['id'])
        assert res.success


class TestDiscovery:
    def test_discover_contracts(self, tmp_path: Path):
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        proj = tmp_path / 'repo'
        (proj / 'src').mkdir(parents=True)
        (proj / 'src' / 'A.sol').write_text('pragma solidity ^0.8.0; contract A {}')
        project = db.create_project(url='https://github.com/o/r', repo_name='r', owner='o', framework='foundry', cache_path=str(proj))
        d = ContractDiscovery(db)
        infos = d.discover(project['id'], proj)
        assert len(infos) == 1
        cts = db.get_contracts(project['id'])
        assert len(cts) == 1


class TestAnalyzer:
    def test_analyze_contracts(self, tmp_path: Path):
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        proj = tmp_path / 'repo'
        (proj / 'src').mkdir(parents=True)
        (proj / 'src' / 'A.sol').write_text('pragma solidity ^0.8.0; contract A { function f() public payable {} }')
        project = db.create_project(url='https://github.com/o/r', repo_name='r', owner='o', framework='foundry', cache_path=str(proj))
        d = ContractDiscovery(db)
        d.discover(project['id'], proj)
        a = SequentialAnalyzer(db)
        outcomes = a.analyze_contracts(project['id'], proj, ['src/A.sol'])
        assert outcomes and outcomes[0].status == 'success'
        results = db.get_analysis_results(db.get_contracts(project['id'])[0]['id'])
        assert results


class TestOrchestrator:
    @patch('core.repository_manager._run')
    @patch('core.builder._run')
    def test_end_to_end_phase2(self, mock_build_run, mock_git_run, tmp_path: Path):
        mock_git_run.return_value = (0, 'ok', '')
        mock_build_run.return_value = (0, 'ok', '')
        db_path = tmp_path / 'db.db'
        auditor = GitHubAuditor(cache_dir=tmp_path / 'repos', db_path=db_path)
        repo_dir = tmp_path / 'repos' / 'o_r'
        (repo_dir / 'src').mkdir(parents=True, exist_ok=True)
        (repo_dir / 'foundry.toml').write_text('solc_version = "0.8.23"')
        (repo_dir / 'out').mkdir(parents=True, exist_ok=True)
        (repo_dir / 'src' / 'A.sol').write_text('pragma solidity ^0.8.0; contract A { unchecked { } }')
        result = auditor.audit('https://github.com/o/r')
        assert result.contracts_analyzed == 1
        assert result.findings and 'unchecked_blocks' in result.findings[0]['summary']


