#!/usr/bin/env python3
"""
Tests for Phase 1 (GitHub Audit Foundation):
- AetherDatabase schema and basic CRUD
- RepositoryManager clone/pull/cache validation (git mocked)
- FrameworkDetector detection helpers
- GitHubAuditor minimal orchestration
- CLI routing to GitHub audit when GitHub URL provided
"""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.database_manager import AetherDatabase
from core.repository_manager import RepositoryManager
from core.framework_detector import FrameworkDetector
from core.github_auditor import GitHubAuditor, AuditOptions as GitHubAuditOptions
from cli.main import AetherCLI


class TestAetherDatabaseSchema:
    def test_init_schema_and_crud(self, tmp_path: Path):
        db_path = tmp_path / 'aether_github_audit_test.db'
        db = AetherDatabase(db_path=db_path)

        # Create project
        proj = db.create_project(
            url='https://github.com/owner/repo',
            repo_name='repo',
            framework='foundry',
            owner='owner',
            cache_path=str(tmp_path / 'cache')
        )
        assert proj and proj.get('url') == 'https://github.com/owner/repo'

        # Fetch project
        proj2 = db.get_project('https://github.com/owner/repo')
        assert proj2 and proj2['repo_name'] == 'repo'

        # Update project
        db.update_project(proj2['id'], framework='hardhat')
        proj3 = db.get_project('https://github.com/owner/repo')
        assert proj3['framework'] == 'hardhat'

        # Save contract and analysis result
        c = db.save_contract(proj3['id'], 'src/Token.sol', {
            'contract_name': 'Token',
            'solc_version': '0.8.19',
            'line_count': 100,
            'dependencies': ['openzeppelin']
        })
        assert c['file_path'] == 'src/Token.sol'

        db.save_analysis_result(c['id'], 'pattern', {'total_findings': 0, 'severity_counts': {}}, 'success')
        results = db.get_analysis_results(c['id'])
        assert len(results) == 1

        # Build artifacts
        db.save_build_artifacts(proj3['id'], '/tmp/artifacts', 'hash123', '0.8.19', 'depshash', 12.3)
        ba = db.get_build_artifacts(proj3['id'])
        assert ba and ba['artifact_path'] == '/tmp/artifacts'

        # Stats
        stats = db.get_project_statistics(proj3['id'])
        assert stats['total_contracts'] == 1


class TestRepositoryManager:
    @patch('core.repository_manager._run')
    def test_clone_or_get_and_pull(self, mock_run, tmp_path: Path):
        # Mock git clone success
        mock_run.return_value = (0, 'ok', '')
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        rm = RepositoryManager(cache_dir=tmp_path / 'repos', db=db)

        res = rm.clone_or_get('https://github.com/owner/repo')
        assert res.repo_path.exists()
        assert res.is_new_clone is True

        # Second call should reuse cache and not clone
        res2 = rm.clone_or_get('https://github.com/owner/repo')
        assert res2.is_new_clone is False

        # Mock pull
        mock_run.return_value = (0, 'up to date', '')
        ok = rm.pull_updates(res.repo_path)
        assert ok is True

    def test_validate_repo_structure(self, tmp_path: Path):
        db = AetherDatabase(db_path=tmp_path / 'db.db')
        rm = RepositoryManager(cache_dir=tmp_path / 'repos', db=db)
        repo = tmp_path / 'repos' / 'owner_repo'
        (repo / 'src').mkdir(parents=True, exist_ok=True)
        assert rm.validate_repo_structure(repo) is True


class TestFrameworkDetector:
    def test_detect_and_helpers(self, tmp_path: Path):
        detector = FrameworkDetector()

        # Foundry
        repo = tmp_path / 'foundry'
        repo.mkdir()
        (repo / 'foundry.toml').write_text('solc_version = "0.8.19"\n', encoding='utf-8')
        (repo / 'remappings.txt').write_text('@openzeppelin=lib/openzeppelin-contracts', encoding='utf-8')
        assert detector.detect(repo) == 'foundry'
        assert detector.get_solc_version(repo) in ('0.8.19', '0.8.19"')
        remap = detector.get_remappings(repo)
        assert '@openzeppelin' in remap
        libs = detector.get_lib_paths(repo)
        assert isinstance(libs, list)

        # Hardhat
        hh = tmp_path / 'hardhat'
        hh.mkdir()
        (hh / 'hardhat.config.js').write_text('// js', encoding='utf-8')
        assert detector.detect(hh) == 'hardhat'

        # Truffle
        tr = tmp_path / 'truffle'
        tr.mkdir()
        (tr / 'truffle-config.js').write_text('// js', encoding='utf-8')
        assert detector.detect(tr) == 'truffle'


class TestGitHubAuditor:
    @patch('core.repository_manager.RepositoryManager.clone_or_get')
    @patch('core.repository_manager.RepositoryManager.pull_updates')
    @patch('core.framework_detector.FrameworkDetector.detect')
    def test_minimal_audit_flow(self, mock_detect, mock_pull, mock_clone, tmp_path: Path):
        mock_clone.return_value = type('CR', (), {'repo_path': tmp_path / 'repo', 'is_new_clone': True})
        (tmp_path / 'repo').mkdir(parents=True, exist_ok=True)
        mock_pull.return_value = True
        mock_detect.return_value = 'foundry'

        auditor = GitHubAuditor(cache_dir=tmp_path / 'repos', db_path=tmp_path / 'db.db')
        opts = GitHubAuditOptions(fresh=True)
        res = auditor.audit('https://github.com/owner/repo', opts)

        assert res.project_path.exists()
        assert res.framework == 'foundry'
        assert res.contracts_analyzed == 0
        assert isinstance(res.findings, list)


class TestCLIRouting:
    def test_audit_routes_to_github_audit_for_url(self, tmp_path: Path, monkeypatch):
        cli = AetherCLI()

        called = {'ok': False}

        def fake_run_github_audit_command(**kwargs):
            called['ok'] = True
            # minimal assertions on forwarded args
            assert 'github_url' in kwargs
            assert kwargs['github_url'].startswith('https://github.com/')
            return 0

        monkeypatch.setattr(cli, 'run_github_audit_command', fake_run_github_audit_command)

        # Simulate argparse namespace as main.py would pass
        rc = cli.run_github_audit_command(
            github_url='https://github.com/owner/repo',
            scope='Token,Pool',
            min_severity='medium',
            output=str(tmp_path / 'out'),
            fmt='display',
            fresh=True,
            reanalyze=False,
            retry_failed=False,
            clear_cache=False,
            skip_build=False,
            no_cache=False,
            verbose=False,
            dry_run=True,
            github_token=None,
        )

        assert rc == 0
        assert called['ok'] is True


