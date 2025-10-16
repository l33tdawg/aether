#!/usr/bin/env python3
"""
GitHubAuditor Orchestrator (minimal scaffolding for Phase 1)

Coordinates repository cloning/updating, framework detection, and stubs for
build/discovery/analysis which will be implemented in subsequent phases.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from rich.console import Console

from core.database_manager import AetherDatabase
from core.repository_manager import RepositoryManager
from core.framework_detector import FrameworkDetector
from core.builder import ProjectBuilder
from core.discovery import ContractDiscovery
from core.sequential_analyzer import SequentialAnalyzer


@dataclass
class AuditOptions:
    scope: Optional[List[str]] = None
    min_severity: Optional[str] = None
    output_format: str = 'display'
    output_file: Optional[str] = None
    fresh: bool = False
    reanalyze: bool = False
    retry_failed: bool = False
    clear_cache: bool = False
    skip_build: bool = False
    no_cache: bool = False
    verbose: bool = False
    dry_run: bool = False
    github_token: Optional[str] = None


@dataclass
class AuditResult:
    project_path: Path
    framework: Optional[str]
    contracts_analyzed: int
    findings: List[Dict[str, Any]]


class GitHubAuditor:
    def __init__(self, cache_dir: Optional[Union[str, Path]] = None, db_path: Optional[Union[str, Path]] = None):
        self.console = Console()
        self.db = AetherDatabase(db_path=db_path)
        self.repo_manager = RepositoryManager(cache_dir=cache_dir, db=self.db)
        self.framework_detector = FrameworkDetector()
        self.builder = ProjectBuilder(db=self.db)
        self.discovery = ContractDiscovery(db=self.db)
        # Enhanced analysis will be determined by options in the audit method

    def audit(self, github_url: str, options: Optional[AuditOptions] = None) -> AuditResult:
        options = options or AuditOptions()

        # 1) Clone or get repo
        # Set token if provided at call time
        if options.github_token:
            self.repo_manager.github_token = options.github_token
        clone = self.repo_manager.clone_or_get(github_url, force_fresh=options.fresh or options.clear_cache)

        # 2) If cache exists and not fresh, try pulling updates
        if not clone.is_new_clone and not options.fresh and not options.clear_cache:
            self.repo_manager.pull_updates(clone.repo_path)

        # 3) Detect framework
        framework = self.framework_detector.detect(clone.repo_path) or 'unknown'

        # 4) Ensure project exists in DB
        owner, repo = self._parse_owner_repo(github_url)
        project = self.db.get_project(github_url) or self.db.create_project(url=github_url, repo_name=repo or 'unknown', framework=framework, owner=owner, cache_path=str(clone.repo_path))
        if project and project.get('framework') != framework:
            self.db.update_project(project['id'], framework=framework)

        # Phase 2: build -> discovery -> analysis (basic)
        contracts_analyzed = 0
        findings: List[Dict[str, Any]] = []

        try:
            project = self.db.get_project(github_url)
            project_id = int(project['id']) if project else None
        except Exception:
            project_id = None

        # Build step (optional)
        try:
            build_result = self.builder.build(framework, clone.repo_path, project_id=project_id, skip=options.skip_build)
        except Exception as e:
            if project_id is not None:
                self.db.log_error({
                    'project_id': project_id,
                    'contract_id': None,
                    'error_type': 'BUILD_FAILED',
                    'error_message': str(e),
                    'tool_that_failed': framework or 'unknown',
                    'contract_path': None,
                    'full_error_log': '',
                    'status': 'logged_for_review'
                })
            build_result = None

        # Discovery step
        if project_id is not None:
            try:
                discovered = self.discovery.discover(project_id, clone.repo_path)
            except Exception as e:
                self.db.log_error({
                    'project_id': project_id,
                    'contract_id': None,
                    'error_type': 'DISCOVERY_FAILED',
                    'error_message': str(e),
                    'tool_that_failed': 'discovery',
                    'contract_path': None,
                    'full_error_log': '',
                    'status': 'logged_for_review'
                })
                discovered = []
            contracts_analyzed = len(discovered)
            rel_paths = []
            for c in discovered:
                try:
                    rel_paths.append(str(Path(c.file_path).relative_to(clone.repo_path)))
                except Exception:
                    rel_paths.append(str(c.file_path))

            # Provide feedback when no contracts are found
            if contracts_analyzed == 0:
                if framework == 'unknown':
                    project_type = self._detect_project_type(clone.repo_path)
                    print(f"ℹ️  No Solidity contracts found. This appears to be a {project_type} project.")
                    print(f"   Supported frameworks: Foundry, Hardhat, Truffle")
                    print(f"   Supported languages: Solidity (.sol files)")
                    print(f"   Found project files: {self._list_project_files(clone.repo_path)}")
                else:
                    print(f"ℹ️  No contracts found in {framework} project. Check if contracts are in expected locations.")

            # Analysis step
            try:
                # Determine if we should use enhanced analysis (for now, always use enhanced for better results)
                use_enhanced = True  # Could be made configurable via options
                analyzer = SequentialAnalyzer(db=self.db, use_enhanced_analysis=use_enhanced)
                outcomes = analyzer.analyze_contracts(project_id, clone.repo_path, rel_paths, force=options.reanalyze)
            except Exception as e:
                self.db.log_error({
                    'project_id': project_id,
                    'contract_id': None,
                    'error_type': 'ANALYSIS_FAILED',
                    'error_message': str(e),
                    'tool_that_failed': 'sequential_analyzer',
                    'contract_path': None,
                    'full_error_log': '',
                    'status': 'logged_for_review'
                })
                outcomes = []
            for oc in outcomes:
                findings.append({'contract': oc.contract_path, 'analysis_type': oc.analysis_type, 'summary': oc.findings})

        return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=contracts_analyzed, findings=findings)

    def _detect_project_type(self, repo_path: Path) -> str:
        """Detect the type of project based on files present."""
        if (repo_path / 'Cargo.toml').exists():
            return 'Rust'
        if (repo_path / 'package.json').exists():
            return 'JavaScript/Node.js'
        if (repo_path / 'go.mod').exists():
            return 'Go'
        if (repo_path / 'pyproject.toml').exists() or (repo_path / 'requirements.txt').exists():
            return 'Python'
        if (repo_path / 'CMakeLists.txt').exists():
            return 'C/C++'
        return 'Unknown'

    def _list_project_files(self, repo_path: Path) -> str:
        """List key project files for user feedback."""
        files = []
        key_files = ['Cargo.toml', 'package.json', 'foundry.toml', 'hardhat.config.js', 'truffle-config.js', 'go.mod', 'pyproject.toml', 'requirements.txt', 'CMakeLists.txt']

        for file in key_files:
            if (repo_path / file).exists():
                files.append(file)

        if not files:
            # Show some common files that exist
            common_files = ['README.md', 'Makefile', 'Cargo.lock', '.git']
            for file in common_files:
                if (repo_path / file).exists():
                    files.append(file)
                    break

        return ', '.join(files[:3]) if files else 'various project files'

    def _parse_owner_repo(self, url: str) -> tuple[Optional[str], Optional[str]]:
        try:
            if url.endswith('.git'):
                url = url[:-4]
            if 'github.com/' in url:
                parts = url.split('github.com/', 1)[1].split('/')
                if len(parts) >= 2:
                    return parts[0], parts[1]
        except Exception:
            pass
        return None, None


