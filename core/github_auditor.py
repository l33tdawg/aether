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
from core.scope_manager import ScopeManager


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
    interactive_scope: bool = False


@dataclass
class AuditResult:
    project_path: Path
    framework: Optional[str]
    contracts_analyzed: int
    findings: List[Dict[str, Any]]


class ScopeSelector:
    """Interactive tool to select which contracts should be audited (for bug bounty scope)."""
    
    def __init__(self, scope_manager: Optional['ScopeManager'] = None):
        self.console = Console()
        from core.scope_manager import ScopeManager
        self.scope_manager = scope_manager or ScopeManager()
    
    def select_scope(self, discovered_contracts: List[Dict[str, Any]]) -> List[str]:
        """
        Present list of discovered contracts and allow user to select which ones to audit.
        Uses interactive curses-based selection with arrow keys and spacebar.
        
        Args:
            discovered_contracts: List of contract info dicts with 'file_path' and optional 'contract_name'
        
        Returns:
            List of file paths to audit (relative paths)
        """
        if not discovered_contracts:
            self.console.print("[yellow]No contracts found to select from[/yellow]")
            return []
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]      INTERACTIVE CONTRACT SELECTOR[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        self.console.print(f"[bold]Total contracts discovered: {len(discovered_contracts)}[/bold]")
        self.console.print("[bold cyan]Launching interactive selector... Press arrow keys to navigate[/bold cyan]\n")
        
        # Use the interactive curses-based selector
        selected_indices = self.scope_manager.interactive_select(discovered_contracts)
        
        if not selected_indices:
            self.console.print("[yellow]No contracts selected. Audit cancelled.[/yellow]")
            return []
        
        # Show summary
        selected_indices_set = set(selected_indices)
        self._show_selection_summary(discovered_contracts, selected_indices_set)
        
        return [discovered_contracts[i].get('file_path', '') for i in sorted(selected_indices)]
    
    def _show_selection_summary(self, contracts: List[Dict[str, Any]], indices: set) -> None:
        """Display summary of selected contracts."""
        self.console.print(f"\n[bold green]✅ Selected {len(indices)}/{len(contracts)} contracts:[/bold green]")
        for i in sorted(indices):
            if i < len(contracts):
                file_path = contracts[i].get('file_path', '')
                contract_name = contracts[i].get('contract_name', 'Unknown')
                self.console.print(f"   • {file_path} ({contract_name})")
        self.console.print()


class GitHubAuditor:
    def __init__(self, cache_dir: Optional[Union[str, Path]] = None, db_path: Optional[Union[str, Path]] = None):
        self.console = Console()
        self.db = AetherDatabase(db_path=db_path)
        self.repo_manager = RepositoryManager(cache_dir=cache_dir, db=self.db)
        self.framework_detector = FrameworkDetector()
        self.builder = ProjectBuilder(db=self.db)
        self.discovery = ContractDiscovery(db=self.db)
        self.scope_selector = ScopeSelector()
        self.scope_manager = ScopeManager(db=self.db)
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

            # SMART RESUME WORKFLOW (check for saved scope before interactive selection)
            if rel_paths:
                # Convert discovered contracts to info dicts
                contract_info_list = []
                for c, rel_path in zip(discovered, rel_paths):
                    contract_info_list.append({
                        'file_path': rel_path,
                        'contract_name': c.contract_name or 'Unknown',
                        'line_count': c.line_count
                    })
                
                # Check if there's a saved scope (smart resume)
                if project_id is not None and not options.interactive_scope and not options.scope:
                    resume_info = self.scope_manager.detect_and_handle_saved_scope(project_id, contract_info_list)
                    
                    if resume_info:
                        action = resume_info.get('action')
                        scope = resume_info.get('scope')
                        
                        if action == 'continue':
                            # Resume with existing scope
                            rel_paths = scope['selected_contracts']
                            contracts_analyzed = len(rel_paths)
                            self.console.print(f"\n[green]Resuming with saved scope: {scope['total_audited']}/{scope['total_selected']} audited[/green]\n")
                        
                        elif action == 'add_contracts':
                            # User wants to add more contracts
                            updated_scope = self.scope_manager.handle_add_contracts(scope, contract_info_list)
                            if updated_scope:
                                rel_paths = updated_scope['selected_contracts']
                                contracts_analyzed = len(rel_paths)
                        
                        elif action == 'remove_contracts':
                            # User wants to remove contracts
                            updated_scope = self.scope_manager.handle_remove_contracts(scope, contract_info_list)
                            if updated_scope:
                                rel_paths = updated_scope['selected_contracts']
                                contracts_analyzed = len(rel_paths)
                        
                        elif action == 'reaudit':
                            # Fresh re-analysis of all selected contracts
                            updated_scope = self.scope_manager.handle_reaudit(scope)
                            rel_paths = updated_scope['selected_contracts']
                            contracts_analyzed = len(rel_paths)
                        
                        elif action == 'new_scope':
                            # Let user create new scope
                            options.interactive_scope = True
                        
                        elif action == 'view_report':
                            # Show partial report and exit
                            self.console.print("[bold]📊 Partial Audit Report[/bold]")
                            self.console.print(f"  Audited: {scope['total_audited']}/{scope['total_selected']}")
                            self.console.print(f"  Pending: {scope['total_pending']}/{scope['total_selected']}")
                            return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=scope['total_audited'], findings=findings)
                        
                        elif action == 'cancel':
                            return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=0, findings=[])
                
                # INTERACTIVE SCOPE SELECTION (for first-time users or new scope)
                if options.interactive_scope and rel_paths:
                    # Let user select which contracts to audit
                    selected_paths = self.scope_selector.select_scope(contract_info_list)
                    if not selected_paths:
                        self.console.print("[red]No contracts selected. Audit cancelled.[/red]")
                        return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=0, findings=[])
                    
                    # Save scope to database
                    if project_id is not None:
                        self.db.save_audit_scope(project_id, selected_paths)
                    
                    rel_paths = selected_paths
                    self.console.print(f"[green]Auditing {len(rel_paths)} selected contracts out of {len(contract_info_list)} discovered[/green]\n")
                    contracts_analyzed = len(rel_paths)
                
                elif options.scope:
                    # Use provided scope list
                    rel_paths = [p for p in rel_paths if p in options.scope]
                    contracts_analyzed = len(rel_paths)
                    self.console.print(f"[green]Auditing {len(rel_paths)} contracts matching scope[/green]\n")

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


