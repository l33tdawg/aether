#!/usr/bin/env python3
"""
GitHubAuditor Orchestrator (minimal scaffolding for Phase 1)

Coordinates repository cloning/updating, framework detection, and stubs for
build/discovery/analysis which will be implemented in subsequent phases.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple

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
    cancelled: bool = False  # Indicates if the audit was cancelled by the user
    scope_id: Optional[int] = None  # ID of the audit scope that was executed


class ScopeSelector:
    """Interactive tool to select which contracts should be audited (for bug bounty scope)."""
    
    def __init__(self, scope_manager: Optional['ScopeManager'] = None):
        self.console = Console()
        from core.scope_manager import ScopeManager
        self.scope_manager = scope_manager or ScopeManager()
    
    def select_scope(self, discovered_contracts: List[Dict[str, Any]], audited_contracts: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """
        Present list of discovered contracts and allow user to select which ones to audit.
        Uses interactive curses-based selection with arrow keys and spacebar.
        
        Args:
            discovered_contracts: List of contract info dicts with 'file_path' and optional 'contract_name'
            audited_contracts: Optional list of already audited contract dicts to show as disabled
        
        Returns:
            List of file paths to audit (relative paths)
        """
        if not discovered_contracts:
            self.console.print("[yellow]No contracts found to select from[/yellow]")
            return []
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]      AETHER  CONTRACT SELECTOR[/bold cyan]")
        self.console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
        self.console.print(f"[bold]Total contracts discovered: {len(discovered_contracts)}[/bold]")
        
        # Calculate audited contract indices for visual reference only
        audited_indices = []
        if audited_contracts:
            # Normalize paths for better matching
            audited_paths = set()
            for c in audited_contracts:
                path = c.get('file_path', '').lstrip('./')
                audited_paths.add(path)
            
            for i, contract in enumerate(discovered_contracts):
                discovered_path = contract.get('file_path', '').lstrip('./')
                if discovered_path in audited_paths:
                    audited_indices.append(i)
            
            if audited_indices:
                self.console.print(f"[yellow]ℹ️  {len(audited_indices)} of {len(discovered_contracts)} contracts were previously audited[/yellow]")
                self.console.print("[italic cyan]Previously audited contracts are shown in GREEN - you can still select them if needed[/italic cyan]\n")
        
        # Check if there's a cached selection
        import hashlib
        paths = '|'.join(c.get('file_path', '') for c in discovered_contracts)
        items_hash = hashlib.md5(paths.encode()).hexdigest()[:8]
        cache_file = self.scope_manager.cache_dir / f"selection_{items_hash}.json"
        
        if cache_file.exists():
            import json
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                    cached_count = len(cache_data.get('selected_indices', []))
                    if cached_count > 0:
                        self.console.print(f"[green]💾 Found previously saved selection: {cached_count} contracts[/green]")
                        self.console.print("[italic yellow]These will be pre-loaded (you can modify them)[/italic yellow]\n")
            except:
                pass
        
        self.console.print("[bold cyan]Launching interactive selector... Press arrow keys to navigate[/bold cyan]\n")
        
        # Use the interactive curses-based selector, passing audited indices as markers (not disabled)
        selected_indices = self.scope_manager.interactive_select(discovered_contracts, disabled_indices=[], previously_audited_indices=audited_indices)
        
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
        
        # Normalize URL early
        try:
            normalized_url = self.repo_manager._normalize_github_url(github_url)  # type: ignore
        except Exception:
            normalized_url = github_url

        # FAST PATH: Check if project exists in DB with contracts already discovered
        project = self.db.get_project(normalized_url)
        if project and not options.fresh and not options.clear_cache:
            project_id = int(project['id'])
            contracts = self.db.get_contracts(project_id)
            
            if contracts:
                print(f"✅ Found cached project with {len(contracts)} contracts", flush=True)
                print(f"📂 Skipping clone/build/discovery (using cached data)", flush=True)
                
                # Get repo path from cache
                owner, repo = self._parse_owner_repo(normalized_url)
                repo_name = repo or 'unknown'
                repo_dir = self.repo_manager.cache_dir / (f"{owner}_{repo_name}" if owner else repo_name)
                
                # Convert contracts to info dicts for resume menu and selector
                contract_dicts = [{'contract_name': c.get('contract_name', c.get('file_path', '')), 
                                 'file_path': c.get('file_path', '')} for c in contracts]
                
                # SMART RESUME WORKFLOW (check for saved scope before showing selector)
                # Resume menu should ALWAYS show when there's a saved scope, regardless of --interactive-scope flag
                resume_scope_processed = False
                current_scope_id: Optional[int] = None
                rel_paths = []
                
                if project_id is not None and not options.scope:
                    resume_info = self.scope_manager.detect_and_handle_saved_scope(project_id, contract_dicts)
                    
                    if resume_info:
                        action = resume_info.get('action')
                        scope = resume_info.get('scope')
                        resume_scope_processed = True
                        
                        if scope and scope.get('id'):
                            try:
                                current_scope_id = int(scope['id'])
                            except Exception:
                                current_scope_id = None
                        
                        # Recalculate actual progress from database
                        if scope and scope.get('id'):
                            progress = self.db.recalculate_scope_progress(scope['id'])
                            scope['total_audited'] = progress['total_audited']
                            scope['total_pending'] = progress['total_pending']
                            scope['total_selected'] = progress['total_selected']
                        
                        if action == 'continue':
                            # Resume with existing scope
                            rel_paths = scope['selected_contracts']
                            print(f"\n[green]Resuming with saved scope: {scope['total_audited']}/{scope['total_selected']} audited[/green]\n", flush=True)
                        
                        elif action == 'reaudit':
                            # Fresh re-analysis of all selected contracts
                            updated_scope = self.scope_manager.handle_reaudit(scope)
                            rel_paths = updated_scope['selected_contracts']
                            current_scope_id = int(updated_scope['id']) if updated_scope.get('id') else current_scope_id
                        
                        elif action == 'new_scope':
                            # Let user create new scope
                            options.interactive_scope = True
                            resume_scope_processed = False  # Reset flag to allow interactive selection
                        
                        elif action == 'view_report':
                            # Show partial report and exit
                            self.console.print("[bold]📊 Partial Audit Report[/bold]")
                            self.console.print(f"  Audited: {scope['total_audited']}/{scope['total_selected']}")
                            self.console.print(f"  Pending: {scope['total_pending']}/{scope['total_selected']}")
                            return AuditResult(project_path=repo_dir, framework=project.get('framework', 'unknown'),
                                             contracts_analyzed=scope['total_audited'], findings=[], scope_id=current_scope_id)
                        
                        elif action == 'cancel':
                            return AuditResult(project_path=repo_dir, framework=project.get('framework', 'unknown'),
                                             contracts_analyzed=0, findings=[], cancelled=True, scope_id=current_scope_id)
                
                # INTERACTIVE SCOPE SELECTION (for first-time users or new scope)
                # Only show selector if resume menu wasn't processed or user chose 'new_scope'
                if options.interactive_scope and not resume_scope_processed and contract_dicts:
                    print(f"\n📋 Interactive Scope Selection", flush=True)
                    # Get audited contracts to show as already analyzed
                    audited_contracts = self._get_audited_contracts(project_id)
                    selected_paths = self.scope_selector.select_scope(contract_dicts, audited_contracts=audited_contracts)
                    
                    if not selected_paths:
                        print("⚠️  No contracts selected. Exiting.", flush=True)
                        return AuditResult(project_path=repo_dir, framework=project.get('framework', 'unknown'),
                                         contracts_analyzed=0, findings=[], cancelled=True, scope_id=current_scope_id)
                    
                    # Save scope to database
                    if project_id is not None:
                        scope_rec = self.db.save_audit_scope(project_id, selected_paths)
                        try:
                            current_scope_id = int(scope_rec.get('id')) if scope_rec else None
                        except Exception:
                            current_scope_id = None
                    
                    rel_paths = selected_paths
                elif not rel_paths:
                    # If no scope was set by resume menu and not interactive, use all contracts
                    rel_paths = [c.get('file_path', '') for c in contracts]
                
                # Run analysis on selected contracts
                try:
                    analyzer = SequentialAnalyzer(db=self.db, use_enhanced_analysis=True)
                    outcomes = analyzer.analyze_contracts(project_id, repo_dir, rel_paths, force=options.reanalyze)
                    findings = [{'contract': oc.contract_path, 'analysis_type': oc.analysis_type, 
                               'summary': oc.findings} for oc in outcomes]
                    
                    # Finalize scope progress after analysis
                    try:
                        if current_scope_id:
                            progress = self.db.recalculate_scope_progress(current_scope_id)
                            if isinstance(progress, dict):
                                # Update the scope with calculated progress
                                total_audited = progress.get('total_audited', 0)
                                total_pending = progress.get('total_pending', 0)
                                # Get the last analyzed contract ID (just use first outcome's contract ID if available)
                                last_contract_id = 0
                                for oc in outcomes:
                                    if oc.status == 'success':
                                        # Try to get the contract ID for this path
                                        for c in contracts:
                                            if c.get('file_path') == oc.contract_path:
                                                last_contract_id = int(c.get('id', 0))
                                                break
                                self.db.update_scope_progress(current_scope_id, last_contract_id, total_audited, total_pending)
                                
                                if total_pending == 0:
                                    # Mark scope as completed when no pending items remain
                                    self.db.complete_scope(current_scope_id)
                    except Exception:
                        pass
                    
                    return AuditResult(project_path=repo_dir, framework=project.get('framework', 'unknown'),
                                     contracts_analyzed=len(outcomes), findings=findings, scope_id=current_scope_id)
                except Exception as e:
                    print(f"❌ Analysis failed: {e}", flush=True)
                    return AuditResult(project_path=repo_dir, framework=project.get('framework', 'unknown'),
                                     contracts_analyzed=0, findings=[], scope_id=current_scope_id)

        # SLOW PATH: Clone/build/discover (for new projects or fresh runs)
        print(f"⏳ Cloning repository (first time or fresh run)...", flush=True)
        
        # 1) Clone or get repo
        # Set token if provided at call time
        if options.github_token:
            self.repo_manager.github_token = options.github_token
        clone = self.repo_manager.clone_or_get(github_url, force_fresh=options.fresh or options.clear_cache)
        print(f"✅ Repository ready at: {clone.repo_path}", flush=True)

        # 2) If cache exists and not fresh, try pulling updates
        if not clone.is_new_clone and not options.fresh and not options.clear_cache:
            print(f"⏳ Pulling latest updates...", flush=True)
            self.repo_manager.pull_updates(clone.repo_path)

        # 3) Detect framework
        framework = self.framework_detector.detect(clone.repo_path) or 'unknown'

        # 4) Ensure project exists in DB
        # Normalize URL to match RepositoryManager behavior for DB keying
        try:
            normalized_url = self.repo_manager._normalize_github_url(github_url)  # type: ignore
        except Exception:
            normalized_url = github_url
        owner, repo = self._parse_owner_repo(normalized_url)
        project = self.db.get_project(normalized_url) or self.db.create_project(url=normalized_url, repo_name=repo or 'unknown', framework=framework, owner=owner, cache_path=str(clone.repo_path))
        if project and project.get('framework') != framework:
            self.db.update_project(project['id'], framework=framework)

        # Phase 2: build -> discovery -> analysis (basic)
        contracts_analyzed = 0
        findings: List[Dict[str, Any]] = []
        current_scope_id: Optional[int] = None

        try:
            project = self.db.get_project(normalized_url)
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
                
                # Check if there's a saved scope (smart resume) - ALWAYS check, regardless of flags
                resume_scope_processed = False  # Flag to prevent double-selection
                if project_id is not None and not options.scope:
                    resume_info = self.scope_manager.detect_and_handle_saved_scope(project_id, contract_info_list)
                    
                    if resume_info:
                        action = resume_info.get('action')
                        scope = resume_info.get('scope')
                        resume_scope_processed = True  # Mark that resume was processed
                        if scope and scope.get('id'):
                            try:
                                current_scope_id = int(scope['id'])
                            except Exception:
                                current_scope_id = None
                        
                        # Recalculate actual progress from database
                        if scope.get('id'):
                            progress = self.db.recalculate_scope_progress(scope['id'])
                            scope['total_audited'] = progress['total_audited']
                            scope['total_pending'] = progress['total_pending']
                            scope['total_selected'] = progress['total_selected']
                        
                        if action == 'continue':
                            # Resume with existing scope
                            rel_paths = scope['selected_contracts']
                            contracts_analyzed = len(rel_paths)
                            self.console.print(f"\n[green]Resuming with saved scope: {scope['total_audited']}/{scope['total_selected']} audited[/green]\n")
                        
                        elif action == 'reaudit':
                            # Fresh re-analysis of all selected contracts
                            updated_scope = self.scope_manager.handle_reaudit(scope)
                            rel_paths = updated_scope['selected_contracts']
                            contracts_analyzed = len(rel_paths)
                        
                        elif action == 'new_scope':
                            # Let user create new scope
                            options.interactive_scope = True
                            resume_scope_processed = False  # Reset flag to allow interactive selection
                        
                        elif action == 'view_report':
                            # Show partial report and exit
                            self.console.print("[bold]📊 Partial Audit Report[/bold]")
                            self.console.print(f"  Audited: {scope['total_audited']}/{scope['total_selected']}")
                            self.console.print(f"  Pending: {scope['total_pending']}/{scope['total_selected']}")
                            return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=scope['total_audited'], findings=findings, scope_id=current_scope_id)
                        
                        elif action == 'cancel':
                            return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=0, findings=[], cancelled=True, scope_id=current_scope_id)
                
                # INTERACTIVE SCOPE SELECTION (for first-time users or new scope)
                # Only show selector if resume menu wasn't processed or user chose 'new_scope'
                if options.interactive_scope and not resume_scope_processed and rel_paths:
                    # Let user select which contracts to audit
                    audited_contracts = self._get_audited_contracts(project_id)
                    selected_paths = self.scope_selector.select_scope(contract_info_list, audited_contracts=audited_contracts)
                    if not selected_paths:
                        self.console.print("[red]No contracts selected. Audit cancelled.[/red]")
                        return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=0, findings=[], cancelled=True, scope_id=current_scope_id)
                    
                    # Save scope to database
                    if project_id is not None:
                        scope_rec = self.db.save_audit_scope(project_id, selected_paths)
                        try:
                            current_scope_id = int(scope_rec.get('id')) if scope_rec else None
                        except Exception:
                            current_scope_id = None
                    
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

        # Finalize scope progress after analysis
        try:
            if current_scope_id:
                progress = self.db.recalculate_scope_progress(current_scope_id)
                if isinstance(progress, dict):
                    # Update the scope with calculated progress
                    total_audited = progress.get('total_audited', 0)
                    total_pending = progress.get('total_pending', 0)
                    # Try to get the last analyzed contract ID
                    last_contract_id = 0
                    if 'discovered' in locals():
                        for oc in outcomes:
                            if oc.status == 'success':
                                # Try to match with discovered contracts
                                for disc in discovered:
                                    if disc.file_path == oc.contract_path or str(Path(disc.file_path).relative_to(clone.repo_path)) == oc.contract_path:
                                        last_contract_id = int(oc.contract_id) if hasattr(oc, 'contract_id') else 0
                                        break
                    self.db.update_scope_progress(current_scope_id, last_contract_id, total_audited, total_pending)
                    
                    if total_pending == 0:
                        # Mark scope as completed when no pending items remain
                        self.db.complete_scope(current_scope_id)
        except Exception:
            # Non-fatal; reporting will still work
            pass

        return AuditResult(project_path=clone.repo_path, framework=framework, contracts_analyzed=contracts_analyzed, findings=findings, scope_id=current_scope_id)

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

    def _get_audited_contracts(self, project_id: Optional[int]) -> List[Dict[str, Any]]:
        """Get ALL contracts that were in ANY completed scope for this project."""
        if not project_id:
            return []
        
        try:
            # Get all scopes for this project
            all_scopes = self.db.get_all_scopes(project_id)
            
            # Collect all contracts from all scopes
            all_audited_paths = set()
            for scope in all_scopes:
                selected_contracts = scope.get('selected_contracts', [])
                if isinstance(selected_contracts, str):
                    import json
                    try:
                        selected_contracts = json.loads(selected_contracts)
                    except:
                        selected_contracts = []
                
                for path in selected_contracts:
                    all_audited_paths.add(path)
            
            # Now get the contract details from the database
            contracts = self.db.get_contracts(project_id)
            audited = []
            
            for contract in contracts:
                file_path = contract.get('file_path', '')
                if file_path in all_audited_paths:
                    audited.append({
                        'file_path': file_path,
                        'contract_name': contract.get('contract_name', 'Unknown')
                    })
            
            return audited
        except Exception as e:
            return []

    def _parse_owner_repo(self, github_url: str) -> Tuple[str, str]:
        try:
            if github_url.endswith('.git'):
                github_url = github_url[:-4]
            if 'github.com/' in github_url:
                parts = github_url.split('github.com/', 1)[1].split('/')
                if len(parts) >= 2:
                    return parts[0], parts[1]
        except Exception:
            pass
        return None, None


