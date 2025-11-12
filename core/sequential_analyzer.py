#!/usr/bin/env python3
"""
Sequential Analyzer (Phase 2)

Runs simple static checks on discovered contracts and persists results.
This is a placeholder for deeper analyzers; keeps interface stable.
"""

import asyncio
import time
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

from rich.console import Console

from core.database_manager import AetherDatabase
from core.enhanced_audit_engine import EnhancedAetherAuditEngine


@dataclass
class AnalysisOutcome:
    contract_path: str
    analysis_type: str
    findings: Dict[str, any]
    status: str
    duration_ms: int


class SequentialAnalyzer:
    def __init__(self, db: Optional[AetherDatabase] = None, use_enhanced_analysis: bool = False):
        self.console = Console()
        self.db = db or AetherDatabase()
        self.use_enhanced_analysis = use_enhanced_analysis

    def _is_abstract_interface(self, file_path: Path) -> bool:
        """Check if a contract is a pure abstract interface (no implementation)."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Get the expected name from filename (e.g., "StablePriceOracle.sol" -> "StablePriceOracle")
            expected_name = file_path.stem  # filename without extension
            
            # Find the definition that matches the filename
            lines = content.split('\n')
            main_definition = None
            in_multiline_comment = False
            
            for line in lines:
                stripped = line.strip()
                
                # Skip multiline comments
                if '/*' in stripped:
                    in_multiline_comment = True
                if '*/' in stripped:
                    in_multiline_comment = False
                    continue
                if in_multiline_comment or stripped.startswith('//'):
                    continue
                
                # Look for contract/interface/library declarations that match filename
                # Match: "interface Name", "contract Name", "abstract contract Name", "library Name"
                for keyword in ['interface ', 'contract ', 'abstract contract ', 'library ']:
                    if stripped.startswith(keyword):
                        # Extract the name after the keyword (before 'is', '{', or whitespace)
                        rest = stripped[len(keyword):].strip()
                        # Get the name (first word)
                        name = rest.split()[0] if rest.split() else ''
                        
                        # If this definition matches the filename, it's the main one
                        if name == expected_name:
                            main_definition = stripped
                            break
                
                if main_definition:
                    break
            
            # If the main definition (matching filename) is an interface, skip it
            if main_definition and main_definition.startswith('interface '):
                return True
                
            return False
        except Exception:
            return False

    def _is_mock_or_test_contract(self, file_path: Path) -> bool:
        """Check if a contract is a mock or test contract (should be skipped in production audits)."""
        try:
            file_name = file_path.name.lower()
            file_path_str = str(file_path).lower()
            
            # PRIORITY 1: Check file path patterns (most reliable indicator)
            # If contract is in test/mock directory, it's definitely a test/mock
            test_dirs = ['test', 'tests', 'mocks', 'mock', 'spec', 'specs', '__tests__', '.test', '.spec']
            for test_dir in test_dirs:
                if f'/{test_dir}/' in file_path_str or file_path_str.startswith(f'{test_dir}/'):
                    return True
            
            # PRIORITY 2: Check file name patterns (reliable if matches common patterns)
            # Only match complete patterns, not substrings
            mock_filename_patterns = [
                'mock.sol',           # exact: mock.sol
                '.mock.sol',          # exact: something.mock.sol
                '_mock.sol',          # exact: something_mock.sol
                'mock_',              # prefix: mock_something.sol
                'test.sol',           # exact: test.sol
                '.test.sol',          # exact: something.test.sol
                '_test.sol',          # exact: something_test.sol
                'test_',              # prefix: test_something.sol
                'stub.sol',
                '_stub.sol',
                'stub_',
                'fake.sol',
                '_fake.sol',
                'fake_',
            ]
            for pattern in mock_filename_patterns:
                if pattern in file_name:
                    return True
            
            # PRIORITY 3: Check contract-level patterns in content (less reliable)
            # This is a secondary check - file path and filename are more reliable
            content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
            
            # More specific patterns - look for contracts that START with mock/test or end with Mock/Test
            mock_name_patterns = [
                'mock',      # appears anywhere (common in mocks like ERC20Mock, UniswapV2PairMock)
                'test',      # appears anywhere (common in test contracts)
                'stub',      # appears anywhere
                'fake',      # appears anywhere
                'dummy',     # appears anywhere
                'scaffold',  # appears anywhere
                'example',   # appears anywhere
            ]
            
            # Check if contract name contains mock indicators
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                # Skip comments
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                    continue
                
                # Look for contract declarations with mock indicators
                if stripped.startswith('contract ') and not stripped.startswith('contract interface'):
                    # Extract contract name
                    parts = stripped.split()
                    if len(parts) >= 2:
                        contract_name = parts[1].split('{')[0].split('(')[0].split('is')[0].strip()
                        contract_name_lower = contract_name.lower()
                        
                        # Check against mock patterns - but be more conservative
                        # Only flag if the pattern appears as a distinct word or at start/end
                        for mock_pattern in mock_name_patterns:
                            # Check if pattern is at start, end, or as whole word
                            if (contract_name_lower.startswith(mock_pattern) or
                                contract_name_lower.endswith(mock_pattern) or
                                f'{mock_pattern}' in contract_name_lower):
                                return True
            
            return False
        except Exception:
            return False

    def _get_mock_or_test_reason(self, file_path: Path) -> Optional[str]:
        """Get the reason why a contract is considered a mock/test (returns None if not a mock/test)."""
        try:
            file_name = file_path.name.lower()
            file_path_str = str(file_path).lower()
            
            # PRIORITY 1: Check file path patterns (most reliable indicator)
            test_dirs = ['test', 'tests', 'mocks', 'mock', 'spec', 'specs', '__tests__', '.test', '.spec']
            for test_dir in test_dirs:
                if f'/{test_dir}/' in file_path_str or file_path_str.startswith(f'{test_dir}/'):
                    return f"path contains '{test_dir}/'"
            
            # PRIORITY 2: Check file name patterns
            mock_filename_patterns = [
                ('mock.sol', 'filename is mock.sol'),
                ('.mock.sol', 'filename contains .mock.sol'),
                ('_mock.sol', 'filename ends with _mock.sol'),
                ('mock_', 'filename starts with mock_'),
                ('test.sol', 'filename is test.sol'),
                ('.test.sol', 'filename contains .test.sol'),
                ('_test.sol', 'filename ends with _test.sol'),
                ('test_', 'filename starts with test_'),
                ('stub.sol', 'filename is stub.sol'),
                ('_stub.sol', 'filename ends with _stub.sol'),
                ('stub_', 'filename starts with stub_'),
                ('fake.sol', 'filename is fake.sol'),
                ('_fake.sol', 'filename ends with _fake.sol'),
                ('fake_', 'filename starts with fake_'),
            ]
            for pattern, reason in mock_filename_patterns:
                if pattern in file_name:
                    return reason
            
            # PRIORITY 3: Check contract-level patterns in content
            content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
            
            mock_name_patterns = ['mock', 'test', 'stub', 'fake', 'dummy', 'scaffold', 'example']
            
            # Check if contract name contains mock indicators
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                # Skip comments
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                    continue
                
                # Look for contract declarations with mock indicators
                if stripped.startswith('contract ') and not stripped.startswith('contract interface'):
                    # Extract contract name
                    parts = stripped.split()
                    if len(parts) >= 2:
                        contract_name = parts[1].split('{')[0].split('(')[0].split('is')[0].strip()
                        contract_name_lower = contract_name.lower()
                        
                        # Check against mock patterns
                        for mock_pattern in mock_name_patterns:
                            if (contract_name_lower.startswith(mock_pattern) or
                                contract_name_lower.endswith(mock_pattern) or
                                f'{mock_pattern}' in contract_name_lower):
                                return f"contract name contains '{mock_pattern}'"
            
            return None
        except Exception:
            return None

    def analyze_contracts(self, project_id: int, project_path: Union[str, Path], contract_relative_paths: List[str], force: bool = False) -> List[AnalysisOutcome]:
        outcomes: List[AnalysisOutcome] = []

        # Use enhanced analysis engine if requested
        if self.use_enhanced_analysis:
            return self._analyze_with_enhanced_engine(project_id, project_path, contract_relative_paths, force)

        # Otherwise use basic analysis
        for rel in contract_relative_paths:
            start = time.time()
            # Check cache
            if not force:
                cached = self._get_cached(project_id, rel)
                if cached is not None:
                    outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='basic_static', findings=cached, status='cached', duration_ms=0))
                    continue

            findings = self._basic_static_checks(Path(project_path) / rel)
            duration_ms = int((time.time() - start) * 1000)
            status = 'success'
            self.db.save_analysis_result(
                contract_id=self._get_contract_id(project_id, rel),
                analysis_type='basic_static',
                findings=findings,
                status=status,
                analysis_duration_ms=duration_ms,
            )
            outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='basic_static', findings=findings, status=status, duration_ms=duration_ms))
        return outcomes

    def _get_cached(self, project_id: int, rel_path: str) -> Optional[Dict[str, any]]:
        contracts = self.db.get_contracts(project_id)
        for c in contracts:
            if c.get('file_path') == rel_path:
                results = self.db.get_analysis_results(int(c['id']))
                for r in results:
                    # Check for any successful analysis (basic_static, enhanced, etc.)
                    if r.get('findings') and r.get('status') == 'success':
                        try:
                            return json.loads(r['findings']) if isinstance(r['findings'], str) else r['findings']
                        except Exception:
                            return None
        return None

    def _get_contract_id(self, project_id: int, rel_path: str) -> int:
        # Small helper to get contract id; DB API doesn't expose a direct fetch-by-path
        contracts = self.db.get_contracts(project_id)
        for c in contracts:
            if c.get('file_path') == rel_path:
                return int(c['id'])
        # Should not happen if discovery ran first; create a placeholder if needed
        created = self.db.save_contract(project_id, rel_path, info={'contract_name': None, 'solc_version': None, 'line_count': 0, 'dependencies': []})
        return int(created['id']) if created and created.get('id') else 0

    def _basic_static_checks(self, file_path: Path) -> Dict[str, any]:
        try:
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            text = ''
        lines = text.splitlines()
        total = len(lines)
        payable_count = sum(1 for ln in lines if 'payable' in ln)
        selfdestruct_count = sum(1 for ln in lines if 'selfdestruct' in ln or 'suicide' in ln)
        unchecked_count = sum(1 for ln in lines if 'unchecked' in ln)
        return {
            'total_lines': total,
            'payable_occurrences': payable_count,
            'selfdestruct_occurrences': selfdestruct_count,
            'unchecked_blocks': unchecked_count,
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': int(payable_count > 10) + int(unchecked_count > 0),
            },
            'total_findings': int(payable_count > 10) + int(unchecked_count > 0) + int(selfdestruct_count > 0),
        }

    def _analyze_with_enhanced_engine(self, project_id: int, project_path: Union[str, Path], contract_relative_paths: List[str], force: bool = False) -> List[AnalysisOutcome]:
        """Use EnhancedAetherAuditEngine for comprehensive analysis."""
        outcomes: List[AnalysisOutcome] = []

        # Initialize enhanced audit engine with AetherDatabase for GitHub audit compatibility
        enhanced_engine = EnhancedAetherAuditEngine(verbose=True, database=self.db)

        for idx, rel in enumerate(contract_relative_paths, 1):
            start = time.time()
            contract_path = Path(project_path) / rel
            contract_name = contract_path.name  # e.g., "RocketBase.sol"

            # Check if this is an abstract interface (skip analysis - no implementation to analyze)
            if self._is_abstract_interface(contract_path):
                duration_ms = int((time.time() - start) * 1000)
                # Save as skipped with empty findings
                empty_findings = {'total_findings': 0, 'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}, 'vulnerabilities': [], 'analysis_types': ['skipped_interface']}
                self.db.save_analysis_result(
                    contract_id=self._get_contract_id(project_id, rel),
                    analysis_type='enhanced',
                    findings=empty_findings,
                    status='skipped',
                    analysis_duration_ms=duration_ms,
                )
                self.console.print(f"[yellow]⏭️  {idx}/{len(contract_relative_paths)}: {contract_name} (skipped - interface)[/yellow]")
                outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='enhanced', findings=empty_findings, status='skipped', duration_ms=duration_ms))
                continue

            # Check if this is a mock or test contract (skip analysis)
            mock_reason = self._get_mock_or_test_reason(contract_path)
            if mock_reason:
                duration_ms = int((time.time() - start) * 1000)
                # Save as skipped with empty findings
                empty_findings = {'total_findings': 0, 'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}, 'vulnerabilities': [], 'analysis_types': ['skipped_mock_test']}
                self.db.save_analysis_result(
                    contract_id=self._get_contract_id(project_id, rel),
                    analysis_type='enhanced',
                    findings=empty_findings,
                    status='skipped',
                    analysis_duration_ms=duration_ms,
                )
                self.console.print(f"[yellow]⏭️  {idx}/{len(contract_relative_paths)}: {contract_name} (skipped - {mock_reason})[/yellow]")
                outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='enhanced', findings=empty_findings, status='skipped', duration_ms=duration_ms))
                continue

            # Check cache first
            if not force:
                cached = self._get_cached(project_id, rel)
                if cached is not None:
                    duration_ms = int((time.time() - start) * 1000)
                    self.console.print(f"[cyan]⚡ {idx}/{len(contract_relative_paths)}: {contract_name} (cached)[/cyan]")
                    outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='enhanced', findings=cached, status='cached', duration_ms=duration_ms))
                    continue

            try:
                # Display progress: Currently analyzing
                self.console.print(f"[bold cyan]🔍 {idx}/{len(contract_relative_paths)}: {contract_name}[/bold cyan]", end="")
                
                # Run enhanced audit on the contract
                results = asyncio.run(enhanced_engine.run_enhanced_audit_with_llm_validation(
                    str(contract_path),
                    output_dir=None,
                    enable_foundry_tests=False
                ))

                duration_ms = int((time.time() - start) * 1000)
                status = 'success'

                # Extract findings from results
                findings = self._extract_findings_from_results(results)
                finding_count = findings.get('total_findings', 0)

                self.db.save_analysis_result(
                    contract_id=self._get_contract_id(project_id, rel),
                    analysis_type='enhanced',
                    findings=findings,
                    status=status,
                    analysis_duration_ms=duration_ms,
                )

                # Display completion with findings count and duration
                duration_sec = duration_ms / 1000
                if finding_count > 0:
                    self.console.print(f" [green]✅ {finding_count} finding{'s' if finding_count != 1 else ''} ({duration_sec:.1f}s)[/green]")
                else:
                    self.console.print(f" [green]✅ clean ({duration_sec:.1f}s)[/green]")
                
                outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='enhanced', findings=findings, status=status, duration_ms=duration_ms))

            except Exception as e:
                duration_ms = int((time.time() - start) * 1000)
                status = 'error'
                findings = {'error': str(e), 'error_type': 'analysis_error'}

                self.db.save_analysis_result(
                    contract_id=self._get_contract_id(project_id, rel),
                    analysis_type='enhanced',
                    findings=findings,
                    status=status,
                    error_log=str(e),
                    analysis_duration_ms=duration_ms,
                )

                duration_sec = duration_ms / 1000
                self.console.print(f" [red]❌ error ({duration_sec:.1f}s)[/red]")
                outcomes.append(AnalysisOutcome(contract_path=rel, analysis_type='enhanced', findings=findings, status=status, duration_ms=duration_ms))

        return outcomes

    def _extract_findings_from_results(self, results: Dict[str, any]) -> Dict[str, any]:
        """Extract findings from enhanced audit results."""
        findings = {
            'total_findings': 0,
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'vulnerabilities': [],
            'analysis_types': []
        }

        # Try multiple paths where vulnerabilities might be stored
        vulnerabilities = []
        
        # Check results['results']['vulnerabilities'] (new format from enhanced audit engine)
        if 'results' in results and isinstance(results['results'], dict) and 'vulnerabilities' in results['results']:
            vulnerabilities = results['results']['vulnerabilities']
        # Check results['audit']['vulnerabilities'] (legacy format)
        elif 'audit' in results and isinstance(results['audit'], dict) and 'vulnerabilities' in results['audit']:
            vulnerabilities = results['audit']['vulnerabilities']
        # Check results['vulnerabilities'] directly
        elif 'vulnerabilities' in results and isinstance(results['vulnerabilities'], list):
            vulnerabilities = results['vulnerabilities']
        # Check results['llm_validation_results'] (another possible location)
        elif 'llm_validation_results' in results and isinstance(results['llm_validation_results'], list):
            vulnerabilities = results['llm_validation_results']
        
        # Extract vulnerabilities from wherever they are
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln_dict = {
                    'type': vuln.get('title', vuln.get('vulnerability_type', 'Unknown')),
                    'severity': vuln.get('severity', 'unknown'),
                    'description': vuln.get('description', ''),
                    'line': vuln.get('line', vuln.get('line_number', 0)),
                    'confidence': vuln.get('confidence', 0.0)
                }

                # Preserve bug bounty assessment metadata if present
                if 'bug_bounty_assessment' in vuln:
                    vuln_dict['bug_bounty_assessment'] = vuln['bug_bounty_assessment']

                findings['vulnerabilities'].append(vuln_dict)

                # Update severity counts
                severity = vuln.get('severity', 'unknown').lower()
                if severity in findings['severity_counts']:
                    findings['severity_counts'][severity] += 1

        findings['total_findings'] = len(findings['vulnerabilities'])

        # Add analysis types
        if 'audit' in results:
            findings['analysis_types'].append('enhanced_audit')
        if 'validation' in results or 'llm_validation' in results:
            findings['analysis_types'].append('llm_validation')

        return findings


