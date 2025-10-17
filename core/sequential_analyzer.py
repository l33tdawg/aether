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
            # Only skip pure Solidity interfaces (interface keyword defines a pure interface)
            # Do NOT skip abstract contracts - they may have implementation code
            if 'interface ' in content and '{' in content:
                # Check if it's a true Solidity interface
                # Interfaces only have function signatures, no implementation
                # If it has 'function' with ';' (signature only), it's likely an interface
                lines = content.split('\n')
                for line in lines:
                    stripped = line.strip()
                    # If we find 'interface' keyword at top level
                    if stripped.startswith('interface ') and not stripped.startswith('interface I'):
                        # This is declaring an interface, not implementing
                        return True
                    # More specific: interface declarations followed by opening brace
                    if stripped.startswith('interface '):
                        return True
            return False
        except Exception:
            return False

    def _is_mock_or_test_contract(self, file_path: Path) -> bool:
        """Check if a contract is a mock or test contract (should be skipped in production audits)."""
        try:
            file_name = file_path.name.lower()
            file_path_str = str(file_path).lower()
            
            # Check file path patterns
            test_dirs = ['test', 'tests', 'mocks', 'mock', 'spec', 'specs', '__tests__', '.test', '.spec']
            for test_dir in test_dirs:
                if f'/{test_dir}/' in file_path_str or file_path_str.startswith(f'{test_dir}/'):
                    return True
            
            # Check file name patterns
            mock_patterns = [
                'mock.sol', 'mock_', '_mock.sol',
                'test.sol', 'test_', '_test.sol',
                'stub.sol', 'stub_', '_stub.sol',
                'fake.sol', 'fake_', '_fake.sol',
                '.test.sol', '.spec.sol', '.mock.sol',
            ]
            for pattern in mock_patterns:
                if pattern in file_name:
                    return True
            
            # Check contract-level patterns in content
            content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
            
            # Common mock/test contract names and patterns
            mock_names = [
                'mock',
                'test',
                'stub',
                'fake',
                'dummy',
                'scaffold',
                'example',
            ]
            
            # Check if contract name contains mock indicators
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                # Look for contract declarations with mock indicators
                if stripped.startswith('contract '):
                    # Extract contract name
                    parts = stripped.split()
                    if len(parts) >= 2:
                        contract_name = parts[1].split('{')[0].split('(')[0]
                        contract_name_lower = contract_name.lower()
                        
                        # Check against mock patterns
                        for mock_pattern in mock_names:
                            if mock_pattern in contract_name_lower:
                                return True
            
            return False
        except Exception:
            return False

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
            if self._is_mock_or_test_contract(contract_path):
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
                self.console.print(f"[yellow]⏭️  {idx}/{len(contract_relative_paths)}: {contract_name} (skipped - mock/test)[/yellow]")
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
                status = 'failed'
                findings = {'error': str(e), 'error_type': 'analysis_failed'}

                self.db.save_analysis_result(
                    contract_id=self._get_contract_id(project_id, rel),
                    analysis_type='enhanced',
                    findings=findings,
                    status=status,
                    error_log=str(e),
                    analysis_duration_ms=duration_ms,
                )

                duration_sec = duration_ms / 1000
                self.console.print(f" [red]❌ failed ({duration_sec:.1f}s)[/red]")
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
                findings['vulnerabilities'].append({
                    'type': vuln.get('title', vuln.get('vulnerability_type', 'Unknown')),
                    'severity': vuln.get('severity', 'unknown'),
                    'description': vuln.get('description', ''),
                    'line': vuln.get('line', vuln.get('line_number', 0)),
                    'confidence': vuln.get('confidence', 0.0)
                })

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


