#!/usr/bin/env python3
"""
GitHub Audit Report Generator

Generates comprehensive reports from findings stored in the GitHub audit database.
Supports multiple output formats: Markdown, JSON, HTML.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class ContractAnalysis:
    """Summary of a contract's analysis."""
    file_path: str
    contract_name: str
    findings_count: int
    high_severity_count: int
    success_status: bool
    analysis_duration_ms: int
    findings: List[Dict[str, Any]]


class GitHubAuditReportGenerator:
    """Generates comprehensive reports from GitHub audit database findings."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize report generator with database path."""
        if db_path is None:
            db_path = str(Path.home() / '.aether' / 'aether_github_audit.db')
        
        self.db_path = db_path
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not Path(db_path).exists():
            raise FileNotFoundError(f"Database not found at {db_path}")
        
        # Initialize protocol pattern library for retroactive filtering
        try:
            from core.protocol_patterns import ProtocolPatternLibrary
            self.protocol_patterns = ProtocolPatternLibrary()
        except ImportError:
            self.protocol_patterns = None
    
    def generate_report(
        self,
        output_dir: Optional[str] = None,
        scope_id: Optional[int] = None,
        project_id: Optional[int] = None,
        contract_id: Optional[int] = None,
        format: str = "markdown"
    ) -> str:
        """
        Generate comprehensive audit report.
        
        Args:
            output_dir: Directory to save report (default: ./output/reports)
            scope_id: Specific audit scope to report on
            project_id: Specific project to report on
            format: Output format ('markdown', 'json', 'html', or 'all')
        
        Returns:
            Path to generated report(s)
        """
        if output_dir is None:
            output_dir = "./output/reports"
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Gather all findings from database
        findings_data = self._extract_findings(scope_id, project_id, contract_id)
        
        if not findings_data:
            print(f"❌ No findings found for scope_id={scope_id}, project_id={project_id}, contract_id={contract_id}")
            return ""
        
        # Generate reports in requested format(s)
        report_paths = []
        
        if format in ['markdown', 'all']:
            md_path = self._generate_markdown_report(findings_data, output_dir)
            report_paths.append(md_path)
            print(f"✅ Markdown report: {md_path}")
        
        if format in ['json', 'all']:
            json_path = self._generate_json_report(findings_data, output_dir)
            report_paths.append(json_path)
            print(f"✅ JSON report: {json_path}")
        
        if format in ['html', 'all']:
            html_path = self._generate_html_report(findings_data, output_dir)
            report_paths.append(html_path)
            print(f"✅ HTML report: {html_path}")
        
        return ", ".join(report_paths)
    
    def _extract_findings(
        self,
        scope_id: Optional[int] = None,
        project_id: Optional[int] = None,
        contract_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Extract all findings from database for specified scope/project."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # Resolve project and contract when contract_id provided
            project_info = None
            single_contract = None
            if contract_id:
                cursor.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,))
                c_row = cursor.fetchone()
                if not c_row:
                    return {}
                single_contract = dict(c_row)
                pid = int(single_contract['project_id'])
                cursor.execute("SELECT * FROM projects WHERE id = ?", (pid,))
                p_row = cursor.fetchone()
                if not p_row:
                    return {}
                project_info = dict(p_row)
            else:
                # Get project info
                if project_id:
                    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
                else:
                    cursor.execute("SELECT * FROM projects LIMIT 1")
                project = cursor.fetchone()
                if not project:
                    return {}
                project_info = dict(project)
            
            # Get scope info if specified
            scope_info = None
            if scope_id:
                cursor.execute("SELECT * FROM audit_scopes WHERE id = ? AND project_id = ?", 
                             (scope_id, project_info['id']))
            else:
                # Get most recent active scope
                cursor.execute("SELECT * FROM audit_scopes WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
                             (project_info['id'],))
            
            scope = cursor.fetchone()
            if scope:
                scope_info = dict(scope)
            
            # Get contracts
            if contract_id and single_contract:
                contracts = [single_contract]
            elif scope_id and scope_info:
                # Filter contracts to only those in the scope's selected_contracts list
                selected_contracts_json = scope_info.get('selected_contracts', '[]')
                try:
                    selected_paths = json.loads(selected_contracts_json) if isinstance(selected_contracts_json, str) else selected_contracts_json
                except json.JSONDecodeError:
                    selected_paths = []
                
                if selected_paths:
                    # Get only contracts that are in the scope and have analysis results
                    placeholders = ','.join('?' * len(selected_paths))
                    cursor.execute(f"""
                        SELECT DISTINCT c.* FROM contracts c
                        WHERE c.project_id = ? 
                        AND c.file_path IN ({placeholders})
                        AND c.id IN (
                            SELECT contract_id FROM analysis_results 
                            WHERE contract_id IN (
                                SELECT id FROM contracts WHERE project_id = ?
                            )
                        )
                    """, (project_info['id'], *selected_paths, project_info['id']))
                    contracts = [dict(row) for row in cursor.fetchall()]
                else:
                    contracts = []
            else:
                cursor.execute("SELECT * FROM contracts WHERE project_id = ?", (project_info['id'],))
                contracts = [dict(row) for row in cursor.fetchall()]
            
            # Get analysis results and findings for each contract
            contract_analyses = []
            total_findings = 0
            high_severity_findings = 0
            
            for contract in contracts:
                cursor.execute("""
                    SELECT * FROM analysis_results 
                    WHERE contract_id = ? 
                    ORDER BY created_at DESC LIMIT 1
                """, (contract['id'],))
                
                analysis = cursor.fetchone()
                if not analysis:
                    continue
                
                analysis_dict = dict(analysis)
                
                # Parse findings JSON
                findings_json = analysis_dict.get('findings', '{}')
                try:
                    findings_data = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
                except json.JSONDecodeError:
                    findings_data = {}
                
                # Try both possible keys: 'vulnerabilities' (from enhanced analyzer) and 'findings' (legacy)
                findings_list = findings_data.get('vulnerabilities', findings_data.get('findings', []))
                
                # Apply retroactive false positive filtering to clean up old database results
                findings_list = self._filter_legacy_false_positives(findings_list, contract)
                
                findings_count = len(findings_list)
                total_findings += findings_count
                
                # Count high severity
                high_count = sum(1 for f in findings_list if f.get('severity', '').lower() in ['high', 'critical'])
                high_severity_findings += high_count
                
                contract_analysis = ContractAnalysis(
                    file_path=contract['file_path'],
                    contract_name=Path(contract['file_path']).stem,  # Extract from filename (e.g., RocketBase.sol -> RocketBase)
                    findings_count=findings_count,
                    high_severity_count=high_count,
                    success_status=analysis_dict.get('status') == 'success',
                    analysis_duration_ms=int(analysis_dict.get('analysis_duration_ms', 0)),
                    findings=findings_list
                )
                contract_analyses.append(contract_analysis)
            
            # Calculate statistics
            successful_count = sum(1 for a in contract_analyses if a.success_status)
            avg_duration = sum(a.analysis_duration_ms for a in contract_analyses) / len(contract_analyses) if contract_analyses else 0
            
            return {
                'project': project_info,
                'scope': scope_info,
                'timestamp': self.timestamp,
                'contracts': contract_analyses,
                'statistics': {
                    'total_contracts_analyzed': len(contract_analyses),
                    'successful_analyses': successful_count,
                    'total_findings': total_findings,
                    'high_severity_findings': high_severity_findings,
                    'average_analysis_time_ms': avg_duration,
                }
            }
        
        finally:
            conn.close()
    
    def _generate_markdown_report(self, findings_data: Dict[str, Any], output_dir: str) -> str:
        """Generate Markdown format report."""
        project = findings_data['project']
        scope = findings_data['scope']
        contracts = findings_data['contracts']
        stats = findings_data['statistics']
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(output_dir) / f"audit_report_{project['repo_name']}_{timestamp}.md"
        
        content = f"""# GitHub Audit Report

**Project:** {project['repo_name']}
**URL:** {project['url']}
**Generated:** {findings_data['timestamp']}

## Executive Summary

- **Total Contracts Analyzed:** {stats['total_contracts_analyzed']}
- **Successful Analyses:** {stats['successful_analyses']}
- **Total Findings:** {stats['total_findings']}
- **High Severity Findings:** {stats['high_severity_findings']}
- **Average Analysis Time:** {stats['average_analysis_time_ms']:.0f}ms

"""
        
        if scope:
            content += f"""## Audit Scope

- **Scope ID:** {scope['id']}
- **Status:** {scope['status']}
- **Contracts in Scope:** {scope['total_selected']}
- **Audited:** {scope['total_audited']}
- **Pending:** {scope['total_pending']}

"""
        
        # Summary by severity
        content += "## Findings by Severity\n\n"
        
        severity_counts = defaultdict(int)
        for contract in contracts:
            for finding in contract.findings:
                severity = finding.get('severity', 'unknown').lower()
                severity_counts[severity] += 1
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in severity_counts:
                content += f"- **{severity.title()}:** {severity_counts[severity]}\n"
        
        content += "\n"
        
        # Detailed findings by contract
        content += "## Detailed Findings by Contract\n\n"
        
        for contract in sorted(contracts, key=lambda c: c.findings_count, reverse=True):
            if contract.findings_count == 0:
                continue
            
            content += f"""### {contract.contract_name} ({contract.file_path})

**Status:** {'✅ Success' if contract.success_status else '❌ Failed'}
**Analysis Time:** {contract.analysis_duration_ms}ms
**Findings:** {contract.findings_count} ({contract.high_severity_count} high/critical)

"""
            
            # Group findings by severity
            by_severity = defaultdict(list)
            for finding in contract.findings:
                severity = finding.get('severity', 'unknown').lower()
                by_severity[severity].append(finding)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity not in by_severity:
                    continue
                
                content += f"#### {severity.title()} Severity\n\n"
                
                for finding in by_severity[severity]:
                    title = finding.get('title', finding.get('type', finding.get('description', 'Unknown')))
                    desc = finding.get('description', '')
                    confidence = finding.get('confidence', 0)
                    line = finding.get('line', finding.get('line_number', 'Unknown'))
                    
                    content += f"""**{title}**
- Line: {line}
- Confidence: {confidence:.1%}
- Description: {desc}

"""
        
        # Contracts with no findings
        clean_contracts = [c for c in contracts if c.findings_count == 0]
        if clean_contracts:
            content += f"""## Clean Contracts

The following {len(clean_contracts)} contracts had no findings:

"""
            for contract in clean_contracts:
                content += f"- {contract.contract_name} ({contract.file_path})\n"
            content += "\n"
        
        # Footer
        content += """---

*Report generated by AetherAudit GitHub Audit Tool*
*For security research and bug bounty purposes*
"""
        
        output_path.write_text(content)
        return str(output_path)
    
    def _generate_json_report(self, findings_data: Dict[str, Any], output_dir: str) -> str:
        """Generate JSON format report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = findings_data['project']['repo_name']
        output_path = Path(output_dir) / f"audit_report_{project_name}_{timestamp}.json"
        
        # Convert dataclasses to dicts
        export_data = {
            'project': findings_data['project'],
            'scope': findings_data['scope'],
            'timestamp': findings_data['timestamp'],
            'statistics': findings_data['statistics'],
            'contracts': [asdict(c) for c in findings_data['contracts']]
        }
        
        output_path.write_text(json.dumps(export_data, indent=2, default=str))
        return str(output_path)
    
    def _generate_html_report(self, findings_data: Dict[str, Any], output_dir: str) -> str:
        """Generate HTML format report."""
        project = findings_data['project']
        scope = findings_data['scope']
        contracts = findings_data['contracts']
        stats = findings_data['statistics']
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(output_dir) / f"audit_report_{project['repo_name']}_{timestamp}.html"
        
        # Calculate severity stats
        severity_counts = defaultdict(int)
        for contract in contracts:
            for finding in contract.findings:
                severity = finding.get('severity', 'unknown').lower()
                severity_counts[severity] += 1
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report - {project['repo_name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 40px;
        }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .meta {{ opacity: 0.9; font-size: 0.95em; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{ color: #667eea; margin-bottom: 10px; }}
        .stat-card .value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .severity-critical {{ color: #e63946; }}
        .severity-high {{ color: #f77f00; }}
        .severity-medium {{ color: #fcbf49; }}
        .severity-low {{ color: #06a77d; }}
        .severity-info {{ color: #118ab2; }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #e63946; }}
        .finding.high {{ border-left-color: #f77f00; }}
        .finding.medium {{ border-left-color: #fcbf49; }}
        .finding.low {{ border-left-color: #06a77d; }}
        .finding.info {{ border-left-color: #118ab2; }}
        .finding h4 {{ margin-bottom: 10px; }}
        .finding .meta {{ font-size: 0.9em; color: #666; margin: 5px 0; }}
        .contract-section {{
            background: white;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .contract-section h2 {{ color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .clean {{ background: #f0fdf4; border-left-color: #22c55e; }}
        footer {{ text-align: center; margin-top: 40px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 AetherAudit Report</h1>
            <p class="meta">Project: <strong>{project['repo_name']}</strong></p>
            <p class="meta">Generated: {findings_data['timestamp']}</p>
            <p class="meta">Repository: <a href="{project['url']}" style="color: white; text-decoration: underline;">{project['url']}</a></p>
        </header>

        <section class="summary">
            <div class="stat-card">
                <h3>Contracts Analyzed</h3>
                <div class="value">{stats['total_contracts_analyzed']}</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">{stats['total_findings']}</div>
            </div>
            <div class="stat-card">
                <h3 class="severity-critical">Critical/High Findings</h3>
                <div class="value severity-critical">{stats['high_severity_findings']}</div>
            </div>
            <div class="stat-card">
                <h3>Analysis Time</h3>
                <div class="value">{stats['average_analysis_time_ms']:.0f}ms avg</div>
            </div>
        </section>

        <section>
            <div class="contract-section">
                <h2>📊 Findings Summary</h2>
"""
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                html += f'<p><span class="severity-{severity}">● {severity.title()}:</span> {count} findings</p>'
        
        html += "</div></section>"
        
        # Findings by contract
        for contract in sorted(contracts, key=lambda c: c.findings_count, reverse=True):
            html += f"""
        <section class="contract-section">
            <h2>{contract.contract_name}</h2>
            <p class="meta">File: <code>{contract.file_path}</code></p>
            <p class="meta">Status: {'✅ Success' if contract.success_status else '❌ Failed'} | Analysis: {contract.analysis_duration_ms}ms</p>
"""
            
            if contract.findings_count == 0:
                html += '<p style="color: #22c55e; font-weight: bold;">✓ No findings</p>'
            else:
                for finding in contract.findings:
                    severity = finding.get('severity', 'unknown').lower()
                    title = finding.get('title', finding.get('type', finding.get('description', 'Unknown')))
                    desc = finding.get('description', '')
                    confidence = finding.get('confidence', 0)
                    line = finding.get('line', finding.get('line_number', 'Unknown'))
                    
                    html += f"""
            <div class="finding {severity}">
                <h4><span class="severity-{severity}">●</span> {title}</h4>
                <div class="meta">Line: <strong>{line}</strong> | Severity: <strong>{severity.title()}</strong> | Confidence: {confidence:.0%}</div>
                <p>{desc}</p>
            </div>
"""
            
            html += "</section>"
        
        html += """
        <footer>
            <p>Report generated by <strong>AetherAudit GitHub Audit Tool</strong></p>
            <p>For security research and bug bounty purposes</p>
        </footer>
    </div>
</body>
</html>
"""
        
        output_path.write_text(html)
        return str(output_path)
    
    def _filter_legacy_false_positives(
        self, 
        findings: List[Dict[str, Any]], 
        contract: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Apply retroactive false positive filtering to legacy database findings.
        
        This filters out known false positives from old audits that were run
        before the protocol pattern library was implemented.
        """
        if not self.protocol_patterns or not findings:
            return findings
        
        # Try to load contract code for pattern matching
        contract_path = contract.get('file_path', '')
        contract_code = ""
        
        if contract_path and Path(contract_path).exists():
            try:
                with open(contract_path, 'r', encoding='utf-8') as f:
                    contract_code = f.read()
            except Exception:
                pass  # Continue without contract code
        
        if not contract_code:
            # Can't filter without contract code
            return findings
        
        # Filter findings using protocol patterns
        filtered_findings = []
        filtered_count = 0
        
        for finding in findings:
            vuln_type = finding.get('vulnerability_type', finding.get('type', ''))
            
            # Build context for pattern matching
            context = {
                'file_path': contract_path,
                'code_snippet': finding.get('code_snippet', ''),
                'surrounding_context': contract_code,
                'function_context': finding.get('context', {}).get('function_context', ''),
                'line_number': finding.get('line_number', finding.get('line', 0)),
            }
            
            # Check if it matches a known false positive pattern
            pattern = self.protocol_patterns.check_pattern_match(
                vuln_type, contract_code, context
            )
            
            if pattern and pattern.acceptable_behavior:
                # Check Solidity version compatibility if specified
                if pattern.solidity_version_specific:
                    version = self.protocol_patterns.extract_solidity_version(contract_code)
                    if version and not self.protocol_patterns.check_solidity_version_compatibility(pattern, version):
                        # Version mismatch - keep the finding
                        filtered_findings.append(finding)
                        continue
                
                # This is a known false positive - filter it out
                filtered_count += 1
                print(f"   🔍 Filtered legacy false positive: {vuln_type} at line {context['line_number']} ({pattern.reason[:60]}...)")
                continue
            
            # Keep the finding
            filtered_findings.append(finding)
        
        if filtered_count > 0:
            print(f"   ✅ Filtered {filtered_count} legacy false positive(s) from {contract.get('file_path', 'unknown')}")
        
        return filtered_findings


if __name__ == "__main__":
    import sys
    
    # Example usage
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    else:
        output_dir = None
    
    generator = GitHubAuditReportGenerator()
    reports = generator.generate_report(output_dir=output_dir, format="all")
    print(f"\n✅ Reports generated:\n{reports}")
