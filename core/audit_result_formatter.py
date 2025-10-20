#!/usr/bin/env python3
"""
Audit Result Formatter

Formats findings for display, JSON, and Immunefi-style markdown.
"""

import json
from typing import Any, Dict, List


class AuditResultFormatter:
    def format_for_display(self, findings: List[Dict[str, Any]]) -> str:
        """
        Format findings for display, handling both flat and nested structures.
        
        Nested structure (from GitHub auditor):
        {
            'contract': 'path/to/contract.sol',
            'analysis_type': 'enhanced',
            'summary': {
                'vulnerabilities': [
                    {'type': '...', 'severity': '...', 'line': 0, 'description': '...'}
                ]
            }
        }
        
        Flat structure (legacy):
        {
            'severity': '...',
            'contract': '...',
            'line': '...'
        }
        """
        lines: List[str] = []
        finding_num = 1
        
        for f in findings:
            # Check if this is nested structure (GitHub auditor format)
            summary = f.get('summary', {})
            if isinstance(summary, dict) and 'vulnerabilities' in summary:
                # Extract vulnerabilities from nested structure
                vulnerabilities = summary.get('vulnerabilities', [])
                contract_path = f.get('contract', '?')
                analysis_type = f.get('analysis_type', '')
                
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'unknown').upper()
                    line = vuln.get('line', '?')
                    vuln_type = vuln.get('type', 'Unknown')
                    description = vuln.get('description', '')[:100]  # Truncate long descriptions
                    
                    line_display = f"[{finding_num}] {severity}: {contract_path}:{line} - {analysis_type}"
                    if vuln_type and vuln_type != 'Unknown':
                        line_display += f"\n    {vuln_type}"
                    if description:
                        line_display += f"\n    {description}"
                    
                    lines.append(line_display)
                    finding_num += 1
            else:
                # Legacy flat structure
                severity = f.get('severity', 'unknown').upper()
                contract = f.get('contract', '?')
                line = f.get('summary', {}).get('line', '?') if isinstance(f.get('summary'), dict) else '?'
                analysis_type = f.get('analysis_type', '')
                
                lines.append(f"[{finding_num}] {severity}: {contract}:{line} - {analysis_type}".strip())
                finding_num += 1
        
        if not lines:
            return "No findings to display"
        
        return "\n".join(lines)

    def format_for_json(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            'total_findings': len(findings),
            'by_contract': self._group_by(findings, key='contract'),
            'by_analysis_type': self._group_by(findings, key='analysis_type'),
            'items': findings,
        }

    def format_for_immunefi(self, findings: List[Dict[str, Any]], project_info: Dict[str, Any]) -> str:
        out: List[str] = []
        out.append(f"# Immunefi Submission\n")
        out.append(f"Project: {project_info.get('url','unknown')}\n")
        out.append(f"Repo: {project_info.get('repo_name','unknown')}\n")
        out.append(f"Framework: {project_info.get('framework','unknown')}\n")
        out.append("\n## Vulnerabilities Found\n")
        for i, f in enumerate(findings, 1):
            summary = f.get('summary', {})
            out.append(f"### {i}. {f.get('analysis_type','finding')}\n")
            out.append(f"- Severity: {summary.get('severity','low')}\n")
            out.append(f"- Location: {f.get('contract','?')}:{summary.get('line','?')}\n")
            out.append(f"- Description: {summary}\n")
            out.append("")
        return "\n".join(out)

    def _group_by(self, findings: List[Dict[str, Any]], key: str) -> Dict[str, List[Dict[str, Any]]]:
        g: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            k = str(f.get(key, 'unknown'))
            g.setdefault(k, []).append(f)
        return g


