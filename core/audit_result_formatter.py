#!/usr/bin/env python3
"""
Audit Result Formatter

Formats findings for display, JSON, and Immunefi-style markdown.
"""

import json
from typing import Any, Dict, List


class AuditResultFormatter:
    def format_for_display(self, findings: List[Dict[str, Any]]) -> str:
        lines: List[str] = []
        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.get('severity','unknown').upper()}: {f.get('contract','?')}:{f.get('summary',{}).get('line', '?')} - {f.get('analysis_type','')}".strip())
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


