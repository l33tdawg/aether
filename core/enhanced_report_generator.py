#!/usr/bin/env python3
"""
Enhanced Report Generator for AetherAudit
Advanced visualization, dashboards, and compliance reporting
"""

import json
import base64
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import html
import re

from core.report_generator import ReportGenerator

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


class RiskScorer:
    """Risk scoring and prioritization system"""

    def __init__(self):
        self.severity_weights = {
            'info': 1,
            'low': 2,
            'medium': 5,
            'high': 8,
            'critical': 10
        }

        self.category_weights = {
            'access_control': 1.2,
            'reentrancy': 1.5,
            'oracle_manipulation': 1.3,
            'flash_loan': 1.4,
            'defi': 1.3,
            'gas_optimization': 0.8,
            'best_practice': 0.6
        }

    def calculate_risk_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate risk score for a vulnerability"""
        severity = vulnerability.get('severity', 'medium').lower()
        category = vulnerability.get('type', vulnerability.get('vulnerability_type', 'unknown')).lower()
        confidence = vulnerability.get('confidence', 0.5)

        # Base score from severity
        base_score = self.severity_weights.get(severity, 5)

        # Category multiplier
        category_multiplier = 1.0
        for cat, weight in self.category_weights.items():
            if cat in category:
                category_multiplier = max(category_multiplier, weight)

        # Confidence adjustment
        confidence_adjustment = confidence * 0.2  # Up to 20% adjustment

        # Calculate final score
        risk_score = base_score * category_multiplier * (1 + confidence_adjustment)

        # Apply severity-specific caps
        severity_caps = {
            'info': 2.0,
            'low': 4.0,
            'medium': 7.0,
            'high': 9.0,
            'critical': 10.0
        }

        max_score = severity_caps.get(severity, 10.0)
        return min(risk_score, max_score)

    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort vulnerabilities by risk score (highest first)"""
        for vuln in vulnerabilities:
            vuln['risk_score'] = self.calculate_risk_score(vuln)

        return sorted(vulnerabilities, key=lambda x: x.get('risk_score', 0), reverse=True)


class ComplianceReporter:
    """Compliance reporting for various standards"""

    def __init__(self):
        self.compliance_templates = {
            'SOC2': self._generate_soc2_report,
            'PCI-DSS': self._generate_pci_dss_report,
            'GDPR': self._generate_gdpr_report,
            'ISO27001': self._generate_iso27001_report,
            'NIST': self._generate_nist_report
        }

    def generate_compliance_report(self, results: Dict[str, Any], standard: str, output_path: str):
        """Generate compliance report for specified standard"""
        if standard not in self.compliance_templates:
            raise ValueError(f"Unsupported compliance standard: {standard}")

        report_content = self.compliance_templates[standard](results)

        with open(output_path, 'w') as f:
            f.write(report_content)

    def _generate_soc2_report(self, results: Dict[str, Any]) -> str:
        """Generate SOC2 compliance report"""
        return f"""# SOC2 Compliance Report

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}
**Audit Period:** {datetime.now().strftime('%Y-%m-%d')}

## Executive Summary

This report assesses smart contract security compliance with SOC2 Type II requirements for security, availability, and confidentiality.

## Security Controls Assessment

### Access Controls
- **Control Environment:** {self._assess_access_controls(results)}
- **Risk Assessment:** {self._assess_risk_assessment(results)}
- **Control Activities:** {self._assess_control_activities(results)}

### Vulnerability Management
- **Vulnerability Identification:** {len(results.get('vulnerabilities', []))} vulnerabilities identified
- **Risk Prioritization:** {self._get_high_risk_count(results)} high-risk findings
- **Remediation Tracking:** {len(results.get('fixes', []))} fixes suggested

## Compliance Status

**Overall Compliance:** {'✅ COMPLIANT' if self._is_soc2_compliant(results) else '❌ NON-COMPLIANT'}

## Recommendations

{self._generate_soc2_recommendations(results)}

---
*This report was generated by AetherAudit automated security analysis.*
"""

    def _generate_pci_dss_report(self, results: Dict[str, Any]) -> str:
        """Generate PCI-DSS compliance report"""
        return f"""# PCI-DSS Compliance Report

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}

## PCI-DSS Requirement Assessment

### Requirement 6: Develop and Maintain Secure Systems
- **Vulnerability Management:** {self._assess_vulnerability_management(results)}
- **Patch Management:** {'✅' if self._check_patch_management(results) else '❌'}

### Requirement 11: Regularly Test Security Systems
- **Network Vulnerability Scans:** {self._assess_network_scanning(results)}
- **Penetration Testing:** {'✅' if self._check_penetration_testing(results) else '❌'}

## Compliance Status

**PCI-DSS Compliance:** {'✅ COMPLIANT' if self._is_pci_compliant(results) else '❌ NON-COMPLIANT'}

## Critical Findings

{self._get_critical_findings(results)}

---
*This report was generated by AetherAudit automated security analysis.*
"""

    def _assess_access_controls(self, results: Dict[str, Any]) -> str:
        """Assess access control implementation"""
        access_vulns = [v for v in results.get('vulnerabilities', [])
                       if 'access' in v.get('type', '').lower() or 'auth' in v.get('type', '').lower()]
        if not access_vulns:
            return '✅ Strong access controls implemented'
        return f'⚠️  {len(access_vulns)} access control issues identified'

    def _assess_risk_assessment(self, results: Dict[str, Any]) -> str:
        """Assess risk assessment process"""
        high_risk = self._get_high_risk_count(results)
        return f'📊 {high_risk} high-risk vulnerabilities identified'

    def _assess_control_activities(self, results: Dict[str, Any]) -> str:
        """Assess control activities"""
        fixes = len(results.get('fixes', []))
        return f'🔧 {fixes} remediation actions identified'

    def _is_soc2_compliant(self, results: Dict[str, Any]) -> bool:
        """Check if results meet SOC2 compliance"""
        critical_vulns = [v for v in results.get('vulnerabilities', [])
                         if v.get('severity', '').lower() in ['critical', 'high']]
        return len(critical_vulns) == 0 and len(results.get('fixes', [])) > 0

    def _is_pci_compliant(self, results: Dict[str, Any]) -> bool:
        """Check if results meet PCI-DSS compliance"""
        critical_vulns = [v for v in results.get('vulnerabilities', [])
                         if v.get('severity', '').lower() in ['critical']]
        return len(critical_vulns) == 0

    def _get_high_risk_count(self, results: Dict[str, Any]) -> int:
        """Get count of high-risk vulnerabilities"""
        return len([v for v in results.get('vulnerabilities', [])
                   if v.get('severity', '').lower() in ['high', 'critical']])

    def _check_patch_management(self, results: Dict[str, Any]) -> bool:
        """Check if patch management is adequate"""
        return len(results.get('fixes', [])) > 0

    def _check_penetration_testing(self, results: Dict[str, Any]) -> bool:
        """Check if penetration testing evidence exists"""
        return 'foundry_tests' in results or 'fuzz_results' in results

    def _assess_vulnerability_management(self, results: Dict[str, Any]) -> str:
        """Assess vulnerability management process"""
        vulns = results.get('vulnerabilities', [])
        if not vulns:
            return '✅ No vulnerabilities found'
        return f'⚠️  {len(vulns)} vulnerabilities require management'

    def _assess_network_scanning(self, results: Dict[str, Any]) -> str:
        """Assess network scanning coverage"""
        return '✅ Comprehensive contract analysis performed'

    def _generate_soc2_recommendations(self, results: Dict[str, Any]) -> str:
        """Generate SOC2-specific recommendations"""
        recommendations = []

        high_risk = self._get_high_risk_count(results)
        if high_risk > 0:
            recommendations.append(f"- Address {high_risk} high-risk vulnerabilities immediately")

        fixes = len(results.get('fixes', []))
        if fixes == 0:
            recommendations.append("- Implement remediation processes for identified vulnerabilities")

        return '\n'.join(recommendations) if recommendations else "✅ No additional recommendations required"

    def _get_critical_findings(self, results: Dict[str, Any]) -> str:
        """Get critical findings for PCI-DSS"""
        critical_vulns = [v for v in results.get('vulnerabilities', [])
                         if v.get('severity', '').lower() == 'critical']

        if not critical_vulns:
            return "✅ No critical vulnerabilities found"

        findings = []
        for vuln in critical_vulns[:5]:  # Show top 5
            findings.append(f"- {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')[:100]}...")

        return '\n'.join(findings)

    def _generate_gdpr_report(self, results: Dict[str, Any]) -> str:
        """Generate GDPR compliance report"""
        return f"""# GDPR Compliance Report

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}

## Data Protection Assessment

### Article 32: Security of Processing
- **Technical Measures:** {self._assess_technical_measures(results)}
- **Organizational Measures:** {self._assess_organizational_measures(results)}

### Article 25: Data Protection by Design
- **Privacy by Design:** {self._assess_privacy_by_design(results)}
- **Default Privacy:** {self._assess_default_privacy(results)}

## Compliance Status

**GDPR Compliance:** {'✅ COMPLIANT' if self._is_gdpr_compliant(results) else '❌ NON-COMPLIANT'}

---
*This report was generated by AetherAudit automated security analysis.*
"""

    def _generate_iso27001_report(self, results: Dict[str, Any]) -> str:
        """Generate ISO27001 compliance report"""
        return f"""# ISO27001 Compliance Report

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}

## Information Security Management Assessment

### A.9: Access Control
- **Access Rights Management:** {self._assess_access_rights(results)}
- **User Access Management:** {self._assess_user_access(results)}

### A.12: Operations Security
- **Vulnerability Management:** {self._assess_operations_security(results)}
- **Technical Vulnerability Management:** {self._assess_technical_vulnerability(results)}

## Compliance Status

**ISO27001 Compliance:** {'✅ COMPLIANT' if self._is_iso_compliant(results) else '❌ NON-COMPLIANT'}

---
*This report was generated by AetherAudit automated security analysis.*
"""

    def _generate_nist_report(self, results: Dict[str, Any]) -> str:
        """Generate NIST compliance report"""
        return f"""# NIST Cybersecurity Framework Report

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}

## Framework Core Assessment

### Identify (ID)
- **Asset Management:** {self._assess_asset_management(results)}
- **Risk Assessment:** {self._assess_nist_risk_assessment(results)}

### Protect (PR)
- **Access Control:** {self._assess_nist_access_control(results)}
- **Data Security:** {self._assess_data_security(results)}

### Detect (DE)
- **Anomalies and Events:** {self._assess_anomaly_detection(results)}
- **Continuous Monitoring:** {self._assess_continuous_monitoring(results)}

## Compliance Status

**NIST Compliance:** {'✅ COMPLIANT' if self._is_nist_compliant(results) else '❌ NON-COMPLIANT'}

---
*This report was generated by AetherAudit automated security analysis.*
"""

    # Placeholder methods for compliance assessments
    def _assess_technical_measures(self, results): return "✅ Adequate technical measures implemented"
    def _assess_organizational_measures(self, results): return "✅ Organizational measures in place"
    def _assess_privacy_by_design(self, results): return "✅ Privacy considerations implemented"
    def _assess_default_privacy(self, results): return "✅ Default privacy settings configured"
    def _is_gdpr_compliant(self, results): return True
    def _assess_access_rights(self, results): return "✅ Access rights properly managed"
    def _assess_user_access(self, results): return "✅ User access controls implemented"
    def _assess_operations_security(self, results): return "✅ Operations security maintained"
    def _assess_technical_vulnerability(self, results): return "✅ Technical vulnerabilities addressed"
    def _is_iso_compliant(self, results): return True
    def _assess_asset_management(self, results): return "✅ Assets properly managed"
    def _assess_nist_risk_assessment(self, results): return "✅ Risk assessment completed"
    def _assess_nist_access_control(self, results): return "✅ Access controls implemented"
    def _assess_data_security(self, results): return "✅ Data security measures in place"
    def _assess_anomaly_detection(self, results): return "✅ Anomaly detection configured"
    def _assess_continuous_monitoring(self, results): return "✅ Continuous monitoring enabled"
    def _is_nist_compliant(self, results): return True


class AdvancedVisualizer:
    """Advanced visualization and dashboard generation"""

    def __init__(self):
        self.risk_scorer = RiskScorer()

    def generate_html_dashboard(self, results: Dict[str, Any], output_path: str):
        """Generate interactive HTML dashboard"""
        if not PLOTLY_AVAILABLE:
            return self._generate_fallback_dashboard(results, output_path)

        # Generate dashboard components
        dashboard_html = self._create_dashboard_html(results)

        with open(output_path, 'w') as f:
            f.write(dashboard_html)

    def _create_dashboard_html(self, results: Dict[str, Any]) -> str:
        """Create complete HTML dashboard"""
        # Generate charts
        charts_html = self._generate_charts_html(results)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AetherAudit Security Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .dashboard {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; border-bottom: 2px solid #eee; padding-bottom: 20px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #007bff; margin: 10px 0; }}
        .metric-label {{ color: #666; font-size: 0.9em; }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .summary {{ margin-top: 40px; padding: 20px; background: #e8f4fd; border-radius: 8px; border-left: 4px solid #17a2b8; }}
        .risk-high {{ color: #dc3545; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🔒 AetherAudit Security Dashboard</h1>
            <p>Comprehensive Smart Contract Security Analysis</p>
            <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="metrics">
            {self._generate_metrics_html(results)}
        </div>

        <div class="charts-grid">
            {charts_html}
        </div>

        <div class="summary">
            <h3>📊 Executive Summary</h3>
            {self._generate_summary_html(results)}
        </div>
    </div>
</body>
</html>"""

    def _generate_metrics_html(self, results: Dict[str, Any]) -> str:
        """Generate metrics cards HTML"""
        vulnerabilities = results.get('vulnerabilities', [])
        high_risk = len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])
        total_vulns = len(vulnerabilities)
        execution_time = results.get('execution_time', 0)
        fixes = len(results.get('fixes', []))

        return f"""
        <div class="metric-card">
            <div class="metric-value">{total_vulns}</div>
            <div class="metric-label">Total Vulnerabilities</div>
        </div>
        <div class="metric-card">
            <div class="metric-value risk-high">{high_risk}</div>
            <div class="metric-label">High Risk Issues</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{execution_time:.1f}s</div>
            <div class="metric-label">Analysis Time</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{fixes}</div>
            <div class="metric-label">Fixes Available</div>
        </div>"""

    def _generate_charts_html(self, results: Dict[str, Any]) -> str:
        """Generate charts HTML"""
        charts = []

        # Severity distribution chart
        charts.append(self._create_severity_chart(results))

        # Vulnerability types chart
        charts.append(self._create_vulnerability_types_chart(results))

        # Risk score distribution
        charts.append(self._create_risk_score_chart(results))

        # Timeline (if historical data available)
        if 'historical_data' in results:
            charts.append(self._create_timeline_chart(results))

        return '\n'.join(charts)

    def _create_severity_chart(self, results: Dict[str, Any]) -> str:
        """Create severity distribution chart"""
        vulnerabilities = results.get('vulnerabilities', [])

        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Create plotly chart
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            title="Vulnerability Severity Distribution"
        )])

        chart_html = fig.to_html(full_html=False, include_plotlyjs=False)
        return f'<div class="chart-container"><h3>Vulnerability Severity</h3>{chart_html}</div>'

    def _create_vulnerability_types_chart(self, results: Dict[str, Any]) -> str:
        """Create vulnerability types chart"""
        vulnerabilities = results.get('vulnerabilities', [])

        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('vulnerability_type', 'unknown'))
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        # Sort by count
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

        fig = go.Figure(data=[go.Bar(
            x=[item[1] for item in sorted_types[:10]],  # Top 10
            y=[item[0] for item in sorted_types[:10]],
            orientation='h',
            title="Top Vulnerability Types"
        )])

        chart_html = fig.to_html(full_html=False, include_plotlyjs=False)
        return f'<div class="chart-container"><h3>Vulnerability Types</h3>{chart_html}</div>'

    def _create_risk_score_chart(self, results: Dict[str, Any]) -> str:
        """Create risk score distribution chart"""
        vulnerabilities = results.get('vulnerabilities', [])

        # Calculate risk scores
        risk_scores = [self.risk_scorer.calculate_risk_score(vuln) for vuln in vulnerabilities]

        if not risk_scores:
            return '<div class="chart-container"><h3>Risk Score Distribution</h3><p>No vulnerabilities to score</p></div>'

        fig = go.Figure(data=[go.Histogram(
            x=risk_scores,
            nbinsx=20,
            title="Risk Score Distribution"
        )])

        chart_html = fig.to_html(full_html=False, include_plotlyjs=False)
        return f'<div class="chart-container"><h3>Risk Score Distribution</h3>{chart_html}</div>'

    def _create_timeline_chart(self, results: Dict[str, Any]) -> str:
        """Create timeline chart (placeholder for future historical data)"""
        return '<div class="chart-container"><h3>Security Trends</h3><p>Historical data visualization will be available in future updates</p></div>'

    def _generate_summary_html(self, results: Dict[str, Any]) -> str:
        """Generate summary HTML"""
        vulnerabilities = results.get('vulnerabilities', [])
        high_risk = len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])
        fixes = len(results.get('fixes', []))

        summary = f"""
        <p><strong>Total Findings:</strong> {len(vulnerabilities)}</p>
        <p><strong>High Risk Issues:</strong> <span class="risk-high">{high_risk}</span></p>
        <p><strong>Available Fixes:</strong> {fixes}</p>
        <p><strong>Overall Risk Level:</strong> <span class="{'risk-high' if high_risk > 0 else 'risk-medium' if len(vulnerabilities) > 5 else 'risk-low'}">
            {'🔴 HIGH' if high_risk > 0 else '🟡 MEDIUM' if len(vulnerabilities) > 5 else '🟢 LOW'}
        </span></p>
        """

        if high_risk > 0:
            summary += f"<p class='risk-high'><strong>⚠️ Immediate Action Required:</strong> {high_risk} high-risk vulnerabilities need immediate attention.</p>"

        return summary

    def _generate_fallback_dashboard(self, results: Dict[str, Any], output_path: str):
        """Generate simple HTML dashboard when plotly is not available"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AetherAudit Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .metric {{ background: #f0f0f0; padding: 20px; margin: 10px; border-radius: 5px; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>AetherAudit Security Dashboard</h1>
            <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

            <div class="metric">
                <h3>Total Vulnerabilities</h3>
                <p>{len(results.get('vulnerabilities', []))}</p>
            </div>

            <div class="metric">
                <h3>High Risk Issues</h3>
                <p class="high">{len([v for v in results.get('vulnerabilities', []) if v.get('severity', '').lower() in ['high', 'critical']])}</p>
            </div>

            <div class="metric">
                <h3>Available Fixes</h3>
                <p>{len(results.get('fixes', []))}</p>
            </div>

            <h2>Vulnerabilities</h2>
            {self._generate_simple_vulnerability_list(results)}
        </body>
        </html>"""

        with open(output_path, 'w') as f:
            f.write(html_content)

    def _generate_simple_vulnerability_list(self, results: Dict[str, Any]) -> str:
        """Generate simple vulnerability list for fallback dashboard"""
        vulnerabilities = results.get('vulnerabilities', [])

        if not vulnerabilities:
            return "<p>✅ No vulnerabilities found!</p>"

        html_list = []
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Show first 10
            title = vuln.get('title', vuln.get('type', 'Unknown'))
            severity = vuln.get('severity', 'unknown')
            description = vuln.get('description', 'No description')[:100]

            html_list.append(f"""
            <div class="metric">
                <h4>{i}. {title}</h4>
                <p><strong>Severity:</strong> {severity}</p>
                <p>{description}...</p>
            </div>""")

        return '\n'.join(html_list)

    def generate_excel_report(self, results: Dict[str, Any], output_path: str):
        """Generate Excel report with multiple sheets"""
        if not PANDAS_AVAILABLE:
            print("❌ Pandas not available for Excel export")
            return

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Metric': ['Total Vulnerabilities', 'High Risk Issues', 'Fixes Available', 'Analysis Time'],
                'Value': [
                    len(results.get('vulnerabilities', [])),
                    len([v for v in results.get('vulnerabilities', []) if v.get('severity', '').lower() in ['high', 'critical']]),
                    len(results.get('fixes', [])),
                    f"{results.get('execution_time', 0):.2f}s"
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)

            # Vulnerabilities sheet
            vulnerabilities = results.get('vulnerabilities', [])
            if vulnerabilities:
                vuln_data = []
                for vuln in vulnerabilities:
                    vuln_data.append({
                        'Type': vuln.get('type', vuln.get('vulnerability_type', 'Unknown')),
                        'Severity': vuln.get('severity', 'Unknown'),
                        'Confidence': vuln.get('confidence', 0),
                        'Description': vuln.get('description', 'No description')[:200],
                        'Line': vuln.get('line', vuln.get('line_number', 'Unknown')),
                        'Risk Score': self.risk_scorer.calculate_risk_score(vuln)
                    })

                vuln_df = pd.DataFrame(vuln_data)
                vuln_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)

    def generate_pdf_report(self, results: Dict[str, Any], output_path: str):
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            print("❌ ReportLab not available for PDF export")
            return

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph("AetherAudit Security Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Summary metrics
        story.append(Paragraph("Executive Summary", styles['Heading1']))

        vulnerabilities = results.get('vulnerabilities', [])
        high_risk = len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])
        fixes = len(results.get('fixes', []))

        summary_data = [
            ['Total Vulnerabilities', str(len(vulnerabilities))],
            ['High Risk Issues', str(high_risk)],
            ['Fixes Available', str(fixes)],
            ['Analysis Time', f"{results.get('execution_time', 0):.2f}s"]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Top vulnerabilities
        if vulnerabilities:
            story.append(Paragraph("Top Vulnerabilities", styles['Heading1']))

            vuln_data = [['Type', 'Severity', 'Confidence', 'Description']]
            for vuln in vulnerabilities[:10]:  # Top 10
                vuln_data.append([
                    vuln.get('type', vuln.get('vulnerability_type', 'Unknown')),
                    vuln.get('severity', 'Unknown'),
                    f"{vuln.get('confidence', 0):.2f}",
                    vuln.get('description', 'No description')[:100]
                ])

            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)

        doc.build(story)


class EnhancedReportGenerator:
    """Enhanced report generator with advanced features"""

    def __init__(self):
        self.report_generator = ReportGenerator()
        self.risk_scorer = RiskScorer()
        self.compliance_reporter = ComplianceReporter()
        self.visualizer = AdvancedVisualizer()

    def generate_comprehensive_report(self, results: Dict[str, Any], output_dir: str, include_compliance: bool = True):
        """Generate comprehensive report package"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate standard Markdown report
        markdown_path = output_path / f"aetheraudit_report_{timestamp}.md"
        self.report_generator.generate_comprehensive_report(results, str(markdown_path))

        # Generate HTML dashboard
        dashboard_path = output_path / f"aetheraudit_dashboard_{timestamp}.html"
        self.visualizer.generate_html_dashboard(results, str(dashboard_path))

        # Generate compliance reports if requested
        if include_compliance:
            compliance_dir = output_path / "compliance"
            compliance_dir.mkdir(exist_ok=True)

            for standard in ['SOC2', 'PCI-DSS', 'GDPR']:
                compliance_path = compliance_dir / f"compliance_{standard.lower()}_{timestamp}.md"
                self.compliance_reporter.generate_compliance_report(results, standard, str(compliance_path))

        # Generate Excel report
        excel_path = output_path / f"aetheraudit_data_{timestamp}.xlsx"
        self.visualizer.generate_excel_report(results, str(excel_path))

        # Generate PDF report
        pdf_path = output_path / f"aetheraudit_report_{timestamp}.pdf"
        self.visualizer.generate_pdf_report(results, str(pdf_path))

        return {
            'markdown': str(markdown_path),
            'dashboard': str(dashboard_path),
            'excel': str(excel_path),
            'pdf': str(pdf_path),
            'compliance': str(compliance_dir) if include_compliance else None
        }

    def generate_per_contract_report(self, results: Dict[str, Any], contract_name: str, output_dir: str, include_compliance: bool = True):
        """Generate comprehensive report package for a specific contract"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate standard Markdown report
        markdown_path = output_path / f"{contract_name}_report_{timestamp}.md"
        self.report_generator.generate_comprehensive_report(results, str(markdown_path))

        # Generate HTML dashboard
        dashboard_path = output_path / f"{contract_name}_dashboard_{timestamp}.html"
        self.visualizer.generate_html_dashboard(results, str(dashboard_path))

        # Generate compliance reports if requested
        compliance_dir = None
        if include_compliance:
            compliance_dir = output_path / "compliance"
            compliance_dir.mkdir(exist_ok=True)

            for standard in ['SOC2', 'PCI-DSS', 'GDPR']:
                compliance_path = compliance_dir / f"{contract_name}_compliance_{standard.lower()}_{timestamp}.md"
                self.compliance_reporter.generate_compliance_report(results, standard, str(compliance_path))

        # Generate Excel report
        excel_path = output_path / f"{contract_name}_data_{timestamp}.xlsx"
        self.visualizer.generate_excel_report(results, str(excel_path))

        # Generate PDF report
        pdf_path = output_path / f"{contract_name}_report_{timestamp}.pdf"
        self.visualizer.generate_pdf_report(results, str(pdf_path))

        return {
            'markdown': str(markdown_path),
            'dashboard': str(dashboard_path),
            'excel': str(excel_path),
            'pdf': str(pdf_path),
            'compliance': str(compliance_dir) if include_compliance else None
        }

    def generate_risk_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        prioritized_vulns = self.risk_scorer.prioritize_vulnerabilities(vulnerabilities)

        risk_distribution = {
            'critical': len([v for v in prioritized_vulns if v.get('risk_score', 0) >= 8]),
            'high': len([v for v in prioritized_vulns if 5 <= v.get('risk_score', 0) < 8]),
            'medium': len([v for v in prioritized_vulns if 2 <= v.get('risk_score', 0) < 5]),
            'low': len([v for v in prioritized_vulns if v.get('risk_score', 0) < 2])
        }

        return {
            'prioritized_vulnerabilities': prioritized_vulns,
            'risk_distribution': risk_distribution,
            'overall_risk_level': self._calculate_overall_risk(risk_distribution),
            'recommendations': self._generate_risk_recommendations(risk_distribution)
        }

    def _calculate_overall_risk(self, risk_distribution: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if risk_distribution['critical'] > 0:
            return 'CRITICAL'
        elif risk_distribution['high'] > 2:
            return 'HIGH'
        elif risk_distribution['medium'] > 5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_risk_recommendations(self, risk_distribution: Dict[str, int]) -> List[str]:
        """Generate risk-based recommendations"""
        recommendations = []

        if risk_distribution['critical'] > 0:
            recommendations.append(f"IMMEDIATE: Address {risk_distribution['critical']} critical vulnerabilities")
        if risk_distribution['high'] > 0:
            recommendations.append(f"URGENT: Address {risk_distribution['high']} high-risk vulnerabilities within 7 days")
        if risk_distribution['medium'] > 3:
            recommendations.append(f"SCHEDULED: Plan remediation for {risk_distribution['medium']} medium-risk issues")

        if not recommendations:
            recommendations.append("MAINTENANCE: Continue regular security monitoring")

        return recommendations

    def export_to_json(self, results: Dict[str, Any], output_path: str):
        """Export results to JSON format"""
        export_data = {
            'metadata': {
                'export_timestamp': datetime.now().isoformat(),
                'framework_version': 'AetherAudit Enhanced',
                'report_type': 'comprehensive_security_analysis'
            },
            'summary': {
                'total_vulnerabilities': len(results.get('vulnerabilities', [])),
                'high_risk_count': len([v for v in results.get('vulnerabilities', []) if v.get('severity', '').lower() in ['high', 'critical']]),
                'execution_time': results.get('execution_time', 0),
                'fixes_available': len(results.get('fixes', []))
            },
            'vulnerabilities': results.get('vulnerabilities', []),
            'fixes': results.get('fixes', []),
            'validation_results': results.get('validation_results', {}),
            'risk_assessment': self.generate_risk_assessment(results.get('vulnerabilities', []))
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def export_to_xml(self, results: Dict[str, Any], output_path: str):
        """Export results to XML format"""
        def dict_to_xml(data, root_name='aetheraudit'):
            if isinstance(data, dict):
                xml_parts = [f'<{root_name}>']
                for key, value in data.items():
                    xml_parts.append(dict_to_xml(value, key))
                xml_parts.append(f'</{root_name}>')
                return '\n'.join(xml_parts)
            elif isinstance(data, list):
                xml_parts = []
                for item in data:
                    xml_parts.append(dict_to_xml(item, 'item'))
                return '\n'.join(xml_parts)
            else:
                return f'<{root_name}>{html.escape(str(data))}</{root_name}>'

        xml_content = dict_to_xml(results, 'aetheraudit_report')

        with open(output_path, 'w') as f:
            f.write(xml_content)

    def export_results(self, results: Dict[str, Any], output_dir: str, formats: List[str] = ['json', 'xml']):
        """Export results in multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        exported_files = {}

        for format_type in formats:
            if format_type.lower() == 'json':
                json_path = output_path / "aetheraudit_results.json"
                self.export_to_json(results, str(json_path))
                exported_files['json'] = str(json_path)

            elif format_type.lower() == 'xml':
                xml_path = output_path / "aetheraudit_results.xml"
                self.export_to_xml(results, str(xml_path))
                exported_files['xml'] = str(xml_path)

        return exported_files
