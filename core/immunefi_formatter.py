#!/usr/bin/env python3
"""
Immunefi Bug Bounty Report Formatter

Generates submission-ready reports for Immunefi platform.
Formats vulnerability findings according to Immunefi standards.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime


@dataclass
class ImmunefiBugReport:
    """Structured bug report for Immunefi."""
    title: str
    severity: str  # Critical, High, Medium, Low
    affected_asset: str  # Contract address
    chain: str  # Base, Ethereum, etc.
    vulnerability_type: str
    description: str
    impact: str
    poc_code: Optional[str] = None
    reproduction_steps: Optional[List[str]] = None
    recommended_fix: Optional[str] = None
    references: Optional[List[str]] = None
    submission_date: Optional[str] = None


class ImmunefFormatter:
    """Format vulnerability findings for Immunefi submission."""
    
    # Immunefi impact categories (from their documentation)
    IMPACT_MAPPING = {
        'reentrancy': 'Direct theft of any user funds',
        'access_control': 'Theft of unclaimed yield',
        'arithmetic_underflow': 'Temporary freezing of funds',
        'arithmetic_overflow': 'Temporary freezing of funds',
        'oracle_manipulation': 'Oracle manipulation leading to incorrect pricing',
        'flash_loan': 'Direct theft of any user funds via flash loan attack',
        'integer_overflow': 'Temporary freezing of funds',
        'integer_underflow': 'Temporary freezing of funds',
        'unchecked_call': 'Permanent freezing of funds',
        'delegatecall': 'Direct theft of any user funds',
        'selfdestruct': 'Permanent freezing of unclaimed yield',
        'gas_griefing': 'Smart contract unable to operate due to lack of token funds',
        'dos': 'Smart contract unable to operate due to lack of token funds',
    }
    
    def generate_report(self, vulnerability: Dict, deployment_info: Optional[Dict] = None) -> ImmunefiBugReport:
        """
        Generate Immunefi-formatted report from vulnerability.
        
        Args:
            vulnerability: Vulnerability dict with standard fields
            deployment_info: Optional dict with 'contract_address', 'chain', etc.
        
        Returns:
            ImmunefiBugReport object ready for submission
        """
        deployment_info = deployment_info or {}
        
        return ImmunefiBugReport(
            title=self._generate_title(vulnerability),
            severity=self._map_severity(vulnerability),
            affected_asset=deployment_info.get('contract_address', 'TBD'),
            chain=deployment_info.get('chain', 'Ethereum'),
            vulnerability_type=vulnerability.get('vulnerability_type', 'Unknown'),
            description=self._format_description(vulnerability),
            impact=self._determine_impact(vulnerability),
            poc_code=vulnerability.get('poc_code', None),
            reproduction_steps=self._extract_reproduction_steps(vulnerability),
            recommended_fix=vulnerability.get('recommendation', None),
            references=self._gather_references(vulnerability),
            submission_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def _generate_title(self, vuln: Dict) -> str:
        """Generate human-readable title."""
        vuln_type = vuln.get('vulnerability_type', 'Vulnerability').replace('_', ' ').title()
        location = vuln.get('contract_name', 'Contract')
        
        # Try to extract impact from description
        description = vuln.get('description', '')
        impact_keywords = {
            'drain': 'Allows Fund Drainage',
            'steal': 'Enables Fund Theft',
            'freeze': 'Causes Fund Freezing',
            'dos': 'Causes Denial of Service',
            'manipulat': 'Enables Price Manipulation',
        }
        
        impact_phrase = None
        for keyword, phrase in impact_keywords.items():
            if keyword in description.lower():
                impact_phrase = phrase
                break
        
        if impact_phrase:
            return f"{vuln_type} in {location} {impact_phrase}"
        else:
            return f"{vuln_type} in {location}"
    
    def _map_severity(self, vuln: Dict) -> str:
        """Map internal severity to Immunefi levels."""
        severity = vuln.get('severity', 'medium').lower()
        
        mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'informational': 'Low',
            'info': 'Low'
        }
        
        return mapping.get(severity, 'Medium')
    
    def _format_description(self, vuln: Dict) -> str:
        """Format vulnerability description for Immunefi."""
        description = vuln.get('description', '')
        
        # Add technical details
        details = []
        
        if vuln.get('line_number'):
            details.append(f"**Location:** Line {vuln['line_number']}")
        
        if vuln.get('code_snippet'):
            details.append(f"**Vulnerable Code:**\n```solidity\n{vuln['code_snippet']}\n```")
        
        if vuln.get('validation_reasoning'):
            details.append(f"**Analysis:** {vuln['validation_reasoning']}")
        
        # Combine description with details
        formatted = description
        if details:
            formatted += "\n\n" + "\n\n".join(details)
        
        return formatted
    
    def _determine_impact(self, vuln: Dict) -> str:
        """Determine Immunefi impact category."""
        vuln_type = vuln.get('vulnerability_type', '').lower()
        
        # Use predefined mapping
        for key, impact in self.IMPACT_MAPPING.items():
            if key in vuln_type:
                return impact
        
        # Fallback based on severity
        severity = vuln.get('severity', 'medium').lower()
        if severity in ['critical', 'high']:
            return 'Temporary freezing of funds'
        elif severity == 'medium':
            return 'Smart contract unable to operate due to lack of token funds'
        else:
            return 'Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)'
    
    def _extract_reproduction_steps(self, vuln: Dict) -> List[str]:
        """Extract reproduction steps from vulnerability."""
        steps = []
        
        # Try to extract from POC code or description
        if vuln.get('poc_code'):
            steps.append("Deploy the vulnerable contract to a testnet")
            steps.append("Deploy the exploit contract")
            steps.append("Execute the exploit function")
            steps.append("Observe the vulnerability being exploited")
        elif vuln.get('code_snippet'):
            steps.append(f"Locate the vulnerable code at line {vuln.get('line_number', 'N/A')}")
            steps.append("Review the code snippet showing the vulnerability")
            steps.append("Verify the absence of proper protections")
        
        # Add custom steps from vulnerability data
        if vuln.get('reproduction_steps'):
            steps.extend(vuln['reproduction_steps'])
        
        return steps if steps else None
    
    def _gather_references(self, vuln: Dict) -> List[str]:
        """Gather relevant references."""
        references = []
        
        # Add SWC reference if available
        if vuln.get('swc_id'):
            references.append(f"SWC Registry: https://swcregistry.io/docs/{vuln['swc_id']}")
        
        # Add category references
        category = vuln.get('category', '')
        if category:
            references.append(f"Vulnerability Category: {category}")
        
        # Add custom references
        if vuln.get('references'):
            references.extend(vuln['references'])
        
        return references if references else None
    
    def to_markdown(self, report: ImmunefiBugReport) -> str:
        """
        Convert report to Immunefi markdown format.
        
        Args:
            report: ImmunefiBugReport object
            
        Returns:
            Markdown-formatted string ready for Immunefi submission
        """
        
        md = f"""# {report.title}

**Severity**: {report.severity}

**Vulnerability Type**: `{report.vulnerability_type}`

**Affected Deployment**: 
- Chain: {report.chain}
- Contract Address: `{report.affected_asset}`

**Contract Verification**: Verified on Block Explorer

---

## Summary

{report.description}

---

## Vulnerability Details

### Affected Contract

**Deployed Address**: `{report.affected_asset}` ({report.chain})  
**Vulnerability Type**: {report.vulnerability_type}

### Root Cause

{report.description}

---

## Impact Analysis

**Impact Classification**: {report.impact}

The vulnerability allows an attacker to exploit the following:

{self._format_impact_details(report)}

---

## Proof of Concept

"""
        
        if report.poc_code:
            md += f"### Exploit Code\n\n```solidity\n{report.poc_code}\n```\n\n"
        
        if report.reproduction_steps:
            md += "### Reproduction Steps\n\n"
            for i, step in enumerate(report.reproduction_steps, 1):
                md += f"{i}. {step}\n"
            md += "\n"
        
        if report.recommended_fix:
            md += f"""---

## Recommended Fix

{report.recommended_fix}

"""
        
        if report.references:
            md += "---\n\n## References\n\n"
            for ref in report.references:
                md += f"- {ref}\n"
        
        md += f"""
---

**Submission Date**: {report.submission_date or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**Discovered By**: Aether Bug Bounty System
"""
        
        return md
    
    def _format_impact_details(self, report: ImmunefiBugReport) -> str:
        """Format detailed impact analysis."""
        severity = report.severity.lower()
        
        if severity == 'critical':
            return """
- **Direct Loss of Funds**: Users can lose funds immediately
- **Protocol Insolvency**: Total value locked could be drained
- **Cascading Failures**: Could impact dependent protocols
"""
        elif severity == 'high':
            return """
- **Significant Loss Risk**: Substantial funds at risk under certain conditions
- **Protocol Disruption**: Core functionality affected
- **User Impact**: Multiple users affected
"""
        elif severity == 'medium':
            return """
- **Limited Loss**: Funds at risk under specific conditions
- **Operational Impact**: Some functionality affected
- **Recovery Possible**: Mitigations available
"""
        else:
            return """
- **Minor Impact**: Limited or no direct financial loss
- **Informational**: Helps improve security posture
"""
    
    def to_json(self, report: ImmunefiBugReport) -> Dict:
        """Convert report to JSON format."""
        return {
            'title': report.title,
            'severity': report.severity,
            'affected_asset': report.affected_asset,
            'chain': report.chain,
            'vulnerability_type': report.vulnerability_type,
            'description': report.description,
            'impact': report.impact,
            'poc_code': report.poc_code,
            'reproduction_steps': report.reproduction_steps,
            'recommended_fix': report.recommended_fix,
            'references': report.references,
            'submission_date': report.submission_date
        }
    
    def save_report(self, report: ImmunefiBugReport, output_path: Path):
        """
        Save report to file.
        
        Args:
            report: ImmunefiBugReport object
            output_path: Path to save the report (supports .md, .json)
        """
        output_path = Path(output_path)
        
        if output_path.suffix == '.json':
            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.to_json(report), f, indent=2)
        else:
            # Default to markdown
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.to_markdown(report))
    
    def batch_generate_reports(
        self, 
        vulnerabilities: List[Dict], 
        deployment_info: Optional[Dict] = None
    ) -> List[ImmunefiBugReport]:
        """
        Generate reports for multiple vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dicts
            deployment_info: Optional deployment info (applied to all)
        
        Returns:
            List of ImmunefiBugReport objects
        """
        reports = []
        
        for vuln in vulnerabilities:
            # Skip low-confidence findings
            if vuln.get('validation_confidence', 1.0) < 0.6:
                continue
            
            # Skip informational findings
            if vuln.get('severity', 'medium').lower() in ['informational', 'info']:
                continue
            
            report = self.generate_report(vuln, deployment_info)
            reports.append(report)
        
        return reports
    
    def save_batch_reports(
        self, 
        vulnerabilities: List[Dict], 
        output_dir: Path,
        deployment_info: Optional[Dict] = None
    ):
        """
        Save multiple reports to directory.
        
        Args:
            vulnerabilities: List of vulnerability dicts
            output_dir: Directory to save reports
            deployment_info: Optional deployment info
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        reports = self.batch_generate_reports(vulnerabilities, deployment_info)
        
        for i, report in enumerate(reports, 1):
            # Create filename from vulnerability type
            vuln_type = report.vulnerability_type.lower().replace(' ', '_')
            filename = f"{i:02d}_{vuln_type}_{report.severity.lower()}.md"
            
            self.save_report(report, output_dir / filename)
        
        # Also save summary JSON
        summary = {
            'total_reports': len(reports),
            'severity_breakdown': self._get_severity_breakdown(reports),
            'reports': [self.to_json(r) for r in reports],
            'generated_at': datetime.now().isoformat()
        }
        
        import json
        with open(output_dir / 'submission_summary.json', 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
    
    def _get_severity_breakdown(self, reports: List[ImmunefiBugReport]) -> Dict[str, int]:
        """Get severity breakdown."""
        breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for report in reports:
            if report.severity in breakdown:
                breakdown[report.severity] += 1
        
        return breakdown

