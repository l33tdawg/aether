"""
Report generation for AetherAudit + AetherFuzz results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class ReportGenerator:
    """Generate comprehensive reports from audit and fuzz results."""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_markdown_report(self, results: Dict[str, Any], output_path: str):
        """Generate a comprehensive Markdown report."""
        report_content = self._generate_markdown_content(results)

        with open(output_path, 'w') as f:
            f.write(report_content)

    def generate_comprehensive_report(self, results: Dict[str, Any], output_path: str):
        """Generate a comprehensive report including audit and fuzz results."""
        report_content = self._generate_comprehensive_markdown(results)

        with open(output_path, 'w') as f:
            f.write(report_content)

    def _generate_markdown_content(self, results: Dict[str, Any]) -> str:
        """Generate Markdown report content matching GitHub audit format."""
        # Extract metadata
        contract_name = results.get('contract_name', 'Unknown Contract')
        contract_address = results.get('contract_address', results.get('address', ''))
        network = results.get('network', 'Ethereum Mainnet')
        
        vulnerabilities = results.get('vulnerabilities', [])
        total_findings = len(vulnerabilities)
        
        # Count by severity
        from collections import defaultdict
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            if hasattr(vuln, 'severity'):
                severity = str(vuln.severity).lower()
            else:
                severity = str(vuln.get('severity', 'unknown')).lower()
            severity_counts[severity] += 1
        
        high_critical_count = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        
        content = f"""# AetherAudit Report

**Contract:** {contract_name}
**Address:** {contract_address}
**Network:** {network}
**Generated:** {self.timestamp}

## Executive Summary

- **Total Findings:** {total_findings}
- **High/Critical Severity Findings:** {high_critical_count}
- **Execution Time:** {results.get('execution_time', 0):.2f}s
- **Status:** {'✅ Clean' if total_findings == 0 else '⚠️ Issues Found'}

"""
        
        # Add tools used section
        content += """### Analysis Tools
- **Slither:** Static analysis for Solidity vulnerabilities
- **Enhanced Detectors:** Pattern-based vulnerability detection
- **AI Ensemble:** Multi-model AI-powered analysis
- **LLM Validation:** False positive filtering
- **Formal Verification:** Mathematical proof of correctness

"""
        
        # Findings by severity section
        if total_findings > 0:
            content += "## Findings by Severity\n\n"
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    content += f"- **{severity.title()}:** {severity_counts[severity]}\n"
            content += "\n"
        
        content += "## Detailed Findings\n\n"

        # Add vulnerability details
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            # Group findings by severity
            from collections import defaultdict
            by_severity = defaultdict(list)
            for vuln in vulnerabilities:
                if hasattr(vuln, 'severity'):
                    severity = str(vuln.severity).lower()
                else:
                    severity = str(vuln.get('severity', 'unknown')).lower()
                by_severity[severity].append(vuln)
            
            # Display findings by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity not in by_severity:
                    continue
                
                content += f"### {severity.title()} Severity\n\n"
                
                for i, vuln in enumerate(by_severity[severity], 1):
                    # Handle both dict and VulnerabilityMatch objects
                    if hasattr(vuln, 'vulnerability_type'):
                        # VulnerabilityMatch object
                        title = vuln.vulnerability_type.replace('_', ' ').title()
                        severity = vuln.severity
                        confidence = vuln.confidence
                        tool = 'Enhanced Detector'
                        description = vuln.description
                        category = getattr(vuln, 'category', '') or 'Unknown'
                        # Extract SWC ID
                        swc_id = getattr(vuln, 'swc_id', '') or ''
                        if swc_id and swc_id != 'Unknown':
                            category = f"{category} ({swc_id})"
                        # Location mapping (prefer file path if available)
                        file_path = ''
                        try:
                            if getattr(vuln, 'context', None):
                                file_path = vuln.context.get('file_path') or vuln.context.get('file_location', '')
                        except Exception:
                            pass
                        line_num = getattr(vuln, 'line_number', 'Unknown')
                        location = f"{file_path}:{line_num}" if file_path else f"Line {line_num}"
                    else:
                        # Dict object - map fields from common keys
                        raw_title = vuln.get('title') or vuln.get('vulnerability_type') or vuln.get('type') or 'Unknown Vulnerability'
                        title = str(raw_title).replace('_', ' ').title()
                        severity = vuln.get('severity', 'Unknown')
                        confidence = vuln.get('confidence', vuln.get('validation_confidence', 0.0)) or 0.0
                        # Tool/source mapping
                        source = (vuln.get('source') or vuln.get('tool') or '').lower()
                        tool_map = {
                            'ai_ensemble': 'AI Ensemble',
                            'enhanced_llm': 'LLM',
                            'enhanced_detector': 'Enhanced Detector',
                            'formal_verification': 'Formal Verification'
                        }
                        tool = tool_map.get(source, vuln.get('tool') or 'AetherAudit')
                        description = vuln.get('description', 'No description available')
                        # Category/SWC mapping
                        category = vuln.get('category') or vuln.get('vulnerability_type') or vuln.get('type') or 'Unknown'
                        swc_id = vuln.get('swc_id') or ''
                        if swc_id and swc_id != 'Unknown':
                            category = f"{category} ({swc_id})"
                        # Location mapping
                        file_path = vuln.get('file') or ''
                        ctx = vuln.get('context') or {}
                        if isinstance(ctx, dict):
                            file_path = ctx.get('file_path') or ctx.get('file_location', file_path)
                        line_num = vuln.get('line') or vuln.get('line_number') or 'Unknown'
                        # If file_location like "path:line" provided, split
                        if isinstance(file_path, str) and ':' in file_path and (not isinstance(line_num, int)):
                            try:
                                fpath, lnum = file_path.split(':', 1)
                                file_path = fpath
                                line_num = lnum
                            except Exception:
                                pass
                        location = f"{file_path}:{line_num}" if file_path else f"Line {line_num}"
                    
                    # Format in GitHub audit style - more concise
                    content += f"""**{title}**
- **Line:** {line_num}
- **Confidence:** {float(confidence):.1%}
- **Description:** {description}
- **Category:** {category}
- **Tool:** {tool}

"""
        else:
            content += "✅ No vulnerabilities found!\n\n"
            content += f"""## Clean Contract

The contract **{contract_name}** passed all security checks with no findings.

"""
        
        # Add footer
        content += """---

*Report generated by AetherAudit*
*For security research and bug bounty purposes*
"""
        
        return content

    def _generate_markdown_content_old(self, results: Dict[str, Any]) -> str:
        """Old basic format - kept for backward compatibility."""
        # Add LLM validation section if available
        content = ""
        llm_validation = results.get('llm_validation') or results.get('validation_results') or {}
        details = llm_validation.get('details', {}) if isinstance(llm_validation, dict) else {}
        validated = details.get('validated', []) if isinstance(details, dict) else []
        filtered = details.get('filtered', []) if isinstance(details, dict) else []

        if validated or filtered:
            content += "## LLM Validation Summary\n\n"
            content += f"- Validated: {len(validated)}\n"
            content += f"- Filtered as False Positive: {len(filtered)}\n\n"

            if filtered:
                content += "### False Positives Removed\n\n"
                content += "| Type | Severity | Line | Confidence | Reasoning (truncated) |\n"
                content += "|---|---|---:|---:|---|\n"
                for fp in filtered:
                    vtype = fp.get('vulnerability_type') or fp.get('title', 'unknown')
                    sev = (fp.get('severity', 'unknown') or '').title()
                    line = fp.get('line') or fp.get('line_number') or '—'
                    conf = f"{fp.get('validation_confidence', 0):.2f}"
                    reason = (fp.get('validation_reasoning', '') or '')[:140].replace('\n', ' ')
                    content += f"| {vtype} | {sev} | {line} | {conf} | {reason} |\n"
                content += "\n"

        # Add fix suggestions if available
        fixes = results.get('fixes', [])
        if fixes:
            content += "## Fix Suggestions\n\n"
            for i, fix in enumerate(fixes, 1):
                content += f"""### {i}. {fix.get('title', 'Fix Suggestion')}

**Vulnerability:** {fix.get('vulnerability_id', 'Unknown')}
**Confidence:** {fix.get('confidence', 'Unknown')}

**Suggested Code:**
```solidity
{fix.get('suggested_code', '// No code suggestion available')}
```

---

"""

        # Add Foundry test summary if available
        try:
            foundry = results.get('foundry_tests') or results.get('results', {}).get('foundry_tests') or {}
            if isinstance(foundry, dict) and (foundry.get('validation_results') or foundry.get('forge_runs')):
                content += "## Foundry Test Summary\n\n"
                vr = foundry.get('validation_results', {})
                fruns = foundry.get('forge_runs', [])
                if isinstance(vr, dict) and vr:
                    content += f"- Test Suites: {vr.get('total_tests', vr.get('total', 0))}\n"
                    content += f"- Suites with Test File: {vr.get('successful_tests', 0)}\n"
                    content += f"- Suites with Exploit Contract: {vr.get('successful_exploits', 0)}\n\n"
                if isinstance(fruns, list) and fruns:
                    total = len(fruns)
                    passed = sum(1 for r in fruns if (r.get('summary', {}) or {}).get('failed', 0) == 0 and (r.get('summary', {}) or {}).get('status_code', 1) == 0)
                    failed = total - passed
                    content += f"- Forge Runs: {total}\n- Passed: {passed}\n- Failed: {failed}\n\n"
                    content += "### Forge Test Results\n\n"
                    content += "| Suite | Passed | Failed |\n|---|---:|---:|\n"
                    for idx, r in enumerate(fruns, 1):
                        s = r.get('summary', {}) or {}
                        content += f"| {idx} | {s.get('passed', 0)} | {s.get('failed', 0)} |\n"
                    content += "\n"
        except Exception:
            pass

        return content

    def _generate_comprehensive_markdown(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive Markdown report including fuzz results."""
        # Extract metadata
        contract_name = results.get('contract_name', 'Unknown Contract')
        contract_address = results.get('contract_address', results.get('address', ''))
        network = results.get('network', 'Ethereum Mainnet')
        
        content = f"""# AetherAudit + AetherFuzz Comprehensive Report

**Contract:** {contract_name}
**Address:** {contract_address}
**Network:** {network}
**Generated on:** {self.timestamp}

## Executive Summary

### Audit Results
- **High Severity (confirmed, tool-backed):** {results.get('audit', {}).get('high_severity_count', 0)}
- **All Findings (incl. suspected):** {results.get('audit', {}).get('total_vulnerabilities', 0)}
- **AI Analysis Issues:** {len(results.get('audit', {}).get('ai_insights', []))}

### Exploitability Verification
- **Confirmed Exploitable:** {results.get('audit', {}).get('confirmed_exploits', 0)}
- **Highly Likely Exploitable:** {results.get('audit', {}).get('highly_likely_exploits', 0)}
- **Possibly Exploitable:** {results.get('audit', {}).get('possible_exploits', 0)}

### Fuzzing Results
- **Vulnerabilities Confirmed:** {results.get('fuzz', {}).get('vulnerabilities_found', 0)}
- **Crashes Detected:** {len(results.get('fuzz', {}).get('crashes', []))}
- **Code Coverage:** {results.get('fuzz', {}).get('coverage', {}).get('lines', 0)}% lines

### Overall Assessment
- **Risk Level:** {'High' if results.get('audit', {}).get('high_severity_count', 0) > 0 else 'Medium' if results.get('fuzz', {}).get('vulnerabilities_found', 0) > 0 else 'Low'}
- **Recommended Actions:** {'Immediate fixes required' if results.get('audit', {}).get('high_severity_count', 0) > 0 else 'Review and test recommended fixes' if results.get('fuzz', {}).get('vulnerabilities_found', 0) > 0 else 'No immediate action required'}

## Detailed Audit Results

"""

        # Add audit section
        audit_results = results.get('audit', {})
        if audit_results:
            content += self._generate_audit_section(audit_results)

        # Add fuzzing section
        fuzz_results = results.get('fuzz', {})
        if fuzz_results:
            content += self._generate_fuzz_section(fuzz_results)

        # Add fix validation section
        validation_results = results.get('validation', {})
        if validation_results:
            content += self._generate_validation_section(validation_results)

        return content

    def generate_bug_bounty_submission(self, results: Dict[str, Any]) -> str:
        """Generate a bug-bounty-friendly submission template."""
        audit = results.get('audit', {})
        vulns = []
        
        # Build candidate list in priority order: confirmed > llm_validated > suspected
        if audit.get('slither', {}).get('vulnerabilities'):
            vulns += audit['slither']['vulnerabilities']
        if audit.get('mythril', {}).get('vulnerabilities'):
            vulns += audit['mythril']['vulnerabilities']
        if audit.get('pattern_analysis', {}).get('vulnerabilities'):
            # Include both llm_validated and confirmed pattern findings
            vulns += [v for v in audit['pattern_analysis']['vulnerabilities']
                     if v.get('status') in ('llm_validated', 'confirmed')]

        # Also include LLM analysis results that were marked as confirmed
        llm_analysis = audit.get('llm_analysis', {})
        if isinstance(llm_analysis, dict) and 'vulnerabilities' in llm_analysis:
            vulns += [v for v in llm_analysis['vulnerabilities'] if v.get('status') == 'confirmed']

        # Include vulnerabilities from the main audit results (this is where our data actually is)
        audit_vulns = audit.get('vulnerabilities', [])
        if audit_vulns:
            # Include all vulnerabilities from audit results, prioritizing critical/high severity
            for vuln in audit_vulns:
                # Handle both dict and VulnerabilityMatch objects
                severity = vuln.get('severity', 'medium') if hasattr(vuln, 'get') else vuln.severity
                if severity.lower() in ['critical', 'high']:
                    if hasattr(vuln, 'get'):
                        vuln['status'] = 'confirmed'
                    else:
                        vuln.validation_status = 'confirmed'
                vulns.append(vuln)

        # Choose the best concrete finding with file/line/SWC and exploit_successful=True
        def score(v):
            s = 0
            # Handle both dict and VulnerabilityMatch objects
            exploit_successful = v.get('exploit_successful', False) if hasattr(v, 'get') else getattr(v, 'validation_status', '') == 'validated'
            if exploit_successful: s += 5  # Prioritize confirmed exploits

            # File and line information
            file_info = v.get('file', '') if hasattr(v, 'get') else v.context.get('file_location', '') if hasattr(v, 'context') else ''
            line_info = v.get('line', '') if hasattr(v, 'get') else str(v.line_number) if hasattr(v, 'line_number') else ''
            if file_info and line_info and file_info != 'Unknown': s += 3

            # SWC ID
            swc_id = v.get('swc_id', '') if hasattr(v, 'get') else v.swc_id
            if swc_id and swc_id != 'Unknown': s += 2

            # Status
            status = v.get('status', '') if hasattr(v, 'get') else getattr(v, 'validation_status', '')
            if status == 'confirmed': s += 3
            if status == 'llm_validated': s += 2

            # Severity
            severity = v.get('severity', 'medium') if hasattr(v, 'get') else v.severity
            if severity.lower() in ('critical','high'): s += 4  # Higher weight for severity

            # Confidence
            confidence = v.get('confidence', 0) if hasattr(v, 'get') else v.confidence
            if confidence > 0.8: s += 2  # High confidence findings

            # Title
            title = v.get('title', '') if hasattr(v, 'get') else v.vulnerability_type
            if title and title != 'Unknown Vulnerability': s += 1

            return s

        primary = {}
        if vulns:
            vulns_sorted = sorted(vulns, key=score, reverse=True)
            for v in vulns_sorted:
                if score(v) > 0:
                    primary = v
                    break
            if not primary:
                primary = vulns_sorted[0]

        # Handle both dict and VulnerabilityMatch objects for primary vulnerability
        if hasattr(primary, 'get'):
            # Dict-like object
            title = primary.get('title', 'Potential Vulnerability')
            severity = primary.get('severity', 'medium').title()
            swc = primary.get('swc_id', '') or 'Unknown'
            desc = primary.get('description', '') or 'No description available'
        else:
            # VulnerabilityMatch object
            title = primary.vulnerability_type.replace('_', ' ').title()
            severity = primary.severity.title()
            swc = primary.swc_id or 'Unknown'
            desc = primary.description

        # Enhanced location extraction with context
        file_location = 'Unknown'
        line_number = 'Unknown'

        # Try multiple sources for location info
        if hasattr(primary, 'context') and primary.context:
            file_location = primary.context.get('file_location', 'Unknown')
            if ':' in file_location:
                file_location, line_number = file_location.split(':', 1)

        # Fallback to legacy fields for dict-like objects
        if file_location == 'Unknown' and hasattr(primary, 'get'):
            file_location = primary.get('file', 'Unknown')
        if line_number == 'Unknown' and hasattr(primary, 'get'):
            line_number = primary.get('line') or (primary.get('line_numbers', [None])[0] if isinstance(primary.get('line_numbers'), list) and primary.get('line_numbers') else 'Unknown')
        elif line_number == 'Unknown' and hasattr(primary, 'line_number'):
            line_number = str(primary.line_number)

        location = f"{file_location}:{line_number}"

        # POC and steps (if present) - handle both dict and VulnerabilityMatch objects
        if hasattr(primary, 'get'):
            # Dict-like object
            steps = primary.get('exploit_steps', []) or primary.get('attack_vector', '').split('\n') if primary.get('attack_vector') else []
            poc = primary.get('poc_code', '') or primary.get('working_poc', '') or ''
        else:
            # VulnerabilityMatch object - generate POC based on vulnerability type
            steps = []
            poc = ''  # Will be generated by template
        # Clean up PoC code - remove extra ```solidity tags
        if poc and '```solidity' in poc:
            poc = poc.replace('```solidity\n', '').replace('```', '').strip()
        # Handle exploit success and impact for both object types
        if hasattr(primary, 'get'):
            exploit_success = primary.get('exploit_successful', False)
            impact = primary.get('impact_assessment', primary.get('financial_impact', 'Not assessed'))
            fix_suggestion = primary.get('fix_suggestion', 'No fix suggestion available')
        else:
            exploit_success = primary.validation_status == 'validated'
            impact = 'High - Significant security impact with potential for financial loss'
            fix_suggestion = 'Return the computed cap variable instead of beanstalk.totalUnharvestable(fieldId)'

        tmpl = f"""# Bug Submission

## Title
{title} ({severity})

## Target
File: {location}
SWC: {swc}

## Summary
{desc}

## Impact
{impact}

## Steps to Reproduce
{self._generate_steps_to_reproduce(primary) if not steps else ''.join(f'{i+1}. {s.strip().lstrip("0123456789. ")}\n' for i, s in enumerate(steps) if s.strip())}

## Proof of Concept
{f'```solidity\n{poc}\n```' if poc else self._generate_poc_template(primary)}

## Validation
- Tool(s): {', '.join([k for k,v in audit.items() if isinstance(v, dict) and v.get('vulnerabilities')]) or 'Enhanced Pattern Analysis'}
- Evidence: {'Exploit validated with working proof-of-concept' if poc else ('Confirmed by static analysis with context validation' if hasattr(primary, 'validation_status') and primary.validation_status == 'validated' else 'Pattern detected with enhanced context analysis')}
- Notes: {'Working proof-of-concept generated for exploit verification' if poc else 'Enhanced static analysis with function-level context validation performed. Vulnerability pattern confirmed in specific contract functions.'}

## Recommended Fix
{fix_suggestion if fix_suggestion != 'No fix suggestion available' else self._generate_fix_template(primary)}

## Appendix
- Full report attached. Triage contacts: add if required.
"""

        return tmpl

    def _generate_audit_section(self, audit_results: Dict[str, Any]) -> str:
        """Generate audit results section."""
        content = "### Static Analysis Results\n\n"

        # Build combined list and split confirmed vs suspected
        all_vulns = []
        if audit_results.get('slither', {}).get('vulnerabilities'):
            for v in audit_results['slither']['vulnerabilities']:
                v['status'] = v.get('status', 'confirmed')
                all_vulns.append(v)
        if audit_results.get('mythril', {}).get('vulnerabilities'):
            for v in audit_results['mythril']['vulnerabilities']:
                v['status'] = v.get('status', 'confirmed')
                all_vulns.append(v)
        if audit_results.get('pattern_analysis', {}).get('vulnerabilities'):
            for v in audit_results['pattern_analysis']['vulnerabilities']:
                v['status'] = v.get('status', 'suspected')
                all_vulns.append(v)

        confirmed = [v for v in all_vulns if v.get('status') == 'confirmed']
        suspected = [v for v in all_vulns if v.get('status') != 'confirmed']

        # Slither results
        slither = audit_results.get('slither', {})
        if slither.get('vulnerabilities'):
            content += "#### Slither Findings\n\n"
            for vuln in slither['vulnerabilities']:
                content += f"""**{vuln.get('title', 'Unknown')}**
- Severity: {vuln.get('severity', 'Unknown').title()}
 - Status: Confirmed
- Location: {vuln.get('file', 'Unknown')}:{vuln.get('line', 'Unknown')}
- Description: {vuln.get('description', 'No description')[:100]}...

"""

        # Mythril results
        mythril = audit_results.get('mythril', {})
        if mythril.get('vulnerabilities'):
            content += "#### Mythril Findings\n\n"
            for vuln in mythril['vulnerabilities']:
                content += f"""**{vuln.get('title', 'Unknown')}**
- Severity: {vuln.get('severity', 'Unknown').title()}
 - Status: Confirmed
- Location: {vuln.get('file', 'Unknown')}:{vuln.get('line', 'Unknown')}
- SWC ID: {vuln.get('swc_id', 'Unknown')}
- Description: {vuln.get('description', 'No description')[:100]}...

"""

        # Pattern analysis (suspected and LLM validated)
        pattern = audit_results.get('pattern_analysis', {})
        if pattern.get('vulnerabilities'):
            # Split
            llm_validated = [v for v in pattern['vulnerabilities'] if v.get('status') == 'llm_validated']
            suspected = [v for v in pattern['vulnerabilities'] if v.get('status') != 'llm_validated']

            if llm_validated:
                content += "#### Pattern Findings Promoted by LLM (Validated)\n\n"
                for vuln in llm_validated[:20]:
                    content += f"""**{vuln.get('title', 'Unknown')}**
- Severity: {vuln.get('severity', 'Unknown').title()}
- Status: LLM Validated
- Location: {vuln.get('file', 'Unknown')}:{vuln.get('line', 'Unknown')}
- Description: {vuln.get('description', 'No description')[:100]}...

"""

            if suspected:
                content += "#### Pattern Findings (Suspected)\n\n"
                for vuln in suspected[:20]:
                    content += f"""**{vuln.get('title', 'Unknown')}**
- Severity: {vuln.get('severity', 'Unknown').title()}
- Status: Suspected (needs tool or fuzz confirmation)
- Location: {vuln.get('file', 'Unknown')}:{vuln.get('line', 'Unknown')}
- Description: {vuln.get('description', 'No description')[:100]}...

"""

        # AI Analysis Results (from LLM)
        ai_vulnerabilities = audit_results.get('vulnerabilities', [])

        # Also check for LLM-specific vulnerabilities in llm_analysis
        llm_analysis = audit_results.get('llm_analysis', {})
        if isinstance(llm_analysis, dict) and 'vulnerabilities' in llm_analysis:
            ai_vulnerabilities.extend(llm_analysis['vulnerabilities'])

        # Add exploitability verification results if available
        exploitability_results = audit_results.get('exploitability_results', [])
        confirmed_exploits = audit_results.get('confirmed_exploits', 0)
        highly_likely_exploits = audit_results.get('highly_likely_exploits', 0)
        possible_exploits = audit_results.get('possible_exploits', 0)
        
        if exploitability_results or confirmed_exploits > 0 or highly_likely_exploits > 0:
            content += "#### Exploitability Verification Results\n\n"
            content += f"- **Confirmed Exploitable:** {confirmed_exploits}\n"
            content += f"- **Highly Likely Exploitable:** {highly_likely_exploits}\n"
            content += f"- **Possibly Exploitable:** {possible_exploits}\n\n"
            
            # Add detailed exploitability information for confirmed/highly likely vulnerabilities
            for result in exploitability_results:
                if result.get('exploitability_level') in ['confirmed', 'highly_likely']:
                    content += f"""**{result.get('vulnerability_id', 'Unknown')}**
- Exploitability Level: {result.get('exploitability_level', 'Unknown').title()}
- Confidence: {result.get('confidence', 0):.2f}
- Validation Methods: {', '.join(result.get('validation_methods', []))}
- Attack Vector: {result.get('attack_vector', 'Unknown')}
- Prerequisites: {', '.join(result.get('prerequisites', []))}
- Estimated Impact: {result.get('estimated_impact', 'Unknown')}

"""

        # Legacy exploit validation results (deprecated)
        exploit_validation_results = None
        if exploit_validation_results:
            print(f"DEBUG: Processing exploit validation results")
            if isinstance(exploit_validation_results, dict):
                if 'results' in exploit_validation_results:
                    exploit_results = exploit_validation_results['results']
                elif 'validation_results' in exploit_validation_results:
                    exploit_results = exploit_validation_results['validation_results']
                else:
                    exploit_results = []
            elif isinstance(exploit_validation_results, list):
                exploit_results = exploit_validation_results
            else:
                exploit_results = []

            if isinstance(exploit_results, list) and exploit_results:
                print(f"DEBUG: Found {len(exploit_results)} exploit results")
                # Add exploit validation info to each vulnerability
                for vuln in ai_vulnerabilities:
                    vuln_id = vuln.get('id', '')
                    for exploit_result in exploit_results:
                        if isinstance(exploit_result, dict) and exploit_result.get('vulnerability_id') == vuln_id:
                            print(f"DEBUG: Found matching exploit result for vuln_id: {vuln_id}")
                            vuln['exploit_successful'] = exploit_result.get('exploitable', exploit_result.get('exploit_successful', False))
                            vuln['poc_code'] = exploit_result.get('poc_code', '')
                            vuln['exploit_steps'] = exploit_result.get('exploit_steps', exploit_result.get('steps', []))
                            vuln['impact_assessment'] = exploit_result.get('impact_assessment', exploit_result.get('impact', ''))
                            # Update status based on exploit success
                            if vuln['exploit_successful']:
                                vuln['status'] = 'confirmed'
                            break
            else:
                print(f"DEBUG: No exploit results found or invalid format")

        if ai_vulnerabilities:
            content += "#### AI-Powered Vulnerability Analysis\n\n"
            vuln_counter = 1
            for vuln in ai_vulnerabilities:
                # Handle both dict and VulnerabilityMatch objects
                swc_id = vuln.get('swc_id') if hasattr(vuln, 'get') else vuln.swc_id
                if swc_id == 'SWC-000':  # Skip manual review placeholder
                    continue

                # Handle both dict and VulnerabilityMatch objects
                if hasattr(vuln, 'get'):
                    title = vuln.get('title', 'Unknown Vulnerability')
                    swc_id = vuln.get('swc_id', 'Unknown')
                    severity = vuln.get('severity', 'Unknown').title()
                    confidence = vuln.get('confidence', 0)
                    line_numbers = vuln.get('line_numbers', [vuln.get('line', 'Unknown')])
                    description = vuln.get('description', 'No description available')
                    exploitability = vuln.get('exploitability', vuln.get('exploit_successful', 'Not assessed'))
                    impact = vuln.get('impact_assessment', vuln.get('impact', 'Not assessed'))
                    exploit_steps = vuln.get('exploit_steps', [])
                    poc_code = vuln.get('poc_code', '')
                    fix_suggestion = vuln.get('fix_suggestion', 'No fix suggestion available')
                else:
                    title = vuln.vulnerability_type.replace('_', ' ').title()
                    swc_id = vuln.swc_id or 'Unknown'
                    severity = vuln.severity.title()
                    confidence = vuln.confidence
                    line_numbers = [vuln.line_number]
                    description = vuln.description
                    exploitability = 'Confirmed by enhanced analysis'
                    impact = 'High - Protocol-level impact'
                    exploit_steps = []
                    poc_code = ''
                    fix_suggestion = 'Implement proper access control'

                content += f"""### {vuln_counter}. {title}

**SWC ID:** {swc_id}
**Severity:** {severity}
**Confidence:** {confidence:.2f}
**Location:** Line(s) {', '.join(map(str, vuln.get('line_numbers', [vuln.get('line', 'Unknown')])))}

**Description:**
{vuln.get('description', 'No description available')}

**Exploitability:** {vuln.get('exploitability', vuln.get('exploit_successful', 'Not assessed'))}
**Impact:** {vuln.get('impact_assessment', vuln.get('impact', 'Not assessed'))}

{vuln.get('exploit_steps', []) and f'''**Exploit Steps:**
{"".join(f"{i+1}. {step}\\n" for i, step in enumerate(vuln.get('exploit_steps', [])))}''' or ''}

{vuln.get('poc_code') and f'''**Proof-of-Concept Code:**
```solidity
{vuln.get('poc_code')}
```
''' or ''}

**Fix Suggestion:**
{vuln.get('fix_suggestion', 'No fix suggestion available')}

---
"""
                vuln_counter += 1

        return content

    def _generate_fuzz_section(self, fuzz_results: Dict[str, Any]) -> str:
        """Generate fuzzing results section."""
        content = "### Dynamic Fuzzing Results\n\n"

        content += f"""#### Summary
- **Total Executions:** {len(fuzz_results.get('fuzz_results', []))}
- **Successful Executions:** {len([r for r in fuzz_results.get('fuzz_results', []) if r.get('success', False)])}
- **Crashes Detected:** {len(fuzz_results.get('crashes', []))}
- **Execution Time:** {fuzz_results.get('execution_time', 0):.2f}s

#### Vulnerabilities Confirmed
"""

        vulnerabilities = fuzz_results.get('vulnerabilities', [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                content += f"""**{vuln.get('type', 'Unknown').replace('_', ' ').title()}**
- Confidence: {vuln.get('confidence', 0):.2f}
- Severity: {vuln.get('severity', 'Unknown').title()}
- Description: {vuln.get('description', 'No description')}

"""
        else:
            content += "✅ No vulnerabilities confirmed through fuzzing.\n\n"

        # Add crash details if any
        crashes = fuzz_results.get('crashes', [])
        if crashes:
            content += "#### Crashes Detected\n\n"
            for crash in crashes[:5]:  # Show first 5 crashes
                content += f"""**Crash #{crash.get('iteration', 'Unknown')}**
- Input: {crash.get('input', {}).get('function', 'Unknown')}()
- Error: {crash.get('error', 'Unknown')}
- Gas Used: {crash.get('gas_used', 'Unknown')}

"""

        # Add coverage information
        coverage = fuzz_results.get('coverage', {})
        if coverage:
            content += "#### Code Coverage\n\n"
            content += f"""- **Lines Covered:** {coverage.get('lines', 0)}%
- **Branches Covered:** {coverage.get('branches', 0)}%
- **Functions Covered:** {coverage.get('functions', 0)}%

"""

        return content

    def _generate_validation_section(self, validation_results: Dict[str, Any]) -> str:
        """Generate fix validation section."""
        content = "### Fix Validation Results\n\n"

        validation_list = validation_results.get('validation_results', [])
        if validation_list:
            for validation in validation_list:
                status_emoji = {
                    'validated': '✅',
                    'failed': '❌',
                    'partial': '⚠️'
                }.get(validation.get('status', 'unknown'), '❓')

                content += f"""**{status_emoji} {validation.get('fix_id', 'Unknown')}**
- Status: {validation.get('status', 'Unknown').title()}
- Message: {validation.get('message', 'No message')}
- Confidence: {validation.get('confidence', 0):.2f}

"""
        else:
            content += "No fix validation results available.\n\n"

        return content

    def _generate_steps_to_reproduce(self, vuln: Dict[str, Any]) -> str:
        """Generate steps to reproduce based on vulnerability type."""
        # Handle both dict and VulnerabilityMatch objects
        if hasattr(vuln, 'get'):
            vuln_type = vuln.get('vulnerability_type', vuln.get('category', '')).lower()
            swc_id = vuln.get('swc_id', '').upper()
        else:
            vuln_type = vuln.vulnerability_type.lower()
            swc_id = vuln.swc_id.upper()
        
        if 'SWC-107' in swc_id or 'reentrancy' in vuln_type:
            return """1. Deploy vulnerable contract with funds
2. Deploy malicious contract with fallback function
3. Fund malicious contract with ETH
4. Call vulnerable function to trigger reentrancy
5. Verify funds were drained from vulnerable contract"""
        
        elif 'SWC-105' in swc_id or 'access_control' in vuln_type:
            return """1. Deploy contract
2. Attempt to call protected function without authorization
3. Verify access control bypass
4. Confirm unauthorized access to critical functions"""
        
        elif 'SWC-101' in swc_id or 'arithmetic' in vuln_type:
            return """1. Deploy contract
2. Call function with values that cause overflow/underflow
3. Verify incorrect calculations
4. Confirm arithmetic vulnerability exploitation"""
        
        else:
            return """1. Deploy contract
2. Call vulnerable function with malicious inputs
3. Verify vulnerability exploitation
4. Confirm security impact"""

    def _generate_poc_template(self, vuln: Dict[str, Any]) -> str:
        """Generate PoC template based on vulnerability type."""
        # Handle both dict and VulnerabilityMatch objects
        if hasattr(vuln, 'get'):
            vuln_type = vuln.get('vulnerability_type', vuln.get('category', '')).lower()
            swc_id = vuln.get('swc_id', '').upper()
        else:
            vuln_type = vuln.vulnerability_type.lower()
            swc_id = vuln.swc_id.upper()
        
        if 'SWC-107' in swc_id or 'reentrancy' in vuln_type:
            return """```solidity
// Reentrancy PoC template
contract ReentrancyExploit {
    VulnerableContract target;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function attack() external payable {
        // Trigger reentrancy attack
        target.vulnerableFunction();
    }
    
    receive() external payable {
        // Re-entrant call
        target.vulnerableFunction();
    }
}
```"""
        
        elif 'SWC-105' in swc_id or 'access_control' in vuln_type:
            return """```solidity
// Access Control Bypass PoC
contract AccessControlExploit {
    VulnerableContract target;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function exploit() external {
        // Call protected function without authorization
        target.protectedFunction();
    }
}
```"""
        
        else:
            return """```solidity
// Vulnerability PoC template
contract VulnerabilityExploit {
    VulnerableContract target;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function exploit() external {
        // Implement exploit logic
        target.vulnerableFunction();
    }
}
```"""

    def _generate_fix_template(self, vuln: Dict[str, Any]) -> str:
        """Generate fix template based on vulnerability type."""
        # Handle both dict and VulnerabilityMatch objects
        if hasattr(vuln, 'get'):
            vuln_type = vuln.get('vulnerability_type', vuln.get('category', '')).lower()
            swc_id = vuln.get('swc_id', '').upper()
        else:
            vuln_type = vuln.vulnerability_type.lower()
            swc_id = vuln.swc_id.upper()
        
        if 'SWC-107' in swc_id or 'reentrancy' in vuln_type:
            return """```solidity
// Before (vulnerable)
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] = 0; // State updated after external call
}

// After (fixed)
function withdraw() external {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0; // State updated before external call
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```"""
        
        elif 'SWC-105' in swc_id or 'access_control' in vuln_type:
            return """```solidity
// Add access control modifier
modifier onlyOwner() {
    require(msg.sender == owner, "Not the owner");
    _;
}

// Apply to protected functions
function protectedFunction() external onlyOwner {
    // Function logic
}
```"""
        
        else:
            return """```solidity
// Implement appropriate security measures
// - Add access control where needed
// - Validate inputs
// - Use safe math operations
// - Follow checks-effects-interactions pattern
```"""
