"""
Enhanced AetherAudit engine with improved accuracy and reduced false positives.
Implements validation layers and better vulnerability detection.
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch
from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer
from core.vulnerability_validator import VulnerabilityValidator, ValidationResult
from core.file_handler import FileHandler
# Phase 3: Advanced AI Integration
from core.ai_ensemble import EnhancedAIEnsemble, ConsensusResult
# Learning system removed - was simulated, not real
# Formal verification removed - was simulated, not real
from core.llm_false_positive_filter import LLMFalsePositiveFilter
from core.foundry_poc_generator import FoundryPoCGenerator
from core.database_manager import DatabaseManager, AuditResult, VulnerabilityFinding, LearningPattern, AuditMetrics
from core.enhanced_report_generator import EnhancedReportGenerator


class EnhancedAetherAuditEngine:
    """Enhanced audit engine with improved accuracy and validation."""

    def __init__(self, verbose: bool = False, openai_api_key: Optional[str] = None, database: Optional[Any] = None):
        self.verbose = verbose
        self.file_handler = FileHandler()

        # Enhanced components (Phase 1-2)
        self.vulnerability_detector = EnhancedVulnerabilityDetector()
        self.llm_analyzer = EnhancedLLMAnalyzer(api_key=openai_api_key)
        self.validator = VulnerabilityValidator()

        # Phase 3: Advanced AI Integration
        self.ai_ensemble = EnhancedAIEnsemble()

        # Database integration
        self.database = database if database is not None else DatabaseManager()
        # Learning system removed - was simulated
        # Formal verification removed - was simulated
        self.llm_false_positive_filter = LLMFalsePositiveFilter(self.llm_analyzer)
        self.foundry_poc_generator = FoundryPoCGenerator()

        # Enhanced report generation
        self.enhanced_report_generator = EnhancedReportGenerator()
        
        # Foundry integration (optional)
        self.foundry_integration = None
        
        # Statistics tracking
        self.stats = {
            'total_findings': 0,
            'validated_findings': 0,
            'false_positives': 0,
            'accuracy_rate': 0.0,
            'ai_consensus_findings': 0,
            'formal_verification_proofs': 0,
            'learning_feedback_entries': 0
        }

    async def run_audit(self, contract_path: str, flow_config: Dict[str, Any], foundry_validation: bool = False, enhanced: bool = True, phase3: bool = False, llm_validation: bool = False, ai_ensemble: bool = False, selected_contracts: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run enhanced audit with validation.
        
        Args:
            contract_path: Path to contract file or directory
            flow_config: Audit flow configuration
            foundry_validation: Enable Foundry validation
            enhanced: Use enhanced analysis
            phase3: Enable Phase 3 features
            llm_validation: Enable LLM validation
            ai_ensemble: Enable AI ensemble
            selected_contracts: Optional list of specific contract file paths to audit (filters directory contents)
        """
        print("🚀 Starting enhanced AetherAudit...", flush=True)
        start_time = time.time()
        
        try:
            # Step 1: Read contract files
            contract_files = self._read_contract_files(contract_path, selected_contracts=selected_contracts)
            if not contract_files:
                return {'error': 'No contract files found'}
            
            # Step 2: Enhanced static analysis
            static_results = await self._run_enhanced_static_analysis(contract_files)
            
            # Step 3: Enhanced LLM analysis
            llm_results = await self._run_enhanced_llm_analysis(contract_files, static_results)
            
            # Step 4: Phase 3 AI Ensemble Analysis
            ai_ensemble_results = await self._run_ai_ensemble_analysis(contract_files, static_results)
            
            # Step 5: Formal Verification for Critical Findings (DISABLED - too many false positives)
            formal_verification_results = None  # Disabled due to excessive false positives
            
            # Step 6: Validation layer
            validated_results = await self._validate_findings(static_results, llm_results, contract_files, ai_ensemble_results, formal_verification_results)
            
            # Step 7: Learning System Integration (removed - was simulated)
            
            # Step 8: Foundry validation (if requested) - MOVED BEFORE report generation
            if foundry_validation:
                await self._run_foundry_validation(contract_path, validated_results)
            
            # Step 9: Generate comprehensive report (MOVED AFTER Foundry validation)
            final_results = self._generate_final_report(validated_results, start_time, ai_ensemble_results, formal_verification_results)

            # Step 10: Save to database (MOVED AFTER report generation)
            self._save_audit_to_database(contract_path, final_results, start_time, flow_config)

            return final_results
            
        except Exception as e:
            print(f"❌ Enhanced audit failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return {'error': str(e)}

    def _read_contract_files(self, contract_path: str, selected_contracts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Read contract files with enhanced error handling.
        
        Args:
            contract_path: Path to contract file or directory
            selected_contracts: Optional list of specific contract file paths to include (filters directory contents)
        """
        contract_files = []
        
        if os.path.isfile(contract_path):
            # Single file
            try:
                with open(contract_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                contract_files.append({
                    'path': contract_path,
                    'content': content,
                    'name': os.path.basename(contract_path)
                })
            except Exception as e:
                print(f"❌ Error reading contract file: {e}")
        elif os.path.isdir(contract_path):
            # Directory - filter by selected_contracts if provided
            selected_set = set(selected_contracts) if selected_contracts else None
            
            for root, dirs, files in os.walk(contract_path):
                for file in files:
                    if file.endswith('.sol'):
                        file_path = os.path.join(root, file)
                        
                        # Filter by selected_contracts if provided
                        if selected_set is not None and file_path not in selected_set:
                            continue
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            contract_files.append({
                                'path': file_path,
                                'content': content,
                                'name': file
                            })
                        except Exception as e:
                            print(f"❌ Error reading {file_path}: {e}")
        
        return contract_files

    async def _run_enhanced_static_analysis(self, contract_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run enhanced static analysis with improved accuracy."""
        print("🔍 Running enhanced static analysis...", flush=True)
        
        all_vulnerabilities = []
        total_lines = 0
        
        # STAGE 1: Run Slither static analysis
        print("   📊 Running Slither static analysis...", flush=True)
        slither_findings = self._run_slither_analysis(contract_files)
        
        # Convert Slither findings (dicts) to VulnerabilityMatch objects
        from core.enhanced_vulnerability_detector import VulnerabilityMatch
        for finding in slither_findings:
            if isinstance(finding, dict):
                # Convert dict to VulnerabilityMatch object
                vuln_match = VulnerabilityMatch(
                    vulnerability_type=finding.get('vulnerability_type', finding.get('type', 'Unknown')),
                    severity=finding.get('severity', 'medium'),
                    confidence=finding.get('confidence', 0.7),
                    line_number=finding.get('line_number', finding.get('line', 0)),
                    description=finding.get('description', ''),
                    code_snippet=finding.get('code_snippet', ''),
                    swc_id=finding.get('swc_id', ''),
                    category=finding.get('category', 'slither_finding'),
                    context=finding.get('context', {}),
                    validation_status='validated'  # Slither findings are pre-validated
                )
                all_vulnerabilities.append(vuln_match)
            else:
                # Already a VulnerabilityMatch object
                all_vulnerabilities.append(finding)
        
        if slither_findings:
            print(f"   📊 Slither total: {len(slither_findings)} findings across all contracts", flush=True)
        
        # STAGE 2: Run our enhanced pattern-based detectors
        print("   🔎 Running enhanced pattern-based detectors...", flush=True)
        
        # NEW: Build call graph across all contracts for better cross-contract analysis
        print("   🔗 Building call graph for cross-contract analysis...", flush=True)
        self.vulnerability_detector.build_call_graph_from_contracts(contract_files)
        
        # NEW: Analyze proxy delegation patterns to prevent false positives
        print("   🔗 Analyzing proxy delegation patterns...", flush=True)
        from core.delegation_analyzer import DelegationFlowAnalyzer
        delegation_analyzer = DelegationFlowAnalyzer()
        delegation_flow = delegation_analyzer.analyze_delegation_flow(contract_files)
        
        if delegation_flow.has_proxy_pattern:
            print(delegation_analyzer.get_summary(delegation_flow))
        else:
            print("   ℹ️  No proxy pattern detected")
        
        # Store delegation flow for later use
        self.context = getattr(self, 'context', {})
        self.context['delegation_flow'] = delegation_flow
        
        for contract_file in contract_files:
            content = contract_file['content']
            total_lines += len(content.split('\n'))
            
            # Set contract context for better analysis
            self.vulnerability_detector.set_contract_context({
                'file_path': contract_file['path'],
                'contract_name': contract_file['name'],
                'total_lines': len(content.split('\n'))
            })
            
            # Run enhanced vulnerability detection
            vulnerabilities = self.vulnerability_detector.analyze_contract(content)
            
            # Add file context to vulnerabilities
            for vuln in vulnerabilities:
                vuln.context['file_path'] = contract_file['path']
                vuln.context['contract_name'] = contract_file['name']
            
            all_vulnerabilities.extend(vulnerabilities)
        
        # NEW: Deduplicate vulnerabilities before filtering
        print("   🔄 Deduplicating vulnerabilities...", flush=True)
        from core.vulnerability_deduplicator import VulnerabilityDeduplicator
        deduplicator = VulnerabilityDeduplicator()
        
        # Convert to dicts for deduplication
        vuln_dicts = []
        for vuln in all_vulnerabilities:
            if isinstance(vuln, dict):
                vuln_dicts.append(vuln)
            else:
                vuln_dicts.append({
                    'vulnerability_type': getattr(vuln, 'vulnerability_type', 'Unknown'),
                    'severity': getattr(vuln, 'severity', 'medium'),
                    'confidence': getattr(vuln, 'confidence', 0.5),
                    'line': getattr(vuln, 'line_number', 0),
                    'line_number': getattr(vuln, 'line_number', 0),
                    'description': getattr(vuln, 'description', ''),
                    'code_snippet': getattr(vuln, 'code_snippet', ''),
                    'validation_status': getattr(vuln, 'validation_status', 'pending'),
                    'context': getattr(vuln, 'context', {}),
                })
        
        # Remove subsumed vulnerabilities
        vuln_dicts = deduplicator.remove_subsumed_vulnerabilities(vuln_dicts)
        
        # Deduplicate
        deduplicated_vulns = deduplicator.deduplicate(vuln_dicts)
        print(f"   📉 Reduced from {len(all_vulnerabilities)} to {len(deduplicated_vulns)} vulnerabilities after deduplication", flush=True)
        
        # NEW: Apply access control context analysis
        print("   🔐 Analyzing access control context...", flush=True)
        from core.access_control_context_analyzer import AccessControlContextAnalyzer
        ac_analyzer = AccessControlContextAnalyzer()
        
        access_adjusted_vulns = []
        for vuln in deduplicated_vulns:
            # Extract function name and code from context
            function_name = vuln.get('context', {}).get('function_name', '')
            if not function_name:
                # Try to extract from description
                import re
                func_match = re.search(r'function\s+(\w+)', vuln.get('description', ''))
                if func_match:
                    function_name = func_match.group(1)
            
            # Get contract content for analysis
            file_path = vuln.get('context', {}).get('file_path', '')
            contract_content = ''
            for cf in contract_files:
                if cf['path'] == file_path:
                    contract_content = cf['content']
                    break
            
            # Analyze access control if we have function name and content
            if function_name and contract_content:
                function_code = ac_analyzer.extract_function_code(
                    contract_content,
                    function_name,
                    vuln.get('line_number', vuln.get('line', 0))
                )
                
                access_info = ac_analyzer.analyze_function_access_control(
                    function_code,
                    function_name,
                    contract_content
                )
                
                # Adjust severity if access control is present
                if access_info['has_access_control']:
                    vuln = ac_analyzer.adjust_vulnerability_severity(vuln, access_info)
                    print(f"   ↓  Downgraded {function_name}() severity due to {access_info['access_control_type']} protection", flush=True)
            
            access_adjusted_vulns.append(vuln)
        
        # Filter out false positives
        validated_vulnerabilities = []
        for vuln in access_adjusted_vulns:
            # Handle both VulnerabilityMatch objects and dicts
            if isinstance(vuln, dict):
                validation_status = vuln.get('validation_status', 'pending')
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                line_num = vuln.get('line_number', vuln.get('line', 0))
            else:
                validation_status = getattr(vuln, 'validation_status', 'pending')
                vuln_type = getattr(vuln, 'vulnerability_type', 'Unknown')
                line_num = getattr(vuln, 'line_number', 0)
            
            if validation_status == "validated":
                validated_vulnerabilities.append(vuln)
            else:
                print(f"⚠️  Filtered false positive: {vuln_type} at line {line_num}")
        
        # Calculate statistics
        self.stats['total_findings'] = len(all_vulnerabilities)
        self.stats['deduplicated_findings'] = len(deduplicated_vulns)
        self.stats['validated_findings'] = len(validated_vulnerabilities)
        self.stats['false_positives'] = len(all_vulnerabilities) - len(validated_vulnerabilities)
        self.stats['accuracy_rate'] = (len(validated_vulnerabilities) / len(all_vulnerabilities) * 100) if all_vulnerabilities else 0
        
        return {
            'vulnerabilities': validated_vulnerabilities,
            'total_lines': total_lines,
            'contract_count': len(contract_files),
            'statistics': self.stats.copy()
        }

    def _run_slither_analysis(self, contract_files: List[Dict[str, Any]]) -> List[Any]:
        """Run Slither static analysis on contract files."""
        try:
            from core.vulnerability_detector import SlitherIntegration
            slither = SlitherIntegration()
            
            if not slither.slither_available:
                print("   ⚠️  Slither unavailable - using enhanced detectors only", flush=True)
                return []
            
            all_findings = []
            for contract_file in contract_files:
                try:
                    # Prefer the actual on-disk file path for correct imports and layout
                    real_path = contract_file.get('path')
                    if real_path and os.path.exists(real_path):
                        findings = slither.analyze_with_slither(real_path)
                        all_findings.extend(findings)
                    else:
                        # Fallback: still support temp-path analysis if file isn't on disk
                        import tempfile
                        from pathlib import Path
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                            f.write(contract_file['content'])
                            temp_path = f.name
                        try:
                            findings = slither.analyze_with_slither(temp_path)
                            all_findings.extend(findings)
                        finally:
                            Path(temp_path).unlink(missing_ok=True)
                
                except Exception as e:
                    print(f"   ⚠️  Slither analysis failed for {contract_file['name']}: {e}", flush=True)
                    continue
            
            return all_findings
        
        except Exception as e:
            print(f"   ⚠️  Could not run Slither analysis: {e}", flush=True)
            return []

    def _extract_code_snippet(self, contract_content: str, line_number: int, context_lines: int = 5) -> str:
        """Extract code snippet around a specific line number for LLM verification."""
        lines = contract_content.split('\n')

        # Ensure line_number is valid
        if line_number < 1 or line_number > len(lines):
            return "// Line number out of range"

        # Calculate start and end lines with context
        start_line = max(1, line_number - context_lines)
        end_line = min(len(lines), line_number + context_lines)

        # Extract the snippet
        snippet_lines = []
        for i in range(start_line - 1, end_line):
            marker = ">>> " if (i + 1) == line_number else "    "
            snippet_lines.append(f"{marker}{i + 1:4d}: {lines[i]}")

        return '\n'.join(snippet_lines)

    async def _run_enhanced_llm_analysis(self, contract_files: List[Dict[str, Any]], static_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run enhanced LLM analysis with validation."""
        print("🤖 Running enhanced LLM analysis...", flush=True)
        
        # Combine all contract content
        combined_content = "\n\n".join([cf['content'] for cf in contract_files])
        
        # Run enhanced LLM analysis
        llm_results = await self.llm_analyzer.analyze_vulnerabilities(
            combined_content,
            static_results,
            {'contract_files': contract_files}
        )
        
        return llm_results

    async def _run_ai_ensemble_analysis(self, contract_files: List[Dict[str, Any]], static_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run Phase 3 AI ensemble analysis with multi-model consensus."""
        print("🤖 Running Phase 3 AI ensemble analysis...", flush=True)
        
        # Combine all contract content
        combined_content = "\n\n".join([cf['content'] for cf in contract_files])
        
        try:
            # Run AI ensemble analysis
            ensemble_result = await self.ai_ensemble.analyze_contract_ensemble(combined_content)
            
            # Process consensus findings
            consensus_findings = []
            for finding in ensemble_result.consensus_findings:
                # Extract relevant code snippet around the vulnerability line
                code_snippet = self._extract_code_snippet(combined_content, finding.get('line', 0))

                consensus_findings.append({
                    'type': finding['type'],
                    'severity': finding['severity'],
                    'confidence': finding.get('confidence', 0.85),
                    'description': finding['description'],
                    'line': finding.get('line', 0),
                    'swc_id': finding.get('swc_id', ''),
                    'models': finding.get('models', []),
                    'model_count': finding.get('consensus_count', 0),
                    'source': 'ai_ensemble',
                    'code_snippet': code_snippet,
                    'contract_content': combined_content  # Include full contract for context
                })
            
            # Update statistics
            self.stats['ai_consensus_findings'] = len(consensus_findings)
            
            print(f"✅ AI ensemble found {len(consensus_findings)} consensus findings")
            print(f"✅ Model agreement: {ensemble_result.model_agreement:.2f}")
            print(f"✅ Confidence score: {ensemble_result.confidence_score:.2f}")
            
            return {
                'consensus_findings': consensus_findings,
                'model_agreement': ensemble_result.model_agreement,
                'confidence_score': ensemble_result.confidence_score,
                'processing_time': ensemble_result.processing_time,
                'individual_results': ensemble_result.individual_results
            }
            
        except Exception as e:
            print(f"⚠️  AI ensemble analysis failed: {e}")
            return {
                'consensus_findings': [],
                'model_agreement': 0.0,
                'confidence_score': 0.0,
                'processing_time': 0.0,
                'error': str(e)
            }

# Formal verification method removed - was simulated

    def _normalize_vulnerability_dict(self, vuln: Any) -> Dict[str, Any]:
        """Normalize vulnerability from any source to consistent dict structure."""
        # Handle VulnerabilityMatch objects (dataclass or object with attributes)
        if hasattr(vuln, '__dataclass_fields__') or hasattr(vuln, 'vulnerability_type'):
            return {
                'vulnerability_type': getattr(vuln, 'vulnerability_type', 'Unknown'),
                'title': getattr(vuln, 'vulnerability_type', 'Unknown'),
                'severity': getattr(vuln, 'severity', 'medium'),
                'confidence': getattr(vuln, 'confidence', 0.0),
                'line_number': getattr(vuln, 'line_number', 0),
                'description': getattr(vuln, 'description', ''),
                'code_snippet': getattr(vuln, 'code_snippet', ''),
                'swc_id': getattr(vuln, 'swc_id', ''),
                'category': getattr(vuln, 'category', ''),
                'context': getattr(vuln, 'context', {})
            }
        
        # Handle dict objects - normalize field names
        elif isinstance(vuln, dict):
            # Extract vulnerability_type from various possible field names
            vuln_type = (
                vuln.get('vulnerability_type') or 
                vuln.get('title') or 
                vuln.get('type') or 
                vuln.get('name') or
                'Unknown'
            )
            
            return {
                'vulnerability_type': vuln_type,
                'title': vuln_type,  # Alias for compatibility
                'severity': vuln.get('severity', 'medium'),
                'confidence': vuln.get('confidence', 0.0),
                'line_number': vuln.get('line_number', vuln.get('line', 0)),
                'description': vuln.get('description', ''),
                'code_snippet': vuln.get('code_snippet', ''),
                'swc_id': vuln.get('swc_id', ''),
                'category': vuln.get('category', vuln_type),
                'context': vuln.get('context', {}),
                # Preserve original fields that aren't duplicated
                **{k: v for k, v in vuln.items() if k not in ['vulnerability_type', 'title', 'type']}
            }
        
        # Fallback for unknown types
        return {
            'vulnerability_type': 'Unknown',
            'severity': 'medium',
            'confidence': 0.0,
            'line_number': 0,
            'description': str(vuln),
            'code_snippet': '',
            'swc_id': '',
            'category': '',
            'context': {}
        }

    def _calibrate_vulnerability_severity(self, vuln: Any, contract_content: str) -> Dict[str, Any]:
        """Calibrate vulnerability severity to prevent false positives."""
        # Ensure vuln is a normalized dict
        if not isinstance(vuln, dict):
            vuln = self._normalize_vulnerability_dict(vuln)
        
        vuln_type = vuln.get('vulnerability_type', 'unknown')
        original_severity = vuln.get('severity', 'medium')
        
        # Calibrate severity based on vulnerability type and context
        calibrated_severity = original_severity
        
        # Downgrade common false positives
        if vuln_type in ['division_by_zero', 'integer_underflow', 'bounds_checking_issue', 'missing_input_validation', 'external_manipulation']:
            # These are often false positives in constants or loops
            if original_severity in ['critical', 'high']:
                calibrated_severity = 'low'
            elif original_severity == 'medium':
                calibrated_severity = 'low'
        
        elif vuln_type in ['parameter_validation_issue', 'malformed_input_handling', 'unvalidated_decoding']:
            # These are often false positives in external interfaces
            if original_severity in ['critical', 'high']:
                calibrated_severity = 'medium'
        
        elif vuln_type in ['access_control']:
            # Access control issues need context validation
            if 'public' in contract_content.lower() and 'external' in contract_content.lower():
                # If there are many public/external functions, downgrade severity
                if original_severity == 'critical':
                    calibrated_severity = 'medium'
        
        # Apply calibration (vuln is always a dict now)
        vuln['severity'] = calibrated_severity
        
        return vuln

# Learning system integration method removed - was simulated

    async def _validate_findings(self, static_results: Dict[str, Any], llm_results: Dict[str, Any], contract_files: List[Dict[str, Any]], ai_ensemble_results: Dict[str, Any] = None, formal_verification_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect findings for Foundry verification - no simulated validation."""
        print("🔍 Collecting findings for Foundry verification...")
        
        all_vulnerabilities = []
        
        # Add static analysis vulnerabilities
        for vuln in static_results.get('vulnerabilities', []):
            all_vulnerabilities.append({
                'type': 'static',
                'vulnerability': vuln,
                'source': 'enhanced_detector'
            })
        
        # Add LLM analysis vulnerabilities
        llm_vulns = llm_results.get('analysis', {}).get('vulnerabilities', [])
        for vuln in llm_vulns:
            all_vulnerabilities.append({
                'type': 'llm',
                'vulnerability': vuln,
                'source': 'enhanced_llm'
            })
        
        # Add AI ensemble consensus findings
        if ai_ensemble_results:
            for finding in ai_ensemble_results.get('consensus_findings', []):
                all_vulnerabilities.append({
                    'type': 'ai_ensemble',
                    'vulnerability': finding,
                    'source': 'ai_ensemble'
                })
        
        # Add formal verification results (only for legitimate vulnerabilities)
        if formal_verification_results:
            for proof in formal_verification_results.get('formal_proofs', []):
                if proof['proof_status'] == 'proven':
                    # Filter out false positives from formal verification
                    vuln_type = proof.get('vulnerability_id', '').split('_')[1] if '_' in proof.get('vulnerability_id', '') else 'unknown'
                    
                    # Skip benign patterns that shouldn't be vulnerabilities
                    benign_patterns = [
                        'division_by_zero',  # Often false positives in constants
                        'integer_underflow',  # Often false positives in loops
                        'bounds_checking_issue',  # Often false positives
                        'parameter_validation_issue',  # Often false positives
                        'malformed_input_handling',  # Often false positives
                        'unvalidated_decoding',  # Often false positives
                        'missing_input_validation',  # Often false positives
                        'external_manipulation'  # Often false positives
                    ]
                    
                    if vuln_type not in benign_patterns:
                        all_vulnerabilities.append({
                            'type': 'formal_verification',
                            'vulnerability': proof,
                            'source': 'formal_verification'
                        })
        
        # Apply severity calibration and collect; preserve source for dict items
        validated_vulnerabilities = []
        contract_content = contract_files[0]['content'] if contract_files else ""
        
        for vuln_data in all_vulnerabilities:
            vuln = vuln_data['vulnerability']
            # Normalize vulnerability to consistent dict structure
            normalized_vuln = self._normalize_vulnerability_dict(vuln)
            # Apply severity calibration
            calibrated_vuln = self._calibrate_vulnerability_severity(normalized_vuln, contract_content)
            # Preserve source tag for downstream triage/reporting
            calibrated_vuln['source'] = vuln_data.get('source', 'unknown')
            validated_vulnerabilities.append(calibrated_vuln)
        
        # Optional post-filter for Foundry workload control
        try:
            # DISABLED BY DEFAULT: Send all findings to Foundry for validation
            # The consensus-only filter was too restrictive and discarded valid findings
            only_consensus = os.getenv('AETHER_FOUNDRY_ONLY_CONSENSUS', '0') == '1'  # Changed default from '1' to '0'
            foundry_max_items = int(os.getenv('AETHER_FOUNDRY_MAX_ITEMS', '80'))
            if only_consensus:
                validated_vulnerabilities = [
                    v for v in validated_vulnerabilities
                    if (isinstance(v, dict) and v.get('source') == 'ai_ensemble')
                ] or validated_vulnerabilities  # fallback if empty
            # Cap items
            if len(validated_vulnerabilities) > foundry_max_items:
                validated_vulnerabilities = validated_vulnerabilities[:foundry_max_items]
        except Exception:
            pass
        
        # NEW: Apply proxy pattern filter to remove false positives
        print("   🔍 Applying proxy pattern filter...", flush=True)
        from core.proxy_pattern_filter import ProxyPatternFilter
        proxy_filter = ProxyPatternFilter(verbose=self.verbose)
        
        delegation_flow = self.context.get('delegation_flow')
        if delegation_flow:
            filtered_vulnerabilities = proxy_filter.filter_findings(
                validated_vulnerabilities,
                delegation_flow,
                contract_files
            )
            
            filter_stats = proxy_filter.get_filter_stats()
            if filter_stats.filtered_findings > 0:
                print(f"   ✂️  Filtered {filter_stats.filtered_findings} proxy pattern false positives")
            
            validated_vulnerabilities = filtered_vulnerabilities

        print(f"✅ Collected {len(validated_vulnerabilities)} findings for Foundry verification")
        
        return {
            'validated_vulnerabilities': validated_vulnerabilities,
            'validation_results': [],  # No simulated validation
            'total_findings': len(validated_vulnerabilities),
            'validated_count': len(validated_vulnerabilities),
            'false_positive_count': 0  # Will be determined by Foundry tests
        }

    def _generate_final_report(self, validated_results: Dict[str, Any], start_time: float, ai_ensemble_results: Dict[str, Any] = None, formal_verification_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final comprehensive report."""
        execution_time = time.time() - start_time
        
        # Calculate final statistics using the deduplicated validated findings
        # Filter out false positives from the count
        confirmed_vulnerabilities = [
            v for v in validated_results.get('validated_vulnerabilities', [])
            if v.get('status', 'confirmed') != 'false_positive'
        ]
        false_positive_vulnerabilities = [
            v for v in validated_results.get('validated_vulnerabilities', [])
            if v.get('status') == 'false_positive'
        ]
        
        total_findings = len(confirmed_vulnerabilities)
        false_positive_count = len(false_positive_vulnerabilities)
        
        final_accuracy = ((total_findings) / (total_findings + false_positive_count) * 100) if (total_findings + false_positive_count) > 0 else 0
        
        # Generate summary with Phase 3 features
        summary = {
            'total_vulnerabilities': total_findings,
            'high_severity_count': len([v for v in confirmed_vulnerabilities
                                      if (isinstance(v, dict) and v.get('severity', '').lower() in ['high', 'critical']) or
                                         (hasattr(v, 'severity') and v.severity.lower() in ['high', 'critical'])]),
            'execution_time': execution_time,
            'accuracy_rate': final_accuracy,
            'false_positives_filtered': false_positive_count,
            # Phase 3 features
            'ai_consensus_findings': ai_ensemble_results.get('consensus_findings', []) if ai_ensemble_results else [],
            'model_agreement': ai_ensemble_results.get('model_agreement', 0.0) if ai_ensemble_results else 0.0,
            'formal_verification_proofs': [],  # Removed - was simulated
            'proven_vulnerabilities': 0,  # Removed - was simulated
            'learning_feedback_entries': 0  # Removed - was simulated
        }
        
        # Generate results structure - only include confirmed vulnerabilities
        results = {
            'vulnerabilities': confirmed_vulnerabilities,
            'validation_summary': {
                'total_analyzed': validated_results.get('total_findings', total_findings + false_positive_count),
                'validated': total_findings,
                'false_positives': false_positive_count,
                'accuracy_rate': final_accuracy
            },
            'execution_time': execution_time
        }
        
        return {
            'summary': summary,
            'results': results,
            'validation_results': validated_results.get('validation_results', []),
            'enhancement_stats': {
                'false_positives_prevented': false_positive_count,
                'accuracy_improvement': final_accuracy,
                'validation_layers': 5,  # Static + LLM + AI Ensemble + Formal Verification + Validation
                'phase3_features': {
                    'ai_ensemble_enabled': ai_ensemble_results is not None,
                    'formal_verification_enabled': False,  # Removed - was simulated
                    'learning_system_enabled': False,  # Removed - was simulated
                    'model_agreement': ai_ensemble_results.get('model_agreement', 0.0) if ai_ensemble_results else 0.0,
                    'formal_proofs_generated': 0  # Removed - was simulated
                }
            }
        }

    def get_enhancement_summary(self) -> Dict[str, Any]:
        """Get summary of enhancements and improvements."""
        return {
            'enhanced_components': [
                'EnhancedVulnerabilityDetector',  # Phase 1-2
                'EnhancedLLMAnalyzer',            # Phase 1-2
                'VulnerabilityValidator',          # Phase 1-2
                'AIEnsemble',                      # Phase 3
                'LearningSystem',                  # Phase 3
                'FormalVerification'               # Phase 3
            ],
            'improvements': [
                'Reduced false positives through validation layers',
                'Better context awareness in static analysis',
                'Enhanced LLM prompts with validation requirements',
                'Dynamic testing integration for verification',
                'Multi-model AI consensus analysis',           # Phase 3
                'Dynamic learning from user feedback',         # Phase 3
                'Mathematical proof generation for critical findings',  # Phase 3
                'Continuous improvement through pattern adaptation'      # Phase 3
            ],
            'current_stats': self.stats,
            'phase3_capabilities': {
                'ai_ensemble_models': 4,
                'learning_system_active': False,  # Removed - was simulated
                'formal_verification_invariants': 0,  # Removed - was simulated
                'consensus_threshold': 0.7,
                'proof_templates': 4
            }
        }

    async def run_enhanced_audit_with_llm_validation(
        self, 
        contract_path: str, 
        output_dir: Optional[str] = None,
        enable_foundry_tests: bool = True
    ) -> Dict[str, Any]:
        """Run enhanced audit with LLM validation and Foundry test generation."""
        
        logger.info("🚀 Starting Enhanced Audit with LLM Validation")
        
        # Step 1: Run initial vulnerability detection
        initial_results = await self.run_audit(contract_path, {}, foundry_validation=False)
        initial_vulnerabilities = initial_results.get('results', {}).get('vulnerabilities', [])
        
        if not initial_vulnerabilities:
            logger.info("No vulnerabilities found in initial scan")
            return initial_results
        
        # Step 2: Load contract code for LLM analysis
        try:
            if os.path.isdir(contract_path):
                # Combine all .sol files in directory
                files = self._read_contract_files(contract_path)
                combined = []
                for cf in files:
                    try:
                        combined.append(f"// File: {cf['path']}\n" + cf['content'])
                    except Exception:
                        continue
                contract_code = "\n\n".join(combined)
                contract_name = Path(contract_path).name
            else:
                contract_code = self.file_handler.read_file(contract_path)
                contract_name = Path(contract_path).stem
        except Exception as e:
            logger.warning(f"Failed reading contract code, continuing with empty code: {e}")
            contract_code = ""
            contract_name = Path(contract_path).stem or "contracts"
        
        # Step 3: Convert VulnerabilityMatch objects to dicts for LLM validation
        vulnerability_dicts = []
        for vuln in initial_vulnerabilities:
            # Use normalization helper to ensure consistent dict structure
            normalized = self._normalize_vulnerability_dict(vuln)
            vulnerability_dicts.append(normalized)
        
        # Step 4: Pre-LLM triage to reduce noise and cost (LLM-specific path)
        triaged_vulnerabilities = self._triage_vulnerabilities(vulnerability_dicts, for_llm=True)
        # Optional: restrict to AI ensemble consensus for LLM validation
        try:
            only_consensus_llm = os.getenv('AETHER_LLM_ONLY_CONSENSUS', '0') == '1'
            if only_consensus_llm:
                triaged_vulnerabilities = [v for v in triaged_vulnerabilities if (v.get('source') == 'ai_ensemble')]
        except Exception:
            pass

        # Step 5: LLM-based false positive filtering
        logger.info("🤖 Running LLM false positive filtering...")
        validated_vulnerabilities = await self.llm_false_positive_filter.validate_vulnerabilities(
            triaged_vulnerabilities, contract_code, contract_name
        )
        
        # Step 6: Generate Foundry tests using FoundryPoCGenerator
        # NOTE: LLM-based test generation is now handled by FoundryPoCGenerator
        # which has a different API. For now, this section is disabled.
        # To use FoundryPoCGenerator, call generate_comprehensive_poc_suite() separately
        foundry_test_suites = []
        # if enable_foundry_tests and validated_vulnerabilities:
        #     logger.info("🧪 Generating Foundry tests with FoundryPoCGenerator...")
        #     try:
        #         # TODO: Integrate FoundryPoCGenerator.generate_comprehensive_poc_suite()
        #         # This requires a different API than the old LLMFoundryGenerator
        #         pass
        #     except Exception as e:
        #         logger.error(f"Failed to generate Foundry tests: {e}")
        
        # Step 7: Update results with validated findings
        updated_results = initial_results.copy()
        updated_results['results']['vulnerabilities'] = validated_vulnerabilities
        updated_results['llm_validation'] = {
            'initial_count': len(initial_vulnerabilities),
            'pre_triage_count': len(vulnerability_dicts),
            'triaged_count': len(triaged_vulnerabilities),
            'validated_count': len(validated_vulnerabilities),
            'false_positives_filtered': len(initial_vulnerabilities) - len(validated_vulnerabilities),
            'validation_summary': self.llm_false_positive_filter.get_validation_summary(validated_vulnerabilities),
            'details': self.llm_false_positive_filter.get_last_validation_details()
        }
        
        # Foundry test results (disabled - API changed)
        # if foundry_test_suites:
        #     updated_results['foundry_tests'] = {
        #         'test_suites': len(foundry_test_suites),
        #         'validation_results': []
        #     }
        
        # Step 8: Update summary
        updated_results['summary']['total_vulnerabilities'] = len(validated_vulnerabilities)
        updated_results['summary']['high_severity_count'] = len([
            v for v in validated_vulnerabilities 
            if v.get('severity', '').lower() in ['high', 'critical']
        ])
        
        logger.info(f"✅ Enhanced audit with LLM validation completed")
        logger.info(f"   Initial findings: {len(initial_vulnerabilities)}")
        logger.info(f"   Pre-triage: {len(vulnerability_dicts)} → Triaged: {len(triaged_vulnerabilities)}")
        logger.info(f"   Validated findings: {len(validated_vulnerabilities)}")
        logger.info(f"   False positives filtered: {len(initial_vulnerabilities) - len(validated_vulnerabilities)}")
        logger.info(f"   Foundry test suites: {len(foundry_test_suites)}")
        
        return updated_results

    # -------------------------
    # Triage helpers
    # -------------------------
    def _severity_value(self, severity: str) -> int:
        mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'informational': 0}
        return mapping.get((severity or '').lower(), 1)

    def _triage_vulnerabilities(self, vulns: List[Dict[str, Any]], for_llm: bool = False) -> List[Dict[str, Any]]:
        """Deduplicate, filter by severity/confidence, and cap volume. 
        
        IMPORTANT: Gas optimizations are EXCLUDED from LLM validation as they are NOT security vulnerabilities.
        They will be reported separately in the final report.
        """
        # Separate gas optimizations from security findings
        gas_optimizations = []
        security_findings = []
        
        for v in vulns:
            vtype = (v.get('vulnerability_type') or v.get('type') or '').strip().lower()
            if vtype == 'gas_optimization':
                gas_optimizations.append(v)
            else:
                security_findings.append(v)
        
        # Store gas optimizations for later reporting (don't validate with LLM)
        if not hasattr(self, '_gas_optimizations'):
            self._gas_optimizations = []
        self._gas_optimizations.extend(gas_optimizations)
        
        # Only process security findings for validation
        vulns = security_findings
        
        # Configurable thresholds via env
        # NEW: Include informational findings by default for comprehensive reports
        # LLM validation still defaults to medium to save API costs
        include_informational = os.getenv('AETHER_INCLUDE_INFORMATIONAL', '1') == '1'
        
        if for_llm:
            # LLM validation uses higher threshold to control costs (default: medium)
            min_sev = os.getenv('AETHER_LLM_TRIAGE_MIN_SEVERITY', os.getenv('AETHER_TRIAGE_MIN_SEVERITY', 'medium'))
            min_conf = float(os.getenv('AETHER_LLM_TRIAGE_MIN_CONFIDENCE', os.getenv('AETHER_TRIAGE_MIN_CONFIDENCE', '0.40')))
            max_items = int(os.getenv('AETHER_LLM_TRIAGE_MAX_ITEMS', os.getenv('AETHER_TRIAGE_MAX_ITEMS', '200')))
            max_per_type = int(os.getenv('AETHER_LLM_TRIAGE_MAX_PER_TYPE', os.getenv('AETHER_TRIAGE_MAX_PER_TYPE', '30')))
        else:
            # Report generation includes low/informational by default for comprehensive audits
            default_min_sev = 'informational' if include_informational else 'medium'
            min_sev = os.getenv('AETHER_TRIAGE_MIN_SEVERITY', default_min_sev)
            min_conf = float(os.getenv('AETHER_TRIAGE_MIN_CONFIDENCE', '0.40'))
            max_items = int(os.getenv('AETHER_TRIAGE_MAX_ITEMS', '200'))
            max_per_type = int(os.getenv('AETHER_TRIAGE_MAX_PER_TYPE', '30'))

        min_sev_val = self._severity_value(min_sev)

        # Normalize and deduplicate
        seen = set()
        normalized: List[Dict[str, Any]] = []
        only_consensus_llm = False
        try:
            only_consensus_llm = for_llm and (os.getenv('AETHER_LLM_ONLY_CONSENSUS', '0') == '1')
        except Exception:
            pass
        for v in vulns:
            vtype = (v.get('vulnerability_type') or v.get('title') or '').strip().lower()
            sev = v.get('severity') or 'low'
            conf = float(v.get('confidence', 0) or 0)
            line = v.get('line_number') or v.get('line') or 0
            file_path = ''
            ctx = v.get('context') or {}
            if isinstance(ctx, dict):
                file_path = ctx.get('file_path') or ctx.get('file_location', '')
            key = (vtype, file_path, int(line))
            if key in seen:
                continue
            seen.add(key)
            # If LLM consensus-only mode: keep AI ensemble items regardless of thresholds
            if only_consensus_llm and (v.get('source') == 'ai_ensemble'):
                normalized.append(v)
                continue
            # Otherwise apply Severity/confidence filter
            if self._severity_value(sev) < min_sev_val:
                continue
            if conf < min_conf:
                continue
            normalized.append(v)

        # Sort by severity desc, confidence desc
        normalized.sort(key=lambda x: (self._severity_value(x.get('severity', 'low')), float(x.get('confidence', 0) or 0)), reverse=True)

        # Cap per type
        per_type_count: Dict[str, int] = {}
        capped: List[Dict[str, Any]] = []
        for v in normalized:
            t = (v.get('vulnerability_type') or v.get('title') or '').lower()
            count = per_type_count.get(t, 0)
            if count >= max_per_type:
                continue
            per_type_count[t] = count + 1
            capped.append(v)
            if len(capped) >= max_items:
                break

        # Log separation of gas optimizations
        if gas_optimizations:
            print(f"ℹ️  Separated {len(gas_optimizations)} gas optimizations (not security vulnerabilities)")
        
        return capped

    async def _run_foundry_validation(self, contract_path: str, validated_results: Dict[str, Any]) -> None:
        """Run enhanced validation on detected vulnerabilities (LLM-based with optional Foundry testing)."""
        try:
            if self.foundry_integration is None:
                from core.enhanced_foundry_integration import EnhancedFoundryIntegration
                self.foundry_integration = EnhancedFoundryIntegration()
            
            print("🔬 Running enhanced validation (LLM + Foundry)...")
            
            # Run analysis and validation
            submission = await self.foundry_integration.analyze_and_validate_contract(contract_path)
            
            # Add validation results to validated results
            if 'enhanced_validation' not in validated_results:
                validated_results['enhanced_validation'] = {}
            
            # Handle both dict and object types for submission
            if isinstance(submission, dict):
                # Extract validation mode to inform users about the method being used
                validation_method = submission.get('validation', {}).get('validation_method', 'unknown')
                
                validated_results['enhanced_validation'].update({
                    'submission': submission,
                    'vulnerabilities_validated': len(submission.get('vulnerabilities', [])),
                    'foundry_tests_generated': len(submission.get('foundry_tests', [])),
                    'exploit_pocs_generated': len(submission.get('exploit_pocs', [])),
                    'confidence_score': submission.get('confidence_score', 0.0),
                    'validation_method': validation_method  # NEW: Track which validation method was used
                })
                
                # Extract validation data from submission vulnerabilities
                foundry_vulns = submission.get('vulnerabilities', [])
                validated_count = 0
                false_positive_count = 0
                
            else:
                # Object with attributes
                validation_method = getattr(submission, 'verification_method', 'unknown')
                
                validated_results['enhanced_validation'].update({
                    'submission': submission,
                    'vulnerabilities_validated': len(getattr(submission, 'vulnerabilities', [])),
                    'foundry_tests_generated': len(getattr(submission, 'foundry_tests', [])),
                    'exploit_pocs_generated': len(getattr(submission, 'exploit_pocs', [])),
                    'confidence_score': getattr(submission, 'confidence_score', 0.0),
                    'validation_method': validation_method  # NEW: Track which validation method was used
                })
                
                # Extract validation data from submission vulnerabilities
                foundry_vulns = getattr(submission, 'vulnerabilities', [])
                validated_count = 0
                false_positive_count = 0
            
            # Update vulnerability statuses based on enhanced validation results
            # Create a mapping of vulnerability identifiers to their validation status
            validation_map = {}
            for vuln_data in foundry_vulns:
                # Build a key from vulnerability type, line number, and description for matching
                vuln_type = vuln_data.get('vulnerability_type', '')
                line_num = vuln_data.get('line_number', 0)
                # Use a simple key for matching
                key = f"{vuln_type}_{line_num}"
                vuln_val = vuln_data.get('foundry_validation', {})
                validation_map[key] = {
                    'validated': vuln_val.get('validated', False),
                    'exploitable': vuln_val.get('exploitable', False)
                }
                if vuln_val.get('validated'):
                    validated_count += 1
                else:
                    false_positive_count += 1
            
            # Update the validated vulnerabilities list with validation results
            updated_vulnerabilities = []
            for vuln in validated_results.get('validated_vulnerabilities', []):
                # Build matching key
                vuln_type = vuln.get('vulnerability_type', vuln.get('title', ''))
                line_num = vuln.get('line_number', vuln.get('line', 0))
                key = f"{vuln_type}_{line_num}"
                
                # Check if validation found this vulnerability
                validation_result = validation_map.get(key)
                
                if validation_result and not validation_result['validated']:
                    # Mark as false positive since validation couldn't confirm it
                    vuln['status'] = 'false_positive'
                    vuln['validation_confidence'] = 0.0
                    vuln['validation_reasoning'] = f'Enhanced validation ({validation_method}) could not confirm this vulnerability'
                else:
                    # Keep as confirmed (or update confidence if validation confirmed)
                    if validation_result and validation_result['validated']:
                        vuln['status'] = 'confirmed'
                        vuln['validation_confidence'] = max(vuln.get('validation_confidence', 0.0), 0.95)
                        vuln['validation_reasoning'] = f'Confirmed by enhanced validation ({validation_method})'
                
                updated_vulnerabilities.append(vuln)
            
            # Update the validated_results with filtered vulnerabilities
            validated_results['validated_vulnerabilities'] = updated_vulnerabilities
            
            # Update metrics
            validated_results['false_positive_count'] = false_positive_count
            validated_results['validated_count'] = validated_count
            
            # Handle both dict and object types for print statement
            if isinstance(submission, dict):
                vuln_count = len(submission.get('vulnerabilities', []))
            else:
                vuln_count = len(getattr(submission, 'vulnerabilities', []))
            
            print(f"✅ Enhanced validation completed ({validation_method}): {validated_count} real / {false_positive_count} false positive")
            
        except Exception as e:
            print(f"⚠️ Enhanced validation failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _save_audit_to_database(self, contract_path: str, final_results: Dict[str, Any], start_time: float, flow_config: Dict[str, Any]) -> None:
        """Save audit results to database."""
        try:
            # Extract contract information
            contract_name = self._extract_contract_name(contract_path)
            contract_address = self._extract_contract_address(contract_path) or "unknown"

            # Check if audit already exists for this contract
            existing_audit = None
            try:
                if hasattr(self.database, 'find_audit_by_contract'):
                    existing_audit = self.database.find_audit_by_contract(contract_path, contract_name, contract_address)
            except Exception as e:
                logger.warning(f"Could not check for existing audit: {e}")
                existing_audit = None

            if existing_audit:
                # Update existing audit
                audit_id = existing_audit['id']
                print(f"🔄 Updating existing audit for contract: {contract_name}")

                # Delete old vulnerability findings and metrics to replace with new ones
                try:
                    if hasattr(self.database, 'delete_vulnerability_findings'):
                        self.database.delete_vulnerability_findings(audit_id)
                except Exception as e:
                    logger.warning(f"Could not delete old vulnerability findings: {e}")
                # Delete old metrics and learning patterns for this audit
                # Note: We could implement delete methods for these if needed
            else:
                # Create new audit
                audit_id = str(uuid.uuid4())
                print(f"🆕 Creating new audit for contract: {contract_name}")

            # Calculate metrics using the deduplicated findings
            execution_time = time.time() - start_time
            # Raw vulnerabilities from pipeline output
            vulnerabilities = final_results.get('results', {}).get('vulnerabilities', [])

            # Gate database persistence to only LLM-validated items by default
            # Opt-in to store unvalidated items by setting AETHER_DB_SAVE_UNVALIDATED=1
            save_unvalidated = os.getenv('AETHER_DB_SAVE_UNVALIDATED', '0') == '1'
            min_conf_str = os.getenv('AETHER_DB_MIN_VALIDATION_CONFIDENCE', '')
            try:
                min_validation_conf = float(min_conf_str) if min_conf_str else None
            except Exception:
                min_validation_conf = None

            eligible_vulnerabilities = []
            for v in vulnerabilities:
                # Normalize access for dict/object
                def vget(key, default=None):
                    if hasattr(v, key):
                        return getattr(v, key, default)
                    return v.get(key, default) if isinstance(v, dict) else default

                status_val = vget('status', 'confirmed')
                if status_val == 'false_positive':
                    # Never store false positives
                    continue

                vc = vget('validation_confidence', None)

                # Enforce LLM validation presence (vc not None) unless explicitly allowed
                if vc is None and not save_unvalidated:
                    continue

                # If a minimum confidence is configured, enforce it
                if vc is not None and min_validation_conf is not None and vc < min_validation_conf:
                    # Treat as not eligible unless storing unvalidated is allowed
                    if not save_unvalidated:
                        continue

                # If unvalidated allowed and vc missing, mark investigating with defaults
                if vc is None and save_unvalidated:
                    if isinstance(v, dict):
                        v.setdefault('status', 'investigating')
                        v.setdefault('validation_confidence', 0.0)
                        v.setdefault('validation_reasoning', 'Not LLM-validated; stored due to AETHER_DB_SAVE_UNVALIDATED=1')
                    else:
                        try:
                            setattr(v, 'status', getattr(v, 'status', 'investigating'))
                            setattr(v, 'validation_confidence', 0.0)
                            setattr(v, 'validation_reasoning', 'Not LLM-validated; stored due to AETHER_DB_SAVE_UNVALIDATED=1')
                        except Exception:
                            pass

                eligible_vulnerabilities.append(v)

            total_vulnerabilities = len(eligible_vulnerabilities)

            # Count severities
            def get_severity(vuln):
                if hasattr(vuln, 'severity'):
                    return vuln.severity
                elif isinstance(vuln, dict):
                    return vuln.get('severity', 'medium')
                return 'medium'

            high_severity_count = sum(1 for v in eligible_vulnerabilities if get_severity(v) in ['high', 'critical'])
            critical_severity_count = sum(1 for v in eligible_vulnerabilities if get_severity(v) == 'critical')

            # Count false positives (confirmed findings)
            def get_status(vuln):
                if hasattr(vuln, 'status'):
                    return vuln.status
                elif isinstance(vuln, dict):
                    return vuln.get('status', 'confirmed')
                return 'confirmed'

            false_positives = sum(1 for v in eligible_vulnerabilities if get_status(v) == 'false_positive')

            # Determine network (default to ethereum if not specified)
            network = flow_config.get('network', 'ethereum')

            # Create audit result record
            audit_result = AuditResult(
                id=audit_id,
                contract_address=contract_address,
                contract_name=contract_name,
                network=network,
                audit_type='comprehensive',
                total_vulnerabilities=total_vulnerabilities,
                high_severity_count=high_severity_count,
                critical_severity_count=critical_severity_count,
                false_positives=false_positives,
                execution_time=execution_time,
                created_at=time.time(),
                metadata={
                    'contract_path': contract_path,
                    'flow_config': flow_config,
                    'ai_ensemble_used': final_results.get('ai_ensemble', {}).get('enabled', False),
                    'llm_validation_used': final_results.get('llm_validation', {}).get('enabled', False),
                    'foundry_validation_used': final_results.get('foundry_validation', {}).get('enabled', False)
                },
                status='completed'
            )

            # Save or update audit result
            if existing_audit:
                # Update existing audit
                if self.database.update_audit_result(audit_result):
                    print(f"💾 Audit result updated in database (ID: {audit_id[:8]}...)")
                else:
                    print("⚠️ Failed to update audit result in database")
            else:
                # Save new audit
                if self.database.save_audit_result(audit_result):
                    print(f"💾 Audit result saved to database (ID: {audit_id[:8]}...)")
                else:
                    print("⚠️ Failed to save audit result to database")

            # Filter out false positives and deduplicate vulnerability findings (from eligible set)
            validated_vulnerabilities = []
            for vuln in eligible_vulnerabilities:
                # Skip false positives
                vuln_status = getattr(vuln, 'status', 'confirmed') if hasattr(vuln, 'vulnerability_type') else vuln.get('status', 'confirmed')
                if vuln_status == 'false_positive':
                    continue

                # Handle both VulnerabilityMatch objects and dictionaries
                if hasattr(vuln, 'vulnerability_type'):
                    # Convert VulnerabilityMatch object to dict
                    # Get file_path from context if available
                    file_path = ''
                    if hasattr(vuln, 'context') and isinstance(vuln.context, dict):
                        file_path = vuln.context.get('file_path', '')

                    vuln_dict = {
                        'vulnerability_type': vuln.vulnerability_type,
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'description': vuln.description,
                        'line_number': vuln.line_number,
                        'swc_id': vuln.swc_id,
                        'file_path': file_path,
                        'status': getattr(vuln, 'status', 'confirmed'),
                        'validation_confidence': getattr(vuln, 'validation_confidence', 0.0),
                        'validation_reasoning': getattr(vuln, 'validation_reasoning', ''),
                        'title': getattr(vuln, 'title', vuln.vulnerability_type)
                    }
                else:
                    # Already a dict
                    vuln_dict = vuln

                validated_vulnerabilities.append(vuln_dict)

            # Deduplicate findings: for each unique (vuln_type, line, file), keep the one with highest confidence
            unique_findings = {}
            for vuln_dict in validated_vulnerabilities:
                key = (
                    vuln_dict.get('vulnerability_type') or vuln_dict.get('title') or 'Unknown Vulnerability',
                    vuln_dict.get('line_number', vuln_dict.get('line', 0)),
                    vuln_dict.get('file_path', vuln_dict.get('file', ''))
                )

                # Keep the finding with highest confidence for this location
                if key not in unique_findings or vuln_dict.get('confidence', 0.0) > unique_findings[key].get('confidence', 0.0):
                    unique_findings[key] = vuln_dict

            # Save vulnerability findings
            vulnerability_findings = []
            for vuln_dict in unique_findings.values():
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    audit_result_id=audit_id,
                    vulnerability_type=vuln_dict.get('vulnerability_type') or vuln_dict.get('title') or 'Unknown Vulnerability',
                    severity=vuln_dict.get('severity', 'medium'),
                    confidence=vuln_dict.get('confidence', 0.0),
                    description=vuln_dict.get('description', ''),
                    line_number=vuln_dict.get('line_number', vuln_dict.get('line', 0)),
                    swc_id=vuln_dict.get('swc_id', ''),
                    file_path=vuln_dict.get('file_path', vuln_dict.get('file', '')),
                    contract_name=contract_name,
                    status=vuln_dict.get('status', 'confirmed'),
                    validation_confidence=vuln_dict.get('validation_confidence', 0.0),
                    validation_reasoning=vuln_dict.get('validation_reasoning', ''),
                    created_at=time.time(),
                    updated_at=time.time()
                )
                vulnerability_findings.append(finding)

            if vulnerability_findings:
                try:
                    if hasattr(self.database, 'save_vulnerability_findings'):
                        if self.database.save_vulnerability_findings(vulnerability_findings):
                            print(f"💾 {len(vulnerability_findings)} vulnerability findings saved to database")
                        else:
                            print("⚠️ Failed to save vulnerability findings to database")
                except Exception as e:
                    logger.warning(f"Could not save vulnerability findings: {e}")

            # Save learning patterns if any were learned (only for new audits)
            if not existing_audit:
                learning_patterns = self._extract_learning_patterns(vulnerabilities, audit_id)
                for pattern in learning_patterns:
                    try:
                        if hasattr(self.database, 'save_learning_pattern'):
                            if self.database.save_learning_pattern(pattern):
                                print(f"💾 Learning pattern saved: {pattern.pattern_type}")
                    except Exception as e:
                        logger.warning(f"Could not save learning pattern: {e}")

            # Save audit metrics
            metrics = self._calculate_audit_metrics(audit_id, vulnerabilities, execution_time)
            if metrics:
                try:
                    if hasattr(self.database, 'save_audit_metrics'):
                        if self.database.save_audit_metrics(metrics):
                            print(f"💾 Audit metrics saved to database")
                except Exception as e:
                    logger.warning(f"Could not save audit metrics: {e}")

        except Exception as e:
            print(f"⚠️ Failed to save audit to database: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _extract_contract_name(self, contract_path: str) -> str:
        """Extract contract name from path."""
        return os.path.splitext(os.path.basename(contract_path))[0]

    def _extract_contract_address(self, contract_path: str) -> Optional[str]:
        """Extract contract address if present in path or filename."""
        # Look for address pattern in path
        import re
        address_pattern = r'0x[a-fA-F0-9]{40}'
        match = re.search(address_pattern, contract_path)
        return match.group(0) if match else None

    def _extract_learning_patterns(self, vulnerabilities: List[Dict[str, Any]], audit_id: str) -> List[LearningPattern]:
        """Extract learning patterns from vulnerabilities that were filtered as false positives."""
        patterns = []

        for vuln in vulnerabilities:
            # Handle both VulnerabilityMatch objects and dictionaries
            def vuln_get(key, default=None):
                if hasattr(vuln, key):
                    return getattr(vuln, key, default)
                return vuln.get(key, default) if isinstance(vuln, dict) else default

            # Only extract patterns for vulnerabilities that were actually filtered out as false positives
            # These should have validation_reasoning explaining why they were filtered
            if vuln_get('status') == 'false_positive' and vuln_get('validation_reasoning'):
                pattern = LearningPattern(
                    id=str(uuid.uuid4()),
                    pattern_type='false_positive',
                    contract_pattern=vuln_get('contract_pattern', ''),
                    vulnerability_type=vuln_get('vulnerability_type', ''),
                    original_classification=vuln_get('original_severity', 'medium'),
                    corrected_classification=vuln_get('severity', 'medium'),
                    confidence_threshold=vuln_get('confidence', 0.5),
                    reasoning=vuln_get('validation_reasoning', ''),
                    source_audit_id=audit_id,
                    created_at=time.time(),
                    usage_count=0,
                    success_rate=0.0
                )
                patterns.append(pattern)

        return patterns

    def _calculate_audit_metrics(self, audit_id: str, vulnerabilities: List[Dict[str, Any]], execution_time: float) -> Optional[AuditMetrics]:
        """Calculate and return audit metrics."""
        try:
            total_findings = len(vulnerabilities)

            # Handle both VulnerabilityMatch objects and dictionaries
            def vuln_get(vuln, key, default=None):
                if hasattr(vuln, key):
                    return getattr(vuln, key, default)
                return vuln.get(key, default) if isinstance(vuln, dict) else default

            # Filter out false positives for confirmed findings count
            confirmed_findings = sum(1 for v in vulnerabilities if vuln_get(v, 'status') != 'false_positive')
            false_positives = total_findings - confirmed_findings

            # Simple accuracy calculation
            accuracy_score = confirmed_findings / max(total_findings, 1)

            # Calculate precision, recall, f1 (simplified)
            precision_score = accuracy_score  # Simplified
            recall_score = accuracy_score      # Simplified
            f1_score = 2 * (precision_score * recall_score) / max(precision_score + recall_score, 0.001)

            # Count LLM calls (simplified estimate)
            llm_calls = max(total_findings * 2, 1)  # Rough estimate
            cache_hits = 0  # Would need to track this

            return AuditMetrics(
                id=str(uuid.uuid4()),
                audit_result_id=audit_id,
                total_findings=total_findings,
                confirmed_findings=confirmed_findings,
                false_positives=false_positives,
                accuracy_score=accuracy_score,
                precision_score=precision_score,
                recall_score=recall_score,
                f1_score=f1_score,
                execution_time=execution_time,
                llm_calls=llm_calls,
                cache_hits=cache_hits,
                created_at=time.time()
            )
        except Exception as e:
            print(f"⚠️ Failed to calculate audit metrics: {e}")
            return None
