"""
Main CLI implementation for AetherAudit + AetherFuzz.
"""

import warnings

# Suppress pkg_resources deprecation warning from slither
warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources is deprecated.*")

import asyncio
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml

from core.audit_engine import AetherAuditEngine
from core.enhanced_audit_engine import EnhancedAetherAuditEngine
from core.fuzz_engine import AetherFuzzEngine
from core.flow_executor import FlowExecutor
from core.report_generator import ReportGenerator
from core.etherscan_fetcher import EtherscanFetcher
from core.basescan_fetcher import BasescanFetcher
from core.config_manager import ConfigManager
from utils.file_handler import FileHandler
from core.foundry_poc_generator import FoundryPoCGenerator
from core.github_auditor import GitHubAuditor, AuditOptions as GitHubAuditOptions
from core.audit_result_formatter import AuditResultFormatter
from core.graceful_shutdown import register_database
from core.exploit_tester import ExploitTester


# Optional monkeypatch targets for tests. These placeholders allow tests to patch
# Slither and AetherDatabase on this module path (cli.main.Slither / .AetherDatabase).
Slither = None  # type: ignore
AetherDatabase = None  # type: ignore


class AetherCLI:
    """Main CLI class for AetherAudit + AetherFuzz."""

    def __init__(self):
        self.version = "1.0.0"
        self.file_handler = FileHandler()
        self.config_manager = ConfigManager()
        self.etherscan_fetcher = EtherscanFetcher(self.config_manager)
        self.basescan_fetcher = BasescanFetcher(self.config_manager)
        self.exploit_tester = ExploitTester()

    def show_version(self):
        """Display version information."""
        print(f"AetherAudit + AetherFuzz v{self.version}")

    def _get_openai_api_key(self) -> Optional[str]:
        """Get OpenAI API key from environment or config."""
        # First try environment variable
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            return api_key
        
        # Try config manager for stored key
        try:
            if getattr(self.config_manager.config, 'openai_api_key', ''):
                api_key = self.config_manager.config.openai_api_key
                os.environ['OPENAI_API_KEY'] = api_key
                return api_key
        except Exception:
            pass
        
        return None

    def _handle_etherscan_address(self, address: str, interactive_scope: bool = False) -> Optional[Union[str, Dict[str, Any]]]:
        """Handle Etherscan address by fetching contract source code.
        
        Returns:
            - str: Path to contract file/directory if single contract or no selection needed
            - Dict: {'path': str, 'contracts': List[Dict]} if multiple contracts found and selection needed
        """
        if not self.etherscan_fetcher.is_etherscan_address(address):
            return None

        print(f"🔍 Detected Etherscan address: {address}")
        
        # Check if API key is configured
        if not self.config_manager.config.etherscan_api_key:
            print("❌ Etherscan API key not configured.")
            print("   Configure it with: python main.py config --set-etherscan-key YOUR_KEY")
            return None

        # Fetch contract info first
        contract_info = self.etherscan_fetcher.get_contract_info(address)
        if not contract_info.get('success'):
            print(f"❌ Error fetching contract info: {contract_info.get('error')}")
            return None

        if not contract_info.get('is_verified'):
            print("❌ Contract is not verified on Etherscan.")
            print("   Only verified contracts can be audited.")
            return None

        print(f"✅ Contract verified: {contract_info['contract_name']}")
        
        # Fetch and save contract source code
        success, result, contract_data = self.etherscan_fetcher.fetch_and_save_contract(address)
        
        if not success:
            print(f"❌ Error fetching contract source: {result}")
            return None

        # Store contract metadata for later use in report generation
        self._etherscan_contract_metadata = {
            'contract_name': contract_data.get('contract_name', 'Unknown Contract'),
            'contract_address': contract_data.get('address', address),
            'network': self.etherscan_fetcher.SUPPORTED_NETWORKS[contract_data.get('network', 'ethereum')]['name']
        }
        
        print(f"📝 Stored contract metadata: {self._etherscan_contract_metadata['contract_name']} at {self._etherscan_contract_metadata['contract_address']}")

        print(f"✅ Contract source saved to: {result}")
        
        # Check if result is a directory (multi-file contract) or single file
        from pathlib import Path
        result_path = Path(result)
        
        if result_path.is_dir():
            # Multi-file contract - discover all .sol files
            discovered_contracts = []
            
            # Patterns to identify library/dependency contracts (should be filtered out)
            library_patterns = [
                'openzeppelin',
                'lib/',
                'interfaces/',
                'utils/',
                'libraries/',
                'vendor/',
                'test/',
                'tests/',
                'mock',
                'Mock',
                'Test',
                'test_',
                'Test_'
            ]
            
            # Track seen contracts to avoid duplicates
            # Use dict to store best path for each contract (prefer contracts/ directory)
            contract_map = {}  # contract_name -> contract_info
            
            for sol_file in result_path.rglob("*.sol"):
                rel_path = str(sol_file.relative_to(result_path))
                file_path_str = str(sol_file)
                
                # Skip library/dependency contracts
                is_library = any(pattern.lower() in file_path_str.lower() or pattern.lower() in rel_path.lower() 
                               for pattern in library_patterns)
                
                # Skip if it's a library file
                if is_library:
                    continue
                
                # Extract contract name and check if it's a library/interface
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='ignore')
                    import re
                    
                    # Check if it's an interface or library (skip these)
                    if re.search(r'\b(interface|library)\s+\w+', content, re.IGNORECASE):
                        continue
                    
                    # Check if file contains only library/interface definitions
                    contract_declarations = re.findall(r'\b(contract|interface|library|abstract\s+contract)\s+(\w+)', content, re.IGNORECASE)
                    if contract_declarations:
                        # If all declarations are interfaces/libraries, skip
                        if all(decl[0].lower() in ['interface', 'library'] for decl in contract_declarations):
                            continue
                    
                    contract_match = re.search(r'contract\s+(\w+)', content)
                    contract_name = contract_match.group(1) if contract_match else sol_file.stem
                    
                    # Create a unique key based on contract name to avoid duplicates
                    contract_key = contract_name.lower()
                    
                    # Prefer contracts in contracts/ directory over flattened ones
                    is_in_contracts_dir = 'contracts/' in rel_path
                    existing = contract_map.get(contract_key)
                    
                    if existing:
                        # If we already have one, prefer the one in contracts/ directory
                        existing_in_contracts = 'contracts/' in existing['relative_path']
                        if is_in_contracts_dir and not existing_in_contracts:
                            # Replace flattened with contracts/ version
                            contract_map[contract_key] = {
                                'file_path': str(sol_file),
                                'contract_name': contract_name,
                                'relative_path': rel_path
                            }
                        # Otherwise keep existing (either both in contracts/ or existing is better)
                    else:
                        # First time seeing this contract
                        contract_map[contract_key] = {
                            'file_path': str(sol_file),
                            'contract_name': contract_name,
                            'relative_path': rel_path
                        }
                except:
                    contract_name = sol_file.stem
                    contract_key = contract_name.lower()
                    if contract_key not in contract_map:
                        contract_map[contract_key] = {
                            'file_path': str(sol_file),
                            'contract_name': contract_name,
                            'relative_path': rel_path
                        }
            
            # Convert map to list
            discovered_contracts = list(contract_map.values())
            
            if len(discovered_contracts) > 1 and interactive_scope:
                # Return info for contract selection
                return {
                    'path': str(result_path),
                    'contracts': discovered_contracts,
                    'is_multi_file': True
                }
            else:
                # Return directory path - will audit all contracts
                return result
        else:
            # Single file contract
            return result

    def _handle_basescan_address(self, address: str) -> Optional[str]:
        """Handle Basescan address by fetching contract source code."""
        if not self.basescan_fetcher.is_basescan_address(address):
            return None

        print(f"🔍 Detected Basescan address: {address}")
        
        # Check if API key is configured
        if not self.config_manager.config.etherscan_api_key:
            print("❌ Basescan API key not configured.")
            print("   Configure it with: python main.py config --set-etherscan-key YOUR_KEY")
            return None

        # Fetch contract info first
        contract_info = self.basescan_fetcher.get_contract_info(address)
        if not contract_info.get('success'):
            print(f"❌ Error fetching contract info: {contract_info.get('error')}")
            return None

        if not contract_info.get('is_verified'):
            print("❌ Contract is not verified on Basescan.")
            print("   Only verified contracts can be audited.")
            return None

        print(f"✅ Contract verified: {contract_info['contract_name']}")
        
        # Fetch and save contract source code
        success, result, contract_data = self.basescan_fetcher.fetch_and_save_contract(address)
        
        if not success:
            print(f"❌ Error fetching contract source: {result}")
            return None

        print(f"✅ Contract source saved to: {result}")
        return result

    def _extract_contract_name_from_results(self, results: Dict[str, Any]) -> str:
        """Extract contract name from results for better organization."""
        # Try to get contract name from various sources
        contract_name = "UnknownContract"

        # First try from reportnode data
        if 'reportnode' in results and isinstance(results['reportnode'], dict):
            reportnode_data = results['reportnode']
            vulnerabilities = reportnode_data.get('results', {}).get('vulnerabilities', [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    if hasattr(vuln, 'context') and vuln.context.get('contract_name'):
                        contract_name = vuln.context['contract_name']
                        break

        # Fallback: try from other vulnerability sources
        if contract_name == "UnknownContract":
            for key, value in results.items():
                if isinstance(value, dict) and 'vulnerabilities' in value:
                    for vuln in value['vulnerabilities']:
                        if hasattr(vuln, 'context') and vuln.context.get('contract_name'):
                            contract_name = vuln.context['contract_name']
                            break
                        elif isinstance(vuln, dict) and vuln.get('context', {}).get('contract_name'):
                            contract_name = vuln['context']['contract_name']
                            break
                    if contract_name != "UnknownContract":
                        break

        # If still unknown, try to extract from contract path or other sources
        if contract_name == "UnknownContract":
            # Try to get from contract path if available in results
            for key, value in results.items():
                if isinstance(value, dict):
                    contract_path = value.get('contract_path') or value.get('file_path')
                    if contract_path:
                        # Extract filename from path
                        filename = os.path.basename(contract_path)
                        if filename.endswith('.sol'):
                            contract_name = filename[:-4]  # Remove .sol extension
                            break

            # If still unknown, try to extract from the original contract path passed to the function
            if contract_name == "UnknownContract" and hasattr(self, '_contract_path'):
                contract_path = self._contract_path
                if contract_path:
                    filename = os.path.basename(contract_path)
                    if filename.endswith('.sol'):
                        contract_name = filename[:-4]  # Remove .sol extension

        # Clean contract name for filename use
        if contract_name != "UnknownContract":
            # Remove file extension and clean for filesystem
            contract_name = contract_name.replace('.sol', '').replace(' ', '_').replace('-', '_')
            # Ensure it's a valid filename component
            contract_name = "".join(c for c in contract_name if c.isalnum() or c in ('_', '-'))

        return contract_name

    def _transform_results_for_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Transform flow execution results into expected report structure."""
        # Get data from the most appropriate sources
        audit_data = {}
        fuzz_data = {}

        # Extract audit data from reportnode if available
        if 'reportnode' in results and isinstance(results['reportnode'], dict):
            reportnode_data = results['reportnode']
            if 'summary' in reportnode_data:
                summary = reportnode_data['summary']
                vulnerabilities = reportnode_data.get('results', {}).get('vulnerabilities', [])
                
            # Ensure vulnerabilities have proper structure for bug bounty submission
            for vuln in vulnerabilities:
                # Handle VulnerabilityMatch objects
                if hasattr(vuln, 'vulnerability_type'):
                    # Convert VulnerabilityMatch to dict-like structure
                    vuln_dict = {
                        'status': 'confirmed' if vuln.severity.lower() in ['critical', 'high'] else 'suspected',
                        'file': 'Unknown',
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.vulnerability_type.replace('_', ' ').title(),
                        'description': vuln.description,
                        'category': vuln.category,
                        'confidence': vuln.confidence
                    }
                    # Replace the object with dict
                    vulnerabilities[vulnerabilities.index(vuln)] = vuln_dict
                else:
                    # Handle dict objects
                    if not vuln.get('status'):
                        vuln['status'] = 'confirmed' if vuln.get('severity', '').lower() in ['critical', 'high'] else 'suspected'
                    if not vuln.get('file'):
                        vuln['file'] = 'Unknown'
                    if not vuln.get('line'):
                        vuln['line'] = 'Unknown'
                
                audit_data = {
                    'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
                    'high_severity_count': summary.get('high_severity_count', 0),
                    'execution_time': summary.get('execution_time', 0),
                    'vulnerabilities': vulnerabilities,
                    'ai_insights': []
                }

        # If no audit data from reportnode, try to calculate from other sources
        if not audit_data:
            all_vulnerabilities = []
            for key, value in results.items():
                if isinstance(value, dict) and 'vulnerabilities' in value:
                    all_vulnerabilities.extend(value['vulnerabilities'])

            # Ensure vulnerabilities have proper structure
            for i, vuln in enumerate(all_vulnerabilities):
                # Handle VulnerabilityMatch objects
                if hasattr(vuln, 'vulnerability_type'):
                    # Convert VulnerabilityMatch to dict-like structure
                    vuln_dict = {
                        'status': 'confirmed' if vuln.severity.lower() in ['critical', 'high'] else 'suspected',
                        'file': 'Unknown',
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.vulnerability_type.replace('_', ' ').title(),
                        'description': vuln.description,
                        'category': vuln.category,
                        'confidence': vuln.confidence
                    }
                    # Replace the object with dict
                    all_vulnerabilities[i] = vuln_dict
                else:
                    # Handle dict objects
                    if not vuln.get('status'):
                        vuln['status'] = 'confirmed' if vuln.get('severity', '').lower() in ['critical', 'high'] else 'suspected'
                    if not vuln.get('file'):
                        vuln['file'] = 'Unknown'
                    if not vuln.get('line'):
                        vuln['line'] = 'Unknown'

            audit_data = {
                'total_vulnerabilities': len(all_vulnerabilities),
                'high_severity_count': len([v for v in all_vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']]),
                'execution_time': 0,
                'vulnerabilities': all_vulnerabilities,
                'ai_insights': []
            }

        # If available, merge AI ensemble consensus findings into vulnerabilities
        try:
            consensus = (results.get('summary', {}) or {}).get('ai_consensus_findings', []) or []
            if consensus:
                merged = audit_data.get('vulnerabilities', [])
                for c in consensus:
                    line_val = c.get('line', 'Unknown')
                    if isinstance(line_val, list) and line_val:
                        try:
                            line_val = int(line_val[0])
                        except Exception:
                            line_val = line_val[0]
                    elif isinstance(line_val, str):
                        # try to parse integer if possible
                        try:
                            line_val = int(line_val.strip())
                        except Exception:
                            pass
                    merged.append({
                        'title': c.get('type', 'Unknown Vulnerability'),
                        'severity': c.get('severity', 'unknown'),
                        'confidence': c.get('confidence', 0.0),
                        'description': c.get('description', ''),
                        'file': getattr(self, '_contract_path', 'Unknown') or 'Unknown',
                        'line': line_val,
                        'swc_id': c.get('swc_id', ''),
                        'category': c.get('type', ''),
                        'source': 'ai_ensemble',
                        'consensus': True
                    })
                audit_data['vulnerabilities'] = merged
        except Exception:
            pass

        # Ensure file paths are present; if missing, default to audited contract path
        try:
            if audit_data.get('vulnerabilities'):
                for v in audit_data['vulnerabilities']:
                    if isinstance(v, dict) and (not v.get('file') or v.get('file') == 'Unknown'):
                        if hasattr(self, '_contract_path') and isinstance(self._contract_path, str) and self._contract_path:
                            v['file'] = self._contract_path
        except Exception:
            pass

        # Extract fuzz data if available
        if 'fuzz' in results and isinstance(results['fuzz'], dict):
            fuzz_data = results['fuzz']

        # Extract validation data if available
        validation_data = results.get('validation', {})

        # Build final result dictionary with Etherscan contract metadata if available
        result_dict = {
            'audit': audit_data,
            'fuzz': fuzz_data,
            'validation': validation_data
        }
        
        # Add Etherscan contract metadata at root level for report generation
        if hasattr(self, '_etherscan_contract_metadata'):
            result_dict['contract_name'] = self._etherscan_contract_metadata.get('contract_name', 'Unknown Contract')
            result_dict['contract_address'] = self._etherscan_contract_metadata.get('contract_address', '')
            result_dict['network'] = self._etherscan_contract_metadata.get('network', 'Ethereum Mainnet')
            print(f"📊 Added contract metadata to report: {result_dict['contract_name']} at {result_dict['contract_address']}")
            
        return result_dict

    async def run_generate_foundry(
        self,
        from_results: Optional[str] = None,
        from_report: Optional[str] = None,
        out_dir: Optional[str] = None,
        max_items: int = 20,
        min_severity: str = "low",
        types_filter: Optional[str] = None,
        only_consensus: bool = False,
        project_id: Optional[int] = None,
        scope_id: Optional[int] = None,
        verbose: bool = False
    ) -> int:
        """Generate Foundry PoCs post-report from structured results (preferred)."""
        import json, os
        from pathlib import Path

        def severity_rank(s: str) -> int:
            order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            return order.get((s or "").lower(), 0)

        try:
            # Determine source: results/report or database
            load_from_db = bool(project_id)
            if not from_results and not from_report and not load_from_db:
                print("❌ Provide --from-results, --from-report, or --project-id to load from DB")
                return 1

            if from_results and not os.path.exists(from_results):
                print(f"❌ results.json not found: {from_results}")
                return 1

            # Load vulnerabilities
            vulns = []
            base_dir = None
            if load_from_db:
                # Load findings/contracts from database by project/scope
                try:
                    # Prefer module-level AetherDatabase (test monkeypatch), fallback to import
                    ADBRef = globals().get('AetherDatabase')
                    if not ADBRef:
                        from core.database_manager import AetherDatabase as ADBRef  # type: ignore
                    adb = ADBRef()
                    # Determine contracts in scope
                    contract_paths = None
                    if scope_id:
                        active = adb.get_active_scope(project_id)
                        # If provided scope_id is not the active one, try fetching it directly
                        if active and active.get('id') == scope_id:
                            contract_paths = active.get('selected_contracts', [])
                        else:
                            # Direct fetch of scope by id
                            with adb._connect() as conn:
                                row = conn.execute('SELECT selected_contracts FROM audit_scopes WHERE id = ?', (scope_id,)).fetchone()
                                if row:
                                    import json as _json
                                    contract_paths = _json.loads(row[0])
                    if not contract_paths:
                        # Fallback: all contracts for project
                        contracts = adb.get_contracts(project_id)
                        contract_paths = [c['file_path'] for c in contracts]

                    # Gather analysis results for those contracts
                    findings_accum = []
                    for p in contract_paths:
                        with adb._connect() as conn:
                            row = conn.execute('SELECT id FROM contracts WHERE project_id = ? AND file_path = ?', (project_id, p)).fetchone()
                            if not row:
                                continue
                            contract_id = row[0]
                            res = conn.execute('SELECT findings, status FROM analysis_results WHERE contract_id = ? ORDER BY analyzed_at DESC LIMIT 1', (contract_id,)).fetchone()
                            if not res:
                                continue
                            status = res[1]
                            if status != 'success':
                                continue
                            try:
                                data = json.loads(res[0]) if res[0] else {}
                                items = (data.get('audit', {}) or {}).get('vulnerabilities', []) or data.get('vulnerabilities', []) or []
                                # Normalize expected fields
                                for it in items:
                                    it['file'] = it.get('file') or p
                                findings_accum.extend(items)
                            except Exception:
                                continue

                    vulns = findings_accum
                    base_dir = os.getcwd()
                    if not vulns:
                        print("⚠️  No vulnerabilities found in database for given project/scope")
                        return 0
                except Exception as e:
                    print(f"❌ Failed to load from database: {e}")
                    if verbose:
                        import traceback; traceback.print_exc()
                    return 1
            elif from_results:
                with open(from_results, 'r') as f:
                    data = json.load(f)
                vulns = (data.get('audit', {}) or {}).get('vulnerabilities', []) or []
                base_dir = os.path.dirname(os.path.abspath(from_results))
            else:
                # Minimal markdown fallback: extract bullet points under '## Vulnerabilities Found'
                if not os.path.exists(from_report):
                    print(f"❌ report not found: {from_report}")
                    return 1
                with open(from_report, 'r') as rf:
                    md = rf.read()
                import re
                # Entries like '### N. Title' followed by fields
                heading_pat = re.compile(r"^###\s*\d+\.\s+(.+)$", re.MULTILINE)
                matches = list(heading_pat.finditer(md))
                if not matches:
                    print("⚠️  Could not parse vulnerabilities from report; please supply --from-results")
                    return 1

                for i, m in enumerate(matches):
                    title = m.group(1).strip()
                    start = m.end()
                    end = matches[i+1].start() if i + 1 < len(matches) else len(md)
                    blk = md[start:end]

                    sev = re.search(r"\*\*Severity:\*\*\s*([^\r\n]+)", blk)
                    loc = re.search(r"\*\*Location:\*\*\s*([^\r\n]+)", blk)
                    desc = re.search(r"\*\*Description:\*\*[\r\n]+([\s\S]*?)\n+\*\*Category:\*\*", blk)
                    location = (loc.group(1).strip() if loc else '')
                    file_path = ''
                    line_no = 0
                    if ':' in location:
                        file_path, _, rest = location.partition(':')
                        try:
                            line_no = int(rest.strip().split()[0])
                        except Exception:
                            line_no = 0
                    vulns.append({
                        'title': title,
                        'severity': (sev.group(1).strip() if sev else 'unknown'),
                        'file': file_path,
                        'line': line_no,
                        'description': (desc.group(1).strip() if desc else '')
                    })
                base_dir = os.path.dirname(os.path.abspath(from_report))

            if not vulns:
                print("⚠️  No vulnerabilities found in results.json")
                return 0

            # Filters
            min_rank = severity_rank(min_severity)
            types_set = set([t.strip().lower() for t in (types_filter or '').split(',') if t.strip()])

            def pass_filters(v: dict) -> bool:
                sev = v.get('severity') or v.get('Severity') or ''
                if severity_rank(sev) < min_rank:
                    return False
                if only_consensus and not bool(v.get('consensus', False)):
                    return False
                if types_set:
                    title = (v.get('title') or v.get('vulnerability_type') or '').lower()
                    category = (v.get('category') or '').lower()
                    if not any(t in title or t in category for t in types_set):
                        return False
                return True

            filtered = [v for v in vulns if pass_filters(v)]
            if max_items and len(filtered) > max_items:
                filtered = filtered[:max_items]

            if not filtered:
                print("⚠️  No vulnerabilities matched filters")
                return 0

            # Group by file
            groups = {}
            for v in filtered:
                file_path = v.get('file') or v.get('source_file') or v.get('path') or ''
                groups.setdefault(file_path, []).append(v)

            # Output dir
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
                gen_root = out_dir
            else:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            gen_root = os.path.join(base_dir or 'output', f'foundry_gen_{ts}')
            os.makedirs(gen_root, exist_ok=True)

            generator = FoundryPoCGenerator()
            context_overrides = {}
            # Global DB-derived context (e.g., solc) if available
            try:
                if project_id:
                    ADBRef = globals().get('AetherDatabase')
                    if not ADBRef:
                        from core.database_manager import AetherDatabase as ADBRef  # type: ignore
                    _adb_global = ADBRef()
                    _artifacts = _adb_global.get_build_artifacts(project_id)
                    if _artifacts and isinstance(_artifacts.get('solc_version'), str):
                        context_overrides['solc_version'] = _artifacts['solc_version']
            except Exception:
                pass
            manifest = {"suites": []}

            # For each contract file group
            for file_path, items in groups.items():
                # Resolve file path relative to workspace
                candidate_paths = []
                if os.path.isabs(file_path):
                    candidate_paths.append(file_path)
                if base_dir:
                    candidate_paths.append(os.path.join(base_dir, file_path))
                candidate_paths.append(file_path)

                contract_file = next((p for p in candidate_paths if p and os.path.exists(p)), None)
                if not contract_file:
                    print(f"⚠️  Contract source not found for: {file_path} — skipping {len(items)} items")
                    continue

                with open(contract_file, 'r') as cf:
                    contract_code = cf.read()

                contract_name = os.path.splitext(os.path.basename(contract_file))[0]

                # Attempt to enrich context from DB and artifacts (ABI, solc, symbols)
                try:
                    if project_id:
                        # Prefer module-level AetherDatabase (test monkeypatch), fallback to import
                        ADBRef = globals().get('AetherDatabase')
                        if not ADBRef:
                            from core.database_manager import AetherDatabase as ADBRef  # type: ignore
                        adb = ADBRef()
                        artifacts = adb.get_build_artifacts(project_id)
                        if artifacts and isinstance(artifacts.get('solc_version'), str):
                            context_overrides['solc_version'] = artifacts['solc_version']
                except Exception:
                    pass

                # Load ABI if Foundry artifact exists (out/<Contract>.sol/<Contract>.json)
                try:
                    out_dir_root = os.path.join(os.getcwd(), 'out')
                    guess_dir = os.path.join(out_dir_root, f"{contract_name}.sol")
                    guess_file = os.path.join(guess_dir, f"{contract_name}.json")
                    if os.path.exists(guess_file):
                        import json as _json
                        with open(guess_file, 'r') as af:
                            art = _json.load(af)
                            abi = art.get('abi') or art.get('metadata', {}).get('output', {}).get('abi')
                            if abi:
                                context_overrides['abi'] = abi
                except Exception:
                    pass

                # Use Slither (if available) to extract richer symbols
                try:
                    # Prefer test-monkeypatched Slither if present, else import
                    patched = globals().get('Slither')
                    if patched is not None:
                        SlitherRef = patched
                    else:
                        try:
                            from slither import Slither as _ImportedSlither  # type: ignore
                        except Exception:
                            _ImportedSlither = None  # type: ignore
                        SlitherRef = _ImportedSlither
                    if not SlitherRef:
                        raise ImportError("Slither not available")

                    s = SlitherRef(contract_file)
                    fn_names = []
                    fn_sigs = []
                    ev_names = []
                    mod_names = []
                    for c in s.contracts:
                        if c.name != contract_name:
                            continue
                        for f in c.functions_declared:
                            # Limit to public/external for test calls
                            vis = str(getattr(f, 'visibility', ''))
                            if 'public' in vis or 'external' in vis:
                                fn_names.append(f.name)
                                try:
                                    fn_sigs.append(f.signature_str)
                                except Exception:
                                    pass
                        for e in getattr(c, 'events_declared', []) or []:
                            ev_names.append(e.name)
                        for m in getattr(c, 'modifiers_declared', []) or []:
                            mod_names.append(m.name)
                    if fn_names:
                        context_overrides['contract_functions'] = sorted(set(fn_names))
                    if fn_sigs:
                        context_overrides['function_signatures'] = sorted(set(fn_sigs))
                    elif context_overrides.get('contract_functions'):
                        # Ensure signatures present even if Slither didn't provide
                        context_overrides['function_signatures'] = list(context_overrides['contract_functions'])
                    if ev_names:
                        context_overrides['events'] = sorted(set(ev_names))
                    if mod_names:
                        context_overrides['modifiers'] = sorted(set(mod_names))
                except Exception:
                    pass

                # Fallback: ensure at least a basic function list is provided to the generator
                if 'contract_functions' not in context_overrides:
                    try:
                        import re as _re
                        basic = _re.findall(r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)", contract_code)
                        if basic:
                            context_overrides['contract_functions'] = sorted(set(basic))
                    except Exception:
                        pass
                # Fallback: ensure function_signatures exist if we at least have names
                if 'function_signatures' not in context_overrides and 'contract_functions' in context_overrides:
                    try:
                        context_overrides['function_signatures'] = list(context_overrides['contract_functions'])
                    except Exception:
                        pass
                # Map fields for generator
                gen_vulns = []
                for v in items:
                    gen_vulns.append({
                        'vulnerability_type': v.get('title') or v.get('vulnerability_type') or 'unknown',
                        'line_number': v.get('line') or v.get('line_number') or 0,
                        'severity': v.get('severity') or 'medium',
                        'description': v.get('description') or ''
                    })

                out_dir_contract = os.path.join(gen_root, contract_name)
                os.makedirs(out_dir_contract, exist_ok=True)

                try:
                    suites = await generator.generate_multiple_tests(
                        gen_vulns, contract_code, contract_name, out_dir_contract, context_overrides
                    )
                    for s in suites:
                        manifest['suites'].append({
                            'contract': contract_name,
                            'test_file': s.test_file,
                            'exploit_contract': s.exploit_contract,
                            'status': 'ok'
                        })
                    print(f"✅ Generated {len(suites)} test suites for {contract_name}")
                except Exception as e:
                    print(f"❌ Generation failed for {contract_name}: {e}")
                    if verbose:
                        import traceback
                        traceback.print_exc()

            # Write manifest
            try:
                manifest_path = os.path.join(gen_root, 'generated_tests.json')
                with open(manifest_path, 'w') as mf:
                    json.dump(manifest, mf, indent=2)
                print(f"📜 Manifest: {manifest_path}")
            except Exception as e:
                print(f"⚠️  Warning: failed to write manifest: {e}")

            print("✅ Foundry generation step completed")
            print(f"📁 Output: {gen_root}")
            return 0

        except Exception as e:
            print(f"❌ generate-foundry failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1

    def run_github_audit_command(
        self,
        github_url: str,
        scope: Optional[str] = None,
        min_severity: Optional[str] = None,
        output: Optional[str] = None,
        fmt: str = 'display',
        fresh: bool = False,
        reanalyze: bool = False,
        retry_failed: bool = False,
        clear_cache: bool = False,
        skip_build: bool = False,
        no_cache: bool = False,
        verbose: bool = False,
        dry_run: bool = False,
        github_token: Optional[str] = None,
        interactive_scope: bool = False,
        skip_scope_selector: bool = False
    ) -> int:
        auditor = GitHubAuditor()
        
        # Register database for graceful shutdown
        if hasattr(auditor, 'db') and auditor.db:
            register_database(auditor.db)
        
        options = GitHubAuditOptions(
            scope=[s.strip() for s in scope.split(',')] if scope else None,
            min_severity=min_severity,
            output_format=fmt,
            output_file=output,
            fresh=fresh,
            reanalyze=reanalyze,
            retry_failed=retry_failed,
            clear_cache=clear_cache,
            skip_build=skip_build,
            no_cache=no_cache,
            verbose=verbose,
            dry_run=dry_run,
            github_token=github_token,
            interactive_scope=interactive_scope and not skip_scope_selector
        )

        # Normalize URL consistently with RepositoryManager for DB/report flows
        try:
            normalized_url = auditor.repo_manager._normalize_github_url(github_url)  # type: ignore
        except Exception:
            normalized_url = github_url
        
        result = auditor.audit(normalized_url, options)
        formatter = AuditResultFormatter()
        project_info = {
            'url': normalized_url,
            'framework': result.framework,
            'repo_name': result.project_path.name,
        }
        
        # Skip report generation if the audit was cancelled
        if result.cancelled:
            print("🚀 GitHub audit completed")
            print(f"📁 Repo: {result.project_path}")
            print(f"🧰 Framework: {result.framework}")
            print("No findings to display")
            return 0
        
        # Generate comprehensive reports automatically
        try:
            from core.github_audit_report_generator import GitHubAuditReportGenerator
            
            # Determine output directory
            if output:
                # If output file specified, use its directory
                output_dir = str(Path(output).parent) if Path(output).parent != Path('.') else './output/reports'
            else:
                output_dir = './output/reports'
            
            # Get project_id from auditor's database
            project = auditor.db.get_project(normalized_url)
            project_id = int(project['id']) if project else None
            
            if project_id:
                # Generate comprehensive reports in all formats
                report_generator = GitHubAuditReportGenerator(db_path=auditor.db.db_path)
                
                print(f"\n📊 Generating comprehensive audit reports...")
                report_paths = report_generator.generate_report(
                    output_dir=output_dir,
                    project_id=project_id,
                    scope_id=result.scope_id,  # Pass scope_id from audit result
                    format='all'  # Generate markdown, JSON, and HTML
                )
                
                if report_paths:
                    print(f"✅ Reports generated:")
                    for path in report_paths.split(', '):
                        print(f"   📄 {path}")
                else:
                    print("⚠️  No reports generated (no findings available)")
            else:
                print("⚠️  Could not generate reports: project not found in database")
                
        except Exception as e:
            print(f"⚠️  Report generation failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
        
        # Display findings based on format
        if fmt == 'json':
            payload = formatter.format_for_json(result.findings)
            if output:
                import json as _json
                with open(output, 'w') as f:
                    _json.dump(payload, f, indent=2)
                print(f"\n📊 JSON written: {output}")
            else:
                print(payload)
        elif fmt == 'immunefi':
            md = formatter.format_for_immunefi(result.findings, project_info)
            if output:
                with open(output, 'w') as f:
                    f.write(md)
                print(f"\n📄 Immunefi report written: {output}")
            else:
                print(md)
        else:
            print("🚀 GitHub audit completed")
            print(f"📁 Repo: {result.project_path}")
            print(f"🧰 Framework: {result.framework or 'unknown'}")
            print(formatter.format_for_display(result.findings))
        return 0

    async def run_audit(
        self,
        contract_path: str,
        flow_config: str = "configs/default_audit.yaml",
        output_dir: Optional[str] = None,
        verbose: bool = False,
        enhanced: bool = False,
        phase3: bool = False,
        ai_ensemble: bool = False,
        enhanced_reports: bool = False,
        per_contract_reports: bool = False,
        compliance_only: bool = False,
        export_formats: List[str] = None,
        foundry: bool = False,
        llm_validation: bool = False,
        interactive_scope: bool = False
    ) -> int:
        """Run AetherAudit static analysis and AI reasoning."""
        print("🚀 Starting AetherAudit...")
        print(f"📁 Contract: {contract_path}")
        print(f"⚙️  Flow: {flow_config}")

        # Check if contract_path is an Etherscan or Basescan address
        etherscan_result = self._handle_etherscan_address(contract_path, interactive_scope=interactive_scope)
        
        # Handle contract selection for multi-file contracts
        selected_contracts = None
        if isinstance(etherscan_result, dict) and etherscan_result.get('is_multi_file'):
            # Multiple contracts found - show selector
            from core.github_auditor import ScopeSelector
            scope_selector = ScopeSelector()
            
            discovered_contracts = etherscan_result['contracts']
            print(f"\n📋 Found {len(discovered_contracts)} contracts in multi-file contract")
            
            # Show contract selector
            selected_paths = scope_selector.select_scope(discovered_contracts)
            if not selected_paths:
                print("[red]No contracts selected. Audit cancelled.[/red]")
                return 1
            
            # Use the base directory and selected contracts
            contract_path = etherscan_result['path']
            selected_contracts = selected_paths
            print(f"[green]Auditing {len(selected_paths)} selected contracts out of {len(discovered_contracts)} discovered[/green]\n")
        elif etherscan_result is not None:
            # Single contract or directory (all contracts)
            contract_path = etherscan_result
        else:
            # Try Basescan
            actual_contract_path = self._handle_basescan_address(contract_path)
            if actual_contract_path is None:
                # Not a blockchain address, use the original path
                actual_contract_path = contract_path
            else:
                # Update contract_path to the fetched file path
                contract_path = actual_contract_path

        try:
            # Load flow configuration
            with open(flow_config, 'r') as f:
                flow_data = yaml.safe_load(f)

            # Initialize audit engine
            # Get OpenAI API key from environment or config
            openai_api_key = self._get_openai_api_key()
            
            if not openai_api_key:
                print("⚠️  Warning: OPENAI_API_KEY not set. LLM analysis will be limited.")
                print("   Set it with: export OPENAI_API_KEY='your-key-here'")

            # Map saved config to env for engine behavior
            try:
                cfg = self.config_manager.config
                os.environ['AETHER_TRIAGE_MIN_SEVERITY'] = str(cfg.triage_min_severity)
                os.environ['AETHER_TRIAGE_MIN_CONFIDENCE'] = str(cfg.triage_min_confidence)
                os.environ['AETHER_TRIAGE_MAX_ITEMS'] = str(cfg.triage_max_items)
                os.environ['AETHER_TRIAGE_MAX_PER_TYPE'] = str(cfg.triage_max_per_type)
                os.environ['AETHER_LLM_ONLY_CONSENSUS'] = '1' if cfg.llm_only_consensus else '0'
                os.environ['AETHER_LLM_TRIAGE_MIN_SEVERITY'] = str(cfg.llm_triage_min_severity)
                os.environ['AETHER_LLM_TRIAGE_MIN_CONFIDENCE'] = str(cfg.llm_triage_min_confidence)
                os.environ['AETHER_LLM_TRIAGE_MAX_ITEMS'] = str(cfg.llm_triage_max_items)
                os.environ['AETHER_LLM_TRIAGE_MAX_PER_TYPE'] = str(cfg.llm_triage_max_per_type)
                os.environ['AETHER_FOUNDRY_ONLY_CONSENSUS'] = '1' if cfg.foundry_only_consensus else '0'
                os.environ['AETHER_FOUNDRY_MAX_ITEMS'] = str(cfg.foundry_max_items)
            except Exception:
                pass

            # Choose between enhanced and standard audit engine
            if enhanced or phase3 or llm_validation:
                print("🔧 Using Enhanced Audit Engine with Phase 1-3 Features")
                print("   ✅ Context-aware analysis")
                print("   ✅ Smart severity calibration")
                print("   ✅ Protocol-specific validation")
                print("   ✅ Advanced exploitability analysis")
                print("   ✅ Multi-vector attack simulation")
                print("   ✅ Cross-protocol impact analysis")
                if phase3:
                    print("   🤖 Multi-model AI ensemble")
                    print("   🧠 Dynamic learning system")
                    print("   🔬 Formal verification")
                if llm_validation:
                    print("   🤖 LLM-based false positive filtering")
                    print("   🧪 LLM-generated Foundry tests")
                audit_engine = EnhancedAetherAuditEngine(verbose=verbose, openai_api_key=openai_api_key)
            else:
                print("🔧 Using Standard Audit Engine")
                audit_engine = AetherAuditEngine(verbose=verbose, openai_api_key=openai_api_key)
            
            # Check for Foundry validation
            if foundry:
                print("🔨 Foundry validation enabled")
                print("   ✅ Dynamic Solidity version detection")
                print("   ✅ Version-specific test generation")
                print("   ✅ Reproducible PoC generation")
                print("   ✅ Bug bounty submission format")

            # Execute audit flow
            self._contract_path = contract_path  # Store for contract name extraction
            
            if llm_validation:
                # Use LLM validation mode
                results = await audit_engine.run_enhanced_audit_with_llm_validation(
                    contract_path, output_dir, enable_foundry_tests=foundry
                )
            else:
                # Use standard audit flow with all parameters
                results = await audit_engine.run_audit(
                    contract_path,
                    flow_data,
                    foundry_validation=foundry,
                    enhanced=enhanced,
                    phase3=phase3,
                    ai_ensemble=ai_ensemble,
                    llm_validation=llm_validation,
                    selected_contracts=selected_contracts
                )

            # Generate report
            report_generator = ReportGenerator()
            output_dir_provided_by_user = output_dir is not None
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, "audit_report.md")
            else:
                # Create timestamped output directory
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = f"output/audit_{timestamp}"
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, "audit_report.md")

            # Define full_output_dir for enhanced reports and bug bounty submission
            full_output_dir = None
            contract_name = self._extract_contract_name_from_results(results)
            # Create standardized per-contract directory regardless of base output_dir
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if output_dir_provided_by_user:
                full_output_dir = os.path.join(output_dir, f"{contract_name}_{timestamp}")
            else:
                full_output_dir = f"output/full_{contract_name}_{timestamp}"
            os.makedirs(full_output_dir, exist_ok=True)

            comprehensive_report_path = os.path.join(full_output_dir, f"{contract_name}-comprehensive_report.md")

            # Transform flow results into expected report structure and write comprehensive report
            report_data = self._transform_results_for_report(results)
            report_generator.generate_comprehensive_report(report_data, comprehensive_report_path)
            # Also standardize basic audit report path inside the standardized directory
            report_path = os.path.join(full_output_dir, "audit_report.md")

            # Determine if bug bounty submission should be generated
            # Generate when enhanced reports or per-contract reports are requested or foundry validation is used
            bug_bounty_submission = enhanced_reports or per_contract_reports or foundry

            # Generate per-contract reports if requested
            if per_contract_reports:
                print("📊 Generating per-contract enhanced reports...")
                
                # Determine scope name from contract path
                if os.path.isdir(contract_path):
                    scope_name = Path(contract_path).name
                else:
                    scope_name = Path(contract_path).parent.name if Path(contract_path).parent.name else "contracts"
                
                # Create scope-based directory structure
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if output_dir_provided_by_user:
                    scope_dir = os.path.join(output_dir, f"{scope_name}_audit_{timestamp}")
                else:
                    scope_dir = f"output/{scope_name}_audit_{timestamp}"
                os.makedirs(scope_dir, exist_ok=True)
                
                print(f"📁 Scope directory: {scope_dir}")
                
                try:
                    # Use the enhanced report generator
                    enhanced_report_gen = audit_engine.enhanced_report_generator
                    
                    # Create per-contract directory and reports
                    contract_report_dir = os.path.join(scope_dir, contract_name, "reports")
                    os.makedirs(contract_report_dir, exist_ok=True)
                    
                    # Generate comprehensive enhanced reports for this contract
                    report_files = enhanced_report_gen.generate_per_contract_report(
                        report_data, 
                        contract_name, 
                        contract_report_dir,
                        include_compliance=not compliance_only
                    )
                    
                    print(f"✅ Generated enhanced reports for {contract_name}:")
                    print(f"   📄 Markdown: {report_files.get('markdown', 'N/A')}")
                    print(f"   🌐 Dashboard: {report_files.get('dashboard', 'N/A')}")
                    print(f"   📊 Excel: {report_files.get('excel', 'N/A')}")
                    print(f"   📋 PDF: {report_files.get('pdf', 'N/A')}")
                    
                    # Copy contract source to contract directory
                    if os.path.isfile(contract_path):
                        contract_dest = os.path.join(scope_dir, contract_name, f"{contract_name}.sol")
                        os.makedirs(os.path.dirname(contract_dest), exist_ok=True)
                        shutil.copy2(contract_path, contract_dest)
                        print(f"   📄 Contract: {contract_dest}")
                    
                    # Export results in requested formats
                    if export_formats:
                        print(f"📤 Exporting results in formats: {', '.join(export_formats)}")
                        exported_files = audit_engine.enhanced_report_generator.export_results(results, contract_report_dir, export_formats)
                        print(f"✅ Exported files: {exported_files}")
                    
                    # Generate bug bounty submission
                    if bug_bounty_submission:
                        bounty_path = os.path.join(scope_dir, contract_name, f"{contract_name}_bug_bounty_submission.md")
                        bounty_content = report_generator.generate_bug_bounty_submission(report_data)
                        with open(bounty_path, 'w') as f:
                            f.write(bounty_content)
                        print(f"✅ Generated bug bounty submission: {bounty_path}")
                    
                    print(f"\n📂 All reports for {contract_name} saved to: {os.path.join(scope_dir, contract_name)}")
                    print(f"\n💡 To generate Foundry tests from these results:")
                    print(f"   python main.py generate-foundry --from-results {os.path.join(contract_report_dir, 'results.json')}")
                    
                except Exception as e:
                    print(f"⚠️  Per-contract report generation failed: {e}")
                    import traceback
                    traceback.print_exc()
            
            # Generate enhanced reports if requested
            elif enhanced_reports or compliance_only:
                print("📊 Generating enhanced reports...")

                try:
                    # Use the enhanced report generator
                    enhanced_report_gen = audit_engine.enhanced_report_generator

                    if compliance_only:
                        # Generate only compliance reports
                        compliance_dir = os.path.join(full_output_dir or output_dir, "compliance")
                        os.makedirs(compliance_dir, exist_ok=True)

                        for standard in ['SOC2', 'PCI-DSS', 'GDPR', 'ISO27001', 'NIST']:
                            compliance_path = os.path.join(compliance_dir, f"compliance_{standard.lower()}.md")
                            enhanced_report_gen.compliance_reporter.generate_compliance_report(report_data, standard, compliance_path)
                            print(f"✅ Generated {standard} compliance report")

                    else:
                        # Generate comprehensive enhanced reports
                        # Use full_output_dir if it exists, otherwise use the regular output_dir
                        target_dir = full_output_dir or output_dir
                        report_files = enhanced_report_gen.generate_comprehensive_report(report_data, target_dir)

                        print("✅ Generated enhanced reports:")
                        print(f"   📄 Markdown: {report_files.get('markdown', 'N/A')}")
                        print(f"   🌐 Dashboard: {report_files.get('dashboard', 'N/A')}")
                        print(f"   📊 Excel: {report_files.get('excel', 'N/A')}")
                        print(f"   📋 PDF: {report_files.get('pdf', 'N/A')}")

                        # Export results in requested formats
                        if export_formats:
                            print(f"📤 Exporting results in formats: {', '.join(export_formats)}")
                            exported_files = audit_engine.enhanced_report_generator.export_results(results, target_dir, export_formats)
                            print(f"✅ Exported files: {exported_files}")

                except Exception as e:
                    print(f"⚠️  Enhanced report generation failed: {e}")
                    import traceback
                    traceback.print_exc()

                # Generate bug bounty submission if requested
                if bug_bounty_submission:
                    # Use full_output_dir if it exists, otherwise use the regular output_dir
                    target_dir = full_output_dir or output_dir
                    bounty_path = os.path.join(target_dir, f"{contract_name}-bug_bounty_submission.md")
                    bounty_content = report_generator.generate_bug_bounty_submission(report_data)
                    with open(bounty_path, 'w') as f:
                        f.write(bounty_content)
                    print(f"✅ Generated bug bounty submission: {bounty_path}")

            # Legacy report generation (keep for backward compatibility)
            if results and 'summary' in results and 'total_vulnerabilities' in results['summary']:
                # Audit engine returned proper data structure - flatten it for the report generator
                flattened_data = {
                    'total_vulnerabilities': results['summary']['total_vulnerabilities'],
                    'high_severity_count': results['summary']['high_severity_count'],
                    'execution_time': results['summary']['execution_time'],
                    'vulnerabilities': results['results']['vulnerabilities']
                }
                print(f"📋 Report data contains {flattened_data['total_vulnerabilities']} vulnerabilities")
            elif results:
                # Create report data from available results
                all_vulnerabilities = []
                for key, value in results.items():
                    if isinstance(value, list) and value and isinstance(value[0], dict) and 'vulnerability_type' in value[0]:
                        all_vulnerabilities.extend(value)
                flattened_data = {
                    'total_vulnerabilities': len(all_vulnerabilities),
                    'high_severity_count': len([v for v in all_vulnerabilities if v.get('severity') in ['high', 'critical']]),
                    'execution_time': results.get('execution_time', 0),
                    'vulnerabilities': all_vulnerabilities
                }
                print(f"📋 Report data contains {flattened_data['total_vulnerabilities']} vulnerabilities")
            else:
                flattened_data = {
                    'total_vulnerabilities': 0,
                    'high_severity_count': 0,
                    'execution_time': 0,
                    'vulnerabilities': []
                }
                print("📋 Report data contains 0 vulnerabilities")

            report_generator.generate_markdown_report(flattened_data, report_path)


            # Emit structured results.json alongside the markdown report for downstream tools
            try:
                structured_results_path = os.path.join(output_dir, "results.json")
                structured_payload = self._transform_results_for_report(results) if isinstance(results, dict) else {
                    'audit': flattened_data,
                    'fuzz': {},
                    'validation': {}
                }
                with open(structured_results_path, 'w') as f:
                    json.dump(structured_payload, f, indent=2, default=str)
                print(f"📊 Structured results written: {structured_results_path}")
            except Exception as e:
                print(f"⚠️  Warning: failed to write structured results.json: {e}")

            print(f"✅ Audit completed successfully!")
            print(f"📄 Report: {report_path}")

            # Also generate comprehensive report and bug bounty submission if output_dir was auto-generated
            if not output_dir_provided_by_user:
                # Create timestamped output directory with contract name
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                contract_name = self._extract_contract_name_from_results(results)
                full_output_dir = f"output/full_{contract_name}_{timestamp}"
                os.makedirs(full_output_dir, exist_ok=True)

                comprehensive_report_path = os.path.join(full_output_dir, f"{contract_name}-comprehensive_report.md")

                # Transform flow results into expected report structure for comprehensive report
                report_data = self._transform_results_for_report(results)
                report_generator.generate_comprehensive_report(report_data, comprehensive_report_path)

            # Generate enhanced reports if requested
            if enhanced_reports or compliance_only:
                print("📊 Generating enhanced reports...")

                try:
                    # Use the enhanced report generator
                    enhanced_report_gen = audit_engine.enhanced_report_generator

                    if compliance_only:
                        # Generate only compliance reports
                        compliance_dir = os.path.join(full_output_dir, "compliance")
                        os.makedirs(compliance_dir, exist_ok=True)

                        for standard in ['SOC2', 'PCI-DSS', 'GDPR', 'ISO27001', 'NIST']:
                            compliance_path = os.path.join(compliance_dir, f"compliance_{standard.lower()}.md")
                            enhanced_report_gen.compliance_reporter.generate_compliance_report(report_data, standard, compliance_path)
                            print(f"✅ Generated {standard} compliance report")

                    else:
                        # Generate comprehensive enhanced reports
                        report_files = enhanced_report_gen.generate_comprehensive_report(report_data, full_output_dir)

                        print("✅ Generated enhanced reports:")
                        print(f"   📄 Markdown: {report_files.get('markdown', 'N/A')}")
                        print(f"   🌐 Dashboard: {report_files.get('dashboard', 'N/A')}")
                        print(f"   📊 Excel: {report_files.get('excel', 'N/A')}")
                        print(f"   📋 PDF: {report_files.get('pdf', 'N/A')}")

                        if report_files.get('compliance'):
                            print(f"   📋 Compliance: {report_files['compliance']}")

                    # Export in additional formats if requested
                    if export_formats and len(export_formats) > 1:  # More than just default JSON
                        exported_files = audit_engine.enhanced_report_generator.export_results(results, full_output_dir, export_formats)
                        print("✅ Exported additional formats:")
                        for format_type, file_path in exported_files.items():
                            print(f"   📁 {format_type.upper()}: {file_path}")

                except Exception as e:
                    print(f"⚠️  Enhanced report generation failed: {e}")

            # Generate bug bounty submission template for quick copy-paste
                bounty_path = os.path.join(full_output_dir, f"{contract_name}-bug_bounty_submission.md")
                try:
                    bounty_content = report_generator.generate_bug_bounty_submission(report_data)
                    with open(bounty_path, 'w') as f:
                        f.write(bounty_content)
                except Exception as e:
                    print(f"⚠️  Warning: Failed to generate bug bounty submission: {e}")
                    if verbose:
                        import traceback
                        traceback.print_exc()

                print(f"✅ Full pipeline completed!")
                print(f"📋 Comprehensive Report: {comprehensive_report_path}")
                if os.path.exists(bounty_path):
                    print(f"📋 Bug bounty submission: {bounty_path}")

            # Show summary
            high_severity = flattened_data.get('high_severity_count', 0)

            if high_severity > 0:
                print(f"⚠️  Found {high_severity} high-severity issues")
            else:
                print("✅ No critical issues found")

            # Return results instead of exit code for programmatic use
            return results

        except FileNotFoundError:
            print(f"❌ Error: Contract file not found: {contract_path}")
            return {'error': f'Contract file not found: {contract_path}'}
        except Exception as e:
            print(f"❌ Error during audit: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return {'error': str(e)}

    async def _run_foundry_validation(
        self,
        contract_path: str,
        audit_results: Dict[str, Any],
        output_dir: Optional[str],
        verbose: bool
    ) -> None:
        """Run Foundry validation on detected vulnerabilities."""
        try:
            from core.enhanced_foundry_integration import EnhancedFoundryIntegration
            
            # Check if Foundry is available
            from core.foundry_validator import FoundryValidator
            validator = FoundryValidator()
            if not validator.check_foundry_installation():
                print("⚠️  Foundry not found. Skipping Foundry validation.")
                print("   Install Foundry with: curl -L https://foundry.paradigm.xyz | bash")
                return
            
            print("✅ Foundry detected, running validation...")
            
            # Initialize Foundry integration
            integration = EnhancedFoundryIntegration()
            
            # Run analysis and validation
            submission = await integration.analyze_and_validate_contract(contract_path, output_dir)
            
            # Display results
            print(f"\n🎯 Foundry Validation Results:")
            print(f"   📊 Vulnerabilities: {len(submission.vulnerabilities)}")
            print(f"   🧪 Foundry tests: {len(submission.foundry_tests)}")
            print(f"   💥 Exploit PoCs: {len(submission.exploit_pocs)}")
            print(f"   📈 Confidence: {submission.confidence_score:.2f}")
            
            if verbose:
                print(f"\n📋 Detailed Results:")
                for i, vuln in enumerate(submission.vulnerabilities[:5], 1):
                    print(f"   {i}. {vuln.vulnerability_type} (Line {vuln.line_number})")
                    print(f"      Severity: {vuln.severity}")
                    print(f"      Confidence: {vuln.confidence:.2f}")
                    print(f"      Description: {vuln.description[:60]}...")
                    print()
                
                if len(submission.vulnerabilities) > 5:
                    print(f"   ... and {len(submission.vulnerabilities) - 5} more vulnerabilities")
            
            print(f"\n📄 Bug bounty submission generated:")
            print(f"   📋 Main report: {submission.submission_report}")
            print(f"   🧪 Test directory: {output_dir or 'temp directory'}")
            
        except Exception as e:
            print(f"❌ Foundry validation failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    async def run_fuzz(
        self,
        contract_path: str,
        max_runs: int = 1000,
        timeout: int = 300,
        output_dir: Optional[str] = None,
        verbose: bool = False
    ) -> int:
        """Run AetherFuzz dynamic fuzzing."""
        print("🎯 Starting AetherFuzz...")
        print(f"📁 Contract: {contract_path}")
        print(f"🎲 Max runs: {max_runs}")
        print(f"⏱️  Timeout: {timeout}s")

        # Check if contract_path is an Etherscan or Basescan address
        actual_contract_path = self._handle_etherscan_address(contract_path)
        if actual_contract_path is None:
            # Try Basescan
            actual_contract_path = self._handle_basescan_address(contract_path)
            if actual_contract_path is None:
                # Not a blockchain address, use the original path
                actual_contract_path = contract_path
            else:
                # Update contract_path to the fetched file path
                contract_path = actual_contract_path
        else:
            # Update contract_path to the fetched file path
            contract_path = actual_contract_path

        try:
            # Initialize fuzz engine
            fuzz_engine = AetherFuzzEngine(verbose=verbose)

            # Execute fuzzing
            results = await fuzz_engine.run_fuzzing(
                contract_path,
                max_runs=max_runs,
                timeout=timeout
            )

            # Generate fuzz report
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, "fuzz_report.json")
            else:
                # Create timestamped output directory
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = f"output/fuzz_{timestamp}"
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, "fuzz_report.json")

            # Save fuzz results
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            print(f"✅ Fuzzing completed!")
            print(f"📊 Results: {report_path}")

            # Show summary
            if results.get('vulnerabilities_found', 0) > 0:
                print(f"⚠️  Found {results['vulnerabilities_found']} potential vulnerabilities")
            else:
                print("✅ No vulnerabilities found")

            return 0

        except Exception as e:
            print(f"❌ Error during fuzzing: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1

    async def run_foundry_validation(
        self,
        contract_path: str,
        output_dir: Optional[str] = None,
        verbose: bool = False
    ) -> int:
        """Run Foundry validation with PoC generation for bug bounty submissions."""
        print("🔨 Starting Foundry validation...")
        print(f"📁 Contract: {contract_path}")
        
        try:
            # Check if Foundry is available
            from core.foundry_validator import FoundryValidator
            validator = FoundryValidator()
            if not validator.check_foundry_installation():
                print("❌ Foundry not found. Please install Foundry first:")
                print("   curl -L https://foundry.paradigm.xyz | bash")
                print("   source ~/.zshrc")
                print("   foundryup")
                return 1
            
            print("✅ Foundry detected")
            
            # Initialize Foundry integration
            from core.enhanced_foundry_integration import EnhancedFoundryIntegration
            integration = EnhancedFoundryIntegration()
            
            # Run analysis and validation
            print("🔍 Analyzing contract and generating Foundry tests...")
            submission = await integration.analyze_and_validate_contract(contract_path, output_dir)
            
            # Display results
            print(f"\n🎯 Foundry Validation Results:")
            print(f"   📊 Vulnerabilities: {len(submission.vulnerabilities)}")
            print(f"   🧪 Foundry tests: {len(submission.foundry_tests)}")
            print(f"   💥 Exploit PoCs: {len(submission.exploit_pocs)}")
            print(f"   📈 Confidence: {submission.confidence_score:.2f}")
            
            if verbose:
                print(f"\n📋 Detailed Results:")
                for i, vuln in enumerate(submission.vulnerabilities[:10], 1):
                    print(f"   {i}. {vuln.vulnerability_type} (Line {vuln.line_number})")
                    print(f"      Severity: {vuln.severity}")
                    print(f"      Confidence: {vuln.confidence:.2f}")
                    print(f"      Description: {vuln.description[:80]}...")
                    print()
                
                if len(submission.vulnerabilities) > 10:
                    print(f"   ... and {len(submission.vulnerabilities) - 10} more vulnerabilities")
            
            print(f"\n📄 Bug bounty submission generated:")
            print(f"   📋 Main report: {submission.submission_report}")
            print(f"   🧪 Test directory: {output_dir or 'temp directory'}")
            
            # Show severity breakdown
            severity_counts = {}
            for vuln in submission.vulnerabilities:
                severity = vuln.severity.lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity_counts:
                print(f"\n📊 Severity Breakdown:")
                for severity, count in severity_counts.items():
                    print(f"   {severity.capitalize()}: {count}")
            
            print(f"\n✅ Foundry validation completed successfully!")
            return 0
            
        except Exception as e:
            print(f"❌ Foundry validation failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1

    async def run_full_pipeline(
        self,
        contract_path: str,
        end_to_end: bool = False,
        flow_config: str = "configs/full_pipeline.yaml",
        output_dir: Optional[str] = None,
        verbose: bool = False,
        enhanced: bool = False,
        phase3: bool = False,
        ai_ensemble: bool = False,
        enhanced_reports: bool = False,
        per_contract_reports: bool = False,
        compliance_only: bool = False,
        export_formats: List[str] = None,
        foundry: bool = False
    ) -> int:
        """Run complete audit + fuzz + fix pipeline."""
        print("🔄 Starting full Aether pipeline...")
        print(f"📁 Contract: {contract_path}")
        print(f"🔗 End-to-end: {end_to_end}")
        print(f"⚙️  Flow: {flow_config}")

        # Check if contract_path is an Etherscan or Basescan address
        actual_contract_path = self._handle_etherscan_address(contract_path)
        if actual_contract_path is None:
            # Try Basescan
            actual_contract_path = self._handle_basescan_address(contract_path)
            if actual_contract_path is None:
                # Not a blockchain address, use the original path
                actual_contract_path = contract_path
            else:
                # Update contract_path to the fetched file path
                contract_path = actual_contract_path
        else:
            # Update contract_path to the fetched file path
            contract_path = actual_contract_path

        try:
            # Load flow configuration
            with open(flow_config, 'r') as f:
                flow_data = yaml.safe_load(f)

            # Initialize flow executor
            flow_executor = FlowExecutor(verbose=verbose)

            # Execute full pipeline
            results = await flow_executor.execute_pipeline(contract_path, flow_data, end_to_end, enhanced)
            
            # Run Foundry validation if requested (standalone)
            if foundry:
                print("\n🔨 Running Foundry validation...")
                await self._run_foundry_validation(contract_path, results, output_dir, verbose)

            # Generate comprehensive report
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            else:
                # Create timestamped output directory with contract name
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                contract_name = self._extract_contract_name_from_results(results)
                output_dir = f"output/full_{contract_name}_{timestamp}"
                os.makedirs(output_dir, exist_ok=True)

            report_generator = ReportGenerator()
            report_path = os.path.join(output_dir, f"{contract_name}-comprehensive_report.md")

            # Transform flow results into expected report structure
            report_data = self._transform_results_for_report(results)
            report_generator.generate_comprehensive_report(report_data, report_path)

            # Generate per-contract reports if requested
            if per_contract_reports:
                print("📊 Generating per-contract enhanced reports...")
                
                # Determine scope name from contract path
                if os.path.isdir(contract_path):
                    scope_name = Path(contract_path).name
                else:
                    scope_name = Path(contract_path).parent.name if Path(contract_path).parent.name else "contracts"
                
                # Create scope-based directory structure
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                scope_dir = f"output/{scope_name}_audit_{timestamp}"
                os.makedirs(scope_dir, exist_ok=True)
                
                print(f"📁 Scope directory: {scope_dir}")
                
                try:
                    # We need an audit engine to get the enhanced report generator
                    # Initialize audit engine temporarily
                    openai_api_key = self._get_openai_api_key()
                    from core.audit_engine import AetherAuditEngine
                    audit_engine = AetherAuditEngine(verbose=verbose, openai_api_key=openai_api_key)
                    enhanced_report_gen = audit_engine.enhanced_report_generator
                    
                    # Create per-contract directory and reports
                    contract_report_dir = os.path.join(scope_dir, contract_name, "reports")
                    os.makedirs(contract_report_dir, exist_ok=True)
                    
                    # Generate comprehensive enhanced reports for this contract
                    report_files = enhanced_report_gen.generate_per_contract_report(
                        report_data, 
                        contract_name, 
                        contract_report_dir,
                        include_compliance=not compliance_only
                    )
                    
                    print(f"✅ Generated enhanced reports for {contract_name}:")
                    print(f"   📄 Markdown: {report_files.get('markdown', 'N/A')}")
                    print(f"   🌐 Dashboard: {report_files.get('dashboard', 'N/A')}")
                    print(f"   📊 Excel: {report_files.get('excel', 'N/A')}")
                    print(f"   📋 PDF: {report_files.get('pdf', 'N/A')}")
                    
                    # Copy contract source to contract directory
                    if os.path.isfile(contract_path):
                        contract_dest = os.path.join(scope_dir, contract_name, f"{contract_name}.sol")
                        os.makedirs(os.path.dirname(contract_dest), exist_ok=True)
                        shutil.copy2(contract_path, contract_dest)
                        print(f"   📄 Contract: {contract_dest}")
                    
                    # Export results in requested formats
                    if export_formats:
                        print(f"📤 Exporting results in formats: {', '.join(export_formats)}")
                        exported_files = enhanced_report_gen.export_results(results, contract_report_dir, export_formats)
                        print(f"✅ Exported files: {exported_files}")
                    
                    print(f"\n📂 All reports for {contract_name} saved to: {os.path.join(scope_dir, contract_name)}")
                    print(f"\n💡 To generate Foundry tests from these results:")
                    print(f"   python main.py generate-foundry --from-results {os.path.join(contract_report_dir, 'results.json')}")
                    
                except Exception as e:
                    print(f"⚠️  Per-contract report generation failed: {e}")
                    import traceback
                    traceback.print_exc()

            # Generate bug bounty submission template for quick copy-paste
            bounty_path = os.path.join(output_dir, f"{contract_name}-bug_bounty_submission.md")
            try:
                bounty_content = report_generator.generate_bug_bounty_submission(report_data)
                with open(bounty_path, 'w') as f:
                    f.write(bounty_content)
            except Exception as e:
                print(f"⚠️  Warning: Failed to generate bug bounty submission: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()

            print(f"✅ Full pipeline completed!")
            print(f"📋 Report: {report_path}")
            if os.path.exists(bounty_path):
                print(f"📋 Bug bounty submission: {bounty_path}")

            # Show summary using the transformed report data
            high_severity = report_data.get('audit', {}).get('high_severity_count', 0)

            if high_severity > 0:
                print(f"⚠️  Found {high_severity} high-severity issues")
            else:
                print("✅ No critical issues found")

            # Return results instead of exit code for programmatic use
            return results

        except Exception as e:
            print(f"❌ Error during pipeline execution: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return {'error': str(e)}

    async def run_generate_report(
            self,
            output_dir: Optional[str] = None,
            format: str = "markdown",
            scope_id: Optional[int] = None,
            project_id: Optional[int] = None,
            contract_id: Optional[int] = None,
            list_projects: bool = False,
            list_scopes: Optional[int] = None,
            verbose: bool = False
        ) -> int:
        """Generate audit reports from GitHub audit database findings."""
        try:
            from core.github_audit_report_generator import GitHubAuditReportGenerator
            import sqlite3
            from pathlib import Path
            
            db_path = str(Path.home() / '.aether' / 'aether_github_audit.db')
            
            # List projects
            if list_projects:
                print("\n📋 Projects in Database:")
                print("=" * 80)
                
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, repo_name, url, created_at FROM projects
                    ORDER BY created_at DESC
                """)
                
                projects = cursor.fetchall()
                if not projects:
                    print("  (No projects found)")
                else:
                    for p in projects:
                        print(f"  ID: {p['id']:3d} | {p['repo_name']:40s} | {p['url']}")
                
                conn.close()
                return 0
            
            # List scopes for a project
            if list_scopes is not None:
                print(f"\n📋 Audit Scopes for Project ID {list_scopes}:")
                print("=" * 80)
                
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Before displaying, recalculate progress for each scope to avoid stale counts
                try:
                    try:
                        from core.database_manager import AetherDatabase as _ADB  # type: ignore
                    except Exception:
                        _ADB = None  # type: ignore
                    ADBRef = _ADB or globals().get('AetherDatabase')
                    if ADBRef:
                        adb = ADBRef(db_path=db_path)  # type: ignore
                        recalc_needed = True
                    else:
                        recalc_needed = False
                except Exception:
                    recalc_needed = False
                
                cursor.execute("""
                    SELECT id, status, total_selected, total_audited, total_pending, created_at, selected_contracts
                    FROM audit_scopes
                    WHERE project_id = ?
                    ORDER BY created_at DESC
                """, (list_scopes,))
                
                scopes = cursor.fetchall()
                if not scopes:
                    print(f"  (No scopes found for project {list_scopes})")
                else:
                    for s in scopes:
                        sid = int(s['id'])
                        total_selected = int(s['total_selected'] or 0)
                        total_audited = int(s['total_audited'] or 0)
                        total_pending = int(s['total_pending'] or 0)
                        status = s['status']
                        
                        if recalc_needed:
                            try:
                                prog = adb.recalculate_scope_progress(sid)
                                total_selected = int(prog.get('total_selected', total_selected))
                                total_audited = int(prog.get('total_audited', total_audited))
                                total_pending = int(prog.get('total_pending', total_pending))
                                # If nothing pending, auto-mark completed for clarity
                                if total_selected > 0 and total_pending == 0 and status != 'completed':
                                    adb.complete_scope(sid)
                                    status = 'completed'
                            except Exception:
                                pass
                        
                        print(
                            f"  Scope ID: {sid:3d} | Status: {status:10s} | "
                            f"Audited: {total_audited:3d}/{total_selected:3d} | "
                            f"Pending: {total_pending:3d}"
                        )
                        # List individual contracts in this scope
                        try:
                            import json as _json
                            selected = []
                            raw_sel = s['selected_contracts']
                            if raw_sel:
                                selected = _json.loads(raw_sel) if isinstance(raw_sel, str) else list(raw_sel)
                        except Exception:
                            selected = []
                        
                        if selected:
                            max_show = 20
                            print("    Contracts:")
                            # Reuse the same DB connection to resolve contract IDs
                            for i, path in enumerate(selected[:max_show], 1):
                                try:
                                    row = conn.execute('SELECT id FROM contracts WHERE project_id = ? AND file_path = ?', (list_scopes, path)).fetchone()
                                    cid = int(row[0]) if row else None
                                except Exception:
                                    cid = None
                                if cid is not None:
                                    print(f"      {i:2d}. [{cid}] {path}")
                                else:
                                    print(f"      {i:2d}. [??] {path}")
                            if len(selected) > max_show:
                                print(f"      ... and {len(selected) - max_show} more")
                
                conn.close()
                return 0
            
            # Generate report
            if not Path(db_path).exists():
                print(f"❌ Database not found at {db_path}")
                print("   Run an audit first with: python main.py audit <github_url>")
                return 1
            
            print("🔍 Generating audit report from database...")
            print(f"   Format: {format}")
            if scope_id:
                print(f"   Scope ID: {scope_id}")
            if project_id:
                print(f"   Project ID: {project_id}")
            if contract_id:
                print(f"   Contract ID: {contract_id}")
            print()
            
            generator = GitHubAuditReportGenerator(db_path=db_path)
            report_paths = generator.generate_report(
                output_dir=output_dir,
                scope_id=scope_id,
                project_id=project_id,
                contract_id=contract_id,
                format=format
            )
            
            if report_paths:
                print(f"\n✅ Reports generated successfully!")
                print(f"📁 Location: {report_paths}")
                return 0
            else:
                print("❌ Failed to generate reports")
                return 1
        
        except Exception as e:
            print(f"❌ Error generating report: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1

    async def run_exploit_tests(
            self,
            project_name: str,
            fork_url: Optional[str] = None,
            anvil_port: int = 8545,
            verbose: bool = False,
        ) -> int:
        """Run exploit tests for a project."""
        try:
            # Run comprehensive exploit tests
            suite = await self.exploit_tester.run_comprehensive_exploit_tests(project_name, fork_url)

            # Save results
            results_file = f"output/exploit_tests/{project_name}_exploit_test_results.json"
            os.makedirs(os.path.dirname(results_file), exist_ok=True)

            with open(results_file, 'w') as f:
                json.dump({
                    'project_name': suite.project_name,
                    'findings_tested': suite.findings_tested,
                    'tests_passed': suite.tests_passed,
                    'exploits_successful': suite.exploits_successful,
                    'total_execution_time': suite.total_execution_time,
                    'results': [
                        {
                            'finding_id': r.finding_id,
                            'contract_name': r.contract_name,
                            'vulnerability_type': r.vulnerability_type,
                            'test_compiled': r.test_compiled,
                            'test_passed': r.test_passed,
                            'execution_time': r.execution_time,
                            'errors': r.errors[:5]  # Limit error output
                        } for r in suite.results
                    ]
                }, f, indent=2)

            print(f"\n✅ Results saved to: {results_file}")
            return 0

        except Exception as e:
            print(f"❌ Error running exploit tests: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1
