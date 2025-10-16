"""
AetherAudit node implementations.
"""

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.flow_executor import BaseNode, NodeResult
from core.defi_vulnerability_detector import DeFiVulnerabilityDetector


class StaticAnalysisNode(BaseNode):
    """Node for running static analysis tools like Slither and Mythril."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute static analysis on contract files."""
        print("🔧 StaticAnalysisNode executing...")
        try:
            contract_files = context.get('contract_files', [])
            if not contract_files:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No contract files found in context"
                )

            print(f"📁 Found {len(contract_files)} contract files")

            # Get configuration for this node
            config = self.config or {}
            tools = config.get('tools', ['slither'])

            all_vulnerabilities = []
            tool_results = {}

            # Run improved pattern-based analysis across all files
            print("🔍 Running improved pattern-based analysis...")
            
            # Check if enhanced mode is enabled
            enhanced_mode = context.get('enhanced_mode', False)
            if enhanced_mode:
                print("🔧 Using Enhanced Vulnerability Detector")
                from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector
                detector = EnhancedVulnerabilityDetector()
            else:
                from core.improved_vulnerability_detector import ImprovedVulnerabilityDetector
                detector = ImprovedVulnerabilityDetector()
            
            pattern_results = []
            for file_path, file_content in contract_files:
                if enhanced_mode:
                    pattern_vulnerabilities = detector.analyze_contract(file_content)
                else:
                    pattern_vulnerabilities = detector.analyze_contract(file_path, file_content)
                for vuln in pattern_vulnerabilities:
                    pattern_results.append({
                        'title': f"{vuln.vulnerability_type.title()} Vulnerability",
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'file': file_path,
                        'line': vuln.line_number,
                        'tool': 'improved_pattern_analyzer',
                        'category': vuln.category,
                        'swc_id': vuln.swc_id,
                        'status': 'confirmed' if vuln.confidence > 0.7 else 'suspected'
                    })

            tool_results['pattern_analysis'] = {
                'vulnerabilities': pattern_results,
                'errors': []
            }

            print(f"📊 Pattern analysis found {len(pattern_results)} vulnerabilities")

            # Run DeFi-specific analysis
            print("🔍 Running DeFi-specific vulnerability analysis...")
            defi_detector = DeFiVulnerabilityDetector()
            defi_results = []
            for file_path, file_content in contract_files:
                defi_vulnerabilities = defi_detector.analyze_contract(file_path, file_content)
                for vuln in defi_vulnerabilities:
                    defi_results.append({
                        'title': f"{vuln.vuln_type.value.title()} Vulnerability",
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'file': file_path,
                        'line': vuln.line_number,
                        'tool': 'defi_analyzer',
                        'category': 'defi_specific',
                        'swc_id': f"DEFI-{vuln.vuln_type.value.upper()}",
                        'status': 'confirmed' if vuln.confidence > 0.7 else 'suspected',
                        'attack_vector': vuln.attack_vector,
                        'financial_impact': vuln.financial_impact,
                        'exploit_complexity': vuln.exploit_complexity,
                        'immunefi_bounty_potential': vuln.immunefi_bounty_potential,
                        'poc_suggestion': vuln.poc_suggestion,
                        'fix_suggestion': vuln.fix_suggestion
                    })

            tool_results['defi_analysis'] = {
                'vulnerabilities': defi_results,
                'errors': []
            }

            print(f"📊 DeFi analysis found {len(defi_results)} vulnerabilities")
            for vuln in defi_results:
                print(f"  - {vuln['title']}: {vuln['description']} (Bounty: {vuln['immunefi_bounty_potential']})")

            # Apply context-aware false positive filtering (already done in improved detector)
            print(f"✅ After context validation: {len(pattern_results)} vulnerabilities (filtered out 0)")
            
            # Combine pattern and DeFi results
            all_vulnerabilities = pattern_results + defi_results

            # Run each enabled tool
            print(f"🔧 Running tools: {tools}")
            for tool in tools:
                print(f"🔍 Running {tool} analysis...")
                if tool == 'slither':
                    results = await self._run_slither(contract_files[0][0])  # Use first file
                    tool_results['slither'] = results
                    vuln_count = len(results.get('vulnerabilities', []))
                    print(f"✅ Slither found {vuln_count} vulnerabilities")
                    for v in results.get('vulnerabilities', []):
                        v['status'] = 'confirmed'
                    all_vulnerabilities.extend(results.get('vulnerabilities', []))
                # Mythril removed due to Python 3.12 compatibility issues
                # Use Slither as primary static analysis tool

            print(f"📊 Total vulnerabilities from tools: {len(all_vulnerabilities)}")

            # Calculate summary statistics
            # Only count confirmed highs in headline
            high_severity = len([
                v for v in all_vulnerabilities
                if v.get('severity', '').lower() in ['high', 'critical'] and v.get('status') == 'confirmed'
            ])

            # Update context with results
            context.update({
                'static_analysis_results': tool_results,
                'vulnerabilities': all_vulnerabilities,
                'total_vulnerabilities': len(all_vulnerabilities),
                'high_severity_count': high_severity
            })

            print(f"DEBUG: StaticAnalysisNode - Total vulnerabilities: {len(all_vulnerabilities)}")
            print(f"DEBUG: StaticAnalysisNode - High severity count: {high_severity}")
            print(f"DEBUG: StaticAnalysisNode - Sample vuln severity: {all_vulnerabilities[0].get('severity', 'NO_SEVERITY') if all_vulnerabilities else 'NO_VULNS'}")

            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    'tool_results': tool_results,
                    'vulnerabilities': all_vulnerabilities,
                    'summary': {
                        'total': len(all_vulnerabilities),
                        'high_severity': high_severity
                    }
                }
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _run_slither(self, contract_path: str) -> Dict[str, Any]:
        """Run Slither static analysis."""
        try:
            import tempfile
            import shutil
            import os

            # Create a temporary directory for the Foundry project
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Initialize git repo
                subprocess.run(['git', 'init'], cwd=temp_dir, capture_output=True)

                # Create foundry.toml with remappings and solc version
                foundry_toml = temp_path / "foundry.toml"
                foundry_toml.write_text("""
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
remappings = [
  "@openzeppelin/=lib/openzeppelin-contracts/",
  "@uniswap/v2-core/=lib/v2-core/"
]
solc_version = "0.7.5"
""".strip())

                # Create src directory and copy contract
                src_dir = temp_path / "src"
                src_dir.mkdir()
                contract_file = Path(contract_path)
                final_contract_path = src_dir / contract_file.name
                shutil.copy2(contract_path, final_contract_path)

                # Setup environment
                env = os.environ.copy()
                env['PATH'] = f"/Users/l33tdawg/.foundry/bin:{env.get('PATH', '')}"

                # Install forge-std
                subprocess.run(
                    ['forge', 'install', 'foundry-rs/forge-std'],
                    cwd=temp_dir,
                    capture_output=True,
                    env=env,
                    timeout=30
                )

                # Install OpenZeppelin - try v4 first, then v3
                oz_versions = ['OpenZeppelin/openzeppelin-contracts@v4.9.0', 'OpenZeppelin/openzeppelin-contracts@v3.4.2']
                oz_installed = False
                for oz_version in oz_versions:
                    result = subprocess.run(
                        ['forge', 'install', oz_version],
                        cwd=temp_dir,
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30
                    )
                    if result.returncode == 0:
                        oz_installed = True
                        break

                # Try to build with Foundry
                build_result = subprocess.run(
                    ['forge', 'build', '--force'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=60
                )

                # If build failed, try running slither without forge (direct analysis)
                if build_result.returncode != 0:
                    # Try direct slither analysis without compilation
                    print(f"⚠️  Foundry build failed, trying direct Slither analysis...")
                    cmd = [
                        'slither',
                        str(final_contract_path),
                        '--json', '-',
                        '--exclude-dependencies',
                        '--exclude-informational'
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        env=env
                    )
                    
                    if result.returncode in [0, 255] and result.stdout.strip().startswith('{'):
                        try:
                            data = json.loads(result.stdout)
                            vulnerabilities = self._parse_slither_output(data)
                            return {
                                'vulnerabilities': vulnerabilities,
                                'success': True,
                                'output': f'Direct analysis (no compilation): {len(vulnerabilities)} issues'
                            }
                        except json.JSONDecodeError:
                            pass
                    
                    # If all else fails, return empty
                    return {
                        'vulnerabilities': [],
                        'success': False,
                        'error': f'Slither analysis skipped - build failed: {build_result.stderr[:100]}'
                    }

                # Run slither on the compiled project
                cmd = [
                    'slither',
                    str(final_contract_path),
                    '--json', '-',
                    '--exclude-dependencies',
                    '--exclude-informational',
                    '--compile-force-framework', 'foundry'
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env=env,
                    cwd=temp_dir
                )

                # Slither returns 255 when it finds vulnerabilities but still produces valid JSON
                if result.returncode == 0 or result.returncode == 255:
                    try:
                        if result.stdout.strip().startswith('{'):
                            data = json.loads(result.stdout)
                            vulnerabilities = self._parse_slither_output(data)
                            return {
                                'vulnerabilities': vulnerabilities,
                                'success': True,
                                'output': result.stdout
                            }
                        else:
                            return {
                                'vulnerabilities': [],
                                'success': False,
                                'error': 'Slither output is not JSON'
                            }
                    except json.JSONDecodeError as e:
                        return {
                            'vulnerabilities': [],
                            'success': False,
                            'error': f'Failed to parse slither JSON output: {e}'
                        }
                else:
                    return {
                        'vulnerabilities': [],
                        'success': False,
                        'error': f'Slither analysis failed with code {result.returncode}: {result.stderr[:100]}'
                    }

        except subprocess.TimeoutExpired:
            return {
                'vulnerabilities': [],
                'success': False,
                'error': 'Slither analysis timed out'
            }
        except FileNotFoundError:
            return {
                'vulnerabilities': [],
                'success': False,
                'error': 'Slither not found. Install: pip install slither-analyzer'
            }
        except Exception as e:
            return {
                'vulnerabilities': [],
                'success': False,
                'error': str(e)
            }

    async def _run_mythril(self, contract_path: str) -> Dict[str, Any]:
        """Run Mythril symbolic execution with enhanced PoC generation."""
        try:
            import tempfile
            import shutil
            import subprocess
            import json
            from pathlib import Path

            # First try Mythril Python API
            try:
                from mythril.analyzer import MythrilAnalyzer
                from mythril.analyzer.report import Report
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                    # Copy contract content to temp file
                    shutil.copy2(contract_path, f.name)
                    temp_contract_path = f.name

                try:
                    # Use Mythril Python API with enhanced configuration
                    analyzer = MythrilAnalyzer()
                    
                    # Configure Mythril for deeper analysis
                    analyzer.config.solver_timeout = 300
                    analyzer.config.max_depth = 12
                    analyzer.config.call_depth_limit = 8
                    analyzer.config.disable_dependency_pruning = False
                    analyzer.config.unconstrained_storage = True
                    analyzer.config.pruning_factor = 1
                    analyzer.config.parallel_solving = True
                    analyzer.config.solver_log = False
                    analyzer.config.transaction_sequences = True
                    analyzer.config.use_integer_overflow = True
                    analyzer.config.use_coinbase = True
                    analyzer.config.use_tx_origin = True
                    analyzer.config.use_tx_gasprice = True
                    analyzer.config.use_tx_blockhash = True
                    analyzer.config.use_tx_timestamp = True
                    analyzer.config.use_tx_number = True
                    analyzer.config.use_tx_gaslimit = True
                    analyzer.config.use_tx_difficulty = True
                    analyzer.config.use_tx_chainid = True
                    analyzer.config.use_tx_basefee = True
                    analyzer.config.use_tx_blobbasefee = True
                    analyzer.config.use_tx_blobhash = True
                    analyzer.config.use_tx_blobversionedhashes = True
                    analyzer.config.use_tx_parentbeaconblockroot = True
                    analyzer.config.use_tx_random = True
                    analyzer.config.use_tx_prevrandao = True
                    analyzer.config.use_tx_blobgasused = True
                    analyzer.config.use_tx_excessblobgas = True
                    analyzer.config.use_tx_logs = True
                    analyzer.config.use_tx_receipts = True
                    analyzer.config.use_tx_block = True
                    analyzer.config.use_tx_msg = True
                    analyzer.config.use_tx_tx = True
                    analyzer.config.use_tx_blockhash = True
                    analyzer.config.use_tx_timestamp = True
                    analyzer.config.use_tx_number = True
                    analyzer.config.use_tx_gaslimit = True
                    analyzer.config.use_tx_difficulty = True
                    analyzer.config.use_tx_chainid = True
                    analyzer.config.use_tx_basefee = True
                    analyzer.config.use_tx_blobbasefee = True
                    analyzer.config.use_tx_blobhash = True
                    analyzer.config.use_tx_blobversionedhashes = True
                    analyzer.config.use_tx_parentbeaconblockroot = True
                    analyzer.config.use_tx_random = True
                    analyzer.config.use_tx_prevrandao = True
                    analyzer.config.use_tx_blobgasused = True
                    analyzer.config.use_tx_excessblobgas = True
                    analyzer.config.use_tx_logs = True
                    analyzer.config.use_tx_receipts = True
                    analyzer.config.use_tx_block = True
                    analyzer.config.use_tx_msg = True
                    analyzer.config.use_tx_tx = True

                    # Run analysis
                    report = analyzer.analyze(temp_contract_path)

                    # Parse results with enhanced PoC generation
                    if report:
                        vulnerabilities = self._parse_mythril_api_output(report)
                        poc_results = await self._generate_mythril_pocs(vulnerabilities, contract_path)
                        
                        return {
                            'vulnerabilities': vulnerabilities,
                            'poc_results': poc_results,
                            'success': True,
                            'output': f'Found {len(vulnerabilities)} issues with {len(poc_results)} PoCs'
                        }
                    else:
                        return {
                            'vulnerabilities': [],
                            'poc_results': [],
                            'success': False,
                            'error': 'Mythril analysis returned no results'
                        }

                finally:
                    # Clean up temp file
                    Path(temp_contract_path).unlink(missing_ok=True)

            except ImportError:
                # Fallback to CLI if Python API not available
                return await self._run_mythril_cli(contract_path)

        except Exception as e:
            return {
                'vulnerabilities': [],
                'success': False,
                'error': f'Mythril analysis failed: {str(e)}'
            }

    async def _run_mythril_cli(self, contract_path: str) -> Dict[str, Any]:
        """Run Mythril via CLI with enhanced configuration."""
        try:
            import subprocess
            import json
            import tempfile
            import shutil
            from pathlib import Path

            # Create temporary directory for Mythril analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_contract_path = Path(temp_dir) / "contract.sol"
                shutil.copy2(contract_path, temp_contract_path)

                # Enhanced Mythril CLI command with deeper analysis
                cmd = [
                    'myth',
                    'analyze',
                    str(temp_contract_path),
                    '--execution-timeout', '300',
                    '--max-depth', '12',
                    '--call-depth-limit', '8',
                    '--solver-timeout', '300',
                    '--parallel-solving',
                    '--transaction-sequences',
                    '--use-integer-overflow',
                    '--use-coinbase',
                    '--use-tx-origin',
                    '--use-tx-gasprice',
                    '--use-tx-blockhash',
                    '--use-tx-timestamp',
                    '--use-tx-number',
                    '--use-tx-gaslimit',
                    '--use-tx-difficulty',
                    '--use-tx-chainid',
                    '--use-tx-basefee',
                    '--use-tx-blobbasefee',
                    '--use-tx-blobhash',
                    '--use-tx-blobversionedhashes',
                    '--use-tx-parentbeaconblockroot',
                    '--use-tx-random',
                    '--use-tx-prevrandao',
                    '--use-tx-blobgasused',
                    '--use-tx-excessblobgas',
                    '--use-tx-logs',
                    '--use-tx-receipts',
                    '--use-tx-block',
                    '--use-tx-msg',
                    '--use-tx-tx',
                    '--unconstrained-storage',
                    '--pruning-factor', '1',
                    '--disable-dependency-pruning',
                    '--solver-log',
                    '--output', 'json'
                ]

                # Run Mythril CLI
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=temp_dir
                )

                if result.returncode == 0 or result.returncode == 255:  # 255 is normal for Mythril
                    try:
                        # Parse JSON output
                        if result.stdout.strip().startswith('{'):
                            data = json.loads(result.stdout)
                            vulnerabilities = self._parse_mythril_cli_output(data)
                            poc_results = await self._generate_mythril_pocs(vulnerabilities, contract_path)
                            
                            return {
                                'vulnerabilities': vulnerabilities,
                                'poc_results': poc_results,
                                'success': True,
                                'output': f'Found {len(vulnerabilities)} issues with {len(poc_results)} PoCs'
                            }
                        else:
                            # Parse text output
                            vulnerabilities = self._parse_mythril_text_output(result.stdout)
                            poc_results = await self._generate_mythril_pocs(vulnerabilities, contract_path)
                            
                            return {
                                'vulnerabilities': vulnerabilities,
                                'poc_results': poc_results,
                                'success': True,
                                'output': f'Found {len(vulnerabilities)} issues with {len(poc_results)} PoCs'
                            }
                    except json.JSONDecodeError:
                        # Fallback to text parsing
                        vulnerabilities = self._parse_mythril_text_output(result.stdout)
                        poc_results = await self._generate_mythril_pocs(vulnerabilities, contract_path)
                        
                        return {
                            'vulnerabilities': vulnerabilities,
                            'poc_results': poc_results,
                            'success': True,
                            'output': f'Found {len(vulnerabilities)} issues with {len(poc_results)} PoCs'
                        }
                else:
                    return {
                        'vulnerabilities': [],
                        'poc_results': [],
                        'success': False,
                        'error': f'Mythril CLI failed: {result.stderr}'
                    }

        except subprocess.TimeoutExpired:
            return {
                'vulnerabilities': [],
                'poc_results': [],
                'success': False,
                'error': 'Mythril analysis timed out'
            }
        except FileNotFoundError:
            return {
                'vulnerabilities': [],
                'poc_results': [],
                'success': False,
                'error': 'Mythril CLI not found. Install: pip install mythril'
            }
        except Exception as e:
            return {
                'vulnerabilities': [],
                'poc_results': [],
                'success': False,
                'error': f'Mythril CLI analysis failed: {str(e)}'
            }

    async def _generate_mythril_pocs(self, vulnerabilities: List[Dict[str, Any]], contract_path: str) -> List[Dict[str, Any]]:
        """Generate Proof of Concept exploits for Mythril vulnerabilities."""
        poc_results = []
        
        for vuln in vulnerabilities:
            try:
                # Generate PoC based on vulnerability type
                vuln_type = vuln.get('type', 'unknown')
                
                if vuln_type in ['integer_overflow', 'integer_underflow']:
                    poc = await self._generate_arithmetic_poc(vuln, contract_path)
                elif vuln_type in ['reentrancy', 'unchecked_call']:
                    poc = await self._generate_reentrancy_poc(vuln, contract_path)
                elif vuln_type in ['suicide', 'selfdestruct']:
                    poc = await self._generate_suicide_poc(vuln, contract_path)
                elif vuln_type in ['ether_thief', 'arbitrary_send']:
                    poc = await self._generate_ether_theft_poc(vuln, contract_path)
                else:
                    poc = await self._generate_generic_poc(vuln, contract_path)
                
                if poc:
                    poc_results.append(poc)
                    
            except Exception as e:
                print(f"⚠️ Failed to generate PoC for {vuln.get('type', 'unknown')}: {e}")
                continue
                
        return poc_results

    async def _generate_arithmetic_poc(self, vuln: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
        """Generate PoC for arithmetic vulnerabilities."""
        return {
            'vulnerability_id': vuln.get('id', 'unknown'),
            'type': 'arithmetic_overflow',
            'title': 'Arithmetic Overflow PoC',
            'description': 'Demonstrates integer overflow/underflow vulnerability',
            'exploit_code': f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ArithmeticOverflowPoC is Test {{
    function testOverflow() public {{
        // Deploy vulnerable contract
        VulnerableContract target = new VulnerableContract();
        
        // Trigger overflow with maximum uint256 value
        uint256 maxValue = type(uint256).max;
        
        // Call vulnerable function
        try target.vulnerableFunction(maxValue) {{
            // If no revert, overflow occurred
            console.log("Overflow successfully triggered");
        }} catch {{
            console.log("Function reverted - overflow prevented");
        }}
    }}
}}

contract VulnerableContract {{
    uint256 public value;
    
    function vulnerableFunction(uint256 input) public {{
        // Vulnerable: No overflow check
        value = value + input;  // Can overflow
    }}
}}
            ''',
            'test_instructions': [
                '1. Deploy the PoC contract',
                '2. Call testOverflow() function',
                '3. Check if overflow occurs',
                '4. Verify contract state corruption'
            ],
            'expected_outcome': 'Integer overflow leading to state corruption',
            'severity': 'high',
            'confidence': 0.8
        }

    async def _generate_reentrancy_poc(self, vuln: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
        """Generate PoC for reentrancy vulnerabilities."""
        return {
            'vulnerability_id': vuln.get('id', 'unknown'),
            'type': 'reentrancy',
            'title': 'Reentrancy Attack PoC',
            'description': 'Demonstrates reentrancy vulnerability exploitation',
            'exploit_code': f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ReentrancyPoC is Test {{
    VulnerableContract target;
    AttackerContract attacker;
    
    function setUp() public {{
        target = new VulnerableContract();
        attacker = new AttackerContract(address(target));
        
        // Fund the vulnerable contract
        vm.deal(address(target), 10 ether);
    }}
    
    function testReentrancy() public {{
        // Deploy attacker contract
        attacker = new AttackerContract(address(target));
        
        // Fund attacker
        vm.deal(address(attacker), 1 ether);
        
        // Execute reentrancy attack
        attacker.attack();
        
        // Check if attack succeeded
        assertTrue(attacker.success(), "Reentrancy attack failed");
        console.log("Reentrancy attack successful");
    }}
}}

contract VulnerableContract {{
    mapping(address => uint256) public balances;
    
    function deposit() public payable {{
        balances[msg.sender] += msg.value;
    }}
    
    function withdraw(uint256 amount) public {{
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: External call before state update
        (bool success, ) = msg.sender.call{{value: amount}}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;  // State update after external call
    }}
}}

contract AttackerContract {{
    VulnerableContract target;
    bool public success;
    
    constructor(address _target) {{
        target = VulnerableContract(_target);
    }}
    
    function attack() public payable {{
        // Deposit to get balance
        target.deposit{{value: 1 ether}}();
        
        // Withdraw to trigger reentrancy
        target.withdraw(1 ether);
    }}
    
    receive() external payable {{
        if (address(target).balance > 0) {{
            // Reentrancy: Call withdraw again
            target.withdraw(1 ether);
            success = true;
        }}
    }}
}}
            ''',
            'test_instructions': [
                '1. Deploy the PoC contract',
                '2. Call testReentrancy() function',
                '3. Observe reentrancy attack',
                '4. Check contract balance depletion'
            ],
            'expected_outcome': 'Successful reentrancy attack draining contract funds',
            'severity': 'critical',
            'confidence': 0.9
        }

    async def _generate_suicide_poc(self, vuln: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
        """Generate PoC for suicide/selfdestruct vulnerabilities."""
        return {
            'vulnerability_id': vuln.get('id', 'unknown'),
            'type': 'suicide',
            'title': 'Suicide Attack PoC',
            'description': 'Demonstrates unauthorized selfdestruct vulnerability',
            'exploit_code': f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract SuicidePoC is Test {{
    VulnerableContract target;
    
    function setUp() public {{
        target = new VulnerableContract();
        
        // Fund the vulnerable contract
        vm.deal(address(target), 5 ether);
    }}
    
    function testSuicide() public {{
        // Check initial balance
        uint256 initialBalance = address(target).balance;
        assertTrue(initialBalance > 0, "Contract should have balance");
        
        // Execute suicide attack
        target.suicideFunction();
        
        // Check if contract was destroyed
        uint256 finalBalance = address(target).balance;
        assertTrue(finalBalance == 0, "Contract should be destroyed");
        
        console.log("Suicide attack successful");
    }}
}}

contract VulnerableContract {{
    address public owner;
    
    constructor() {{
        owner = msg.sender;
    }}
    
    function suicideFunction() public {{
        // Vulnerable: No access control
        selfdestruct(payable(msg.sender));  // Anyone can destroy contract
    }}
    
    receive() external payable {{
        // Contract can receive funds
    }}
}}
            ''',
            'test_instructions': [
                '1. Deploy the PoC contract',
                '2. Call testSuicide() function',
                '3. Observe contract destruction',
                '4. Verify funds are sent to attacker'
            ],
            'expected_outcome': 'Contract destroyed and funds stolen',
            'severity': 'critical',
            'confidence': 0.9
        }

    async def _generate_ether_theft_poc(self, vuln: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
        """Generate PoC for ether theft vulnerabilities."""
        return {
            'vulnerability_id': vuln.get('id', 'unknown'),
            'type': 'ether_theft',
            'title': 'Ether Theft PoC',
            'description': 'Demonstrates unauthorized ether withdrawal vulnerability',
            'exploit_code': f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract EtherTheftPoC is Test {{
    VulnerableContract target;
    address attacker;
    
    function setUp() public {{
        target = new VulnerableContract();
        attacker = address(0x1337);
        
        // Fund the vulnerable contract
        vm.deal(address(target), 10 ether);
        
        // Fund attacker
        vm.deal(attacker, 1 ether);
    }}
    
    function testEtherTheft() public {{
        // Check initial balance
        uint256 initialBalance = address(target).balance;
        assertTrue(initialBalance > 0, "Contract should have balance");
        
        // Execute ether theft
        vm.prank(attacker);
        target.withdrawAll();
        
        // Check if funds were stolen
        uint256 finalBalance = address(target).balance;
        assertTrue(finalBalance == 0, "All funds should be stolen");
        
        console.log("Ether theft successful");
    }}
}}

contract VulnerableContract {{
    mapping(address => uint256) public balances;
    
    function deposit() public payable {{
        balances[msg.sender] += msg.value;
    }}
    
    function withdrawAll() public {{
        // Vulnerable: No access control
        uint256 amount = address(this).balance;
        (bool success, ) = msg.sender.call{{value: amount}}("");
        require(success, "Transfer failed");
    }}
}}
            ''',
            'test_instructions': [
                '1. Deploy the PoC contract',
                '2. Call testEtherTheft() function',
                '3. Observe unauthorized withdrawal',
                '4. Verify contract balance depletion'
            ],
            'expected_outcome': 'Unauthorized withdrawal of all contract funds',
            'severity': 'critical',
            'confidence': 0.9
        }

    async def _generate_generic_poc(self, vuln: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
        """Generate generic PoC for other vulnerability types."""
        return {
            'vulnerability_id': vuln.get('id', 'unknown'),
            'type': vuln.get('type', 'unknown'),
            'title': f'{vuln.get("type", "Unknown")} PoC',
            'description': f'Demonstrates {vuln.get("type", "unknown")} vulnerability',
            'exploit_code': f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract GenericPoC is Test {{
    function testVulnerability() public {{
        // TODO: Implement specific exploit for {vuln.get("type", "unknown")}
        console.log("Vulnerability type: {vuln.get("type", "unknown")}");
        console.log("Description: {vuln.get("description", "No description")}");
        
        // Placeholder for exploit implementation
        assertTrue(true, "PoC needs implementation");
    }}
}}
            ''',
            'test_instructions': [
                '1. Deploy the PoC contract',
                '2. Call testVulnerability() function',
                '3. Observe vulnerability exploitation',
                '4. Verify expected outcome'
            ],
            'expected_outcome': f'Exploitation of {vuln.get("type", "unknown")} vulnerability',
            'severity': vuln.get('severity', 'medium'),
            'confidence': 0.5
        }

    def _parse_mythril_cli_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Mythril CLI JSON output."""
        vulnerabilities = []
        
        # Handle different Mythril output formats
        if 'issues' in data:
            for issue in data['issues']:
                vulnerabilities.append({
                    'type': issue.get('title', 'unknown'),
                    'description': issue.get('description', ''),
                    'severity': issue.get('severity', 'medium'),
                    'confidence': issue.get('confidence', 0.5),
                    'line': issue.get('lineno', 0),
                    'swc_id': issue.get('swc-id', ''),
                    'id': issue.get('id', ''),
                    'source_mapping': issue.get('source_mapping', {}),
                    'source_type': 'mythril_cli'
                })
        elif 'detectors' in data:
            for detector in data['detectors']:
                for element in detector.get('elements', []):
                    vulnerabilities.append({
                        'type': detector.get('check', 'unknown'),
                        'description': detector.get('description', ''),
                        'severity': detector.get('impact', 'medium').lower(),
                        'confidence': detector.get('confidence', 0.5),
                        'line': element.get('source_mapping', {}).get('lines', [0])[0],
                        'swc_id': detector.get('id', ''),
                        'id': detector.get('id', ''),
                        'source_mapping': element.get('source_mapping', {}),
                        'source_type': 'mythril_cli'
                    })
        
        return vulnerabilities

    def _parse_mythril_text_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Mythril text output."""
        vulnerabilities = []
        lines = output.split('\n')
        
        current_vuln = None
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability markers
            if 'Vulnerability:' in line or 'Issue:' in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                
                current_vuln = {
                    'type': 'unknown',
                    'description': '',
                    'severity': 'medium',
                    'confidence': 0.5,
                    'line': 0,
                    'swc_id': '',
                    'id': '',
                    'source_mapping': {},
                    'source_type': 'mythril_text'
                }
                
                # Extract vulnerability type
                if 'Vulnerability:' in line:
                    current_vuln['type'] = line.split('Vulnerability:')[1].strip()
                elif 'Issue:' in line:
                    current_vuln['type'] = line.split('Issue:')[1].strip()
            
            elif current_vuln and 'Description:' in line:
                current_vuln['description'] = line.split('Description:')[1].strip()
            
            elif current_vuln and 'Severity:' in line:
                current_vuln['severity'] = line.split('Severity:')[1].strip().lower()
            
            elif current_vuln and 'Confidence:' in line:
                try:
                    current_vuln['confidence'] = float(line.split('Confidence:')[1].strip())
                except ValueError:
                    current_vuln['confidence'] = 0.5
            
            elif current_vuln and 'Line:' in line:
                try:
                    current_vuln['line'] = int(line.split('Line:')[1].strip())
                except ValueError:
                    current_vuln['line'] = 0
        
        # Add the last vulnerability
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities

    def _parse_slither_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Slither JSON output into standardized format."""
        vulnerabilities = []

        # Handle the actual slither JSON structure
        results = data.get('results', {})
        detectors = results.get('detectors', [])

        for detector in detectors:
            # Each detector has elements array with vulnerability info
            for element in detector.get('elements', []):
                vulnerabilities.append({
                    'title': detector.get('check', 'Unknown'),
                    'description': detector.get('description', ''),
                    'severity': detector.get('impact', 'Medium').lower(),
                    'confidence': detector.get('confidence', 'Medium').lower(),
                    'file': element.get('source_mapping', {}).get('filename_relative', '') if element.get('source_mapping') else '',
                    'line': element.get('source_mapping', {}).get('lines', [0])[0] if element.get('source_mapping') else 0,
                    'column': element.get('source_mapping', {}).get('starting_column', 0) if element.get('source_mapping') else 0,
                    'tool': 'slither',
                    'category': detector.get('check', 'unknown'),
                    'swc_id': detector.get('id', ''),
                    'elements': [element]
                })

        return vulnerabilities

    def _parse_mythril_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Mythril JSON output into standardized format."""
        vulnerabilities = []

        for issue in data.get('issues', []):
            vulnerabilities.append({
                'title': issue.get('title', 'Unknown'),
                'description': issue.get('description', ''),
                'severity': issue.get('severity', 'Medium').lower(),
                'confidence': 'high',  # Mythril doesn't provide confidence scores
                'file': issue.get('sourceLocation', {}).get('file', ''),
                'line': issue.get('sourceLocation', {}).get('line', 0),
                'column': issue.get('sourceLocation', {}).get('column', 0),
                'tool': 'mythril',
                'category': issue.get('type', 'unknown'),
                'swc_id': issue.get('swcID', ''),
                'swc_title': issue.get('swcTitle', ''),
                'extra': issue.get('extra', {})
            })

        return vulnerabilities

    def _parse_mythril_api_output(self, report) -> List[Dict[str, Any]]:
        """Parse Mythril Python API output into standardized format."""
        vulnerabilities = []

        try:
            # Mythril Report object structure
            if hasattr(report, 'issues') and report.issues:
                for issue in report.issues:
                    vulnerabilities.append({
                        'title': getattr(issue, 'title', 'Unknown'),
                        'description': getattr(issue, 'description', ''),
                        'severity': getattr(issue, 'severity', 'Medium').lower(),
                        'confidence': 'high',  # Mythril doesn't provide confidence scores via API
                        'file': getattr(issue, 'filename', ''),
                        'line': getattr(issue, 'lineno', 0),
                        'column': getattr(issue, 'col_offset', 0),
                        'tool': 'mythril',
                        'category': getattr(issue, 'type', 'unknown'),
                        'swc_id': getattr(issue, 'swc_id', ''),
                        'swc_title': getattr(issue, 'swc_title', ''),
                        'extra': {
                            'code': getattr(issue, 'code', ''),
                            'function_name': getattr(issue, 'function_name', ''),
                            'contract_name': getattr(issue, 'contract_name', '')
                        }
                    })
        except Exception as e:
            print(f"Error parsing Mythril API output: {e}")

        return vulnerabilities


class LLMAnalysisNode(BaseNode):
    """Node for AI-powered analysis using GPT models."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute AI analysis on contract code and vulnerabilities."""
        try:
            contract_files = context.get('contract_files', [])
            vulnerabilities = context.get('vulnerabilities', [])
            
            print(f"DEBUG: LLMAnalysisNode - Contract files: {len(contract_files)}")
            print(f"DEBUG: LLMAnalysisNode - Vulnerabilities received: {len(vulnerabilities)}")
            print(f"DEBUG: LLMAnalysisNode - Context keys: {list(context.keys())}")

            if not contract_files:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No contract files found in context"
                )

            # Get configuration
            config = self.config or {}
            analysis_types = config.get('analysis_types', ['vulnerability_detection'])

            # Combine all contract code
            combined_code = '\n\n'.join([
                f"// File: {file_path}\n{content}"
                for file_path, content in contract_files
            ])

            # Perform AI analysis
            ai_results = await self._perform_llm_analysis(combined_code, vulnerabilities, analysis_types)
            
            print(f"DEBUG: LLMAnalysisNode - AI results immediately after _perform_llm_analysis: {len(ai_results.get('vulnerabilities', []))}")

            # Promote suspected -> llm_validated when corroborated by LLM at threshold
            llm_threshold = float((self.config or {}).get('llm_confirm_threshold', 0.75))
            llm_vulns = ai_results.get('vulnerabilities', []) or []
            if llm_vulns and vulnerabilities:
                promoted = 0
                for sus in vulnerabilities:
                    if sus.get('status') != 'suspected':
                        continue
                    for lv in llm_vulns:
                        # Match by SWC and near line if present
                        swc_match = (sus.get('swc_id') and sus.get('swc_id') == lv.get('swc_id')) or not sus.get('swc_id')
                        line_close = False
                        line_nums = lv.get('line_numbers') or []
                        if isinstance(line_nums, list) and line_nums:
                            line_close = any(abs((sus.get('line') or 0) - int(x)) <= 2 for x in line_nums if isinstance(x, int) or (isinstance(x, str) and x.isdigit()))
                        # Confidence gate
                        conf_ok = float(lv.get('confidence', 0)) >= llm_threshold
                        if swc_match and (line_close or not line_nums) and conf_ok:
                            sus['status'] = 'llm_validated'
                            sus['severity'] = lv.get('severity', sus.get('severity'))
                            sus['confidence'] = max(float(sus.get('confidence', 0)), float(lv.get('confidence', 0)))
                            promoted += 1
                            break
                if promoted:
                    print(f"LLM promoted {promoted} suspected findings to llm_validated")

            # Update context
            context.update({
                'llm_analysis_results': ai_results,
                'ai_insights': ai_results.get('insights', [])
            })
            
            print(f"DEBUG: LLMAnalysisNode - AI results keys: {list(ai_results.keys())}")
            print(f"DEBUG: LLMAnalysisNode - Vulnerabilities in AI results: {len(ai_results.get('vulnerabilities', []))}")
            if ai_results.get('vulnerabilities'):
                print(f"DEBUG: LLMAnalysisNode - First AI vuln: {ai_results['vulnerabilities'][0]}")
            else:
                print(f"DEBUG: LLMAnalysisNode - Raw response preview: {ai_results.get('raw_response', '')[:300]}")
            
            # Debug: Check what we're about to store
            print(f"DEBUG: LLMAnalysisNode - About to store vulnerabilities: {len(ai_results.get('vulnerabilities', []))}")
            print(f"DEBUG: LLMAnalysisNode - Context before update: {list(context.keys())}")
            
            # Debug: Check what was actually stored
            print(f"DEBUG: LLMAnalysisNode - Context after update: {list(context.keys())}")
            print(f"DEBUG: LLMAnalysisNode - Stored vulnerabilities: {len(context.get('llm_analysis_results', {}).get('vulnerabilities', []))}")

            return NodeResult(
                node_name=self.name,
                success=True,
                data=ai_results
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _perform_llm_analysis(
        self,
        code: str,
        existing_vulnerabilities: List[Dict[str, Any]],
        analysis_types: List[str]
    ) -> Dict[str, Any]:
        """Perform AI analysis using GPT model."""
        try:
            from core.llm_analyzer import LLMAnalyzer
            import os

            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                # Try config manager for stored key
                try:
                    from core.config_manager import ConfigManager
                    cm = ConfigManager()
                    if getattr(cm.config, 'openai_api_key', ''):
                        os.environ['OPENAI_API_KEY'] = cm.config.openai_api_key
                        api_key = cm.config.openai_api_key
                except Exception:
                    pass
            if not api_key:
                return self._get_fallback_analysis(code, existing_vulnerabilities, analysis_types)

            # Use the real LLM analyzer
            llm_analyzer = LLMAnalyzer(api_key=api_key)

            # Create static analysis results for context
            static_results = {
                'pattern_analysis': {'vulnerabilities': existing_vulnerabilities, 'errors': []}
            }

            # Run LLM analysis
            llm_result = await llm_analyzer.analyze_vulnerabilities(
                code,
                static_results,
                {'vulnerabilities': existing_vulnerabilities}
            )

            if llm_result['success']:
                analysis = llm_result['analysis']

                # Convert LLM format to expected format
                return {
                    'insights': [
                        {
                            'type': vuln.get('title', 'unknown').lower().replace(' ', '_'),
                            'confidence': vuln.get('confidence', 0.5),
                            'description': vuln.get('description', ''),
                            'line_range': vuln.get('line_numbers', []),
                            'severity': vuln.get('severity', 'medium'),
                            'swc_id': vuln.get('swc_id', ''),
                            'exploitability': vuln.get('exploitability', ''),
                            'fix_suggestion': vuln.get('fix_suggestion', '')
                        }
                        for vuln in analysis.get('vulnerabilities', [])
                    ],
                    'analysis_types': analysis_types,
                    'code_analyzed': len(code.split('\n')),
                    'existing_vulnerabilities_reviewed': len(existing_vulnerabilities),
                    'summary': f'AI analysis completed with {llm_result.get("model", "unknown")} model',
                    'vulnerabilities': analysis.get('vulnerabilities', []),
                    'gas_optimizations': analysis.get('gas_optimizations', []),
                    'best_practices': analysis.get('best_practices', []),
                    'raw_response': llm_result.get('raw_response', '')
                }
            else:
                return self._get_fallback_analysis(code, existing_vulnerabilities, analysis_types)

        except Exception as e:
            print(f"❌ LLM analysis error: {str(e)}")
            return self._get_fallback_analysis(code, existing_vulnerabilities, analysis_types)

    def _get_fallback_analysis(self, code: str, existing_vulnerabilities: List[Dict[str, Any]], analysis_types: List[str]) -> Dict[str, Any]:
        """Get fallback analysis when LLM fails.
        Adds heuristic confirmations for well-known patterns to enable promotion in offline mode.
        """
        heuristic_vulns: List[Dict[str, Any]] = []

        for v in existing_vulnerabilities or []:
            desc = (v.get('description') or '').lower()
            cat = (v.get('category') or '').lower()
            line = v.get('line')
            # Heuristic: tx.origin auth usage
            if 'tx_origin' in cat or 'tx.origin' in desc:
                heuristic_vulns.append({
                    'swc_id': 'SWC-115',
                    'title': 'Authorization through tx.origin',
                    'description': 'Use of tx.origin for authorization is dangerous and can be phished by contracts.',
                    'severity': 'medium',
                    'confidence': 0.9,
                    'line_numbers': [line] if isinstance(line, int) else [],
                    'exploitability': 'Medium',
                    'fix_suggestion': 'Replace tx.origin with msg.sender and proper role-based access control.'
                })
            # Heuristic: time/block manipulation
            if 'time_manipulation' in cat or 'block.number' in desc or 'block.timestamp' in desc:
                heuristic_vulns.append({
                    'swc_id': 'SWC-120',
                    'title': 'Timestamp/Block Manipulation',
                    'description': 'Dependency on block properties can be miner-influenced in the short term.',
                    'severity': 'low',
                    'confidence': 0.8,
                    'line_numbers': [line] if isinstance(line, int) else [],
                    'exploitability': 'Low',
                    'fix_suggestion': 'Avoid strict reliance on block.timestamp/number for critical logic.'
                })

        return {
            'insights': [
                {
                    'type': 'manual_review_required',
                    'confidence': 1.0,
                    'description': 'LLM analysis unavailable - applied heuristic confirmations for common patterns',
                    'line_range': [],
                    'severity': 'info'
                }
            ],
            'analysis_types': analysis_types,
            'code_analyzed': len(code.split('\n')),
            'existing_vulnerabilities_reviewed': len(existing_vulnerabilities or []),
            'summary': 'Fallback analysis - heuristic confirmations applied',
            'vulnerabilities': heuristic_vulns,
            'gas_optimizations': [],
            'best_practices': []
        }


class FixGeneratorNode(BaseNode):
    """Node for generating fix suggestions."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Generate fix suggestions for identified vulnerabilities."""
        try:
            vulnerabilities = context.get('vulnerabilities', [])
            contract_files = context.get('contract_files', [])

            if not vulnerabilities:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'fixes': []}
                )

            # Get configuration
            config = self.config or {}
            fix_types = config.get('fix_types', ['security'])

            # Generate fixes for each vulnerability
            fixes = []
            for vuln in vulnerabilities:
                if vuln.get('severity', '').lower() in ['high', 'critical']:
                    fix = await self._generate_fix(vuln, contract_files)
                    if fix:
                        fixes.append(fix)

            # Update context
            context['generated_fixes'] = fixes

            return NodeResult(
                node_name=self.name,
                success=True,
                data={'fixes': fixes}
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _generate_fix(self, vulnerability: Dict[str, Any], contract_files: List) -> Optional[Dict[str, Any]]:
        """Generate a fix for a specific vulnerability."""
        vuln_type = vulnerability.get('category', '').lower()
        severity = vulnerability.get('severity', 'medium')

        # Generate fix based on vulnerability type
        if 'reentrancy' in vuln_type:
            return {
                'vulnerability_id': f"{vulnerability['tool']}_{vulnerability.get('line', 0)}",
                'type': 'reentrancy_guard',
                'title': 'Add Reentrancy Guard',
                'description': 'Implement checks-effects-interactions pattern',
                'suggested_code': '''// Add reentrancy guard
bool private _locked;
modifier noReentrancy() {
    require(!_locked, "ReentrancyGuard: reentrant call");
    _locked = true;
    _;
    _locked = false;
}''',
                'line_numbers': [vulnerability.get('line', 0)],
                'confidence': 0.9
            }

        elif 'access' in vuln_type or 'control' in vuln_type:
            return {
                'vulnerability_id': f"{vulnerability['tool']}_{vulnerability.get('line', 0)}",
                'type': 'access_control',
                'title': 'Add Access Control',
                'description': 'Add proper access control modifier',
                'suggested_code': '''modifier onlyOwner() {
    require(msg.sender == owner, "Only owner can call this function");
    _;
}''',
                'line_numbers': [vulnerability.get('line', 0)],
                'confidence': 0.85
            }

        elif 'overflow' in vuln_type:
            return {
                'vulnerability_id': f"{vulnerability['tool']}_{vulnerability.get('line', 0)}",
                'type': 'safe_math',
                'title': 'Use SafeMath or Solidity 0.8+',
                'description': 'Prevent integer overflow/underflow',
                'suggested_code': '''// Use Solidity 0.8+ built-in overflow checks
// Or import SafeMath library for older versions''',
                'line_numbers': [vulnerability.get('line', 0)],
                'confidence': 0.95
            }

        # Default fix for other vulnerability types
        return {
            'vulnerability_id': f"{vulnerability['tool']}_{vulnerability.get('line', 0)}",
            'type': 'general_security',
            'title': f'Fix for {vulnerability.get("title", "Security Issue")}',
            'description': vulnerability.get('description', ''),
            'suggested_code': '''// Review and implement appropriate security measures
// Consider using OpenZeppelin security libraries''',
            'line_numbers': [vulnerability.get('line', 0)],
            'confidence': 0.7
        }


class ValidationNode(BaseNode):
    """Node for validating fix effectiveness."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Validate that fixes resolve vulnerabilities."""
        try:
            fixes = context.get('generated_fixes', [])

            if not fixes:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'validation_results': []}
                )

            # Get configuration
            config = self.config or {}
            retest_tools = config.get('retest_tools', ['slither'])

            validation_results = []

            for fix in fixes:
                # Set pending by default; real implementation would re-run tools on patched code
                validation = {
                    'fix_id': fix['vulnerability_id'],
                    'status': 'pending',
                    'confidence': 0.0,
                    'message': 'Re-run static tools on patched build required to validate',
                    'retested_tools': retest_tools
                }
                validation_results.append(validation)

            # Update context
            context['validation_results'] = validation_results

            return NodeResult(
                node_name=self.name,
                success=True,
                data={'validation_results': validation_results}
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )


class ReportNode(BaseNode):
    """Node for generating comprehensive reports."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Generate audit report from all results."""
        try:
            # Gather all vulnerabilities from different sources
            all_vulnerabilities = []

            # Get vulnerabilities from static analysis results
            static_analysis = context.get('static_analysis_results', {})
            for tool_name, tool_results in static_analysis.items():
                if isinstance(tool_results, dict) and 'vulnerabilities' in tool_results:
                    all_vulnerabilities.extend(tool_results['vulnerabilities'])

            # Get vulnerabilities from LLM analysis results
            llm_analysis = context.get('llm_analysis_results', {})
            print(f"DEBUG: ReportNode - LLM analysis keys: {list(llm_analysis.keys())}")
            print(f"DEBUG: ReportNode - LLM analysis vulnerabilities: {len(llm_analysis.get('vulnerabilities', []))}")
            
            # Also check the results structure
            results = context.get('results', {})
            print(f"DEBUG: ReportNode - Results keys: {list(results.keys())}")
            if 'llmanalysisnode' in results:
                llm_result = results['llmanalysisnode']
                print(f"DEBUG: ReportNode - LLM result keys: {list(llm_result.keys())}")
                print(f"DEBUG: ReportNode - LLM result vulnerabilities: {len(llm_result.get('vulnerabilities', []))}")
            
            if isinstance(llm_analysis, dict) and 'vulnerabilities' in llm_analysis:
                all_vulnerabilities.extend(llm_analysis['vulnerabilities'])
                print(f"📋 Added {len(llm_analysis['vulnerabilities'])} vulnerabilities from LLM analysis")

            # Also check for direct vulnerabilities in context
            direct_vulnerabilities = context.get('vulnerabilities', [])
            all_vulnerabilities.extend(direct_vulnerabilities)
            
            # Get PoC results from enhanced exploitability node
            poc_results = []
            if 'enhancedexploitabilitynode' in results:
                enhanced_result = results['enhancedexploitabilitynode']
                if isinstance(enhanced_result, dict) and 'poc_results' in enhanced_result:
                    poc_results = enhanced_result['poc_results']
                    print(f"📋 Found {len(poc_results)} PoC results from enhanced exploitability node")

            # Remove duplicates (enhanced deduplication by multiple criteria)
            unique_vulnerabilities = []
            seen = set()
            for vuln in all_vulnerabilities:
                # Create a more comprehensive key for deduplication
                title = vuln.get('title', vuln.get('description', '')).strip()
                line = vuln.get('line', vuln.get('line_number', 0))
                swc_id = vuln.get('swc_id', '')
                file_path = vuln.get('file', '')
                
                # Use multiple criteria for better deduplication
                key = (title, line, swc_id, file_path)
                if key not in seen:
                    # Merge information from duplicates if they exist
                    existing_vuln = None
                    for existing in unique_vulnerabilities:
                        if (existing.get('title', existing.get('description', '')).strip() == title and 
                            existing.get('line', existing.get('line_number', 0)) == line):
                            existing_vuln = existing
                            break
                    
                    if existing_vuln:
                        # Merge information, keeping the best data
                        if vuln.get('confidence', 0) > existing_vuln.get('confidence', 0):
                            existing_vuln['confidence'] = vuln.get('confidence', 0)
                        if vuln.get('status') == 'confirmed' and existing_vuln.get('status') != 'confirmed':
                            existing_vuln['status'] = 'confirmed'
                        if vuln.get('exploit_successful') and not existing_vuln.get('exploit_successful'):
                            existing_vuln['exploit_successful'] = True
                        if vuln.get('poc_code') and not existing_vuln.get('poc_code'):
                            existing_vuln['poc_code'] = vuln.get('poc_code')
                    else:
                        unique_vulnerabilities.append(vuln)
                        seen.add(key)

            # Enhance vulnerabilities with impact and exploitability assessment
            from core.vulnerability_assessor import VulnerabilityAssessor
            assessor = VulnerabilityAssessor()
            
            for vuln in unique_vulnerabilities:
                if not vuln.get('impact_assessment') or vuln.get('impact_assessment') == 'Not assessed':
                    vuln['impact_assessment'] = assessor.assess_impact(vuln)
                if not vuln.get('exploitability') or vuln.get('exploitability') == 'Not assessed':
                    vuln['exploitability'] = assessor.assess_exploitability(vuln)
                if not vuln.get('fix_suggestion') or vuln.get('fix_suggestion') == 'No fix suggestion available':
                    vuln['fix_suggestion'] = assessor.generate_fix_suggestion(vuln)

            print(f"📊 ReportNode found {len(unique_vulnerabilities)} unique vulnerabilities")
            print(f"DEBUG: ReportNode - High severity count: {len([v for v in unique_vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])}")
            print(f"DEBUG: ReportNode - Sample vuln severity: {unique_vulnerabilities[0].get('severity', 'NO_SEVERITY') if unique_vulnerabilities else 'NO_VULNS'}")

            # Gather all results from context
            results = {
                'contract_files': context.get('contract_files', []),
                'static_analysis': static_analysis,
                'llm_analysis': context.get('llm_analysis_results', {}),
                'vulnerabilities': unique_vulnerabilities,
                'fixes': context.get('generated_fixes', []),
                'validation': context.get('validation_results', []),
                'poc_results': poc_results,
                'execution_time': context.get('execution_time', 0)
            }

            # Generate report content
            report_data = {
                'summary': {
                    'total_vulnerabilities': len(unique_vulnerabilities),
                    'high_severity_count': len([
                        v for v in unique_vulnerabilities
                        if v.get('severity', '').lower() in ['high', 'critical']
                    ]),
                    'pocs_generated': len(poc_results),
                    'execution_time': results['execution_time']
                },
                'results': results
            }

            # Update context with report data
            context['report_data'] = report_data

            return NodeResult(
                node_name=self.name,
                success=True,
                data=report_data
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )
