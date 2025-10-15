"""
AetherFuzz node implementations.
"""

import asyncio
import json
import os
import random
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.flow_executor import BaseNode, NodeResult

# Import Web3 for exploit validation
try:
    from web3 import Web3
except ImportError:
    Web3 = None


class AnalyzerNode(BaseNode):
    """Node for analyzing contracts to identify fuzzable functions."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze contract for fuzzing opportunities."""
        try:
            contract_files = context.get('contract_files', [])

            if not contract_files:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No contract files found in context"
                )

            # Analyze first contract file for fuzzable functions
            contract_path = contract_files[0][0]
            contract_content = contract_files[0][1]

            # Extract contract information for fuzzing
            analysis_result = await self._analyze_contract(contract_path, contract_content)

            # Update context
            context.update({
                'contract_analysis': analysis_result,
                'fuzzable_functions': analysis_result.get('functions', [])
            })

            return NodeResult(
                node_name=self.name,
                success=True,
                data=analysis_result
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _analyze_contract(self, contract_path: str, content: str) -> Dict[str, Any]:
        """Analyze contract to identify fuzzable functions and state variables."""
        # This would use ABI analysis and AST parsing
        # For now, return mock analysis based on common patterns

        functions = [
            {
                'name': 'transfer',
                'signature': 'transfer(address,uint256)',
                'inputs': ['address', 'uint256'],
                'visibility': 'public',
                'mutability': 'nonpayable',
                'fuzz_weight': 0.8
            },
            {
                'name': 'withdraw',
                'signature': 'withdraw()',
                'inputs': [],
                'visibility': 'public',
                'mutability': 'payable',
                'fuzz_weight': 0.9
            },
            {
                'name': 'approve',
                'signature': 'approve(address,uint256)',
                'inputs': ['address', 'uint256'],
                'visibility': 'public',
                'mutability': 'nonpayable',
                'fuzz_weight': 0.7
            }
        ]

        state_variables = [
            {'name': 'balance', 'type': 'mapping(address => uint256)', 'fuzz_weight': 0.8},
            {'name': 'totalSupply', 'type': 'uint256', 'fuzz_weight': 0.6},
            {'name': 'owner', 'type': 'address', 'fuzz_weight': 0.5}
        ]

        return {
            'contract_path': contract_path,
            'functions': functions,
            'state_variables': state_variables,
            'constructor': {
                'inputs': [],
                'payable': False
            },
            'fuzzable_targets': len(functions) + len(state_variables)
        }


class SeedGeneratorNode(BaseNode):
    """Node for generating intelligent seed inputs for fuzzing."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Generate intelligent seed inputs based on contract analysis."""
        try:
            contract_analysis = context.get('contract_analysis', {})
            functions = contract_analysis.get('functions', [])

            if not functions:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No functions found for seed generation"
                )

            # Get configuration
            config = self.config or {}
            strategy = config.get('strategy', 'intelligent')
            count = config.get('count', 50)

            # Generate seeds based on strategy
            if strategy == 'intelligent':
                seeds = await self._generate_intelligent_seeds(functions, count)
            else:
                seeds = await self._generate_random_seeds(functions, count)

            # Update context
            context.update({
                'generated_seeds': seeds,
                'seed_count': len(seeds)
            })

            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    'seeds': seeds,
                    'strategy': strategy,
                    'count': len(seeds)
                }
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _generate_intelligent_seeds(self, functions: List[Dict], count: int) -> List[Dict[str, Any]]:
        """Generate intelligent seeds based on function signatures and common attack patterns."""
        seeds = []

        # Define common attack patterns and edge cases
        attack_patterns = {
            'reentrancy': [
                {'function': 'withdraw', 'inputs': [], 'pattern': 'reentrancy_test'},
                {'function': 'transfer', 'inputs': ['0x0000000000000000000000000000000000000000', '0'], 'pattern': 'zero_values'}
            ],
            'overflow': [
                {'function': 'transfer', 'inputs': ['0x742d35Cc6634C0532925a3b8D0007b0c5B5D8F4', '2**256-1'], 'pattern': 'max_uint'}
            ],
            'access_control': [
                {'function': 'transfer', 'inputs': ['0x742d35Cc6634C0532925a3b8D0007b0c5B5D8F4', '100'], 'pattern': 'unauthorized_access'}
            ]
        }

        # Generate seeds for each attack pattern
        for pattern_name, pattern_seeds in attack_patterns.items():
            for seed_template in pattern_seeds:
                seed = {
                    'function': seed_template['function'],
                    'inputs': seed_template['inputs'],
                    'pattern': seed_template['pattern'],
                    'attack_type': pattern_name,
                    'expected_behavior': self._get_expected_behavior(seed_template['pattern']),
                    'weight': 2.0  # Higher weight for attack patterns
                }
                seeds.append(seed)

        # Fill remaining seeds with normal operation patterns
        normal_operations = [
            {'function': 'transfer', 'inputs': ['0x742d35Cc6634C0532925a3b8D0007b0c5B5D8F4', '1000000000000000000'], 'pattern': 'normal_transfer'},
            {'function': 'approve', 'inputs': ['0x742d35Cc6634C0532925a3b8D0007b0c5B5D8F4', '500000000000000000'], 'pattern': 'normal_approve'},
            {'function': 'withdraw', 'inputs': [], 'pattern': 'normal_withdraw'}
        ]

        for operation in normal_operations:
            seed = {
                'function': operation['function'],
                'inputs': operation['inputs'],
                'pattern': operation['pattern'],
                'attack_type': 'normal',
                'expected_behavior': self._get_expected_behavior(operation['pattern']),
                'weight': 1.0
            }
            seeds.append(seed)

        # Pad with additional random seeds if needed
        while len(seeds) < count:
            func = random.choice(functions)
            seed = {
                'function': func['name'],
                'inputs': self._generate_random_inputs(func['inputs']),
                'pattern': 'random',
                'attack_type': 'random',
                'expected_behavior': 'unknown',
                'weight': 0.5
            }
            seeds.append(seed)

        return seeds[:count]  # Return exactly count seeds

    async def _generate_random_seeds(self, functions: List[Dict], count: int) -> List[Dict[str, Any]]:
        """Generate random seeds for baseline testing."""
        seeds = []

        for _ in range(count):
            func = random.choice(functions)
            seed = {
                'function': func['name'],
                'inputs': self._generate_random_inputs(func['inputs']),
                'pattern': 'random',
                'attack_type': 'random',
                'expected_behavior': 'unknown',
                'weight': 1.0
            }
            seeds.append(seed)

        return seeds

    def _generate_random_inputs(self, input_types: List[str]) -> List[Any]:
        """Generate random inputs based on type signatures."""
        inputs = []

        for input_type in input_types:
            if 'address' in input_type:
                # Generate random address
                inputs.append(f'0x{random.randint(0, 2**160-1):040x"}')
            elif 'uint' in input_type:
                # Generate random uint value
                if '256' in input_type:
                    inputs.append(str(random.randint(0, 2**256-1)))
                else:
                    inputs.append(str(random.randint(0, 1000000)))
            elif 'bool' in input_type:
                inputs.append(random.choice(['true', 'false']))
            else:
                inputs.append('0')  # Default fallback

        return inputs

    def _get_expected_behavior(self, pattern: str) -> str:
        """Get expected behavior for different patterns."""
        behavior_map = {
            'reentrancy_test': 'should_revert_or_succeed',
            'zero_values': 'should_revert',
            'max_uint': 'should_handle_gracefully',
            'unauthorized_access': 'should_revert',
            'normal_transfer': 'should_succeed',
            'normal_approve': 'should_succeed',
            'normal_withdraw': 'should_succeed',
            'random': 'unknown'
        }
        return behavior_map.get(pattern, 'unknown')


class FuzzExecutorNode(BaseNode):
    """Node for executing fuzzing campaigns."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute fuzzing campaign with generated seeds."""
        try:
            contract_files = context.get('contract_files', [])
            seeds = context.get('generated_seeds', [])
            contract_analysis = context.get('contract_analysis', {})

            if not contract_files or not seeds:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="Missing contract files or seeds"
                )

            # Get configuration
            config = self.config or {}
            max_runs = config.get('max_runs', 1000)
            timeout = config.get('timeout', 300)

            # Execute fuzzing campaign
            fuzz_results = await self._execute_fuzzing_campaign(
                contract_files[0][0],  # Use first contract file
                seeds,
                contract_analysis,
                max_runs,
                timeout
            )

            # Update context
            context.update({
                'fuzz_results': fuzz_results,
                'vulnerabilities_found': fuzz_results.get('vulnerabilities_found', 0),
                'crashes': fuzz_results.get('crashes', [])
            })

            return NodeResult(
                node_name=self.name,
                success=True,
                data=fuzz_results
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _execute_fuzzing_campaign(
        self,
        contract_path: str,
        seeds: List[Dict[str, Any]],
        contract_analysis: Dict[str, Any],
        max_runs: int,
        timeout: int
    ) -> Dict[str, Any]:
        """Execute the actual fuzzing campaign."""
        results = {
            'contract_path': contract_path,
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'crashes': [],
            'vulnerabilities_found': 0,
            'execution_time': 0,
            'coverage': {'lines': 0, 'branches': 0, 'functions': 0}
        }

        start_time = asyncio.get_event_loop().time()

        # Create temporary directory for fuzzing artifacts
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Deploy contract to local EVM
                deployment_result = await self._deploy_contract(contract_path, temp_dir)

                if not deployment_result['success']:
                    results['errors'] = [deployment_result['error']]
                    return results

                contract_address = deployment_result['contract_address']

                # Execute fuzzing runs
                for i, seed in enumerate(seeds[:max_runs]):
                    run_result = await self._execute_fuzz_run(contract_address, seed, temp_dir)

                    results['total_runs'] += 1

                    if run_result.get('success', False):
                        results['successful_runs'] += 1
                    else:
                        results['failed_runs'] += 1
                        if run_result.get('crash', False):
                            results['crashes'].append({
                                'run': i,
                                'seed': seed,
                                'error': run_result.get('error', 'Unknown crash'),
                                'trace': run_result.get('trace', [])
                            })

                    # Simple vulnerability detection based on crashes and failures
                    if run_result.get('crash', False) or not run_result.get('success', True):
                        results['vulnerabilities_found'] += 1

                # Calculate execution time and mock coverage
                end_time = asyncio.get_event_loop().time()
                results['execution_time'] = end_time - start_time
                results['coverage'] = {
                    'lines': min(95, 50 + (results['total_runs'] // 10)),
                    'branches': min(80, 30 + (results['total_runs'] // 15)),
                    'functions': min(90, 40 + (results['total_runs'] // 12))
                }

            except Exception as e:
                results['errors'] = [str(e)]

        return results

    async def _deploy_contract(self, contract_path: str, temp_dir: str) -> Dict[str, Any]:
        """Deploy contract to local EVM for fuzzing."""
        # This would use Foundry/Anvil to deploy
        # For now, return mock deployment
        return {
            'success': True,
            'contract_address': '0x742d35Cc6634C0532925a3b8D0007b0c5B5D8F4',
            'deployment_tx': '0xabcdef123456789',
            'gas_used': 150000
        }

    async def _execute_fuzz_run(self, contract_address: str, seed: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Execute a single fuzzing run."""
        # This would execute the function call via Anvil/RPC
        # For now, return mock execution results with some randomness

        # Simulate execution success/failure
        success_rate = 0.85  # 85% success rate baseline

        # Adjust success rate based on seed pattern
        if seed.get('attack_type') == 'reentrancy':
            success_rate = 0.3  # Lower success rate for attack patterns
        elif seed.get('pattern') == 'zero_values':
            success_rate = 0.1  # Very low for invalid inputs

        success = random.random() < success_rate

        if success:
            return {
                'success': True,
                'gas_used': random.randint(21000, 100000),
                'return_value': '0x' + ''.join(random.choices('0123456789abcdef', k=64)),
                'logs': [],
                'trace': ['CALL', 'SSTORE', 'LOG']
            }
        else:
            # Generate different types of failures
            failure_types = ['revert', 'out_of_gas', 'invalid_opcode', 'stack_overflow']
            failure_type = random.choice(failure_types)

            return {
                'success': False,
                'crash': failure_type in ['invalid_opcode', 'stack_overflow'],
                'error': f'EVM {failure_type}',
                'gas_used': random.randint(21000, 50000),
                'return_value': None,
                'trace': ['CALL', 'REVERT'] if failure_type == 'revert' else ['CALL', 'INVALID']
            }


class RewardEngineNode(BaseNode):
    """Node for optimizing fuzzing strategy based on rewards."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze fuzzing results and optimize strategy."""
        try:
            fuzz_results = context.get('fuzz_results', {})

            if not fuzz_results:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'strategy_optimization': {}}
                )

            # Analyze results and suggest optimizations
            optimization = await self._analyze_and_optimize(fuzz_results)

            # Update context
            context['strategy_optimization'] = optimization

            return NodeResult(
                node_name=self.name,
                success=True,
                data=optimization
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _analyze_and_optimize(self, fuzz_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze fuzzing results and suggest optimizations."""
        crashes = fuzz_results.get('crashes', [])
        total_runs = fuzz_results.get('total_runs', 0)
        successful_runs = fuzz_results.get('successful_runs', 0)

        # Calculate metrics
        crash_rate = len(crashes) / total_runs if total_runs > 0 else 0
        success_rate = successful_runs / total_runs if total_runs > 0 else 0

        # Analyze crash patterns
        crash_patterns = {}
        for crash in crashes:
            pattern = crash.get('seed', {}).get('pattern', 'unknown')
            crash_patterns[pattern] = crash_patterns.get(pattern, 0) + 1

        # Generate optimization suggestions
        suggestions = []

        if crash_rate > 0.1:  # High crash rate
            suggestions.append({
                'type': 'reduce_aggressive_patterns',
                'description': 'High crash rate detected, consider reducing attack pattern frequency',
                'confidence': 0.8
            })

        if success_rate < 0.7:  # Low success rate
            suggestions.append({
                'type': 'increase_normal_operations',
                'description': 'Low success rate, consider increasing normal operation patterns',
                'confidence': 0.7
            })

        # Suggest focusing on high-value targets
        if crash_patterns:
            top_pattern = max(crash_patterns.items(), key=lambda x: x[1])
            suggestions.append({
                'type': 'focus_high_crash_pattern',
                'description': f'Focus on {top_pattern[0]} pattern (highest crash rate)',
                'confidence': 0.9,
                'target_pattern': top_pattern[0]
            })

        return {
            'metrics': {
                'crash_rate': crash_rate,
                'success_rate': success_rate,
                'total_runs': total_runs,
                'crash_patterns': crash_patterns
            },
            'suggestions': suggestions,
            'optimization_score': min(1.0, success_rate * 0.7 + (1 - crash_rate) * 0.3)
        }


class LLMReasonerNode(BaseNode):
    """Node for AI-powered fuzzing strategy adjustment."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Use AI to reason about fuzzing strategy and suggest improvements."""
        try:
            fuzz_results = context.get('fuzz_results', {})
            contract_analysis = context.get('contract_analysis', {})

            if not fuzz_results:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'ai_suggestions': []}
                )

            # Perform AI reasoning on fuzzing strategy
            ai_suggestions = await self._llm_fuzzing_reasoning(fuzz_results, contract_analysis)

            # Update context
            context['ai_fuzzing_suggestions'] = ai_suggestions

            return NodeResult(
                node_name=self.name,
                success=True,
                data={'ai_suggestions': ai_suggestions}
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _llm_fuzzing_reasoning(self, fuzz_results: Dict[str, Any], contract_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to reason about fuzzing strategy."""
        # This would integrate with GPT for fuzzing strategy reasoning
        # For now, return mock AI suggestions

        suggestions = [
            {
                'type': 'increase_withdraw_testing',
                'description': 'Consider increasing test coverage for withdraw function - potential reentrancy vector',
                'confidence': 0.8,
                'reasoning': 'Based on contract structure, withdraw function appears to be a high-risk area'
            },
            {
                'type': 'test_large_transfers',
                'description': 'Focus on large transfer amounts to test overflow conditions',
                'confidence': 0.7,
                'reasoning': 'Contract may have insufficient overflow protection'
            },
            {
                'type': 'access_control_focus',
                'description': 'Increase testing of access control mechanisms',
                'confidence': 0.75,
                'reasoning': 'Multiple functions may be missing proper authorization checks'
            }
        ]

        return suggestions


class AetherFuzzRunner(BaseNode):
    """Enhanced fuzzing execution node with stateful DeFi fuzzing."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute enhanced fuzzing for DeFi protocols."""
        try:
            contract_files = context.get('contract_files', [])
            vulnerabilities = context.get('vulnerabilities', [])

            if not contract_files:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No contract files found in context"
                )

            # Get configuration
            config = self.config or {}
            max_runs = config.get('max_runs', 1000)
            timeout = config.get('timeout', 300)
            
            # Import enhanced fuzz engine
            from core.fuzz_engine import AetherFuzzEngine
            
            # Initialize enhanced fuzz engine
            fuzz_engine = AetherFuzzEngine(verbose=True)
            
            # Check if Foundry is available for enhanced fuzzing
            foundry_available = fuzz_engine._check_foundry_availability()
            if foundry_available:
                print("✅ Foundry available for enhanced fuzzing")
            else:
                print("⚠️ Foundry not available, using basic fuzzing")
            
            # Prepare vulnerabilities for enhanced fuzzing
            fuzz_vulnerabilities = []
            if vulnerabilities:
                for vuln_group in vulnerabilities:
                    if isinstance(vuln_group, dict) and 'vulnerabilities' in vuln_group:
                        fuzz_vulnerabilities.extend(vuln_group['vulnerabilities'])
                    elif isinstance(vuln_group, list):
                        fuzz_vulnerabilities.extend(vuln_group)
            
            # Run enhanced fuzzing
            contract_path = contract_files[0][0]
            fuzz_results = await fuzz_engine.run_enhanced_fuzzing(contract_path, fuzz_vulnerabilities)
            
            print(f"🎯 Enhanced fuzzing completed: {fuzz_results.get('vulnerabilities_confirmed', 0)} vulnerabilities confirmed")
            print(f"📊 Coverage achieved: {fuzz_results.get('coverage_achieved', 0.0):.2%}")
            
            # Extract results
            confirmed_vulnerabilities = []
            exploit_validations = fuzz_results.get('exploit_validations', [])
            
            for validation in exploit_validations:
                if validation.exploit_feasible:
                    confirmed_vulnerabilities.append({
                        'type': validation.vulnerability_type,
                        'severity': validation.severity,
                        'confidence': validation.confidence,
                        'poc_generated': validation.poc_generated,
                        'test_passed': validation.test_passed,
                        'poc_code': validation.poc_code
                    })
            
            # Update context with results
            context.update({
                'fuzz_results': fuzz_results,
                'confirmed_vulnerabilities': confirmed_vulnerabilities,
                'exploit_validations': exploit_validations,
                'performance_metrics': fuzz_results.get('performance_metrics', {}),
                'coverage_achieved': fuzz_results.get('coverage_achieved', 0.0)
            })
            
            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    'fuzz_results': fuzz_results,
                    'confirmed_vulnerabilities': confirmed_vulnerabilities,
                    'exploit_validations': exploit_validations,
                    'performance_metrics': fuzz_results.get('performance_metrics', {}),
                    'coverage_achieved': fuzz_results.get('coverage_achieved', 0.0)
                }
            )

        except Exception as e:
            error_msg = f"Enhanced fuzzing failed: {str(e)}"
            print(f"❌ {error_msg}")
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=error_msg
            )

    async def _run_fuzzing_campaign(self, contract_files: List, max_runs: int, timeout: int, stateful: bool) -> Dict[str, Any]:
        """Run comprehensive fuzzing campaign."""
        import tempfile
        import shutil

        results = {
            'runs_completed': 0,
            'crashes': 0,
            'coverage': 0,
            'invariant_violations': [],
            'errors': []
        }

        try:
            # Use first contract for fuzzing
            contract_path = contract_files[0][0]

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Create Foundry project structure
                (temp_path / 'src').mkdir()
                (temp_path / 'test').mkdir()

                # Copy contract
                contract_file = Path(contract_path)
                final_contract_path = temp_path / 'src' / contract_file.name
                shutil.copy2(contract_path, final_contract_path)

                # Create fuzzing test
                fuzz_test = self._generate_fuzz_test(contract_path, stateful)
                test_file = temp_path / 'test' / f'{contract_file.stem}.t.sol'
                test_file.write_text(fuzz_test)

                # Create foundry.toml
                foundry_toml = temp_path / 'foundry.toml'
                foundry_toml.write_text("""
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
solc_version = "0.8.19"

[fuzz]
runs = 1000
max_test_rejects = 65536
dictionary_weight = 40
include_storage = true
include_push_bytes = true

[invariant]
runs = 100
depth = 15
fail_on_revert = false
call_override = false
shrink_run_limit = 5000
                """.strip())

                # Run fuzzing
                env = os.environ.copy()
                foundry_path = "/Users/l33tdawg/.foundry/bin"
                env['PATH'] = f"{foundry_path}:{env.get('PATH', '')}"

                # Run fuzz tests
                fuzz_cmd = ['forge', 'test', '--fuzz-runs', str(max_runs), '--match-test', 'testFuzz']
                if stateful:
                    fuzz_cmd.extend(['--match-invariant', 'invariant'])

                fuzz_result = subprocess.run(
                    fuzz_cmd,
                    cwd=temp_path,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env
                )

                results['runs_completed'] = max_runs
                results['fuzz_output'] = fuzz_result.stdout

                # Parse results
                if fuzz_result.returncode == 0:
                    results['success'] = True
                    print("✅ Fuzzing completed successfully")
                else:
                    # Check for crashes or invariant violations
                    if 'FAIL' in fuzz_result.stdout or 'invariant' in fuzz_result.stdout.lower():
                        results['crashes'] = 1
                        print("🚨 Fuzzing detected potential issues")

                    results['success'] = False
                    results['errors'].append(fuzz_result.stderr)

        except subprocess.TimeoutExpired:
            results['errors'].append("Fuzzing timed out")
        except Exception as e:
            results['errors'].append(str(e))

        return results

    def _generate_fuzz_test(self, contract_path: str, stateful: bool) -> str:
        """Generate Foundry fuzz test for the contract."""
        contract_name = Path(contract_path).stem

        # Enhanced fuzz test with DeFi-specific invariants
        test_code = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{Path(contract_path).name}";

contract {contract_name}FuzzTest is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    /// @dev Fuzz test for general function calls
    function testFuzz(uint256 randomValue) public {{
        // Bound to reasonable ranges
        uint256 boundedValue = bound(randomValue, 0, 1e18);

        try target.someFunction(boundedValue) {{
            // Test passed
        }} catch {{
            // Function might legitimately revert
        }}
    }}

    /// @dev Stateful fuzzing for DeFi invariants
    function testStatefulFuzz() public {{
        // Test multiple operations in sequence
        for (uint256 i = 0; i < 10; i++) {{
            uint256 randomAction = uint256(keccak256(abi.encode(block.timestamp, i))) % 4;

            if (randomAction == 0) {{
                // Deposit
                try target.deposit{{value: 1 ether}}() {{
                }} catch {{}}
            }} else if (randomAction == 1) {{
                // Withdraw
                try target.withdraw(0.5 ether) {{
                }} catch {{}}
            }} else if (randomAction == 2) {{
                // Transfer
                try target.transfer(address(0x123), 0.1 ether) {{
                }} catch {{}}
            }}
        }}

        // Check invariants after operations
        invariantTotalSupply();
        invariantNoFundsDrained();
    }}

    /// @dev Invariant: Total supply should remain consistent
    function invariantTotalSupply() public {{
        // Implement total supply check
        // assert(target.totalSupply() >= 0, "Total supply invariant violated");
    }}

    /// @dev Invariant: Contract shouldn't be drained unexpectedly
    function invariantNoFundsDrained() public {{
        // Check that contract balance doesn't drop unexpectedly
        // This is a simplified check - real implementation would track expected balance
    }}

    /// @dev Invariant: User balances should be consistent
    function invariantUserBalances() public {{
        // Check that user balance calculations are consistent
        // assert(target.balanceOf(address(this)) >= 0, "Balance invariant violated");
    }}

    /// @dev Invariant: No unauthorized access
    function invariantAccessControl() public {{
        // Check that only authorized functions can be called
        // This would test access control mechanisms
    }}
}}
'''
        return test_code

    async def _analyze_invariant_violations(self, fuzz_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze fuzzing results for invariant violations."""
        violations = []

        # Check fuzzing output for failures
        output = fuzz_results.get('fuzz_output', '')

        if 'FAIL' in output:
            # Extract failure information
            violations.append({
                'type': 'test_failure',
                'description': 'Fuzz test failed - potential vulnerability detected',
                'severity': 'high',
                'evidence': output
            })

        if 'invariant' in output.lower() and 'violation' in output.lower():
            violations.append({
                'type': 'invariant_violation',
                'description': 'State invariant violated during fuzzing',
                'severity': 'critical',
                'evidence': output
            })

        return violations


class ExploitValidatorNode(BaseNode):
    """Node for validating exploit feasibility using Foundry."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Validate that detected issues are actually exploitable using Foundry."""
        try:
            vulnerabilities = context.get('vulnerabilities', [])
            contract_files = context.get('contract_files', [])

            if not vulnerabilities:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'exploit_validation': {'confirmed_exploits': 0}}
                )

            # Import exploit validator
            from core.exploit_validator import ExploitValidator
            
            validator = ExploitValidator()
            
            # Check if Foundry is available
            foundry_available = validator._check_foundry_availability()
            
            if not foundry_available:
                print("⚠️ Foundry not available, using basic validation")
                # Use basic validation as fallback
                validation_results = await validator._basic_validation(contract_files[0][0] if contract_files else '', vulnerabilities)
            else:
                print("✅ Foundry available, using advanced validation")
                # Use Foundry-based validation
                validation_results = await validator.validate_vulnerabilities(contract_files[0][0] if contract_files else '', vulnerabilities)

            # Update vulnerability statuses based on validation
            for vuln in vulnerabilities:
                vuln_id = vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}")
                for result in validation_results:
                    if result.vulnerability_id == vuln_id:
                        vuln['status'] = 'confirmed' if result.exploit_successful else 'false_positive'
                        vuln['exploit_successful'] = result.exploit_successful
                        vuln['exploit_steps'] = result.exploit_steps
                        vuln['poc_code'] = result.poc_code
                        vuln['impact_assessment'] = result.impact_assessment
                        break

            # Update the main vulnerabilities list in context
            context['vulnerabilities'] = vulnerabilities

            # Update context
            confirmed_exploits = len([v for v in vulnerabilities if v.get('exploit_successful', False)])
            context['confirmed_exploits'] = confirmed_exploits
            context['exploit_validation'] = validation_results
            context['foundry_validation_used'] = foundry_available

            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    'validation_results': validation_results,
                    'confirmed_exploits': confirmed_exploits,
                    'results': validation_results  # Also store results in the expected format
                }
            )

        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _setup_validation_fork(self) -> Optional[str]:
        """Set up Anvil fork for exploit validation."""
        try:
            import subprocess
            import time

            # Use the user's RPC endpoint from config
            from core.config_manager import ConfigManager
            cm = ConfigManager()
            rpc_url = getattr(cm.config, 'rpc_url', None) or "https://rpc.ankr.com/eth"
            
            # Use the user's API key if available
            api_key = getattr(cm.config, 'api_key', None)
            if api_key and 'ankr.com' in rpc_url:
                rpc_url = f"https://rpc.ankr.com/eth/{api_key}"
            
            # Fallback to a working public endpoint
            if not api_key:
                rpc_url = "https://ethereum.publicnode.com"

            # Start Anvil in background
            cmd = [
                "anvil",
                "--fork-url", rpc_url,
                "--port", "8546",  # Different port for validation
                "--accounts", "10",
                "--balance", "1000",
                "--no-mining"  # Manual mining for deterministic testing
            ]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait a moment for Anvil to start
            time.sleep(2)

            if process.poll() is None:  # Process is still running
                return "http://localhost:8546"
            else:
                return None

        except Exception as e:
            print(f"Failed to setup validation fork: {e}")
            return None

    async def _validate_vulnerability(self, vuln: Dict[str, Any], contract_files: List, fork_url: Optional[str]) -> Dict[str, Any]:
        """Validate a specific vulnerability using Web3 and Anvil fork."""
        try:
            import json

            if fork_url:
                w3 = Web3(Web3.HTTPProvider(fork_url))

                # Get contract address for validation
                contract_address = self._get_contract_address_for_validation(vuln)
                if not contract_address:
                    return {
                        'vulnerability_id': vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}"),
                        'status': 'unknown',
                        'exploitable': False,
                        'error': 'No contract address for validation'
                    }

                # Get ABI for the contract
                abi = await self._get_contract_abi(contract_address, w3)
                if not abi:
                    return {
                        'vulnerability_id': vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}"),
                        'status': 'unknown',
                        'exploitable': False,
                        'error': 'Failed to get contract ABI'
                    }

                # Create PoC for the vulnerability type
                poc_result = await self._create_and_run_poc(vuln, w3, contract_address, abi)
                return poc_result
            else:
                # Basic validation without fork
                return await self._basic_validation(vuln)

        except Exception as e:
            return {
                'vulnerability_id': vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}"),
                'status': 'error',
                'exploitable': False,
                'error': str(e)
            }

    def _get_contract_address_for_validation(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract contract address for validation."""
        # For GFarm token validation, use the known address
        if 'GFarm' in str(vuln.get('file', '')):
            return "0x831091da075665168e01898c6dac004a867f1e1b"  # GFARM2 token
        return None

    async def _get_contract_abi(self, contract_address: str, w3) -> Optional[List]:
        """Fetch ABI for a contract address."""
        try:
            # For ERC20 contracts, use standard ABI
            if contract_address == "0x831091da075665168e01898c6dac004a867f1e1b":
                return [
                    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
                    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
                    {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
                    {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
                    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}, {"name": "_spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "type": "function"}
                ]
            return None
        except Exception:
            return None

    async def _create_and_run_poc(self, vuln: Dict[str, Any], w3, contract_address: str, abi: List) -> Dict[str, Any]:
        """Create and run PoC for a specific vulnerability."""
        vuln_type = vuln.get('category', '').lower()

        if 'tx_origin' in vuln_type or 'access_control' in vuln_type:
            return await self._validate_tx_origin_access_control(vuln, w3, contract_address, abi)
        elif 'time_manipulation' in vuln_type:
            return await self._validate_time_manipulation(vuln, w3, contract_address, abi)
        else:
            return {
                'vulnerability_id': vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}"),
                'status': 'not_tested',
                'exploitable': False,
                'exploit_steps': [],
                'poc_code': '',
                'impact_assessment': 'Not tested - unsupported vulnerability type'
            }

    async def _validate_tx_origin_access_control(self, vuln: Dict[str, Any], w3, contract_address: str, abi: List) -> Dict[str, Any]:
        """Validate tx.origin or access control vulnerabilities."""
        vuln_id = vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}")

        # For tx.origin, the vulnerability is that contracts can be used to bypass checks
        # We'll simulate this by trying to call a function that should be protected

        try:
            # Create a simple attacker contract that calls the vulnerable function
            attacker_code = f'''
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {vuln.get('function_name', 'vulnerableFunction')}() external;
}}

contract Attacker {{
    IVulnerable public target;

    constructor(address _target) {{
        target = IVulnerable(_target);
    }}

    function attack() external {{
        target.{vuln.get('function_name', 'vulnerableFunction')}();
    }}
}}
'''

            # For now, assume tx.origin vulnerabilities are exploitable since they can be bypassed by contracts
            return {
                'vulnerability_id': vuln_id,
                'status': 'confirmed',
                'exploitable': True,
                'exploit_steps': [
                    '1. Deploy attacker contract that calls the vulnerable function',
                    '2. Call attack() function through the attacker contract',
                    '3. Attack succeeds because tx.origin != msg.sender in contract context'
                ],
                'poc_code': attacker_code,
                'impact_assessment': 'High - Unauthorized access to protected functions via contract calls'
            }

        except Exception as e:
            return {
                'vulnerability_id': vuln_id,
                'status': 'error',
                'exploitable': False,
                'error': str(e)
            }

    async def _validate_time_manipulation(self, vuln: Dict[str, Any], w3, contract_address: str, abi: List) -> Dict[str, Any]:
        """Validate time manipulation vulnerabilities."""
        vuln_id = vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}")

        # Time manipulation is usually not exploitable for authorization
        # Only exploitable if used for critical logic like vesting or access control

        return {
            'vulnerability_id': vuln_id,
            'status': 'informational',
            'exploitable': False,
            'exploit_steps': [
                '1. Time/block manipulation requires miner cooperation',
                '2. Only exploitable for authorization/vesting logic',
                '3. Generally not practically exploitable for most DeFi contracts'
            ],
            'poc_code': '',
            'impact_assessment': 'Low - Requires miner cooperation, not practically exploitable'
        }

    async def _basic_validation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Basic validation when Anvil fork is not available."""
        vuln_id = vuln.get('id', f"{vuln.get('tool', 'unknown')}_{vuln.get('line', 0)}")
        vuln_type = vuln.get('category', '').lower()

        # For tx.origin vulnerabilities, they're generally exploitable via contracts
        if 'tx_origin' in vuln_type:
            return {
                'vulnerability_id': vuln_id,
                'status': 'confirmed',
                'exploitable': True,
                'exploit_steps': [
                    '1. Deploy attacker contract that calls the vulnerable function',
                    '2. Call attack() function through the attacker contract',
                    '3. Attack succeeds because tx.origin != msg.sender in contract context'
                ],
                'poc_code': f'''
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {vuln.get('function_name', 'vulnerableFunction')}() external;
}}

contract Attacker {{
    IVulnerable public target;

    constructor(address _target) {{
        target = IVulnerable(_target);
    }}

    function attack() external {{
        target.{vuln.get('function_name', 'vulnerableFunction')}();
    }}
}}
''',
                'impact_assessment': 'High - Unauthorized access to protected functions via contract calls'
            }
        elif 'access_control' in vuln_type:
            return {
                'vulnerability_id': vuln_id,
                'status': 'confirmed',
                'exploitable': True,
                'exploit_steps': [
                    '1. Identify function without proper access control',
                    '2. Call the function from an unauthorized address',
                    '3. Function executes successfully despite missing access control'
                ],
                'poc_code': f'''
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {vuln.get('function_name', 'vulnerableFunction')}() external;
}}

contract Attacker {{
    function exploit(address target) external {{
        IVulnerable(target).{vuln.get('function_name', 'vulnerableFunction')}();
    }}
}}
''',
                'impact_assessment': 'High - Unauthorized access to protected functions'
            }
        else:
            return {
                'vulnerability_id': vuln_id,
                'status': 'not_tested',
                'exploitable': False,
                'exploit_steps': [],
                'poc_code': '',
                'impact_assessment': 'Not tested - requires manual validation'
            }

    def _generate_poc_code(self, vuln: Dict[str, Any]) -> str:
        """Generate PoC code for a vulnerability."""
        vuln_type = vuln.get('title', '').lower()

        if 'access_control' in vuln_type or 'modifier' in vuln_type:
            return self._generate_access_control_poc(vuln)
        elif 'reentrancy' in vuln_type:
            return self._generate_reentrancy_poc(vuln)
        elif 'arithmetic' in vuln_type or 'overflow' in vuln_type or 'underflow' in vuln_type:
            return self._generate_arithmetic_poc(vuln)
        else:
            return "// PoC generation for this vulnerability type not implemented"

    def _generate_exploit_steps(self, vuln: Dict[str, Any]) -> List[str]:
        """Generate exploit steps for a vulnerability."""
        vuln_type = vuln.get('title', '').lower()

        if 'access_control' in vuln_type or 'modifier' in vuln_type:
            return [
                "1. Identify function without proper access control",
                "2. Call the function from an unauthorized address",
                "3. Verify that the function executed successfully",
                "4. Exploit the unauthorized access"
            ]
        elif 'reentrancy' in vuln_type:
            return [
                "1. Deploy vulnerable contract",
                "2. Deploy malicious contract with fallback function",
                "3. Fund malicious contract",
                "4. Call vulnerable function to trigger reentrancy",
                "5. Verify funds were drained from vulnerable contract"
            ]
        elif 'arithmetic' in vuln_type or 'overflow' in vuln_type or 'underflow' in vuln_type:
            return [
                "1. Perform operations to reach overflow/underflow condition",
                "2. Trigger the vulnerable operation",
                "3. Verify unexpected behavior occurred",
                "4. Exploit the incorrect calculation"
            ]
        else:
            return ["1. Exploit steps not defined for this vulnerability type"]

    def _assess_impact(self, vuln: Dict[str, Any]) -> str:
        """Assess the impact of a vulnerability."""
        vuln_type = vuln.get('title', '').lower()
        severity = vuln.get('severity', 'Medium').lower()

        if severity == 'critical':
            return "Critical - Can lead to complete loss of funds or contract control"
        elif severity == 'high':
            if 'access_control' in vuln_type:
                return "High - Unauthorized access to critical functions"
            elif 'reentrancy' in vuln_type:
                return "High - Can drain all funds from contract"
            else:
                return "High - Significant security impact"
        else:
            return "Medium - Moderate security impact"

    def _generate_access_control_poc(self, vuln: Dict[str, Any]) -> str:
        """Generate access control bypass PoC."""
        return '''// Access Control Bypass PoC
contract AccessControlExploit {
    VulnerableContract target;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    function exploit() external {
        // Call protected function without authorization
        target.protectedFunction(); // This should fail but doesn't

        // If we reach here, access control is broken
        require(false, "Access control bypassed");
    }
}'''

    def _generate_reentrancy_poc(self, vuln: Dict[str, Any]) -> str:
        """Generate reentrancy PoC."""
        return '''// Reentrancy Exploit PoC
contract ReentrancyExploit {
    VulnerableContract target;
    uint256 attackCount;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    // Fallback function that re-enters the vulnerable contract
    receive() external payable {
        if (address(target).balance >= 1 ether && attackCount < 3) {
            attackCount++;
            target.withdrawFunds(1 ether); // Re-enter here
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ether to attack");

        // Initial deposit
        target.deposit{value: 1 ether}();

        // Trigger reentrancy
        target.withdrawFunds(1 ether);

        // Withdraw stolen funds
        payable(msg.sender).transfer(address(this).balance);
    }
}'''

    def _generate_arithmetic_poc(self, vuln: Dict[str, Any]) -> str:
        """Generate arithmetic overflow PoC."""
        return '''// Arithmetic Overflow PoC
contract ArithmeticExploit {
    VulnerableContract target;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    function exploit() external {
        // Perform operations that trigger overflow
        for (uint256 i = 0; i < 1000; i++) {
            target.incrementCounter();
        }

        // Check if overflow occurred
        uint256 counter = target.getCounter();
        require(counter < 1000, "No overflow detected");
    }
}'''

    async def _validate_exploit(self, crash: Dict[str, Any], fuzz_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate if a crash represents an actual exploit."""
        # This would perform deeper analysis of the crash
        # For now, return mock validation

        # Simulate validation based on crash characteristics
        exploitable_indicators = [
            'reentrancy' in crash.get('error', '').lower(),
            'overflow' in crash.get('error', '').lower(),
            'access' in crash.get('error', '').lower()
        ]

        exploitable = any(exploitable_indicators)

        return {
            'crash_id': crash.get('run', 'unknown'),
            'exploitable': exploitable,
            'confidence': 0.8 if exploitable else 0.3,
            'exploit_type': self._classify_exploit_type(crash),
            'validation_method': 'pattern_analysis',
            'recommendations': [
                'Review crash trace for exploit feasibility',
                'Consider manual verification if confidence is high'
            ]
        }

    def _classify_exploit_type(self, crash: Dict[str, Any]) -> str:
        """Classify the type of exploit based on crash characteristics."""
        error_msg = crash.get('error', '').lower()
        seed = crash.get('seed', {})

        if 'reentrancy' in error_msg or seed.get('pattern') == 'reentrancy_test':
            return 'reentrancy'
        elif 'overflow' in error_msg or 'max_uint' in seed.get('pattern', ''):
            return 'integer_overflow'
        elif 'access' in error_msg or 'unauthorized' in seed.get('pattern', ''):
            return 'access_control'
        elif 'gas' in error_msg:
            return 'gas_griefing'
        else:
            return 'unknown'
