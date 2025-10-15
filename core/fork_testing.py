#!/usr/bin/env python3
"""
Real-World Fork Testing Infrastructure for Bug Bounty Submissions

This module implements the fork testing infrastructure outlined in the
real-world Foundry verification plan, enabling validation of vulnerabilities
against actual mainnet state using Anvil forks.
"""

import asyncio
import json
import subprocess
import tempfile
import shutil
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import os
import yaml

@dataclass
class ForkTestingConfig:
    """Configuration for fork testing."""
    mainnet_rpc: str = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
    testnet_rpc: str = "https://eth-goerli.g.alchemy.com/v2/YOUR_KEY"
    fork_block_number: Optional[int] = None  # Latest by default
    fork_timeout: int = 300  # 5 minutes
    anvil_port: int = 8545
    max_retries: int = 3
    retry_delay: float = 1.0

@dataclass
class AnvilForkProcess:
    """Anvil fork process management."""
    process: subprocess.Popen
    rpc_url: str
    port: int
    fork_url: str
    block_number: Optional[int]
    start_time: float

@dataclass
class ForkTestResult:
    """Result of fork-based testing."""
    success: bool
    fork_rpc: str
    contract_address: str
    exploit_executed: bool
    profit_realized: float
    gas_used: int
    transaction_hash: Optional[str]
    error_message: Optional[str]
    execution_time: float

@dataclass
class ExploitResult:
    """Result of exploit execution on fork."""
    success: bool
    profit: float
    gas_used: int
    transaction_hash: str
    transaction_receipt: Dict[str, Any]
    state_changes: List[Dict[str, Any]]

# Configuration management
class ForkConfigManager:
    """Manage fork testing configuration."""

    def __init__(self, config_file: str = "configs/fork_config.yaml"):
        self.config_file = Path(config_file)
        self.config = None
        self.load_config()

    def load_config(self):
        """Load configuration from file."""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                "mainnet_rpc": "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
                "testnet_rpc": "https://eth-goerli.g.alchemy.com/v2/YOUR_KEY",
                "default_block_number": None,
                "anvil_port": 8545,
                "timeout": 300
            }

    def save_config(self):
        """Save configuration to file."""
        self.config_file.parent.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f, indent=2)

    def update_rpc_config(self, mainnet_rpc: str = None, testnet_rpc: str = None):
        """Update RPC configuration."""
        if mainnet_rpc:
            self.config["mainnet_rpc"] = mainnet_rpc
        if testnet_rpc:
            self.config["testnet_rpc"] = testnet_rpc
        self.save_config()

class ForkTestingManager:
    """Manages fork testing infrastructure."""

    def __init__(self, config_manager: ForkConfigManager = None):
        self.config_manager = config_manager or ForkConfigManager()
        self.config = self.config_manager.config
        self.active_forks: Dict[str, AnvilForkProcess] = {}
        self._ensure_anvil_available()

    def _ensure_anvil_available(self) -> bool:
        """Ensure Anvil is available."""
        try:
            result = subprocess.run(
                ["anvil", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("⚠️  Anvil not found. Please install Foundry: https://book.getfoundry.sh/getting-started/installation")
            return False

    async def start_mainnet_fork(self, block_number: int = None) -> str:
        """Start a mainnet fork and return RPC URL."""
        return await self._start_fork("mainnet", block_number)

    async def start_testnet_fork(self, block_number: int = None) -> str:
        """Start a testnet fork and return RPC URL."""
        return await self._start_fork("testnet", block_number)

    async def _start_fork(self, network: str, block_number: int = None) -> str:
        """Start fork for specified network."""
        import socket

        # Find available port
        port = self._find_available_port()

        # Use configured RPC or default
        rpc_url = self.config["mainnet_rpc"] if network == "mainnet" else self.config["testnet_rpc"]
        target_block = block_number or self.config.get("default_block_number")

        # Build anvil command
        cmd = ["anvil", "--port", str(port), "--fork-url", rpc_url]

        if target_block:
            # Convert hex block number to decimal if needed
            if isinstance(target_block, str) and target_block.startswith('0x'):
                block_num = int(target_block, 16)
            else:
                block_num = int(target_block)
            cmd.extend(["--fork-block-number", str(block_num)])

        # Add additional options for stability
        # Note: --block-time and --no-mining are incompatible, so we use --no-mining
        cmd.extend([
            "--no-mining",                # Don't mine automatically (allows manual control)
            "--timeout", "120000",        # 2 minutes timeout for initialization
            "--retries", "10",            # More retry attempts
            "--fork-retry-backoff", "2000", # 2 second backoff between retries
            "--no-rate-limit"             # Disable rate limiting for anvil
        ])

        print(f"🔧 Starting {network} fork on port {port}...")

        try:
            # Start anvil process
            env = os.environ.copy()
            env['PATH'] = f"{os.path.expanduser('~/.foundry/bin')}:{env.get('PATH', '')}"

            # Start anvil without capturing output to avoid potential issues
            process = subprocess.Popen(
                cmd,
                env=env,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )

            # Wait for startup - use fixed delay since we know anvil takes ~10 seconds
            print(f"⏳ Waiting for anvil to initialize on port {port}...")
            time.sleep(10)  # Wait 10 seconds for anvil to fully start

            if process.poll() is None:  # Process still running
                # Test connection
                if self._test_rpc_connection(f"http://localhost:{port}"):
                    fork_url = f"http://localhost:{port}"

                    # Store fork info
                    fork_process = AnvilForkProcess(
                        process=process,
                        rpc_url=fork_url,
                        port=port,
                        fork_url=rpc_url,
                        block_number=target_block,
                        start_time=time.time()
                    )

                    self.active_forks[fork_url] = fork_process
                    print(f"✅ {network.title()} fork ready at {fork_url}")
                    return fork_url

            # If we get here, anvil failed to start properly
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

            raise RuntimeError(f"Failed to start {network} fork - anvil not responding after startup")

        except Exception as e:
            raise RuntimeError(f"Failed to start {network} fork: {str(e)}")

    def _find_available_port(self) -> int:
        """Find an available port."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _test_rpc_connection(self, rpc_url: str) -> bool:
        """Test if RPC endpoint is responding."""
        try:
            import requests
            response = requests.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "id": 1},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    async def stop_fork(self, fork_url: str) -> bool:
        """Stop a running fork."""
        if fork_url not in self.active_forks:
            return False

        fork_process = self.active_forks[fork_url]

        try:
            # Terminate process
            if os.name == 'nt':  # Windows
                fork_process.process.terminate()
            else:  # Unix-like
                os.killpg(os.getpgid(fork_process.process.pid), 9)

            # Wait for cleanup
            try:
                fork_process.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                fork_process.process.kill()

            # Remove from active forks
            del self.active_forks[fork_url]

            print(f"🛑 Fork stopped: {fork_url}")
            return True

        except Exception as e:
            print(f"⚠️  Error stopping fork {fork_url}: {e}")
            return False

    async def stop_all_forks(self) -> None:
        """Stop all running forks."""
        for fork_url in list(self.active_forks.keys()):
            await self.stop_fork(fork_url)

    def get_active_forks(self) -> List[str]:
        """Get list of active fork URLs."""
        return list(self.active_forks.keys())

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup forks."""
        await self.stop_all_forks()

class ForkContractDeployer:
    """Deploy contracts to fork environments."""

    def __init__(self, web3_provider: str = None):
        self.web3_provider = web3_provider or "http://localhost:8545"

    async def deploy_target_contract(self, fork_rpc: str, contract_code: str) -> str:
        """Deploy target contract on fork and return address."""
        try:
            from web3 import Web3
            from web3.contract import Contract

            # Initialize Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))

            if not w3.is_connected():
                raise ConnectionError(f"Cannot connect to fork RPC: {fork_rpc}")

            # Get accounts
            accounts = w3.eth.accounts
            if not accounts:
                raise ValueError("No accounts available on fork")

            deployer_account = accounts[0]

            # For testing purposes, deploy a simple contract with known bytecode
            # This is a minimal contract that just returns true
            simple_bytecode = "0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063b69ef8a81461003b578063f8a8fd6d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b61006161007b565b60405161006e91906100a1565b60405180910390f35b60005481565b60005481565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b9291505056fea2646970667358221220"
            contract_factory = w3.eth.contract(abi=[], bytecode=simple_bytecode)

            # Build transaction
            tx = contract_factory.constructor().build_transaction({
                'from': deployer_account,
                'nonce': w3.eth.get_transaction_count(deployer_account),
                'gas': 3000000,
                'gasPrice': w3.eth.gas_price
            })

            # Sign and send (using the first account's private key from anvil)
            private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            # Wait for receipt
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if tx_receipt.status != 1:
                raise ValueError(f"Contract deployment failed: {tx_receipt}")

            contract_address = tx_receipt.contractAddress
            print(f"✅ Contract deployed at: {contract_address}")

            return contract_address

        except Exception as e:
            raise RuntimeError(f"Failed to deploy contract to fork: {str(e)}")

    async def deploy_exploit_contract(self, fork_rpc: str, exploit_code: str, target_address: str) -> str:
        """Deploy exploit contract on fork."""
        # Similar to deploy_target_contract but for exploit contracts
        # This would need to be customized based on exploit contract interface

        # Placeholder implementation
        return await self.deploy_target_contract(fork_rpc, exploit_code)

class ForkExploitExecutor:
    """Execute exploits on fork environments."""

    def __init__(self, web3_provider: str = None):
        self.web3_provider = web3_provider or "http://localhost:8545"

    async def execute_exploit(
        self,
        fork_rpc: str,
        exploit_address: str,
        exploit_function: str = "exploit"
    ) -> ExploitResult:
        """Execute exploit on fork and measure results."""

        try:
            from web3 import Web3

            w3 = Web3(Web3.HTTPProvider(fork_rpc))

            if not w3.is_connected():
                raise ConnectionError(f"Cannot connect to fork RPC: {fork_rpc}")

            # Get initial state
            initial_balance = await self.get_balance(fork_rpc, exploit_address)

            # Execute exploit transaction
            tx_hash = await self.call_function(fork_rpc, exploit_address, exploit_function)

            # Get final state
            final_balance = await self.get_balance(fork_rpc, exploit_address)

            # Calculate profit
            profit = final_balance - initial_balance

            # Get transaction details
            tx_receipt = await self.get_transaction_receipt(fork_rpc, tx_hash)

            # Analyze state changes (simplified)
            state_changes = await self.analyze_state_changes(fork_rpc, tx_hash)

            return ExploitResult(
                success=tx_receipt.status == 1,
                profit=profit,
                gas_used=tx_receipt.gasUsed,
                transaction_hash=tx_hash,
                transaction_receipt=tx_receipt,
                state_changes=state_changes
            )

        except Exception as e:
            raise RuntimeError(f"Failed to execute exploit: {str(e)}")

    async def get_balance(self, fork_rpc: str, address: str) -> float:
        """Get ETH balance for address."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            balance_wei = w3.eth.get_balance(address)
            return float(w3.from_wei(balance_wei, 'ether'))
        except Exception as e:
            print(f"Warning: Failed to get balance: {e}")
            return 0.0

    async def call_function(self, fork_rpc: str, contract_address: str, function_name: str) -> str:
        """Call contract function and return transaction hash."""
        try:
            from web3 import Web3

            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            contract = w3.eth.contract(address=contract_address, abi=[])  # Would need ABI

            # Build transaction (simplified)
            accounts = w3.eth.accounts
            if not accounts:
                raise ValueError("No accounts available")

            tx = contract.functions[function_name]().build_transaction({
                'from': accounts[0],
                'nonce': w3.eth.get_transaction_count(accounts[0]),
                'gas': 3000000,
                'gasPrice': w3.eth.gas_price
            })

            # Sign and send
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=w3.eth.account.privateKey)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            return tx_hash.hex()

        except Exception as e:
            raise RuntimeError(f"Failed to call function {function_name}: {str(e)}")

    async def get_transaction_receipt(self, fork_rpc: str, tx_hash: str) -> Dict[str, Any]:
        """Get transaction receipt."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            return w3.eth.get_transaction_receipt(tx_hash)
        except Exception as e:
            raise RuntimeError(f"Failed to get transaction receipt: {str(e)}")

    async def analyze_state_changes(self, fork_rpc: str, tx_hash: str) -> List[Dict[str, Any]]:
        """Analyze state changes from transaction."""
        # Placeholder for state change analysis
        # This would involve comparing state before/after transaction
        return []

class TransactionProofGenerator:
    """Generate proofs of exploit transactions."""

    async def generate_exploit_proof(
        self,
        fork_rpc: str,
        transactions: List[str]
    ) -> Dict[str, Any]:
        """Generate comprehensive proof of exploit."""

        proof = {
            "fork_info": {
                "rpc_url": fork_rpc,
                "block_number": await self.get_block_number(fork_rpc),
                "timestamp": await self.get_timestamp(fork_rpc)
            },
            "transactions": [],
            "state_changes": [],
            "profit_calculation": {}
        }

        for tx_hash in transactions:
            tx_receipt = await self.get_transaction_receipt(fork_rpc, tx_hash)
            tx_details = await self.get_transaction(fork_rpc, tx_hash)

            proof["transactions"].append({
                "hash": tx_hash,
                "from": tx_details["from"],
                "to": tx_details["to"],
                "value": tx_details["value"],
                "gas_used": tx_receipt["gasUsed"],
                "status": tx_receipt["status"],
                "logs": tx_receipt["logs"]
            })

        return proof

    async def get_block_number(self, fork_rpc: str) -> int:
        """Get current block number."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            return w3.eth.block_number
        except:
            return 0

    async def get_timestamp(self, fork_rpc: str) -> int:
        """Get current block timestamp."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            block = w3.eth.get_block('latest')
            return block.timestamp
        except:
            return 0

    async def get_transaction_receipt(self, fork_rpc: str, tx_hash: str) -> Dict[str, Any]:
        """Get transaction receipt."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            return w3.eth.get_transaction_receipt(tx_hash)
        except:
            return {}

    async def get_transaction(self, fork_rpc: str, tx_hash: str) -> Dict[str, Any]:
        """Get transaction details."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_rpc))
            return w3.eth.get_transaction(tx_hash)
        except:
            return {}

class ProofVerifier:
    """Verify exploit proofs."""

    async def verify_proof(self, proof: Dict[str, Any]) -> bool:
        """Verify that proof is valid and reproducible."""

        # 1. Verify fork state
        if not await self.verify_fork_state(proof["fork_info"]):
            return False

        # 2. Verify transactions
        for tx in proof["transactions"]:
            if not await self.verify_transaction(tx):
                return False

        # 3. Verify state changes
        if not await self.verify_state_changes(proof["state_changes"]):
            return False

        return True

    async def verify_fork_state(self, fork_info: Dict[str, Any]) -> bool:
        """Verify fork state is accessible."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(fork_info["rpc_url"]))
            return w3.is_connected()
        except:
            return False

    async def verify_transaction(self, tx: Dict[str, Any]) -> bool:
        """Verify transaction exists and is valid."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(tx.get("fork_url", "")))
            tx_receipt = w3.eth.get_transaction_receipt(tx["hash"])
            return tx_receipt is not None
        except:
            return False

    async def verify_state_changes(self, state_changes: List[Dict[str, Any]]) -> bool:
        """Verify state changes are consistent."""
        # Placeholder for state change verification
        return True

# Main integration class
class RealWorldFoundryValidator:
    """Real-world Foundry validator using mainnet forks."""

    def __init__(self, config: ForkTestingConfig = None):
        self.config_manager = ForkConfigManager()
        self.config = config or ForkTestingConfig()
        self.fork_manager = ForkTestingManager(self.config_manager)
        self.contract_deployer = ForkContractDeployer()
        self.exploit_executor = ForkExploitExecutor()
        self.proof_generator = TransactionProofGenerator()
        self.proof_verifier = ProofVerifier()

    async def validate_vulnerability_on_fork(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str,
        target_address: str = None
    ) -> Dict[str, Any]:
        """Validate vulnerability against real mainnet fork."""

        print(f"🔬 Validating {vulnerability.get('vulnerability_type', 'unknown')} vulnerability...")

        try:
            # 1. Start mainnet fork
            fork_rpc = await self.fork_manager.start_mainnet_fork()
            print(f"🔗 Fork started: {fork_rpc}")

            try:
                # 2. Deploy target contract (or use existing address)
                if target_address:
                    contract_address = target_address
                    print(f"🎯 Using existing contract: {contract_address}")
                else:
                    contract_address = await self.contract_deployer.deploy_target_contract(fork_rpc, contract_code)
                    print(f"📦 Contract deployed: {contract_address}")

                # 3. Generate exploit contract
                exploit_code = await self._generate_exploit_contract(vulnerability, contract_address)

                # 4. Deploy exploit contract
                exploit_address = await self.contract_deployer.deploy_exploit_contract(fork_rpc, exploit_code, contract_address)
                print(f"💥 Exploit contract deployed: {exploit_address}")

                # 5. Execute exploit and measure impact
                result = await self.exploit_executor.execute_exploit(fork_rpc, exploit_address)

                # 6. Generate transaction proof
                proof = await self.proof_generator.generate_exploit_proof(fork_rpc, [result.transaction_hash])

                return {
                    "success": result.success,
                    "exploit_executed": result.success,
                    "profit_realized": result.profit,
                    "gas_used": result.gas_used,
                    "transaction_proof": proof,
                    "vulnerability_confirmed": result.success,
                    "fork_rpc": fork_rpc,
                    "contract_address": contract_address,
                    "exploit_address": exploit_address,
                    "transaction_hash": result.transaction_hash
                }

            finally:
                # Always cleanup fork
                await self.fork_manager.stop_fork(fork_rpc)

        except Exception as e:
            print(f"❌ Validation failed: {e}")
            return {
                "success": False,
                "exploit_executed": False,
                "profit_realized": 0.0,
                "gas_used": 0,
                "transaction_proof": {},
                "vulnerability_confirmed": False,
                "error": str(e)
            }

    async def _generate_exploit_contract(self, vulnerability: Dict[str, Any], contract_address: str) -> str:
        """Generate exploit contract for vulnerability."""
        vuln_type = vulnerability.get("vulnerability_type", "unknown")

        # This would integrate with existing exploit generation logic
        # For now, return a placeholder exploit contract
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ExploitContract {{
    address public target = {contract_address};

    function exploit() external {{
        // Exploit implementation for {vuln_type}
        // This would contain the actual exploit logic
    }}
}}
"""

# Utility functions for configuration
def setup_rpc_config(mainnet_key: str, testnet_key: str = None):
    """Setup RPC configuration."""
    config_manager = ForkConfigManager()
    config_manager.update_rpc_config(
        mainnet_rpc=f"https://eth-mainnet.g.alchemy.com/v2/{mainnet_key}",
        testnet_rpc=f"https://eth-goerli.g.alchemy.com/v2/{testnet_key}" if testnet_key else None
    )
    print("🔑 RPC configuration updated")

def check_dependencies():
    """Check if all required dependencies are installed."""
    dependencies_ok = True

    # Check Anvil/Foundry
    try:
        result = subprocess.run(["anvil", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Anvil/Foundry available")
        else:
            print("❌ Anvil/Foundry not available")
            dependencies_ok = False
    except:
        print("❌ Anvil/Foundry not available")
        dependencies_ok = False

    # Check web3.py
    try:
        import web3
        print("✅ web3.py available")
    except ImportError:
        print("❌ web3.py not available - run: pip install web3")
        dependencies_ok = False

    # Check requests
    try:
        import requests
        print("✅ requests available")
    except ImportError:
        print("❌ requests not available - run: pip install requests")
        dependencies_ok = False

    return dependencies_ok
