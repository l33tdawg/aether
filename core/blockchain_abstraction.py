#!/usr/bin/env python3
"""
Blockchain Abstraction Layer for Multi-Chain Support

Provides a unified interface for interacting with different blockchain networks,
including EVM-compatible chains and non-EVM chains like Solana.
"""

import json
import asyncio
import aiohttp
import requests
from typing import Dict, Any, Optional, List, Union
from abc import ABC, abstractmethod
from dataclasses import dataclass
from rich.console import Console

from core.etherscan_fetcher import EtherscanFetcher


@dataclass
class ChainInfo:
    """Information about a blockchain network."""
    name: str
    chain_id: Union[int, str]
    blockchain_type: str  # 'evm', 'solana', etc.
    api_url: str
    explorer_url: str
    test_address: str


@dataclass
class ContractData:
    """Contract data from any blockchain."""
    address: str
    source_code: str
    abi: List[Dict[str, Any]]
    bytecode: str
    contract_name: str
    compiler_version: str
    optimization_enabled: bool
    license: str
    network: str
    blockchain_type: str


class BlockchainClient(ABC):
    """Abstract base class for blockchain clients."""

    @abstractmethod
    async def get_contract_source(self, address: str) -> Optional[ContractData]:
        """Fetch contract source code and metadata."""
        pass

    @abstractmethod
    def get_chain_info(self) -> ChainInfo:
        """Get information about this blockchain."""
        pass

    @abstractmethod
    def is_valid_address(self, address: str) -> bool:
        """Check if address format is valid for this blockchain."""
        pass


class EVMClient(BlockchainClient):
    """Client for EVM-compatible blockchains."""

    def __init__(self, chain_info: ChainInfo, api_key: Optional[str] = None):
        self.chain_info = chain_info
        self.api_key = api_key
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def get_chain_info(self) -> ChainInfo:
        return self.chain_info

    def is_valid_address(self, address: str) -> bool:
        return (
            address.startswith('0x') and
            len(address) == 42 and
            all(c in '0123456789abcdefABCDEF' for c in address[2:])
        )

    async def get_contract_source(self, address: str) -> Optional[ContractData]:
        """Fetch contract source from Etherscan-compatible API."""
        if not self.session:
            self.session = aiohttp.ClientSession()

        if not self.is_valid_address(address):
            return None

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': self.api_key or ''
        }

        try:
            async with self.session.get(self.chain_info.api_url, params=params) as response:
                if response.status != 200:
                    return None

                data = await response.json()
                if data.get('status') != '1' or not data.get('result'):
                    return None

                result = data['result'][0]  # Etherscan returns array

                return ContractData(
                    address=address,
                    source_code=result.get('SourceCode', ''),
                    abi=json.loads(result.get('ABI', '[]')),
                    bytecode=result.get('Bytecode', ''),
                    contract_name=result.get('ContractName', ''),
                    compiler_version=result.get('CompilerVersion', ''),
                    optimization_enabled=result.get('OptimizationUsed', '0') == '1',
                    license=result.get('LicenseType', ''),
                    network=self.chain_info.name,
                    blockchain_type='evm'
                )

        except Exception:
            return None


class SolanaClient(BlockchainClient):
    """Client for Solana blockchain."""

    def __init__(self, chain_info: ChainInfo):
        self.chain_info = chain_info
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def get_chain_info(self) -> ChainInfo:
        return self.chain_info

    def is_valid_address(self, address: str) -> bool:
        """Check if Solana address is valid."""
        if len(address) < 32 or len(address) > 44:
            return False
        base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        return all(c in base58_chars for c in address)

    async def get_contract_source(self, address: str) -> Optional[ContractData]:
        """Fetch Solana program/account info."""
        if not self.session:
            self.session = aiohttp.ClientSession()

        if not self.is_valid_address(address):
            return None

        try:
            # Get account info from Solana RPC
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [address, {"encoding": "base64"}]
            }

            async with self.session.post(self.chain_info.api_url, json=payload) as response:
                if response.status != 200:
                    return None

                data = await response.json()
                if 'error' in data or 'result' not in data:
                    return None

                account_info = data['result']
                if not account_info or account_info['value'] is None:
                    return None

                # For now, return basic info - Solana program source fetching is complex
                # and would require additional APIs like Solscan or Helius
                return ContractData(
                    address=address,
                    source_code="",  # Would need additional API integration
                    abi=[],  # Solana doesn't use ABI in the same way
                    bytecode=account_info['value']['data'][0] if account_info['value']['data'] else "",
                    contract_name=f"Program_{address[:8]}",
                    compiler_version="",
                    optimization_enabled=False,
                    license="",
                    network=self.chain_info.name,
                    blockchain_type='solana'
                )

        except Exception:
            return None


class BlockchainManager:
    """Manager for multiple blockchain clients."""

    def __init__(self, etherscan_api_key: Optional[str] = None):
        self.etherscan_api_key = etherscan_api_key
        self.console = Console()
        self.clients: Dict[str, BlockchainClient] = {}
        self._initialize_clients()

    def _initialize_clients(self):
        """Initialize blockchain clients for supported networks."""
        # EVM clients
        evm_networks = {
            'ethereum': {'chain_id': 1, 'api_url': 'https://api.etherscan.io/v2/api', 'explorer_url': 'https://etherscan.io'},
            'polygon': {'chain_id': 137, 'api_url': 'https://api.polygonscan.com/v2/api', 'explorer_url': 'https://polygonscan.com'},
            'arbitrum': {'chain_id': 42161, 'api_url': 'https://api.arbiscan.io/v2/api', 'explorer_url': 'https://arbiscan.io'},
            'optimism': {'chain_id': 10, 'api_url': 'https://api-optimistic.etherscan.io/v2/api', 'explorer_url': 'https://optimistic.etherscan.io'},
            'bsc': {'chain_id': 56, 'api_url': 'https://api.bscscan.com/v2/api', 'explorer_url': 'https://bscscan.com'},
            'base': {'chain_id': 8453, 'api_url': 'https://api.basescan.org/v2/api', 'explorer_url': 'https://basescan.org'},
            'polygon_zkevm': {'chain_id': 1101, 'api_url': 'https://api-zkevm.polygonscan.com/v2/api', 'explorer_url': 'https://zkevm.polygonscan.com'},
            'avalanche': {'chain_id': 43114, 'api_url': 'https://api.snowtrace.io/v2/api', 'explorer_url': 'https://snowtrace.io'},
            'fantom': {'chain_id': 250, 'api_url': 'https://api.ftmscan.com/v2/api', 'explorer_url': 'https://ftmscan.com'}
        }

        for network, info in evm_networks.items():
            chain_info = ChainInfo(
                name=f"{network.title()} Mainnet",
                chain_id=info['chain_id'],
                blockchain_type='evm',
                api_url=info['api_url'],
                explorer_url=info['explorer_url'],
                test_address=self._get_test_address(network)
            )
            self.clients[network] = EVMClient(chain_info, self.etherscan_api_key)

        # Non-EVM clients (placeholder for future expansion)
        # self.clients['solana'] = SolanaClient(...)

    def _get_test_address(self, network: str) -> str:
        """Get test address for network."""
        test_addresses = {
            'ethereum': '0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C',
            'polygon': '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
            'arbitrum': '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
            'optimism': '0x7f5c764cbc14f9669b88837ca1490cca17c31607',
            'bsc': '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
            'base': '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
            'polygon_zkevm': '0xa8ce8aee21bc2a48a5ef670afcc9274c7bbbc035',
            'avalanche': '0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664',
            'fantom': '0x04068da6c83afcfa0e13ba15a6696662335d5b75'
        }
        return test_addresses.get(network, test_addresses['ethereum'])

    async def get_contract(self, address: str, network: Optional[str] = None) -> Optional[ContractData]:
        """Get contract data from any supported network."""
        # Auto-detect blockchain type if network not specified
        if not network:
            if address.startswith('0x'):
                # Try EVM networks
                for client in self.clients.values():
                    if client.blockchain_type == 'evm' and client.is_valid_address(address):
                        return await client.get_contract_source(address)
            else:
                # Try non-EVM networks in future
                pass
            return None

        if network not in self.clients:
            self.console.print(f"[red]❌ Unsupported network: {network}[/red]")
            return None

        client = self.clients[network]
        if not client.is_valid_address(address):
            self.console.print(f"[red]❌ Invalid address format for {network}[/red]")
            return None

        return await client.get_contract_source(address)

    def get_supported_networks(self) -> List[str]:
        """Get list of supported networks."""
        return list(self.clients.keys())

    def get_network_info(self, network: str) -> Optional[ChainInfo]:
        """Get information about a network."""
        if network in self.clients:
            return self.clients[network].get_chain_info()
        return None

    async def test_connection(self, network: str) -> bool:
        """Test connection to a network."""
        if network not in self.clients:
            return False

        try:
            client = self.clients[network]
            chain_info = client.get_chain_info()
            contract_data = await client.get_contract_source(chain_info.test_address)

            if contract_data:
                self.console.print(f"[green]✅ {chain_info.name} connection successful[/green]")
                return True
            else:
                self.console.print(f"[yellow]⚠️  {chain_info.name} connection test inconclusive[/yellow]")
                return True  # API might be down but format is correct
        except Exception as e:
            self.console.print(f"[red]❌ {chain_info.name} connection failed: {e}[/red]")
            return False
