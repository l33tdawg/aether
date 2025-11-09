#!/usr/bin/env python3
"""
Enhanced Etherscan Contract Source Code Fetcher

Fetches verified smart contract source code from multiple Etherscan-compatible APIs.
Supports Ethereum mainnet, testnets, and other EVM-compatible chains.
"""

import json
import os
import requests
import tempfile
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config_manager import ConfigManager


class EtherscanFetcher:
    """Enhanced contract source code fetcher supporting multiple EVM chains."""

    # Supported networks and their API endpoints
    SUPPORTED_NETWORKS = {
        'ethereum': {
            'name': 'Ethereum Mainnet',
            'chain_id': 1,
            'api_url': 'https://api.etherscan.io/v2/api',
            'explorer_url': 'https://etherscan.io',
            'test_address': '0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C'  # USDC
        },
        'goerli': {
            'name': 'Ethereum Goerli',
            'chain_id': 5,
            'api_url': 'https://api-goerli.etherscan.io/v2/api',
            'explorer_url': 'https://goerli.etherscan.io',
            'test_address': '0x07865c6e87b9f70255377e024ace6630c1eaa37f'  # USDC on Goerli
        },
        'sepolia': {
            'name': 'Ethereum Sepolia',
            'chain_id': 11155111,
            'api_url': 'https://api-sepolia.etherscan.io/v2/api',
            'explorer_url': 'https://sepolia.etherscan.io',
            'test_address': '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238'  # USDC on Sepolia
        },
        'polygon': {
            'name': 'Polygon Mainnet',
            'chain_id': 137,
            'api_url': 'https://api.polygonscan.com/v2/api',
            'explorer_url': 'https://polygonscan.com',
            'test_address': '0x2791bca1f2de4661ed88a30c99a7a9449aa84174'  # USDC on Polygon
        },
        'arbitrum': {
            'name': 'Arbitrum One',
            'chain_id': 42161,
            'api_url': 'https://api.arbiscan.io/v2/api',
            'explorer_url': 'https://arbiscan.io',
            'test_address': '0xaf88d065e77c8cC2239327C5EDb3A432268e5831'  # USDC on Arbitrum
        },
        'optimism': {
            'name': 'Optimism',
            'chain_id': 10,
            'api_url': 'https://api-optimistic.etherscan.io/v2/api',
            'explorer_url': 'https://optimistic.etherscan.io',
            'test_address': '0x7f5c764cbc14f9669b88837ca1490cca17c31607'  # USDC on Optimism
        },
        'bsc': {
            'name': 'BNB Smart Chain',
            'chain_id': 56,
            'api_url': 'https://api.bscscan.com/v2/api',
            'explorer_url': 'https://bscscan.com',
            'test_address': '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d'  # USDC on BSC
        },
        'base': {
            'name': 'Base',
            'chain_id': 8453,
            'api_url': 'https://api.basescan.org/v2/api',
            'explorer_url': 'https://basescan.org',
            'test_address': '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'  # USDC on Base
        },
        'polygon_zkevm': {
            'name': 'Polygon zkEVM',
            'chain_id': 1101,
            'api_url': 'https://api-zkevm.polygonscan.com/v2/api',
            'explorer_url': 'https://zkevm.polygonscan.com',
            'test_address': '0xa8ce8aee21bc2a48a5ef670afcc9274c7bbbc035'  # USDC on Polygon zkEVM
        },
        'avalanche': {
            'name': 'Avalanche C-Chain',
            'chain_id': 43114,
            'api_url': 'https://api.snowtrace.io/v2/api',
            'explorer_url': 'https://snowtrace.io',
            'test_address': '0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664'  # USDC on Avalanche
        },
        'fantom': {
            'name': 'Fantom',
            'chain_id': 250,
            'api_url': 'https://api.ftmscan.com/v2/api',
            'explorer_url': 'https://ftmscan.com',
            'test_address': '0x04068da6c83afcfa0e13ba15a6696662335d5b75'  # USDC on Fantom
        }
    }

    # Non-EVM chain support (for future expansion)
    NON_EVM_NETWORKS = {
        'solana': {
            'name': 'Solana Mainnet',
            'chain_id': 'mainnet-beta',
            'api_url': 'https://api.mainnet-beta.solana.com',
            'explorer_url': 'https://solscan.io',
            'test_address': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',  # USDC on Solana
            'blockchain_type': 'solana'
        }
    }

    def __init__(self, config_manager: Optional[ConfigManager] = None):
        self.console = Console()
        self.config_manager = config_manager or ConfigManager()
        self.api_key = self.config_manager.config.etherscan_api_key
        self.cache_dir = Path.home() / '.bugbounty' / 'etherscan_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.request_delay = 0.2  # Rate limiting delay between requests

        # Set default network
        self.current_network = 'ethereum'
        # Initialize base_url with default network
        self.base_url = self.SUPPORTED_NETWORKS['ethereum']['api_url']

    def is_etherscan_address(self, address: str) -> bool:
        """Check if the input is a valid Ethereum-style address."""
        return (
            address.startswith('0x') and
            len(address) == 42 and
            all(c in '0123456789abcdefABCDEF' for c in address[2:])
        )

    def parse_explorer_url(self, url_or_address: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse an explorer URL or address and return (network, address).
        
        Supports URLs like:
        - https://etherscan.io/address/0x123...#code
        - https://polygonscan.com/address/0x123...
        - https://arbiscan.io/address/0x123...
        - Or just the address: 0x123...
        
        Returns:
            (network, address): Network name and contract address, or (None, None) if invalid
        """
        import re
        from urllib.parse import urlparse
        
        # First, check if it's already just an address
        if self.is_etherscan_address(url_or_address):
            return ('ethereum', url_or_address)  # Default to ethereum
        
        # Try to parse as URL
        try:
            # Handle URLs with or without protocol
            url = url_or_address
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            
            # Extract address from path (format: /address/0x123...)
            address_match = re.search(r'/address/(0x[a-fA-F0-9]{40})', path)
            if not address_match:
                return (None, None)
            
            address = address_match.group(1)
            
            # Map domain to network
            network_map = {
                'etherscan.io': 'ethereum',
                'goerli.etherscan.io': 'goerli',
                'sepolia.etherscan.io': 'sepolia',
                'polygonscan.com': 'polygon',
                'arbiscan.io': 'arbitrum',
                'optimistic.etherscan.io': 'optimism',
                'bscscan.com': 'bsc',
                'basescan.org': 'base',
                'zkevm.polygonscan.com': 'polygon_zkevm',
                'snowtrace.io': 'avalanche',
                'ftmscan.com': 'fantom'
            }
            
            network = network_map.get(domain, 'ethereum')  # Default to ethereum
            return (network, address)
            
        except Exception as e:
            self.console.print(f"[yellow]⚠️ Failed to parse URL: {e}[/yellow]")
            return (None, None)

    def set_network(self, network: str) -> bool:
        """Set the current network for API calls."""
        if network not in self.SUPPORTED_NETWORKS:
            self.console.print(f"[red]❌ Unsupported network: {network}[/red]")
            return False

        self.current_network = network
        self.base_url = self.SUPPORTED_NETWORKS[network]['api_url']
        self.console.print(f"[green]✅ Switched to network: {self.SUPPORTED_NETWORKS[network]['name']}[/green]")
        return True

    def get_supported_networks(self) -> List[str]:
        """Get list of supported network names."""
        return list(self.SUPPORTED_NETWORKS.keys())

    def get_non_evm_networks(self) -> List[str]:
        """Get list of supported non-EVM network names."""
        return list(self.NON_EVM_NETWORKS.keys())

    def get_all_supported_networks(self) -> List[str]:
        """Get list of all supported network names (EVM + non-EVM)."""
        evm_networks = list(self.SUPPORTED_NETWORKS.keys())
        non_evm_networks = list(self.NON_EVM_NETWORKS.keys())
        return evm_networks + non_evm_networks

    def is_evm_address(self, address: str) -> bool:
        """Check if the input is a valid EVM-style address."""
        return (
            address.startswith('0x') and
            len(address) == 42 and
            all(c in '0123456789abcdefABCDEF' for c in address[2:])
        )

    def is_solana_address(self, address: str) -> bool:
        """Check if the input is a valid Solana address."""
        # Solana addresses are base58 encoded, typically 32-44 characters
        if len(address) < 32 or len(address) > 44:
            return False
        # Basic base58 character check (simplified)
        base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        return all(c in base58_chars for c in address)

    def _get_cache_path(self, address: str, network: str) -> Path:
        """Get cache file path for a contract address."""
        # Create hash of address + network for cache key
        cache_key = hashlib.md5(f"{address}_{network}".encode()).hexdigest()
        return self.cache_dir / f"{cache_key}.json"

    def _load_from_cache(self, address: str, network: str) -> Optional[Dict[str, Any]]:
        """Load contract data from cache if available and fresh."""
        cache_path = self._get_cache_path(address, network)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)

            # Check if cache is still fresh (24 hours)
            cache_time = data.get('cached_at', 0)
            if time.time() - cache_time > 86400:  # 24 hours
                cache_path.unlink()  # Remove stale cache
                return None

            return data.get('contract_data')
        except Exception:
            # Remove corrupted cache file
            try:
                cache_path.unlink()
            except:
                pass
            return None

    def _save_to_cache(self, address: str, network: str, contract_data: Dict[str, Any]) -> None:
        """Save contract data to cache."""
        cache_path = self._get_cache_path(address, network)

        try:
            cache_data = {
                'cached_at': time.time(),
                'contract_data': contract_data
            }

            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            self.console.print(f"[yellow]⚠️ Failed to save cache: {e}[/yellow]")

    def fetch_contract_source(self, address: str, network: Optional[str] = None) -> Dict[str, Any]:
        """Fetch contract source code from specified network."""
        if not self.is_etherscan_address(address):
            return {'error': f'Invalid Ethereum address format: {address}'}

        if not self.api_key:
            return {'error': 'Etherscan API key not configured. Use config.set_etherscan_key() to set it.'}

        # Use specified network or current network
        target_network = network or self.current_network
        if target_network not in self.SUPPORTED_NETWORKS:
            return {'error': f'Unsupported network: {target_network}'}

        # Check cache first
        cached_data = self._load_from_cache(address, target_network)
        if cached_data:
            self.console.print(f"[green]📋 Using cached data for {address} on {self.SUPPORTED_NETWORKS[target_network]['name']}[/green]")
            return cached_data

        self.console.print(f"[cyan]🔍 Fetching contract source code for {address} on {self.SUPPORTED_NETWORKS[target_network]['name']}...[/cyan]")

        # Set base URL for the target network
        base_url = self.SUPPORTED_NETWORKS[target_network]['api_url']
        chain_id = self.SUPPORTED_NETWORKS[target_network]['chain_id']

        url = f"{base_url}?chainid={chain_id}&module=contract&action=getsourcecode&address={address}&apikey={self.api_key}"

        # Rate limiting
        time.sleep(self.request_delay)

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Fetching from Etherscan...", total=None)
                
                response = requests.get(url, timeout=30)
                response.raise_for_status()

            data = response.json()

            if data.get('status') != '1':
                error_msg = data.get('message', 'Unknown error')
                if 'rate limit' in error_msg.lower():
                    return {'error': 'Etherscan API rate limit exceeded. Please try again later.'}
                elif 'invalid api key' in error_msg.lower():
                    return {'error': 'Invalid Etherscan API key. Please check your configuration.'}
                else:
                    return {'error': f'API error: {error_msg}'}

            result = data.get('result', [])
            if not result:
                return {'error': 'No contract data found'}

            contract_data = result[0]

            if not contract_data.get('SourceCode'):
                return {'error': 'Contract source code is not available (not verified)'}

            source_code = contract_data['SourceCode']
            contract_name = contract_data.get('ContractName', 'UnknownContract')

            self.console.print(f"[green]✅ Successfully fetched contract: {contract_name}[/green]")
            self.console.print(f"[blue]📄 Source code length: {len(source_code)} characters[/blue]")

            # Prepare result data
            result_data = {
                'success': True,
                'source_code': source_code,
                'contract_name': contract_name,
                'address': address,
                'network': target_network,
                'chain_id': chain_id,
                'abi': contract_data.get('ABI', ''),
                'compiler_version': contract_data.get('CompilerVersion', ''),
                'optimization': contract_data.get('OptimizationUsed', ''),
                'runs': contract_data.get('Runs', ''),
                'constructor_args': contract_data.get('ConstructorArguments', ''),
                'evm_version': contract_data.get('EVMVersion', ''),
                'library': contract_data.get('Library', ''),
                'license': contract_data.get('LicenseType', ''),
                'proxy': contract_data.get('Proxy', ''),
                'implementation': contract_data.get('Implementation', ''),
                'swarm_source': contract_data.get('SwarmSource', ''),
                'metadata': contract_data
            }

            # Save to cache
            self._save_to_cache(address, target_network, result_data)

            return result_data

        except requests.exceptions.RequestException as e:
            return {'error': f'Network error fetching contract: {e}'}
        except json.JSONDecodeError as e:
            return {'error': f'JSON decode error: {e}'}
        except Exception as e:
            return {'error': f'Unexpected error: {e}'}

    def save_contract_source(self, contract_data: Dict[str, Any], output_dir: str = "temp_contracts") -> str:
        """Save contract source code to files."""
        if not contract_data.get('success'):
            raise ValueError(f"Cannot save contract: {contract_data.get('error', 'Unknown error')}")

        os.makedirs(output_dir, exist_ok=True)

        contract_name = contract_data.get('contract_name', 'UnknownContract')
        address = contract_data.get('address', 'unknown')

        # Clean contract name for filename
        safe_name = "".join(c for c in contract_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_name = safe_name.replace(' ', '_')

        # Handle different source code formats
        source_code = contract_data['source_code']

        # Check if source code is JSON (for multi-file contracts)
        if source_code.startswith('{'):
            try:
                source_json = json.loads(source_code)
                if 'sources' in source_json:
                    # Multi-file contract
                    self.console.print(f"[blue]📁 Detected multi-file contract with {len(source_json['sources'])} files[/blue]")

                    # Create directory for multi-file contract
                    contract_dir = os.path.join(output_dir, safe_name)
                    os.makedirs(contract_dir, exist_ok=True)

                    # Save each source file
                    for file_path, file_data in source_json['sources'].items():
                        # Clean file path
                        clean_path = file_path.replace('@', '').replace('/', '_')
                        if not clean_path.endswith('.sol'):
                            clean_path += '.sol'

                        full_path = os.path.join(contract_dir, clean_path)
                        os.makedirs(os.path.dirname(full_path), exist_ok=True)

                        with open(full_path, 'w', encoding='utf-8') as f:
                            f.write(file_data.get('content', ''))

                    self.console.print(f"[green]💾 Saved multi-file contract to: {contract_dir}[/green]")
                    return contract_dir
            except json.JSONDecodeError:
                # Not JSON, treat as single file
                pass

        # Single file contract
        filename = f"{safe_name}_{address[:8]}.sol"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(source_code)

        self.console.print(f"[green]💾 Saved contract source to: {filepath}[/green]")
        return filepath

    def fetch_and_save_contract(self, address: str, output_dir: str = "temp_contracts") -> Tuple[bool, str, Dict[str, Any]]:
        """Fetch contract source code and save it to files."""
        contract_data = self.fetch_contract_source(address)
        
        if not contract_data.get('success'):
            return False, contract_data.get('error', 'Unknown error'), {}

        try:
            file_path = self.save_contract_source(contract_data, output_dir)
            return True, file_path, contract_data
        except Exception as e:
            return False, str(e), contract_data

    def get_contract_info(self, address: str) -> Dict[str, Any]:
        """Get basic contract information without fetching source code."""
        if not self.is_etherscan_address(address):
            return {'error': f'Invalid Ethereum address format: {address}'}

        if not self.api_key:
            return {'error': 'Etherscan API key not configured'}

        url = f"{self.base_url}?chainid=1&module=contract&action=getsourcecode&address={address}&apikey={self.api_key}"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get('status') != '1':
                return {'error': f'Etherscan API error: {data.get("message", "Unknown error")}'}

            result = data.get('result', [])
            if not result:
                return {'error': 'No contract data found'}

            contract_data = result[0]

            return {
                'success': True,
                'contract_name': contract_data.get('ContractName', 'Unknown'),
                'address': address,
                'is_verified': bool(contract_data.get('SourceCode')),
                'compiler_version': contract_data.get('CompilerVersion', ''),
                'proxy': contract_data.get('Proxy', ''),
                'implementation': contract_data.get('Implementation', ''),
            }

        except Exception as e:
            return {'error': f'Error fetching contract info: {e}'}

    def test_api_connection(self, network: Optional[str] = None) -> bool:
        """Test if the API key is working for a specific network."""
        if not self.api_key:
            self.console.print("[red]❌ No Etherscan API key configured[/red]")
            return False

        # Use specified network or current network
        test_network = network or self.current_network
        if test_network not in self.SUPPORTED_NETWORKS:
            self.console.print(f"[red]❌ Unsupported network for testing: {test_network}[/red]")
            return False

        test_address = self.SUPPORTED_NETWORKS[test_network]['test_address']
        network_info = self.SUPPORTED_NETWORKS[test_network]

        self.console.print(f"[blue]🧪 Testing API connection for {network_info['name']}...[/blue]")

        # Temporarily set network for testing
        original_network = self.current_network
        self.set_network(test_network)

        try:
            # Test with a known contract
            url = f"{self.base_url}?chainid={network_info['chain_id']}&module=contract&action=getsourcecode&address={test_address}&apikey={self.api_key}"

            response = requests.get(url, timeout=10)
            data = response.json()

            if data.get('status') == '1':
                self.console.print(f"[green]✅ {network_info['name']} API key is working[/green]")
                return True
            elif 'invalid api key' in data.get('message', '').lower():
                self.console.print(f"[red]❌ Invalid API key for {network_info['name']}[/red]")
                return False
            elif 'rate limit' in data.get('message', '').lower():
                self.console.print(f"[yellow]⚠️ Rate limit exceeded for {network_info['name']}[/yellow]")
                return True  # API is working but rate limited
            else:
                self.console.print(f"[yellow]⚠️ {network_info['name']} API test inconclusive: {data.get('message', 'Unknown')}[/yellow]")
                return True  # Assume it's working if we get a response

        except Exception as e:
            self.console.print(f"[red]❌ Error testing {network_info['name']} API: {e}[/red]")
            return False
        finally:
            # Restore original network
            self.set_network(original_network)

    def fetch_multiple_contracts(self, addresses: List[str], network: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Fetch source code for multiple contracts in batch."""
        results = {}

        for address in addresses:
            self.console.print(f"[blue]📦 Fetching {address}...[/blue]")
            result = self.fetch_contract_source(address, network)

            if result.get('success'):
                results[address] = result
                self.console.print(f"[green]✅ Fetched {result['contract_name']}[/green]")
            else:
                results[address] = result
                self.console.print(f"[red]❌ Failed to fetch {address}: {result.get('error', 'Unknown error')}[/red]")

            # Rate limiting between requests
            time.sleep(self.request_delay)

        return results

    def validate_abi_compatibility(self, contract_data: Dict[str, Any], expected_functions: List[str]) -> Dict[str, Any]:
        """Validate that contract ABI contains expected functions."""
        if not contract_data.get('success'):
            return {'valid': False, 'error': 'Contract data not available'}

        try:
            abi = contract_data.get('abi', '[]')
            if isinstance(abi, str):
                abi = json.loads(abi)

            available_functions = []
            for item in abi:
                if item.get('type') == 'function':
                    func_name = item.get('name', '')
                    if func_name:
                        available_functions.append(func_name)

            missing_functions = [func for func in expected_functions if func not in available_functions]

            return {
                'valid': len(missing_functions) == 0,
                'available_functions': available_functions,
                'missing_functions': missing_functions,
                'total_functions': len(available_functions)
            }

        except Exception as e:
            return {'valid': False, 'error': f'ABI validation error: {e}'}

    def get_contract_explorer_url(self, address: str, network: Optional[str] = None) -> str:
        """Get the explorer URL for a contract address."""
        target_network = network or self.current_network
        if target_network not in self.SUPPORTED_NETWORKS:
            return f"https://etherscan.io/address/{address}"  # Default fallback

        explorer_url = self.SUPPORTED_NETWORKS[target_network]['explorer_url']
        return f"{explorer_url}/address/{address}"

    def clear_cache(self, network: Optional[str] = None) -> int:
        """Clear cached contract data."""
        cleared_count = 0

        if network:
            # Clear cache for specific network
            pattern = f"*{network}.json"
            for cache_file in self.cache_dir.glob(pattern):
                try:
                    cache_file.unlink()
                    cleared_count += 1
                except Exception:
                    pass
        else:
            # Clear all cache
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                    cleared_count += 1
                except Exception:
                    pass

        self.console.print(f"[green]🗑️ Cleared {cleared_count} cached entries[/green]")
        return cleared_count

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        total_files = 0
        total_size = 0

        for cache_file in self.cache_dir.glob("*.json"):
            total_files += 1
            try:
                total_size += cache_file.stat().st_size
            except Exception:
                pass

        return {
            'total_cached_contracts': total_files,
            'total_cache_size_bytes': total_size,
            'cache_directory': str(self.cache_dir)
        }

    def fetch_contract_for_poc_generation(self, address: str, expected_functions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enhanced fetch method specifically for PoC generation workflow."""
        self.console.print(f"[cyan]🔍 Fetching contract for PoC generation: {address}[/cyan]")

        # Fetch contract data
        contract_data = self.fetch_contract_source(address)

        if not contract_data.get('success'):
            return contract_data

        # Validate ABI if expected functions are provided
        if expected_functions:
            abi_validation = self.validate_abi_compatibility(contract_data, expected_functions)
            if not abi_validation['valid']:
                self.console.print(f"[yellow]⚠️ ABI validation issues: {abi_validation.get('error', 'Missing expected functions')}[/yellow]")
                if abi_validation.get('missing_functions'):
                    self.console.print(f"[yellow]Missing functions: {', '.join(abi_validation['missing_functions'])}[/yellow]")

        # Add explorer URL for reference
        contract_data['explorer_url'] = self.get_contract_explorer_url(address)

        return contract_data

    def auto_detect_network_from_address(self, address: str) -> Optional[str]:
        """Attempt to auto-detect network from contract address patterns."""
        # This is a simple heuristic - in practice, you'd need more sophisticated detection
        # For now, we'll assume most addresses are Ethereum mainnet unless specified
        return 'ethereum'  # Default fallback

    def get_network_info(self, network: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific network."""
        return self.SUPPORTED_NETWORKS.get(network)

    def list_supported_networks(self) -> None:
        """Display information about all supported networks."""
        self.console.print("[bold blue]🌐 Supported Networks:[/bold blue]")

        for network, info in self.SUPPORTED_NETWORKS.items():
            status = "[green]✅[/green]" if self.api_key else "[yellow]⚠️[/yellow]"
            self.console.print(f"  {status} {network:<12} - {info['name']:<20} (Chain ID: {info['chain_id']})")

        if not self.api_key:
            self.console.print("[yellow]⚠️ No API key configured - some networks may not work[/yellow]")
