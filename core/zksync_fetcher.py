#!/usr/bin/env python3
"""
zkSync Explorer Contract Source Code Fetcher

Fetches verified smart contract source code from zkSync Explorer.
"""

import json
import os
import requests
import tempfile
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from bs4 import BeautifulSoup

from core.config_manager import ConfigManager


class ZkSyncFetcher:
    """Fetches contract source code from zkSync Explorer API."""

    def __init__(self, config_manager: Optional[ConfigManager] = None):
        self.console = Console()
        self.config_manager = config_manager or ConfigManager()
        self.base_url = "https://explorer.zksync.io/api/v0.2"

    def is_zksync_address(self, address: str) -> bool:
        """Check if the input is a valid Ethereum address."""
        return (
            address.startswith('0x') and 
            len(address) == 42 and 
            address[2:].isalnum()
        )

    def fetch_contract_source(self, address: str) -> Dict[str, Any]:
        """Fetch contract source code from zkSync Explorer."""
        if not self.is_zksync_address(address):
            return {'error': f'Invalid address format: {address}'}

        self.console.print(f"[blue]🔍 Fetching contract source code for {address} from zkSync Explorer...[/blue]")

        # zkSync Explorer contract page URL
        url = f"https://explorer.zksync.io/address/{address}"

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Fetching contract page...", total=None)
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                
                progress.update(task, description="Parsing HTML...")
                soup = BeautifulSoup(response.content, 'html.parser')

            # Look for contract source code in the page
            # Check if there's a contract tab or source code section
            contract_section = soup.find('div', {'class': re.compile(r'contract|source|code', re.I)})
            
            if not contract_section:
                # Try to find source code in pre tags or code blocks
                source_code_elements = soup.find_all(['pre', 'code'], string=re.compile(r'pragma|contract|function'))
                
                if not source_code_elements:
                    return {
                        'error': 'Contract source code is not verified or not available on zkSync Explorer',
                        'address': address,
                        'verified': False
                    }
                
                # Extract source code from the first matching element
                source_code = source_code_elements[0].get_text()
            else:
                # Extract source code from contract section
                source_code = contract_section.get_text()

            # Clean up the source code
            source_code = source_code.strip()
            
            if not source_code or len(source_code) < 100:
                return {
                    'error': 'No valid source code found',
                    'address': address,
                    'verified': False
                }

            # Try to extract contract name from source code
            contract_name_match = re.search(r'contract\s+(\w+)', source_code)
            contract_name = contract_name_match.group(1) if contract_name_match else 'UnknownContract'

            # Try to extract compiler version
            compiler_match = re.search(r'pragma\s+solidity\s+([^;]+)', source_code)
            compiler_version = compiler_match.group(1).strip() if compiler_match else ''

            self.console.print(f"[green]✅ Successfully fetched contract: {contract_name}[/green]")
            self.console.print(f"[green]📄 Source code length: {len(source_code)} characters[/green]")

            return {
                'success': True,
                'source_code': source_code,
                'contract_name': contract_name,
                'address': address,
                'compiler_version': compiler_version,
                'verified': True,
                'platform': 'zksync'
            }

        except requests.exceptions.RequestException as e:
            error_msg = f"Network error fetching contract: {e}"
            self.console.print(f"[red]❌ {error_msg}[/red]")
            return {'error': error_msg}
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.console.print(f"[red]❌ {error_msg}[/red]")
            return {'error': error_msg}

    def save_contract_source(self, contract_data: Dict[str, Any], output_dir: str = "temp_contracts") -> str:
        """Save contract source code to file."""
        if not contract_data.get('success'):
            raise ValueError("Contract data is not valid")

        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Generate filename
        contract_name = contract_data.get('contract_name', 'UnknownContract')
        address = contract_data.get('address', 'unknown')
        filename = f"{contract_name}_{address[:8]}.sol"
        filepath = output_path / filename

        # Save source code
        source_code = contract_data['source_code']
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(source_code)

        # Save metadata
        metadata = {
            'contract_name': contract_data.get('contract_name'),
            'address': contract_data.get('address'),
            'compiler_version': contract_data.get('compiler_version'),
            'optimization': contract_data.get('optimization'),
            'runs': contract_data.get('runs'),
            'constructor_args': contract_data.get('constructor_args'),
            'platform': contract_data.get('platform'),
            'verified': contract_data.get('verified')
        }
        
        metadata_file = output_path / f"{contract_name}_{address[:8]}_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        self.console.print(f"[green]💾 Contract saved to: {filepath}[/green]")
        return str(filepath)

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
        if not self.is_zksync_address(address):
            return {'error': f'Invalid address format: {address}'}

        url = f"{self.base_url}/contracts/{address}"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'success': True,
                'address': address,
                'verified': data.get('verified', False),
                'contract_name': data.get('contract_name', 'Unknown'),
                'platform': 'zksync'
            }

        except Exception as e:
            return {'error': f'Error fetching contract info: {e}'}

    def test_api_connection(self) -> bool:
        """Test if the zkSync Explorer is accessible."""
        try:
            response = requests.get("https://explorer.zksync.io", timeout=10)
            return response.status_code == 200
        except:
            return False


def main():
    """Test the zkSync fetcher."""
    fetcher = ZkSyncFetcher()
    
    # Test API connection
    if fetcher.test_api_connection():
        print("✅ zkSync Explorer API is accessible")
    else:
        print("❌ zkSync Explorer API is not accessible")
        return

    # Test contract fetching
    test_address = "0x0616e5762c1E7Dc3723c50663dF10a162D690a86"
    result = fetcher.fetch_and_save_contract(test_address)
    
    if result[0]:
        print(f"✅ Successfully fetched and saved contract to: {result[1]}")
    else:
        print(f"❌ Failed to fetch contract: {result[1]}")


if __name__ == "__main__":
    main()
