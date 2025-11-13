#!/usr/bin/env python3
"""
Basescan Contract Source Code Fetcher

Fetches verified smart contract source code from Basescan API.
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


class BasescanFetcher:
    """Fetches contract source code from Basescan API."""

    def __init__(self, config_manager: Optional[ConfigManager] = None):
        self.console = Console()
        self.config_manager = config_manager or ConfigManager()
        self.api_key = self.config_manager.config.etherscan_api_key  # Use same API key
        self.base_url = "https://api.basescan.org/v2/api"
        self.default_contracts_dir = Path.home() / '.aether' / 'contracts'
        self.default_contracts_dir.mkdir(parents=True, exist_ok=True)

    def is_basescan_address(self, address: str) -> bool:
        """Check if the input is a Basescan address."""
        return (
            address.startswith('0x') and 
            len(address) == 42 and 
            address[2:].isalnum()
        )

    def fetch_contract_source(self, address: str) -> Dict[str, Any]:
        """Fetch contract source code from Basescan using web scraping."""
        if not self.is_basescan_address(address):
            return {'error': f'Invalid Base address format: {address}'}

        self.console.print(f"[blue]🔍 Fetching contract source code for {address} from Basescan...[/blue]")

        # Use web scraping since API requires key
        url = f"https://basescan.org/address/{address}#code"

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

            # Check if contract is verified by looking for source code
            pre_tags = soup.find_all('pre')
            source_code = None
            
            # Try to find pre tags with source code
            for pre in pre_tags:
                text = pre.get_text()
                if 'pragma solidity' in text or 'contract ' in text or 'interface ' in text:
                    source_code = text
                    break

            if not source_code:
                return {'error': 'Contract is not verified on Basescan or source code not found'}

            # Try to find contract name
            contract_name = 'Unknown'
            # Look for contract name in various locations
            name_elements = soup.find_all(['h1', 'span', 'div'], string=re.compile(r'Contract Name:', re.I))
            for elem in name_elements:
                parent = elem.parent
                if parent:
                    text = parent.get_text()
                    if 'Contract Name:' in text:
                        # Extract the name after "Contract Name:"
                        parts = text.split('Contract Name:', 1)
                        if len(parts) > 1:
                            name_part = parts[1].strip()
                            # Take the first line or first word
                            contract_name = name_part.split('\n')[0].split()[0] if name_part else 'Unknown'
                            break
            
            # If no specific name found, try to extract from source code
            if contract_name == 'Unknown' and source_code:
                # Look for contract declarations
                contract_matches = re.findall(r'contract\s+(\w+)', source_code)
                if contract_matches:
                    contract_name = contract_matches[0]

            # Extract compiler version and other metadata if available
            compiler_version = ''
            optimization = ''
            runs = ''
            
            # Look for metadata in the page
            metadata_elements = soup.find_all(['span', 'div'], text=re.compile(r'Compiler|Optimization|Runs', re.I))
            for elem in metadata_elements:
                text = elem.get_text()
                if 'compiler' in text.lower():
                    compiler_version = text
                elif 'optimization' in text.lower():
                    optimization = text
                elif 'runs' in text.lower():
                    runs = text

            return {
                'success': True,
                'contract_name': contract_name,
                'address': address,
                'compiler_version': compiler_version,
                'optimization': optimization,
                'runs': runs,
                'constructor_args': '',
                'proxy': '',
                'implementation': '',
                'source_code': source_code,
                'is_multi_file': False,
                'platform': 'basescan'
            }

        except Exception as e:
            return {'error': f'Error fetching contract source: {e}'}

    def save_contract_source(self, contract_data: Dict[str, Any], output_dir: Optional[str] = None) -> str:
        """Save contract source code to files."""
        # Use default contracts directory if not specified
        if output_dir is None:
            output_dir = str(self.default_contracts_dir)
        
        os.makedirs(output_dir, exist_ok=True)
        
        contract_name = contract_data.get('contract_name', 'UnknownContract')
        address = contract_data.get('address', 'unknown')
        
        # Clean contract name for filename
        safe_name = "".join(c for c in contract_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_name = safe_name.replace(' ', '_')
        
        if contract_data.get('is_multi_file'):
            # Multi-file contract
            source_json = contract_data['source_code']
            sources = source_json.get('sources', {})
            
            # Create directory for this contract
            contract_dir = os.path.join(output_dir, f"{safe_name}_{address}")
            os.makedirs(contract_dir, exist_ok=True)
            
            main_file = None
            for file_path, file_data in sources.items():
                if isinstance(file_data, dict) and 'content' in file_data:
                    content = file_data['content']
                    
                    # Clean file path
                    clean_path = file_path.replace('contracts/', '').replace('/', '_')
                    if not clean_path.endswith('.sol'):
                        clean_path += '.sol'
                    
                    file_path_full = os.path.join(contract_dir, clean_path)
                    
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(file_path_full), exist_ok=True)
                    
                    with open(file_path_full, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    # Use the first file as main file
                    if main_file is None:
                        main_file = file_path_full
            
            if main_file:
                self.console.print(f"[green]✅ Contract source saved to: {main_file}[/green]")
                return main_file
            else:
                raise Exception("No source files found in multi-file contract")
        else:
            # Single file contract
            filename = f"{safe_name}_{address}.sol"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(contract_data['source_code'])
            
            self.console.print(f"[green]✅ Contract source saved to: {filepath}[/green]")
            return filepath

    def fetch_and_save_contract(self, address: str, output_dir: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
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
        if not self.is_basescan_address(address):
            return {'error': f'Invalid Base address format: {address}'}

        url = f"https://basescan.org/address/{address}"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check if contract is verified by looking for source code
            pre_tags = soup.find_all('pre')
            is_verified = False
            contract_name = 'Unknown'
            
            for pre in pre_tags:
                text = pre.get_text()
                if 'pragma solidity' in text or 'contract ' in text or 'interface ' in text:
                    is_verified = True
                    # Try to extract contract name from source code
                    contract_matches = re.findall(r'contract\s+(\w+)', text)
                    if contract_matches:
                        contract_name = contract_matches[0]
                    break
            
            # Try to find contract name from page elements
            if contract_name == 'Unknown':
                name_elements = soup.find_all(['h1', 'span', 'div'], string=re.compile(r'Contract Name:', re.I))
                for elem in name_elements:
                    parent = elem.parent
                    if parent:
                        text = parent.get_text()
                        if 'Contract Name:' in text:
                            parts = text.split('Contract Name:', 1)
                            if len(parts) > 1:
                                name_part = parts[1].strip()
                                contract_name = name_part.split('\n')[0].split()[0] if name_part else 'Unknown'
                                break

            return {
                'success': True,
                'contract_name': contract_name,
                'address': address,
                'is_verified': is_verified,
                'compiler_version': '',
                'proxy': '',
                'implementation': '',
                'platform': 'basescan'
            }

        except Exception as e:
            return {'error': f'Error fetching contract info: {e}'}

    def test_api_connection(self) -> bool:
        """Test if Basescan is accessible."""
        # Test with a known Base contract (USDC on Base)
        test_address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(f"https://basescan.org/address/{test_address}", headers=headers, timeout=10)
            
            if response.status_code == 200:
                self.console.print("[green]✅ Basescan is accessible[/green]")
                return True
            else:
                self.console.print(f"[red]❌ Basescan returned status code: {response.status_code}[/red]")
                return False

        except Exception as e:
            self.console.print(f"[red]❌ Error testing Basescan: {e}[/red]")
            return False


def main():
    """Test the Basescan fetcher."""
    fetcher = BasescanFetcher()
    
    # Test with USDC on Base
    test_address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    
    print("Testing Basescan API connection...")
    if fetcher.test_api_connection():
        print("✅ API connection successful")
        
        print(f"\nFetching contract info for {test_address}...")
        info = fetcher.get_contract_info(test_address)
        print(f"Contract info: {info}")
        
        if info.get('success'):
            print(f"\nFetching and saving contract source...")
            success, path, data = fetcher.fetch_and_save_contract(test_address)
            if success:
                print(f"✅ Contract saved to: {path}")
            else:
                print(f"❌ Error: {path}")
    else:
        print("❌ API connection failed")


if __name__ == "__main__":
    main()
