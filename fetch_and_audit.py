#!/usr/bin/env python3
"""
Script to fetch contract source code from Etherscan and run audit.
"""

import asyncio
import json
import os
import requests
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from cli.main import AetherCLI


def fetch_contract_from_etherscan(address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Fetch contract source code from Etherscan API."""
    print(f"🔍 Fetching contract source code for {address}...")
    
    # Try to get API key from environment
    if not api_key:
        api_key = os.getenv('ETHERSCAN_API_KEY')
    
    # Try to get API key from config manager
    if not api_key:
        try:
            from core.config_manager import ConfigManager
            cm = ConfigManager()
            api_key = cm.config.etherscan_api_key
        except Exception:
            pass
    
    if not api_key:
        print("⚠️  Warning: No Etherscan API key provided. Using public endpoint (may be rate limited).")
        api_key = "YourApiKeyToken"
    
    url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') != '1':
            error_msg = data.get('message', 'Unknown error')
            if 'rate limit' in error_msg.lower():
                print("❌ Etherscan API rate limit exceeded. Please try again later.")
            else:
                print(f"❌ Etherscan API error: {error_msg}")
            return {}
        
        result = data.get('result', [])
        if not result:
            print("❌ No contract data found")
            return {}
        
        contract_data = result[0]
        
        if not contract_data.get('SourceCode'):
            print("❌ Contract source code is not available (not verified)")
            return {}
        
        source_code = contract_data['SourceCode']
        contract_name = contract_data.get('ContractName', 'UnknownContract')
        
        print(f"✅ Successfully fetched contract: {contract_name}")
        print(f"📄 Source code length: {len(source_code)} characters")
        
        return {
            'source_code': source_code,
            'contract_name': contract_name,
            'address': address,
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
            'swarm_source': contract_data.get('SwarmSource', '')
        }
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error fetching contract: {e}")
        return {}
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        return {}
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return {}


def save_contract_source(contract_data: Dict[str, Any], output_dir: str = "temp_contracts") -> str:
    """Save contract source code to a file."""
    os.makedirs(output_dir, exist_ok=True)
    
    contract_name = contract_data.get('contract_name', 'UnknownContract')
    address = contract_data.get('address', 'unknown')
    
    # Clean contract name for filename
    safe_name = "".join(c for c in contract_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
    safe_name = safe_name.replace(' ', '_')
    
    filename = f"{safe_name}_{address[:8]}.sol"
    filepath = os.path.join(output_dir, filename)
    
    # Handle different source code formats
    source_code = contract_data['source_code']
    
    # Check if source code is JSON (for multi-file contracts)
    if source_code.startswith('{'):
        try:
            source_json = json.loads(source_code)
            if 'sources' in source_json:
                # Multi-file contract
                print(f"📁 Detected multi-file contract with {len(source_json['sources'])} files")
                
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
                
                return contract_dir
        except json.JSONDecodeError:
            # Not JSON, treat as single file
            pass
    
    # Single file contract
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(source_code)
    
    print(f"💾 Saved contract source to: {filepath}")
    return filepath


async def run_audit_on_contract(contract_path: str, verbose: bool = True) -> Dict[str, Any]:
    """Run the audit tool on the fetched contract."""
    print(f"🚀 Starting audit on {contract_path}...")
    
    cli = AetherCLI()
    
    try:
        result = await cli.run_audit(
            contract_path=contract_path,
            flow_config="configs/default_audit.yaml",
            output_dir=None,  # Let it create timestamped directory
            verbose=verbose
        )
        
        if result and not result.get('error'):
            print("✅ Audit completed successfully!")
            return result
        else:
            print(f"❌ Audit failed: {result.get('error', 'Unknown error')}")
            return result
            
    except Exception as e:
        print(f"❌ Audit error: {e}")
        return {'error': str(e)}


async def main():
    """Main function to fetch and audit contract."""
    if len(sys.argv) < 2:
        print("Usage: python fetch_and_audit.py <contract_address> [etherscan_api_key]")
        print("Example: python fetch_and_audit.py 0xEFFC18fC3b7eb8E676dac549E0c693ad50D1Ce31")
        sys.exit(1)
    
    address = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Validate address format
    if not address.startswith('0x') or len(address) != 42:
        print("❌ Invalid Ethereum address format")
        sys.exit(1)
    
    print(f"🎯 Target contract: {address}")
    print("=" * 60)
    
    # Step 1: Fetch contract from Etherscan
    contract_data = fetch_contract_from_etherscan(address, api_key)
    
    if not contract_data:
        print("❌ Failed to fetch contract data")
        sys.exit(1)
    
    # Step 2: Save contract source code
    contract_path = save_contract_source(contract_data)
    
    if not contract_path:
        print("❌ Failed to save contract source")
        sys.exit(1)
    
    print("=" * 60)
    
    # Step 3: Run audit
    audit_result = await run_audit_on_contract(contract_path, verbose=True)
    
    print("=" * 60)
    print("📋 AUDIT SUMMARY")
    print("=" * 60)
    
    if audit_result and not audit_result.get('error'):
        # Extract summary from results
        vulnerabilities = []
        if 'reportnode' in audit_result:
            report_data = audit_result['reportnode']
            if 'results' in report_data and 'vulnerabilities' in report_data['results']:
                vulnerabilities = report_data['results']['vulnerabilities']
        
        total_vulns = len(vulnerabilities)
        high_severity = len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])
        
        print(f"Contract: {contract_data['contract_name']} ({address})")
        print(f"Total vulnerabilities found: {total_vulns}")
        print(f"High severity issues: {high_severity}")
        
        if total_vulns > 0:
            print("\n🔍 Top vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                severity = vuln.get('severity', 'unknown').upper()
                title = vuln.get('title', 'Unknown vulnerability')
                print(f"  {i}. [{severity}] {title}")
        
        if high_severity > 0:
            print(f"\n⚠️  Found {high_severity} high-severity issues that need attention!")
        else:
            print("\n✅ No critical issues found")
            
    else:
        print(f"❌ Audit failed: {audit_result.get('error', 'Unknown error')}")
    
    print("=" * 60)
    print("🎯 Tool testing completed!")


if __name__ == "__main__":
    asyncio.run(main())
