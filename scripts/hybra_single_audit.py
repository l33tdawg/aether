#!/usr/bin/env python3
"""
Hybra Finance Single Contract Audit Script

This script runs the audit on individual contracts one at a time with delays
to avoid rate limits while still processing all contracts.
"""

import asyncio
import time
import json
import sys
import os
from pathlib import Path
from typing import List

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib.util
spec = importlib.util.spec_from_file_location("cli.main", "/Users/l33tdawg/nodejs-projects/bugbounty/cli/main.py")
cli_main = importlib.util.module_from_spec(spec)
sys.modules["cli.main"] = cli_main
spec.loader.exec_module(cli_main)

AetherCLI = cli_main.AetherCLI


class HybraSingleAuditor:
    """Single contract auditor for Hybra Finance"""

    def __init__(self, contracts_dir: str):
        self.contracts_dir = Path(contracts_dir)
        self.output_dir = Path("hybra_single_audit")
        self.output_dir.mkdir(exist_ok=True)

        # Get all contract files
        self.contract_files = list(self.contracts_dir.rglob("*.sol"))
        print(f"📁 Found {len(self.contract_files)} contract files")

    async def audit_single_contract(self, contract_path: Path, contract_num: int) -> dict:
        """Audit a single contract"""
        contract_name = contract_path.name
        print(f"\n🔍 Auditing contract {contract_num + 1}/{len(self.contract_files)}: {contract_name}")

        # Create output directory for this contract
        contract_output_dir = self.output_dir / contract_name.replace('.sol', '')
        contract_output_dir.mkdir(exist_ok=True)

        try:
            # Run audit on this single contract
            cli = AetherCLI()

            result = await cli.run_audit(
                contract_path=str(contract_path),
                flow_config="configs/hybra_audit.yaml",
                output_dir=str(contract_output_dir),
                verbose=False,  # Reduce verbosity to avoid spam
                enhanced=True,
                foundry=False  # Disable Foundry for individual contracts
            )

            return {
                'contract': contract_name,
                'path': str(contract_path),
                'success': True,
                'result': result,
                'output_dir': str(contract_output_dir)
            }

        except Exception as e:
            print(f"❌ Failed to audit {contract_name}: {e}")
            return {
                'contract': contract_name,
                'path': str(contract_path),
                'success': False,
                'error': str(e),
                'output_dir': str(contract_output_dir)
            }

    async def run_all_contracts(self):
        """Run audit on all contracts one by one"""
        print(f"🚀 Running audit on {len(self.contract_files)} contracts individually")
        print("⏳ This will take time due to rate limiting and processing delays")

        all_results = []

        for i, contract_file in enumerate(self.contract_files):
            try:
                result = await self.audit_single_contract(contract_file, i)
                all_results.append(result)

                # Add delay between contracts to respect rate limits
                if i < len(self.contract_files) - 1:  # Don't delay after last contract
                    delay = 60  # 60 seconds between contracts
                    print(f"⏳ Waiting {delay} seconds before next contract...")
                    time.sleep(delay)

            except Exception as e:
                print(f"❌ Contract {i + 1} failed completely: {e}")
                all_results.append({
                    'contract': contract_file.name,
                    'path': str(contract_file),
                    'success': False,
                    'error': f"Complete failure: {e}"
                })

        # Save overall results
        results_file = self.output_dir / "single_audit_results.json"
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)

        print(f"\n✅ Single contract audit complete! Results saved to {results_file}")
        return all_results

    def summarize_results(self, results: List[dict]):
        """Summarize the single contract audit results"""
        print("\n📋 SINGLE CONTRACT AUDIT SUMMARY")
        print("=" * 50)

        total_contracts = len(results)
        successful_contracts = len([r for r in results if r.get('success', False)])

        print(f"Total contracts: {total_contracts}")
        print(f"Successful audits: {successful_contracts}")
        print(f"Failed audits: {total_contracts - successful_contracts}")

        # Aggregate vulnerabilities across all contracts
        total_vulnerabilities = 0
        high_severity_count = 0

        for result in results:
            if result.get('success', False) and 'result' in result:
                # Extract vulnerabilities from result
                vulnerabilities = self._extract_vulnerabilities(result['result'])
                total_vulnerabilities += len(vulnerabilities)
                high_severity_count += len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])

        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"High/Critical severity: {high_severity_count}")

        return {
            'total_contracts': total_contracts,
            'successful_contracts': successful_contracts,
            'total_vulnerabilities': total_vulnerabilities,
            'high_severity_count': high_severity_count
        }

    def _extract_vulnerabilities(self, result: dict) -> List[dict]:
        """Extract vulnerabilities from audit result"""
        vulnerabilities = []

        if isinstance(result, dict):
            # Check different possible result structures
            for key in ['reportnode', 'results']:
                if key in result:
                    data = result[key]
                    if isinstance(data, dict) and 'results' in data:
                        vulns = data['results'].get('vulnerabilities', [])
                        if isinstance(vulns, list):
                            vulnerabilities.extend(vulns)

        return vulnerabilities


async def main():
    """Main single contract audit function"""
    if len(sys.argv) != 2:
        print("Usage: python scripts/hybra_single_audit.py /path/to/hybra_contracts")
        sys.exit(1)

    contracts_dir = sys.argv[1]

    if not Path(contracts_dir).exists():
        print(f"❌ Contracts directory does not exist: {contracts_dir}")
        sys.exit(1)

    print("🚀 Starting Hybra Finance single contract audit...")
    print("This will process each contract individually with 60-second delays")

    auditor = HybraSingleAuditor(contracts_dir)
    results = await auditor.run_all_contracts()
    summary = auditor.summarize_results(results)

    print("\n🎯 Single contract audit completed!")
    print(f"📊 Summary: {summary}")

    return summary


if __name__ == "__main__":
    summary = asyncio.run(main())
    sys.exit(0)
