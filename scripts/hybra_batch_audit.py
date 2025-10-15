#!/usr/bin/env python3
"""
Hybra Finance Batch Audit Script

This script runs the audit in smaller batches to avoid rate limits.
Each batch processes a subset of contracts to stay within API limits.
"""

import asyncio
import time
import json
import sys
import os
from pathlib import Path
from typing import List
import subprocess

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import AetherCLI


class HybraBatchAuditor:
    """Batch auditor for Hybra Finance contracts"""

    def __init__(self, contracts_dir: str):
        self.contracts_dir = Path(contracts_dir)
        self.output_dir = Path("hybra_audit_batches")
        self.output_dir.mkdir(exist_ok=True)

        # Get all contract files
        self.contract_files = list(self.contracts_dir.rglob("*.sol"))
        print(f"📁 Found {len(self.contract_files)} contract files")

    def get_contract_batches(self, batch_size: int = 3) -> List[List[Path]]:
        """Split contracts into batches"""
        batches = []
        for i in range(0, len(self.contract_files), batch_size):
            batch = self.contract_files[i:i + batch_size]
            batches.append(batch)
        return batches

    async def audit_batch(self, batch: List[Path], batch_num: int) -> dict:
        """Audit a single batch of contracts"""
        print(f"\n🔍 Auditing batch {batch_num + 1}/{(len(self.contract_files) + 2) // 3}")

        batch_dir = self.output_dir / f"batch_{batch_num + 1}"
        batch_dir.mkdir(exist_ok=True)

        # Create a temporary directory with just these contracts
        temp_dir = Path(f"temp_batch_{batch_num}")
        temp_dir.mkdir(exist_ok=True)

        try:
            # Copy contracts to temp directory
            for contract in batch:
                rel_path = contract.relative_to(self.contracts_dir)
                dest_path = temp_dir / rel_path
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy2(contract, dest_path)

            # Run audit on this batch
            cli = AetherCLI()

            result = await cli.run_audit(
                contract_path=str(temp_dir),
                flow_config="configs/hybra_audit.yaml",
                output_dir=str(batch_dir),
                verbose=True,
                enhanced=True,
                foundry=False  # Disable Foundry for batch processing
            )

            return {
                'batch': batch_num + 1,
                'contracts': [str(c.name) for c in batch],
                'result': result,
                'output_dir': str(batch_dir)
            }

        finally:
            # Clean up temp directory
            if temp_dir.exists():
                import shutil
                shutil.rmtree(temp_dir)

    async def run_all_batches(self):
        """Run audit on all batches"""
        batches = self.get_contract_batches(batch_size=3)

        print(f"🚀 Running audit in {len(batches)} batches of 3 contracts each")

        all_results = []

        for i, batch in enumerate(batches):
            try:
                result = await self.audit_batch(batch, i)
                all_results.append(result)

                # Add delay between batches to respect rate limits
                if i < len(batches) - 1:  # Don't delay after last batch
                    print("⏳ Waiting 30 seconds before next batch...")
                    time.sleep(30)

            except Exception as e:
                print(f"❌ Batch {i + 1} failed: {e}")
                all_results.append({
                    'batch': i + 1,
                    'error': str(e),
                    'contracts': [str(c.name) for c in batch]
                })

        # Save overall results
        results_file = self.output_dir / "batch_results.json"
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)

        print(f"\n✅ Batch audit complete! Results saved to {results_file}")
        return all_results

    def summarize_results(self, results: List[dict]):
        """Summarize the batch audit results"""
        print("\n📋 BATCH AUDIT SUMMARY")
        print("=" * 50)

        total_batches = len(results)
        successful_batches = len([r for r in results if 'error' not in r])

        print(f"Total batches: {total_batches}")
        print(f"Successful batches: {successful_batches}")
        print(f"Failed batches: {total_batches - successful_batches}")

        total_contracts = sum(len(r.get('contracts', [])) for r in results)
        print(f"Total contracts processed: {total_contracts}")

        # Aggregate vulnerabilities across all batches
        total_vulnerabilities = 0
        high_severity_count = 0

        for result in results:
            if 'result' in result and result['result']:
                # Extract vulnerabilities from result
                vulnerabilities = self._extract_vulnerabilities(result['result'])
                total_vulnerabilities += len(vulnerabilities)
                high_severity_count += len([v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']])

        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"High/Critical severity: {high_severity_count}")

        return {
            'total_batches': total_batches,
            'successful_batches': successful_batches,
            'total_contracts': total_contracts,
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
    """Main batch audit function"""
    if len(sys.argv) != 2:
        print("Usage: python scripts/hybra_batch_audit.py /path/to/hybra_contracts")
        sys.exit(1)

    contracts_dir = sys.argv[1]

    if not Path(contracts_dir).exists():
        print(f"❌ Contracts directory does not exist: {contracts_dir}")
        sys.exit(1)

    print("🚀 Starting Hybra Finance batch audit...")
    print("This will process contracts in small batches to avoid rate limits")

    auditor = HybraBatchAuditor(contracts_dir)
    results = await auditor.run_all_batches()
    summary = auditor.summarize_results(results)

    print("\n🎯 Batch audit completed!")
    print(f"📊 Summary: {summary}")

    return summary


if __name__ == "__main__":
    import sys
    summary = asyncio.run(main())
    sys.exit(0)
