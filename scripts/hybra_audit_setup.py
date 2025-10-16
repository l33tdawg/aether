#!/usr/bin/env python3
"""
Hybra Finance Audit Setup Script

This script helps set up the environment for auditing the Hybra Finance protocol.
It handles the specific requirements including bytecode migration and cross-repo dependencies.

Usage:
    python scripts/hybra_audit_setup.py /path/to/hybra-repo
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


class HybraAuditSetup:
    """Setup utilities for Hybra Finance audit"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.ve33_path = self.repo_path / "ve33"
        self.cl_path = self.repo_path / "cl"

    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are installed"""
        print("🔍 Checking prerequisites...")

        # Check Node.js and npm
        try:
            subprocess.run(["node", "--version"], check=True, capture_output=True)
            subprocess.run(["npm", "--version"], check=True, capture_output=True)
            print("✅ Node.js and npm found")
        except subprocess.CalledProcessError:
            print("❌ Node.js and npm are required but not found")
            return False

        # Check Foundry
        try:
            env = os.environ.copy()
            foundry_bin = os.path.expanduser("~/.foundry/bin")
            if os.path.exists(foundry_bin):
                env['PATH'] = f"{foundry_bin}:{env.get('PATH', '')}"
            subprocess.run(["forge", "--version"], check=True, capture_output=True, env=env)
            print("✅ Foundry found")
        except subprocess.CalledProcessError:
            print("❌ Foundry is required but not found")
            return False

        return True

    def setup_ve33_dependencies(self) -> bool:
        """Install npm dependencies for ve33"""
        print("📦 Installing ve33 dependencies...")

        if not self.ve33_path.exists():
            print(f"❌ ve33 directory not found at {self.ve33_path}")
            return False

        try:
            result = subprocess.run(
                ["npm", "install"],
                cwd=self.ve33_path,
                check=True,
                capture_output=True,
                text=True
            )
            print("✅ ve33 dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install ve33 dependencies: {e.stderr}")
            return False

    def compile_cl_contracts(self) -> bool:
        """Compile cl contracts (Solidity 0.7.6)"""
        print("🔨 Compiling cl contracts...")

        if not self.cl_path.exists():
            print(f"❌ cl directory not found at {self.cl_path}")
            return False

        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=self.cl_path,
                check=True,
                capture_output=True,
                text=True
            )
            print("✅ cl contracts compiled")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to compile cl contracts: {e.stderr}")
            return False

    def generate_bytecode_migration(self) -> bool:
        """Generate bytecode migration JSON for ve33"""
        print("🔄 Generating bytecode migration...")

        if not self.cl_path.exists():
            print(f"❌ cl directory not found at {self.cl_path}")
            return False

        migration_script = self.cl_path / "script" / "ExportDeployments.s.sol"
        if not migration_script.exists():
            print(f"❌ Migration script not found at {migration_script}")
            return False

        try:
            result = subprocess.run(
                ["forge", "script", "script/ExportDeployments.s.sol"],
                cwd=self.cl_path,
                check=True,
                capture_output=True,
                text=True
            )
            print("✅ Bytecode migration generated")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate bytecode migration: {e.stderr}")
            return False

    def compile_ve33_contracts(self) -> bool:
        """Compile ve33 contracts (Solidity 0.8.13)"""
        print("🔨 Compiling ve33 contracts...")

        if not self.ve33_path.exists():
            print(f"❌ ve33 directory not found at {self.ve33_path}")
            return False

        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=self.ve33_path,
                check=True,
                capture_output=True,
                text=True
            )
            print("✅ ve33 contracts compiled")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to compile ve33 contracts: {e.stderr}")
            return False

    def run_test_suites(self) -> bool:
        """Run the C4PoC test suites"""
        print("🧪 Running test suites...")

        # Test cl contracts
        if self.cl_path.exists():
            print("Testing cl contracts...")
            try:
                result = subprocess.run(
                    ["forge", "test", "--match-test", "submissionValidity", "-vvv"],
                    cwd=self.cl_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✅ cl test suite passed")
            except subprocess.CalledProcessError as e:
                print(f"❌ cl test suite failed: {e.stderr}")
                return False

        # Test ve33 contracts
        if self.ve33_path.exists():
            print("Testing ve33 contracts...")
            try:
                result = subprocess.run(
                    ["forge", "test", "--match-test", "submissionValidity", "-vvv"],
                    cwd=self.ve33_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✅ ve33 test suite passed")
            except subprocess.CalledProcessError as e:
                print(f"❌ ve33 test suite failed: {e.stderr}")
                return False

        return True

    def get_in_scope_contracts(self) -> List[str]:
        """Get list of in-scope contracts"""
        in_scope = [
            # ve33 contracts
            "ve33/contracts/GaugeManager.sol",
            "ve33/contracts/GaugeV2.sol",
            "ve33/contracts/MinterUpgradeable.sol",
            "ve33/contracts/VoterV3.sol",
            "ve33/contracts/VotingEscrow.sol",
            "ve33/contracts/GovernanceHYBR.sol",
            "ve33/contracts/HYBR.sol",
            "ve33/contracts/RewardHYBR.sol",
            "ve33/contracts/swapper/HybrSwapper.sol",
            "ve33/contracts/CLGauge/GaugeCL.sol",
            "ve33/contracts/CLGauge/GaugeFactoryCL.sol",
            # cl contracts
            "cl/contracts/core/CLFactory.sol",
            "cl/contracts/core/CLPool.sol",
            "cl/contracts/core/fees/DynamicSwapFeeModule.sol"
        ]

        return [str(self.repo_path / contract) for contract in in_scope if (self.repo_path / contract).exists()]

    def setup_audit_environment(self) -> bool:
        """Complete setup process"""
        print("🚀 Setting up Hybra Finance audit environment...")

        steps = [
            ("Prerequisites check", self.check_prerequisites),
            ("ve33 dependencies", self.setup_ve33_dependencies),
            ("cl compilation", self.compile_cl_contracts),
            ("Bytecode migration", self.generate_bytecode_migration),
            ("ve33 compilation", self.compile_ve33_contracts),
            ("Test suites", self.run_test_suites)
        ]

        for step_name, step_func in steps:
            print(f"\n📋 {step_name}...")
            if not step_func():
                print(f"❌ Failed at step: {step_name}")
                return False

        print("\n✅ Hybra Finance audit environment setup complete!")
        return True


def main():
    """Main setup function"""
    if len(sys.argv) != 2:
        print("Usage: python scripts/hybra_audit_setup.py /path/to/hybra-repo")
        sys.exit(1)

    repo_path = sys.argv[1]

    setup = HybraAuditSetup(repo_path)

    if not setup.repo_path.exists():
        print(f"❌ Repository path does not exist: {repo_path}")
        sys.exit(1)

    success = setup.setup_audit_environment()

    if success:
        print("\n🎯 Ready for Hybra Finance audit!")
        print(f"📁 Repository: {repo_path}")
        print(f"📋 In-scope contracts: {len(setup.get_in_scope_contracts())}")

        # Show next steps
        print("\n🔄 Next steps:")
        print("1. Run the audit: python main.py run ve33/ cl/ --flow configs/hybra_audit.yaml --enhanced")
        print("2. Generate PoCs: python main.py generate-foundry --from-results results.json")
        print("3. Fork validation: python main.py fork-verify output/hybra_foundry_tests/ --rpc-url YOUR_RPC_URL")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
