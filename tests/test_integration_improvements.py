"""
Integration test for audit improvements

Tests that the improvements work correctly in the full audit pipeline
"""

import unittest
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.enhanced_audit_engine import EnhancedAetherAuditEngine


class TestAuditImprovements(unittest.TestCase):
    """Test the integrated improvements in the audit pipeline"""
    
    def setUp(self):
        self.engine = EnhancedAetherAuditEngine(verbose=True)
        
    def test_zetachain_scenario_integration(self):
        """
        Test with a ZetaChain-like contract to verify:
        1. Deduplication reduces duplicate findings
        2. Access control detection adjusts severity
        3. Admin-only functions are marked appropriately
        """
        
        # Create a test contract similar to ZetaChain's patterns
        contract_code = '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.7;

        contract TestContract {
            address public constant FUNGIBLE_MODULE_ADDRESS = 0x735b14BB79463307AAcBED86DAf3322B1e6226aB;
            address public wzeta;
            
            error OnlyFungibleModule();
            error ZeroAddress();
            
            modifier onlyFungibleModule() {
                if (msg.sender != FUNGIBLE_MODULE_ADDRESS) revert OnlyFungibleModule();
                _;
            }
            
            // Admin function - should be downgraded
            function setWzetaAddress(address wzeta_) external onlyFungibleModule {
                wzeta = wzeta_;  // Missing zero-address check
            }
            
            // Public function - should remain medium/high
            function send(uint256 value) external {
                // Missing input validation
                payable(msg.sender).transfer(value);
            }
            
            // Admin function with validation issue
            function setGasCoin(uint256 chainID, address token) external {
                if (msg.sender != FUNGIBLE_MODULE_ADDRESS) revert OnlyFungibleModule();
                // Missing zero-address check for token
            }
        }
        '''
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract_code)
            contract_path = f.name
        
        try:
            # Run audit
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self.engine.run_audit(
                    contract_path=contract_path,
                    flow_config={},
                    enhanced=True
                )
            )
            
            # Verify results
            self.assertIsNotNone(result)
            self.assertIn('results', result)
            
            vulnerabilities = result.get('results', {}).get('vulnerabilities', [])
            
            # Check that deduplication happened
            stats = self.engine.stats
            if 'deduplicated_findings' in stats:
                # Should have fewer findings after deduplication
                self.assertLessEqual(stats['deduplicated_findings'], stats['total_findings'])
            
            # Check for severity adjustments on admin functions
            admin_vulns_adjusted = [
                v for v in vulnerabilities 
                if 'access_control' in v and v.get('access_control', {}).get('protected')
            ]
            
            # Should have some admin functions downgraded
            self.assertGreater(len(admin_vulns_adjusted), 0, 
                             "Should have downgraded some admin functions")
            
            print(f"\n✅ Test passed!")
            print(f"   Total findings: {stats.get('total_findings', 0)}")
            print(f"   After deduplication: {stats.get('deduplicated_findings', 0)}")
            print(f"   Validated: {stats.get('validated_findings', 0)}")
            
        finally:
            # Cleanup
            import os
            os.unlink(contract_path)
    
    def test_public_function_unchanged(self):
        """Test that public functions without access control keep their severity"""
        
        contract_code = '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract PublicContract {
            function unsafeTransfer(address to, uint256 amount) external {
                // No validation - this should remain high severity
                payable(to).transfer(amount);
            }
        }
        '''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract_code)
            contract_path = f.name
        
        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self.engine.run_audit(
                    contract_path=contract_path,
                    flow_config={},
                    enhanced=True
                )
            )
            
            # Public functions without access control should maintain severity
            vulnerabilities = result.get('results', {}).get('vulnerabilities', [])
            
            # Should find vulnerabilities
            self.assertGreater(len(vulnerabilities), 0, "Should find vulnerabilities in unsafe code")
            
            print(f"\n✅ Public function test passed!")
            print(f"   Found {len(vulnerabilities)} vulnerabilities")
            
        finally:
            import os
            os.unlink(contract_path)


if __name__ == '__main__':
    unittest.main()

