"""
Comprehensive Test Suite for Centralization Detector
"""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.centralization_detector import CentralizationDetector


class TestUnlimitedMinting(unittest.TestCase):
    """Test unlimited minting detection"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_owner_unlimited_mint(self):
        """Test detection of unlimited minting by owner"""
        code = """
        function mint(address to, uint256 amount) external onlyOwner {
            _mint(to, amount);  // No cap
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        minting_vulns = [v for v in results if v.vulnerability_type == 'unlimited_minting']
        self.assertGreater(len(minting_vulns), 0)
    
    def test_mint_without_supply_cap(self):
        """Test detection of minting without supply cap check"""
        code = """
        function mint(uint256 amount) external {
            _mint(msg.sender, amount);  // No maxSupply check
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        minting_vulns = [v for v in results if v.vulnerability_type == 'unlimited_minting']
        self.assertGreater(len(minting_vulns), 0)


class TestUnlimitedBurning(unittest.TestCase):
    """Test unlimited burning detection"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_admin_burn_from_any_address(self):
        """Test detection of admin burning from arbitrary addresses"""
        code = """
        function burnFrom(address from, uint256 amount) external onlyOwner {
            _burn(from, amount);  // Can burn from anyone
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        burning_vulns = [v for v in results if v.vulnerability_type == 'unlimited_burning']
        self.assertGreater(len(burning_vulns), 0)


class TestMissingMultisig(unittest.TestCase):
    """Test missing multisig detection"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_pause_without_multisig(self):
        """Test detection of pause function without multisig"""
        code = """
        function pause() external onlyOwner {
            _pause();  // Critical function, needs multisig
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        multisig_vulns = [v for v in results if v.vulnerability_type == 'no_multisig']
        self.assertGreater(len(multisig_vulns), 0)


class TestSinglePointFailure(unittest.TestCase):
    """Test single point of failure detection"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_many_privileged_functions(self):
        """Test detection of many privileged functions"""
        code = """
        function setFee() external onlyOwner {}
        function pause() external onlyOwner {}
        function unpause() external onlyOwner {}
        function setRate() external onlyOwner {}
        function upgrade() external onlyOwner {}
        function withdraw() external onlyOwner {}
        function mint() external onlyOwner {}
        """
        results = self.detector.analyze_centralization_risks(code)
        spof_vulns = [v for v in results if v.vulnerability_type == 'single_point_of_failure']
        self.assertGreater(len(spof_vulns), 0)
    
    def test_privileged_withdrawal(self):
        """Test detection of privileged withdrawal functions"""
        code = """
        function withdrawFees() external onlyOwner {
            payable(owner).transfer(address(this).balance);
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        withdrawal_vulns = [v for v in results if v.vulnerability_type == 'privileged_withdrawal']
        self.assertGreater(len(withdrawal_vulns), 0)


class TestCentralizationSummary(unittest.TestCase):
    """Test centralization summary"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_summary_with_multiple_risks(self):
        """Test summary generation with multiple centralization risks"""
        code = """
        function mint(uint256 amount) external onlyOwner {
            _mint(msg.sender, amount);
        }
        function pause() external onlyOwner {
            _pause();
        }
        function withdraw() external onlyOwner {
            payable(owner).transfer(address(this).balance);
        }
        """
        summary = self.detector.get_centralization_summary(code)
        self.assertIn('total_vulnerabilities', summary)
        self.assertIn('privileged_functions_count', summary)
        self.assertGreater(summary['privileged_functions_count'], 0)


if __name__ == '__main__':
    unittest.main()

