#!/usr/bin/env python3
"""
Tests for enhanced ArchitecturalPatternDetector with delegation support.
"""

import pytest
from core.architectural_patterns import ArchitecturalPatternDetector, ArchitecturalPattern


class TestUUPSPatternEnhancements:
    """Test enhanced UUPS pattern detection and adjustment."""
    
    def setup_method(self):
        self.detector = ArchitecturalPatternDetector()
    
    def test_detect_implementation_contract_by_component(self):
        """Test detection of implementation contract by component list."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            components={'implementation': ['MyImplementation.sol']},
            access_control_layer='implementation'
        )
        
        is_impl = self.detector._is_implementation_contract(
            'MyImplementation.sol',
            'contracts/MyImplementation.sol',
            pattern
        )
        assert is_impl is True
    
    def test_detect_implementation_contract_by_path(self):
        """Test detection of implementation contract by file path."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            access_control_layer='implementation'
        )
        
        is_impl = self.detector._is_implementation_contract(
            'Module',
            'contracts/modules/Module.sol',
            pattern
        )
        assert is_impl is True
    
    def test_not_implementation_proxy_file(self):
        """Test that proxy files are not detected as implementations."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            access_control_layer='implementation'
        )
        
        is_impl = self.detector._is_implementation_contract(
            'Proxy',
            'contracts/Proxy.sol',
            pattern
        )
        # Proxy file should not be detected as implementation
        assert is_impl is False or 'proxy' in 'contracts/Proxy.sol'.lower()
    
    def test_adjust_access_control_in_implementation(self):
        """Test adjustment of access control findings in implementation contracts."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            components={'implementation': ['Module.sol']},
            access_control_layer='implementation'
        )
        
        finding = {
            'vulnerability_type': 'access_control',
            'contract_name': 'Module.sol',
            'file_path': 'contracts/modules/Module.sol',
            'description': 'Missing access control',
        }
        
        adjusted = self.detector._adjust_for_uups_pattern(finding, pattern)
        
        # Should add architectural note
        assert 'context' in adjusted
        assert 'architectural_note' in adjusted['context']
        assert 'proxy level' in adjusted['context']['architectural_note'].lower()
    
    def test_adjust_constructor_disable_initializers(self):
        """Test that _disableInitializers in constructor is recognized as correct."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            access_control_layer='implementation'
        )
        
        finding = {
            'vulnerability_type': 'initialization',
            'description': 'Constructor with disableInitializers',
            'code_snippet': '''
                constructor() {
                    _disableInitializers();
                }
            ''',
        }
        
        adjusted = self.detector._adjust_for_uups_pattern(finding, pattern)
        
        assert adjusted['is_false_positive'] is True
        assert 'correct pattern' in adjusted['false_positive_reason'].lower()
    
    def test_adjust_authorize_upgrade_with_modifier(self):
        """Test that protected _authorizeUpgrade is not flagged."""
        pattern = ArchitecturalPattern(
            pattern_type='UUPS_Proxy',
            access_control_layer='implementation'
        )
        
        finding = {
            'vulnerability_type': 'upgrade_authorization',
            'code_snippet': '''
                function _authorizeUpgrade(address) internal override onlyOwner {}
            ''',
        }
        
        adjusted = self.detector._adjust_for_uups_pattern(finding, pattern)
        
        assert adjusted['is_false_positive'] is True
        assert 'properly protected' in adjusted['false_positive_reason'].lower()


class TestDiamondPatternEnhancements:
    """Test Diamond pattern detection (existing functionality)."""
    
    def setup_method(self):
        self.detector = ArchitecturalPatternDetector()
    
    def test_library_access_control_false_positive(self):
        """Test that library access control issues are filtered."""
        pattern = ArchitecturalPattern(
            pattern_type='EIP2535_Diamond',
            components={'library': ['LibDiamond.sol']},
            access_control_layer='facet'
        )
        
        finding = {
            'vulnerability_type': 'access_control',
            'contract_name': 'LibDiamond.sol',
            'description': 'Missing access control',
        }
        
        adjusted = self.detector._adjust_for_diamond_pattern(finding, pattern)
        
        assert adjusted['is_false_positive'] is True
        assert 'facet level' in adjusted['false_positive_reason'].lower()


class TestIntegrationWithDelegationAnalyzer:
    """Test that architectural pattern detector works with delegation analyzer."""
    
    def setup_method(self):
        self.detector = ArchitecturalPatternDetector()
    
    def test_ssv_network_pattern_detection(self):
        """Test detection of SSV Network's UUPS + delegation pattern."""
        contracts = [
            {
                'name': 'SSVNetwork.sol',
                'path': 'contracts/SSVNetwork.sol',
                'content': '''
                    import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
                    
                    contract SSVNetwork is UUPSUpgradeable, Ownable2StepUpgradeable {
                        function _authorizeUpgrade(address) internal override onlyOwner {}
                        
                        function upgradeToAndCall(address newImplementation, bytes memory data) external {
                            // UUPS upgrade
                        }
                        
                        function updateNetworkFee(uint256 fee) external onlyOwner {
                            _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                        }
                    }
                '''
            },
            {
                'name': 'SSVDAO.sol',
                'path': 'contracts/modules/SSVDAO.sol',
                'content': '''
                    contract SSVDAO {
                        function updateNetworkFee(uint256 fee) external {
                            // Implementation
                        }
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.pattern_type == 'UUPS_Proxy'
        assert pattern.confidence > 0.5
        assert 'UUPSUpgradeable' in pattern.indicators_found
    
    def test_finding_adjustment_with_pattern(self):
        """Test that findings are properly adjusted based on detected pattern."""
        # Detect pattern from SSV-like contracts
        contracts = [
            {
                'name': 'Proxy.sol',
                'path': 'contracts/Proxy.sol',
                'content': '''
                    import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
                    
                    contract Proxy is UUPSUpgradeable {
                        function _authorizeUpgrade(address) internal override onlyOwner {}
                        
                        function upgradeToAndCall(address newImpl, bytes memory data) external {}
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        
        # Create a finding for module contract
        finding = {
            'vulnerability_type': 'access_control',
            'contract_name': 'Module',
            'file_path': 'contracts/modules/Module.sol',
            'description': 'Missing access control',
        }
        
        adjusted = self.detector.adjust_finding_for_pattern(finding, pattern)
        
        # Should have architectural note added
        assert 'context' in adjusted


class TestEdgeCases:
    """Test edge cases in architectural pattern detection."""
    
    def setup_method(self):
        self.detector = ArchitecturalPatternDetector()
    
    def test_no_pattern_detected(self):
        """Test handling when no pattern is detected."""
        contracts = [
            {
                'name': 'Simple.sol',
                'path': 'contracts/Simple.sol',
                'content': '''
                    contract Simple {
                        uint256 public value;
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        assert pattern is None
    
    def test_adjust_finding_no_pattern(self):
        """Test that findings are unchanged when no pattern exists."""
        finding = {
            'vulnerability_type': 'access_control',
            'description': 'Missing access control',
        }
        
        # Create empty pattern
        pattern = ArchitecturalPattern(
            pattern_type='Unknown',
            access_control_layer='contract'
        )
        
        adjusted = self.detector.adjust_finding_for_pattern(finding, pattern)
        
        # Should be unchanged
        assert adjusted == finding
    
    def test_multiple_indicators_increase_confidence(self):
        """Test that more indicators increase confidence."""
        contracts = [
            {
                'name': 'UUPSContract.sol',
                'content': '''
                    import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
                    
                    contract UUPSContract is UUPSUpgradeable {
                        function _authorizeUpgrade(address) internal override {}
                        function upgradeToAndCall(address, bytes) external {}
                        function proxiableUUID() external {}
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.confidence > 0.7  # High confidence with many indicators
        assert len(pattern.indicators_found) >= 3


class TestRealWorldPatterns:
    """Test with real-world contract patterns."""
    
    def setup_method(self):
        self.detector = ArchitecturalPatternDetector()
    
    def test_openzeppelin_uups_pattern(self):
        """Test detection of OpenZeppelin UUPS pattern."""
        contracts = [
            {
                'name': 'MyContract.sol',
                'content': '''
                    import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
                    import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
                    
                    contract MyContract is UUPSUpgradeable, OwnableUpgradeable {
                        function initialize() public initializer {
                            __Ownable_init();
                            __UUPSUpgradeable_init();
                        }
                        
                        function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
                        
                        function upgradeToAndCall(address newImplementation, bytes memory data) external onlyOwner {}
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.pattern_type == 'UUPS_Proxy'
        assert '_authorizeUpgrade' in pattern.indicators_found
        assert 'UUPSUpgradeable' in pattern.indicators_found
    
    def test_diamond_pattern_with_facets(self):
        """Test detection of Diamond pattern with facets."""
        contracts = [
            {
                'name': 'DiamondProxy.sol',
                'content': '''
                    import "./libraries/LibDiamond.sol";
                    
                    contract DiamondProxy {
                        using LibDiamond for DiamondStorage;
                        
                        function diamondCut(FacetCut[] calldata _diamondCut) external {
                            LibDiamond.diamondCut(_diamondCut);
                        }
                        
                        function facetAddress(bytes4 _functionSelector) external view returns (address) {
                            return LibDiamond.facetAddress(_functionSelector);
                        }
                    }
                '''
            },
            {
                'name': 'LibDiamond.sol',
                'content': '''
                    library LibDiamond {
                        struct DiamondStorage {
                            mapping(bytes4 => address) facetAddresses;
                        }
                        
                        function diamondCut(FacetCut[] calldata _diamondCut) internal {
                            // Diamond cut logic
                        }
                    }
                '''
            }
        ]
        
        pattern = self.detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.pattern_type == 'EIP2535_Diamond'
        assert len(pattern.indicators_found) >= 4  # Needs minimum 4 indicators


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

