#!/usr/bin/env python3
"""
Comprehensive tests for false positive reduction improvements.

Tests:
1. Call Chain Analyzer
2. Constructor Context Detection
3. Architectural Pattern Detector
"""

import pytest
from core.call_chain_analyzer import CallChainAnalyzer, CallPath, FunctionInfo
from core.architectural_patterns import ArchitecturalPatternDetector, ArchitecturalPattern
from core.validation_pipeline import ValidationPipeline


class TestCallChainAnalyzer:
    """Test the Call Chain Analyzer functionality."""
    
    def test_basic_call_chain_building(self):
        """Test building a basic call graph."""
        contracts = [
            {
                'content': '''
                contract Test {
                    function publicFunc() public {
                        internalFunc();
                    }
                    
                    function internalFunc() internal {
                        // Some logic
                    }
                }
                ''',
                'name': 'Test.sol',
                'path': 'contracts/Test.sol'
            }
        ]
        
        analyzer = CallChainAnalyzer()
        result = analyzer.build_call_graph(contracts)
        
        assert result['functions'] >= 2
        assert result['entry_points'] >= 1
        assert 'Test.publicFunc' in analyzer.entry_points
    
    def test_diamond_proxy_call_chain(self):
        """Test call chain analysis for Diamond proxy pattern."""
        facet_code = '''
        contract DiamondCut {
            function diamondCut(
                FacetCut[] calldata _diamondCut,
                address _init,
                bytes calldata _calldata
            ) external restricted {
                LibDiamond.diamondCut(_diamondCut, _init, _calldata);
            }
        }
        '''
        
        library_code = '''
        library LibDiamond {
            function diamondCut(
                FacetCut[] memory _diamondCut,
                address _init,
                bytes memory _calldata
            ) internal {
                _initializeDiamondCut(_init, _calldata);
            }
            
            function _initializeDiamondCut(address _init, bytes memory _calldata) private {
                if (_init == address(0)) return;
                (bool success, ) = _init.delegatecall(_calldata);
                require(success);
            }
        }
        '''
        
        contracts = [
            {'content': facet_code, 'name': 'DiamondCut.sol', 'path': 'contracts/DiamondCut.sol'},
            {'content': library_code, 'name': 'LibDiamond.sol', 'path': 'contracts/LibDiamond.sol'}
        ]
        
        analyzer = CallChainAnalyzer()
        analyzer.build_call_graph(contracts)
        
        # Test that _initializeDiamondCut is protected via call chain
        protection = analyzer.is_function_protected('_initializeDiamondCut', 'LibDiamond')
        
        assert protection['protected'] == True
        assert 'restricted' in protection['reasoning']
        assert len(protection['protected_paths']) > 0
    
    def test_unprotected_function_detection(self):
        """Test detection of truly unprotected functions."""
        code = '''
        contract Test {
            function unprotectedFunction() public {
                // No access control
                criticalOperation();
            }
            
            function criticalOperation() internal {
                // Some critical logic
            }
        }
        '''
        
        contracts = [{'content': code, 'name': 'Test.sol', 'path': 'contracts/Test.sol'}]
        
        analyzer = CallChainAnalyzer()
        analyzer.build_call_graph(contracts)
        
        protection = analyzer.is_function_protected('unprotectedFunction', 'Test')
        
        assert protection['protected'] == False
        assert len(protection['unprotected_paths']) > 0
    
    def test_constructor_only_function(self):
        """Test detection of constructor-only functions."""
        code = '''
        contract Test {
            constructor() {
                initializeInternal();
            }
            
            function initializeInternal() internal {
                // Initialization logic
            }
        }
        '''
        
        contracts = [{'content': code, 'name': 'Test.sol', 'path': 'contracts/Test.sol'}]
        
        analyzer = CallChainAnalyzer()
        analyzer.build_call_graph(contracts)
        
        protection = analyzer.is_function_protected('initializeInternal', 'Test')
        
        # Should be protected (constructor-only)
        assert protection['protected'] == True
        assert 'constructor' in protection['reasoning'].lower()
        assert len(protection['constructor_only_paths']) > 0


class TestConstructorContextDetection:
    """Test constructor context detection in validation pipeline."""
    
    def test_vulnerability_in_constructor(self):
        """Test detecting vulnerabilities in constructor."""
        code = '''
        pragma solidity 0.8.0;
        
        contract Test {
            constructor(address _init) {
                _init.delegatecall("");  // Line 5
            }
            
            function initialize() public {
                // Proper initializer
            }
        }
        '''
        
        pipeline = ValidationPipeline(None, code)
        
        vulnerability = {
            'vulnerability_type': 'delegatecall',
            'description': 'Delegatecall in constructor',
            'line': 5,
            'line_number': 5,
            'code_snippet': '_init.delegatecall("")'
        }
        
        results = pipeline.validate(vulnerability)
        
        # Should be filtered as false positive (constructor + has initializer)
        assert len(results) > 0
        assert results[0].is_false_positive == True
        assert 'constructor' in results[0].reasoning.lower()
    
    def test_runtime_vulnerability_not_filtered(self):
        """Test that runtime vulnerabilities are not filtered."""
        code = '''
        pragma solidity 0.8.0;
        
        contract Test {
            constructor() {
                // Constructor
            }
            
            function runtimeFunction() public {
                address(0).delegatecall("");  // Line 9
            }
        }
        '''
        
        pipeline = ValidationPipeline(None, code)
        
        vulnerability = {
            'vulnerability_type': 'delegatecall',
            'description': 'Delegatecall in runtime function',
            'line': 9,
            'line_number': 9,
            'code_snippet': 'address(0).delegatecall("")'
        }
        
        results = pipeline.validate(vulnerability)
        
        # Should NOT be filtered (runtime context)
        # The constructor check should return None for non-constructor code
        # So the function will continue to other checks
        assert 'constructor_context' not in [r.stage_name for r in results]


class TestArchitecturalPatternDetector:
    """Test architectural pattern detection."""
    
    def test_detect_diamond_pattern(self):
        """Test detection of Diamond proxy pattern."""
        proxy_code = '''
        contract DiamondProxy {
            constructor(FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) {
                LibDiamond.diamondCut(_diamondCut, _init, _calldata);
            }
            
            fallback() external payable {
                DiamondStorage storage ds = diamondStorage();
                address facetAddress = ds.selectorInfo[msg.sig].facetAddress;
                require(facetAddress != address(0), "Function not found");
                
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), facetAddress, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
        '''
        
        library_code = '''
        library LibDiamond {
            function diamondCut(FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) internal {
                // Diamond cut logic
            }
        }
        '''
        
        facet_code = '''
        contract DiamondCutFacet {
            function diamondCut(FacetCut[] calldata _diamondCut) external {
                // Facet logic
            }
        }
        '''
        
        contracts = [
            {'content': proxy_code, 'name': 'DiamondProxy.sol', 'path': 'contracts/DiamondProxy.sol'},
            {'content': library_code, 'name': 'LibDiamond.sol', 'path': 'contracts/LibDiamond.sol'},
            {'content': facet_code, 'name': 'DiamondCutFacet.sol', 'path': 'contracts/facets/DiamondCutFacet.sol'}
        ]
        
        detector = ArchitecturalPatternDetector()
        pattern = detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.pattern_type == 'EIP2535_Diamond'
        assert pattern.confidence > 0.7
        assert 'DiamondProxy' in pattern.indicators_found
        assert pattern.access_control_layer == 'facet'
    
    def test_detect_uups_pattern(self):
        """Test detection of UUPS proxy pattern."""
        code = '''
        import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
        
        contract MyContract is UUPSUpgradeable {
            function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
                // Authorization logic
            }
            
            function upgradeToAndCall(address newImplementation, bytes memory data) external {
                // Upgrade logic
            }
        }
        '''
        
        contracts = [
            {'content': code, 'name': 'MyContract.sol', 'path': 'contracts/MyContract.sol'}
        ]
        
        detector = ArchitecturalPatternDetector()
        pattern = detector.detect_pattern(contracts)
        
        assert pattern is not None
        assert pattern.pattern_type == 'UUPS_Proxy'
        assert 'UUPSUpgradeable' in pattern.indicators_found
    
    def test_adjust_finding_for_diamond_library(self):
        """Test adjusting findings for Diamond pattern libraries."""
        detector = ArchitecturalPatternDetector()
        
        # Create a Diamond pattern
        pattern = ArchitecturalPattern(
            pattern_type='EIP2535_Diamond',
            components={'library': ['LibDiamond.sol']},
            access_control_layer='facet',
            validation_rules={
                'libraries_can_skip_modifiers': True
            },
            confidence=0.9
        )
        
        finding = {
            'vulnerability_type': 'access_control',
            'contract_name': 'LibDiamond',
            'description': 'Function lacks access control',
            'code_snippet': 'function _initializeDiamondCut(...) private',
            'confidence': 0.8,
            'is_false_positive': False
        }
        
        adjusted = detector.adjust_finding_for_pattern(finding, pattern)
        
        assert adjusted['is_false_positive'] == True
        assert 'facet' in adjusted['false_positive_reason'].lower()
        assert 'library' in adjusted['false_positive_reason'].lower()
    
    def test_no_pattern_detected(self):
        """Test that regular contracts don't match any pattern."""
        code = '''
        contract SimpleContract {
            uint256 public value;
            
            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        '''
        
        contracts = [
            {'content': code, 'name': 'SimpleContract.sol', 'path': 'contracts/SimpleContract.sol'}
        ]
        
        detector = ArchitecturalPatternDetector()
        pattern = detector.detect_pattern(contracts)
        
        # Should not detect any pattern
        assert pattern is None


class TestIntegration:
    """Integration tests combining all improvements."""
    
    def test_diamond_proxy_integration(self):
        """
        Full integration test simulating parallel-parallelizer analysis.
        Should NOT flag LibDiamond._initializeDiamondCut as vulnerable.
        """
        # This would be a full integration test with the actual detector
        # For now, we verify the components work together
        
        contracts = [
            {
                'content': '''
                contract DiamondProxy {
                    constructor(FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) {
                        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
                    }
                }
                ''',
                'name': 'DiamondProxy.sol',
                'path': 'contracts/DiamondProxy.sol'
            },
            {
                'content': '''
                contract DiamondCut {
                    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external restricted {
                        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
                    }
                }
                ''',
                'name': 'DiamondCut.sol',
                'path': 'contracts/facets/DiamondCut.sol'
            },
            {
                'content': '''
                library LibDiamond {
                    function diamondCut(FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) internal {
                        _initializeDiamondCut(_init, _calldata);
                    }
                    
                    function _initializeDiamondCut(address _init, bytes memory _calldata) private {
                        if (_init == address(0)) return;
                        (bool success,) = _init.delegatecall(_calldata);
                        require(success);
                    }
                }
                ''',
                'name': 'LibDiamond.sol',
                'path': 'contracts/libraries/LibDiamond.sol'
            }
        ]
        
        # Test call chain analysis
        call_analyzer = CallChainAnalyzer()
        call_analyzer.build_call_graph(contracts)
        
        protection = call_analyzer.is_function_protected('_initializeDiamondCut', 'LibDiamond')
        assert protection['protected'] == True, "Library function should be protected via call chain"
        
        # Test architectural pattern detection
        arch_detector = ArchitecturalPatternDetector()
        pattern = arch_detector.detect_pattern(contracts)
        
        assert pattern is not None, "Should detect Diamond pattern"
        assert pattern.pattern_type == 'EIP2535_Diamond'
        
        # Test finding adjustment
        finding = {
            'vulnerability_type': 'access_control',
            'contract_name': 'LibDiamond',
            'description': 'Function _initializeDiamondCut lacks access control',
            'code_snippet': 'function _initializeDiamondCut(address _init, bytes memory _calldata) private',
            'confidence': 0.8,
            'is_false_positive': False
        }
        
        adjusted = arch_detector.adjust_finding_for_pattern(finding, pattern)
        assert adjusted['is_false_positive'] == True, "Should be filtered as false positive for Diamond library"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

