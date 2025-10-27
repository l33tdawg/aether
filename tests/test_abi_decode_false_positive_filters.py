"""
Test Suite for ABI Decode False Positive Filters

Tests the improvements to data_decoding_analyzer.py that filter out
common false positives for abi.decode operations.
"""

import pytest
from core.data_decoding_analyzer import DataDecodingAnalyzer


class TestAbiDecodeFalsePositiveFilters:
    """Test false positive filtering for abi.decode operations"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = DataDecodingAnalyzer()
    
    def test_view_function_abi_decode_filtered(self):
        """Test that abi.decode in view functions is filtered out"""
        contract = """
        contract Resolver {
            function resolve(bytes calldata name) external view returns (bytes memory) {
                (string memory result, address resolver) = abi.decode(response, (string, address));
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode in view function
        assert len(vulnerabilities) == 0, "View function abi.decode should be filtered"
    
    def test_pure_function_abi_decode_filtered(self):
        """Test that abi.decode in pure functions is filtered out"""
        contract = """
        contract Utils {
            function decodeData(bytes memory data) public pure returns (uint256, address) {
                (uint256 amount, address recipient) = abi.decode(data, (uint256, address));
                return (amount, recipient);
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode in pure function
        assert len(vulnerabilities) == 0, "Pure function abi.decode should be filtered"
    
    def test_external_call_result_decode_filtered(self):
        """Test that decoding external call results is filtered out"""
        contract = """
        contract Caller {
            function getData() public returns (bytes memory) {
                (bool success, bytes memory returnData) = target.call(data);
                require(success, "Call failed");
                (uint256 value) = abi.decode(returnData, (uint256));
                return value;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode of returnData from .call()
        assert len(vulnerabilities) == 0, "External call result decode should be filtered"
    
    def test_staticcall_result_decode_filtered(self):
        """Test that decoding staticcall results is filtered out"""
        contract = """
        contract Reader {
            function readValue() public view returns (uint256) {
                (bool success, bytes memory data) = target.staticcall(callData);
                require(success);
                uint256 result = abi.decode(data, (uint256));
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode of data from .staticcall()
        assert len(vulnerabilities) == 0, "Staticcall result decode should be filtered"
    
    def test_ccip_read_extradata_filtered(self):
        """Test that CCIP-Read extraData decoding is filtered out (ENS pattern)"""
        contract = """
        contract OffchainResolver {
            function resolveCallback(bytes calldata response, bytes calldata extraData) 
                external view returns (bytes memory) {
                (bytes memory query, address resolver) = abi.decode(extraData, (bytes, address));
                return query;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode of extraData (CCIP-Read pattern)
        assert len(vulnerabilities) == 0, "CCIP-Read extraData decode should be filtered"
    
    def test_offchain_lookup_response_filtered(self):
        """Test that OffchainLookup response decoding is filtered out"""
        contract = """
        contract Gateway {
            function handleResponse(bytes calldata response) external view returns (bytes memory) {
                bytes memory data = abi.decode(response, (bytes));
                return data;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode of response
        assert len(vulnerabilities) == 0, "OffchainLookup response decode should be filtered"
    
    def test_callback_pattern_filtered(self):
        """Test that callback function abi.decode is filtered out"""
        contract = """
        contract CallbackHandler {
            function myCallback(bytes memory data) public returns (uint256) {
                (uint256 value, address user) = abi.decode(data, (uint256, address));
                return value;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode in callback functions
        assert len(vulnerabilities) == 0, "Callback pattern decode should be filtered"
    
    def test_state_changing_function_still_detected(self):
        """Test that abi.decode in state-changing functions is still detected"""
        contract = """
        contract Vulnerable {
            mapping(address => uint256) public balances;
            
            function processData(bytes memory userData) public {
                (uint256 amount, address recipient) = abi.decode(userData, (uint256, address));
                balances[recipient] += amount;  // State change!
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # SHOULD flag abi.decode in state-changing function without validation
        # (This is a real potential vulnerability)
        assert len(vulnerabilities) > 0, "State-changing function abi.decode should still be detected"
    
    def test_msg_data_decode_still_detected(self):
        """Test that dangerous msg.data decoding is still detected"""
        contract = """
        contract Vulnerable {
            function execute() public {
                (address target, uint256 value) = abi.decode(msg.data[4:], (address, uint256));
                // Direct msg.data decoding is risky
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # SHOULD flag direct msg.data decoding
        assert len(vulnerabilities) > 0, "Direct msg.data decode should still be detected"
    
    def test_unvalidated_user_input_still_detected(self):
        """Test that unvalidated user input decoding is still detected"""
        contract = """
        contract Vulnerable {
            function processUserData(bytes calldata data) public {
                (uint256 amount) = abi.decode(data, (uint256));
                // No validation before decode - should be flagged
                _mint(msg.sender, amount);
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # SHOULD flag unvalidated user input decode in state-changing function
        assert len(vulnerabilities) > 0, "Unvalidated user input decode should still be detected"
    
    def test_with_try_catch_filtered(self):
        """Test that abi.decode with try-catch is filtered out"""
        contract = """
        contract SafeDecoder {
            function safeDecodе(bytes memory data) public view returns (uint256) {
                try this.decode(data) returns (uint256 value) {
                    return value;
                } catch {
                    return 0;
                }
            }
            
            function decode(bytes memory data) external pure returns (uint256) {
                return abi.decode(data, (uint256));
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode within try-catch
        assert len(vulnerabilities) == 0, "Try-catch protected decode should be filtered"
    
    def test_with_require_validation_filtered(self):
        """Test that abi.decode with require validation is filtered out"""
        contract = """
        contract ValidatedDecoder {
            function decode(bytes memory data) public pure returns (uint256) {
                require(data.length == 32, "Invalid length");
                return abi.decode(data, (uint256));
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag abi.decode with require validation
        assert len(vulnerabilities) == 0, "Validated decode should be filtered"
    
    def test_complex_ccip_read_scenario(self):
        """Test realistic CCIP-Read scenario from ENS (actual false positive we saw)"""
        contract = """
        contract AbstractUniversalResolver {
            function resolveCallback(
                bytes calldata response,
                bytes calldata extraData
            ) external view returns (bytes memory) {
                (bytes memory query, address resolver) = abi.decode(extraData, (bytes, address));
                
                (bool success, bytes memory returnData) = resolver.staticcall(query);
                require(success, "Resolution failed");
                
                bytes memory result = abi.decode(returnData, (bytes));
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag any of these abi.decode operations
        # - extraData decode (CCIP-Read pattern)
        # - returnData decode (staticcall result)
        # - All in view function
        assert len(vulnerabilities) == 0, "Complex CCIP-Read scenario should be filtered"
    
    def test_dns_resolver_pattern_filtered(self):
        """Test DNS resolver pattern from ENS (another actual false positive)"""
        contract = """
        contract OffchainDNSResolver {
            function resolve(bytes memory name, bytes memory data) 
                external view returns (bytes memory) {
                (bool success, bytes memory result) = address(this).staticcall(data);
                require(success);
                
                bytes memory decoded = abi.decode(result, (bytes));
                return decoded;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should not flag this (view function + staticcall result)
        assert len(vulnerabilities) == 0, "DNS resolver pattern should be filtered"


class TestAbiDecodeContextAwareness:
    """Test context-aware detection of abi.decode vulnerabilities"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = DataDecodingAnalyzer()
    
    def test_internal_vs_external_source(self):
        """Test that analyzer distinguishes between internal and external data sources"""
        # Internal trusted data - should be filtered
        contract_internal = """
        contract TrustedDecoder {
            bytes private internalData;
            
            function process() public view returns (uint256) {
                return abi.decode(internalData, (uint256));
            }
        }
        """
        
        # External untrusted data - should be detected
        contract_external = """
        contract UntrustedDecoder {
            function process(bytes calldata externalData) public {
                uint256 value = abi.decode(externalData, (uint256));
                // Use value to modify state
            }
        }
        """
        
        vulns_internal = self.analyzer.analyze_decoding_operations(contract_internal)
        vulns_external = self.analyzer.analyze_decoding_operations(contract_external)
        
        # Internal should be cleaner than external
        assert len(vulns_internal) <= len(vulns_external), \
            "Internal data decoding should have fewer/no flags than external"


class TestRegressionPrevention:
    """Ensure we don't break existing detection capabilities"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = DataDecodingAnalyzer()
    
    def test_critical_vulnerabilities_still_caught(self):
        """Ensure critical vulnerabilities are still detected after our improvements"""
        
        # Test 1: Unchecked msg.data decode
        vuln1 = """
        contract Vulnerable {
            function executeArbitrary() public {
                (address target, bytes memory data) = abi.decode(msg.data[4:], (address, bytes));
                target.call(data);  // Critical: arbitrary call
            }
        }
        """
        
        # Test 2: Unvalidated calldata decode in payment function
        vuln2 = """
        contract Vulnerable {
            function transfer(bytes calldata encoded) public {
                (address to, uint256 amount) = abi.decode(encoded, (address, uint256));
                payable(to).transfer(amount);  // Critical: no validation
            }
        }
        """
        
        # Test 3: Delegatecall with decoded address
        vuln3 = """
        contract Vulnerable {
            function execute(bytes memory data) public {
                (address impl) = abi.decode(data, (address));
                impl.delegatecall(data);  // Critical: delegatecall to user address
            }
        }
        """
        
        vulns1 = self.analyzer.analyze_decoding_operations(vuln1)
        vulns2 = self.analyzer.analyze_decoding_operations(vuln2)
        vulns3 = self.analyzer.analyze_decoding_operations(vuln3)
        
        # All should detect vulnerabilities
        assert len(vulns1) > 0, "msg.data decode vulnerability should be detected"
        assert len(vulns2) > 0, "Unvalidated transfer decode should be detected"
        assert len(vulns3) > 0, "Delegatecall decode should be detected"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

