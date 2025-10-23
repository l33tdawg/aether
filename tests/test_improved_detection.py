"""
Tests for improved detection rules to prevent false positives
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.arithmetic_analyzer import ArithmeticAnalyzer
from core.data_decoding_analyzer import DataDecodingAnalyzer
from core.precision_analyzer import PrecisionAnalyzer
from core.external_trust_analyzer import ExternalTrustAnalyzer


class TestArithmeticAnalyzer:
    """Test arithmetic overflow detection improvements"""
    
    def test_solidity_08_no_false_positive(self):
        """Test that Solidity 0.8+ code is not flagged"""
        analyzer = ArithmeticAnalyzer()
        
        contract = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.28;
        
        contract Test {
            function calculate(uint256 a, uint256 b) public pure returns (uint256) {
                return a * b;  // Should NOT be flagged - Solidity 0.8+ has built-in protection
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should find no vulnerabilities (automatic overflow protection)
        assert len(vulnerabilities) == 0, f"Found {len(vulnerabilities)} false positives in Solidity 0.8+ code"
    
    def test_solidity_08_unchecked_block_detected(self):
        """Test that unchecked blocks ARE flagged"""
        analyzer = ArithmeticAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        contract Test {
            function calculate(uint256 a, uint256 b) public pure returns (uint256) {
                unchecked {
                    return a * b;  // SHOULD be flagged - no overflow protection
                }
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should find vulnerability in unchecked block
        assert len(vulnerabilities) > 0, "Should detect overflow in unchecked block"
    
    def test_safecast_not_flagged(self):
        """Test that SafeCast usage is not flagged"""
        analyzer = ArithmeticAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
        
        contract Test {
            using SafeCast for uint256;
            
            function convert(uint256 value) public pure returns (uint128) {
                return value.toUint128();  // Should NOT be flagged - SafeCast reverts on overflow
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should not flag SafeCast usage
        assert len(vulnerabilities) == 0, "SafeCast should not be flagged"
    
    def test_math_muldiv_not_flagged(self):
        """Test that Math.mulDiv is not flagged"""
        analyzer = ArithmeticAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
        
        contract Test {
            function calculate(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                return Math.mulDiv(a, b, c);  // Should NOT be flagged - safe library
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should not flag Math.mulDiv
        assert len(vulnerabilities) == 0, "Math.mulDiv should not be flagged"
    
    def test_parallel_protocol_case(self):
        """Test the actual Parallel Protocol case that was a false positive"""
        analyzer = ArithmeticAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        library LibManager {
            function invest(uint256 amount, bytes memory config) internal {
                (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
                if (managerType == ManagerType.EXTERNAL) {
                    abi.decode(data, (IManager)).invest(amount);
                }
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should not flag anything
        assert len(vulnerabilities) == 0, "Should not flag Parallel Protocol code"


class TestDataDecodingAnalyzer:
    """Test data decoding vulnerability detection improvements"""
    
    def test_governance_controlled_not_flagged(self):
        """Test that governance-controlled decoding is not flagged"""
        analyzer = DataDecodingAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        library LibManager {
            function invest(uint256 amount, bytes memory config) internal {
                (ManagerType managerType, bytes memory data) = abi.decode(config, (ManagerType, bytes));
                if (managerType == ManagerType.EXTERNAL) {
                    abi.decode(data, (IManager)).invest(amount);
                }
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_decoding_operations(contract)
        
        # Should not flag library functions with config parameters
        governance_vulns = [v for v in vulnerabilities if 'malformed' in v.vulnerability_type or 'unvalidated' in v.vulnerability_type]
        assert len(governance_vulns) == 0, "Should not flag governance-controlled decoding in libraries"
    
    def test_user_controlled_decoding_flagged(self):
        """Test that user-controlled decoding IS flagged"""
        analyzer = DataDecodingAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        contract Test {
            function processUserData(bytes calldata userData) external {
                (address target, uint256 amount) = abi.decode(userData, (address, uint256));
                // No validation - should be flagged
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_decoding_operations(contract)
        
        # Should flag user-controlled decoding without validation
        assert len(vulnerabilities) > 0, "Should flag unvalidated user input decoding"


class TestPrecisionAnalyzer:
    """Test precision loss detection improvements"""
    
    def test_import_statement_not_flagged(self):
        """Test that import statements are not flagged"""
        analyzer = PrecisionAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
        import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        
        contract Test {
            // Some code
        }
        """
        
        vulnerabilities = analyzer.analyze_precision_loss(contract)
        
        # Should not flag any import statements
        import_vulns = [v for v in vulnerabilities if v.line_number <= 4]
        assert len(import_vulns) == 0, "Should not flag import statements"
    
    def test_muldiv_precision_not_flagged(self):
        """Test that Math.mulDiv precision handling is recognized"""
        analyzer = PrecisionAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
        
        contract Test {
            function calculate(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                return Math.mulDiv(a, b, c);  // Proper precision handling
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_precision_loss(contract)
        
        # Should not flag Math.mulDiv
        assert len(vulnerabilities) == 0, "Math.mulDiv has proper precision handling"


class TestExternalTrustAnalyzer:
    """Test external call and reentrancy detection improvements"""
    
    def test_nonreentrant_not_flagged(self):
        """Test that functions with nonReentrant modifier are not flagged"""
        analyzer = ExternalTrustAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        contract Test {
            function withdraw() external nonReentrant {
                (bool success, ) = msg.sender.call{value: balance}("");
                require(success);
                balance = 0;  // State change after external call, but protected
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_external_dependencies(contract)
        
        # Should not flag reentrancy with guard
        reentrancy_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'reentrancy_vulnerability']
        assert len(reentrancy_vulns) == 0, "Should not flag functions with nonReentrant modifier"
    
    def test_no_guard_flagged(self):
        """Test that functions without guards ARE flagged"""
        analyzer = ExternalTrustAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        contract Test {
            mapping(address => uint256) public balances;
            
            function withdraw() external {
                uint256 amount = balances[msg.sender];
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] = 0;  // State change after external call - VULNERABLE
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_external_dependencies(contract)
        
        # Should flag reentrancy without guard
        reentrancy_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'reentrancy_vulnerability']
        assert len(reentrancy_vulns) > 0, "Should flag reentrancy without protection"


class TestParallelProtocolRegression:
    """Regression tests for Parallel Protocol false positives"""
    
    def test_swapper_arithmetic_not_flagged(self):
        """Test that Swapper.sol arithmetic is not flagged"""
        analyzer = ArithmeticAnalyzer()
        
        # Simplified version of the actual Swapper code that was flagged
        contract = """
        pragma solidity 0.8.28;
        
        import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
        import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
        
        contract Swapper {
            using SafeCast for uint256;
            using Math for uint256;
            
            function _quoteFees() internal view returns (uint256) {
                // Line 392: This was flagged as "silent wrap-around" but it's impossible in 0.8.28
                uint256 slope = uint256(v.upperFees - v.lowerFees) * amountFromPrevBreakPoint;
                
                // Line 423: This was also flagged
                uint256 ac4 = BASE_9.mulDiv(2 * amountStable * uint256(v.upperFees - currentFees), v.amountToNextBreakPoint, Math.Rounding.Ceil);
                
                return slope;
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_arithmetic_operations(contract)
        
        # Should not flag Solidity 0.8.28 code with Math.mulDiv
        assert len(vulnerabilities) == 0, f"Should not flag Parallel Protocol Swapper.sol, found {len(vulnerabilities)} false positives"
    
    def test_libmanager_decoding_not_flagged(self):
        """Test that LibManager.sol decoding is not flagged"""
        analyzer = DataDecodingAnalyzer()
        
        contract = """
        pragma solidity 0.8.28;
        
        library LibManager {
            function invest(uint256 amount, bytes memory config) internal {
                (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
                if (managerType == ManagerType.EXTERNAL) abi.decode(data, (IManager)).invest(amount);
            }
            
            function parseManagerConfig(bytes memory config) internal pure returns (ManagerType managerType, bytes memory data) {
                (managerType, data) = abi.decode(config, (ManagerType, bytes));
            }
        }
        """
        
        vulnerabilities = analyzer.analyze_decoding_operations(contract)
        
        # Should not flag library functions with governance-controlled config
        malformed_vulns = [v for v in vulnerabilities if 'malformed' in v.vulnerability_type]
        assert len(malformed_vulns) == 0, "Should not flag LibManager config decoding"
    
    def test_redeemer_import_not_flagged(self):
        """Test that Redeemer.sol import is not flagged"""
        analyzer = PrecisionAnalyzer()
        
        contract = """
        // SPDX-License-Identifier: BUSL-1.1
        pragma solidity 0.8.28;
        
        import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
        import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
        import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
        
        contract Redeemer {
            // Contract code
        }
        """
        
        vulnerabilities = analyzer.analyze_precision_loss(contract)
        
        # Line 7 should NOT be flagged as "precision loss"
        line7_vulns = [v for v in vulnerabilities if v.line_number == 7]
        assert len(line7_vulns) == 0, "Should not flag line 7 (import statement) as precision loss"


def run_tests():
    """Run all tests and report results"""
    print("🧪 Running Detection Improvement Tests...\n")
    
    test_classes = [
        TestArithmeticAnalyzer,
        TestDataDecodingAnalyzer,
        TestPrecisionAnalyzer,
        TestExternalTrustAnalyzer,
        TestParallelProtocolRegression
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        print(f"📋 {test_class.__name__}")
        test_instance = test_class()
        
        # Get all test methods
        test_methods = [method for method in dir(test_instance) if method.startswith('test_')]
        
        for method_name in test_methods:
            total_tests += 1
            method = getattr(test_instance, method_name)
            
            try:
                method()
                print(f"  ✅ {method_name}")
                passed_tests += 1
            except AssertionError as e:
                print(f"  ❌ {method_name}: {str(e)}")
                failed_tests.append((test_class.__name__, method_name, str(e)))
            except Exception as e:
                print(f"  ⚠️  {method_name}: {type(e).__name__}: {str(e)}")
                failed_tests.append((test_class.__name__, method_name, f"{type(e).__name__}: {str(e)}"))
        
        print()
    
    # Summary
    print("=" * 60)
    print(f"📊 Test Summary")
    print("=" * 60)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests} ✅")
    print(f"Failed: {len(failed_tests)} ❌")
    print()
    
    if failed_tests:
        print("Failed Tests:")
        for test_class, method, error in failed_tests:
            print(f"  • {test_class}.{method}")
            print(f"    {error}")
            print()
        return False
    else:
        print("🎉 All tests passed!")
        return True


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

