#!/usr/bin/env python3
"""
Tests for PoCSetupGenerator and PoCTemplates.

Validates constructor extraction, mock selection, setUp body generation,
and template selection/merging logic.
"""

import re
import unittest
from typing import Dict, List

from core.poc_templates import (
    PoCTemplate,
    MOCK_ERC20_TEMPLATE,
    MOCK_ORACLE_TEMPLATE,
    MOCK_WETH_TEMPLATE,
    FLASH_LOAN_TEMPLATE,
    FORK_TEST_TEMPLATE,
    PROXY_DEPLOY_TEMPLATE,
    MOCK_ERC20_SOL,
    MOCK_ORACLE_SOL,
    get_templates_for_vulnerability,
    get_mock_erc20_source,
    get_mock_oracle_source,
    get_all_mock_sources,
    _merge_templates,
)
from core.poc_setup_generator import (
    PoCSetupGenerator,
    ConstructorParam,
    SetupResult,
)


# ---------------------------------------------------------------------------
# Sample contract fixtures
# ---------------------------------------------------------------------------

SIMPLE_VAULT_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SimpleVault {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(IERC20 _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}'''

ORACLE_DEPENDENT_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

contract OracleLending {
    IERC20 public collateralToken;
    AggregatorV3Interface public oracle;
    mapping(address => uint256) public deposits;

    constructor(address _token, address _oracle) {
        collateralToken = IERC20(_token);
        oracle = AggregatorV3Interface(_oracle);
    }

    function getPrice() public view returns (int256) {
        (, int256 price,,,) = oracle.latestRoundData();
        return price;
    }

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}'''

NO_CONSTRUCTOR_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleCounter {
    uint256 public count;

    function increment() external {
        count++;
    }

    function decrement() external {
        require(count > 0, "Cannot decrement below 0");
        count--;
    }
}'''

UPGRADEABLE_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract UpgradeableVault is Initializable {
    address public token;
    address public admin;

    function initialize(address _token, address _admin) public initializer {
        token = _token;
        admin = _admin;
    }

    function deposit(uint256 amount) external {
        // deposit logic
    }
}'''

MULTI_TOKEN_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract LiquidityPool {
    address public tokenA;
    address public tokenB;
    uint256 public fee;

    constructor(address _tokenA, address _tokenB, uint256 _fee) {
        tokenA = _tokenA;
        tokenB = _tokenB;
        fee = _fee;
    }

    function swap(address tokenIn, uint256 amountIn) external {
        // swap logic
    }
}'''

COMPLEX_CONSTRUCTOR_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ComplexProtocol {
    address public governance;
    IERC20 public rewardToken;
    uint256 public rewardRate;
    bool public paused;
    string public protocolName;

    constructor(
        address _governance,
        IERC20 _rewardToken,
        uint256 _rewardRate,
        bool _paused,
        string memory _protocolName
    ) {
        governance = _governance;
        rewardToken = _rewardToken;
        rewardRate = _rewardRate;
        paused = _paused;
        protocolName = _protocolName;
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}'''

PAYABLE_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ETHVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }

    receive() external payable {}
    fallback() external payable {}
}'''

OWNABLE_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract OwnableVault {
    address public owner;
    IERC20 public token;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function withdraw(uint256 amount) external onlyOwner {
        token.transfer(owner, amount);
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}'''


# ===========================================================================
# PoCTemplates Tests
# ===========================================================================


class TestPoCTemplates(unittest.TestCase):
    """Tests for poc_templates.py template definitions and selection logic."""

    def test_mock_erc20_template_has_required_functions(self):
        src = MOCK_ERC20_SOL
        self.assertIn("function mint(", src)
        self.assertIn("function transfer(", src)
        self.assertIn("function transferFrom(", src)
        self.assertIn("function approve(", src)
        self.assertIn("mapping(address => uint256) public balanceOf", src)
        self.assertIn("mapping(address => mapping(address => uint256)) public allowance", src)

    def test_mock_oracle_template_has_latest_round_data(self):
        src = MOCK_ORACLE_SOL
        self.assertIn("function latestRoundData()", src)
        self.assertIn("function setPrice(", src)
        self.assertIn("function decimals()", src)
        self.assertIn("int256 public price", src)

    def test_mock_erc20_template_instance(self):
        t = MOCK_ERC20_TEMPLATE
        self.assertEqual(t.name, "mock_erc20")
        self.assertIn("MockERC20", t.mock_contracts)
        self.assertIn("token", t.state_variables)

    def test_mock_oracle_template_instance(self):
        t = MOCK_ORACLE_TEMPLATE
        self.assertEqual(t.name, "mock_oracle")
        self.assertIn("MockOracle", t.mock_contracts)
        self.assertIn("oracle", t.state_variables)

    def test_flash_loan_template_has_both_mocks(self):
        t = FLASH_LOAN_TEMPLATE
        self.assertIn("MockERC20", t.mock_contracts)
        self.assertIn("MockFlashLoanProvider", t.mock_contracts)
        self.assertIn("flashProvider", t.state_variables)

    # -- Template selection ------------------------------------------------

    def test_get_templates_oracle_vulnerability(self):
        t = get_templates_for_vulnerability("oracle_manipulation")
        self.assertIn("MockOracle", t.mock_contracts)

    def test_get_templates_flash_loan_vulnerability(self):
        t = get_templates_for_vulnerability("flash_loan_attack")
        self.assertIn("MockFlashLoanProvider", t.mock_contracts)

    def test_get_templates_reentrancy_has_erc20(self):
        t = get_templates_for_vulnerability("reentrancy")
        self.assertIn("MockERC20", t.mock_contracts)

    def test_get_templates_share_inflation(self):
        t = get_templates_for_vulnerability("share_inflation")
        self.assertIn("MockERC20", t.mock_contracts)

    def test_get_templates_proxy_vulnerability(self):
        t = get_templates_for_vulnerability("proxy_implementation_uninitialized")
        self.assertEqual(t.name, "proxy_deploy")

    def test_get_templates_upgrade_vulnerability(self):
        t = get_templates_for_vulnerability("upgrade_vulnerability")
        self.assertEqual(t.name, "proxy_deploy")

    def test_get_templates_lending_gets_oracle_and_token(self):
        t = get_templates_for_vulnerability("lending_pool_exploit")
        self.assertIn("MockERC20", t.mock_contracts)
        self.assertIn("MockOracle", t.mock_contracts)

    def test_get_templates_unknown_defaults_to_erc20(self):
        t = get_templates_for_vulnerability("unknown_weird_bug")
        self.assertIn("MockERC20", t.mock_contracts)

    def test_get_templates_from_contract_content(self):
        """Content-based detection should find oracle usage."""
        content = "function foo() { (, int256 p,,,) = feed.latestRoundData(); }"
        t = get_templates_for_vulnerability("generic", content)
        self.assertIn("MockOracle", t.mock_contracts)

    def test_merge_deduplicates_mocks(self):
        """Merging two templates with the same mock should not duplicate it."""
        merged = _merge_templates([MOCK_ERC20_TEMPLATE, MOCK_ERC20_TEMPLATE])
        count = merged.mock_contracts.count("contract MockERC20")
        self.assertEqual(count, 1, "MockERC20 should appear exactly once")

    def test_merge_combines_different_mocks(self):
        merged = _merge_templates([MOCK_ERC20_TEMPLATE, MOCK_ORACLE_TEMPLATE])
        self.assertIn("MockERC20", merged.mock_contracts)
        self.assertIn("MockOracle", merged.mock_contracts)

    # -- Helper functions --------------------------------------------------

    def test_get_mock_erc20_source(self):
        src = get_mock_erc20_source()
        self.assertIn("contract MockERC20", src)

    def test_get_mock_oracle_source(self):
        src = get_mock_oracle_source()
        self.assertIn("contract MockOracle", src)

    def test_get_all_mock_sources(self):
        sources = get_all_mock_sources()
        self.assertIn("MockERC20", sources)
        self.assertIn("MockOracle", sources)
        self.assertIn("MockWETH", sources)
        self.assertIn("MockFlashLoanProvider", sources)


# ===========================================================================
# PoCSetupGenerator Tests
# ===========================================================================


class TestConstructorExtraction(unittest.TestCase):
    """Tests for constructor parameter extraction."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_extract_single_address_param(self):
        params = self.gen._extract_constructor_params(
            "contract X { constructor(address _token) {} }", "X"
        )
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].solidity_type, "address")
        self.assertEqual(params[0].name, "token")
        self.assertTrue(params[0].is_address)

    def test_extract_address_and_uint256(self):
        params = self.gen._extract_constructor_params(
            "contract X { constructor(address _token, uint256 _fee) {} }", "X"
        )
        self.assertEqual(len(params), 2)
        self.assertTrue(params[0].is_address)
        self.assertTrue(params[1].is_uint)

    def test_extract_ierc20_param(self):
        params = self.gen._extract_constructor_params(
            "contract X { constructor(IERC20 _asset) {} }", "X"
        )
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].solidity_type, "IERC20")
        self.assertTrue(params[0].is_interface)

    def test_extract_oracle_param(self):
        params = self.gen._extract_constructor_params(
            "contract X { constructor(AggregatorV3Interface _oracle) {} }", "X"
        )
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].solidity_type, "AggregatorV3Interface")
        self.assertTrue(params[0].is_interface)

    def test_no_constructor(self):
        params = self.gen._extract_constructor_params(
            NO_CONSTRUCTOR_CONTRACT, "SimpleCounter"
        )
        self.assertEqual(len(params), 0)

    def test_multiline_constructor(self):
        params = self.gen._extract_constructor_params(
            COMPLEX_CONSTRUCTOR_CONTRACT, "ComplexProtocol"
        )
        self.assertEqual(len(params), 5)
        self.assertTrue(params[0].is_address)       # governance
        self.assertTrue(params[1].is_interface)      # IERC20
        self.assertTrue(params[2].is_uint)           # rewardRate
        self.assertTrue(params[3].is_bool)           # paused
        self.assertTrue(params[4].is_string)         # protocolName

    def test_extract_memory_qualifier_removed(self):
        params = self.gen._extract_constructor_params(
            "contract X { constructor(string memory _name) {} }", "X"
        )
        self.assertEqual(len(params), 1)
        self.assertTrue(params[0].is_string)
        self.assertEqual(params[0].name, "name")

    def test_scoped_to_contract_name(self):
        """When multiple contracts exist, extract from the named one."""
        code = """
contract Base { constructor(uint256 _x) {} }
contract Child is Base {
    constructor(address _token, uint256 _fee) Base(_fee) {}
}
"""
        params = self.gen._extract_constructor_params(code, "Child")
        self.assertEqual(len(params), 2)
        self.assertTrue(params[0].is_address)
        self.assertTrue(params[1].is_uint)


class TestUpgradeableDetection(unittest.TestCase):
    """Tests for upgradeable contract detection."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_upgradeable_contract_detected(self):
        self.assertTrue(self.gen._is_upgradeable_contract(UPGRADEABLE_CONTRACT))
        self.assertTrue(self.gen._has_initialize_function(UPGRADEABLE_CONTRACT))

    def test_non_upgradeable_contract(self):
        self.assertFalse(self.gen._is_upgradeable_contract(SIMPLE_VAULT_CONTRACT))
        self.assertFalse(self.gen._has_initialize_function(SIMPLE_VAULT_CONTRACT))


class TestMockDetermination(unittest.TestCase):
    """Tests for mock contract selection logic."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_ierc20_param_gets_mock_erc20(self):
        params = [ConstructorParam("token", "IERC20", is_interface=True)]
        mocks = self.gen._determine_needed_mocks(params, "", "")
        mock_names = [m["contract_name"] for m in mocks]
        self.assertIn("MockERC20", mock_names)

    def test_oracle_param_gets_mock_oracle(self):
        params = [ConstructorParam("oracle", "AggregatorV3Interface", is_interface=True)]
        mocks = self.gen._determine_needed_mocks(params, "", "")
        mock_names = [m["contract_name"] for m in mocks]
        self.assertIn("MockOracle", mock_names)

    def test_content_based_token_detection(self):
        """Even with no token constructor param, content analysis detects IERC20 usage."""
        content = "function foo() { IERC20(token).transfer(msg.sender, 100); }"
        mocks = self.gen._determine_needed_mocks([], content, "")
        mock_names = [m["contract_name"] for m in mocks]
        self.assertIn("MockERC20", mock_names)

    def test_content_based_oracle_detection(self):
        content = "function foo() { oracle.latestRoundData(); }"
        mocks = self.gen._determine_needed_mocks([], content, "")
        mock_names = [m["contract_name"] for m in mocks]
        self.assertIn("MockOracle", mock_names)


class TestDefaultValues(unittest.TestCase):
    """Tests for sensible default value generation."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_fee_param_gets_small_value(self):
        param = ConstructorParam("fee", "uint256", is_uint=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, "100")

    def test_amount_param_gets_large_value(self):
        param = ConstructorParam("amount", "uint256", is_uint=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, "1_000_000e18")

    def test_duration_param_gets_seconds(self):
        param = ConstructorParam("duration", "uint256", is_uint=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, "86400")

    def test_bool_param_defaults_true(self):
        param = ConstructorParam("paused", "bool", is_bool=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, "true")

    def test_string_param_uses_name(self):
        param = ConstructorParam("protocolName", "string", is_string=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, '"protocolName"')

    def test_address_param_uses_make_addr(self):
        param = ConstructorParam("governance", "address", is_address=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, 'makeAddr("governance")')

    def test_address_param_prefers_mock(self):
        param = ConstructorParam("token", "address", is_address=True)
        mocks = {"token": {"contract_name": "MockERC20", "var_name": "token"}}
        val = self.gen._default_value_for_param(param, mocks)
        self.assertEqual(val, "address(token)")

    def test_decimal_param(self):
        param = ConstructorParam("decimals", "uint8", is_uint=True)
        val = self.gen._default_value_for_param(param, {})
        self.assertEqual(val, "18")


class TestSetupGeneration(unittest.TestCase):
    """Tests for full setUp() body generation."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_simple_vault_setup(self):
        """Simple vault with IERC20 constructor: should have token mock + vault deploy + approval."""
        template = get_templates_for_vulnerability("reentrancy", SIMPLE_VAULT_CONTRACT)
        result = self.gen.generate_setup(
            SIMPLE_VAULT_CONTRACT, "SimpleVault",
            {"vulnerability_type": "reentrancy"}, template
        )

        # Should deploy MockERC20
        self.assertIn("new MockERC20", result.setup_body)
        # Should deploy the target
        self.assertIn("new SimpleVault", result.setup_body)
        # Should have token approval
        self.assertIn("approve(address(target)", result.setup_body)
        # Should have vm.label
        self.assertIn('vm.label(address(target)', result.setup_body)
        self.assertIn('"Attacker"', result.setup_body)
        # State variables should include target
        self.assertIn("SimpleVault public target", result.state_variables)
        # Mock contracts should have MockERC20
        self.assertIn("contract MockERC20", result.mock_contracts)

    def test_oracle_dependent_setup(self):
        """Oracle-dependent contract should deploy both MockERC20 and MockOracle."""
        template = get_templates_for_vulnerability("oracle_manipulation", ORACLE_DEPENDENT_CONTRACT)
        result = self.gen.generate_setup(
            ORACLE_DEPENDENT_CONTRACT, "OracleLending",
            {"vulnerability_type": "oracle_manipulation"}, template
        )

        self.assertIn("new MockERC20", result.setup_body)
        self.assertIn("new MockOracle", result.setup_body)
        self.assertIn("new OracleLending", result.setup_body)
        self.assertIn("contract MockOracle", result.mock_contracts)

    def test_no_constructor_setup(self):
        """Contract without constructor should deploy with no args."""
        template = get_templates_for_vulnerability("generic", NO_CONSTRUCTOR_CONTRACT)
        result = self.gen.generate_setup(
            NO_CONSTRUCTOR_CONTRACT, "SimpleCounter",
            {"vulnerability_type": "generic"}, template
        )

        self.assertIn("new SimpleCounter()", result.setup_body)
        self.assertIn('vm.label(address(target), "SimpleCounter")', result.setup_body)

    def test_upgradeable_contract_setup(self):
        """Upgradeable contract should use initialize pattern."""
        template = get_templates_for_vulnerability("proxy_vulnerability", UPGRADEABLE_CONTRACT)
        result = self.gen.generate_setup(
            UPGRADEABLE_CONTRACT, "UpgradeableVault",
            {"vulnerability_type": "proxy_vulnerability"}, template
        )

        self.assertIn("initialize", result.setup_body)
        self.assertIn("UpgradeableVault", result.setup_body)

    def test_payable_contract_gets_eth(self):
        """Contract with receive() should get vm.deal for ETH."""
        template = get_templates_for_vulnerability("reentrancy", PAYABLE_CONTRACT)
        result = self.gen.generate_setup(
            PAYABLE_CONTRACT, "ETHVault",
            {"vulnerability_type": "reentrancy"}, template
        )

        self.assertIn("vm.deal", result.setup_body)

    def test_multi_token_constructor(self):
        """Contract with two address params named tokenA/tokenB should get mocks."""
        template = get_templates_for_vulnerability("swap_vulnerability", MULTI_TOKEN_CONTRACT)
        result = self.gen.generate_setup(
            MULTI_TOKEN_CONTRACT, "LiquidityPool",
            {"vulnerability_type": "swap_vulnerability"}, template
        )

        self.assertIn("new LiquidityPool", result.setup_body)
        # Fee parameter should be generated with a numeric default
        self.assertIn("100", result.setup_body)  # fee default

    def test_complex_constructor(self):
        """Complex constructor with mixed types should produce valid setup."""
        template = get_templates_for_vulnerability("access_control", COMPLEX_CONSTRUCTOR_CONTRACT)
        result = self.gen.generate_setup(
            COMPLEX_CONSTRUCTOR_CONTRACT, "ComplexProtocol",
            {"vulnerability_type": "access_control"}, template
        )

        self.assertIn("new ComplexProtocol", result.setup_body)
        # Should have makeAddr for governance
        self.assertIn('makeAddr("governance")', result.setup_body)
        # Should have true for bool param
        self.assertIn("true", result.setup_body)

    def test_setup_has_no_todos(self):
        """Generated setUp should NOT contain TODO comments."""
        template = get_templates_for_vulnerability("reentrancy", SIMPLE_VAULT_CONTRACT)
        result = self.gen.generate_setup(
            SIMPLE_VAULT_CONTRACT, "SimpleVault",
            {"vulnerability_type": "reentrancy"}, template
        )
        self.assertNotIn("TODO", result.setup_body)


class TestFullTestFileGeneration(unittest.TestCase):
    """Tests for the convenience full-file generation method."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_simple_vault_full_file(self):
        output = self.gen.generate_full_test_file(
            SIMPLE_VAULT_CONTRACT, "SimpleVault",
            {"vulnerability_type": "reentrancy"},
            solc_version="0.8.19",
        )

        self.assertIn("pragma solidity 0.8.19", output)
        self.assertIn('import "forge-std/Test.sol"', output)
        self.assertIn("contract SimpleVaultReentrancyTest is Test", output)
        self.assertIn("function setUp() public", output)
        self.assertIn("new MockERC20", output)
        self.assertIn("new SimpleVault", output)
        self.assertIn("function testReentrancyExploit()", output)

    def test_full_file_07x_has_abicoder(self):
        output = self.gen.generate_full_test_file(
            NO_CONSTRUCTOR_CONTRACT, "SimpleCounter",
            {"vulnerability_type": "generic"},
            solc_version="0.7.6",
        )
        self.assertIn("pragma abicoder v2", output)

    def test_full_file_does_not_have_empty_setup(self):
        """The generated file should not have an empty setUp with just comments."""
        output = self.gen.generate_full_test_file(
            SIMPLE_VAULT_CONTRACT, "SimpleVault",
            {"vulnerability_type": "reentrancy"},
        )
        # setUp should contain actual code, not just comments/whitespace
        setup_match = re.search(r'function setUp\(\) public \{([\s\S]*?)\n    \}', output)
        self.assertIsNotNone(setup_match, "Should find setUp function")
        setup_body = setup_match.group(1)
        # Remove comments and whitespace — there should still be code
        code_lines = [
            line.strip() for line in setup_body.splitlines()
            if line.strip() and not line.strip().startswith("//")
        ]
        self.assertGreater(len(code_lines), 0, "setUp should contain executable code, not just comments")


class TestInitializeExtraction(unittest.TestCase):
    """Tests for extracting initialize() function parameters."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_extract_initialize_params(self):
        params = self.gen._extract_initialize_params(UPGRADEABLE_CONTRACT)
        self.assertEqual(len(params), 2)
        self.assertTrue(params[0].is_address)  # _token
        self.assertTrue(params[1].is_address)  # _admin

    def test_no_initialize(self):
        params = self.gen._extract_initialize_params(SIMPLE_VAULT_CONTRACT)
        self.assertEqual(len(params), 0)


class TestOwnerDetection(unittest.TestCase):
    """Tests for owner/access control detection in post-deploy setup."""

    def setUp(self):
        self.gen = PoCSetupGenerator()

    def test_ownable_contract_note(self):
        template = get_templates_for_vulnerability("access_control", OWNABLE_CONTRACT)
        result = self.gen.generate_setup(
            OWNABLE_CONTRACT, "OwnableVault",
            {"vulnerability_type": "access_control"}, template
        )
        # Should note that deployer is owner
        self.assertIn("deployer/owner", result.setup_body.lower())


if __name__ == '__main__':
    unittest.main()
