#!/usr/bin/env python3
"""
PoC Template Library for Common Test Setups

Provides reusable Solidity mock contracts and test scaffolding templates
for generating Foundry PoC tests that actually compile and run.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PoCTemplate:
    """A reusable Foundry test template with mock contracts and setup code."""
    name: str
    description: str
    setup_code: str          # Solidity setUp() body
    imports: List[str]       # Required imports
    state_variables: str     # Contract-level state variable declarations
    helper_functions: str    # Additional helper functions in the test contract
    mock_contracts: str = "" # Mock contract definitions to place above the test


# ---------------------------------------------------------------------------
# Mock contract Solidity source code
# ---------------------------------------------------------------------------

MOCK_ERC20_SOL = """
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}
"""

MOCK_ORACLE_SOL = """
contract MockOracle {
    int256 public price;
    uint8 public oracleDecimals;
    uint256 public updatedAt;
    uint80 public roundId;

    constructor(int256 _price, uint8 _decimals) {
        price = _price;
        oracleDecimals = _decimals;
        updatedAt = block.timestamp;
        roundId = 1;
    }

    function setPrice(int256 _price) external {
        price = _price;
        updatedAt = block.timestamp;
        roundId++;
    }

    function setStalePrice(int256 _price, uint256 _updatedAt) external {
        price = _price;
        updatedAt = _updatedAt;
        roundId++;
    }

    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (roundId, price, block.timestamp, updatedAt, roundId);
    }

    function decimals() external view returns (uint8) {
        return oracleDecimals;
    }
}
"""

MOCK_WETH_SOL = """
contract MockWETH {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        (bool ok,) = msg.sender.call{value: wad}("");
        require(ok, "ETH transfer failed");
        emit Withdrawal(msg.sender, wad);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
"""

MOCK_FLASH_LOAN_PROVIDER_SOL = """
contract MockFlashLoanProvider {
    // Simplified flash loan provider for PoC testing
    mapping(address => uint256) public reserves;

    function setReserve(address token, uint256 amount) external {
        reserves[token] = amount;
    }

    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        uint256 balBefore = MockERC20(token).balanceOf(address(this));
        require(balBefore >= amount, "Insufficient reserves");

        MockERC20(token).transfer(receiver, amount);

        // Callback — receiver must repay
        IFlashBorrower(receiver).onFlashLoan(msg.sender, token, amount, 0, data);

        uint256 balAfter = MockERC20(token).balanceOf(address(this));
        require(balAfter >= balBefore, "Flash loan not repaid");
    }
}

interface IFlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}
"""

# ---------------------------------------------------------------------------
# Pre-built PoCTemplate instances
# ---------------------------------------------------------------------------

MOCK_ERC20_TEMPLATE = PoCTemplate(
    name="mock_erc20",
    description="ERC20 token mock for testing token interactions",
    setup_code=(
        '        token = new MockERC20("Test Token", "TT", 18);\n'
        '        token.mint(address(this), 1_000_000e18);\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables="    MockERC20 public token;\n",
    helper_functions="",
    mock_contracts=MOCK_ERC20_SOL,
)

MOCK_ORACLE_TEMPLATE = PoCTemplate(
    name="mock_oracle",
    description="Chainlink-style oracle mock for price feed testing",
    setup_code=(
        '        oracle = new MockOracle(1e8, 8); // $1.00 with 8 decimals\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables="    MockOracle public oracle;\n",
    helper_functions="",
    mock_contracts=MOCK_ORACLE_SOL,
)

MOCK_WETH_TEMPLATE = PoCTemplate(
    name="mock_weth",
    description="WETH mock for testing ETH wrapping interactions",
    setup_code=(
        '        weth = new MockWETH();\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables="    MockWETH public weth;\n",
    helper_functions="",
    mock_contracts=MOCK_WETH_SOL,
)

FORK_TEST_TEMPLATE = PoCTemplate(
    name="fork_test",
    description="Base template for mainnet fork testing",
    setup_code=(
        '        // Fork mainnet at latest block\n'
        '        vm.createSelectFork("https://eth.llamarpc.com");\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables="",
    helper_functions="",
    mock_contracts="",
)

FLASH_LOAN_TEMPLATE = PoCTemplate(
    name="flash_loan",
    description="Flash loan provider mock for attack scenario testing",
    setup_code=(
        '        token = new MockERC20("Test Token", "TT", 18);\n'
        '        flashProvider = new MockFlashLoanProvider();\n'
        '        // Seed the flash loan provider with liquidity\n'
        '        token.mint(address(flashProvider), 10_000_000e18);\n'
        '        flashProvider.setReserve(address(token), 10_000_000e18);\n'
        '        // Give attacker some tokens for fees\n'
        '        token.mint(address(this), 100_000e18);\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables=(
        "    MockERC20 public token;\n"
        "    MockFlashLoanProvider public flashProvider;\n"
    ),
    helper_functions="",
    mock_contracts=MOCK_ERC20_SOL + "\n" + MOCK_FLASH_LOAN_PROVIDER_SOL,
)

PROXY_DEPLOY_TEMPLATE = PoCTemplate(
    name="proxy_deploy",
    description="Template for testing upgradeable proxy contracts",
    setup_code=(
        '        // Deploy implementation\n'
        '        // implementation = new TargetContract();\n'
        '        // Deploy proxy pointing to implementation\n'
        '        // bytes memory initData = abi.encodeWithSignature("initialize()");\n'
        '        // proxy = address(new ERC1967Proxy(address(implementation), initData));\n'
        '        // target = TargetContract(proxy);\n'
    ),
    imports=['import "forge-std/Test.sol";'],
    state_variables="    address public proxy;\n",
    helper_functions="",
    mock_contracts="",
)


# ---------------------------------------------------------------------------
# Template selection logic
# ---------------------------------------------------------------------------

# Map vulnerability type keywords to the templates they need
_VULN_TEMPLATE_MAP: Dict[str, List[PoCTemplate]] = {
    "flash_loan": [FLASH_LOAN_TEMPLATE],
    "price_manipulation": [FLASH_LOAN_TEMPLATE, MOCK_ORACLE_TEMPLATE],
    "oracle": [MOCK_ORACLE_TEMPLATE, MOCK_ERC20_TEMPLATE],
    "reentrancy": [MOCK_ERC20_TEMPLATE],
    "share_inflation": [MOCK_ERC20_TEMPLATE],
    "first_depositor": [MOCK_ERC20_TEMPLATE],
    "erc4626": [MOCK_ERC20_TEMPLATE],
    "vault": [MOCK_ERC20_TEMPLATE],
    "token": [MOCK_ERC20_TEMPLATE],
    "erc20": [MOCK_ERC20_TEMPLATE],
    "proxy": [PROXY_DEPLOY_TEMPLATE],
    "upgrade": [PROXY_DEPLOY_TEMPLATE],
    "weth": [MOCK_WETH_TEMPLATE, MOCK_ERC20_TEMPLATE],
    "lending": [MOCK_ERC20_TEMPLATE, MOCK_ORACLE_TEMPLATE],
    "liquidat": [MOCK_ERC20_TEMPLATE, MOCK_ORACLE_TEMPLATE],
    "borrow": [MOCK_ERC20_TEMPLATE, MOCK_ORACLE_TEMPLATE],
    "collateral": [MOCK_ERC20_TEMPLATE, MOCK_ORACLE_TEMPLATE],
    "swap": [MOCK_ERC20_TEMPLATE],
    "amm": [MOCK_ERC20_TEMPLATE],
    "pool": [MOCK_ERC20_TEMPLATE],
    "stake": [MOCK_ERC20_TEMPLATE],
    "deposit": [MOCK_ERC20_TEMPLATE],
    "withdraw": [MOCK_ERC20_TEMPLATE],
}


def get_templates_for_vulnerability(
    vuln_type: str,
    contract_content: str = "",
) -> PoCTemplate:
    """Select and merge appropriate test templates based on vulnerability type
    and contract code analysis.

    Returns a single merged ``PoCTemplate`` that combines all relevant mocks,
    state variables, setup code, and helper functions.
    """
    vuln_lower = (vuln_type or "").lower().replace(" ", "_")

    matched: List[PoCTemplate] = []
    for keyword, templates in _VULN_TEMPLATE_MAP.items():
        if keyword in vuln_lower:
            for t in templates:
                if t not in matched:
                    matched.append(t)

    # Heuristic: scan contract code for common patterns
    content_lower = (contract_content or "").lower()
    if not matched:
        # Fall back to content-based detection
        if "ierc20" in content_lower or "transfer(" in content_lower or "balanceof" in content_lower:
            if MOCK_ERC20_TEMPLATE not in matched:
                matched.append(MOCK_ERC20_TEMPLATE)
        if "latestRoundData" in contract_content or "aggregatorv3" in content_lower or "pricefeed" in content_lower:
            if MOCK_ORACLE_TEMPLATE not in matched:
                matched.append(MOCK_ORACLE_TEMPLATE)
        if "flashloan" in content_lower or "flash_loan" in content_lower:
            if FLASH_LOAN_TEMPLATE not in matched:
                matched.append(FLASH_LOAN_TEMPLATE)

    # Default: at least provide ERC20 mock — most DeFi contracts interact with tokens
    if not matched:
        matched.append(MOCK_ERC20_TEMPLATE)

    # Merge all matched templates into a single PoCTemplate
    return _merge_templates(matched)


def _merge_templates(templates: List[PoCTemplate]) -> PoCTemplate:
    """Merge multiple PoCTemplate instances into one, deduplicating mocks."""
    if not templates:
        return MOCK_ERC20_TEMPLATE

    if len(templates) == 1:
        return templates[0]

    merged_name = "+".join(t.name for t in templates)
    merged_desc = "; ".join(t.description for t in templates)

    # Deduplicate imports
    seen_imports: set = set()
    all_imports: List[str] = []
    for t in templates:
        for imp in t.imports:
            if imp not in seen_imports:
                seen_imports.add(imp)
                all_imports.append(imp)

    # Deduplicate mock contracts by checking if the contract name already appears
    seen_mock_names: set = set()
    merged_mocks_parts: List[str] = []
    for t in templates:
        if not t.mock_contracts:
            continue
        # Extract contract names from mock source to avoid duplicates
        import re
        contract_names_in_mock = set(re.findall(r'contract\s+(\w+)', t.mock_contracts))
        new_names = contract_names_in_mock - seen_mock_names
        if new_names:
            merged_mocks_parts.append(t.mock_contracts)
            seen_mock_names.update(contract_names_in_mock)

    # Deduplicate state variables by line
    seen_vars: set = set()
    merged_vars_lines: List[str] = []
    for t in templates:
        for line in t.state_variables.splitlines():
            stripped = line.strip()
            if stripped and stripped not in seen_vars:
                seen_vars.add(stripped)
                merged_vars_lines.append(line)

    # Concatenate setup code
    merged_setup = "\n".join(t.setup_code for t in templates if t.setup_code)

    # Concatenate helpers
    merged_helpers = "\n".join(t.helper_functions for t in templates if t.helper_functions)

    return PoCTemplate(
        name=merged_name,
        description=merged_desc,
        setup_code=merged_setup,
        imports=all_imports,
        state_variables="\n".join(merged_vars_lines) + "\n" if merged_vars_lines else "",
        helper_functions=merged_helpers,
        mock_contracts="\n".join(merged_mocks_parts),
    )


def get_mock_erc20_source() -> str:
    """Return the MockERC20 Solidity source code."""
    return MOCK_ERC20_SOL


def get_mock_oracle_source() -> str:
    """Return the MockOracle Solidity source code."""
    return MOCK_ORACLE_SOL


def get_all_mock_sources() -> Dict[str, str]:
    """Return a mapping of mock contract name to Solidity source."""
    return {
        "MockERC20": MOCK_ERC20_SOL,
        "MockOracle": MOCK_ORACLE_SOL,
        "MockWETH": MOCK_WETH_SOL,
        "MockFlashLoanProvider": MOCK_FLASH_LOAN_PROVIDER_SOL,
    }
