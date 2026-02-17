#!/usr/bin/env python3
"""
Intelligent setUp() Generator for Foundry PoC Tests

Analyses the target contract source to extract constructor parameters,
detect initialization patterns (upgradeable proxies, factories), and
generate a complete, compilable setUp() function body with all required
mock deployments and state configuration.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.poc_templates import (
    PoCTemplate,
    MOCK_ERC20_SOL,
    MOCK_ORACLE_SOL,
    MOCK_WETH_SOL,
    get_templates_for_vulnerability,
)

logger = logging.getLogger(__name__)


@dataclass
class ConstructorParam:
    """A single constructor parameter extracted from Solidity source."""
    name: str
    solidity_type: str
    is_interface: bool = False     # True when type starts with I (e.g. IERC20)
    is_address: bool = False
    is_uint: bool = False
    is_int: bool = False
    is_bool: bool = False
    is_string: bool = False
    is_bytes: bool = False


@dataclass
class SetupResult:
    """Output of the setUp generator."""
    setup_body: str            # Solidity code inside setUp()
    state_variables: str       # Contract-level state variable declarations
    mock_contracts: str        # Mock contract definitions to place above the test
    extra_imports: List[str]   # Any additional imports needed


class PoCSetupGenerator:
    """Generates complete setUp() function bodies for Foundry PoC tests."""

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def generate_setup(
        self,
        contract_content: str,
        contract_name: str,
        vulnerability: Dict[str, Any],
        template: PoCTemplate,
    ) -> SetupResult:
        """Generate a complete setUp() function body for a PoC test.

        Parameters
        ----------
        contract_content : str
            Full Solidity source of the target contract.
        contract_name : str
            Name of the target contract (e.g. ``VulnerableVault``).
        vulnerability : dict
            Vulnerability metadata (type, severity, description, ...).
        template : PoCTemplate
            The matched template from ``poc_templates.get_templates_for_vulnerability``.

        Returns
        -------
        SetupResult
            Contains the setUp body, required state variables, mock contract
            source, and extra imports.
        """
        vuln_type = (
            vulnerability.get("vulnerability_type", "")
            or vulnerability.get("type", "")
            or ""
        ).lower()

        # 1. Extract constructor information
        constructor_params = self._extract_constructor_params(contract_content, contract_name)
        has_initialize = self._has_initialize_function(contract_content)
        is_upgradeable = self._is_upgradeable_contract(contract_content)

        # 2. Determine which mocks are needed based on constructor params
        needed_mocks = self._determine_needed_mocks(
            constructor_params, contract_content, vuln_type
        )

        # 3. Build state variable declarations
        state_vars_lines: List[str] = []
        mock_deploys: List[str] = []
        mock_contracts_code: List[str] = []

        # Add mocks from the template
        if template.mock_contracts:
            mock_contracts_code.append(template.mock_contracts)

        # Add template state variables (avoiding duplicates we will declare)
        template_var_names = set()
        for line in template.state_variables.splitlines():
            stripped = line.strip()
            if stripped:
                template_var_names.add(stripped)

        # Track what mock names we already have from the template
        existing_mock_names = set(re.findall(r'contract\s+(\w+)', "\n".join(mock_contracts_code)))

        # Process each needed mock
        for mock in needed_mocks:
            if mock["contract_name"] not in existing_mock_names:
                mock_contracts_code.append(mock["source"])
                existing_mock_names.add(mock["contract_name"])
            var_decl = f'    {mock["contract_name"]} public {mock["var_name"]};'
            if var_decl.strip() not in template_var_names:
                state_vars_lines.append(var_decl)
            mock_deploys.append(mock["deploy_code"])

        # Add target contract state variable
        state_vars_lines.append(f"    {contract_name} public target;")

        # 4. Build the setUp body
        setup_lines: List[str] = []

        # Add template setup code first (e.g. fork setup from FORK_TEST_TEMPLATE)
        # Skip any template lines that deploy or configure mocks we generate ourselves
        if template.setup_code and needed_mocks:
            mock_var_names = {m["var_name"] for m in needed_mocks}
            mock_class_names = {m["contract_name"] for m in needed_mocks}
            for line in template.setup_code.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                # Skip lines that reference our mock variables (deploy, mint, approve, etc.)
                skip = False
                for var in mock_var_names:
                    if var + " =" in stripped or var + "." in stripped:
                        skip = True
                        break
                if not skip:
                    for cls in mock_class_names:
                        if f"new {cls}" in stripped:
                            skip = True
                            break
                if not skip:
                    setup_lines.append(line)
        elif template.setup_code:
            for line in template.setup_code.splitlines():
                stripped = line.strip()
                if stripped:
                    setup_lines.append(line)

        # Deploy mocks
        if mock_deploys:
            setup_lines.append("        // Deploy mock dependencies")
            setup_lines.extend(mock_deploys)
            setup_lines.append("")

        # Deploy target contract
        if is_upgradeable and has_initialize:
            setup_lines.extend(
                self._generate_upgradeable_deploy(
                    contract_name, contract_content, constructor_params, needed_mocks
                )
            )
        else:
            setup_lines.extend(
                self._generate_direct_deploy(
                    contract_name, constructor_params, needed_mocks
                )
            )

        # Post-deployment setup (approvals, minting, roles)
        post_setup = self._generate_post_deploy_setup(
            contract_content, contract_name, constructor_params, needed_mocks, vuln_type
        )
        if post_setup:
            setup_lines.append("")
            setup_lines.append("        // Setup initial state")
            setup_lines.extend(post_setup)

        # vm.label() calls
        setup_lines.append("")
        setup_lines.append("        // Label addresses for trace readability")
        setup_lines.append(f'        vm.label(address(target), "{contract_name}");')
        for mock in needed_mocks:
            label = mock["var_name"][0].upper() + mock["var_name"][1:]
            setup_lines.append(f'        vm.label(address({mock["var_name"]}), "{label}");')
        setup_lines.append('        vm.label(address(this), "Attacker");')

        # Merge state variables (template + generated)
        all_state_vars = list(template_var_names) + state_vars_lines

        # Merge mock contracts
        merged_mocks = "\n".join(mock_contracts_code)

        return SetupResult(
            setup_body="\n".join(setup_lines),
            state_variables="\n".join(all_state_vars) + "\n",
            mock_contracts=merged_mocks,
            extra_imports=template.imports[:],
        )

    # -----------------------------------------------------------------------
    # Constructor extraction
    # -----------------------------------------------------------------------

    def _extract_constructor_params(
        self, content: str, contract_name: str = ""
    ) -> List[ConstructorParam]:
        """Extract constructor parameters from Solidity source.

        Handles multi-line constructors and various type modifiers.
        """
        # Try to find constructor within the target contract block first
        params: List[ConstructorParam] = []

        # Match constructor(...) with potentially multi-line params
        # Capture everything inside the parens
        pattern = r'constructor\s*\(([^)]*)\)'
        matches = re.findall(pattern, content, re.DOTALL)

        if not matches:
            return params

        # Use the last constructor found (most likely the target contract's)
        # If contract_name is provided, try to scope it
        if contract_name:
            # Find the constructor that belongs to our target contract
            contract_pattern = (
                r'contract\s+' + re.escape(contract_name) +
                r'\b[^{]*\{([\s\S]*?)(?=\ncontract\s|\Z)'
            )
            contract_match = re.search(contract_pattern, content)
            if contract_match:
                contract_body = contract_match.group(1)
                inner_matches = re.findall(pattern, contract_body, re.DOTALL)
                if inner_matches:
                    matches = inner_matches

        raw_params = matches[-1].strip()
        if not raw_params:
            return params

        # Split by comma, handling possible whitespace and newlines
        # Clean up whitespace
        raw_params = re.sub(r'\s+', ' ', raw_params).strip()

        for part in raw_params.split(','):
            part = part.strip()
            if not part:
                continue

            # Remove memory/calldata/storage qualifiers
            part = re.sub(r'\b(memory|calldata|storage)\b', '', part).strip()
            # Remove extra spaces
            part = re.sub(r'\s+', ' ', part).strip()

            tokens = part.split()
            if len(tokens) < 2:
                # Could be just a type with no name, e.g. "address"
                if len(tokens) == 1:
                    params.append(self._classify_param(tokens[0], f"param{len(params)}"))
                continue

            sol_type = tokens[0]
            param_name = tokens[-1].lstrip('_')
            params.append(self._classify_param(sol_type, param_name))

        return params

    def _classify_param(self, sol_type: str, name: str) -> ConstructorParam:
        """Classify a Solidity type into a ConstructorParam."""
        sol_type_lower = sol_type.lower()
        # Detect interface types: starts with I + uppercase, or ends with Interface
        is_iface = (
            (sol_type.startswith("I") and sol_type[1:2].isupper())
            or sol_type.endswith("Interface")
        )
        return ConstructorParam(
            name=name,
            solidity_type=sol_type,
            is_interface=is_iface,
            is_address=sol_type_lower == "address",
            is_uint="uint" in sol_type_lower,
            is_int="int" in sol_type_lower and "uint" not in sol_type_lower,
            is_bool=sol_type_lower == "bool",
            is_string=sol_type_lower == "string",
            is_bytes=sol_type_lower.startswith("bytes"),
        )

    # -----------------------------------------------------------------------
    # Contract pattern detection
    # -----------------------------------------------------------------------

    def _has_initialize_function(self, content: str) -> bool:
        """Check if the contract has an initialize() function (upgradeable pattern)."""
        return bool(re.search(
            r'function\s+initialize\s*\(', content
        ))

    def _is_upgradeable_contract(self, content: str) -> bool:
        """Detect if the contract uses an upgradeable proxy pattern."""
        indicators = [
            r'Initializable',
            r'UUPSUpgradeable',
            r'TransparentUpgradeableProxy',
            r'ERC1967',
            r'__init\b',
            r'initializer\b',
            r'function\s+initialize\s*\(',
        ]
        for pattern in indicators:
            if re.search(pattern, content):
                return True
        return False

    # -----------------------------------------------------------------------
    # Mock determination
    # -----------------------------------------------------------------------

    def _determine_needed_mocks(
        self,
        params: List[ConstructorParam],
        contract_content: str,
        vuln_type: str,
    ) -> List[Dict[str, Any]]:
        """Determine which mock contracts are needed based on constructor params
        and contract content analysis.

        Returns a list of dicts with keys:
            contract_name, var_name, source, deploy_code
        """
        mocks: List[Dict[str, Any]] = []
        seen_names: set = set()
        token_count = 0

        for param in params:
            mock = self._mock_for_param(param, contract_content, token_count)
            if mock and mock["var_name"] not in seen_names:
                mocks.append(mock)
                seen_names.add(mock["var_name"])
                if mock["contract_name"] == "MockERC20":
                    token_count += 1

        # If no constructor params produced mocks but contract uses tokens, add one
        content_lower = contract_content.lower()
        if "MockERC20" not in seen_names and not any(m["contract_name"] == "MockERC20" for m in mocks):
            if ("ierc20" in content_lower or "transfer(" in content_lower) and "token" not in seen_names:
                mocks.append({
                    "contract_name": "MockERC20",
                    "var_name": "token",
                    "source": MOCK_ERC20_SOL,
                    "deploy_code": '        token = new MockERC20("Test Token", "TT", 18);',
                })
                seen_names.add("token")

        if not any(m["contract_name"] == "MockOracle" for m in mocks):
            if "latestrounddata" in content_lower or "aggregatorv3" in content_lower:
                mocks.append({
                    "contract_name": "MockOracle",
                    "var_name": "oracle",
                    "source": MOCK_ORACLE_SOL,
                    "deploy_code": '        oracle = new MockOracle(1e8, 8);',
                })

        return mocks

    def _mock_for_param(
        self,
        param: ConstructorParam,
        contract_content: str,
        token_index: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Return a mock definition for a constructor parameter, or None."""
        name_lower = param.name.lower()
        type_lower = param.solidity_type.lower()

        # Token-like parameters
        if self._is_token_param(param):
            suffix = "" if token_index == 0 else str(token_index + 1)
            var_name = name_lower if name_lower not in ("param0",) else f"token{suffix}"
            label = f"Token{suffix}" if suffix else "Token"
            return {
                "contract_name": "MockERC20",
                "var_name": var_name,
                "source": MOCK_ERC20_SOL,
                "deploy_code": f'        {var_name} = new MockERC20("{label}", "TK{suffix}", 18);',
            }

        # Oracle-like parameters
        if self._is_oracle_param(param):
            var_name = name_lower if name_lower not in ("param0",) else "oracle"
            return {
                "contract_name": "MockOracle",
                "var_name": var_name,
                "source": MOCK_ORACLE_SOL,
                "deploy_code": f'        {var_name} = new MockOracle(1e8, 8);',
            }

        # Generic address — use makeAddr
        if param.is_address or param.is_interface:
            # Don't create a mock, just return None — we'll handle addresses in deploy
            return None

        return None

    def _is_token_param(self, param: ConstructorParam) -> bool:
        """Check if a constructor param looks like a token reference."""
        name_lower = param.name.lower()
        type_str = param.solidity_type

        token_names = {"token", "asset", "underlying", "staketoken", "rewardtoken",
                       "deposittoken", "collateral", "basetoken", "quotetoken",
                       "tokenin", "tokenout", "lptoken", "weth"}
        token_types = {"IERC20", "IERC20Metadata", "ERC20", "IWETH"}

        if type_str in token_types:
            return True
        if name_lower in token_names or any(t in name_lower for t in ("token", "asset", "erc20")):
            if param.is_address or param.is_interface:
                return True
        return False

    def _is_oracle_param(self, param: ConstructorParam) -> bool:
        """Check if a constructor param looks like an oracle reference."""
        name_lower = param.name.lower()
        type_str = param.solidity_type

        oracle_types = {"AggregatorV3Interface", "IAggregator", "IOracle",
                        "IPriceFeed", "IPriceOracle", "AggregatorInterface"}
        oracle_names = {"oracle", "pricefeed", "pricefeedaddress", "aggregator",
                        "feed", "pricefeedoracle"}

        if type_str in oracle_types:
            return True
        if name_lower in oracle_names or "oracle" in name_lower or "pricefeed" in name_lower:
            if param.is_address or param.is_interface:
                return True
        return False

    # -----------------------------------------------------------------------
    # Deployment code generation
    # -----------------------------------------------------------------------

    def _generate_direct_deploy(
        self,
        contract_name: str,
        params: List[ConstructorParam],
        mocks: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate deployment code for a regular (non-upgradeable) contract."""
        lines: List[str] = []
        lines.append("        // Deploy target contract")

        if not params:
            lines.append(f"        target = new {contract_name}();")
            return lines

        # Build constructor arguments
        args = self._build_constructor_args(params, mocks)
        args_str = ", ".join(args)

        # If the arg list is short, put it on one line
        if len(args_str) < 80:
            lines.append(f"        target = new {contract_name}({args_str});")
        else:
            lines.append(f"        target = new {contract_name}(")
            for i, arg in enumerate(args):
                comma = "," if i < len(args) - 1 else ""
                lines.append(f"            {arg}{comma}")
            lines.append("        );")

        return lines

    def _generate_upgradeable_deploy(
        self,
        contract_name: str,
        contract_content: str,
        params: List[ConstructorParam],
        mocks: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate deployment code for an upgradeable (proxy) contract."""
        lines: List[str] = []
        lines.append("        // Deploy upgradeable contract via proxy pattern")
        lines.append(f"        {contract_name} implementation = new {contract_name}();")

        # Extract initialize() params
        init_params = self._extract_initialize_params(contract_content)
        if init_params:
            init_args = self._build_constructor_args(init_params, mocks)
            init_args_str = ", ".join(init_args)
            lines.append(
                f'        bytes memory initData = abi.encodeWithSignature('
                f'"initialize({",".join(p.solidity_type for p in init_params)})", {init_args_str});'
            )
        else:
            lines.append(
                '        bytes memory initData = abi.encodeWithSignature("initialize()");'
            )

        lines.append("        // Deploy minimal proxy (ERC1967-style)")
        lines.append("        // Using vm.etch to simulate proxy deployment")
        lines.append(f"        target = {contract_name}(address(implementation));")
        lines.append("        // Call initialize directly on implementation for PoC purposes")
        if init_params:
            init_args_str = ", ".join(self._build_constructor_args(init_params, mocks))
            lines.append(f"        target.initialize({init_args_str});")
        else:
            lines.append("        target.initialize();")

        return lines

    def _extract_initialize_params(self, content: str) -> List[ConstructorParam]:
        """Extract parameters from an initialize() function."""
        pattern = r'function\s+initialize\s*\(([^)]*)\)'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            return []

        raw = match.group(1).strip()
        if not raw:
            return []

        raw = re.sub(r'\s+', ' ', raw).strip()
        params: List[ConstructorParam] = []
        for part in raw.split(','):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r'\b(memory|calldata|storage)\b', '', part).strip()
            part = re.sub(r'\s+', ' ', part).strip()
            tokens = part.split()
            if len(tokens) >= 2:
                params.append(self._classify_param(tokens[0], tokens[-1].lstrip('_')))
            elif len(tokens) == 1:
                params.append(self._classify_param(tokens[0], f"param{len(params)}"))

        return params

    def _build_constructor_args(
        self,
        params: List[ConstructorParam],
        mocks: List[Dict[str, Any]],
    ) -> List[str]:
        """Build Solidity expressions for constructor arguments."""
        args: List[str] = []

        # Build a lookup: var_name -> mock info
        mock_by_var: Dict[str, Dict[str, Any]] = {m["var_name"]: m for m in mocks}

        for param in params:
            arg = self._default_value_for_param(param, mock_by_var)
            args.append(arg)

        return args

    def _default_value_for_param(
        self,
        param: ConstructorParam,
        mocks: Dict[str, Dict[str, Any]],
    ) -> str:
        """Generate a sensible default value for a constructor parameter."""
        name_lower = param.name.lower()

        # Check if we have a mock with a matching variable name
        if name_lower in mocks:
            return f"address({name_lower})"

        # Token-like params — check mocks by type
        if self._is_token_param(param):
            for var_name, mock in mocks.items():
                if mock["contract_name"] == "MockERC20":
                    return f"address({var_name})"

        # Oracle-like params
        if self._is_oracle_param(param):
            for var_name, mock in mocks.items():
                if mock["contract_name"] == "MockOracle":
                    return f"address({var_name})"

        # Address types
        if param.is_address or param.is_interface:
            # Use makeAddr for named addresses
            return f'makeAddr("{param.name}")'

        # Numeric types
        if param.is_uint:
            return self._default_uint_for_name(name_lower, param.solidity_type)

        if param.is_int:
            return "0"

        if param.is_bool:
            return "true"

        if param.is_string:
            return f'"{param.name}"'

        if param.is_bytes:
            if param.solidity_type == "bytes32":
                return 'bytes32(0)'
            return '""'

        # Fallback
        if param.is_address or param.solidity_type.startswith("I"):
            return f'makeAddr("{param.name}")'

        return "0"

    def _default_uint_for_name(self, name: str, sol_type: str) -> str:
        """Generate a sensible uint default based on the parameter name."""
        # Percentages / basis points
        if any(kw in name for kw in ("fee", "bps", "basispoint", "rate", "percent")):
            return "100"  # 1% in basis points

        # Durations / timestamps
        if any(kw in name for kw in ("duration", "period", "interval", "delay", "timeout")):
            return "86400"  # 1 day in seconds

        # Amounts / limits — use 18 decimal standard
        if any(kw in name for kw in ("amount", "limit", "cap", "supply", "threshold", "min", "max")):
            return "1_000_000e18"

        # Counts / ids
        if any(kw in name for kw in ("count", "id", "index", "nonce")):
            return "1"

        # Decimals
        if "decimal" in name:
            return "18"

        # Default uint
        if "256" in sol_type or sol_type == "uint":
            return "1e18"

        # Smaller uints
        return "100"

    # -----------------------------------------------------------------------
    # Post-deployment setup
    # -----------------------------------------------------------------------

    def _generate_post_deploy_setup(
        self,
        contract_content: str,
        contract_name: str,
        params: List[ConstructorParam],
        mocks: List[Dict[str, Any]],
        vuln_type: str,
    ) -> List[str]:
        """Generate post-deployment state setup (minting, approvals, etc.)."""
        lines: List[str] = []
        content_lower = contract_content.lower()

        # Token minting and approvals
        for mock in mocks:
            if mock["contract_name"] == "MockERC20":
                var = mock["var_name"]
                # Mint tokens to the test contract (attacker)
                lines.append(f"        {var}.mint(address(this), 1_000_000e18);")
                # Approve the target contract to spend tokens
                lines.append(f"        {var}.approve(address(target), type(uint256).max);")

        # If the contract has deposit/stake functions, seed it with some tokens
        if any(kw in content_lower for kw in ("function deposit", "function stake")):
            for mock in mocks:
                if mock["contract_name"] == "MockERC20":
                    var = mock["var_name"]
                    lines.append(f"        // Seed target with initial liquidity")
                    lines.append(f"        {var}.mint(address(target), 100_000e18);")
                    break

        # Fund the test contract with ETH if the contract accepts it
        if "payable" in content_lower and ("receive()" in content_lower or "fallback()" in content_lower):
            lines.append("        vm.deal(address(this), 100 ether);")

        # If contract has owner-based access control, prank as owner for setup
        if "onlyowner" in content_lower or "owner()" in content_lower:
            lines.append(f"        // Note: address(this) is the deployer/owner by default")

        return lines

    # -----------------------------------------------------------------------
    # Full test file generation (convenience)
    # -----------------------------------------------------------------------

    def generate_full_test_file(
        self,
        contract_content: str,
        contract_name: str,
        vulnerability: Dict[str, Any],
        solc_version: str = "0.8.19",
    ) -> str:
        """Generate a complete Foundry test .sol file with mocks, setUp, and
        a placeholder test function.

        This is a convenience method for when you want a full compilable file
        without going through the LLM.
        """
        template = get_templates_for_vulnerability(
            vulnerability.get("vulnerability_type", vulnerability.get("type", "")),
            contract_content,
        )

        result = self.generate_setup(
            contract_content, contract_name, vulnerability, template
        )

        vuln_type = (
            vulnerability.get("vulnerability_type", "")
            or vulnerability.get("type", "")
            or "unknown"
        )
        safe_vuln = re.sub(r'[^A-Za-z0-9]', '', vuln_type.title())

        # Build abicoder pragma for 0.7.x
        abicoder_pragma = ""
        if solc_version.startswith("0.7"):
            abicoder_pragma = "pragma abicoder v2;\n"

        parts: List[str] = []
        parts.append(f"// SPDX-License-Identifier: MIT")
        parts.append(f"pragma solidity {solc_version};")
        if abicoder_pragma:
            parts.append(abicoder_pragma.rstrip())
        parts.append("")
        parts.append('import "forge-std/Test.sol";')
        parts.append(f'import "./{contract_name}.sol";')
        parts.append("")

        # Mock contracts
        if result.mock_contracts:
            parts.append("// --- Mock contracts for PoC testing ---")
            parts.append(result.mock_contracts.strip())
            parts.append("")

        # Test contract
        parts.append(f"contract {contract_name}{safe_vuln}Test is Test {{")
        # State variables
        if result.state_variables:
            parts.append(result.state_variables.rstrip())
        parts.append("")

        # setUp
        parts.append("    function setUp() public {")
        parts.append(result.setup_body)
        parts.append("    }")
        parts.append("")

        # Placeholder test
        parts.append(f"    function test{safe_vuln}Exploit() public {{")
        parts.append(f"        // TODO: Implement exploit for {vuln_type}")
        parts.append(f"        assertTrue(address(target) != address(0), \"Target should be deployed\");")
        parts.append("    }")
        parts.append("}")
        parts.append("")

        return "\n".join(parts)
