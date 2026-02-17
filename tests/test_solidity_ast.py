"""
Comprehensive test suite for the Solidity AST Parser module.

Tests are organized into:
1. Regex fallback tests (always work, no solc needed)
2. AST walking tests (mock the AST JSON)
3. Storage layout tests (mock the storage layout JSON)
4. Helper method tests
5. Integration test (real solc, skipped if unavailable)
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import sys
import copy

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.solidity_ast import (
    ContractDef,
    FunctionDef,
    FunctionParam,
    ModifierDef,
    Mutability,
    SolidityAST,
    SolidityASTParser,
    StateVariable,
    Visibility,
)

# ---------------------------------------------------------------------------
# Check if real solcx is available for integration tests
# ---------------------------------------------------------------------------
try:
    import solcx
    _installed = solcx.get_installed_solc_versions()
    solcx_available = len(_installed) > 0
except Exception:
    solcx_available = False


# ===========================================================================
# 1. Regex Fallback Tests
# ===========================================================================

class TestRegexFallbackSimpleContract(unittest.TestCase):
    """Parse simple contracts via regex when compilation is not available."""

    def setUp(self):
        self.parser = SolidityASTParser()
        # Force regex fallback by pretending solcx is unavailable
        self.parser._ast_available = False

    def test_parse_simple_contract(self):
        """Extract name, functions, and state variables from a simple contract."""
        code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleToken {
    uint256 public totalSupply;
    mapping(address => uint256) private balances;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
}
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 1)

        c = ast.contracts[0]
        self.assertEqual(c.name, "SimpleToken")
        self.assertEqual(c.kind, "contract")
        self.assertEqual(c.base_contracts, [])

        # Functions
        func_names = [f.name for f in c.functions]
        self.assertIn("mint", func_names)
        self.assertIn("balanceOf", func_names)

        # Visibility
        mint = next(f for f in c.functions if f.name == "mint")
        self.assertEqual(mint.visibility, Visibility.EXTERNAL)

        balance_of = next(f for f in c.functions if f.name == "balanceOf")
        self.assertEqual(balance_of.visibility, Visibility.PUBLIC)
        self.assertEqual(balance_of.mutability, Mutability.VIEW)

        # State variables
        var_names = [sv.name for sv in c.state_variables]
        self.assertIn("totalSupply", var_names)
        self.assertIn("balances", var_names)

        ts = next(sv for sv in c.state_variables if sv.name == "totalSupply")
        self.assertEqual(ts.visibility, Visibility.PUBLIC)
        self.assertEqual(ts.type_name, "uint256")

    def test_parse_contract_with_constructor(self):
        """Extract constructor from a contract."""
        code = """
pragma solidity ^0.8.20;

contract Owned {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 1)

        c = ast.contracts[0]
        constructors = [f for f in c.functions if f.is_constructor]
        self.assertEqual(len(constructors), 1)
        self.assertEqual(constructors[0].name, "constructor")


class TestRegexFallbackInterface(unittest.TestCase):
    """Parse interface definitions via regex."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_interface(self):
        """Extract function signatures from an interface."""
        code = """
pragma solidity ^0.8.20;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
}
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 1)

        c = ast.contracts[0]
        self.assertEqual(c.name, "IERC20")
        self.assertEqual(c.kind, "interface")

        func_names = sorted(f.name for f in c.functions)
        self.assertIn("totalSupply", func_names)
        self.assertIn("balanceOf", func_names)
        self.assertIn("transfer", func_names)
        self.assertIn("approve", func_names)

        # Check return types
        ts = next(f for f in c.functions if f.name == "totalSupply")
        self.assertEqual(len(ts.returns), 1)
        self.assertEqual(ts.returns[0].type_name, "uint256")

        # Events
        self.assertEqual(len(c.events), 1)
        self.assertEqual(c.events[0]["name"], "Transfer")


class TestRegexFallbackInheritance(unittest.TestCase):
    """Parse inheritance declarations via regex."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_inheritance(self):
        """Extract base contract list."""
        code = """
pragma solidity ^0.8.20;

contract Pool is Ownable, ReentrancyGuard, IPool {
    uint256 public totalAssets;
}
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 1)

        c = ast.contracts[0]
        self.assertEqual(c.name, "Pool")
        self.assertIn("Ownable", c.base_contracts)
        self.assertIn("ReentrancyGuard", c.base_contracts)
        self.assertIn("IPool", c.base_contracts)

        # Inheritance graph
        self.assertIn("Pool", ast.inheritance_graph)
        self.assertEqual(sorted(ast.inheritance_graph["Pool"]),
                         sorted(["Ownable", "ReentrancyGuard", "IPool"]))


class TestRegexFallbackModifiers(unittest.TestCase):
    """Parse modifier names on functions and modifier definitions."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_function_modifiers(self):
        """Extract modifier names applied to functions."""
        code = """
pragma solidity ^0.8.20;

contract Vault {
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function setFee(uint256 fee) external onlyOwner {
        _fee = fee;
    }
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]

        # Modifier definitions
        mod_names = [m.name for m in c.modifiers]
        self.assertIn("onlyOwner", mod_names)

        # Function modifiers
        set_fee = next(f for f in c.functions if f.name == "setFee")
        self.assertIn("onlyOwner", set_fee.modifiers)

    def test_modifier_with_params(self):
        """Extract modifier definition with parameters."""
        code = """
pragma solidity ^0.8.20;

contract Auth {
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender));
        _;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
    }
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]

        m = next(mod for mod in c.modifiers if mod.name == "onlyRole")
        self.assertEqual(len(m.params), 1)
        self.assertEqual(m.params[0].type_name, "bytes32")


class TestRegexFallbackImports(unittest.TestCase):
    """Parse import statements via regex."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_imports(self):
        """Extract import paths."""
        code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/IPool.sol";

contract Pool is Ownable {
}
"""
        ast = self.parser.parse_single(code)
        self.assertIn("@openzeppelin/contracts/access/Ownable.sol", ast.import_map)
        self.assertIn("@openzeppelin/contracts/token/ERC20/IERC20.sol", ast.import_map)
        self.assertIn("./interfaces/IPool.sol", ast.import_map)


class TestRegexFallbackMultiContract(unittest.TestCase):
    """Parse multiple contracts from one file."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_multi_contract_file(self):
        """Extract all contracts from a file with multiple definitions."""
        code = """
pragma solidity ^0.8.20;

interface IToken {
    function totalSupply() external view returns (uint256);
}

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

contract Token is IToken {
    uint256 public totalSupply;
}
"""
        ast = self.parser.parse_single(code)
        names = sorted(c.name for c in ast.contracts)
        self.assertIn("IToken", names)
        self.assertIn("MathLib", names)
        self.assertIn("Token", names)

        # Check kinds
        itoken = next(c for c in ast.contracts if c.name == "IToken")
        self.assertEqual(itoken.kind, "interface")

        mathlib = next(c for c in ast.contracts if c.name == "MathLib")
        self.assertEqual(mathlib.kind, "library")

        token = next(c for c in ast.contracts if c.name == "Token")
        self.assertEqual(token.kind, "contract")
        self.assertIn("IToken", token.base_contracts)


class TestRegexFallbackAbstractContract(unittest.TestCase):
    """Parse abstract contract definitions."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_abstract(self):
        """Detect abstract contracts."""
        code = """
pragma solidity ^0.8.20;

abstract contract Base {
    function foo() external virtual;
}
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 1)
        c = ast.contracts[0]
        self.assertEqual(c.name, "Base")
        self.assertEqual(c.kind, "abstract")


class TestRegexFallbackReceiveFallback(unittest.TestCase):
    """Parse receive and fallback functions."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_receive_and_fallback(self):
        """Extract receive and fallback functions."""
        code = """
pragma solidity ^0.8.20;

contract Wallet {
    receive() external payable {
    }

    fallback() external payable {
    }
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]
        func_names = [f.name for f in c.functions]
        self.assertIn("receive", func_names)
        self.assertIn("fallback", func_names)

        recv = next(f for f in c.functions if f.name == "receive")
        self.assertTrue(recv.is_receive)

        fb = next(f for f in c.functions if f.name == "fallback")
        self.assertTrue(fb.is_fallback)


class TestRegexFallbackStateVarModifiers(unittest.TestCase):
    """Parse constant and immutable state variables."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_constant_and_immutable(self):
        """Detect constant and immutable state variables."""
        code = """
pragma solidity ^0.8.20;

contract Config {
    uint256 public constant MAX_FEE = 10000;
    address public immutable deployer;
    uint256 internal _fee;
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]

        max_fee = next((sv for sv in c.state_variables if sv.name == "MAX_FEE"), None)
        self.assertIsNotNone(max_fee)
        self.assertTrue(max_fee.constant)
        self.assertFalse(max_fee.immutable)

        deployer = next((sv for sv in c.state_variables if sv.name == "deployer"), None)
        self.assertIsNotNone(deployer)
        self.assertFalse(deployer.constant)
        self.assertTrue(deployer.immutable)

        fee = next((sv for sv in c.state_variables if sv.name == "_fee"), None)
        self.assertIsNotNone(fee)
        self.assertEqual(fee.visibility, Visibility.INTERNAL)


class TestRegexFallbackMultipleFiles(unittest.TestCase):
    """Parse multiple contract files via the parse() method."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_parse_multiple_files(self):
        """Parse multiple files and aggregate results."""
        files = [
            {"name": "A.sol", "path": "/src/A.sol", "content": """
pragma solidity ^0.8.20;
contract A {
    uint256 public x;
}
"""},
            {"name": "B.sol", "path": "/src/B.sol", "content": """
pragma solidity ^0.8.20;
contract B is A {
    uint256 public y;
}
"""},
        ]
        ast = self.parser.parse(files)
        names = [c.name for c in ast.contracts]
        self.assertIn("A", names)
        self.assertIn("B", names)
        self.assertIn("B", ast.inheritance_graph)
        self.assertIn("A", ast.inheritance_graph["B"])


# ===========================================================================
# 2. AST Walking Tests (mock the AST JSON)
# ===========================================================================

class TestASTWalkingContract(unittest.TestCase):
    """Walk mocked solc AST JSON and extract ContractDef."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def _make_compiler_output(self, ast_nodes, storage=None):
        """Helper to build mock compiler output."""
        output = {
            "sources": {
                "Test.sol": {
                    "ast": {
                        "nodeType": "SourceUnit",
                        "nodes": ast_nodes,
                    }
                }
            },
            "contracts": {},
            "errors": [],
        }
        if storage:
            output["contracts"] = {
                "Test.sol": storage,
            }
        return output

    def test_walk_contract_definition(self):
        """Walk a ContractDefinition node and create ContractDef."""
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "MyContract",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [
                {"baseName": {"name": "Ownable"}},
                {"baseName": {"name": "IERC20"}},
            ],
            "nodes": [],
            "src": "0:100:0",
        }]

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        output = self._make_compiler_output(ast_nodes)
        result = self.parser._process_compiler_output(output, result)

        self.assertEqual(len(result.contracts), 1)
        c = result.contracts[0]
        self.assertEqual(c.name, "MyContract")
        self.assertEqual(c.kind, "contract")
        self.assertIn("Ownable", c.base_contracts)
        self.assertIn("IERC20", c.base_contracts)

    def test_walk_abstract_contract(self):
        """Detect abstract contracts from AST."""
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "AbstractBase",
            "contractKind": "contract",
            "abstract": True,
            "baseContracts": [],
            "nodes": [],
            "src": "",
        }]

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        output = self._make_compiler_output(ast_nodes)
        result = self.parser._process_compiler_output(output, result)

        self.assertEqual(result.contracts[0].kind, "abstract")

    def test_walk_interface(self):
        """Detect interfaces from AST."""
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "IPool",
            "contractKind": "interface",
            "abstract": False,
            "baseContracts": [],
            "nodes": [],
            "src": "",
        }]

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        output = self._make_compiler_output(ast_nodes)
        result = self.parser._process_compiler_output(output, result)

        self.assertEqual(result.contracts[0].kind, "interface")

    def test_walk_library(self):
        """Detect libraries from AST."""
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "MathLib",
            "contractKind": "library",
            "abstract": False,
            "baseContracts": [],
            "nodes": [],
            "src": "",
        }]

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        output = self._make_compiler_output(ast_nodes)
        result = self.parser._process_compiler_output(output, result)

        self.assertEqual(result.contracts[0].kind, "library")


class TestASTWalkingFunction(unittest.TestCase):
    """Walk FunctionDefinition nodes and extract FunctionDef."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def _make_function_node(self, **kwargs):
        """Helper to build a mock FunctionDefinition node."""
        node = {
            "nodeType": "FunctionDefinition",
            "name": kwargs.get("name", "myFunc"),
            "kind": kwargs.get("kind", "function"),
            "visibility": kwargs.get("visibility", "public"),
            "stateMutability": kwargs.get("stateMutability", "nonpayable"),
            "parameters": {
                "parameters": kwargs.get("params", []),
            },
            "returnParameters": {
                "parameters": kwargs.get("returns", []),
            },
            "modifiers": kwargs.get("modifiers", []),
            "body": kwargs.get("body"),
            "src": kwargs.get("src", ""),
        }
        return node

    def _make_contract_output(self, func_nodes, state_var_nodes=None):
        """Wrap function nodes in a contract definition for full processing."""
        nodes = list(state_var_nodes or []) + list(func_nodes)
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "TestContract",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": nodes,
            "src": "",
        }]
        output = {
            "sources": {
                "Test.sol": {
                    "ast": {
                        "nodeType": "SourceUnit",
                        "nodes": ast_nodes,
                    }
                }
            },
            "contracts": {},
            "errors": [],
        }
        return output

    def test_function_with_visibility_and_mutability(self):
        """Extract visibility and mutability from FunctionDefinition."""
        func = self._make_function_node(
            name="getBalance",
            visibility="external",
            stateMutability="view",
            params=[{
                "name": "account",
                "typeName": {"nodeType": "ElementaryTypeName", "name": "address"},
                "storageLocation": "default",
            }],
            returns=[{
                "name": "",
                "typeName": {"nodeType": "ElementaryTypeName", "name": "uint256"},
                "storageLocation": "default",
            }],
        )

        output = self._make_contract_output([func])
        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        f = result.contracts[0].functions[0]
        self.assertEqual(f.name, "getBalance")
        self.assertEqual(f.visibility, Visibility.EXTERNAL)
        self.assertEqual(f.mutability, Mutability.VIEW)
        self.assertEqual(len(f.params), 1)
        self.assertEqual(f.params[0].name, "account")
        self.assertEqual(f.params[0].type_name, "address")
        self.assertEqual(len(f.returns), 1)
        self.assertEqual(f.returns[0].type_name, "uint256")

    def test_constructor_detection(self):
        """Detect constructor from AST."""
        func = self._make_function_node(name="", kind="constructor")

        output = self._make_contract_output([func])
        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        f = result.contracts[0].functions[0]
        self.assertTrue(f.is_constructor)
        self.assertEqual(f.name, "constructor")

    def test_fallback_and_receive_detection(self):
        """Detect fallback and receive functions from AST."""
        fb = self._make_function_node(name="", kind="fallback", visibility="external", stateMutability="payable")
        rcv = self._make_function_node(name="", kind="receive", visibility="external", stateMutability="payable")

        output = self._make_contract_output([fb, rcv])
        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        funcs = result.contracts[0].functions
        fb_func = next(f for f in funcs if f.is_fallback)
        self.assertEqual(fb_func.name, "fallback")
        self.assertEqual(fb_func.mutability, Mutability.PAYABLE)

        rcv_func = next(f for f in funcs if f.is_receive)
        self.assertEqual(rcv_func.name, "receive")

    def test_function_with_modifiers(self):
        """Extract modifier names from FunctionDefinition."""
        func = self._make_function_node(
            name="withdraw",
            modifiers=[
                {"modifierName": {"name": "nonReentrant"}},
                {"modifierName": {"name": "onlyOwner"}},
            ],
        )

        output = self._make_contract_output([func])
        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        f = result.contracts[0].functions[0]
        self.assertIn("nonReentrant", f.modifiers)
        self.assertIn("onlyOwner", f.modifiers)


class TestASTWalkingStateVariable(unittest.TestCase):
    """Walk state VariableDeclaration nodes."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_state_variable_basic(self):
        """Extract basic state variable with type and visibility."""
        var_node = {
            "nodeType": "VariableDeclaration",
            "name": "totalSupply",
            "stateVariable": True,
            "visibility": "public",
            "constant": False,
            "mutability": "mutable",
            "typeName": {"nodeType": "ElementaryTypeName", "name": "uint256"},
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Token",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [var_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        sv = result.contracts[0].state_variables[0]
        self.assertEqual(sv.name, "totalSupply")
        self.assertEqual(sv.type_name, "uint256")
        self.assertEqual(sv.visibility, Visibility.PUBLIC)
        self.assertFalse(sv.constant)
        self.assertFalse(sv.immutable)

    def test_state_variable_constant(self):
        """Detect constant state variables."""
        var_node = {
            "nodeType": "VariableDeclaration",
            "name": "MAX_FEE",
            "stateVariable": True,
            "visibility": "public",
            "constant": True,
            "mutability": "mutable",
            "typeName": {"nodeType": "ElementaryTypeName", "name": "uint256"},
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Config",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [var_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        sv = result.contracts[0].state_variables[0]
        self.assertTrue(sv.constant)

    def test_state_variable_immutable(self):
        """Detect immutable state variables."""
        var_node = {
            "nodeType": "VariableDeclaration",
            "name": "deployer",
            "stateVariable": True,
            "visibility": "public",
            "constant": False,
            "mutability": "immutable",
            "typeName": {"nodeType": "ElementaryTypeName", "name": "address"},
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Config",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [var_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        sv = result.contracts[0].state_variables[0]
        self.assertTrue(sv.immutable)

    def test_mapping_type(self):
        """Extract mapping type from state variable."""
        var_node = {
            "nodeType": "VariableDeclaration",
            "name": "balances",
            "stateVariable": True,
            "visibility": "private",
            "constant": False,
            "mutability": "mutable",
            "typeName": {
                "nodeType": "Mapping",
                "keyType": {"nodeType": "ElementaryTypeName", "name": "address"},
                "valueType": {"nodeType": "ElementaryTypeName", "name": "uint256"},
            },
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Token",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [var_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        sv = result.contracts[0].state_variables[0]
        self.assertEqual(sv.type_name, "mapping(address => uint256)")


class TestASTWalkingFunctionBody(unittest.TestCase):
    """Analyze function body for state reads, writes, and calls."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_state_reads_and_writes(self):
        """Detect state variable reads and writes in function body."""
        # Simulate: function deposit(uint256 amount) { totalSupply += amount; balances[msg.sender] += amount; }
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "Assignment",
                        "operator": "+=",
                        "leftHandSide": {
                            "nodeType": "Identifier",
                            "name": "totalSupply",
                        },
                        "rightHandSide": {
                            "nodeType": "Identifier",
                            "name": "amount",
                        },
                    },
                },
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "Assignment",
                        "operator": "+=",
                        "leftHandSide": {
                            "nodeType": "IndexAccess",
                            "baseExpression": {
                                "nodeType": "Identifier",
                                "name": "balances",
                            },
                            "indexExpression": {
                                "nodeType": "MemberAccess",
                                "memberName": "sender",
                                "expression": {"nodeType": "Identifier", "name": "msg"},
                            },
                        },
                        "rightHandSide": {
                            "nodeType": "Identifier",
                            "name": "amount",
                        },
                    },
                },
            ],
        }

        state_var_names = {"totalSupply", "balances", "fee"}
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertIn("totalSupply", state_writes)
        self.assertIn("balances", state_writes)

    def test_external_call_detection(self):
        """Detect external calls in function body."""
        # Simulate: token.transfer(to, amount)
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "expression": {
                            "nodeType": "MemberAccess",
                            "memberName": "transfer",
                            "expression": {
                                "nodeType": "Identifier",
                                "name": "token",
                                "typeDescriptions": {
                                    "typeString": "contract IERC20",
                                },
                            },
                        },
                        "arguments": [],
                    },
                },
            ],
        }

        state_var_names = {"token"}
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertEqual(len(external_calls), 1)
        self.assertEqual(external_calls[0]["target"], "token")
        self.assertEqual(external_calls[0]["function"], "transfer")

    def test_internal_call_detection(self):
        """Detect internal function calls in body."""
        # Simulate: _updateBalance(account, amount)
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "expression": {
                            "nodeType": "Identifier",
                            "name": "_updateBalance",
                        },
                        "arguments": [],
                    },
                },
            ],
        }

        state_var_names = set()
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertIn("_updateBalance", internal_calls)

    def test_low_level_call_detection(self):
        """Detect low-level calls (address.call, etc.)."""
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "expression": {
                            "nodeType": "MemberAccess",
                            "memberName": "call",
                            "expression": {
                                "nodeType": "Identifier",
                                "name": "recipient",
                                "typeDescriptions": {
                                    "typeString": "address payable",
                                },
                            },
                        },
                        "arguments": [],
                    },
                },
            ],
        }

        state_var_names = set()
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertEqual(len(external_calls), 1)
        self.assertEqual(external_calls[0]["function"], "call")
        self.assertEqual(external_calls[0]["type"], "low_level")

    def test_builtins_not_recorded_as_internal_calls(self):
        """require, assert, etc. should not appear in internal_calls."""
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "expression": {
                            "nodeType": "Identifier",
                            "name": "require",
                        },
                        "arguments": [],
                    },
                },
            ],
        }

        state_var_names = set()
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertNotIn("require", internal_calls)

    def test_unary_write_detection(self):
        """Detect state writes via ++, --, delete."""
        body = {
            "nodeType": "Block",
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "UnaryOperation",
                        "operator": "++",
                        "subExpression": {
                            "nodeType": "Identifier",
                            "name": "counter",
                        },
                    },
                },
            ],
        }

        state_var_names = {"counter"}
        state_reads = set()
        state_writes = set()
        external_calls = []
        internal_calls = []

        self.parser._analyze_function_body(
            body, state_var_names,
            state_reads, state_writes, external_calls, internal_calls,
        )

        self.assertIn("counter", state_writes)


class TestASTWalkingInheritance(unittest.TestCase):
    """Test inheritance graph building from AST."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_inheritance_graph(self):
        """Build inheritance graph from multiple contracts."""
        ast_nodes = [
            {
                "nodeType": "ContractDefinition",
                "name": "Ownable",
                "contractKind": "contract",
                "abstract": False,
                "baseContracts": [],
                "nodes": [],
                "src": "",
            },
            {
                "nodeType": "ContractDefinition",
                "name": "ReentrancyGuard",
                "contractKind": "contract",
                "abstract": True,
                "baseContracts": [],
                "nodes": [],
                "src": "",
            },
            {
                "nodeType": "ContractDefinition",
                "name": "Pool",
                "contractKind": "contract",
                "abstract": False,
                "baseContracts": [
                    {"baseName": {"name": "Ownable"}},
                    {"baseName": {"name": "ReentrancyGuard"}},
                ],
                "nodes": [],
                "src": "",
            },
        ]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        self.assertIn("Pool", result.inheritance_graph)
        self.assertIn("Ownable", result.inheritance_graph["Pool"])
        self.assertIn("ReentrancyGuard", result.inheritance_graph["Pool"])
        self.assertEqual(result.inheritance_graph.get("Ownable", []), [])


class TestASTWalkingEvents(unittest.TestCase):
    """Walk EventDefinition nodes."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_event_extraction(self):
        """Extract event definitions from AST."""
        event_node = {
            "nodeType": "EventDefinition",
            "name": "Transfer",
            "parameters": {
                "parameters": [
                    {
                        "name": "from",
                        "typeName": {"nodeType": "ElementaryTypeName", "name": "address"},
                        "indexed": True,
                    },
                    {
                        "name": "to",
                        "typeName": {"nodeType": "ElementaryTypeName", "name": "address"},
                        "indexed": True,
                    },
                    {
                        "name": "value",
                        "typeName": {"nodeType": "ElementaryTypeName", "name": "uint256"},
                        "indexed": False,
                    },
                ],
            },
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Token",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [event_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        events = result.contracts[0].events
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["name"], "Transfer")
        self.assertEqual(len(events[0]["params"]), 3)
        self.assertTrue(events[0]["params"][0]["indexed"])


class TestASTWalkingImports(unittest.TestCase):
    """Walk ImportDirective nodes."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_import_collection(self):
        """Collect import directives from AST."""
        ast_nodes = [
            {
                "nodeType": "ImportDirective",
                "file": "@openzeppelin/contracts/access/Ownable.sol",
                "absolutePath": "node_modules/@openzeppelin/contracts/access/Ownable.sol",
            },
            {
                "nodeType": "ImportDirective",
                "file": "./interfaces/IPool.sol",
                "absolutePath": "src/interfaces/IPool.sol",
            },
            {
                "nodeType": "ContractDefinition",
                "name": "Pool",
                "contractKind": "contract",
                "abstract": False,
                "baseContracts": [],
                "nodes": [],
                "src": "",
            },
        ]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        self.assertIn("@openzeppelin/contracts/access/Ownable.sol", result.import_map)
        self.assertEqual(
            result.import_map["@openzeppelin/contracts/access/Ownable.sol"],
            "node_modules/@openzeppelin/contracts/access/Ownable.sol",
        )
        self.assertIn("./interfaces/IPool.sol", result.import_map)


class TestASTWalkingUsingDirective(unittest.TestCase):
    """Walk UsingForDirective nodes."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_using_directive(self):
        """Extract using...for directives."""
        using_node = {
            "nodeType": "UsingForDirective",
            "libraryName": {"name": "SafeMath"},
            "typeName": {"nodeType": "ElementaryTypeName", "name": "uint256"},
        }

        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Token",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [using_node],
            "src": "",
        }]

        output = {
            "sources": {"Test.sol": {"ast": {"nodeType": "SourceUnit", "nodes": ast_nodes}}},
            "contracts": {},
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Test.sol"])
        result = self.parser._process_compiler_output(output, result)

        using = result.contracts[0].using_directives
        self.assertEqual(len(using), 1)
        self.assertEqual(using[0]["library"], "SafeMath")
        self.assertEqual(using[0]["type"], "uint256")


# ===========================================================================
# 3. Storage Layout Tests
# ===========================================================================

class TestStorageLayout(unittest.TestCase):
    """Test storage layout parsing from compiler output."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_simple_storage_layout(self):
        """Parse basic storage layout with ordered slots."""
        layout = {
            "storage": [
                {"label": "totalSupply", "slot": "0", "offset": 0, "type": "t_uint256"},
                {"label": "owner", "slot": "1", "offset": 0, "type": "t_address"},
                {"label": "paused", "slot": "1", "offset": 20, "type": "t_bool"},
            ],
            "types": {
                "t_uint256": {"label": "uint256", "numberOfBytes": "32"},
                "t_address": {"label": "address", "numberOfBytes": "20"},
                "t_bool": {"label": "bool", "numberOfBytes": "1"},
            },
        }

        result = self.parser._parse_storage_layout(layout)
        self.assertEqual(len(result), 3)

        self.assertEqual(result[0].name, "totalSupply")
        self.assertEqual(result[0].slot, 0)
        self.assertEqual(result[0].offset, 0)
        self.assertEqual(result[0].type_name, "uint256")

        self.assertEqual(result[1].name, "owner")
        self.assertEqual(result[1].slot, 1)
        self.assertEqual(result[1].offset, 0)
        self.assertEqual(result[1].type_name, "address")

        # Packed variable
        self.assertEqual(result[2].name, "paused")
        self.assertEqual(result[2].slot, 1)
        self.assertEqual(result[2].offset, 20)
        self.assertEqual(result[2].type_name, "bool")

    def test_mapping_storage_layout(self):
        """Parse storage layout with mappings."""
        layout = {
            "storage": [
                {"label": "balances", "slot": "0", "offset": 0, "type": "t_mapping_address_uint256"},
                {"label": "allowances", "slot": "1", "offset": 0, "type": "t_mapping_address_mapping_address_uint256"},
            ],
            "types": {
                "t_mapping_address_uint256": {
                    "label": "mapping(address => uint256)",
                    "numberOfBytes": "32",
                },
                "t_mapping_address_mapping_address_uint256": {
                    "label": "mapping(address => mapping(address => uint256))",
                    "numberOfBytes": "32",
                },
            },
        }

        result = self.parser._parse_storage_layout(layout)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "balances")
        self.assertEqual(result[0].slot, 0)
        self.assertEqual(result[0].type_name, "mapping(address => uint256)")

    def test_storage_layout_in_compiler_output(self):
        """Verify storage layout is attached to the correct contract in SolidityAST."""
        ast_nodes = [{
            "nodeType": "ContractDefinition",
            "name": "Token",
            "contractKind": "contract",
            "abstract": False,
            "baseContracts": [],
            "nodes": [],
            "src": "",
        }]

        output = {
            "sources": {
                "Token.sol": {
                    "ast": {
                        "nodeType": "SourceUnit",
                        "nodes": ast_nodes,
                    }
                }
            },
            "contracts": {
                "Token.sol": {
                    "Token": {
                        "storageLayout": {
                            "storage": [
                                {"label": "totalSupply", "slot": "0", "offset": 0, "type": "t_uint256"},
                            ],
                            "types": {
                                "t_uint256": {"label": "uint256", "numberOfBytes": "32"},
                            },
                        }
                    }
                }
            },
            "errors": [],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=["Token.sol"])
        result = self.parser._process_compiler_output(output, result)

        self.assertIn("Token", result.storage_layout)
        layout = result.storage_layout["Token"]
        self.assertEqual(len(layout), 1)
        self.assertEqual(layout[0].name, "totalSupply")
        self.assertEqual(layout[0].slot, 0)

    def test_inherited_storage_layout(self):
        """Storage layout from inherited contracts includes parent slots."""
        layout = {
            "storage": [
                {"label": "owner", "slot": "0", "offset": 0, "type": "t_address"},
                {"label": "totalSupply", "slot": "1", "offset": 0, "type": "t_uint256"},
                {"label": "fee", "slot": "2", "offset": 0, "type": "t_uint256"},
            ],
            "types": {
                "t_address": {"label": "address", "numberOfBytes": "20"},
                "t_uint256": {"label": "uint256", "numberOfBytes": "32"},
            },
        }

        result = self.parser._parse_storage_layout(layout)
        self.assertEqual(len(result), 3)
        # owner from Ownable at slot 0
        self.assertEqual(result[0].slot, 0)
        self.assertEqual(result[0].name, "owner")
        # totalSupply at slot 1
        self.assertEqual(result[1].slot, 1)
        # fee at slot 2
        self.assertEqual(result[2].slot, 2)


# ===========================================================================
# 4. Helper Method Tests
# ===========================================================================

class TestHelperGetExternalFunctions(unittest.TestCase):
    """Test get_external_functions helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def _make_ast(self):
        """Build a SolidityAST with mixed visibility functions."""
        base_contract = ContractDef(
            name="Base",
            kind="contract",
            base_contracts=[],
            functions=[
                FunctionDef(name="basePub", visibility=Visibility.PUBLIC, mutability=Mutability.NONPAYABLE),
                FunctionDef(name="baseInt", visibility=Visibility.INTERNAL, mutability=Mutability.NONPAYABLE),
            ],
        )
        child_contract = ContractDef(
            name="Child",
            kind="contract",
            base_contracts=["Base"],
            functions=[
                FunctionDef(name="deposit", visibility=Visibility.EXTERNAL, mutability=Mutability.PAYABLE),
                FunctionDef(name="_update", visibility=Visibility.PRIVATE, mutability=Mutability.NONPAYABLE),
                FunctionDef(name="getBalance", visibility=Visibility.PUBLIC, mutability=Mutability.VIEW),
            ],
        )
        ast = SolidityAST(
            contracts=[base_contract, child_contract],
            inheritance_graph={"Child": ["Base"], "Base": []},
        )
        return ast

    def test_returns_only_external_public(self):
        """Only external and public functions should be returned."""
        ast = self._make_ast()
        result = self.parser.get_external_functions(ast, "Child")
        names = [f.name for f in result]
        self.assertIn("deposit", names)
        self.assertIn("getBalance", names)
        self.assertNotIn("_update", names)

    def test_includes_inherited(self):
        """Inherited public functions should be included."""
        ast = self._make_ast()
        result = self.parser.get_external_functions(ast, "Child")
        names = [f.name for f in result]
        self.assertIn("basePub", names)
        self.assertNotIn("baseInt", names)

    def test_no_duplicates(self):
        """If child overrides a parent function, it should appear once."""
        ast = self._make_ast()
        # Add an override in Child
        ast.contracts[1].functions.append(
            FunctionDef(name="basePub", visibility=Visibility.PUBLIC, mutability=Mutability.NONPAYABLE)
        )
        result = self.parser.get_external_functions(ast, "Child")
        count = sum(1 for f in result if f.name == "basePub")
        self.assertEqual(count, 1)


class TestHelperGetStateVariableWriters(unittest.TestCase):
    """Test get_state_variable_writers helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_finds_writers(self):
        """Find functions that write to a specific state variable."""
        contract = ContractDef(
            name="Vault",
            kind="contract",
            functions=[
                FunctionDef(name="deposit", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                            state_writes={"totalAssets", "balances"}),
                FunctionDef(name="withdraw", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                            state_writes={"totalAssets", "balances"}),
                FunctionDef(name="getPrice", visibility=Visibility.PUBLIC, mutability=Mutability.VIEW,
                            state_reads={"totalAssets"}),
            ],
        )
        ast = SolidityAST(contracts=[contract])

        writers = self.parser.get_state_variable_writers(ast, "Vault", "totalAssets")
        names = [f.name for f in writers]
        self.assertIn("deposit", names)
        self.assertIn("withdraw", names)
        self.assertNotIn("getPrice", names)


class TestHelperGetModifierChain(unittest.TestCase):
    """Test get_modifier_chain helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_modifier_chain(self):
        """Get modifier names for a function."""
        contract = ContractDef(
            name="Vault",
            kind="contract",
            functions=[
                FunctionDef(name="withdraw", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                            modifiers=["nonReentrant", "onlyOwner"]),
                FunctionDef(name="deposit", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                            modifiers=["nonReentrant"]),
            ],
        )
        ast = SolidityAST(contracts=[contract])

        chain = self.parser.get_modifier_chain(ast, "Vault", "withdraw")
        self.assertIn("nonReentrant", chain)
        self.assertIn("onlyOwner", chain)

        chain2 = self.parser.get_modifier_chain(ast, "Vault", "deposit")
        self.assertEqual(chain2, ["nonReentrant"])

    def test_no_function_returns_empty(self):
        """Return empty list for nonexistent function."""
        ast = SolidityAST(contracts=[ContractDef(name="A", kind="contract")])
        chain = self.parser.get_modifier_chain(ast, "A", "nonexistent")
        self.assertEqual(chain, [])


class TestHelperGetStorageLayout(unittest.TestCase):
    """Test get_storage_layout helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_returns_layout(self):
        """Get ordered storage layout for a contract."""
        sv1 = StateVariable(name="x", type_name="uint256", visibility=Visibility.PUBLIC, slot=0)
        sv2 = StateVariable(name="y", type_name="address", visibility=Visibility.PUBLIC, slot=1)
        ast = SolidityAST(storage_layout={"Token": [sv1, sv2]})

        layout = self.parser.get_storage_layout(ast, "Token")
        self.assertEqual(len(layout), 2)
        self.assertEqual(layout[0].name, "x")
        self.assertEqual(layout[1].name, "y")

    def test_missing_contract_returns_empty(self):
        """Return empty list for contract not in layout."""
        ast = SolidityAST()
        layout = self.parser.get_storage_layout(ast, "Missing")
        self.assertEqual(layout, [])


class TestHelperFormatForLLM(unittest.TestCase):
    """Test format_for_llm helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_basic_format(self):
        """Generate readable summary for LLM."""
        contract = ContractDef(
            name="Pool",
            kind="contract",
            base_contracts=["Ownable", "ReentrancyGuard"],
            state_variables=[
                StateVariable(name="totalAssets", type_name="uint256", visibility=Visibility.PUBLIC, slot=0),
                StateVariable(name="fee", type_name="uint256", visibility=Visibility.PUBLIC),
            ],
            functions=[
                FunctionDef(
                    name="deposit", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                    params=[FunctionParam(name="assets", type_name="uint256")],
                    returns=[FunctionParam(name="shares", type_name="uint256")],
                    modifiers=["nonReentrant"],
                    state_writes={"totalAssets"},
                ),
                FunctionDef(
                    name="getSharePrice", visibility=Visibility.PUBLIC, mutability=Mutability.VIEW,
                    state_reads={"totalAssets"},
                ),
                FunctionDef(
                    name="setFee", visibility=Visibility.EXTERNAL, mutability=Mutability.NONPAYABLE,
                    params=[FunctionParam(name="newFee", type_name="uint256")],
                    modifiers=["onlyOwner"],
                    state_writes={"fee"},
                ),
                FunctionDef(
                    name="_update", visibility=Visibility.INTERNAL, mutability=Mutability.NONPAYABLE,
                ),
            ],
        )
        ast = SolidityAST(contracts=[contract])

        text = self.parser.format_for_llm(ast)

        self.assertIn("## Contract Structure (from AST)", text)
        self.assertIn("### Pool (is Ownable, ReentrancyGuard)", text)
        self.assertIn("totalAssets(uint256", text)
        self.assertIn("deposit(uint256 assets)", text)
        self.assertIn("[nonReentrant]", text)
        self.assertIn("writes: totalAssets", text)
        self.assertIn("Admin Functions:", text)
        self.assertIn("setFee", text)
        self.assertIn("[onlyOwner]", text)
        self.assertIn("Internal Functions:", text)
        self.assertIn("_update", text)

    def test_empty_contract(self):
        """Format an empty contract without crashing."""
        contract = ContractDef(name="Empty", kind="contract")
        ast = SolidityAST(contracts=[contract])
        text = self.parser.format_for_llm(ast)
        self.assertIn("### Empty", text)

    def test_interface_format(self):
        """Interfaces should have kind label."""
        contract = ContractDef(name="IPool", kind="interface")
        ast = SolidityAST(contracts=[contract])
        text = self.parser.format_for_llm(ast)
        self.assertIn("### Interface IPool", text)


class TestHelperResolveAllBases(unittest.TestCase):
    """Test transitive inheritance resolution."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_transitive_bases(self):
        """Resolve full chain: C -> B -> A."""
        ast = SolidityAST(
            inheritance_graph={
                "C": ["B"],
                "B": ["A"],
                "A": [],
            }
        )
        bases = self.parser._resolve_all_bases(ast, "C")
        self.assertEqual(bases, ["B", "A"])

    def test_diamond_inheritance(self):
        """Handle diamond pattern without duplicates."""
        ast = SolidityAST(
            inheritance_graph={
                "D": ["B", "C"],
                "B": ["A"],
                "C": ["A"],
                "A": [],
            }
        )
        bases = self.parser._resolve_all_bases(ast, "D")
        self.assertIn("B", bases)
        self.assertIn("C", bases)
        self.assertIn("A", bases)
        # No duplicates
        self.assertEqual(len(bases), len(set(bases)))

    def test_no_bases(self):
        """Contract with no inheritance returns empty list."""
        ast = SolidityAST(inheritance_graph={"Solo": []})
        bases = self.parser._resolve_all_bases(ast, "Solo")
        self.assertEqual(bases, [])


# ===========================================================================
# 5. Type Resolution Tests
# ===========================================================================

class TestTypeResolution(unittest.TestCase):
    """Test _resolve_type_name for various AST type nodes."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_elementary_type(self):
        """Resolve elementary types like uint256, address."""
        node = {"nodeType": "ElementaryTypeName", "name": "uint256"}
        self.assertEqual(self.parser._resolve_type_name(node), "uint256")

    def test_user_defined_type(self):
        """Resolve user-defined types (structs, contracts, etc.)."""
        node = {"nodeType": "UserDefinedTypeName", "name": "IERC20"}
        self.assertEqual(self.parser._resolve_type_name(node), "IERC20")

    def test_mapping_type(self):
        """Resolve mapping types."""
        node = {
            "nodeType": "Mapping",
            "keyType": {"nodeType": "ElementaryTypeName", "name": "address"},
            "valueType": {"nodeType": "ElementaryTypeName", "name": "uint256"},
        }
        self.assertEqual(self.parser._resolve_type_name(node), "mapping(address => uint256)")

    def test_array_type(self):
        """Resolve dynamic array types."""
        node = {
            "nodeType": "ArrayTypeName",
            "baseType": {"nodeType": "ElementaryTypeName", "name": "uint256"},
        }
        self.assertEqual(self.parser._resolve_type_name(node), "uint256[]")

    def test_function_type(self):
        """Resolve function types."""
        node = {"nodeType": "FunctionTypeName"}
        self.assertEqual(self.parser._resolve_type_name(node), "function")

    def test_empty_node(self):
        """Handle empty/missing type node."""
        self.assertEqual(self.parser._resolve_type_name({}), "")
        self.assertEqual(self.parser._resolve_type_name(None), "")


# ===========================================================================
# 6. Compilation Failure Fallback Test
# ===========================================================================

class TestCompilationFallback(unittest.TestCase):
    """Test that compilation failure falls back to regex gracefully."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = True

    def test_compilation_failure_falls_back_to_regex(self):
        """When compilation fails, fall back to regex parsing."""
        # Mock compile_standard to raise an exception
        mock_solcx = MagicMock()
        mock_solcx.compile_standard.side_effect = Exception("Compilation error: missing import")
        mock_solcx.set_solc_version = MagicMock()
        self.parser._solcx = mock_solcx

        code = """
pragma solidity ^0.8.20;

import "./Missing.sol";

contract Fallback is Missing {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}
"""
        ast = self.parser.parse_single(code)
        # Should have gotten results from regex fallback
        self.assertGreater(len(ast.contracts), 0)
        self.assertEqual(ast.contracts[0].name, "Fallback")
        # Should record the error
        self.assertTrue(any("Compilation failed" in e for e in ast.errors))


class TestASTAvailableProperty(unittest.TestCase):
    """Test the ast_available property."""

    def test_available_when_solcx_present(self):
        """ast_available is True when solcx is importable."""
        parser = SolidityASTParser()
        # Since we know solcx is installed in the test environment
        self.assertTrue(parser.ast_available)

    def test_not_available_when_forced_off(self):
        """ast_available is False when forced off."""
        parser = SolidityASTParser()
        parser._ast_available = False
        self.assertFalse(parser.ast_available)


# ===========================================================================
# 7. Edge Case Tests
# ===========================================================================

class TestEdgeCases(unittest.TestCase):
    """Various edge cases."""

    def setUp(self):
        self.parser = SolidityASTParser()
        self.parser._ast_available = False

    def test_empty_source(self):
        """Parsing empty source returns empty AST."""
        ast = self.parser.parse_single("")
        self.assertEqual(len(ast.contracts), 0)

    def test_comments_only(self):
        """Parsing comments-only source returns empty AST."""
        code = """
// This is just a comment file
/* Multi-line
   comment */
"""
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 0)

    def test_pragma_only(self):
        """Parsing file with only pragma returns empty AST."""
        code = "pragma solidity ^0.8.20;"
        ast = self.parser.parse_single(code)
        self.assertEqual(len(ast.contracts), 0)

    def test_nested_braces_in_function(self):
        """Regex correctly handles nested braces in function bodies."""
        code = """
pragma solidity ^0.8.20;

contract Nested {
    function complex() external {
        if (true) {
            for (uint i = 0; i < 10; i++) {
                // nested
            }
        }
    }

    function simple() external {
    }
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]
        func_names = [f.name for f in c.functions]
        self.assertIn("complex", func_names)
        self.assertIn("simple", func_names)

    def test_string_with_braces(self):
        """Brace matching ignores braces inside string literals."""
        code = """
pragma solidity ^0.8.20;

contract Strings {
    string constant MSG = "hello { world }";

    function foo() external {
    }
}
"""
        ast = self.parser.parse_single(code)
        c = ast.contracts[0]
        func_names = [f.name for f in c.functions]
        self.assertIn("foo", func_names)

    def test_contract_with_payable_function(self):
        """Extract payable mutability."""
        code = """
pragma solidity ^0.8.20;

contract Payable {
    function deposit() external payable {
    }
}
"""
        ast = self.parser.parse_single(code)
        func = ast.contracts[0].functions[0]
        self.assertEqual(func.mutability, Mutability.PAYABLE)

    def test_function_with_pure(self):
        """Extract pure mutability."""
        code = """
pragma solidity ^0.8.20;

contract Pure {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}
"""
        ast = self.parser.parse_single(code)
        func = ast.contracts[0].functions[0]
        self.assertEqual(func.mutability, Mutability.PURE)

    def test_visibility_enum_values(self):
        """Visibility enum has expected values."""
        self.assertEqual(Visibility.PUBLIC.value, "public")
        self.assertEqual(Visibility.EXTERNAL.value, "external")
        self.assertEqual(Visibility.INTERNAL.value, "internal")
        self.assertEqual(Visibility.PRIVATE.value, "private")

    def test_mutability_enum_values(self):
        """Mutability enum has expected values."""
        self.assertEqual(Mutability.PURE.value, "pure")
        self.assertEqual(Mutability.VIEW.value, "view")
        self.assertEqual(Mutability.NONPAYABLE.value, "nonpayable")
        self.assertEqual(Mutability.PAYABLE.value, "payable")


class TestBraceExtraction(unittest.TestCase):
    """Test the brace block extraction utility."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_simple_block(self):
        """Extract a simple brace-delimited block."""
        content = "prefix { body } suffix"
        result = self.parser._extract_brace_block(content, 7)
        self.assertEqual(result, "{ body }")

    def test_nested_blocks(self):
        """Extract block with nested braces."""
        content = "{ outer { inner } more }"
        result = self.parser._extract_brace_block(content, 0)
        self.assertEqual(result, "{ outer { inner } more }")

    def test_string_braces_ignored(self):
        """Braces inside strings don't count."""
        content = '{ "a { b }" }'
        result = self.parser._extract_brace_block(content, 0)
        self.assertEqual(result, '{ "a { b }" }')

    def test_comment_braces_ignored(self):
        """Braces inside comments don't count."""
        content = "{ // }\nreal }"
        result = self.parser._extract_brace_block(content, 0)
        self.assertEqual(result, "{ // }\nreal }")

    def test_block_comment_braces_ignored(self):
        """Braces inside block comments don't count."""
        content = "{ /* } */ real }"
        result = self.parser._extract_brace_block(content, 0)
        self.assertEqual(result, "{ /* } */ real }")

    def test_not_at_brace(self):
        """Return None when start position is not a brace."""
        content = "hello { world }"
        result = self.parser._extract_brace_block(content, 0)
        self.assertIsNone(result)


class TestErrorCollection(unittest.TestCase):
    """Test that compiler warnings/errors are collected."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_compilation_warnings_collected(self):
        """Warnings from compiler output are stored in errors list."""
        output = {
            "sources": {},
            "contracts": {},
            "errors": [
                {
                    "type": "Warning",
                    "formattedMessage": "Warning: Unused variable",
                    "severity": "warning",
                },
                {
                    "type": "Error",
                    "formattedMessage": "Error: Stack too deep",
                    "severity": "error",
                },
            ],
        }

        result = SolidityAST(compiler_version="0.8.30", source_files=[])
        result = self.parser._process_compiler_output(output, result)

        self.assertEqual(len(result.errors), 2)
        self.assertIn("Warning: Unused variable", result.errors[0])
        self.assertIn("Error: Stack too deep", result.errors[1])


# ===========================================================================
# 8. Integration Test (real solc, skipped if unavailable)
# ===========================================================================

@unittest.skipUnless(solcx_available, "solc not installed — skipping integration test")
class TestRealCompilation(unittest.TestCase):
    """Integration test that actually compiles Solidity with solc."""

    def test_compile_and_parse_simple_contract(self):
        """Compile a simple standalone contract and verify full AST extraction."""
        code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleVault {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function getBalance(address user) external view returns (uint256) {
        return deposits[user];
    }
}
"""
        parser = SolidityASTParser(solc_version="0.8.30")
        ast = parser.parse_single(code, "SimpleVault.sol")

        # Should compile without errors (warnings OK)
        real_errors = [e for e in ast.errors if "Error" in e and "Warning" not in e]
        self.assertEqual(len(real_errors), 0, f"Compilation errors: {real_errors}")

        # Contract parsed
        self.assertEqual(len(ast.contracts), 1)
        c = ast.contracts[0]
        self.assertEqual(c.name, "SimpleVault")
        self.assertEqual(c.kind, "contract")

        # Functions
        func_names = [f.name for f in c.functions]
        self.assertIn("deposit", func_names)
        self.assertIn("withdraw", func_names)
        self.assertIn("setOwner", func_names)
        self.assertIn("getBalance", func_names)
        self.assertIn("constructor", func_names)

        # Visibility
        deposit_fn = next(f for f in c.functions if f.name == "deposit")
        self.assertEqual(deposit_fn.visibility, Visibility.EXTERNAL)
        self.assertEqual(deposit_fn.mutability, Mutability.PAYABLE)

        get_balance = next(f for f in c.functions if f.name == "getBalance")
        self.assertEqual(get_balance.visibility, Visibility.EXTERNAL)
        self.assertEqual(get_balance.mutability, Mutability.VIEW)

        # Modifiers on setOwner
        set_owner = next(f for f in c.functions if f.name == "setOwner")
        self.assertIn("onlyOwner", set_owner.modifiers)

        # State variables
        var_names = [sv.name for sv in c.state_variables]
        self.assertIn("owner", var_names)
        self.assertIn("totalDeposits", var_names)
        self.assertIn("deposits", var_names)

        # Events
        event_names = [e["name"] for e in c.events]
        self.assertIn("Deposited", event_names)
        self.assertIn("Withdrawn", event_names)

        # Modifier definitions
        mod_names = [m.name for m in c.modifiers]
        self.assertIn("onlyOwner", mod_names)

        # Storage layout (solc should provide it)
        self.assertIn("SimpleVault", ast.storage_layout)
        layout = ast.storage_layout["SimpleVault"]
        self.assertGreater(len(layout), 0)
        # First slot should be owner (address)
        slot_names = [sv.name for sv in layout]
        self.assertIn("owner", slot_names)
        self.assertIn("totalDeposits", slot_names)

        # State reads/writes (AST body analysis)
        deposit_fn = next(f for f in c.functions if f.name == "deposit")
        self.assertIn("deposits", deposit_fn.state_writes)
        self.assertIn("totalDeposits", deposit_fn.state_writes)

        withdraw_fn = next(f for f in c.functions if f.name == "withdraw")
        self.assertIn("deposits", withdraw_fn.state_writes)
        self.assertIn("totalDeposits", withdraw_fn.state_writes)

        # set_owner should write to owner
        set_owner = next(f for f in c.functions if f.name == "setOwner")
        self.assertIn("owner", set_owner.state_writes)

        # Inheritance graph
        self.assertIn("SimpleVault", ast.inheritance_graph)

        # format_for_llm should produce output
        summary = parser.format_for_llm(ast)
        self.assertIn("SimpleVault", summary)
        self.assertIn("deposit", summary)

    def test_compile_interface(self):
        """Compile and parse an interface."""
        code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"""
        parser = SolidityASTParser(solc_version="0.8.30")
        ast = parser.parse_single(code, "IERC20.sol")

        self.assertEqual(len(ast.contracts), 1)
        c = ast.contracts[0]
        self.assertEqual(c.name, "IERC20")
        self.assertEqual(c.kind, "interface")

        func_names = [f.name for f in c.functions]
        self.assertIn("totalSupply", func_names)
        self.assertIn("balanceOf", func_names)
        self.assertIn("transfer", func_names)

    def test_compile_with_inheritance(self):
        """Compile a contract with inheritance in a single file."""
        code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Base {
    uint256 public baseValue;

    function setBaseValue(uint256 v) external virtual {
        baseValue = v;
    }
}

contract Child is Base {
    uint256 public childValue;

    function setBaseValue(uint256 v) external override {
        baseValue = v + 1;
    }

    function setChildValue(uint256 v) external {
        childValue = v;
    }
}
"""
        parser = SolidityASTParser(solc_version="0.8.30")
        ast = parser.parse_single(code, "Inheritance.sol")

        names = sorted(c.name for c in ast.contracts)
        self.assertIn("Base", names)
        self.assertIn("Child", names)

        child = next(c for c in ast.contracts if c.name == "Child")
        self.assertIn("Base", child.base_contracts)
        self.assertIn("Child", ast.inheritance_graph)
        self.assertIn("Base", ast.inheritance_graph["Child"])


if __name__ == "__main__":
    unittest.main()
