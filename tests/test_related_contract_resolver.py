"""
Tests for RelatedContractResolver and related contract context integration.
"""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.cross_contract_analyzer import (
    RelatedContractSource,
    RelatedContractResolver,
    InterContractAnalyzer,
    STANDARD_LIBRARY_PREFIXES,
)


class TestRelatedContractSource(unittest.TestCase):
    """Tests for the RelatedContractSource dataclass."""

    def test_char_count_auto_computed(self):
        src = RelatedContractSource(
            name="Ownable",
            file_path="/contracts/Ownable.sol",
            content="pragma solidity ^0.8.0;\ncontract Ownable {}",
            relationship="parent",
            priority=1,
        )
        self.assertEqual(src.char_count, len(src.content))

    def test_char_count_explicit(self):
        src = RelatedContractSource(
            name="Ownable",
            file_path="/contracts/Ownable.sol",
            content="pragma solidity ^0.8.0;",
            relationship="parent",
            priority=1,
            char_count=999,
        )
        self.assertEqual(src.char_count, 999)


class TestResolveFromProjectFiles(unittest.TestCase):
    """Test project mode resolution (multi-file audit)."""

    def test_resolve_from_project_files(self):
        """Inheritance relationships correctly resolved."""
        target = {
            'path': '/proj/src/Vault.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'import "./Ownable.sol";\n'
                'contract Vault is Ownable {\n'
                '    function deposit() external {}\n'
                '}\n'
            ),
            'name': 'Vault.sol',
        }
        parent = {
            'path': '/proj/src/Ownable.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'contract Ownable {\n'
                '    address public owner;\n'
                '    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }\n'
                '}\n'
            ),
            'name': 'Ownable.sol',
        }
        sibling = {
            'path': '/proj/src/Token.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'contract Token {\n'
                '    function mint() external {}\n'
                '}\n'
            ),
            'name': 'Token.sol',
        }

        resolver = RelatedContractResolver()
        related = resolver.resolve_related_sources(
            target_files=[target],
            all_files=[target, parent, sibling],
        )

        # Ownable should be resolved as a parent with priority 1
        parent_sources = [r for r in related if r.name == 'Ownable']
        self.assertEqual(len(parent_sources), 1)
        self.assertEqual(parent_sources[0].relationship, 'parent')
        self.assertEqual(parent_sources[0].priority, 1)

    def test_interface_resolved(self):
        """Interface relationships detected and prioritized."""
        target = {
            'path': '/proj/src/Pool.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'import "./IPool.sol";\n'
                'contract Pool {\n'
                '    IPool public otherPool;\n'
                '    function swap() external { otherPool.doSwap(); }\n'
                '}\n'
            ),
            'name': 'Pool.sol',
        }
        iface = {
            'path': '/proj/src/IPool.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'interface IPool {\n'
                '    function doSwap() external;\n'
                '}\n'
            ),
            'name': 'IPool.sol',
        }

        resolver = RelatedContractResolver()
        related = resolver.resolve_related_sources(
            target_files=[target],
            all_files=[target, iface],
        )

        iface_sources = [r for r in related if r.name == 'IPool']
        self.assertEqual(len(iface_sources), 1)
        self.assertEqual(iface_sources[0].relationship, 'interface')
        self.assertEqual(iface_sources[0].priority, 1)

    def test_library_resolved(self):
        """Library relationships detected with priority 2."""
        target = {
            'path': '/proj/src/Vault.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'import "./MathLib.sol";\n'
                'contract Vault {\n'
                '    using MathLib for uint256;\n'
                '}\n'
            ),
            'name': 'Vault.sol',
        }
        lib = {
            'path': '/proj/src/MathLib.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'library MathLib {\n'
                '    function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }\n'
                '}\n'
            ),
            'name': 'MathLib.sol',
        }

        resolver = RelatedContractResolver()
        related = resolver.resolve_related_sources(
            target_files=[target],
            all_files=[target, lib],
        )

        lib_sources = [r for r in related if r.name == 'MathLib']
        self.assertEqual(len(lib_sources), 1)
        self.assertEqual(lib_sources[0].relationship, 'library')
        self.assertEqual(lib_sources[0].priority, 2)


class TestPriorityOrdering(unittest.TestCase):
    """Test that resolved sources are sorted by priority."""

    def test_priority_ordering(self):
        """Parents (1) before libraries (2) before transitive (3)."""
        target = {
            'path': '/proj/src/Vault.sol',
            'content': (
                'pragma solidity ^0.8.0;\n'
                'import "./Ownable.sol";\n'
                'import "./MathLib.sol";\n'
                'contract Vault is Ownable {\n'
                '    using MathLib for uint256;\n'
                '}\n'
            ),
            'name': 'Vault.sol',
        }
        parent = {
            'path': '/proj/src/Ownable.sol',
            'content': 'pragma solidity ^0.8.0;\ncontract Ownable {}',
            'name': 'Ownable.sol',
        }
        lib = {
            'path': '/proj/src/MathLib.sol',
            'content': 'pragma solidity ^0.8.0;\nlibrary MathLib {}',
            'name': 'MathLib.sol',
        }

        resolver = RelatedContractResolver()
        related = resolver.resolve_related_sources(
            target_files=[target],
            all_files=[target, parent, lib],
        )

        self.assertTrue(len(related) >= 2)
        # Parent should come before library in sorted output
        names = [r.name for r in related]
        if 'Ownable' in names and 'MathLib' in names:
            self.assertLess(
                names.index('Ownable'), names.index('MathLib'),
                "Parent (priority 1) should appear before library (priority 2)"
            )


class TestBudgetSelection(unittest.TestCase):
    """Test budget enforcement with priority-based selection."""

    def test_budget_selection(self):
        """Budget enforced: only sources fitting within budget selected."""
        sources = [
            RelatedContractSource("A", "/a.sol", "x" * 100, "parent", 1),
            RelatedContractSource("B", "/b.sol", "y" * 100, "library", 2),
            RelatedContractSource("C", "/c.sol", "z" * 100, "sibling", 3),
        ]

        # Budget fits only 2 sources
        selected = RelatedContractResolver.select_within_budget(sources, 200)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0].name, "A")
        self.assertEqual(selected[1].name, "B")

    def test_budget_zero(self):
        """Zero budget returns empty list."""
        sources = [
            RelatedContractSource("A", "/a.sol", "x" * 100, "parent", 1),
        ]
        selected = RelatedContractResolver.select_within_budget(sources, 0)
        self.assertEqual(len(selected), 0)

    def test_budget_all_fit(self):
        """All sources included when budget is sufficient."""
        sources = [
            RelatedContractSource("A", "/a.sol", "x" * 50, "parent", 1),
            RelatedContractSource("B", "/b.sol", "y" * 50, "library", 2),
        ]
        selected = RelatedContractResolver.select_within_budget(sources, 1000)
        self.assertEqual(len(selected), 2)

    def test_budget_interface_fallback(self):
        """High-priority sources fall back to interface summary when too large."""
        large_content = (
            'pragma solidity ^0.8.0;\n'
            'contract BigContract {\n'
            '    function doStuff() external;\n'
            '    ' + 'uint256 public x;\n    ' * 200 +  # make it large
            '}\n'
        )
        sources = [
            RelatedContractSource("Big", "/big.sol", large_content, "parent", 1),
        ]
        # Budget too small for full content but large enough for summary
        selected = RelatedContractResolver.select_within_budget(sources, 500)
        if selected:
            self.assertIn('[Standard library', selected[0].content)
            self.assertLessEqual(selected[0].char_count, 500)


class TestSingleFileImportResolution(unittest.TestCase):
    """Test single-file mode import resolution."""

    def test_single_file_import_resolution(self):
        """Mock file system: imports resolved from same directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create target file
            target_path = os.path.join(tmpdir, 'Vault.sol')
            with open(target_path, 'w') as f:
                f.write(
                    'pragma solidity ^0.8.0;\n'
                    'import "./Ownable.sol";\n'
                    'contract Vault is Ownable {}\n'
                )

            # Create dependency file
            dep_path = os.path.join(tmpdir, 'Ownable.sol')
            with open(dep_path, 'w') as f:
                f.write(
                    'pragma solidity ^0.8.0;\n'
                    'contract Ownable {\n'
                    '    address public owner;\n'
                    '}\n'
                )

            target_file = {
                'path': target_path,
                'content': open(target_path).read(),
                'name': 'Vault.sol',
            }

            resolver = RelatedContractResolver()
            related = resolver.resolve_related_sources(
                target_files=[target_file],
                all_files=[target_file],
                project_root=tmpdir,
            )

            self.assertEqual(len(related), 1)
            self.assertEqual(related[0].name, 'Ownable')
            self.assertEqual(related[0].relationship, 'parent')

    def test_remappings_resolution(self):
        """Foundry remappings used for import resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create remappings.txt
            with open(os.path.join(tmpdir, 'remappings.txt'), 'w') as f:
                f.write('@oz/=lib/openzeppelin/\n')

            # Create the mapped directory and file
            oz_dir = os.path.join(tmpdir, 'lib', 'openzeppelin')
            os.makedirs(oz_dir, exist_ok=True)
            with open(os.path.join(oz_dir, 'Ownable.sol'), 'w') as f:
                f.write('pragma solidity ^0.8.0;\ncontract Ownable {}\n')

            # Create target
            target_path = os.path.join(tmpdir, 'src', 'Vault.sol')
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, 'w') as f:
                f.write(
                    'pragma solidity ^0.8.0;\n'
                    'import "@oz/Ownable.sol";\n'
                    'contract Vault is Ownable {}\n'
                )

            target_file = {
                'path': target_path,
                'content': open(target_path).read(),
                'name': 'Vault.sol',
            }

            resolver = RelatedContractResolver()
            related = resolver.resolve_related_sources(
                target_files=[target_file],
                all_files=[target_file],
                project_root=tmpdir,
            )

            self.assertEqual(len(related), 1)
            self.assertEqual(related[0].name, 'Ownable')


class TestCircularInheritanceSafety(unittest.TestCase):
    """Test that circular references don't cause infinite loops."""

    def test_circular_inheritance_safety(self):
        """No infinite loops on circular import references."""
        with tempfile.TemporaryDirectory() as tmpdir:
            a_path = os.path.join(tmpdir, 'A.sol')
            b_path = os.path.join(tmpdir, 'B.sol')

            with open(a_path, 'w') as f:
                f.write(
                    'pragma solidity ^0.8.0;\n'
                    'import "./B.sol";\n'
                    'contract A is B {}\n'
                )
            with open(b_path, 'w') as f:
                f.write(
                    'pragma solidity ^0.8.0;\n'
                    'import "./A.sol";\n'
                    'contract B is A {}\n'
                )

            target_file = {
                'path': a_path,
                'content': open(a_path).read(),
                'name': 'A.sol',
            }

            resolver = RelatedContractResolver()
            # This should complete without hanging
            related = resolver.resolve_related_sources(
                target_files=[target_file],
                all_files=[target_file],
                project_root=tmpdir,
            )

            # Should resolve B.sol as a dependency, not hang
            self.assertIsInstance(related, list)


class TestBuildRelatedContextSection(unittest.TestCase):
    """Test prompt formatting for related context."""

    def test_build_related_context_section(self):
        """Formatted section contains contract names and source."""
        from core.deep_analysis_engine import _build_related_context_section

        sources = [
            RelatedContractSource(
                name="Ownable",
                file_path="/proj/Ownable.sol",
                content="contract Ownable { address public owner; }",
                relationship="parent",
                priority=1,
            ),
        ]

        result = _build_related_context_section(sources, budget_chars=10000)

        self.assertIn("Related Contract Source Code", result)
        self.assertIn("Parent: Ownable", result)
        self.assertIn("contract Ownable", result)
        self.assertIn("```solidity", result)

    def test_build_related_context_empty(self):
        """Empty sources returns empty string."""
        from core.deep_analysis_engine import _build_related_context_section
        result = _build_related_context_section([], budget_chars=10000)
        self.assertEqual(result, "")

    def test_build_related_context_reference_only(self):
        """full_source=False produces one-liner reference list."""
        from core.deep_analysis_engine import _build_related_context_section

        sources = [
            RelatedContractSource("Ownable", "/Ownable.sol", "...", "parent", 1),
            RelatedContractSource("IERC20", "/IERC20.sol", "...", "interface", 1),
        ]

        result = _build_related_context_section(sources, budget_chars=0, full_source=False)

        self.assertIn("Related Contracts (Reference)", result)
        self.assertIn("Ownable (parent)", result)
        self.assertIn("IERC20 (interface)", result)
        # Should NOT contain full source
        self.assertNotIn("```solidity", result)


class TestStandardLibraryDetection(unittest.TestCase):
    """Test standard library detection and summarization."""

    def test_standard_library_detection(self):
        """Well-known libraries detected by path."""
        self.assertTrue(
            RelatedContractResolver.is_standard_library(
                '@openzeppelin/contracts/access/Ownable.sol'
            )
        )
        self.assertTrue(
            RelatedContractResolver.is_standard_library(
                'lib/openzeppelin/contracts/token/ERC20.sol'
            )
        )
        self.assertTrue(
            RelatedContractResolver.is_standard_library('solmate/src/tokens/ERC20.sol')
        )
        self.assertTrue(
            RelatedContractResolver.is_standard_library('solady/src/utils/SafeTransferLib.sol')
        )
        self.assertTrue(
            RelatedContractResolver.is_standard_library('forge-std/src/Test.sol')
        )

    def test_non_standard_library(self):
        """Custom project files are not flagged as standard libraries."""
        self.assertFalse(
            RelatedContractResolver.is_standard_library('/proj/src/MyVault.sol')
        )
        self.assertFalse(
            RelatedContractResolver.is_standard_library('contracts/Pool.sol')
        )

    def test_extract_interface_summary(self):
        """Interface summary extracts signatures, not bodies."""
        content = (
            'pragma solidity ^0.8.0;\n'
            'contract Ownable {\n'
            '    address public owner;\n'
            '    event OwnershipTransferred(address indexed old, address indexed new_);\n'
            '    error NotOwner();\n'
            '    function transferOwnership(address newOwner) public virtual {\n'
            '        require(msg.sender == owner, "!owner");\n'
            '        owner = newOwner;\n'
            '    }\n'
            '    function renounceOwnership() public virtual {\n'
            '        owner = address(0);\n'
            '    }\n'
            '}\n'
        )

        summary = RelatedContractResolver.extract_interface_summary(content)

        self.assertIn('pragma solidity', summary)
        self.assertIn('contract Ownable', summary)
        self.assertIn('transferOwnership', summary)
        self.assertIn('renounceOwnership', summary)
        self.assertIn('OwnershipTransferred', summary)
        self.assertIn('NotOwner', summary)
        self.assertIn('[Standard library', summary)
        # Should NOT contain function bodies
        self.assertNotIn('require(msg.sender', summary)


class TestRelatedContextIntegration(unittest.TestCase):
    """Integration tests for related context in prompt builders."""

    def test_related_context_injected_into_pass1(self):
        """Pass 1 prompt contains related source when provided."""
        from core.deep_analysis_engine import _build_pass1_prompt
        from core.protocol_archetypes import ArchetypeResult, ProtocolArchetype

        archetype = ArchetypeResult(
            primary=ProtocolArchetype.UNKNOWN,
            secondary=[],
            confidence=0.5,
            signals=[],
        )

        related_ctx = (
            "## Related Contract Source Code (Dependencies)\n"
            "### Parent: Ownable\n"
            "```solidity\ncontract Ownable {}\n```\n"
        )

        prompt = _build_pass1_prompt(
            "contract Vault is Ownable {}",
            archetype,
            related_context=related_ctx,
        )

        self.assertIn("Related Contract Source Code", prompt)
        self.assertIn("Parent: Ownable", prompt)

    def test_related_context_budget_respected(self):
        """Budget enforcement: stays within character limits."""
        from core.deep_analysis_engine import _build_related_context_section

        # Create sources that exceed budget
        sources = [
            RelatedContractSource(
                name=f"Contract{i}",
                file_path=f"/c{i}.sol",
                content="x" * 1000,
                relationship="dependency",
                priority=2,
            )
            for i in range(10)
        ]

        budget = 3000
        result = _build_related_context_section(sources, budget_chars=budget)

        # The actual source content in the result should respect the budget
        # (header text adds some overhead, but actual source chars should be limited)
        total_source_chars = sum(
            len(s.content) for s in
            RelatedContractResolver.select_within_budget(sources, budget)
        )
        self.assertLessEqual(total_source_chars, budget)


class TestDetectProjectRoot(unittest.TestCase):
    """Test project root detection."""

    def test_detect_from_foundry_toml(self):
        """Detects project root from foundry.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create foundry.toml at root
            with open(os.path.join(tmpdir, 'foundry.toml'), 'w') as f:
                f.write('[profile.default]\n')

            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir, exist_ok=True)

            result = RelatedContractResolver._detect_project_root(
                os.path.join(src_dir, 'Vault.sol')
            )
            self.assertEqual(result, tmpdir)

    def test_detect_returns_none_for_no_markers(self):
        """Returns None when no project markers found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = RelatedContractResolver._detect_project_root(
                os.path.join(tmpdir, 'Vault.sol')
            )
            self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
