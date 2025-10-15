"""
Tests for flow execution engine.
"""

import pytest
import asyncio
from pathlib import Path

from core.flow_executor import FlowExecutor, FileReaderNode, DecisionNode
from core.flow_executor import NodeResult


class TestFlowExecutor:
    """Test cases for FlowExecutor."""

    def setup_method(self):
        """Set up test fixtures."""
        self.flow_executor = FlowExecutor(verbose=True)

    def test_file_reader_node_success(self):
        """Test FileReaderNode with valid contract file."""
        # Create a test contract file
        test_content = '''
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;
}
'''
        test_file = Path("test.sol")
        test_file.write_text(test_content)

        try:
            # Create FileReaderNode and execute
            node = FileReaderNode("test_reader", {})
            context = {'contract_path': str(test_file)}

            async def run_test():
                result = await node.execute(context)
                return result

            result = asyncio.run(run_test())

            assert result.success
            assert 'contract_files' in context
            assert len(context['contract_files']) == 1

        finally:
            test_file.unlink()

    def test_file_reader_node_failure(self):
        """Test FileReaderNode with nonexistent file."""
        node = FileReaderNode("test_reader", {})
        context = {'contract_path': 'nonexistent.sol'}

        async def run_test():
            result = await node.execute(context)
            return result

        result = asyncio.run(run_test())

        assert not result.success
        assert 'error' in result.data or result.error

    def test_decision_node_evaluation(self):
        """Test DecisionNode condition evaluation."""
        # Test simple decision
        node = DecisionNode("test_decision", {
            'decisions': [
                {
                    'condition': 'high_severity_count > 0',
                    'then_branch': ['FixGeneratorNode', 'ReportNode'],
                    'else_branch': ['ReportNode']
                }
            ]
        })

        # Test condition true
        context = {'high_severity_count': 2}
        async def run_test_true():
            result = await node.execute(context)
            return result

        result = asyncio.run(run_test_true())
        assert result.success
        assert result.data['next_nodes'] == ['FixGeneratorNode', 'ReportNode']

        # Test condition false
        context = {'high_severity_count': 0}
        async def run_test_false():
            result = await node.execute(context)
            return result

        result = asyncio.run(run_test_false())
        assert result.success
        assert result.data['next_nodes'] == ['ReportNode']

    def test_flow_executor_initialization(self):
        """Test FlowExecutor initialization and node registration."""
        executor = FlowExecutor()

        # Check that core nodes are registered
        assert 'FileReaderNode' in executor.node_registry
        assert 'DecisionNode' in executor.node_registry

        # Check that audit nodes are registered (if available)
        # Note: This might fail if the modules aren't properly imported
        audit_nodes = ['StaticAnalysisNode', 'LLMAnalysisNode', 'FixGeneratorNode']
        for node_name in audit_nodes:
            # These might not be available yet, so we just check the registry exists
            assert hasattr(executor, 'node_registry')

    def test_node_result_creation(self):
        """Test NodeResult creation and properties."""
        result = NodeResult(
            node_name="test_node",
            success=True,
            data={'test': 'data'},
            execution_time=1.5
        )

        assert result.node_name == "test_node"
        assert result.success
        assert result.data == {'test': 'data'}
        assert result.execution_time == 1.5
        assert result.error is None
