"""
YAML-based flow execution engine for AetherAudit + AetherFuzz.
"""

import asyncio
import importlib
import yaml
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from utils.file_handler import FileHandler


@dataclass
class NodeResult:
    """Result from a node execution."""
    node_name: str
    success: bool
    data: Any
    error: Optional[str] = None
    execution_time: Optional[float] = None


@dataclass
class Decision:
    """Decision configuration for conditional flow execution."""
    condition: str
    then_branch: List[str]
    else_branch: Optional[List[str]] = None


class BaseNode(ABC):
    """Abstract base class for all workflow nodes."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute the node with given context."""
        pass


class DecisionNode(BaseNode):
    """Node for conditional branching in workflows."""

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        # Handle both single decision dict and list of decisions
        decisions_config = config.get('decisions', [config])
        if isinstance(decisions_config, dict):
            decisions_config = [decisions_config]
        self.decisions = [
            Decision(**decision_config)
            for decision_config in decisions_config
        ]

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Execute decision logic and determine next nodes."""
        try:
            for decision in self.decisions:
                # Simple condition evaluation (can be extended)
                if self._evaluate_condition(decision.condition, context):
                    return NodeResult(
                        node_name=self.name,
                        success=True,
                        data={'next_nodes': decision.then_branch}
                    )

            # If no conditions match and there's an else branch
            if self.decisions and self.decisions[0].else_branch:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={'next_nodes': self.decisions[0].else_branch}
                )

            return NodeResult(
                node_name=self.name,
                success=True,
                data={'next_nodes': []}
            )
        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a simple condition string."""
        # Simple condition parser - can be extended for complex expressions
        if '==' in condition:
            var, value = condition.split('==', 1)
            var = var.strip()
            value = value.strip().strip('"\'')
            return str(context.get(var)) == value
        elif '>' in condition:
            var, value = condition.split('>', 1)
            var = var.strip()
            value = value.strip()
            try:
                return float(context.get(var, 0)) > float(value)
            except ValueError:
                return False
        elif '<' in condition:
            var, value = condition.split('<', 1)
            var = var.strip()
            value = value.strip()
            try:
                return float(context.get(var, 0)) < float(value)
            except ValueError:
                return False
        return False


class FileReaderNode(BaseNode):
    """Node for reading smart contract files."""

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Read contract files and extract metadata."""
        try:
            file_handler = FileHandler()
            contract_path = context.get('contract_path')

            if not contract_path:
                return NodeResult(
                    node_name=self.name,
                    success=False,
                    data=None,
                    error="No contract path provided in context"
                )

            # Read contract files
            files_data = file_handler.read_contract_files(contract_path)

            # Update context with file data
            context.update({
                'contract_files': files_data,
                'contract_count': len(files_data),
                'total_lines': sum(len(content.split('\n')) for _, content in files_data)
            })

            return NodeResult(
                node_name=self.name,
                success=True,
                data={'files': files_data}
            )
        except Exception as e:
            return NodeResult(
                node_name=self.name,
                success=False,
                data=None,
                error=str(e)
            )


class FlowExecutor:
    """Main flow execution engine."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.node_registry = {
            'DecisionNode': DecisionNode,
            'FileReaderNode': FileReaderNode,
        }
        self._register_core_nodes()

    def _register_core_nodes(self):
        """Register core node types."""
        print("🔧 Registering core nodes...")

        # Import and register audit nodes
        try:
            from core.nodes.audit_nodes import (
                StaticAnalysisNode, LLMAnalysisNode,
                FixGeneratorNode, ValidationNode, ReportNode
            )
            self.node_registry.update({
                'StaticAnalysisNode': StaticAnalysisNode,
                'LLMAnalysisNode': LLMAnalysisNode,
                'FixGeneratorNode': FixGeneratorNode,
                'ValidationNode': ValidationNode,
                'ReportNode': ReportNode,
            })
            print(f"✅ Registered audit nodes: {list(self.node_registry.keys())}")
        except ImportError as e:
            print(f"❌ Failed to import audit nodes: {e}")
            if self.verbose:
                print("Warning: Audit nodes not available yet")

        # Import and register enhanced exploitability node
        try:
            from core.nodes.enhanced_exploitability_node import EnhancedExploitabilityNode
            self.node_registry.update({
                'EnhancedExploitabilityNode': EnhancedExploitabilityNode
            })
            print(f"✅ Registered enhanced exploitability node")
        except ImportError as e:
            print(f"❌ Failed to import enhanced exploitability node: {e}")
            if self.verbose:
                print("Warning: Enhanced exploitability node not available yet")

        # Import and register fuzz nodes
        try:
            from core.nodes.fuzz_nodes import (
                AnalyzerNode, SeedGeneratorNode, FuzzExecutorNode,
                RewardEngineNode, LLMReasonerNode, ExploitValidatorNode, AetherFuzzRunner
            )
            self.node_registry.update({
                'AnalyzerNode': AnalyzerNode,
                'SeedGeneratorNode': SeedGeneratorNode,
                'FuzzExecutorNode': FuzzExecutorNode,
                'RewardEngineNode': RewardEngineNode,
                'LLMReasonerNode': LLMReasonerNode,
                'ExploitValidatorNode': ExploitValidatorNode,
                'AetherFuzzRunner': AetherFuzzRunner,
            })
        except ImportError:
            pass
            if self.verbose:
                print("Warning: Fuzz nodes not available yet")

    async def execute_pipeline(
        self,
        contract_path: str,
        flow_config: Dict[str, Any],
        end_to_end: bool = False,
        enhanced: bool = False
    ) -> Dict[str, Any]:
        """Execute the complete pipeline."""
        print("🚀 Starting pipeline execution...")

        context = {
            'contract_path': contract_path,
            'end_to_end': end_to_end,
            'enhanced_mode': enhanced,
            'start_time': asyncio.get_event_loop().time(),
            'results': {
                'audit': {},
                'fuzz': {},
                'fixes': [],
                'validation': {}
            }
        }

        # Execute flow steps
        flow_steps = flow_config.get('flow', [])
        print(f"📋 Flow steps: {[step if isinstance(step, str) else 'complex' for step in flow_steps]}")
        current_step = 0

        while current_step < len(flow_steps):
            step = flow_steps[current_step]

            print(f"📋 Processing step {current_step}: {type(step)} - {step}")

            if isinstance(step, str):
                # Simple node execution
                node_result = await self._execute_node(step, context)
                if not node_result.success:
                    print(f"❌ Node '{step}' failed: {node_result.error}")
                    break
                current_step += 1  # Move to next step

            elif isinstance(step, dict):
                # Handle YAML structure like {"node": "NodeName"} or {"decision": {...}}
                if 'node' in step:
                    node_name = step['node']
                    print(f"🔧 Executing node from dict: {node_name}")
                    node_result = await self._execute_node(node_name, context)
                    if not node_result.success:
                        print(f"❌ Node '{node_name}' failed: {node_result.error}")
                        break
                    current_step += 1  # Move to next step
                elif 'decision' in step:
                    print(f"🔀 Processing decision: {step['decision']}")
                    decision_result = await self._execute_decision(step['decision'], context)
                    if decision_result.success:
                        next_nodes = decision_result.data.get('next_nodes', [])
                        print(f"🔀 Decision result: next_nodes = {next_nodes}")
                        # Execute the nodes in the decision branch inline
                        if next_nodes:
                            for next_node in next_nodes:
                                if isinstance(next_node, dict) and 'node' in next_node:
                                    node_name = next_node['node']
                                    print(f"🔧 Executing decision node: {node_name}")
                                    node_result = await self._execute_node(node_name, context)
                                    if not node_result.success:
                                        print(f"❌ Decision node '{node_name}' failed: {node_result.error}")
                                        break
                        current_step += 1  # Move past the decision after executing its branch
                    else:
                        print(f"❌ Decision failed: {decision_result.error}")
                        break
                else:
                    print(f"⚠️  Unknown dict structure in flow: {step}")
                    current_step += 1
            else:
                print(f"⚠️  Unknown step type: {type(step)} - {step}")
                current_step += 1

        # Calculate execution time
        end_time = asyncio.get_event_loop().time()
        context['execution_time'] = end_time - context['start_time']

        print(f"DEBUG: Flow execution returning results with keys: {list(context['results'].keys())}")
        return context['results']

    async def _execute_node(self, node_name: str, context: Dict[str, Any]) -> NodeResult:
        """Execute a single node."""
        print(f"🔧 Executing node: {node_name}")

        try:
            # Parse node configuration from context or use defaults
            node_config = context.get('node_configs', {}).get(node_name, {})

            # Create node instance
            if node_name not in self.node_registry:
                return NodeResult(
                    node_name=node_name,
                    success=False,
                    data=None,
                    error=f"Unknown node type: {node_name}"
                )

            node_class = self.node_registry[node_name]
            node = node_class(node_name, node_config)

            if self.verbose:
                print(f"🔧 Executing node: {node_name}")

            # Execute node
            result = await node.execute(context)

            # Store result in context
            if result.success:
                context['results'][node_name.lower()] = result.data
                context[f'last_{node_name.lower()}_result'] = result.data

            return result

        except Exception as e:
            return NodeResult(
                node_name=node_name,
                success=False,
                data=None,
                error=str(e)
            )

    async def _execute_decision(self, decision_config: Dict[str, Any], context: Dict[str, Any]) -> NodeResult:
        """Execute a decision node."""
        try:
            decision_node = DecisionNode("decision", decision_config)
            return await decision_node.execute(context)
        except Exception as e:
            return NodeResult(
                node_name="decision",
                success=False,
                data=None,
                error=str(e)
            )
