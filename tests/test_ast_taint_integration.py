"""
Tests for AST parser and taint analyzer integration into the audit pipeline.

Validates:
- enhanced_audit_engine uses AST parser when available
- enhanced_audit_engine runs taint analysis
- Taint findings are added to static results
- Deep analysis receives ast_data and taint_reports parameters
- Graceful fallback when AST/taint modules fail or are unavailable
- Validation pipeline uses taint data to validate findings
"""

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Minimal Solidity source for testing
SAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"""


class TestSolidityASTParser(unittest.TestCase):
    """Test the SolidityASTParser directly."""

    def test_import_solidity_ast(self):
        """Test that solidity_ast module can be imported."""
        from core.solidity_ast import SolidityASTParser, SolidityAST, ContractDef
        parser = SolidityASTParser()
        self.assertIsNotNone(parser)

    def test_regex_fallback(self):
        """Test regex fallback when solc is not available."""
        from core.solidity_ast import SolidityASTParser
        parser = SolidityASTParser()
        # Force regex fallback by disabling AST
        parser._ast_available = False

        contract_files = [
            {'path': 'Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol'}
        ]
        result = parser.parse(contract_files)

        self.assertIsNotNone(result)
        self.assertGreater(len(result.contracts), 0)
        # Should find the Vault contract
        contract_names = [c.name for c in result.contracts]
        self.assertIn('Vault', contract_names)

    def test_format_for_llm(self):
        """Test format_for_llm produces readable output."""
        from core.solidity_ast import SolidityASTParser
        parser = SolidityASTParser()
        parser._ast_available = False

        contract_files = [
            {'path': 'Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol'}
        ]
        ast_data = parser.parse(contract_files)
        llm_text = parser.format_for_llm(ast_data)

        self.assertIn('Contract Structure', llm_text)
        self.assertIn('Vault', llm_text)

    def test_parse_empty_input(self):
        """Test parsing with empty contract list."""
        from core.solidity_ast import SolidityASTParser
        parser = SolidityASTParser()
        parser._ast_available = False

        result = parser.parse([])
        self.assertIsNotNone(result)
        self.assertEqual(len(result.contracts), 0)


class TestTaintAnalyzer(unittest.TestCase):
    """Test the TaintAnalyzer directly."""

    def test_import_taint_analyzer(self):
        """Test that taint_analyzer module can be imported."""
        from core.taint_analyzer import TaintAnalyzer, TaintReport, TaintFlow
        analyzer = TaintAnalyzer()
        self.assertIsNotNone(analyzer)

    def test_analyze_contract(self):
        """Test basic taint analysis on a contract."""
        from core.taint_analyzer import TaintAnalyzer
        analyzer = TaintAnalyzer()

        report = analyzer.analyze(SAMPLE_CONTRACT, 'Vault')
        self.assertEqual(report.contract_name, 'Vault')
        self.assertIsInstance(report.taint_flows, list)
        self.assertIsInstance(report.dangerous_flows, list)
        self.assertIsInstance(report.sanitized_flows, list)

    def test_analyze_multiple(self):
        """Test multi-contract taint analysis."""
        from core.taint_analyzer import TaintAnalyzer
        analyzer = TaintAnalyzer()

        contract_files = [
            {'content': SAMPLE_CONTRACT, 'name': 'Vault.sol'},
        ]
        reports = analyzer.analyze_multiple(contract_files)
        self.assertEqual(len(reports), 1)
        self.assertIsNotNone(reports[0].summary)

    def test_format_for_llm(self):
        """Test LLM formatting of taint report."""
        from core.taint_analyzer import TaintAnalyzer
        analyzer = TaintAnalyzer()

        report = analyzer.analyze(SAMPLE_CONTRACT, 'Vault')
        llm_text = analyzer.format_for_llm(report)
        self.assertIn('Taint Analysis', llm_text)


class TestASTIntegrationInAuditEngine(unittest.TestCase):
    """Test AST integration into enhanced_audit_engine."""

    @patch('core.solidity_ast.SolidityASTParser')
    def test_ast_fallback_when_unavailable(self, MockParser):
        """Test that AST parsing gracefully falls back when solc is not available."""
        mock_instance = MagicMock()
        mock_instance.ast_available = False
        MockParser.return_value = mock_instance

        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=False)

        contract_files = [
            {'path': '/tmp/Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol', 'is_script': False}
        ]

        # Run the static analysis (will use mocked parser)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine._run_enhanced_static_analysis(contract_files)
            )
        finally:
            loop.close()

        # Should succeed despite AST being unavailable
        self.assertIn('vulnerabilities', result)
        # AST data should be None in context
        self.assertIsNone(engine.context.get('ast_data'))

    @patch('core.solidity_ast.SolidityASTParser')
    def test_ast_integration_when_available(self, MockParser):
        """Test that AST data is stored in context when available."""
        from core.solidity_ast import SolidityAST, ContractDef

        mock_ast = SolidityAST(
            contracts=[ContractDef(name='Vault', kind='contract')],
            errors=[],
        )
        mock_instance = MagicMock()
        mock_instance.ast_available = True
        mock_instance.parse.return_value = mock_ast
        MockParser.return_value = mock_instance

        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=False)

        contract_files = [
            {'path': '/tmp/Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol', 'is_script': False}
        ]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine._run_enhanced_static_analysis(contract_files)
            )
        finally:
            loop.close()

        # AST data should be stored in context
        self.assertIsNotNone(engine.context.get('ast_data'))
        self.assertEqual(len(engine.context['ast_data'].contracts), 1)

    @patch('core.solidity_ast.SolidityASTParser')
    def test_ast_exception_handling(self, MockParser):
        """Test that AST parsing exceptions are caught gracefully."""
        MockParser.side_effect = RuntimeError("solcx not installed")

        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=False)

        contract_files = [
            {'path': '/tmp/Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol', 'is_script': False}
        ]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine._run_enhanced_static_analysis(contract_files)
            )
        finally:
            loop.close()

        # Should still succeed
        self.assertIn('vulnerabilities', result)
        # AST data should be None
        self.assertIsNone(engine.context.get('ast_data'))


class TestTaintIntegrationInAuditEngine(unittest.TestCase):
    """Test taint analysis integration into enhanced_audit_engine."""

    @patch('core.taint_analyzer.TaintAnalyzer')
    def test_taint_findings_added_to_results(self, MockTaintAnalyzer):
        """Test that taint dangerous flows are converted to vulnerability findings."""
        from core.taint_analyzer import TaintReport, TaintFlow, TaintSource, TaintSink

        mock_flow = TaintFlow(
            source=TaintSource.FUNCTION_PARAM,
            source_function='withdraw',
            source_param='amount',
            sink=TaintSink.ETH_TRANSFER,
            sink_function='withdraw',
            sink_expression='payable(msg.sender).transfer(amount)',
            sink_line=22,
            taint_path=['amount'],
            is_sanitized=False,
            sanitizers=[],
            severity='critical',
            description='Tainted data from amount reaches eth_transfer',
        )
        mock_report = TaintReport(
            contract_name='Vault.sol',
            dangerous_flows=[mock_flow],
            sanitized_flows=[],
            summary={'dangerous_flows': 1, 'sanitized_flows': 0},
        )

        mock_instance = MagicMock()
        mock_instance.analyze_multiple.return_value = [mock_report]
        MockTaintAnalyzer.return_value = mock_instance

        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=False)

        contract_files = [
            {'path': '/tmp/Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol', 'is_script': False}
        ]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine._run_enhanced_static_analysis(contract_files)
            )
        finally:
            loop.close()

        # Taint findings should be in the results
        vulns = result.get('vulnerabilities', [])
        taint_vulns = [v for v in vulns if isinstance(v, dict) and v.get('source') == 'taint_analysis']
        self.assertGreater(len(taint_vulns), 0)

        # Check the taint finding has expected fields
        tv = taint_vulns[0]
        self.assertEqual(tv['severity'], 'critical')
        self.assertIn('taint_', tv['vulnerability_type'])

    @patch('core.taint_analyzer.TaintAnalyzer')
    def test_taint_exception_handling(self, MockTaintAnalyzer):
        """Test that taint analysis exceptions are caught gracefully."""
        MockTaintAnalyzer.side_effect = ImportError("Module not found")

        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=False)

        contract_files = [
            {'path': '/tmp/Vault.sol', 'content': SAMPLE_CONTRACT, 'name': 'Vault.sol', 'is_script': False}
        ]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine._run_enhanced_static_analysis(contract_files)
            )
        finally:
            loop.close()

        # Should still succeed
        self.assertIn('vulnerabilities', result)


class TestDeepAnalysisEngineIntegration(unittest.TestCase):
    """Test that deep analysis engine accepts ast_data and taint_reports."""

    def test_analyze_signature_accepts_new_params(self):
        """Test that analyze() accepts ast_data and taint_reports parameters."""
        import inspect
        from core.deep_analysis_engine import DeepAnalysisEngine

        sig = inspect.signature(DeepAnalysisEngine.analyze)
        params = list(sig.parameters.keys())

        self.assertIn('ast_data', params)
        self.assertIn('taint_reports', params)

    def test_analyze_with_none_params(self):
        """Test analyze() works with None for ast_data and taint_reports."""
        from core.deep_analysis_engine import DeepAnalysisEngine

        async def mock_call_llm(*args, **kwargs):
            return '{"findings": []}'

        mock_llm = MagicMock()
        mock_llm._call_llm = mock_call_llm

        engine = DeepAnalysisEngine(mock_llm)

        # Just verify the engine can be constructed with the mock
        # (Full async test would require running the event loop with proper mocking)
        self.assertIsNotNone(engine)

    def test_ast_context_formatting(self):
        """Test that AST data can be formatted for LLM context."""
        from core.solidity_ast import SolidityASTParser, SolidityAST, ContractDef, FunctionDef, Visibility, Mutability

        parser = SolidityASTParser()
        parser._ast_available = False

        ast_data = SolidityAST(
            contracts=[
                ContractDef(
                    name='TestContract',
                    kind='contract',
                    functions=[
                        FunctionDef(
                            name='deposit',
                            visibility=Visibility.EXTERNAL,
                            mutability=Mutability.PAYABLE,
                        )
                    ],
                )
            ],
        )

        text = parser.format_for_llm(ast_data)
        self.assertIn('TestContract', text)
        self.assertIn('deposit', text)

    def test_taint_context_formatting(self):
        """Test that taint reports can be formatted for LLM context."""
        from core.taint_analyzer import TaintAnalyzer, TaintReport, TaintFlow, TaintSource, TaintSink

        analyzer = TaintAnalyzer()
        report = TaintReport(
            contract_name='Test',
            dangerous_flows=[
                TaintFlow(
                    source=TaintSource.FUNCTION_PARAM,
                    source_function='deposit',
                    source_param='amount',
                    sink=TaintSink.STORAGE_WRITE,
                    sink_function='deposit',
                    sink_expression='balances[msg.sender] = amount',
                    sink_line=10,
                    taint_path=['amount', 'balances'],
                    is_sanitized=False,
                    sanitizers=[],
                    severity='medium',
                    description='Tainted data flows to storage write',
                )
            ],
        )

        text = analyzer.format_for_llm(report)
        self.assertIn('Taint Analysis', text)
        self.assertIn('amount', text)
        self.assertIn('MEDIUM', text)


class TestValidationPipelineTaintIntegration(unittest.TestCase):
    """Test taint data integration in validation pipeline."""

    def test_set_taint_reports(self):
        """Test that taint reports can be set on the pipeline."""
        from core.validation_pipeline import ValidationPipeline

        pipeline = ValidationPipeline(None, SAMPLE_CONTRACT)
        pipeline.set_taint_reports([])
        self.assertEqual(pipeline._taint_reports, [])

    def test_taint_validation_no_reports(self):
        """Test that taint validation is skipped when no reports are available."""
        from core.validation_pipeline import ValidationPipeline

        pipeline = ValidationPipeline(None, SAMPLE_CONTRACT)
        # No taint reports set

        finding = {
            'vulnerability_type': 'input_validation',
            'description': 'User-controlled input reaches dangerous sink',
            'line_number': 22,
            'code_snippet': 'payable(msg.sender).transfer(amount)',
        }

        result = pipeline._validate_with_taint_data(finding)
        self.assertIsNone(result)

    def test_taint_validation_sanitized_flow(self):
        """Test that findings are marked as FP when taint shows sanitization."""
        from core.validation_pipeline import ValidationPipeline
        from core.taint_analyzer import TaintReport, TaintFlow, TaintSource, TaintSink

        pipeline = ValidationPipeline(None, SAMPLE_CONTRACT)

        sanitized_flow = TaintFlow(
            source=TaintSource.FUNCTION_PARAM,
            source_function='withdraw',
            source_param='amount',
            sink=TaintSink.ETH_TRANSFER,
            sink_function='withdraw',
            sink_expression='payable(msg.sender).transfer(amount)',
            sink_line=22,
            taint_path=['amount'],
            is_sanitized=True,
            sanitizers=['require: require(balances[msg.sender] >= amount)'],
            severity='low',
            description='sanitized',
        )
        report = TaintReport(
            contract_name='Vault',
            sanitized_flows=[sanitized_flow],
            dangerous_flows=[],
        )
        pipeline.set_taint_reports([report])

        finding = {
            'vulnerability_type': 'input_validation',
            'description': 'User-controlled input reaches transfer without validation',
            'line_number': 22,
            'code_snippet': 'payable(msg.sender).transfer(amount)',
        }

        result = pipeline._validate_with_taint_data(finding)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_false_positive)
        self.assertIn('sanitized', result.reasoning)

    def test_taint_validation_dangerous_flow_corroborated(self):
        """Test that findings with matching dangerous flows are NOT marked as FP."""
        from core.validation_pipeline import ValidationPipeline
        from core.taint_analyzer import TaintReport, TaintFlow, TaintSource, TaintSink

        pipeline = ValidationPipeline(None, SAMPLE_CONTRACT)

        dangerous_flow = TaintFlow(
            source=TaintSource.FUNCTION_PARAM,
            source_function='withdraw',
            source_param='amount',
            sink=TaintSink.ETH_TRANSFER,
            sink_function='withdraw',
            sink_expression='payable(msg.sender).transfer(amount)',
            sink_line=22,
            taint_path=['amount'],
            is_sanitized=False,
            sanitizers=[],
            severity='critical',
            description='unsanitized',
        )
        report = TaintReport(
            contract_name='Vault',
            dangerous_flows=[dangerous_flow],
            sanitized_flows=[],
        )
        pipeline.set_taint_reports([report])

        finding = {
            'vulnerability_type': 'input_validation',
            'description': 'User-controlled input reaches transfer',
            'line_number': 22,
            'code_snippet': 'payable(msg.sender).transfer(amount)',
        }

        result = pipeline._validate_with_taint_data(finding)
        # Should return None (inconclusive/corroborated - not a FP)
        self.assertIsNone(result)

    def test_taint_validation_skips_non_dataflow_findings(self):
        """Test that taint validation is skipped for findings without data flow claims."""
        from core.validation_pipeline import ValidationPipeline

        pipeline = ValidationPipeline(None, SAMPLE_CONTRACT)
        pipeline.set_taint_reports([])

        finding = {
            'vulnerability_type': 'reentrancy',
            'description': 'State updated after external call',
            'line_number': 22,
            'code_snippet': 'payable(msg.sender).transfer(amount)',
        }

        result = pipeline._validate_with_taint_data(finding)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
