"""
Test suite for the Taint Analysis Engine.

Tests cover:
- Source identification (function params, implicit sources, external call returns)
- Taint propagation (direct assignment, arithmetic, storage, ternary)
- Sanitizer detection (require, if-revert, clamping, access control)
- Sink detection (external calls, delegatecall, selfdestruct, etc.)
- Severity calculation
- Cross-contract taint tracking
- LLM format output
- False positive avoidance
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.taint_analyzer import (
    TaintAnalyzer,
    TaintSource,
    TaintSink,
    TaintedVariable,
    TaintFlow,
    TaintReport,
)


class TestSourceIdentification(unittest.TestCase):
    """Test taint source identification."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_external_function_params_are_sources(self):
        """External function parameters are taint sources."""
        contract = """
        contract Token {
            function transfer(address to, uint256 amount) external {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Token")
        param_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.FUNCTION_PARAM.value
        ]
        param_names = [s.get('parameter', '') for s in param_sources]
        self.assertIn('to', param_names)
        self.assertIn('amount', param_names)

    def test_public_function_params_are_sources(self):
        """Public function parameters are taint sources."""
        contract = """
        contract Token {
            function approve(address spender, uint256 value) public returns (bool) {
                allowances[msg.sender][spender] = value;
                return true;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Token")
        param_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.FUNCTION_PARAM.value
        ]
        param_names = [s.get('parameter', '') for s in param_sources]
        self.assertIn('spender', param_names)
        self.assertIn('value', param_names)

    def test_private_function_params_are_not_sources(self):
        """Private function parameters are NOT taint sources."""
        contract = """
        contract Token {
            function _transfer(address from, address to, uint256 amount) private {
                balances[from] -= amount;
                balances[to] += amount;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Token")
        param_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.FUNCTION_PARAM.value
        ]
        # _transfer is private, so its params should not be listed as sources
        param_funcs = [s.get('function', '') for s in param_sources]
        self.assertNotIn('_transfer', param_funcs)

    def test_internal_function_params_are_not_sources(self):
        """Internal function parameters are NOT taint sources."""
        contract = """
        contract Token {
            function _mint(address account, uint256 amount) internal {
                totalSupply += amount;
                balances[account] += amount;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Token")
        param_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.FUNCTION_PARAM.value
        ]
        param_funcs = [s.get('function', '') for s in param_sources]
        self.assertNotIn('_mint', param_funcs)

    def test_msg_sender_is_source(self):
        """msg.sender is an implicit taint source."""
        contract = """
        contract Token {
            function getBalance() external view returns (uint256) {
                return balances[msg.sender];
            }
        }
        """
        report = self.analyzer.analyze(contract, "Token")
        implicit_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.MSG_SENDER.value
        ]
        self.assertGreater(len(implicit_sources), 0)

    def test_msg_value_is_source(self):
        """msg.value is an implicit taint source."""
        contract = """
        contract Vault {
            function deposit() external payable {
                balances[msg.sender] += msg.value;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Vault")
        implicit_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.MSG_VALUE.value
        ]
        self.assertGreater(len(implicit_sources), 0)

    def test_block_timestamp_is_source(self):
        """block.timestamp is an implicit taint source."""
        contract = """
        contract TimeLock {
            function lock() external {
                lockTime[msg.sender] = block.timestamp + 1 days;
            }
        }
        """
        report = self.analyzer.analyze(contract, "TimeLock")
        implicit_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.BLOCK_TIMESTAMP.value
        ]
        self.assertGreater(len(implicit_sources), 0)

    def test_tx_origin_is_source(self):
        """tx.origin is an implicit taint source."""
        contract = """
        contract Auth {
            function checkOrigin() external view returns (address) {
                return tx.origin;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Auth")
        implicit_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.TX_ORIGIN.value
        ]
        self.assertGreater(len(implicit_sources), 0)

    def test_external_call_return_is_source(self):
        """Return values from external calls are taint sources."""
        contract = """
        contract PriceFeed {
            function getPrice() external returns (uint256) {
                uint256 price = oracle.latestAnswer();
                return price;
            }
        }
        """
        report = self.analyzer.analyze(contract, "PriceFeed")
        ext_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.EXTERNAL_CALL_RETURN.value
        ]
        self.assertGreater(len(ext_sources), 0)


class TestTaintPropagation(unittest.TestCase):
    """Test taint propagation through code."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_direct_assignment_propagates_taint(self):
        """Taint propagates through direct assignment."""
        contract = """
        contract Vault {
            mapping(address => uint256) public balances;
            uint256 public totalAssets;
            uint256 public totalSupply;
            function deposit(uint256 amount) external {
                uint256 shares = amount * totalSupply / totalAssets;
                balances[msg.sender] += shares;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Vault")
        # amount should taint shares, which should taint balances via +=
        amount_flows = [
            f for f in report.taint_flows if f.source_param == 'amount'
        ]
        self.assertGreater(len(amount_flows), 0,
                           "amount should generate at least one taint flow")
        # Check that shares appears in propagation path
        has_shares = any('shares' in path for f in amount_flows for path in f.taint_path)
        self.assertTrue(has_shares, "shares should be in taint path from amount")

    def test_arithmetic_propagates_taint(self):
        """Taint propagates through arithmetic operations."""
        contract = """
        contract Calc {
            uint256 public result;
            function compute(uint256 x) external {
                uint256 y = x + 10;
                uint256 z = y * 2;
                result = z;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Calc")
        # x taints y, y taints z, z written to state
        x_flows = [f for f in report.taint_flows if f.source_param == 'x']
        self.assertGreater(len(x_flows), 0,
                           "x should generate taint flows")
        path_vars = set()
        for f in x_flows:
            path_vars.update(f.taint_path)
        self.assertIn('y', path_vars, "y should be tainted from x")

    def test_compound_assignment_propagates_taint(self):
        """Taint propagates through compound assignment (+=, -= etc.)."""
        contract = """
        contract Accum {
            uint256 public total;
            function add(uint256 amount) external {
                total += amount;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Accum")
        # total should become tainted through += amount (storage write sink)
        amount_flows = [
            f for f in report.taint_flows if f.source_param == 'amount'
        ]
        self.assertGreater(len(amount_flows), 0,
                           "amount should generate taint flows via += storage write")

    def test_mapping_write_propagates_taint(self):
        """Taint propagates through mapping writes."""
        contract = """
        contract Registry {
            mapping(address => uint256) public data;
            function set(address key, uint256 val) external {
                data[key] = val;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Registry")
        # Both key and val taint the mapping
        all_flows = report.taint_flows
        key_flows = [f for f in all_flows if f.source_param == 'key']
        val_flows = [f for f in all_flows if f.source_param == 'val']
        self.assertGreater(len(key_flows) + len(val_flows), 0,
                           "Mapping write should generate taint flows")

    def test_ternary_propagates_taint(self):
        """Taint propagates through ternary expressions."""
        contract = """
        contract Chooser {
            uint256 public stored;
            function choose(uint256 x, bool flag) external {
                uint256 result = flag ? x : 0;
                stored = result;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Chooser")
        # result should be tainted from x (appears in ternary branch)
        x_flows = [f for f in report.taint_flows if f.source_param == 'x']
        self.assertGreater(len(x_flows), 0,
                           "x should generate taint flows")
        path_vars = set()
        for f in x_flows:
            path_vars.update(f.taint_path)
        self.assertIn('result', path_vars,
                       "result should be tainted from x via ternary")


class TestSanitizerDetection(unittest.TestCase):
    """Test sanitizer detection between source and sink."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_require_bounds_check_is_sanitizer(self):
        """require(amount > 0 && amount <= max) is a sanitizer."""
        contract = """
        contract Vault {
            mapping(address => uint256) public balances;
            IERC20 public token;
            function withdraw(uint256 amount) external {
                require(amount > 0 && amount <= balances[msg.sender], "invalid");
                balances[msg.sender] -= amount;
                token.transfer(msg.sender, amount);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Vault")
        amount_flows = [
            f for f in report.taint_flows if f.source_param == 'amount'
        ]
        # At least some flows for amount should be sanitized
        sanitized = [f for f in amount_flows if f.is_sanitized]
        self.assertGreater(len(sanitized), 0,
                           "amount should be sanitized by require check")

    def test_only_owner_is_sanitizer(self):
        """onlyOwner modifier is a sanitizer for access control."""
        contract = """
        contract Admin {
            uint256 public fee;
            uint256 public constant MAX_FEE = 1000;
            function setFee(uint256 newFee) external onlyOwner {
                require(newFee <= MAX_FEE);
                fee = newFee;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Admin")
        fee_flows = [
            f for f in report.taint_flows if f.source_param == 'newFee'
        ]
        # newFee should be sanitized (bounds check + onlyOwner)
        sanitized = [f for f in fee_flows if f.is_sanitized]
        self.assertGreater(len(sanitized), 0,
                           "newFee should be sanitized by require + onlyOwner")

    def test_conditional_revert_is_sanitizer(self):
        """if (cond) revert is a sanitizer."""
        contract = """
        contract Guard {
            function process(uint256 amount) external {
                if (amount == 0) revert("zero");
                uint256 result = 100 / amount;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Guard")
        amount_flows = [
            f for f in report.taint_flows if f.source_param == 'amount'
        ]
        # The division by amount should be flagged, but with sanitizer
        sanitized = [f for f in amount_flows if f.is_sanitized]
        self.assertGreater(len(sanitized), 0,
                           "amount should be sanitized by if-revert")

    def test_math_min_is_sanitizer(self):
        """Math.min(tainted, MAX) is a sanitizer."""
        contract = """
        contract Clamped {
            uint256 public value;
            function setValue(uint256 newVal) external {
                value = Math.min(newVal, 1000);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Clamped")
        val_flows = [
            f for f in report.taint_flows if f.source_param == 'newVal'
        ]
        sanitized = [f for f in val_flows if f.is_sanitized]
        self.assertGreater(len(sanitized), 0,
                           "newVal should be sanitized by Math.min")

    def test_zero_address_check_is_sanitizer(self):
        """require(addr != address(0)) is a sanitizer."""
        contract = """
        contract Registry {
            address public target;
            function setTarget(address newTarget) external {
                require(newTarget != address(0));
                target = newTarget;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Registry")
        addr_flows = [
            f for f in report.taint_flows if f.source_param == 'newTarget'
        ]
        sanitized = [f for f in addr_flows if f.is_sanitized]
        self.assertGreater(len(sanitized), 0,
                           "newTarget should be sanitized by zero address check")


class TestUnsanitizedSinkDetection(unittest.TestCase):
    """Test detection of unsanitized tainted data reaching dangerous sinks."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_unsanitized_eth_transfer(self):
        """Unsanitized address reaching payable().transfer() is detected."""
        contract = """
        contract Sender {
            function transferTo(address to, uint256 amount) external {
                payable(to).transfer(amount);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Sender")
        # 'to' reaches payable(to).transfer() without sanitization
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.ETH_TRANSFER and f.source_param == 'to'
        ]
        self.assertGreater(len(dangerous), 0,
                           "to should reach ETH_TRANSFER unsanitized")

    def test_unsanitized_delegatecall(self):
        """Unsanitized data reaching delegatecall is critical."""
        contract = """
        contract Proxy {
            function forward(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Proxy")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.DELEGATECALL
        ]
        self.assertGreater(len(dangerous), 0,
                           "Unsanitized delegatecall should be detected")
        # Should be critical
        for flow in dangerous:
            self.assertEqual(flow.severity, "critical",
                             "Unsanitized delegatecall should be critical")

    def test_unsanitized_selfdestruct(self):
        """Unsanitized address reaching selfdestruct is critical."""
        contract = """
        contract Destroyable {
            function destroy(address payable recipient) external {
                selfdestruct(recipient);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Destroyable")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.SELFDESTRUCT
        ]
        self.assertGreater(len(dangerous), 0,
                           "Unsanitized selfdestruct should be detected")
        for flow in dangerous:
            self.assertEqual(flow.severity, "critical")

    def test_unsanitized_call_value(self):
        """Unsanitized value in .call{value: } is detected."""
        contract = """
        contract Payer {
            function pay(address target, uint256 amount) external {
                target.call{value: amount}("");
            }
        }
        """
        report = self.analyzer.analyze(contract, "Payer")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.EXTERNAL_CALL_VALUE
        ]
        self.assertGreater(len(dangerous), 0,
                           "Tainted value in .call{value:} should be detected")

    def test_unsanitized_division(self):
        """Tainted data used as divisor is detected."""
        contract = """
        contract Divider {
            function divide(uint256 divisor) external pure returns (uint256) {
                return 1000 / divisor;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Divider")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.DIVISION and f.source_param == 'divisor'
        ]
        self.assertGreater(len(dangerous), 0,
                           "Tainted divisor should be detected")
        for flow in dangerous:
            self.assertEqual(flow.severity, "medium")

    def test_unsanitized_array_index(self):
        """Tainted array index is detected."""
        contract = """
        contract ArrayAccess {
            uint256[] public data;
            function get(uint256 index) external view returns (uint256) {
                return data[index];
            }
        }
        """
        report = self.analyzer.analyze(contract, "ArrayAccess")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.ARRAY_INDEX and f.source_param == 'index'
        ]
        self.assertGreater(len(dangerous), 0,
                           "Tainted array index should be detected")

    def test_unsanitized_create(self):
        """Tainted data in constructor is detected."""
        contract = """
        contract Factory {
            function create(uint256 param) external returns (address) {
                Widget widget = new Widget(param);
                return address(widget);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Factory")
        dangerous = [
            f for f in report.dangerous_flows
            if f.sink == TaintSink.CREATE and f.source_param == 'param'
        ]
        self.assertGreater(len(dangerous), 0,
                           "Tainted data in new Contract() should be detected")


class TestSeverityCalculation(unittest.TestCase):
    """Test severity calculation logic."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_critical_sinks(self):
        """delegatecall, selfdestruct, eth_transfer are critical when unsanitized."""
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.DELEGATECALL, False, TaintSource.FUNCTION_PARAM
            ),
            "critical",
        )
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.SELFDESTRUCT, False, TaintSource.FUNCTION_PARAM
            ),
            "critical",
        )
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.ETH_TRANSFER, False, TaintSource.FUNCTION_PARAM
            ),
            "critical",
        )

    def test_sanitized_downgrades_severity(self):
        """Sanitized flows are downgraded by one level."""
        # Critical -> high when sanitized
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.DELEGATECALL, True, TaintSource.FUNCTION_PARAM
            ),
            "high",
        )
        # High -> medium when sanitized
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.EXTERNAL_CALL_VALUE, True, TaintSource.FUNCTION_PARAM
            ),
            "medium",
        )
        # Medium -> low when sanitized
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.DIVISION, True, TaintSource.FUNCTION_PARAM
            ),
            "low",
        )

    def test_block_timestamp_less_critical(self):
        """Block.timestamp source downgrades severity."""
        # Critical -> high for block.timestamp
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.DELEGATECALL, False, TaintSource.BLOCK_TIMESTAMP
            ),
            "high",
        )
        # High -> medium for block.timestamp
        self.assertEqual(
            self.analyzer._calculate_severity(
                TaintSink.EXTERNAL_CALL, False, TaintSource.BLOCK_TIMESTAMP
            ),
            "medium",
        )


class TestFalsePositiveAvoidance(unittest.TestCase):
    """Test that well-protected patterns don't produce dangerous flows."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_bounded_admin_function_is_sanitized(self):
        """onlyOwner + bounds check means the flow is sanitized."""
        contract = """
        contract Admin {
            uint256 public fee;
            uint256 public constant MAX_FEE = 10000;
            function setFee(uint256 newFee) external onlyOwner {
                require(newFee <= MAX_FEE);
                fee = newFee;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Admin")
        fee_dangerous = [
            f for f in report.dangerous_flows if f.source_param == 'newFee'
        ]
        # All flows for newFee should be sanitized due to require + onlyOwner
        self.assertEqual(len(fee_dangerous), 0,
                         "Bounded admin function should not produce dangerous flows")

    def test_guarded_transfer_is_sanitized(self):
        """Transfer with proper validation is sanitized."""
        contract = """
        contract Safe {
            mapping(address => uint256) public balances;
            IERC20 public token;
            function withdraw(uint256 amount) external {
                require(amount > 0, "zero");
                require(amount <= balances[msg.sender], "insufficient");
                balances[msg.sender] -= amount;
                token.transfer(msg.sender, amount);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Safe")
        amount_dangerous = [
            f for f in report.dangerous_flows if f.source_param == 'amount'
        ]
        # amount is validated by require checks
        amount_sanitized = [
            f for f in report.sanitized_flows if f.source_param == 'amount'
        ]
        self.assertGreater(len(amount_sanitized), 0,
                           "amount should have sanitized flows")


class TestCrossContractTaint(unittest.TestCase):
    """Test cross-contract taint tracking."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_taint_flows_across_contracts(self):
        """Taint from Contract A flows into Contract B via external call."""
        contract_a = """
        contract Depositor {
            IVault public vault;
            function deposit(uint256 amount) external {
                vault.deposit(amount);
            }
        }
        """
        contract_b = """
        contract Vault {
            mapping(address => uint256) public balances;
            function deposit(uint256 amount) external {
                balances[msg.sender] += amount;
            }
        }
        """
        reports = self.analyzer.analyze_multiple([
            {'content': contract_a, 'name': 'Depositor'},
            {'content': contract_b, 'name': 'Vault'},
        ])

        # The first report (Depositor) should have a cross-contract flow
        depositor_report = reports[0]
        cross_flows = [
            f for f in depositor_report.taint_flows
            if 'cross:' in str(f.taint_path) or 'vault.deposit' in f.sink_expression
        ]
        self.assertGreater(len(cross_flows), 0,
                           "Cross-contract taint should be detected")

    def test_multiple_contracts_analyzed(self):
        """analyze_multiple returns a report per contract."""
        contracts = [
            {'content': 'contract A { function foo(uint256 x) external {} }', 'name': 'A'},
            {'content': 'contract B { function bar(uint256 y) external {} }', 'name': 'B'},
        ]
        reports = self.analyzer.analyze_multiple(contracts)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0].contract_name, 'A')
        self.assertEqual(reports[1].contract_name, 'B')


class TestFormatForLLM(unittest.TestCase):
    """Test LLM format output."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_format_includes_dangerous_flows(self):
        """Format output includes dangerous unsanitized flows."""
        contract = """
        contract Sender {
            function send(address to, uint256 amount) external {
                payable(to).transfer(amount);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Sender")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("Taint Analysis Results", formatted)
        self.assertIn("Dangerous Unsanitized Flows", formatted)

    def test_format_includes_sanitized_flows(self):
        """Format output includes sanitized flows."""
        contract = """
        contract Safe {
            uint256 public fee;
            uint256 public constant MAX_FEE = 100;
            function setFee(uint256 newFee) external onlyOwner {
                require(newFee <= MAX_FEE);
                fee = newFee;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Safe")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("Taint Analysis Results", formatted)
        if report.sanitized_flows:
            self.assertIn("Sanitized Flows", formatted)

    def test_format_includes_severity(self):
        """Format output includes severity markers."""
        contract = """
        contract Proxy {
            function forward(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Proxy")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("[CRITICAL]", formatted)

    def test_format_includes_path(self):
        """Format output includes taint path."""
        contract = """
        contract Payer {
            function pay(address to) external {
                payable(to).transfer(1 ether);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Payer")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("Path:", formatted)

    def test_format_includes_summary(self):
        """Format output includes summary counts."""
        contract = """
        contract Mixed {
            uint256 public fee;
            function setFee(uint256 newFee) external onlyOwner {
                require(newFee <= 1000);
                fee = newFee;
            }
            function forward(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Mixed")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("Summary", formatted)

    def test_empty_report_format(self):
        """Format handles empty report gracefully."""
        report = TaintReport(contract_name="Empty")
        formatted = self.analyzer.format_for_llm(report)
        self.assertIn("No Dangerous Unsanitized Flows Found", formatted)


class TestContractNameDetection(unittest.TestCase):
    """Test contract name auto-detection."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_auto_detects_contract_name(self):
        """Contract name is detected from source when not provided."""
        contract = """
        contract MyVault {
            function deposit(uint256 amount) external {}
        }
        """
        report = self.analyzer.analyze(contract)
        self.assertEqual(report.contract_name, "MyVault")

    def test_explicit_name_overrides(self):
        """Explicit contract name overrides auto-detection."""
        contract = """
        contract MyVault {
            function deposit(uint256 amount) external {}
        }
        """
        report = self.analyzer.analyze(contract, contract_name="CustomName")
        self.assertEqual(report.contract_name, "CustomName")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and robustness."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_empty_contract(self):
        """Empty contract does not crash."""
        report = self.analyzer.analyze("", "Empty")
        self.assertEqual(report.contract_name, "Empty")
        self.assertEqual(len(report.taint_flows), 0)

    def test_contract_with_no_functions(self):
        """Contract with no functions produces empty report."""
        contract = """
        contract Empty {
            uint256 public x;
        }
        """
        report = self.analyzer.analyze(contract, "Empty")
        self.assertEqual(len(report.taint_flows), 0)

    def test_contract_with_comments_only(self):
        """Contract with comments does not crash."""
        contract = """
        // This is a comment
        /* Multi-line
           comment */
        contract Commented {
            // No functions
        }
        """
        report = self.analyzer.analyze(contract, "Commented")
        self.assertIsNotNone(report)

    def test_complex_nested_contract(self):
        """Complex contract with nested logic does not crash."""
        contract = """
        contract Complex {
            mapping(address => mapping(address => uint256)) public allowances;
            mapping(address => uint256) public balances;

            function transferFrom(address from, address to, uint256 amount) external returns (bool) {
                require(allowances[from][msg.sender] >= amount, "allowance");
                require(balances[from] >= amount, "balance");
                allowances[from][msg.sender] -= amount;
                balances[from] -= amount;
                balances[to] += amount;
                return true;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Complex")
        self.assertIsNotNone(report)
        # amount should be sanitized by require checks
        amount_flows = [
            f for f in report.taint_flows if f.source_param == 'amount'
        ]
        self.assertGreater(len(amount_flows), 0)

    def test_multiple_functions_analyzed(self):
        """All external/public functions are analyzed."""
        contract = """
        contract Multi {
            function funcA(uint256 a) external { }
            function funcB(address b) external { }
            function funcC(uint256 c) public { }
            function _internal(uint256 d) internal { }
        }
        """
        report = self.analyzer.analyze(contract, "Multi")
        source_funcs = set()
        for s in report.taint_sources:
            if s.get('function'):
                source_funcs.add(s['function'])
        self.assertIn('funcA', source_funcs)
        self.assertIn('funcB', source_funcs)
        self.assertIn('funcC', source_funcs)
        self.assertNotIn('_internal', source_funcs)

    def test_report_summary_counts(self):
        """Report summary has correct counts."""
        contract = """
        contract Summary {
            function unsafeForward(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
            function safeFee(uint256 newFee) external onlyOwner {
                require(newFee <= 1000);
                fee = newFee;
            }
        }
        """
        report = self.analyzer.analyze(contract, "Summary")
        self.assertIn('total_flows', report.summary)
        self.assertIn('dangerous_flows', report.summary)
        self.assertIn('sanitized_flows', report.summary)
        self.assertEqual(
            report.summary['total_flows'],
            len(report.taint_flows),
        )
        self.assertEqual(
            report.summary['dangerous_flows'],
            len(report.dangerous_flows),
        )


class TestASTDataIntegration(unittest.TestCase):
    """Test that AST data can be accepted without crashing."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_dict_ast_data(self):
        """Dictionary-style AST data is accepted."""
        contract = """
        contract Token {
            function transfer(address to, uint256 amount) external {}
        }
        """
        ast_data = {
            'nodes': [
                {
                    'nodeType': 'FunctionDefinition',
                    'name': 'transfer',
                    'visibility': 'external',
                    'parameters': {
                        'parameters': [
                            {'name': 'to', 'typeName': {'name': 'address'}},
                            {'name': 'amount', 'typeName': {'name': 'uint256'}},
                        ]
                    },
                }
            ]
        }
        report = self.analyzer.analyze(contract, "Token", ast_data=ast_data)
        self.assertIsNotNone(report)
        param_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.FUNCTION_PARAM.value
        ]
        self.assertGreater(len(param_sources), 0)

    def test_none_ast_data(self):
        """None ast_data falls back to regex analysis."""
        contract = """
        contract Token {
            function transfer(address to, uint256 amount) external {}
        }
        """
        report = self.analyzer.analyze(contract, "Token", ast_data=None)
        self.assertIsNotNone(report)

    def test_invalid_ast_data(self):
        """Invalid ast_data does not crash (falls back to regex)."""
        contract = """
        contract Token {
            function transfer(address to, uint256 amount) external {}
        }
        """
        report = self.analyzer.analyze(contract, "Token", ast_data="invalid")
        self.assertIsNotNone(report)


class TestEventEmitSink(unittest.TestCase):
    """Test event emit sink detection."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_event_emit_detected_as_low(self):
        """Tainted data in event emit is low severity."""
        contract = """
        contract Logger {
            event Transfer(address from, address to, uint256 amount);
            function transfer(address to, uint256 amount) external {
                emit Transfer(msg.sender, to, amount);
            }
        }
        """
        report = self.analyzer.analyze(contract, "Logger")
        event_flows = [
            f for f in report.taint_flows if f.sink == TaintSink.EVENT_EMIT
        ]
        self.assertGreater(len(event_flows), 0,
                           "Event emit with tainted data should be detected")
        for flow in event_flows:
            self.assertEqual(flow.severity, "low")


class TestExternalCallReturnTaint(unittest.TestCase):
    """Test that external call return values are tracked."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_oracle_return_value_tainted(self):
        """Return value from oracle call is a taint source."""
        contract = """
        contract PriceFeed {
            IOracle public oracle;
            function getPrice() external returns (uint256) {
                uint256 price = oracle.latestAnswer();
                return price;
            }
        }
        """
        report = self.analyzer.analyze(contract, "PriceFeed")
        # price should be tainted as external call return
        ext_sources = [
            s for s in report.taint_sources
            if s.get('type') == TaintSource.EXTERNAL_CALL_RETURN.value
        ]
        self.assertGreater(len(ext_sources), 0,
                           "External call return should be a taint source")


class TestAssemblyMstoreSink(unittest.TestCase):
    """Test assembly mstore sink detection."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_mstore_with_tainted_data(self):
        """Tainted data used in mstore is detected."""
        contract = """
        contract AsmUser {
            function writeMemory(uint256 offset) external {
                assembly {
                    mstore(offset, 42)
                }
            }
        }
        """
        report = self.analyzer.analyze(contract, "AsmUser")
        mstore_flows = [
            f for f in report.taint_flows
            if f.sink == TaintSink.ASSEMBLY_MSTORE
        ]
        self.assertGreater(len(mstore_flows), 0,
                           "Tainted mstore offset should be detected")


if __name__ == '__main__':
    unittest.main()
