"""
Shared test fixtures for Aether test suite.

Provides mock ConfigManager, mock API keys, temporary directories,
sample Solidity contracts, and JobManager reset helpers.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.job_manager import JobManager
from core.llm_usage_tracker import LLMUsageTracker


# ── Sample Solidity contract source ─────────────────────────────

SAMPLE_SOLIDITY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""

SAMPLE_VAULT_SOLIDITY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SimpleToken.sol";

contract Vault {
    SimpleToken public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = SimpleToken(_token);
    }

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient deposit");
        deposits[msg.sender] -= amount;
    }
}
"""


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def mock_env_api_keys(monkeypatch):
    """Set fake API keys in environment so ConfigManager doesn't read real ones."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fake-openai-key-12345")
    monkeypatch.setenv("GEMINI_API_KEY", "test-fake-gemini-key-12345")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-12345")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-fake-etherscan-key")


@pytest.fixture
def mock_config():
    """Return a MagicMock that behaves like AetherConfig."""
    config = MagicMock()
    config.workspace = "/tmp/aether-test-workspace"
    config.output_dir = "/tmp/aether-test-output"
    config.reports_dir = "/tmp/aether-test-reports"
    config.max_analysis_time = 3600
    config.parallel_analysis = True
    config.max_concurrent_contracts = 5
    config.openai_api_key = "sk-test-fake-openai-key-12345"
    config.gemini_api_key = "test-fake-gemini-key-12345"
    config.anthropic_api_key = "sk-ant-test-fake-key-12345"
    config.etherscan_api_key = "test-fake-etherscan-key"
    config.openai_model = "gpt-5-chat-latest"
    config.gemini_model = "gemini-2.5-flash"
    config.anthropic_model = "claude-sonnet-4-5-20250929"
    config.triage_min_severity = "medium"
    config.triage_confidence_threshold = 0.5
    config.triage_max_findings = 50
    return config


@pytest.fixture
def mock_config_manager(mock_config):
    """Return a MagicMock ConfigManager with a mock config attribute."""
    mgr = MagicMock()
    mgr.config = mock_config
    mgr.save_config = MagicMock()
    return mgr


@pytest.fixture
def fresh_job_manager():
    """Reset JobManager singleton and return a fresh instance.

    The test should use this fixture to ensure isolation. The singleton
    is reset after the test completes.
    """
    JobManager.reset()
    jm = JobManager.get_instance()
    yield jm
    JobManager.reset()


@pytest.fixture
def tmp_sol_dir():
    """Create a temporary directory with sample Solidity files."""
    with tempfile.TemporaryDirectory(prefix="aether_test_") as tmpdir:
        sol_path = Path(tmpdir) / "SimpleToken.sol"
        sol_path.write_text(SAMPLE_SOLIDITY)

        vault_path = Path(tmpdir) / "Vault.sol"
        vault_path.write_text(SAMPLE_VAULT_SOLIDITY)

        yield Path(tmpdir)


@pytest.fixture
def tmp_single_sol():
    """Create a temporary directory with a single Solidity file."""
    with tempfile.TemporaryDirectory(prefix="aether_test_") as tmpdir:
        sol_path = Path(tmpdir) / "SimpleToken.sol"
        sol_path.write_text(SAMPLE_SOLIDITY)
        yield sol_path
