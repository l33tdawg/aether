"""Tests for core.github_auditor, core.etherscan_fetcher, and core.basescan_fetcher.

Covers GitHub repository audit orchestration, Etherscan API contract fetching,
and BaseScan web-scraping contract fetching. All external calls (HTTP, git,
subprocess) are mocked.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch, call

import requests


# ---------------------------------------------------------------------------
# Shared mock response fixtures
# ---------------------------------------------------------------------------

ETHERSCAN_SUCCESS_RESPONSE = {
    "status": "1",
    "message": "OK",
    "result": [{
        "SourceCode": "pragma solidity ^0.8.0;\n\ncontract Token {\n    string public name;\n}",
        "ABI": '[{"type":"function","name":"name","inputs":[],"outputs":[{"type":"string"}]}]',
        "ContractName": "Token",
        "CompilerVersion": "v0.8.19+commit.7dd6d404",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "",
        "EVMVersion": "Default",
        "Library": "",
        "LicenseType": "MIT",
        "Proxy": "0",
        "Implementation": "",
        "SwarmSource": "",
        "ContractAddress": "0x1234567890abcdef1234567890abcdef12345678"
    }]
}

ETHERSCAN_MULTI_FILE_SOURCE = json.dumps({
    "sources": {
        "contracts/Token.sol": {
            "content": "pragma solidity ^0.8.0;\nimport './IERC20.sol';\ncontract Token is IERC20 {}"
        },
        "@openzeppelin/contracts/token/ERC20/IERC20.sol": {
            "content": "pragma solidity ^0.8.0;\ninterface IERC20 {}"
        }
    }
})

ETHERSCAN_MULTI_FILE_RESPONSE = {
    "status": "1",
    "message": "OK",
    "result": [{
        "SourceCode": ETHERSCAN_MULTI_FILE_SOURCE,
        "ABI": "[]",
        "ContractName": "Token",
        "CompilerVersion": "v0.8.19+commit.7dd6d404",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "",
        "EVMVersion": "Default",
        "Library": "",
        "LicenseType": "MIT",
        "Proxy": "0",
        "Implementation": "",
        "SwarmSource": "",
        "ContractAddress": "0xaabbccddaabbccddaabbccddaabbccddaabbccdd"
    }]
}

ETHERSCAN_PROXY_RESPONSE = {
    "status": "1",
    "message": "OK",
    "result": [{
        "SourceCode": "pragma solidity ^0.8.0;\ncontract ProxyToken {}",
        "ABI": "[]",
        "ContractName": "ProxyToken",
        "CompilerVersion": "v0.8.19+commit.7dd6d404",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "",
        "EVMVersion": "Default",
        "Library": "",
        "LicenseType": "MIT",
        "Proxy": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Implementation": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "SwarmSource": "",
        "ContractAddress": "0x1234567890abcdef1234567890abcdef12345678"
    }]
}

ETHERSCAN_ERROR_RESPONSE = {
    "status": "0",
    "message": "NOTOK",
    "result": "Invalid API Key"
}

ETHERSCAN_RATE_LIMIT_RESPONSE = {
    "status": "0",
    "message": "Rate limit exceeded",
    "result": ""
}

ETHERSCAN_UNVERIFIED_RESPONSE = {
    "status": "1",
    "message": "OK",
    "result": [{
        "SourceCode": "",
        "ABI": "Contract source code not verified",
        "ContractName": "",
        "CompilerVersion": "",
        "OptimizationUsed": "",
        "Runs": "",
        "ConstructorArguments": "",
        "EVMVersion": "",
        "Library": "",
        "LicenseType": "",
        "Proxy": "0",
        "Implementation": "",
        "SwarmSource": ""
    }]
}

VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
VALID_ADDRESS_2 = "0xaabbccddaabbccddaabbccddaabbccddaabbccdd"
INVALID_ADDRESS_SHORT = "0x1234"
INVALID_ADDRESS_NO_PREFIX = "1234567890abcdef1234567890abcdef12345678"


# ===========================================================================
# Helper to build a mock ConfigManager with a desired API key
# ===========================================================================

def _mock_config_manager(etherscan_api_key="test_api_key_12345"):
    """Return a MagicMock that behaves like ConfigManager for fetcher ctors."""
    mgr = MagicMock()
    mgr.config.etherscan_api_key = etherscan_api_key
    return mgr


def _make_etherscan_fetcher(api_key="test_key"):
    """Create an EtherscanFetcher with an isolated temp cache directory."""
    from core.etherscan_fetcher import EtherscanFetcher
    fetcher = EtherscanFetcher(config_manager=_mock_config_manager(api_key))
    # Redirect cache to temp dir to prevent cross-test pollution
    tmp_cache = Path(tempfile.mkdtemp())
    fetcher.cache_dir = tmp_cache
    fetcher._tmp_cache_dir = tmp_cache  # Stash ref for cleanup
    return fetcher


def _cleanup_etherscan_fetcher(fetcher):
    """Remove the temp cache created by _make_etherscan_fetcher."""
    tmp = getattr(fetcher, '_tmp_cache_dir', None)
    if tmp and tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Helper to build a mock BeautifulSoup pre tag element
# ===========================================================================

def _make_mock_soup_with_pre(source_code_text, contract_name_text=None):
    """Create a mock BeautifulSoup object that returns pre tags with given text."""
    mock_pre = MagicMock()
    mock_pre.get_text.return_value = source_code_text

    mock_soup = MagicMock()
    mock_soup.find_all.side_effect = lambda *args, **kwargs: {
        'pre': [mock_pre],
    }.get(args[0] if args else kwargs.get('name', ''), [])

    return mock_soup


def _make_mock_soup_no_source():
    """Create a mock BeautifulSoup that returns no pre tags with source."""
    mock_soup = MagicMock()
    mock_soup.find_all.return_value = []
    return mock_soup


# ===========================================================================
# EtherscanFetcher Tests
# ===========================================================================

class TestEtherscanFetcherAddressValidation(unittest.TestCase):
    """Tests for address and URL validation methods."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_valid_ethereum_address(self):
        self.assertTrue(self.fetcher.is_etherscan_address(VALID_ADDRESS))

    def test_invalid_address_too_short(self):
        self.assertFalse(self.fetcher.is_etherscan_address(INVALID_ADDRESS_SHORT))

    def test_invalid_address_no_0x_prefix(self):
        self.assertFalse(self.fetcher.is_etherscan_address(INVALID_ADDRESS_NO_PREFIX))

    def test_invalid_address_bad_hex(self):
        self.assertFalse(self.fetcher.is_etherscan_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"))

    def test_is_evm_address_same_as_etherscan(self):
        self.assertTrue(self.fetcher.is_evm_address(VALID_ADDRESS))
        self.assertFalse(self.fetcher.is_evm_address("not_an_address"))

    def test_is_solana_address_valid(self):
        self.assertTrue(self.fetcher.is_solana_address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"))

    def test_is_solana_address_too_short(self):
        self.assertFalse(self.fetcher.is_solana_address("abc"))

    def test_is_solana_address_invalid_chars(self):
        # Solana base58 excludes 0, O, I, l
        self.assertFalse(self.fetcher.is_solana_address("0" * 40))


class TestEtherscanFetcherURLParsing(unittest.TestCase):
    """Tests for parse_explorer_url."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_parse_plain_address(self):
        network, addr = self.fetcher.parse_explorer_url(VALID_ADDRESS)
        self.assertEqual(network, "ethereum")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_etherscan_url(self):
        url = f"https://etherscan.io/address/{VALID_ADDRESS}#code"
        network, addr = self.fetcher.parse_explorer_url(url)
        self.assertEqual(network, "ethereum")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_polygonscan_url(self):
        url = f"https://polygonscan.com/address/{VALID_ADDRESS}"
        network, addr = self.fetcher.parse_explorer_url(url)
        self.assertEqual(network, "polygon")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_arbiscan_url(self):
        url = f"https://arbiscan.io/address/{VALID_ADDRESS}"
        network, addr = self.fetcher.parse_explorer_url(url)
        self.assertEqual(network, "arbitrum")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_basescan_url(self):
        url = f"https://basescan.org/address/{VALID_ADDRESS}"
        network, addr = self.fetcher.parse_explorer_url(url)
        self.assertEqual(network, "base")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_optimism_url(self):
        url = f"https://optimistic.etherscan.io/address/{VALID_ADDRESS}"
        network, addr = self.fetcher.parse_explorer_url(url)
        self.assertEqual(network, "optimism")
        self.assertEqual(addr, VALID_ADDRESS)

    def test_parse_invalid_url_no_address(self):
        network, addr = self.fetcher.parse_explorer_url("https://etherscan.io/tx/0xabc")
        self.assertIsNone(network)
        self.assertIsNone(addr)

    def test_parse_garbage_string(self):
        network, addr = self.fetcher.parse_explorer_url("not_a_url_or_address")
        self.assertIsNone(network)
        self.assertIsNone(addr)


class TestEtherscanFetcherNetworks(unittest.TestCase):
    """Tests for network management."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_default_network_is_ethereum(self):
        self.assertEqual(self.fetcher.current_network, "ethereum")

    def test_set_network_valid(self):
        result = self.fetcher.set_network("polygon")
        self.assertTrue(result)
        self.assertEqual(self.fetcher.current_network, "polygon")
        self.assertIn("polygonscan", self.fetcher.base_url)

    def test_set_network_invalid(self):
        result = self.fetcher.set_network("nonexistent_chain")
        self.assertFalse(result)
        # Should remain on previous network
        self.assertEqual(self.fetcher.current_network, "ethereum")

    def test_get_supported_networks(self):
        networks = self.fetcher.get_supported_networks()
        self.assertIn("ethereum", networks)
        self.assertIn("polygon", networks)
        self.assertIn("arbitrum", networks)
        self.assertIn("base", networks)

    def test_get_non_evm_networks(self):
        networks = self.fetcher.get_non_evm_networks()
        self.assertIn("solana", networks)

    def test_get_all_supported_networks(self):
        all_nets = self.fetcher.get_all_supported_networks()
        self.assertIn("ethereum", all_nets)
        self.assertIn("solana", all_nets)

    def test_get_network_info(self):
        info = self.fetcher.get_network_info("ethereum")
        self.assertIsNotNone(info)
        self.assertEqual(info['chain_id'], 1)
        self.assertEqual(info['name'], 'Ethereum Mainnet')

    def test_get_network_info_nonexistent(self):
        info = self.fetcher.get_network_info("nonexistent")
        self.assertIsNone(info)

    def test_get_contract_explorer_url(self):
        url = self.fetcher.get_contract_explorer_url(VALID_ADDRESS, "polygon")
        self.assertIn("polygonscan.com", url)
        self.assertIn(VALID_ADDRESS, url)

    def test_get_contract_explorer_url_default_network(self):
        url = self.fetcher.get_contract_explorer_url(VALID_ADDRESS)
        self.assertIn("etherscan.io", url)

    def test_auto_detect_network_from_address(self):
        # Currently always returns 'ethereum' as default
        result = self.fetcher.auto_detect_network_from_address(VALID_ADDRESS)
        self.assertEqual(result, "ethereum")


class TestEtherscanFetcherFetchContract(unittest.TestCase):
    """Tests for fetch_contract_source with mocked HTTP.

    Each test uses an isolated temp cache dir to prevent cross-test
    pollution from the Etherscan caching layer.
    """

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_fetch_invalid_address(self):
        result = self.fetcher.fetch_contract_source("invalid_address")
        self.assertIn("error", result)
        self.assertIn("Invalid", result["error"])

    def test_fetch_no_api_key(self):
        fetcher = _make_etherscan_fetcher(api_key="")
        try:
            result = fetcher.fetch_contract_source(VALID_ADDRESS)
            self.assertIn("error", result)
            self.assertIn("API key", result["error"])
        finally:
            _cleanup_etherscan_fetcher(fetcher)

    def test_fetch_unsupported_network(self):
        result = self.fetcher.fetch_contract_source(VALID_ADDRESS, network="nonexistent")
        self.assertIn("error", result)
        self.assertIn("Unsupported", result["error"])

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_success(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertEqual(result['contract_name'], 'Token')
        self.assertEqual(result['network'], 'ethereum')
        self.assertIn('source_code', result)
        self.assertIn('pragma solidity', result['source_code'])
        self.assertEqual(result['compiler_version'], 'v0.8.19+commit.7dd6d404')
        self.assertEqual(result['optimization'], '1')
        self.assertEqual(result['runs'], '200')
        self.assertEqual(result['license'], 'MIT')

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_multi_file_contract(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_MULTI_FILE_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS_2)

        self.assertTrue(result.get('success'))
        self.assertEqual(result['contract_name'], 'Token')
        # Source code should be JSON string for multi-file
        self.assertTrue(result['source_code'].startswith('{'))

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_api_error(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_ERROR_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_rate_limit(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_RATE_LIMIT_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)
        self.assertIn("rate limit", result["error"].lower())

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_unverified_contract(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_UNVERIFIED_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)
        self.assertIn("not verified", result["error"].lower())

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_network_error(self, mock_sleep, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)
        self.assertIn("Network error", result["error"])

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_json_decode_error(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_empty_result(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "1", "message": "OK", "result": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_uses_correct_network_url(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        self.fetcher.fetch_contract_source(VALID_ADDRESS, network="polygon")

        called_url = mock_get.call_args[0][0]
        self.assertIn("polygonscan.com", called_url)
        self.assertIn("chainid=137", called_url)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_circular_reference_prevention(self, mock_sleep, mock_get):
        """Verify _visited prevents infinite loops with proxy addresses."""
        result = self.fetcher.fetch_contract_source(
            VALID_ADDRESS, _visited={VALID_ADDRESS.lower()}
        )
        self.assertIn("error", result)
        self.assertIn("Circular reference", result["error"])

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_includes_all_contracts_field(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn('all_contracts', result)
        self.assertIsInstance(result['all_contracts'], list)
        self.assertGreaterEqual(len(result['all_contracts']), 1)
        self.assertEqual(result['contract_count'], len(result['all_contracts']))

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_invalid_api_key_error(self, mock_sleep, mock_get):
        """Check that 'invalid api key' message is properly detected."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "0",
            "message": "Invalid API Key",
            "result": ""
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)
        self.assertIn("Invalid", result["error"])


class TestEtherscanFetcherCache(unittest.TestCase):
    """Tests for caching behavior."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()
        # Use the already-isolated temp cache from _make_etherscan_fetcher

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_cache_path_generation(self):
        path = self.fetcher._get_cache_path(VALID_ADDRESS, "ethereum")
        self.assertTrue(str(path).endswith(".json"))

    def test_save_and_load_cache(self):
        contract_data = {"source_code": "test", "contract_name": "Test"}
        self.fetcher._save_to_cache(VALID_ADDRESS, "ethereum", contract_data)

        loaded = self.fetcher._load_from_cache(VALID_ADDRESS, "ethereum")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["source_code"], "test")

    def test_load_nonexistent_cache(self):
        loaded = self.fetcher._load_from_cache("0x" + "a" * 40, "ethereum")
        self.assertIsNone(loaded)

    def test_stale_cache_removed(self):
        """Cache older than 24h should be discarded."""
        cache_path = self.fetcher._get_cache_path(VALID_ADDRESS, "ethereum")
        stale_data = {
            "cached_at": time.time() - 100000,  # >24h ago
            "contract_data": {"source_code": "old"}
        }
        with open(cache_path, 'w') as f:
            json.dump(stale_data, f)

        loaded = self.fetcher._load_from_cache(VALID_ADDRESS, "ethereum")
        self.assertIsNone(loaded)
        # Cache file should be deleted
        self.assertFalse(cache_path.exists())

    def test_corrupted_cache_removed(self):
        cache_path = self.fetcher._get_cache_path(VALID_ADDRESS, "ethereum")
        with open(cache_path, 'w') as f:
            f.write("NOT VALID JSON{{{")

        loaded = self.fetcher._load_from_cache(VALID_ADDRESS, "ethereum")
        self.assertIsNone(loaded)

    def test_get_cache_stats(self):
        # Start empty
        stats = self.fetcher.get_cache_stats()
        self.assertEqual(stats['total_cached_contracts'], 0)

        # Save one item
        self.fetcher._save_to_cache(VALID_ADDRESS, "ethereum", {"source_code": "x"})
        stats = self.fetcher.get_cache_stats()
        self.assertEqual(stats['total_cached_contracts'], 1)
        self.assertGreater(stats['total_cache_size_bytes'], 0)

    def test_clear_all_cache(self):
        self.fetcher._save_to_cache(VALID_ADDRESS, "ethereum", {"data": "1"})
        self.fetcher._save_to_cache("0x" + "b" * 40, "polygon", {"data": "2"})
        cleared = self.fetcher.clear_cache()
        self.assertEqual(cleared, 2)
        stats = self.fetcher.get_cache_stats()
        self.assertEqual(stats['total_cached_contracts'], 0)

    def test_clear_cache_specific_address(self):
        self.fetcher._save_to_cache(VALID_ADDRESS, "ethereum", {"data": "1"})
        self.fetcher._save_to_cache("0x" + "b" * 40, "ethereum", {"data": "2"})
        cleared = self.fetcher.clear_cache(network="ethereum", address=VALID_ADDRESS)
        self.assertEqual(cleared, 1)


class TestEtherscanFetcherSaveContract(unittest.TestCase):
    """Tests for save_contract_source."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_save_single_file_contract(self):
        contract_data = {
            'success': True,
            'source_code': 'pragma solidity ^0.8.0;\ncontract Test {}',
            'contract_name': 'Test',
            'address': VALID_ADDRESS,
            'compiler_version': 'v0.8.19',
            'all_contracts': [],
            'contract_count': 0
        }
        path = self.fetcher.save_contract_source(contract_data, self.tmp_dir)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("pragma solidity", content)

    def test_save_raises_on_error_data(self):
        contract_data = {'success': False, 'error': 'Not verified'}
        with self.assertRaises(ValueError):
            self.fetcher.save_contract_source(contract_data, self.tmp_dir)

    def test_save_multi_file_contract(self):
        source_json = json.dumps({
            "sources": {
                "contracts/Token.sol": {"content": "pragma solidity ^0.8.0;\ncontract Token {}"},
                "contracts/IERC20.sol": {"content": "pragma solidity ^0.8.0;\ninterface IERC20 {}"}
            }
        })
        contract_data = {
            'success': True,
            'source_code': source_json,
            'contract_name': 'Token',
            'address': VALID_ADDRESS,
            'compiler_version': 'v0.8.19+commit.7dd6d404',
            'all_contracts': [],
            'contract_count': 0
        }
        path = self.fetcher.save_contract_source(contract_data, self.tmp_dir)
        self.assertTrue(os.path.isdir(path))
        # Should have saved the solidity files
        sol_files = list(Path(path).rglob("*.sol"))
        self.assertGreaterEqual(len(sol_files), 1)


class TestEtherscanFetcherABIValidation(unittest.TestCase):
    """Tests for validate_abi_compatibility."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_abi_valid_all_functions_present(self):
        contract_data = {
            'success': True,
            'abi': json.dumps([
                {"type": "function", "name": "transfer"},
                {"type": "function", "name": "balanceOf"},
                {"type": "event", "name": "Transfer"}
            ])
        }
        result = self.fetcher.validate_abi_compatibility(
            contract_data, ["transfer", "balanceOf"]
        )
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['missing_functions']), 0)
        self.assertEqual(result['total_functions'], 2)

    def test_abi_missing_functions(self):
        contract_data = {
            'success': True,
            'abi': json.dumps([
                {"type": "function", "name": "transfer"}
            ])
        }
        result = self.fetcher.validate_abi_compatibility(
            contract_data, ["transfer", "approve", "balanceOf"]
        )
        self.assertFalse(result['valid'])
        self.assertIn("approve", result['missing_functions'])
        self.assertIn("balanceOf", result['missing_functions'])

    def test_abi_validation_no_success(self):
        contract_data = {'success': False, 'error': 'fail'}
        result = self.fetcher.validate_abi_compatibility(contract_data, ["transfer"])
        self.assertFalse(result['valid'])

    def test_abi_validation_invalid_abi_json(self):
        contract_data = {'success': True, 'abi': 'not_json'}
        result = self.fetcher.validate_abi_compatibility(contract_data, ["transfer"])
        self.assertFalse(result['valid'])
        self.assertIn("error", result)


class TestEtherscanFetcherGetContractInfo(unittest.TestCase):
    """Tests for get_contract_info."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    def test_get_info_invalid_address(self):
        result = self.fetcher.get_contract_info("bad_addr")
        self.assertIn("error", result)

    def test_get_info_no_api_key(self):
        fetcher = _make_etherscan_fetcher(api_key="")
        try:
            result = fetcher.get_contract_info(VALID_ADDRESS)
            self.assertIn("error", result)
        finally:
            _cleanup_etherscan_fetcher(fetcher)

    @patch('core.etherscan_fetcher.requests.get')
    def test_get_info_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.fetcher.get_contract_info(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertEqual(result['contract_name'], 'Token')
        self.assertTrue(result['is_verified'])

    @patch('core.etherscan_fetcher.requests.get')
    def test_get_info_network_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("timed out")

        result = self.fetcher.get_contract_info(VALID_ADDRESS)

        self.assertIn("error", result)


class TestEtherscanFetcherFetchAndSave(unittest.TestCase):
    """Tests for fetch_and_save_contract convenience method."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_and_save_success(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        success, path, data = self.fetcher.fetch_and_save_contract(
            VALID_ADDRESS, self.tmp_dir
        )

        self.assertTrue(success)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(data.get('success'))

    def test_fetch_and_save_invalid_address(self):
        success, error_msg, data = self.fetcher.fetch_and_save_contract("bad")
        self.assertFalse(success)
        self.assertIn("Invalid", error_msg)


class TestEtherscanFetcherMultipleFetch(unittest.TestCase):
    """Tests for fetch_multiple_contracts."""

    def setUp(self):
        self.fetcher = _make_etherscan_fetcher()

    def tearDown(self):
        _cleanup_etherscan_fetcher(self.fetcher)

    @patch('core.etherscan_fetcher.requests.get')
    @patch('core.etherscan_fetcher.time.sleep')
    def test_fetch_multiple(self, mock_sleep, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ETHERSCAN_SUCCESS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        addr1 = VALID_ADDRESS
        addr2 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        results = self.fetcher.fetch_multiple_contracts([addr1, addr2])

        self.assertIn(addr1, results)
        self.assertIn(addr2, results)
        self.assertTrue(results[addr1].get('success'))


# ===========================================================================
# BasescanFetcher Tests
#
# The project ships a local stub bs4 package (bs4/__init__.py) that returns
# empty from find_all(). To test BasescanFetcher properly we must mock
# BeautifulSoup at the module level used by basescan_fetcher.
# ===========================================================================

class TestBasescanFetcherAddressValidation(unittest.TestCase):
    """Tests for BasescanFetcher address validation."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())

    def test_valid_address(self):
        self.assertTrue(self.fetcher.is_basescan_address(VALID_ADDRESS))

    def test_invalid_address_short(self):
        self.assertFalse(self.fetcher.is_basescan_address("0x1234"))

    def test_invalid_address_no_prefix(self):
        self.assertFalse(self.fetcher.is_basescan_address(
            "1234567890abcdef1234567890abcdef12345678"
        ))

    def test_invalid_address_non_hex(self):
        self.assertFalse(self.fetcher.is_basescan_address("0x" + "!" * 40))


class TestBasescanFetcherFetch(unittest.TestCase):
    """Tests for BasescanFetcher.fetch_contract_source with mocked HTTP + BS4."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())

    def test_fetch_invalid_address(self):
        result = self.fetcher.fetch_contract_source("invalid")
        self.assertIn("error", result)
        self.assertIn("Invalid", result["error"])

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_verified_contract(self, mock_get, MockBS):
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        # Mock the soup object
        source_text = 'pragma solidity ^0.8.0;\ncontract MyToken {\n    string public name = "Test";\n}'
        mock_pre = MagicMock()
        mock_pre.get_text.return_value = source_text

        mock_soup = MagicMock()
        # find_all('pre') returns the pre tag
        def find_all_side_effect(*args, **kwargs):
            tag = args[0] if args else None
            if tag == 'pre':
                return [mock_pre]
            return []
        mock_soup.find_all.side_effect = find_all_side_effect
        MockBS.return_value = mock_soup

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertEqual(result['contract_name'], 'MyToken')
        self.assertEqual(result['address'], VALID_ADDRESS)
        self.assertIn('pragma solidity', result['source_code'])
        self.assertEqual(result['platform'], 'basescan')

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_unverified_contract(self, mock_get, MockBS):
        mock_resp = MagicMock()
        mock_resp.content = b"<html><body>No source</body></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        mock_soup = MagicMock()
        mock_soup.find_all.return_value = []
        MockBS.return_value = mock_soup

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)
        self.assertIn("not verified", result["error"].lower())

    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_network_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertIn("error", result)

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_extracts_contract_name_from_source(self, mock_get, MockBS):
        """When no Contract Name element exists, extract name from source regex."""
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        source_text = (
            'pragma solidity ^0.8.0;\n'
            'interface IVault {\n    function deposit() external;\n}\n'
            'contract VaultV2 {\n    function deposit() external {}\n}'
        )
        mock_pre = MagicMock()
        mock_pre.get_text.return_value = source_text

        mock_soup = MagicMock()
        def find_all_side_effect(*args, **kwargs):
            tag = args[0] if args else None
            if tag == 'pre':
                return [mock_pre]
            return []
        mock_soup.find_all.side_effect = find_all_side_effect
        MockBS.return_value = mock_soup

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        # First regex match for contract\s+(\w+) is IVault
        self.assertIn(result['contract_name'], ['IVault', 'VaultV2'])

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_interface_only_source(self, mock_get, MockBS):
        """Source code with only an interface keyword should still be detected."""
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        source_text = 'pragma solidity ^0.8.0;\ninterface IERC20 { function totalSupply() external view returns (uint256); }'
        mock_pre = MagicMock()
        mock_pre.get_text.return_value = source_text

        mock_soup = MagicMock()
        def find_all_side_effect(*args, **kwargs):
            tag = args[0] if args else None
            if tag == 'pre':
                return [mock_pre]
            return []
        mock_soup.find_all.side_effect = find_all_side_effect
        MockBS.return_value = mock_soup

        result = self.fetcher.fetch_contract_source(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertIn('interface IERC20', result['source_code'])


class TestBasescanFetcherSave(unittest.TestCase):
    """Tests for BasescanFetcher.save_contract_source."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_save_single_file(self):
        contract_data = {
            'success': True,
            'source_code': 'pragma solidity ^0.8.0;\ncontract Test {}',
            'contract_name': 'Test',
            'address': VALID_ADDRESS,
            'is_multi_file': False
        }
        path = self.fetcher.save_contract_source(contract_data, self.tmp_dir)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith('.sol'))

    def test_save_multi_file(self):
        contract_data = {
            'success': True,
            'source_code': {
                'sources': {
                    'contracts/Token.sol': {
                        'content': 'pragma solidity ^0.8.0;\ncontract Token {}'
                    }
                }
            },
            'contract_name': 'Token',
            'address': VALID_ADDRESS,
            'is_multi_file': True
        }
        path = self.fetcher.save_contract_source(contract_data, self.tmp_dir)
        self.assertTrue(os.path.exists(path))


class TestBasescanFetcherFetchAndSave(unittest.TestCase):
    """Tests for BasescanFetcher.fetch_and_save_contract."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_fetch_and_save_success(self, mock_get, MockBS):
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        source_text = 'pragma solidity ^0.8.0;\ncontract MyToken { string public name; }'
        mock_pre = MagicMock()
        mock_pre.get_text.return_value = source_text

        mock_soup = MagicMock()
        def find_all_side_effect(*args, **kwargs):
            tag = args[0] if args else None
            if tag == 'pre':
                return [mock_pre]
            return []
        mock_soup.find_all.side_effect = find_all_side_effect
        MockBS.return_value = mock_soup

        success, path, data = self.fetcher.fetch_and_save_contract(
            VALID_ADDRESS, self.tmp_dir
        )

        self.assertTrue(success)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(data.get('success'))

    def test_fetch_and_save_invalid_address(self):
        success, error_msg, data = self.fetcher.fetch_and_save_contract("bad")
        self.assertFalse(success)


class TestBasescanFetcherGetContractInfo(unittest.TestCase):
    """Tests for BasescanFetcher.get_contract_info."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())

    def test_get_info_invalid_address(self):
        result = self.fetcher.get_contract_info("nope")
        self.assertIn("error", result)

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_get_info_verified(self, mock_get, MockBS):
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        source_text = 'pragma solidity ^0.8.0;\ncontract Vault { function deposit() external {} }'
        mock_pre = MagicMock()
        mock_pre.get_text.return_value = source_text

        mock_soup = MagicMock()
        def find_all_side_effect(*args, **kwargs):
            tag = args[0] if args else None
            if tag == 'pre':
                return [mock_pre]
            return []
        mock_soup.find_all.side_effect = find_all_side_effect
        MockBS.return_value = mock_soup

        result = self.fetcher.get_contract_info(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertTrue(result['is_verified'])
        self.assertEqual(result['contract_name'], 'Vault')
        self.assertEqual(result['platform'], 'basescan')

    @patch('core.basescan_fetcher.BeautifulSoup')
    @patch('core.basescan_fetcher.requests.get')
    def test_get_info_unverified(self, mock_get, MockBS):
        mock_resp = MagicMock()
        mock_resp.content = b"<html></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        mock_soup = MagicMock()
        mock_soup.find_all.return_value = []
        MockBS.return_value = mock_soup

        result = self.fetcher.get_contract_info(VALID_ADDRESS)

        self.assertTrue(result.get('success'))
        self.assertFalse(result['is_verified'])

    @patch('core.basescan_fetcher.requests.get')
    def test_get_info_network_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("timeout")

        result = self.fetcher.get_contract_info(VALID_ADDRESS)

        self.assertIn("error", result)


class TestBasescanFetcherTestConnection(unittest.TestCase):
    """Tests for BasescanFetcher.test_api_connection."""

    def setUp(self):
        from core.basescan_fetcher import BasescanFetcher
        self.fetcher = BasescanFetcher(config_manager=_mock_config_manager())

    @patch('core.basescan_fetcher.requests.get')
    def test_connection_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        result = self.fetcher.test_api_connection()
        self.assertTrue(result)

    @patch('core.basescan_fetcher.requests.get')
    def test_connection_failure_status(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        result = self.fetcher.test_api_connection()
        self.assertFalse(result)

    @patch('core.basescan_fetcher.requests.get')
    def test_connection_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")

        result = self.fetcher.test_api_connection()
        self.assertFalse(result)


# ===========================================================================
# GitHubAuditor Tests
# ===========================================================================

def _make_github_auditor():
    """Create a GitHubAuditor with all heavy dependencies mocked."""
    with patch('core.github_auditor.AetherDatabase'), \
         patch('core.github_auditor.RepositoryManager'), \
         patch('core.github_auditor.FrameworkDetector'), \
         patch('core.github_auditor.ProjectBuilder'), \
         patch('core.github_auditor.ContractDiscovery'), \
         patch('core.github_auditor.ScopeManager'), \
         patch('core.github_auditor.ScopeSelector'):
        from core.github_auditor import GitHubAuditor
        return GitHubAuditor(cache_dir="/tmp/test_cache", db_path=":memory:")


class TestGitHubAuditorParseOwnerRepo(unittest.TestCase):
    """Tests for GitHubAuditor._parse_owner_repo."""

    def setUp(self):
        self.auditor = _make_github_auditor()

    def test_parse_standard_url(self):
        owner, repo = self.auditor._parse_owner_repo(
            "https://github.com/OpenZeppelin/openzeppelin-contracts"
        )
        self.assertEqual(owner, "OpenZeppelin")
        self.assertEqual(repo, "openzeppelin-contracts")

    def test_parse_url_with_git_suffix(self):
        owner, repo = self.auditor._parse_owner_repo(
            "https://github.com/OpenZeppelin/openzeppelin-contracts.git"
        )
        self.assertEqual(owner, "OpenZeppelin")
        self.assertEqual(repo, "openzeppelin-contracts")

    def test_parse_url_with_path(self):
        owner, repo = self.auditor._parse_owner_repo(
            "https://github.com/owner/repo/tree/main/src"
        )
        self.assertEqual(owner, "owner")
        self.assertEqual(repo, "repo")

    def test_parse_invalid_url(self):
        owner, repo = self.auditor._parse_owner_repo("not_a_url")
        self.assertIsNone(owner)
        self.assertIsNone(repo)

    def test_parse_empty_string(self):
        owner, repo = self.auditor._parse_owner_repo("")
        self.assertIsNone(owner)
        self.assertIsNone(repo)

    def test_parse_non_github_url(self):
        owner, repo = self.auditor._parse_owner_repo("https://gitlab.com/owner/repo")
        self.assertIsNone(owner)
        self.assertIsNone(repo)


class TestGitHubAuditorDetectProjectType(unittest.TestCase):
    """Tests for _detect_project_type and _list_project_files."""

    def setUp(self):
        self.auditor = _make_github_auditor()
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_detect_rust_project(self):
        (self.tmp_dir / 'Cargo.toml').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'Rust')

    def test_detect_javascript_project(self):
        (self.tmp_dir / 'package.json').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'JavaScript/Node.js')

    def test_detect_go_project(self):
        (self.tmp_dir / 'go.mod').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'Go')

    def test_detect_python_project(self):
        (self.tmp_dir / 'pyproject.toml').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'Python')

    def test_detect_python_requirements(self):
        (self.tmp_dir / 'requirements.txt').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'Python')

    def test_detect_cpp_project(self):
        (self.tmp_dir / 'CMakeLists.txt').touch()
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'C/C++')

    def test_detect_unknown_project(self):
        self.assertEqual(self.auditor._detect_project_type(self.tmp_dir), 'Unknown')

    def test_list_project_files_foundry(self):
        (self.tmp_dir / 'foundry.toml').touch()
        (self.tmp_dir / 'package.json').touch()
        result = self.auditor._list_project_files(self.tmp_dir)
        self.assertIn('foundry.toml', result)

    def test_list_project_files_empty(self):
        result = self.auditor._list_project_files(self.tmp_dir)
        # Should return something reasonable
        self.assertIsInstance(result, str)


class TestGitHubAuditorGetAuditedContracts(unittest.TestCase):
    """Tests for _get_audited_contracts."""

    def setUp(self):
        self.auditor = _make_github_auditor()
        self.mock_db = self.auditor.db

    def test_no_project_id(self):
        result = self.auditor._get_audited_contracts(None)
        self.assertEqual(result, [])

    def test_with_scopes(self):
        self.mock_db.get_all_scopes.return_value = [
            {'selected_contracts': ['src/Token.sol', 'src/Vault.sol']},
            {'selected_contracts': ['src/Vault.sol', 'src/Pool.sol']}
        ]
        self.mock_db.get_contracts.return_value = [
            {'file_path': 'src/Token.sol', 'contract_name': 'Token'},
            {'file_path': 'src/Vault.sol', 'contract_name': 'Vault'},
            {'file_path': 'src/Pool.sol', 'contract_name': 'Pool'},
            {'file_path': 'src/Other.sol', 'contract_name': 'Other'}
        ]

        result = self.auditor._get_audited_contracts(1)

        self.assertEqual(len(result), 3)
        paths = {c['file_path'] for c in result}
        self.assertIn('src/Token.sol', paths)
        self.assertIn('src/Vault.sol', paths)
        self.assertIn('src/Pool.sol', paths)
        self.assertNotIn('src/Other.sol', paths)

    def test_scope_with_json_string(self):
        """Scopes may store selected_contracts as a JSON string."""
        self.mock_db.get_all_scopes.return_value = [
            {'selected_contracts': json.dumps(['src/Token.sol'])}
        ]
        self.mock_db.get_contracts.return_value = [
            {'file_path': 'src/Token.sol', 'contract_name': 'Token'}
        ]

        result = self.auditor._get_audited_contracts(1)
        self.assertEqual(len(result), 1)

    def test_db_exception_returns_empty(self):
        self.mock_db.get_all_scopes.side_effect = Exception("DB error")
        result = self.auditor._get_audited_contracts(1)
        self.assertEqual(result, [])


class TestAuditOptions(unittest.TestCase):
    """Tests for the AuditOptions dataclass."""

    def test_default_values(self):
        from core.github_auditor import AuditOptions
        opts = AuditOptions()
        self.assertIsNone(opts.scope)
        self.assertFalse(opts.fresh)
        self.assertFalse(opts.reanalyze)
        self.assertFalse(opts.verbose)
        self.assertEqual(opts.output_format, 'display')
        self.assertIsNone(opts.resume_scope_id)

    def test_custom_values(self):
        from core.github_auditor import AuditOptions
        opts = AuditOptions(
            scope=['contracts/Token.sol'],
            fresh=True,
            github_token='ghp_test123',
            interactive_scope=True,
            resume_scope_id=42
        )
        self.assertEqual(opts.scope, ['contracts/Token.sol'])
        self.assertTrue(opts.fresh)
        self.assertEqual(opts.github_token, 'ghp_test123')
        self.assertTrue(opts.interactive_scope)
        self.assertEqual(opts.resume_scope_id, 42)

    def test_all_boolean_flags_default_false(self):
        from core.github_auditor import AuditOptions
        opts = AuditOptions()
        for attr in ['fresh', 'reanalyze', 'retry_failed', 'clear_cache',
                     'skip_build', 'no_cache', 'verbose', 'dry_run',
                     'interactive_scope']:
            self.assertFalse(getattr(opts, attr), f"{attr} should default to False")


class TestAuditResult(unittest.TestCase):
    """Tests for the AuditResult dataclass."""

    def test_default_values(self):
        from core.github_auditor import AuditResult
        result = AuditResult(
            project_path=Path("/tmp/repo"),
            framework="foundry",
            contracts_analyzed=5,
            findings=[{"severity": "high"}]
        )
        self.assertEqual(result.project_path, Path("/tmp/repo"))
        self.assertEqual(result.framework, "foundry")
        self.assertEqual(result.contracts_analyzed, 5)
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(result.cancelled)
        self.assertIsNone(result.scope_id)

    def test_cancelled_result(self):
        from core.github_auditor import AuditResult
        result = AuditResult(
            project_path=Path("/tmp/repo"),
            framework=None,
            contracts_analyzed=0,
            findings=[],
            cancelled=True,
            scope_id=7
        )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.scope_id, 7)


class TestScopeSelector(unittest.TestCase):
    """Tests for the ScopeSelector class."""

    def test_empty_contracts_returns_empty(self):
        with patch('core.github_auditor.ScopeManager'):
            from core.github_auditor import ScopeSelector
            selector = ScopeSelector()
            result = selector.select_scope([])
            self.assertEqual(result, [])


# ===========================================================================
# FrameworkDetector integration tests (used by GitHubAuditor)
# ===========================================================================

class TestFrameworkDetector(unittest.TestCase):
    """Tests for FrameworkDetector -- used by GitHubAuditor for framework detection."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_detect_foundry(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'foundry.toml').write_text('[profile.default]\nsrc = "src"')
        detector = FrameworkDetector()
        self.assertEqual(detector.detect(self.tmp_dir), 'foundry')

    def test_detect_hardhat_js(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'hardhat.config.js').write_text('module.exports = {}')
        detector = FrameworkDetector()
        self.assertEqual(detector.detect(self.tmp_dir), 'hardhat')

    def test_detect_hardhat_ts(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'hardhat.config.ts').write_text('export default {}')
        detector = FrameworkDetector()
        self.assertEqual(detector.detect(self.tmp_dir), 'hardhat')

    def test_detect_truffle(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'truffle-config.js').write_text('module.exports = {}')
        detector = FrameworkDetector()
        self.assertEqual(detector.detect(self.tmp_dir), 'truffle')

    def test_detect_unknown_framework(self):
        from core.framework_detector import FrameworkDetector
        detector = FrameworkDetector()
        self.assertIsNone(detector.detect(self.tmp_dir))

    def test_foundry_takes_priority(self):
        """When both foundry.toml and hardhat.config.js exist, foundry wins."""
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'foundry.toml').write_text('[profile.default]')
        (self.tmp_dir / 'hardhat.config.js').write_text('module.exports = {}')
        detector = FrameworkDetector()
        self.assertEqual(detector.detect(self.tmp_dir), 'foundry')

    def test_supports_framework(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'foundry.toml').write_text('')
        detector = FrameworkDetector()
        self.assertTrue(detector.supports_framework(self.tmp_dir))

    def test_read_config_foundry(self):
        from core.framework_detector import FrameworkDetector
        config_content = '[profile.default]\nsrc = "src"\nsolc = "0.8.20"'
        (self.tmp_dir / 'foundry.toml').write_text(config_content)
        detector = FrameworkDetector()
        config = detector.read_config(self.tmp_dir)
        self.assertEqual(config['framework'], 'foundry')
        self.assertIn('raw', config)

    def test_get_solc_version_foundry(self):
        from core.framework_detector import FrameworkDetector
        (self.tmp_dir / 'foundry.toml').write_text(
            '[profile.default]\nsolc = "0.8.20"\n'
        )
        detector = FrameworkDetector()
        version = detector.get_solc_version(self.tmp_dir)
        self.assertEqual(version, '0.8.20')


if __name__ == '__main__':
    unittest.main()
