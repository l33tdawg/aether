"""Tests for core.sage_client — SAGE SDK wrapper client."""

import threading
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from core.sage_client import SageClient


class TestSageClientSingleton(unittest.TestCase):
    """Singleton and lifecycle tests."""

    def setUp(self):
        SageClient.reset_instance()

    def tearDown(self):
        SageClient.reset_instance()

    def test_get_instance_returns_same_object(self):
        a = SageClient.get_instance("http://localhost:9999")
        b = SageClient.get_instance("http://localhost:9999")
        self.assertIs(a, b)

    def test_reset_instance_clears_singleton(self):
        a = SageClient.get_instance()
        SageClient.reset_instance()
        b = SageClient.get_instance()
        self.assertIsNot(a, b)

    def test_thread_safe_singleton(self):
        """Multiple threads should all get the same instance."""
        instances = []

        def grab():
            instances.append(SageClient.get_instance())

        threads = [threading.Thread(target=grab) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertTrue(all(inst is instances[0] for inst in instances))


class TestSageClientHealthCheck(unittest.TestCase):
    """health_check() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")

    def tearDown(self):
        SageClient.reset_instance()

    def test_healthy_with_sdk(self):
        mock_sdk = MagicMock()
        mock_sdk.health.return_value = {"sage": "running", "chain": {"block_height": "100"}}
        self.client._sdk_client = mock_sdk
        self.client._sdk_checked = True
        self.assertTrue(self.client.health_check())

    def test_healthy_v4_format(self):
        mock_sdk = MagicMock()
        mock_sdk.health.return_value = {"chain": {"block_height": "100"}}
        self.client._sdk_client = mock_sdk
        self.client._sdk_checked = True
        self.assertTrue(self.client.health_check())

    def test_unhealthy_no_sdk(self):
        self.client._sdk_client = None
        self.client._sdk_checked = True
        self.assertFalse(self.client.health_check())

    def test_connection_error(self):
        mock_sdk = MagicMock()
        mock_sdk.health.side_effect = Exception("connection refused")
        self.client._sdk_client = mock_sdk
        self.client._sdk_checked = True
        self.assertFalse(self.client.health_check())


class TestSageClientRemember(unittest.TestCase):
    """remember() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")
        self.mock_sdk = MagicMock()
        self.client._sdk_client = self.mock_sdk
        self.client._sdk_checked = True

    def tearDown(self):
        SageClient.reset_instance()

    def test_remember_success(self):
        mock_result = MagicMock()
        mock_result.memory_id = "abc123"
        mock_result.tx_hash = "TX123"
        self.mock_sdk.propose.return_value = mock_result

        result = self.client.remember("test content", domain="test-domain")
        self.assertEqual(result["memory_id"], "abc123")
        self.assertEqual(result["status"], "proposed")

        # Verify propose was called with correct args
        self.mock_sdk.propose.assert_called_once()
        call_kwargs = self.mock_sdk.propose.call_args[1]
        self.assertIn("test content", call_kwargs["content"])
        self.assertEqual(call_kwargs["domain_tag"], "test-domain")
        self.assertEqual(call_kwargs["memory_type"], "observation")

    def test_remember_with_tags(self):
        mock_result = MagicMock()
        mock_result.memory_id = "x"
        mock_result.tx_hash = "y"
        self.mock_sdk.propose.return_value = mock_result

        self.client.remember("x", tags=["a", "b"])
        content = self.mock_sdk.propose.call_args[1]["content"]
        self.assertIn("[tags: a, b]", content)

    def test_remember_no_sdk(self):
        self.client._sdk_client = None
        result = self.client.remember("x")
        self.assertEqual(result, {})

    def test_remember_failure(self):
        self.mock_sdk.propose.side_effect = Exception("network error")
        result = self.client.remember("x")
        self.assertEqual(result, {})


class TestSageClientRecall(unittest.TestCase):
    """recall() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")
        self.mock_sdk = MagicMock()
        self.client._sdk_client = self.mock_sdk
        self.client._sdk_checked = True

    def tearDown(self):
        SageClient.reset_instance()

    def test_recall_returns_memories(self):
        mock_mem = MagicMock()
        mock_mem.content = "reentrancy finding A with external call"
        mock_mem.confidence_score = 0.9
        mock_mem.domain_tag = "test"
        mock_mem.memory_id = "mem1"

        mock_result = MagicMock()
        mock_result.memories = [mock_mem]
        self.mock_sdk.list_memories.return_value = mock_result

        result = self.client.recall("reentrancy external call", domain="test")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["content"], "reentrancy finding A with external call")

    def test_recall_no_sdk(self):
        self.client._sdk_client = None
        result = self.client.recall("q")
        self.assertEqual(result, [])

    def test_recall_failure(self):
        self.mock_sdk.list_memories.side_effect = Exception("failed")
        result = self.client.recall("q")
        self.assertEqual(result, [])

    def test_recall_filters_by_keyword(self):
        """Only memories matching query keywords should be returned."""
        mem1 = MagicMock()
        mem1.content = "reentrancy vulnerability in withdraw"
        mem1.confidence_score = 0.9
        mem1.domain_tag = "test"
        mem1.memory_id = "m1"

        mem2 = MagicMock()
        mem2.content = "oracle price manipulation"
        mem2.confidence_score = 0.8
        mem2.domain_tag = "test"
        mem2.memory_id = "m2"

        mock_result = MagicMock()
        mock_result.memories = [mem1, mem2]
        self.mock_sdk.list_memories.return_value = mock_result

        result = self.client.recall("reentrancy withdraw", domain="test", top_k=5)
        self.assertEqual(len(result), 1)
        self.assertIn("reentrancy", result[0]["content"])


class TestSageClientReflect(unittest.TestCase):
    """reflect() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")
        self.mock_sdk = MagicMock()
        self.client._sdk_client = self.mock_sdk
        self.client._sdk_checked = True

    def tearDown(self):
        SageClient.reset_instance()

    def test_reflect_stores_as_memory(self):
        mock_result = MagicMock()
        mock_result.memory_id = "ref1"
        mock_result.tx_hash = "TX"
        self.mock_sdk.propose.return_value = mock_result

        result = self.client.reflect(
            dos=["use X"], donts=["avoid Y"], domain="test"
        )
        self.assertEqual(result["status"], "proposed")
        content = self.mock_sdk.propose.call_args[1]["content"]
        self.assertIn("DO: use X", content)
        self.assertIn("DON'T: avoid Y", content)

    def test_reflect_empty(self):
        result = self.client.reflect(dos=[], donts=[])
        self.assertEqual(result, {})


class TestSageClientGetStatus(unittest.TestCase):
    """get_status() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")
        self.mock_sdk = MagicMock()
        self.client._sdk_client = self.mock_sdk
        self.client._sdk_checked = True

    def tearDown(self):
        SageClient.reset_instance()

    def test_status_success(self):
        self.mock_sdk.health.return_value = {"total_memories": 100}
        result = self.client.get_status()
        self.assertEqual(result["total_memories"], 100)

    def test_status_failure(self):
        self.mock_sdk.health.side_effect = Exception("down")
        result = self.client.get_status()
        self.assertEqual(result, {})


class TestSageClientContentHash(unittest.TestCase):
    """content_hash() utility tests."""

    def test_deterministic(self):
        a = SageClient.content_hash("hello")
        b = SageClient.content_hash("hello")
        self.assertEqual(a, b)

    def test_different_inputs(self):
        a = SageClient.content_hash("hello")
        b = SageClient.content_hash("world")
        self.assertNotEqual(a, b)

    def test_length(self):
        h = SageClient.content_hash("test")
        self.assertEqual(len(h), 16)


class TestSageClientHashEmbedding(unittest.TestCase):
    """_hash_embedding() tests."""

    def test_deterministic(self):
        a = SageClient._hash_embedding("hello")
        b = SageClient._hash_embedding("hello")
        self.assertEqual(a, b)

    def test_correct_dimension(self):
        emb = SageClient._hash_embedding("test", dim=768)
        self.assertEqual(len(emb), 768)

    def test_normalized(self):
        emb = SageClient._hash_embedding("test")
        norm = sum(f * f for f in emb) ** 0.5
        self.assertAlmostEqual(norm, 1.0, places=5)


if __name__ == "__main__":
    unittest.main()
