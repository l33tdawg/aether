"""Tests for core.sage_client — SAGE REST client."""

import json
import threading
import unittest
from unittest.mock import MagicMock, patch

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

    @patch("core.sage_client.requests.Session.get")
    def test_healthy(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        self.assertTrue(self.client.health_check())

    @patch("core.sage_client.requests.Session.get")
    def test_unhealthy_status(self, mock_get):
        mock_get.return_value = MagicMock(status_code=503)
        self.assertFalse(self.client.health_check())

    @patch("core.sage_client.requests.Session.get")
    def test_connection_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("refused")
        self.assertFalse(self.client.health_check())

    @patch("core.sage_client.requests.Session.get")
    def test_timeout(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout("timed out")
        self.assertFalse(self.client.health_check())


class TestSageClientRemember(unittest.TestCase):
    """remember() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")

    def tearDown(self):
        SageClient.reset_instance()

    @patch("core.sage_client.requests.Session.post")
    def test_remember_success(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"memory_id": "abc123", "status": "proposed"},
        )
        result = self.client.remember("test content", domain="test-domain")
        self.assertEqual(result["memory_id"], "abc123")

        # Verify payload
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        self.assertEqual(payload["content"], "test content")
        self.assertEqual(payload["domain"], "test-domain")
        self.assertEqual(payload["type"], "observation")
        self.assertEqual(payload["confidence"], 0.8)

    @patch("core.sage_client.requests.Session.post")
    def test_remember_with_tags(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"memory_id": "x"}
        )
        self.client.remember("x", tags=["a", "b"])
        payload = mock_post.call_args[1]["json"]
        self.assertEqual(payload["tags"], ["a", "b"])

    @patch("core.sage_client.requests.Session.post")
    def test_remember_connection_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError()
        result = self.client.remember("x")
        self.assertEqual(result, {})

    @patch("core.sage_client.requests.Session.post")
    def test_remember_timeout(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.Timeout()
        result = self.client.remember("x")
        self.assertEqual(result, {})


class TestSageClientRecall(unittest.TestCase):
    """recall() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")

    def tearDown(self):
        SageClient.reset_instance()

    @patch("core.sage_client.requests.Session.post")
    def test_recall_returns_memories_list(self, mock_post):
        memories = [{"content": "finding A", "confidence": 0.9}]
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"memories": memories}
        )
        result = self.client.recall("test query", domain="test")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["content"], "finding A")

    @patch("core.sage_client.requests.Session.post")
    def test_recall_handles_raw_list_response(self, mock_post):
        """Some API versions return a raw list."""
        memories = [{"content": "x"}]
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: memories
        )
        result = self.client.recall("q")
        self.assertEqual(len(result), 1)

    @patch("core.sage_client.requests.Session.post")
    def test_recall_connection_error_returns_empty(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError()
        result = self.client.recall("q")
        self.assertEqual(result, [])

    @patch("core.sage_client.requests.Session.post")
    def test_recall_with_top_k(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"memories": []}
        )
        self.client.recall("q", top_k=10)
        payload = mock_post.call_args[1]["json"]
        self.assertEqual(payload["top_k"], 10)


class TestSageClientReflect(unittest.TestCase):
    """reflect() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")

    def tearDown(self):
        SageClient.reset_instance()

    @patch("core.sage_client.requests.Session.post")
    def test_reflect_success(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"status": "ok"}
        )
        result = self.client.reflect(
            dos=["use X"], donts=["avoid Y"], domain="test"
        )
        self.assertEqual(result["status"], "ok")
        payload = mock_post.call_args[1]["json"]
        self.assertEqual(payload["dos"], ["use X"])
        self.assertEqual(payload["donts"], ["avoid Y"])

    @patch("core.sage_client.requests.Session.post")
    def test_reflect_failure_returns_empty(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError()
        result = self.client.reflect(dos=[], donts=[])
        self.assertEqual(result, {})


class TestSageClientGetStatus(unittest.TestCase):
    """get_status() tests."""

    def setUp(self):
        SageClient.reset_instance()
        self.client = SageClient("http://test:8080")

    def tearDown(self):
        SageClient.reset_instance()

    @patch("core.sage_client.requests.Session.get")
    def test_status_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"total_memories": 100},
        )
        mock_get.return_value.raise_for_status = MagicMock()
        result = self.client.get_status()
        self.assertEqual(result["total_memories"], 100)

    @patch("core.sage_client.requests.Session.get")
    def test_status_failure(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError()
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


if __name__ == "__main__":
    unittest.main()
