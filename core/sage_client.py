"""
SAGE Client — REST client for SAGE institutional memory system.

Provides a thread-safe singleton client that communicates with a SAGE node
over its REST API. All methods degrade gracefully — if SAGE is unavailable,
methods return empty results and log a warning rather than raising.
"""

import hashlib
import logging
import threading
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_DEFAULT_SAGE_URL = "http://localhost:8080"
_REQUEST_TIMEOUT = 10  # seconds


class SageClient:
    """Thread-safe singleton REST client for SAGE institutional memory."""

    _instance: Optional["SageClient"] = None
    _lock = threading.Lock()

    def __init__(self, sage_url: str = _DEFAULT_SAGE_URL):
        self._base_url = sage_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, sage_url: str = _DEFAULT_SAGE_URL) -> "SageClient":
        """Return the singleton SageClient, creating it if needed."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(sage_url)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing only)."""
        with cls._lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Health & Status
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Return True if the SAGE node is reachable and healthy."""
        try:
            resp = self._session.get(
                f"{self._base_url}/v1/dashboard/health",
                timeout=_REQUEST_TIMEOUT,
            )
            return resp.status_code == 200
        except Exception as exc:
            logger.debug("SAGE health check failed: %s", exc)
            return False

    def get_status(self) -> Dict[str, Any]:
        """Return SAGE node status dict, or empty dict on failure."""
        try:
            resp = self._session.get(
                f"{self._base_url}/v1/dashboard/status",
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("SAGE status request failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Memory Operations
    # ------------------------------------------------------------------

    def remember(
        self,
        content: str,
        domain: str = "general",
        memory_type: str = "observation",
        confidence: float = 0.8,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Store a memory in SAGE. Returns the response dict or {} on failure."""
        payload: Dict[str, Any] = {
            "content": content,
            "domain": domain,
            "type": memory_type,
            "confidence": confidence,
        }
        if tags:
            payload["tags"] = tags
        return self._post("/v1/memory/remember", payload)

    def recall(
        self,
        query: str,
        domain: str = "general",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Retrieve relevant memories from SAGE. Returns list of memory dicts."""
        payload = {"query": query, "domain": domain, "top_k": top_k}
        result = self._post("/v1/memory/recall", payload)
        # The API may return memories under different keys
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("memories", result.get("results", []))
        return []

    def reflect(
        self,
        dos: List[str],
        donts: List[str],
        domain: str = "general",
    ) -> Dict[str, Any]:
        """Submit a reflection (dos/don'ts) to SAGE."""
        payload = {"dos": dos, "donts": donts, "domain": domain}
        return self._post("/v1/memory/reflect", payload)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def content_hash(content: str) -> str:
        """Return a short SHA-256 hex digest for deduplication."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST JSON to SAGE and return the parsed response, or {} on error."""
        try:
            resp = self._session.post(
                f"{self._base_url}{path}",
                json=payload,
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            logger.debug("SAGE not reachable at %s", self._base_url)
            return {}
        except requests.exceptions.Timeout:
            logger.warning("SAGE request timed out: POST %s", path)
            return {}
        except Exception as exc:
            logger.warning("SAGE request failed: %s", exc)
            return {}
