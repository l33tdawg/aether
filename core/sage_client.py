"""
SAGE Client — Wrapper around the official sage-agent-sdk for Aether.

Uses the ``sage-agent-sdk`` Python package (``pip install sage-agent-sdk``)
for authenticated communication with a SAGE node. Provides a simplified
interface matching Aether's needs (remember, recall, reflect) while
delegating all authentication and protocol handling to the SDK.

All methods degrade gracefully — if SAGE is unavailable, methods return
empty results and log a warning rather than raising.
"""

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_SAGE_URL = "http://localhost:8080"
_REQUEST_TIMEOUT = 10  # seconds


def _find_agent_key() -> Optional[Path]:
    """Locate the SAGE agent key file.

    Searches in order:
      1. SAGE_AGENT_KEY env var (explicit path)
      2. ~/.sage/agents/*/agent.key (first match)
    """
    env_path = os.environ.get("SAGE_AGENT_KEY")
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p

    sage_home = Path(os.environ.get("SAGE_HOME", "~/.sage")).expanduser()
    agents_dir = sage_home / "agents"
    if agents_dir.is_dir():
        for agent_dir in sorted(agents_dir.iterdir()):
            key_file = agent_dir / "agent.key"
            if key_file.exists():
                return key_file
    return None


class SageClient:
    """Thread-safe singleton client for SAGE institutional memory.

    Wraps ``sage_sdk.SageClient`` with graceful degradation and a simplified
    remember/recall/reflect interface.
    """

    _instance: Optional["SageClient"] = None
    _lock = threading.Lock()

    def __init__(self, sage_url: str = _DEFAULT_SAGE_URL):
        self._base_url = sage_url.rstrip("/")
        self._sdk_client = None
        self._sdk_checked = False
        self._agent_name = "aether"

    def _ensure_sdk(self):
        """Lazy-initialize the SDK client with agent identity."""
        if self._sdk_checked:
            return self._sdk_client
        self._sdk_checked = True
        try:
            from sage_sdk import SageClient as SDKClient, AgentIdentity

            key_path = _find_agent_key()
            if key_path:
                identity = AgentIdentity.from_file(str(key_path))
                logger.debug("SAGE identity loaded from %s", key_path)
            else:
                # Generate a new identity for this Aether instance
                sage_home = Path(os.environ.get("SAGE_HOME", "~/.sage")).expanduser()
                agent_dir = sage_home / "agents" / "aether-instance"
                agent_dir.mkdir(parents=True, exist_ok=True)
                key_file = agent_dir / "agent.key"
                if key_file.exists():
                    identity = AgentIdentity.from_file(str(key_file))
                else:
                    identity = AgentIdentity.generate()
                    identity.to_file(str(key_file))
                logger.debug("SAGE identity generated at %s", key_file)

            self._sdk_client = SDKClient(
                base_url=self._base_url,
                identity=identity,
                timeout=_REQUEST_TIMEOUT,
            )
            # Register agent if not already registered
            try:
                self._sdk_client.register_agent(
                    name=self._agent_name,
                    provider="aether",
                    boot_bio="Aether smart contract security analysis framework",
                )
            except Exception:
                pass  # Already registered or registration failed — fine either way

        except ImportError:
            logger.warning("sage-agent-sdk not installed — SAGE features disabled")
        except Exception as exc:
            logger.warning("Failed to initialize SAGE SDK: %s", exc)
        return self._sdk_client

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
            sdk = self._ensure_sdk()
            if sdk is None:
                return False
            result = sdk.health()
            return bool(result and (
                result.get("sage") == "running"
                or result.get("status") == "healthy"
                or "chain" in result
            ))
        except Exception as exc:
            logger.debug("SAGE health check failed: %s", exc)
            return False

    def get_status(self) -> Dict[str, Any]:
        """Return SAGE node status dict, or empty dict on failure."""
        try:
            sdk = self._ensure_sdk()
            if sdk is None:
                return {}
            return sdk.health()
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
        """Store a memory in SAGE via propose(). Returns response dict or {} on failure."""
        try:
            sdk = self._ensure_sdk()
            if sdk is None:
                return {}

            # Build content with tags inline (SAGE stores tags in content for keyword recall)
            tagged_content = content
            if tags:
                tagged_content = f"{content} [tags: {', '.join(tags)}]"

            result = sdk.propose(
                content=tagged_content,
                memory_type=memory_type,
                domain_tag=domain,
                confidence=confidence,
            )
            return {
                "memory_id": getattr(result, "memory_id", ""),
                "tx_hash": getattr(result, "tx_hash", ""),
                "status": "proposed",
            }
        except Exception as exc:
            logger.warning("SAGE remember failed: %s", exc)
            return {}

    def recall(
        self,
        query: str,
        domain: str = "general",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Retrieve relevant memories from SAGE.

        Uses ``list_memories`` filtered by domain and then does client-side
        keyword relevance ranking. This works reliably across all SAGE
        embedding modes (hash, ollama, cloud).
        """
        try:
            sdk = self._ensure_sdk()
            if sdk is None:
                return []

            # Fetch committed memories from the domain
            result = sdk.list_memories(
                domain=domain,
                status="committed",
                limit=min(top_k * 4, 50),  # Fetch extra for ranking
            )

            raw_memories = getattr(result, "memories", [])
            if not raw_memories:
                return []

            # Client-side keyword relevance ranking
            query_words = set(query.lower().split())
            scored = []
            for mem in raw_memories:
                content = getattr(mem, "content", "")
                content_lower = content.lower()
                # Score by keyword overlap
                score = sum(1 for w in query_words if w in content_lower)
                if score > 0:
                    scored.append((score, mem))

            # Sort by relevance, return top_k
            scored.sort(key=lambda x: -x[0])
            memories = []
            for _, mem in scored[:top_k]:
                memories.append({
                    "content": getattr(mem, "content", ""),
                    "confidence": getattr(mem, "confidence_score", 0.0),
                    "domain": getattr(mem, "domain_tag", domain),
                    "memory_id": getattr(mem, "memory_id", ""),
                    "tags": [],
                })
            return memories
        except Exception as exc:
            logger.warning("SAGE recall failed: %s", exc)
            return []

    def reflect(
        self,
        dos: List[str],
        donts: List[str],
        domain: str = "general",
    ) -> Dict[str, Any]:
        """Submit a reflection to SAGE as a memory with dos/don'ts."""
        try:
            content = ""
            if dos:
                content += "DO: " + "; ".join(dos)
            if donts:
                content += " | DON'T: " + "; ".join(donts)
            if content:
                return self.remember(
                    content=content.strip(),
                    domain=domain,
                    memory_type="observation",
                    confidence=0.85,
                    tags=["reflection"],
                )
            return {}
        except Exception as exc:
            logger.warning("SAGE reflect failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Session Memory (v6.0 Collaborative Pipeline)
    # ------------------------------------------------------------------

    def remember_session(self, content: str, session_domain: str) -> Dict[str, Any]:
        """Store a session record in SAGE for the collaborative audit pipeline.

        Convenience wrapper that uses memory_type='observation' and high
        confidence for intra-session records (findings, dismissals, protections).

        Args:
            content: JSON-encoded session record
            session_domain: Domain identifier, typically 'audit-session-{content_hash}'

        Returns:
            SAGE response dict, or {} on failure.

        Raises:
            RuntimeError: If SAGE is not available (v6.0: SAGE is required).
        """
        return self.remember(
            content=content,
            domain=session_domain,
            memory_type="observation",
            confidence=0.90,
            tags=["session-record"],
        )

    def recall_session(self, session_domain: str) -> List[Dict[str, Any]]:
        """Recall all session records for a collaborative audit pipeline session.

        Fetches all committed memories in the given session domain, returning
        them in full without keyword ranking (all records are relevant).

        Args:
            session_domain: Domain identifier, typically 'audit-session-{content_hash}'

        Returns:
            List of memory dicts with 'content', 'confidence', 'memory_id' keys.

        Raises:
            RuntimeError: If SAGE is not available (v6.0: SAGE is required).
        """
        try:
            sdk = self._ensure_sdk()
            if sdk is None:
                raise RuntimeError(
                    "SAGE institutional memory is required. Run: docker compose up -d"
                )

            result = sdk.list_memories(
                domain=session_domain,
                status="committed",
                limit=100,  # Session records are bounded by pass count
            )

            raw_memories = getattr(result, "memories", [])
            memories = []
            for mem in raw_memories:
                memories.append({
                    "content": getattr(mem, "content", ""),
                    "confidence": getattr(mem, "confidence_score", 0.0),
                    "domain": getattr(mem, "domain_tag", session_domain),
                    "memory_id": getattr(mem, "memory_id", ""),
                })
            return memories
        except RuntimeError:
            raise
        except Exception as exc:
            logger.warning("SAGE recall_session failed: %s", exc)
            raise RuntimeError(
                f"SAGE session recall failed: {exc}. "
                "SAGE institutional memory is required. Run: docker compose up -d"
            ) from exc

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def content_hash(content: str) -> str:
        """Return a short SHA-256 hex digest for deduplication."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _hash_embedding(text: str, dim: int = 768) -> List[float]:
        """Generate a deterministic pseudo-embedding via hashing.

        Matches SAGE's ``hash`` embedding mode used when Ollama is offline.
        Uses iterative hashing to produce stable float values in [-1, 1].
        """
        values = []
        seed = text.encode("utf-8")
        for i in range(dim):
            h = hashlib.sha256(seed + i.to_bytes(4, "little")).digest()
            # Convert first 4 bytes to unsigned int, map to [-1, 1]
            val = int.from_bytes(h[:4], "little")
            values.append((val / 2147483647.5) - 1.0)
        # Normalize to unit vector
        norm = sum(v * v for v in values) ** 0.5
        if norm > 0:
            return [v / norm for v in values]
        return [0.0] * dim
