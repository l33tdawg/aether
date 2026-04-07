"""
SAGE Knowledge Seeder — Loads pre-trained institutional knowledge into SAGE.

Ships seed data as JSON fixtures under ``data/sage_seeds/``. On first launch
(or version bump) the seeder bulk-loads all fixtures into SAGE so every fresh
Aether checkout starts with full institutional audit knowledge.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEED_DIR = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
_SEED_VERSION = "1.0.0"


class SageSeeder:
    """Loads pre-trained audit knowledge into SAGE."""

    def __init__(self, sage_client: Optional[Any] = None):
        from core.sage_client import SageClient
        self._client = sage_client or SageClient.get_instance()
        self._seed_dir = _SEED_DIR

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed_all(self, force: bool = False) -> Dict[str, int]:
        """Seed SAGE with all knowledge fixtures.

        Checks ``_seed_version`` in SAGE ``sage-meta`` domain. Skips if
        the current version is already seeded (unless *force* is True).

        Returns:
            Counts per category, e.g. ``{"exploits": 75, "archetypes": 77, ...}``
        """
        if not force and self._is_current_version():
            logger.info("SAGE already seeded with version %s, skipping", _SEED_VERSION)
            return {"status": "already_seeded", "version": _SEED_VERSION}

        counts: Dict[str, int] = {}
        counts["exploits"] = self.seed_exploits()
        counts["archetypes"] = self.seed_archetypes()
        counts["token_quirks"] = self.seed_token_quirks()
        counts["historical_exploits"] = self.seed_historical_exploits()

        # Mark version
        try:
            self._client.remember(
                content=f"Aether knowledge base seeded: version {_SEED_VERSION}",
                domain="sage-meta",
                memory_type="fact",
                confidence=0.99,
                tags=["seed-version", _SEED_VERSION],
            )
        except Exception as exc:
            logger.debug("Failed to store seed version marker: %s", exc)

        total = sum(v for v in counts.values() if isinstance(v, int))
        logger.info("SAGE seeded %d memories (version %s)", total, _SEED_VERSION)
        return counts

    def seed_exploits(self) -> int:
        """Seed exploit patterns from fixture."""
        return self._seed_fixture("exploit_patterns.json", "exploit-patterns", "fact", 0.95)

    def seed_archetypes(self) -> int:
        """Seed protocol archetype checklists from fixture."""
        entries = self._load_fixture("protocol_archetypes.json")
        count = 0
        for entry in entries:
            domain = entry.get("domain", "protocol-unknown")
            try:
                self._client.remember(
                    content=entry["content"],
                    domain=domain,
                    memory_type="fact",
                    confidence=0.93,
                    tags=entry.get("tags", []),
                )
                count += 1
            except Exception as exc:
                logger.debug("Failed to seed archetype entry: %s", exc)
        return count

    def seed_token_quirks(self) -> int:
        """Seed token quirks from fixture."""
        return self._seed_fixture("token_quirks.json", "token-quirks", "fact", 0.92)

    def seed_historical_exploits(self) -> int:
        """Seed curated historical exploit summaries."""
        return self._seed_fixture("historical_exploits.json", "historical-exploits", "fact", 0.98)

    # ------------------------------------------------------------------
    # Fixture generation (dev-time tool)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_seed_fixtures(output_dir: Optional[Path] = None) -> Dict[str, int]:
        """Read Python knowledge bases and export JSON seed fixtures.

        Call this when the underlying knowledge bases are updated to
        regenerate the shipped fixtures.
        """
        out = output_dir or _SEED_DIR
        out.mkdir(parents=True, exist_ok=True)
        counts: Dict[str, int] = {}

        # --- Exploit patterns ---
        from core.exploit_knowledge_base import ExploitKnowledgeBase
        kb = ExploitKnowledgeBase()
        exploit_entries = []
        for pat in kb.all_patterns:
            exploit_entries.append({
                "content": (
                    f"[{pat.id}] {pat.name} ({pat.category.value}, {pat.severity}): "
                    f"{pat.description} | Mechanism: {pat.exploit_mechanism} | "
                    f"Indicators: {', '.join(pat.code_indicators[:5])} | "
                    f"Missing: {', '.join(pat.missing_protections[:3])} | "
                    f"Examples: {', '.join(pat.real_world_examples[:3])}"
                ),
                "tags": [
                    pat.id, pat.category.value, pat.severity,
                    *(a.value for a in pat.applicable_archetypes),
                ],
            })
        _write_fixture(out / "exploit_patterns.json", exploit_entries)
        counts["exploits"] = len(exploit_entries)

        # --- Protocol archetypes ---
        from core.protocol_archetypes import (
            ProtocolArchetype, get_checklists_for_result, ArchetypeResult
        )
        archetype_entries = []
        for arch in ProtocolArchetype:
            if arch == ProtocolArchetype.UNKNOWN:
                continue
            dummy_result = ArchetypeResult(primary=arch, confidence=1.0)
            checklist = get_checklists_for_result(dummy_result)
            for item in checklist:
                archetype_entries.append({
                    "content": (
                        f"[{arch.value}] {item.name} ({item.severity}): "
                        f"{item.description} | Exploit precedent: {item.exploit_precedent} | "
                        f"Detection: {item.detection_prompt[:200]}"
                    ),
                    "domain": f"protocol-{arch.value}",
                    "tags": [arch.value, item.severity, item.name],
                })
        _write_fixture(out / "protocol_archetypes.json", archetype_entries)
        counts["archetypes"] = len(archetype_entries)

        # --- Token quirks ---
        from core.token_quirks import TOKEN_QUIRKS
        quirk_entries = []
        for q in TOKEN_QUIRKS:
            quirk_entries.append({
                "content": (
                    f"{q.name} ({q.severity}): {q.description} | "
                    f"Known tokens: {', '.join(q.known_tokens[:5])} | "
                    f"Exploit: {q.exploit_scenario[:200]} | "
                    f"Fix: {q.missing_protection[:200]}"
                ),
                "tags": [q.name, q.severity, *q.archetype_relevance[:3]],
            })
        _write_fixture(out / "token_quirks.json", quirk_entries)
        counts["token_quirks"] = len(quirk_entries)

        # --- Historical exploits ---
        historical = _build_historical_exploits()
        _write_fixture(out / "historical_exploits.json", historical)
        counts["historical_exploits"] = len(historical)

        # --- Manifest ---
        manifest = {
            "version": _SEED_VERSION,
            "checksums": {},
        }
        for fname in ["exploit_patterns.json", "protocol_archetypes.json",
                       "token_quirks.json", "historical_exploits.json"]:
            fpath = out / fname
            if fpath.exists():
                manifest["checksums"][fname] = hashlib.sha256(
                    fpath.read_bytes()
                ).hexdigest()
        _write_fixture(out / "manifest.json", manifest)

        return counts

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_current_version(self) -> bool:
        """Check if SAGE already has the current seed version."""
        try:
            memories = self._client.recall(
                query=f"seed-version {_SEED_VERSION}",
                domain="sage-meta",
                top_k=1,
            )
            for m in memories:
                content = m.get("content", "")
                if _SEED_VERSION in content:
                    return True
        except Exception:
            pass
        return False

    def _load_fixture(self, filename: str) -> List[Dict[str, Any]]:
        """Load a JSON fixture file."""
        fpath = self._seed_dir / filename
        if not fpath.exists():
            logger.warning("Seed fixture not found: %s", fpath)
            return []
        try:
            return json.loads(fpath.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load fixture %s: %s", filename, exc)
            return []

    def _seed_fixture(
        self, filename: str, domain: str, memory_type: str, confidence: float
    ) -> int:
        """Load fixture and remember each entry."""
        entries = self._load_fixture(filename)
        count = 0
        for entry in entries:
            content = entry if isinstance(entry, str) else entry.get("content", "")
            tags = entry.get("tags", []) if isinstance(entry, dict) else []
            if not content:
                continue
            try:
                self._client.remember(
                    content=content,
                    domain=domain,
                    memory_type=memory_type,
                    confidence=confidence,
                    tags=tags,
                )
                count += 1
            except Exception as exc:
                logger.debug("Failed to seed entry: %s", exc)
        return count


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _write_fixture(path: Path, data: Any) -> None:
    """Write JSON fixture to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _build_historical_exploits() -> List[Dict[str, Any]]:
    """Build curated list of major historical smart contract exploits."""
    return [
        {
            "content": "The DAO Hack (2016, $60M): Recursive reentrancy in splitDAO() allowed attacker to drain ETH by re-entering before balance update. Led to Ethereum hard fork. Root cause: external call before state update.",
            "tags": ["reentrancy", "critical", "2016", "dao"],
        },
        {
            "content": "Wormhole Bridge (2022, $326M): Missing signer verification in guardian set allowed forged VAA messages. Attacker called complete_transfer with fabricated signatures. Root cause: incomplete signature validation.",
            "tags": ["bridge", "signature", "critical", "2022"],
        },
        {
            "content": "Ronin Bridge (2022, $624M): 5 of 9 validator private keys compromised. Attacker signed fraudulent withdrawals. Root cause: insufficient validator decentralization and key management.",
            "tags": ["bridge", "access-control", "critical", "2022"],
        },
        {
            "content": "Euler Finance (2023, $197M): Donation attack via ERC-4626-like mechanism. Attacker inflated share price through direct token transfer then liquidated. Root cause: missing virtual shares/minimum deposit.",
            "tags": ["vault", "inflation-share", "critical", "2023"],
        },
        {
            "content": "Curve/Vyper Reentrancy (2023, $70M): Read-only reentrancy in Vyper compiler's @nonreentrant decorator. Attacker exploited cross-function reentrancy in stable pools. Root cause: compiler bug in reentrancy guard.",
            "tags": ["reentrancy", "dex", "critical", "2023"],
        },
        {
            "content": "Cream Finance (2021, $130M): Flash loan oracle manipulation. Attacker manipulated yUSDVault price oracle via large deposit, then used inflated collateral to borrow. Root cause: spot price oracle.",
            "tags": ["oracle", "flash-loan", "critical", "2021"],
        },
        {
            "content": "Nomad Bridge (2022, $190M): Message verification bypass allowed anyone to copy a successful transaction and replay with their own address. Root cause: zero-initialized trusted root accepted all messages.",
            "tags": ["bridge", "verification", "critical", "2022"],
        },
        {
            "content": "Harvest Finance (2020, $34M): Flash loan oracle manipulation via large Curve pool swap to deflate USDC/USDT price, deposit into vault at low price, reverse swap, withdraw at higher price. Root cause: TWAP oracle with no delay.",
            "tags": ["oracle", "flash-loan", "high", "2020"],
        },
        {
            "content": "Beanstalk (2022, $182M): Governance flash loan attack. Attacker borrowed enough tokens to reach quorum, proposed and executed malicious governance proposal in single transaction. Root cause: no voting delay/lock.",
            "tags": ["governance", "flash-loan", "critical", "2022"],
        },
        {
            "content": "Mango Markets (2022, $114M): Oracle manipulation via thin order book. Attacker took large perp position, then pumped MNGO oracle price to inflate unrealized PnL, used as collateral to borrow. Root cause: manipulable oracle.",
            "tags": ["oracle", "perpetual", "critical", "2022"],
        },
        {
            "content": "Parity Multisig (2017, $30M): Uninitialized library contract. Anyone could call initWallet() to become owner, then kill the library contract, freezing 513K ETH. Root cause: unprotected initialization.",
            "tags": ["access-control", "proxy", "critical", "2017"],
        },
        {
            "content": "BadgerDAO (2021, $120M): Compromised Cloudflare API key allowed frontend injection of malicious approve() calls. Users unknowingly approved attacker's address. Root cause: frontend supply chain attack.",
            "tags": ["access-control", "approval", "critical", "2021"],
        },
        {
            "content": "Wintermute (2022, $160M): Profanity vanity address vulnerability. Private key derived from weak entropy in vanity address generator. Root cause: brute-forceable address generation algorithm.",
            "tags": ["signature", "key-management", "critical", "2022"],
        },
        {
            "content": "BNB Bridge (2022, $586M): IAVL proof verification bypass. Attacker crafted proof for non-existent block to mint BNB. Root cause: insufficient Merkle proof validation.",
            "tags": ["bridge", "verification", "critical", "2022"],
        },
        {
            "content": "Compound (2021, $80M): Governance proposal bug in reward distribution. Incorrect comparison operator caused excess COMP distribution. Root cause: logic error in reward calculation.",
            "tags": ["governance", "logic", "high", "2021"],
        },
        {
            "content": "Rari/Fei (2022, $80M): Reentrancy in cToken borrow function. Attacker used reentrancy to borrow against same collateral multiple times. Root cause: CEI violation in lending pool.",
            "tags": ["reentrancy", "lending", "critical", "2022"],
        },
        {
            "content": "Cashio (2022, $48M): Insufficient validation of collateral backing. Attacker created fake LP tokens accepted as valid collateral to mint CASH stablecoin. Root cause: missing collateral verification.",
            "tags": ["validation", "stablecoin", "critical", "2022"],
        },
        {
            "content": "Poly Network (2021, $611M): Cross-chain relay allowed attacker to change keeper list by crafting message that called EthCrossChainData's putCurEpochConPkBytes. Root cause: unrestricted cross-chain message execution.",
            "tags": ["bridge", "access-control", "critical", "2021"],
        },
        {
            "content": "dForce/Lendf.Me (2020, $25M): ERC-777 reentrancy via tokensToSend hook in imBTC. Attacker re-entered supply() to inflate collateral. Root cause: ERC-777 callback not anticipated by lending protocol.",
            "tags": ["reentrancy", "token-quirk", "critical", "2020"],
        },
        {
            "content": "Balancer V2 (2023, $2M): Read-only reentrancy in nested pool joins. Attacker exploited rate provider callback during mid-join state to get stale exchange rate. Root cause: view function reentrancy.",
            "tags": ["reentrancy", "dex", "high", "2023"],
        },
    ]
