"""
Contract Scanner — intelligent classification and audit-worthiness scoring.

Scans a directory of Solidity contracts, classifies each file (core protocol,
interface, library, test, mock, script, abstract), and scores core contracts
on a 0-100 scale across 7 categories of audit relevance.  No LLM calls, no
DB access, no heavy imports — pure static heuristics.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Enums ──────────────────────────────────────────────────────────────

class ContractClassification(Enum):
    """Classification for a Solidity source file."""
    CORE_PROTOCOL = "core_protocol"
    INTERFACE = "interface"
    LIBRARY = "library"
    ABSTRACT = "abstract"
    TEST = "test"
    MOCK = "mock"
    SCRIPT = "script"


class PriorityTier(Enum):
    """Audit-priority tier derived from the numeric score."""
    CRITICAL = "critical"   # >= 70
    HIGH = "high"           # >= 50
    MEDIUM = "medium"       # >= 30
    LOW = "low"             # >= 15
    SKIP = "skip"           # < 15 or non-core


def _score_to_priority(score: int, classification: ContractClassification) -> PriorityTier:
    """Map a numeric score + classification to a priority tier."""
    if classification != ContractClassification.CORE_PROTOCOL:
        return PriorityTier.SKIP
    if score >= 70:
        return PriorityTier.CRITICAL
    if score >= 50:
        return PriorityTier.HIGH
    if score >= 30:
        return PriorityTier.MEDIUM
    if score >= 15:
        return PriorityTier.LOW
    return PriorityTier.SKIP


# ── Data classes ───────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result for a single scanned file."""
    file_path: Path
    contract_name: str
    classification: ContractClassification
    score: int  # 0-100
    priority: PriorityTier
    line_count: int
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    signals: List[str] = field(default_factory=list)


@dataclass
class DiscoveryReport:
    """Aggregated result of scanning a directory."""
    root_path: Path
    total_files: int
    scanned: int
    skipped: int
    results: List[ScanResult] = field(default_factory=list)
    scan_time_ms: int = 0

    @property
    def recommended(self) -> List[ScanResult]:
        """Return CRITICAL + HIGH + MEDIUM results (the auto-select set)."""
        keep = {PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM}
        return [r for r in self.results if r.priority in keep]


# ── Directories to skip ───────────────────────────────────────────────

SKIP_DIRS = {
    # Build / dependency artifacts
    "lib", "libs", "node_modules", "out", "artifacts", "cache",
    "build", "dist", ".git", "venv", "env",
    # Test / mock / script directories
    "test", "tests", "mock", "mocks", "script", "scripts",
    "deploy", "deployments", "migrations",
    # Well-known dependency directories
    "forge-std", "openzeppelin-contracts", "openzeppelin",
    "@openzeppelin", "solmate", "solady", "prb-math",
    "ds-test", "hardhat", "typechain", "typechain-types",
}


# ── Classification regexes ─────────────────────────────────────────────

_RE_INTERFACE = re.compile(
    r'^\s*interface\s+\w+', re.MULTILINE
)
_RE_CONTRACT = re.compile(
    r'^\s*contract\s+\w+', re.MULTILINE
)
_RE_LIBRARY = re.compile(
    r'^\s*library\s+\w+', re.MULTILINE
)
_RE_ABSTRACT = re.compile(
    r'^\s*abstract\s+contract\s+\w+', re.MULTILINE
)
_RE_FORGE_IMPORT = re.compile(
    r'import\s+.*(?:forge-std|ds-test|Test\.sol|Script\.sol)', re.MULTILINE
)
_RE_IS_TEST = re.compile(
    r'is\s+(?:\w+\s*,\s*)*Test\b', re.MULTILINE
)
_RE_IS_SCRIPT = re.compile(
    r'is\s+(?:\w+\s*,\s*)*Script\b', re.MULTILINE
)

# ── Scoring regexes ────────────────────────────────────────────────────

# Value handling (max 25)
_RE_PAYABLE = re.compile(r'\bpayable\b')
_RE_VALUE_CALL = re.compile(r'\.call\{value\s*:')
_RE_TRANSFER_SEND = re.compile(r'\.(transfer|send)\s*\(')
_RE_IERC20 = re.compile(r'\bIERC20\b|\bsafeTransfer\b|\bsafeTransferFrom\b')
_RE_MSG_VALUE = re.compile(r'\bmsg\.value\b')

# External interactions (max 20)
_RE_DELEGATECALL = re.compile(r'\bdelegatecall\b')
_RE_LOW_LEVEL_CALL = re.compile(r'\.(call|staticcall)\s*[\({]')
_RE_INTERFACE_CAST = re.compile(r'I[A-Z]\w+\([^)]*\)\.\w+\(')

# State complexity (max 15)
_RE_MAPPING = re.compile(r'\bmapping\s*\(')
_RE_NESTED_MAPPING = re.compile(r'\bmapping\s*\([^)]*mapping\s*\(')
_RE_STATE_VAR = re.compile(r'^\s+\w+(?:\[\])?\s+(?:public|private|internal)\s+\w+', re.MULTILINE)

# Access surface (max 10)
_RE_PUBLIC_EXTERNAL = re.compile(
    r'function\s+\w+\s*\([^)]*\)\s+(?:external|public)\b', re.MULTILINE
)
_RE_ACCESS_MODIFIER = re.compile(
    r'\b(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyMinter|require\s*\(\s*msg\.sender)\b'
)

# Code complexity (max 10)
_RE_ASSEMBLY = re.compile(r'\bassembly\s*\{')
_RE_UNCHECKED = re.compile(r'\bunchecked\s*\{')

# Upgrade / proxy (max 5)
_RE_UPGRADEABLE = re.compile(r'\b(?:Upgradeable|UUPSUpgradeable|TransparentUpgradeable)\b')
_RE_INITIALIZER = re.compile(r'\binitialize\s*\(|\binitializer\b')
_RE_PROXY = re.compile(r'\bProxy\b|\b_implementation\b|\bimplementation\(\)')


# ── Scanner ────────────────────────────────────────────────────────────

class ContractScanner:
    """Scans Solidity files for classification and audit-worthiness scoring."""

    def scan_directory(self, root: Path) -> DiscoveryReport:
        """Walk *root*, classify and score every .sol file found."""
        root = Path(root).resolve()
        t0 = time.monotonic()

        sol_files: List[Path] = []
        skipped = 0

        for dirpath, dirnames, filenames in root.walk():
            # Prune skip dirs in-place
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            for fname in filenames:
                if fname.endswith(".sol"):
                    fp = dirpath / fname
                    # Double-check no skip dir in parents
                    try:
                        rel_parts = fp.relative_to(root).parts
                    except ValueError:
                        rel_parts = ()
                    if any(p.lower() in SKIP_DIRS for p in rel_parts[:-1]):
                        skipped += 1
                        continue
                    sol_files.append(fp)

        results: List[ScanResult] = []
        for fp in sol_files:
            try:
                results.append(self.scan_file(fp))
            except Exception:
                skipped += 1

        # Sort by score descending, then by name
        results.sort(key=lambda r: (-r.score, r.contract_name.lower()))

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return DiscoveryReport(
            root_path=root,
            total_files=len(sol_files) + skipped,
            scanned=len(results),
            skipped=skipped,
            results=results,
            scan_time_ms=elapsed_ms,
        )

    def scan_file(self, file_path: Path) -> ScanResult:
        """Classify and score a single Solidity file."""
        file_path = Path(file_path).resolve()
        content = file_path.read_text(errors="replace")
        line_count = content.count("\n") + 1
        name = file_path.stem

        classification = self._classify(file_path, content)
        score, breakdown, signals = self._compute_score(file_path, content, classification)
        priority = _score_to_priority(score, classification)

        return ScanResult(
            file_path=file_path,
            contract_name=name,
            classification=classification,
            score=score,
            priority=priority,
            line_count=line_count,
            score_breakdown=breakdown,
            signals=signals,
        )

    # ── Classification ─────────────────────────────────────────────

    def _classify(self, file_path: Path, content: str) -> ContractClassification:
        """Classify a file by path heuristics first, then content heuristics."""
        fname = file_path.name.lower()
        stem = file_path.stem.lower()
        parts = [p.lower() for p in file_path.parts]

        # Path-based heuristics (highest priority)
        if fname.endswith(".t.sol"):
            return ContractClassification.TEST
        if fname.endswith(".s.sol"):
            return ContractClassification.SCRIPT
        if "mock" in stem or any(p in ("mock", "mocks") for p in parts):
            return ContractClassification.MOCK
        if any(p in ("test", "tests") for p in parts):
            return ContractClassification.TEST
        if any(p in ("script", "scripts", "deploy", "deployments", "migrations") for p in parts):
            return ContractClassification.SCRIPT

        # Content-based heuristics
        has_interface = bool(_RE_INTERFACE.search(content))
        has_contract = bool(_RE_CONTRACT.search(content))
        has_library = bool(_RE_LIBRARY.search(content))
        has_abstract = bool(_RE_ABSTRACT.search(content))

        # Forge test/script inheritance
        if _RE_IS_TEST.search(content) or _RE_FORGE_IMPORT.search(content) and _RE_IS_TEST.search(content):
            return ContractClassification.TEST
        if _RE_IS_SCRIPT.search(content):
            return ContractClassification.SCRIPT

        # Pure interface file (no concrete contract or library)
        if has_interface and not has_contract and not has_library:
            return ContractClassification.INTERFACE

        # Pure library file
        if has_library and not has_contract and not has_interface:
            return ContractClassification.LIBRARY

        # Pure abstract file (all contract declarations are abstract)
        # _RE_CONTRACT matches "contract X" which also matches inside "abstract contract X",
        # so we subtract abstract matches from the total to find concrete-only contracts.
        concrete_count = len(_RE_CONTRACT.findall(content))
        abstract_count = len(_RE_ABSTRACT.findall(content))
        concrete_only = concrete_count - abstract_count
        if has_abstract and concrete_only <= 0:
            return ContractClassification.ABSTRACT

        return ContractClassification.CORE_PROTOCOL

    # ── Scoring ────────────────────────────────────────────────────

    def _compute_score(
        self,
        file_path: Path,
        content: str,
        classification: ContractClassification,
    ) -> Tuple[int, Dict[str, int], List[str]]:
        """Compute audit-worthiness score for a file.

        Non-core contracts always score 0.  Core contracts are scored across
        7 categories (max 100).
        """
        if classification != ContractClassification.CORE_PROTOCOL:
            return 0, {}, []

        breakdown: Dict[str, int] = {}
        signals: List[str] = []

        # 1. Value handling (max 25)
        val_score = 0
        payable_count = len(_RE_PAYABLE.findall(content))
        if payable_count:
            val_score += min(8, payable_count * 2)
            signals.append(f"payable ({payable_count})")
        if _RE_VALUE_CALL.search(content):
            val_score += 7
            signals.append("call{value}")
        if _RE_TRANSFER_SEND.search(content):
            val_score += 5
            signals.append("transfer/send")
        ierc20_matches = len(_RE_IERC20.findall(content))
        if ierc20_matches:
            val_score += min(10, ierc20_matches * 3)
            signals.append("ERC20 transfers")
        if _RE_MSG_VALUE.search(content):
            val_score += 3
            signals.append("msg.value")
        breakdown["value_handling"] = min(25, val_score)

        # 2. External interactions (max 20)
        ext_score = 0
        if _RE_DELEGATECALL.search(content):
            ext_score += 10
            signals.append("delegatecall")
        if _RE_LOW_LEVEL_CALL.search(content):
            ext_score += 7
            signals.append("low-level call")
        iface_calls = len(_RE_INTERFACE_CAST.findall(content))
        if iface_calls:
            ext_score += min(8, iface_calls * 2)
            signals.append(f"interface calls ({iface_calls})")
        breakdown["external_interactions"] = min(20, ext_score)

        # 3. State complexity (max 15)
        state_score = 0
        mapping_count = len(_RE_MAPPING.findall(content))
        nested_count = len(_RE_NESTED_MAPPING.findall(content))
        state_vars = len(_RE_STATE_VAR.findall(content))
        if mapping_count:
            state_score += min(6, mapping_count)
            signals.append(f"mappings ({mapping_count})")
        if nested_count:
            state_score += min(5, nested_count * 2)
            signals.append(f"nested mappings ({nested_count})")
        if state_vars:
            state_score += min(4, state_vars // 2)
        breakdown["state_complexity"] = min(15, state_score)

        # 4. Access surface (max 10)
        access_score = 0
        pub_ext_count = len(_RE_PUBLIC_EXTERNAL.findall(content))
        if pub_ext_count:
            access_score += min(7, pub_ext_count)
            # Check how many lack access control
            functions = _RE_PUBLIC_EXTERNAL.findall(content)
            # Rough heuristic: count lines with access modifier near function
            modifier_count = len(_RE_ACCESS_MODIFIER.findall(content))
            unprotected = max(0, pub_ext_count - modifier_count)
            if unprotected > 2:
                access_score += min(3, unprotected - 2)
                signals.append(f"unprotected funcs ({unprotected})")
        breakdown["access_surface"] = min(10, access_score)

        # 5. DeFi / protocol signals (max 15)
        defi_score = 0
        try:
            from core.protocol_archetypes import (
                ProtocolArchetype,
                ProtocolArchetypeDetector,
            )
            detector = ProtocolArchetypeDetector()
            result = detector.detect(content)
            high_value = {
                ProtocolArchetype.VAULT_ERC4626,
                ProtocolArchetype.LENDING_POOL,
                ProtocolArchetype.BRIDGE,
                ProtocolArchetype.DEX_AMM,
                ProtocolArchetype.DEX_ORDERBOOK,
            }
            medium_value = {
                ProtocolArchetype.STAKING,
                ProtocolArchetype.GOVERNANCE,
                ProtocolArchetype.ORACLE,
                ProtocolArchetype.NFT_MARKETPLACE,
            }
            if result.primary in high_value:
                defi_score += 12
                signals.append(f"archetype: {result.primary.value}")
            elif result.primary in medium_value:
                defi_score += 8
                signals.append(f"archetype: {result.primary.value}")
            for sec in result.secondary:
                if sec in high_value:
                    defi_score += 3
                elif sec in medium_value:
                    defi_score += 2
        except Exception:
            # Fallback: simple keyword detection
            defi_keywords = [
                (r'\bswap\b', 3), (r'\bliquidity\b', 3),
                (r'\bborrow\b', 3), (r'\bliquidat', 3),
                (r'\bstake\b', 2), (r'\bvault\b', 2),
                (r'\bbridge\b', 2), (r'\boracle\b', 2),
            ]
            for pattern, pts in defi_keywords:
                if re.search(pattern, content, re.IGNORECASE):
                    defi_score += pts
        breakdown["defi_signals"] = min(15, defi_score)

        # 6. Code complexity (max 10)
        complexity_score = 0
        line_count = content.count("\n") + 1
        if line_count > 500:
            complexity_score += 4
            signals.append(f"large ({line_count} lines)")
        elif line_count > 200:
            complexity_score += 2
        elif line_count > 100:
            complexity_score += 1
        asm_count = len(_RE_ASSEMBLY.findall(content))
        if asm_count:
            complexity_score += min(4, asm_count * 2)
            signals.append(f"assembly ({asm_count})")
        unchecked_count = len(_RE_UNCHECKED.findall(content))
        if unchecked_count:
            complexity_score += min(2, unchecked_count)
            signals.append(f"unchecked ({unchecked_count})")
        breakdown["code_complexity"] = min(10, complexity_score)

        # 7. Upgrade / proxy (max 5)
        upgrade_score = 0
        if _RE_UPGRADEABLE.search(content):
            upgrade_score += 3
            signals.append("upgradeable")
        if _RE_INITIALIZER.search(content):
            upgrade_score += 1
        if _RE_PROXY.search(content):
            upgrade_score += 2
            signals.append("proxy pattern")
        breakdown["upgrade_proxy"] = min(5, upgrade_score)

        total = sum(breakdown.values())
        return min(100, total), breakdown, signals
