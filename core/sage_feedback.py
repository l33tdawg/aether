"""
SAGE Feedback Manager — Connects audit outcomes to SAGE institutional memory.

Implements the feedback loop: audit findings → outcomes → SAGE remember/reflect
→ future audit recall. This is the core learning mechanism that makes each
audit better than the last.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SageFeedbackManager:
    """Bridges audit outcomes and detector accuracy data to SAGE."""

    def __init__(self, sage_client: Optional[Any] = None):
        from core.sage_client import SageClient
        self._client = sage_client or SageClient.get_instance()

    # ------------------------------------------------------------------
    # Finding outcomes
    # ------------------------------------------------------------------

    def record_finding_outcome(
        self,
        finding: Dict[str, Any],
        outcome: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store a finding outcome in SAGE for future recall.

        Args:
            finding: Vulnerability dict (must have ``vulnerability_type``, ``severity``).
            outcome: 'accepted', 'rejected', 'duplicate', 'out_of_scope'.
            context: Optional dict with ``archetype``, ``contract_name``, ``reason``.
        """
        ctx = context or {}
        archetype = ctx.get("archetype", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        severity = finding.get("severity", "unknown")
        description = finding.get("description", "")[:300]

        try:
            if outcome == "accepted":
                self._client.remember(
                    content=(
                        f"Confirmed vulnerability: {vuln_type} ({severity}) in "
                        f"{archetype} contracts. {description}"
                    ),
                    domain=f"audit-{archetype}",
                    memory_type="fact",
                    confidence=0.90,
                    tags=["confirmed", vuln_type, severity],
                )
            elif outcome == "rejected":
                reason = ctx.get("reason", "not exploitable")
                self._client.remember(
                    content=(
                        f"False positive: {vuln_type} ({severity}) flagged in "
                        f"{archetype} contracts but was not exploitable. "
                        f"Reason: {reason}. Pattern: {description}"
                    ),
                    domain="false-positives",
                    memory_type="observation",
                    confidence=0.85,
                    tags=["false-positive", vuln_type, archetype],
                )
        except Exception as exc:
            logger.debug("SAGE record_finding_outcome failed: %s", exc)

    # ------------------------------------------------------------------
    # Detector accuracy sync
    # ------------------------------------------------------------------

    def sync_detector_accuracy(
        self, accuracy_tracker: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Pull accuracy stats from AccuracyTracker and reflect to SAGE.

        Args:
            accuracy_tracker: An ``AccuracyTracker`` instance. If None, creates one.

        Returns:
            Summary dict with dos/donts counts.
        """
        if accuracy_tracker is None:
            try:
                from core.accuracy_tracker import AccuracyTracker
                accuracy_tracker = AccuracyTracker()
            except Exception:
                return {"error": "AccuracyTracker not available"}

        try:
            stats = accuracy_tracker.get_detector_accuracy()
        except Exception as exc:
            logger.debug("Failed to get detector accuracy: %s", exc)
            return {"error": str(exc)}

        dos: List[str] = []
        donts: List[str] = []

        for name, ds in stats.items():
            if ds.total < 10:
                continue
            if ds.precision >= 0.8:
                dos.append(
                    f"Detector '{name}' has {ds.precision:.0%} precision "
                    f"({ds.accepted}/{ds.total}). Trust its findings."
                )
                self._safe_remember(
                    content=(
                        f"High-accuracy detector: {name} — precision {ds.precision:.0%} "
                        f"over {ds.total} findings."
                    ),
                    domain="detector-accuracy",
                    memory_type="fact",
                    confidence=min(0.70 + ds.precision * 0.25, 0.98),
                    tags=["high-accuracy", name],
                )
            elif ds.precision < 0.5:
                donts.append(
                    f"Detector '{name}' has only {ds.precision:.0%} precision "
                    f"({ds.accepted}/{ds.total}). Review its findings carefully."
                )
                self._safe_remember(
                    content=(
                        f"Low-accuracy detector: {name} — precision {ds.precision:.0%} "
                        f"over {ds.total} findings. High false positive rate."
                    ),
                    domain="detector-accuracy",
                    memory_type="observation",
                    confidence=0.80,
                    tags=["low-accuracy", name],
                )

        if dos or donts:
            try:
                self._client.reflect(
                    dos=dos, donts=donts, domain="detector-accuracy"
                )
            except Exception as exc:
                logger.debug("SAGE reflect failed: %s", exc)

        return {"dos": len(dos), "donts": len(donts)}

    # ------------------------------------------------------------------
    # Audit completion
    # ------------------------------------------------------------------

    def record_audit_completion(
        self,
        contract_name: str,
        archetype: str,
        findings_summary: Dict[str, int],
        validation_stats: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store an audit summary in SAGE for future reference.

        Args:
            contract_name: Name of the audited contract.
            archetype: Detected protocol archetype value.
            findings_summary: Dict mapping severity -> count.
            validation_stats: Optional FP filtering stats.
        """
        severity_str = ", ".join(
            f"{sev}: {cnt}" for sev, cnt in findings_summary.items() if cnt > 0
        )
        total = sum(findings_summary.values())
        fp_rate = ""
        if validation_stats:
            filtered = validation_stats.get("filtered", 0)
            total_raw = validation_stats.get("total_raw", total + filtered)
            if total_raw > 0:
                fp_rate = f" FP rate: {filtered}/{total_raw} ({filtered/total_raw:.0%})."

        self._safe_remember(
            content=(
                f"Audit of {contract_name} ({archetype}): "
                f"{total} findings ({severity_str}).{fp_rate}"
            ),
            domain="audit-history",
            memory_type="observation",
            confidence=0.85,
            tags=["audit-complete", archetype, contract_name],
        )

    # ------------------------------------------------------------------
    # Recall helpers (for pipeline integration)
    # ------------------------------------------------------------------

    # Tag that gates a FP memory for use as an auto-suppression pattern.
    # Routine record_finding_outcome() entries do NOT get this tag — they are
    # audit history. Only memories an auditor has explicitly promoted with
    # mark_fp_verified() are eligible to suppress future findings at Stage -1.
    _FP_VERIFIED_TAG = "fp-verified"

    def get_historical_fp_patterns(self, archetype: str) -> List[str]:
        """Recall verified false positive patterns for an archetype.

        Only returns memories tagged ``fp-verified`` — an explicit promotion
        gate that prevents arbitrary writes to the false-positives domain
        from auto-suppressing real findings via Stage -1.

        Returns:
            List of human-readable FP pattern strings.
        """
        try:
            memories = self._client.recall(
                query=f"false positive patterns for {archetype}",
                domain="false-positives",
                top_k=20,
            )
        except Exception:
            return []

        verified: List[str] = []
        marker = f"[tags:"
        for m in memories:
            content = m.get("content", "")
            if not content:
                continue
            # Tags are stored inline as "... [tags: t1, t2, ...]" by SageClient.remember.
            idx = content.rfind(marker)
            if idx == -1:
                continue
            tag_blob = content[idx:].lower()
            if self._FP_VERIFIED_TAG in tag_blob:
                verified.append(content)
        return verified

    def mark_fp_verified(
        self,
        pattern: str,
        vulnerability_type: str,
        archetype: str = "general",
        reason: str = "",
    ) -> None:
        """Promote a false-positive pattern so Stage -1 will auto-suppress matches.

        This is the explicit gate that lets a memory affect future audit
        verdicts. Use only for patterns an auditor has manually confirmed are
        consistently non-exploitable. Stored as a fact (not observation) so
        the consistency validator enforces a stricter confidence floor.
        """
        content = (
            f"Verified false positive pattern: {vulnerability_type} in "
            f"{archetype} contracts. {pattern}"
        )
        if reason:
            content += f" Reason: {reason}"
        self._safe_remember(
            content=content,
            domain="false-positives",
            memory_type="fact",
            confidence=0.95,
            tags=[self._FP_VERIFIED_TAG, vulnerability_type, archetype],
        )

    def get_detector_recommendations(self, archetype: str) -> Dict[str, List[str]]:
        """Recall which detectors work well/poorly for an archetype.

        Returns:
            Dict with ``boost`` (high-accuracy) and ``suppress`` (low-accuracy) lists.
        """
        result: Dict[str, List[str]] = {"boost": [], "suppress": []}
        try:
            memories = self._client.recall(
                query=f"detector accuracy for {archetype}",
                domain="detector-accuracy",
                top_k=10,
            )
            for m in memories:
                content = m.get("content", "")
                tags = m.get("tags", [])
                if "high-accuracy" in tags:
                    result["boost"].append(content)
                elif "low-accuracy" in tags:
                    result["suppress"].append(content)
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _safe_remember(self, **kwargs) -> None:
        """Call sage_client.remember, swallowing any exceptions."""
        try:
            self._client.remember(**kwargs)
        except Exception as exc:
            logger.debug("SAGE remember failed: %s", exc)
