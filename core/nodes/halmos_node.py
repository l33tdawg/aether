"""
Halmos Symbolic Execution Node for the AetherAudit pipeline.

Integrates Halmos-based formal verification into the YAML-driven flow.
Generates symbolic test properties from the current findings, runs them
through Halmos, and annotates each finding with ``formal_proof_status``.

Gracefully skipped when Halmos is not installed.
"""

import logging
from typing import Any, Dict, List

from core.flow_executor import BaseNode, NodeResult
from core.halmos_runner import HalmosRunner, HalmosResult
from core.halmos_property_generator import HalmosPropertyGenerator

logger = logging.getLogger(__name__)


class HalmosSymbolicNode(BaseNode):
    """Pipeline node for Halmos symbolic execution."""

    def __init__(self, name: str = "HalmosSymbolicNode", config: Dict[str, Any] = None):
        super().__init__(name, config or {})
        self._runner = HalmosRunner(
            timeout=self.config.get("timeout", HalmosRunner.DEFAULT_TIMEOUT),
            loop_bound=self.config.get("loop_bound", HalmosRunner.DEFAULT_LOOP_BOUND),
            solver_timeout_ms=self.config.get(
                "solver_timeout_ms", HalmosRunner.DEFAULT_SOLVER_TIMEOUT
            ),
        )
        self._generator = HalmosPropertyGenerator()

    async def execute(self, context: Dict[str, Any]) -> NodeResult:
        """Run Halmos symbolic verification on current findings.

        Reads ``vulnerabilities`` from the pipeline context, converts them to
        symbolic test properties, runs halmos, and writes back
        ``formal_verification_results`` into the context.
        """
        # Graceful degradation — skip if halmos not installed
        if not self._runner.is_available():
            logger.info("Halmos not installed — skipping symbolic verification")
            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    "formal_verification_results": [],
                    "halmos_available": False,
                    "summary": {
                        "skipped": True,
                        "reason": "halmos not installed",
                    },
                },
            )

        try:
            vulnerabilities = context.get("vulnerabilities", [])
            contract_files = context.get("contract_files", [])
            project_dir = context.get("project_dir", context.get("contract_path", ""))

            if not vulnerabilities:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={
                        "formal_verification_results": [],
                        "halmos_available": True,
                        "summary": {"total": 0, "verified": 0, "refuted": 0},
                    },
                )

            # Determine contract name from context or first file
            contract_name = context.get("contract_name", "")
            if not contract_name and contract_files:
                first_path = contract_files[0][0] if isinstance(contract_files[0], (list, tuple)) else contract_files[0]
                contract_name = first_path.rsplit("/", 1)[-1].replace(".sol", "")

            # Generate symbolic test properties
            suite = self._generator.generate_from_findings(
                findings=vulnerabilities,
                contract_name=contract_name,
            )

            if not suite:
                return NodeResult(
                    node_name=self.name,
                    success=True,
                    data={
                        "formal_verification_results": [],
                        "halmos_available": True,
                        "summary": {
                            "total": len(vulnerabilities),
                            "verified": 0,
                            "refuted": 0,
                            "note": "no properties generated",
                        },
                    },
                )

            # Run halmos
            run_result = self._runner.run_symbolic_test(
                project_dir=project_dir,
                test_contract=suite.contract_name,
            )

            # Map results back to findings
            verified = 0
            refuted = 0
            inconclusive = 0
            results_list: List[Dict[str, Any]] = []

            for prop in suite.properties:
                # Find matching halmos result
                matching = [
                    r for r in run_result.test_results
                    if r.function_name == prop.function_name
                ]

                if matching:
                    tr = matching[0]
                    if tr.result == HalmosResult.PASS:
                        status = "verified"
                        verified += 1
                    elif tr.result == HalmosResult.FAIL:
                        status = "refuted"
                        refuted += 1
                    else:
                        status = "inconclusive"
                        inconclusive += 1

                    results_list.append({
                        "finding_id": prop.related_finding_id,
                        "property": prop.function_name,
                        "status": status,
                        "counterexample": tr.counterexample,
                        "duration": tr.duration_seconds,
                    })
                else:
                    inconclusive += 1
                    results_list.append({
                        "finding_id": prop.related_finding_id,
                        "property": prop.function_name,
                        "status": "inconclusive",
                        "counterexample": None,
                        "duration": 0.0,
                    })

            # Annotate vulnerabilities with formal proof status
            for vuln in vulnerabilities:
                vuln_id = vuln.get("id", "")
                for r in results_list:
                    if r["finding_id"] == vuln_id:
                        vuln["formal_proof_status"] = r["status"]
                        if r["counterexample"]:
                            vuln["formal_counterexample"] = r["counterexample"]
                        break

            context["formal_verification_results"] = results_list

            logger.info(
                "Halmos symbolic verification: %d verified, %d refuted, %d inconclusive",
                verified, refuted, inconclusive,
            )

            return NodeResult(
                node_name=self.name,
                success=True,
                data={
                    "formal_verification_results": results_list,
                    "halmos_available": True,
                    "halmos_version": run_result.halmos_version,
                    "summary": {
                        "total": len(suite.properties),
                        "verified": verified,
                        "refuted": refuted,
                        "inconclusive": inconclusive,
                        "duration": run_result.total_duration_seconds,
                    },
                },
            )

        except Exception as exc:
            logger.warning("Halmos node error: %s", exc)
            return NodeResult(
                node_name=self.name,
                success=True,  # non-fatal — don't break the pipeline
                data={
                    "formal_verification_results": [],
                    "halmos_available": self._runner.is_available(),
                    "error": str(exc),
                    "summary": {"error": str(exc)},
                },
            )
