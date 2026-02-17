#!/usr/bin/env python3
"""
Comprehensive tests for the database persistence layer.

Tests DatabaseManager (local audit persistence), AetherDatabase (GitHub audit persistence),
and related dataclasses (AuditResult, VulnerabilityFinding, LearningPattern, AuditMetrics).
"""

import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.database_manager import (
    AetherDatabase,
    AuditMetrics,
    AuditResult,
    DatabaseManager,
    LearningPattern,
    VulnerabilityFinding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_audit_result(
    audit_id="audit-001",
    contract_address="0xABC123",
    contract_name="TestToken",
    network="mainnet",
    audit_type="comprehensive",
    total_vulnerabilities=3,
    high_severity_count=1,
    critical_severity_count=0,
    false_positives=1,
    execution_time=12.5,
    created_at=None,
    metadata=None,
    status="completed",
):
    return AuditResult(
        id=audit_id,
        contract_address=contract_address,
        contract_name=contract_name,
        network=network,
        audit_type=audit_type,
        total_vulnerabilities=total_vulnerabilities,
        high_severity_count=high_severity_count,
        critical_severity_count=critical_severity_count,
        false_positives=false_positives,
        execution_time=execution_time,
        created_at=created_at or time.time(),
        metadata=metadata or {"source": "test"},
        status=status,
    )


def _make_vulnerability_finding(
    finding_id="vuln-001",
    audit_result_id="audit-001",
    vulnerability_type="reentrancy",
    severity="high",
    confidence=0.85,
    description="Reentrancy vulnerability detected",
    line_number=42,
    swc_id="SWC-107",
    file_path="/contracts/Token.sol",
    contract_name="Token",
    status="confirmed",
    validation_confidence=0.9,
    validation_reasoning="Cross-function reentrancy via external call",
    created_at=None,
    updated_at=None,
):
    now = time.time()
    return VulnerabilityFinding(
        id=finding_id,
        audit_result_id=audit_result_id,
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=confidence,
        description=description,
        line_number=line_number,
        swc_id=swc_id,
        file_path=file_path,
        contract_name=contract_name,
        status=status,
        validation_confidence=validation_confidence,
        validation_reasoning=validation_reasoning,
        created_at=created_at or now,
        updated_at=updated_at or now,
    )


def _make_learning_pattern(
    pattern_id="pat-001",
    pattern_type="false_positive",
    contract_pattern="ERC20.*transfer",
    vulnerability_type="reentrancy",
    original_classification="high",
    corrected_classification="false_positive",
    confidence_threshold=0.7,
    reasoning="Standard ERC20 transfer with checks-effects-interactions",
    source_audit_id="audit-001",
    created_at=None,
    usage_count=0,
    success_rate=0.0,
):
    return LearningPattern(
        id=pattern_id,
        pattern_type=pattern_type,
        contract_pattern=contract_pattern,
        vulnerability_type=vulnerability_type,
        original_classification=original_classification,
        corrected_classification=corrected_classification,
        confidence_threshold=confidence_threshold,
        reasoning=reasoning,
        source_audit_id=source_audit_id,
        created_at=created_at or time.time(),
        usage_count=usage_count,
        success_rate=success_rate,
    )


def _make_audit_metrics(
    metrics_id="met-001",
    audit_result_id="audit-001",
    total_findings=10,
    confirmed_findings=7,
    false_positives=3,
    accuracy_score=0.85,
    precision_score=0.7,
    recall_score=0.9,
    f1_score=0.79,
    execution_time=45.2,
    llm_calls=15,
    cache_hits=5,
    created_at=None,
):
    return AuditMetrics(
        id=metrics_id,
        audit_result_id=audit_result_id,
        total_findings=total_findings,
        confirmed_findings=confirmed_findings,
        false_positives=false_positives,
        accuracy_score=accuracy_score,
        precision_score=precision_score,
        recall_score=recall_score,
        f1_score=f1_score,
        execution_time=execution_time,
        llm_calls=llm_calls,
        cache_hits=cache_hits,
        created_at=created_at or time.time(),
    )


# ===================================================================
# Dataclass Tests
# ===================================================================

class TestAuditResultDataclass(unittest.TestCase):
    """Tests for the AuditResult dataclass."""

    def test_field_assignment(self):
        ar = _make_audit_result()
        self.assertEqual(ar.id, "audit-001")
        self.assertEqual(ar.contract_address, "0xABC123")
        self.assertEqual(ar.contract_name, "TestToken")
        self.assertEqual(ar.network, "mainnet")
        self.assertEqual(ar.audit_type, "comprehensive")
        self.assertEqual(ar.total_vulnerabilities, 3)
        self.assertEqual(ar.high_severity_count, 1)
        self.assertEqual(ar.critical_severity_count, 0)
        self.assertEqual(ar.false_positives, 1)
        self.assertAlmostEqual(ar.execution_time, 12.5)
        self.assertEqual(ar.status, "completed")
        self.assertEqual(ar.metadata, {"source": "test"})

    def test_asdict_serialization(self):
        ar = _make_audit_result()
        d = asdict(ar)
        self.assertIsInstance(d, dict)
        self.assertEqual(d["id"], "audit-001")
        self.assertEqual(d["metadata"], {"source": "test"})

    def test_metadata_complex_dict(self):
        meta = {"source": "etherscan", "tags": ["defi", "swap"], "depth": 3}
        ar = _make_audit_result(metadata=meta)
        self.assertEqual(ar.metadata["tags"], ["defi", "swap"])


class TestVulnerabilityFindingDataclass(unittest.TestCase):
    """Tests for the VulnerabilityFinding dataclass."""

    def test_field_assignment(self):
        vf = _make_vulnerability_finding()
        self.assertEqual(vf.id, "vuln-001")
        self.assertEqual(vf.audit_result_id, "audit-001")
        self.assertEqual(vf.vulnerability_type, "reentrancy")
        self.assertEqual(vf.severity, "high")
        self.assertAlmostEqual(vf.confidence, 0.85)
        self.assertEqual(vf.line_number, 42)
        self.assertEqual(vf.swc_id, "SWC-107")
        self.assertEqual(vf.status, "confirmed")

    def test_asdict_serialization(self):
        vf = _make_vulnerability_finding()
        d = asdict(vf)
        self.assertIn("vulnerability_type", d)
        self.assertIn("validation_reasoning", d)


class TestLearningPatternDataclass(unittest.TestCase):
    """Tests for the LearningPattern dataclass."""

    def test_field_defaults(self):
        lp = _make_learning_pattern()
        self.assertEqual(lp.usage_count, 0)
        self.assertAlmostEqual(lp.success_rate, 0.0)
        self.assertEqual(lp.pattern_type, "false_positive")

    def test_asdict_serialization(self):
        lp = _make_learning_pattern(usage_count=5, success_rate=0.8)
        d = asdict(lp)
        self.assertEqual(d["usage_count"], 5)
        self.assertAlmostEqual(d["success_rate"], 0.8)


class TestAuditMetricsDataclass(unittest.TestCase):
    """Tests for the AuditMetrics dataclass."""

    def test_field_assignment(self):
        am = _make_audit_metrics()
        self.assertEqual(am.total_findings, 10)
        self.assertEqual(am.confirmed_findings, 7)
        self.assertEqual(am.false_positives, 3)
        self.assertAlmostEqual(am.f1_score, 0.79)
        self.assertEqual(am.llm_calls, 15)
        self.assertEqual(am.cache_hits, 5)

    def test_asdict_serialization(self):
        am = _make_audit_metrics()
        d = asdict(am)
        self.assertIn("accuracy_score", d)
        self.assertIn("recall_score", d)


# ===================================================================
# DatabaseManager Tests
# ===================================================================

class TestDatabaseManagerInit(unittest.TestCase):
    """Tests for DatabaseManager initialization and schema creation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_audit.db")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_manager(self):
        """Create a DatabaseManager with the db_path patched to the temp directory."""
        with patch("core.database_manager.ConfigManager"):
            mgr = DatabaseManager.__new__(DatabaseManager)
            mgr.console = MagicMock()
            mgr.config_manager = MagicMock()
            mgr.db_path = Path(self.db_path)
            mgr.db_path.parent.mkdir(parents=True, exist_ok=True)
            mgr._initialize_database()
            return mgr

    def test_db_file_created(self):
        mgr = self._make_manager()
        self.assertTrue(os.path.exists(self.db_path))

    def test_schema_tables_created(self):
        mgr = self._make_manager()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        expected = {
            "audit_results",
            "vulnerability_findings",
            "learning_patterns",
            "audit_metrics",
        }
        self.assertTrue(expected.issubset(tables), f"Missing tables: {expected - tables}")

    def test_indexes_created(self):
        mgr = self._make_manager()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
        )
        indexes = {row[0] for row in cursor.fetchall()}
        conn.close()
        expected_indexes = {
            "idx_audit_results_created_at",
            "idx_audit_results_contract_address",
            "idx_vulnerability_findings_audit_id",
            "idx_vulnerability_findings_type",
            "idx_learning_patterns_type",
            "idx_audit_metrics_audit_id",
        }
        self.assertTrue(
            expected_indexes.issubset(indexes),
            f"Missing indexes: {expected_indexes - indexes}",
        )

    def test_repeated_init_is_idempotent(self):
        """Calling _initialize_database twice should not error (CREATE IF NOT EXISTS)."""
        mgr = self._make_manager()
        # Second init should be no-op
        mgr._initialize_database()
        self.assertTrue(os.path.exists(self.db_path))


class TestDatabaseManagerSaveAndRetrieveAuditResult(unittest.TestCase):
    """Tests for saving and retrieving audit results in DatabaseManager."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_audit.db")
        with patch("core.database_manager.ConfigManager"):
            self.mgr = DatabaseManager.__new__(DatabaseManager)
            self.mgr.console = MagicMock()
            self.mgr.config_manager = MagicMock()
            self.mgr.db_path = Path(self.db_path)
            self.mgr.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.mgr._initialize_database()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_audit_result_returns_true(self):
        ar = _make_audit_result()
        result = self.mgr.save_audit_result(ar)
        self.assertTrue(result)

    def test_save_and_retrieve_audit_result(self):
        """Verify round-trip: save then retrieve by raw SQL."""
        ar = _make_audit_result(audit_id="audit-rt-001", metadata={"key": "val"})
        self.mgr.save_audit_result(ar)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_results WHERE id = ?", ("audit-rt-001",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["contract_name"], "TestToken")
        self.assertEqual(row["network"], "mainnet")
        self.assertEqual(json.loads(row["metadata"]), {"key": "val"})

    def test_save_replaces_on_duplicate_id(self):
        """INSERT OR REPLACE should overwrite an existing audit with the same id."""
        ar1 = _make_audit_result(audit_id="dup-001", total_vulnerabilities=2)
        ar2 = _make_audit_result(audit_id="dup-001", total_vulnerabilities=7)
        self.mgr.save_audit_result(ar1)
        self.mgr.save_audit_result(ar2)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_results WHERE id = ?", ("dup-001",)).fetchone()
        conn.close()
        self.assertEqual(row["total_vulnerabilities"], 7)

    def test_save_multiple_distinct_audits(self):
        for i in range(5):
            ar = _make_audit_result(audit_id=f"multi-{i}")
            self.mgr.save_audit_result(ar)
        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM audit_results").fetchone()[0]
        conn.close()
        self.assertEqual(count, 5)

    def test_metadata_serialized_as_json(self):
        meta = {"nested": {"a": 1}, "list": [1, 2, 3]}
        ar = _make_audit_result(metadata=meta)
        self.mgr.save_audit_result(ar)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT metadata FROM audit_results WHERE id = ?", (ar.id,)).fetchone()
        conn.close()
        self.assertEqual(json.loads(row[0]), meta)


class TestDatabaseManagerAuditMetrics(unittest.TestCase):
    """Tests for saving audit metrics through DatabaseManager."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_audit.db")
        with patch("core.database_manager.ConfigManager"):
            self.mgr = DatabaseManager.__new__(DatabaseManager)
            self.mgr.console = MagicMock()
            self.mgr.config_manager = MagicMock()
            self.mgr.db_path = Path(self.db_path)
            self.mgr.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.mgr._initialize_database()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_audit_metrics_returns_true(self):
        metrics = _make_audit_metrics()
        result = self.mgr.save_audit_metrics(metrics)
        self.assertTrue(result)

    def test_save_and_read_metrics(self):
        metrics = _make_audit_metrics(metrics_id="met-read-001", llm_calls=42, cache_hits=10)
        self.mgr.save_audit_metrics(metrics)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_metrics WHERE id = ?", ("met-read-001",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["llm_calls"], 42)
        self.assertEqual(row["cache_hits"], 10)

    def test_store_audit_metrics_alias(self):
        """store_audit_metrics is an alias that should also persist data."""
        metrics = _make_audit_metrics(metrics_id="met-alias-001")
        self.mgr.store_audit_metrics(metrics)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT id FROM audit_metrics WHERE id = ?", ("met-alias-001",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)

    def test_store_audit_metrics_raises_on_error(self):
        """store_audit_metrics re-raises exceptions (unlike save_audit_metrics which returns False)."""
        metrics = _make_audit_metrics()
        # Force an error by using an invalid db path
        self.mgr.db_path = Path("/nonexistent/path/test.db")
        with self.assertRaises(Exception):
            self.mgr.store_audit_metrics(metrics)

    def test_save_metrics_replaces_on_duplicate_id(self):
        m1 = _make_audit_metrics(metrics_id="dup-met", llm_calls=5)
        m2 = _make_audit_metrics(metrics_id="dup-met", llm_calls=99)
        self.mgr.save_audit_metrics(m1)
        self.mgr.save_audit_metrics(m2)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT llm_calls FROM audit_metrics WHERE id = ?", ("dup-met",)).fetchone()
        conn.close()
        self.assertEqual(row["llm_calls"], 99)


# ===================================================================
# AetherDatabase Tests
# ===================================================================

class TestAetherDatabaseInit(unittest.TestCase):
    """Tests for AetherDatabase initialization and schema."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_db_file_created(self):
        db = AetherDatabase(db_path=self.db_path)
        self.assertTrue(os.path.exists(self.db_path))

    def test_custom_path_used(self):
        custom_path = os.path.join(self.test_dir, "subdir", "custom.db")
        db = AetherDatabase(db_path=custom_path)
        self.assertTrue(os.path.exists(custom_path))

    def test_schema_tables_created(self):
        db = AetherDatabase(db_path=self.db_path)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        expected = {
            "projects",
            "contracts",
            "analysis_results",
            "audit_scopes",
            "build_artifacts",
            "analysis_errors",
            "project_statistics",
            "audit_results",
            "vulnerability_findings",
            "learning_patterns",
            "audit_metrics",
        }
        self.assertTrue(expected.issubset(tables), f"Missing tables: {expected - tables}")

    def test_init_schema_idempotent(self):
        db = AetherDatabase(db_path=self.db_path)
        db.init_schema()  # second call should not raise
        self.assertTrue(os.path.exists(self.db_path))

    def test_connect_sets_row_factory(self):
        db = AetherDatabase(db_path=self.db_path)
        conn = db._connect()
        self.assertEqual(conn.row_factory, sqlite3.Row)
        conn.close()


class TestAetherDatabaseProjectCRUD(unittest.TestCase):
    """Tests for project CRUD operations in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_project(self):
        project = self.db.create_project(
            url="https://github.com/owner/repo",
            repo_name="repo",
            owner="owner",
            framework="foundry",
            cache_path="/tmp/cache",
        )
        self.assertIsNotNone(project)
        self.assertEqual(project["url"], "https://github.com/owner/repo")
        self.assertEqual(project["repo_name"], "repo")
        self.assertEqual(project["owner"], "owner")
        self.assertEqual(project["framework"], "foundry")

    def test_get_project_by_url(self):
        self.db.create_project(url="https://github.com/a/b", repo_name="b", owner="a")
        project = self.db.get_project("https://github.com/a/b")
        self.assertIsNotNone(project)
        self.assertEqual(project["repo_name"], "b")

    def test_get_project_nonexistent(self):
        result = self.db.get_project("https://github.com/no/exist")
        self.assertIsNone(result)

    def test_get_project_by_id(self):
        created = self.db.create_project(url="https://github.com/c/d", repo_name="d", owner="c")
        project = self.db.get_project_by_id(created["id"])
        self.assertIsNotNone(project)
        self.assertEqual(project["repo_name"], "d")

    def test_get_project_by_id_nonexistent(self):
        result = self.db.get_project_by_id(99999)
        self.assertIsNone(result)

    def test_update_project(self):
        created = self.db.create_project(url="https://github.com/e/f", repo_name="f", owner="e")
        self.db.update_project(created["id"], framework="hardhat", build_status="success")
        updated = self.db.get_project_by_id(created["id"])
        self.assertEqual(updated["framework"], "hardhat")
        self.assertEqual(updated["build_status"], "success")

    def test_update_project_no_fields(self):
        """update_project with no fields is a no-op."""
        created = self.db.create_project(url="https://github.com/g/h", repo_name="h", owner="g")
        self.db.update_project(created["id"])  # No fields, should not raise

    def test_create_project_insert_or_ignore_duplicate(self):
        """Creating a project with the same URL twice should not raise."""
        self.db.create_project(url="https://github.com/dup/repo", repo_name="repo", owner="dup")
        project2 = self.db.create_project(url="https://github.com/dup/repo", repo_name="repo", owner="dup")
        self.assertIsNotNone(project2)


class TestAetherDatabaseContractOperations(unittest.TestCase):
    """Tests for contract CRUD in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(
            url="https://github.com/test/contracts", repo_name="contracts", owner="test"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_contract(self):
        contract = self.db.save_contract(
            self.project["id"],
            "src/Token.sol",
            info={"contract_name": "Token", "line_count": 200, "solc_version": "0.8.20"},
        )
        self.assertIsNotNone(contract)
        self.assertEqual(contract["file_path"], "src/Token.sol")
        self.assertEqual(contract["contract_name"], "Token")

    def test_get_contracts(self):
        self.db.save_contract(self.project["id"], "src/A.sol", {"contract_name": "A"})
        self.db.save_contract(self.project["id"], "src/B.sol", {"contract_name": "B"})
        contracts = self.db.get_contracts(self.project["id"])
        self.assertEqual(len(contracts), 2)
        paths = [c["file_path"] for c in contracts]
        self.assertIn("src/A.sol", paths)
        self.assertIn("src/B.sol", paths)

    def test_get_contracts_empty_project(self):
        contracts = self.db.get_contracts(99999)
        self.assertEqual(contracts, [])

    def test_save_contract_upsert(self):
        """Saving a contract with the same project_id+file_path should update fields."""
        self.db.save_contract(self.project["id"], "src/X.sol", {"contract_name": "X", "line_count": 100})
        self.db.save_contract(self.project["id"], "src/X.sol", {"contract_name": "X_Updated", "line_count": 150})
        contracts = self.db.get_contracts(self.project["id"])
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_name"], "X_Updated")
        self.assertEqual(contracts[0]["line_count"], 150)

    def test_save_contract_minimal_info(self):
        """Save contract with no info dict."""
        contract = self.db.save_contract(self.project["id"], "src/Bare.sol")
        self.assertIsNotNone(contract)
        self.assertEqual(contract["file_path"], "src/Bare.sol")


class TestAetherDatabaseAnalysisResults(unittest.TestCase):
    """Tests for analysis_results in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(url="https://github.com/t/r", repo_name="r", owner="t")
        self.contract = self.db.save_contract(self.project["id"], "src/C.sol", {"contract_name": "C"})

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_analysis_result(self):
        findings = {"total_findings": 2, "severity_counts": {"high": 1, "medium": 1}}
        self.db.save_analysis_result(
            self.contract["id"], "static", findings, "success", analysis_duration_ms=1200
        )
        results = self.db.get_analysis_results(self.contract["id"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "success")
        parsed = json.loads(results[0]["findings"])
        self.assertEqual(parsed["total_findings"], 2)

    def test_save_analysis_result_upsert(self):
        """Same (contract_id, analysis_type) should update on conflict."""
        self.db.save_analysis_result(self.contract["id"], "static", {"v": 1}, "success")
        self.db.save_analysis_result(self.contract["id"], "static", {"v": 2}, "error", error_log="fail")
        results = self.db.get_analysis_results(self.contract["id"])
        self.assertEqual(len(results), 1)
        parsed = json.loads(results[0]["findings"])
        self.assertEqual(parsed["v"], 2)
        self.assertEqual(results[0]["status"], "error")

    def test_get_analysis_results_empty(self):
        results = self.db.get_analysis_results(99999)
        self.assertEqual(results, [])


class TestAetherDatabaseBuildArtifacts(unittest.TestCase):
    """Tests for build artifacts in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(url="https://github.com/ba/rp", repo_name="rp", owner="ba")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_get_build_artifacts(self):
        self.db.save_build_artifacts(
            self.project["id"], "/out/artifacts", "abc123", solc_version="0.8.20", size_mb=1.5
        )
        arts = self.db.get_build_artifacts(self.project["id"])
        self.assertIsNotNone(arts)
        self.assertEqual(arts["artifact_path"], "/out/artifacts")
        self.assertEqual(arts["artifact_hash"], "abc123")
        self.assertAlmostEqual(arts["size_mb"], 1.5)

    def test_get_build_artifacts_nonexistent(self):
        result = self.db.get_build_artifacts(99999)
        self.assertIsNone(result)

    def test_save_build_artifacts_upsert(self):
        self.db.save_build_artifacts(self.project["id"], "/out/v1", "hash1")
        self.db.save_build_artifacts(self.project["id"], "/out/v2", "hash2")
        arts = self.db.get_build_artifacts(self.project["id"])
        self.assertEqual(arts["artifact_path"], "/out/v2")
        self.assertEqual(arts["artifact_hash"], "hash2")


class TestAetherDatabaseErrorLogging(unittest.TestCase):
    """Tests for error logging in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_log_error(self):
        self.db.log_error({
            "project_id": None,
            "contract_id": None,
            "error_type": "compilation",
            "error_message": "solc version mismatch",
            "tool_that_failed": "forge",
            "contract_path": "src/Bad.sol",
            "status": "unresolved",
        })
        patterns = self.db.get_error_patterns()
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0]["error_type"], "compilation")
        self.assertEqual(patterns[0]["frequency"], 1)

    def test_get_error_patterns_multiple(self):
        for _ in range(3):
            self.db.log_error({"error_type": "compilation"})
        for _ in range(2):
            self.db.log_error({"error_type": "timeout"})
        patterns = self.db.get_error_patterns()
        # Should be ordered by frequency DESC
        self.assertEqual(patterns[0]["error_type"], "compilation")
        self.assertEqual(patterns[0]["frequency"], 3)
        self.assertEqual(patterns[1]["error_type"], "timeout")
        self.assertEqual(patterns[1]["frequency"], 2)

    def test_get_error_patterns_empty(self):
        patterns = self.db.get_error_patterns()
        self.assertEqual(patterns, [])


class TestAetherDatabaseAuditResults(unittest.TestCase):
    """Tests for audit_results CRUD through AetherDatabase (enhanced engine compat)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_get_audit_result(self):
        ar = _make_audit_result(audit_id="adb-001")
        self.assertTrue(self.db.save_audit_result(ar))
        result = self.db.get_audit_result("adb-001")
        self.assertIsNotNone(result)
        self.assertEqual(result["contract_name"], "TestToken")
        self.assertEqual(result["status"], "completed")

    def test_get_audit_result_nonexistent(self):
        result = self.db.get_audit_result("no-such-id")
        self.assertIsNone(result)

    def test_get_audit_results_pagination(self):
        for i in range(15):
            ar = _make_audit_result(audit_id=f"page-{i:03d}", created_at=time.time() + i)
            self.db.save_audit_result(ar)
        # Get first 5
        results = self.db.get_audit_results(limit=5, offset=0)
        self.assertEqual(len(results), 5)
        # Get next 5
        results2 = self.db.get_audit_results(limit=5, offset=5)
        self.assertEqual(len(results2), 5)
        # IDs should not overlap
        ids1 = {r["id"] for r in results}
        ids2 = {r["id"] for r in results2}
        self.assertEqual(len(ids1 & ids2), 0)

    def test_get_audit_results_empty(self):
        results = self.db.get_audit_results()
        self.assertEqual(results, [])

    def test_update_audit_result(self):
        ar = _make_audit_result(audit_id="upd-001", total_vulnerabilities=3)
        self.db.save_audit_result(ar)
        ar.total_vulnerabilities = 10
        ar.status = "error"
        self.assertTrue(self.db.update_audit_result(ar))
        result = self.db.get_audit_result("upd-001")
        self.assertEqual(result["total_vulnerabilities"], 10)
        self.assertEqual(result["status"], "error")

    def test_delete_audit_result(self):
        ar = _make_audit_result(audit_id="del-001")
        self.db.save_audit_result(ar)
        self.assertTrue(self.db.delete_audit_result("del-001"))
        result = self.db.get_audit_result("del-001")
        self.assertIsNone(result)

    def test_delete_audit_result_cascades_findings(self):
        """Deleting an audit should also delete its vulnerability findings."""
        ar = _make_audit_result(audit_id="cascade-001")
        self.db.save_audit_result(ar)
        vf = _make_vulnerability_finding(finding_id="vf-c-001", audit_result_id="cascade-001")
        self.db.save_vulnerability_findings([vf])
        self.db.delete_audit_result("cascade-001")
        findings = self.db.get_vulnerability_findings("cascade-001")
        self.assertEqual(findings, [])

    def test_find_audit_by_contract(self):
        meta = {"contract_path": "/src/MyToken.sol"}
        ar = _make_audit_result(
            audit_id="find-001",
            contract_name="MyToken",
            contract_address="0xFIND",
            metadata=meta,
        )
        self.db.save_audit_result(ar)
        found = self.db.find_audit_by_contract("/src/MyToken.sol", "MyToken")
        self.assertIsNotNone(found)
        self.assertEqual(found["id"], "find-001")

    def test_find_audit_by_contract_not_found(self):
        result = self.db.find_audit_by_contract("/no/path.sol", "NoContract")
        self.assertIsNone(result)


class TestAetherDatabaseVulnerabilityFindings(unittest.TestCase):
    """Tests for vulnerability findings in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        # Create a parent audit result for FK compliance
        self.audit = _make_audit_result(audit_id="vf-parent")
        self.db.save_audit_result(self.audit)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_get_findings(self):
        findings = [
            _make_vulnerability_finding(finding_id="vf-001", audit_result_id="vf-parent"),
            _make_vulnerability_finding(
                finding_id="vf-002",
                audit_result_id="vf-parent",
                vulnerability_type="integer_overflow",
                severity="medium",
            ),
        ]
        result = self.db.save_vulnerability_findings(findings)
        self.assertTrue(result)
        retrieved = self.db.get_vulnerability_findings("vf-parent")
        self.assertEqual(len(retrieved), 2)
        types = {r["vulnerability_type"] for r in retrieved}
        self.assertIn("reentrancy", types)
        self.assertIn("integer_overflow", types)

    def test_save_empty_findings_list(self):
        result = self.db.save_vulnerability_findings([])
        self.assertTrue(result)

    def test_get_findings_empty(self):
        findings = self.db.get_vulnerability_findings("nonexistent-audit")
        self.assertEqual(findings, [])

    def test_delete_vulnerability_findings(self):
        vf = _make_vulnerability_finding(finding_id="vf-del-001", audit_result_id="vf-parent")
        self.db.save_vulnerability_findings([vf])
        self.assertTrue(self.db.delete_vulnerability_findings("vf-parent"))
        findings = self.db.get_vulnerability_findings("vf-parent")
        self.assertEqual(findings, [])

    def test_findings_data_integrity(self):
        """Verify all fields are correctly persisted and retrieved."""
        now = time.time()
        vf = _make_vulnerability_finding(
            finding_id="vf-int-001",
            audit_result_id="vf-parent",
            vulnerability_type="access_control",
            severity="critical",
            confidence=0.95,
            description="Missing access control on sensitive function",
            line_number=100,
            swc_id="SWC-105",
            file_path="/contracts/Vault.sol",
            contract_name="Vault",
            status="investigating",
            validation_confidence=0.88,
            validation_reasoning="No modifier on withdraw()",
            created_at=now,
            updated_at=now,
        )
        self.db.save_vulnerability_findings([vf])
        retrieved = self.db.get_vulnerability_findings("vf-parent")
        self.assertEqual(len(retrieved), 1)
        r = retrieved[0]
        self.assertEqual(r["vulnerability_type"], "access_control")
        self.assertEqual(r["severity"], "critical")
        self.assertAlmostEqual(r["confidence"], 0.95, places=5)
        self.assertEqual(r["line_number"], 100)
        self.assertEqual(r["swc_id"], "SWC-105")
        self.assertEqual(r["file_path"], "/contracts/Vault.sol")
        self.assertEqual(r["contract_name"], "Vault")
        self.assertEqual(r["status"], "investigating")
        self.assertAlmostEqual(r["validation_confidence"], 0.88, places=5)
        self.assertEqual(r["validation_reasoning"], "No modifier on withdraw()")


class TestAetherDatabaseLearningPatterns(unittest.TestCase):
    """Tests for learning patterns in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        # Create parent audit result for FK constraint
        self.db.save_audit_result(_make_audit_result(audit_id="lp-parent"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_get_learning_pattern(self):
        lp = _make_learning_pattern(pattern_id="lp-001", source_audit_id="lp-parent")
        self.assertTrue(self.db.save_learning_pattern(lp))
        patterns = self.db.get_learning_patterns()
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0]["pattern_type"], "false_positive")

    def test_get_learning_patterns_by_type(self):
        lp1 = _make_learning_pattern(pattern_id="lp-fp", pattern_type="false_positive", source_audit_id="lp-parent")
        lp2 = _make_learning_pattern(pattern_id="lp-sc", pattern_type="severity_correction", source_audit_id="lp-parent")
        self.db.save_learning_pattern(lp1)
        self.db.save_learning_pattern(lp2)
        fp_only = self.db.get_learning_patterns(pattern_type="false_positive")
        self.assertEqual(len(fp_only), 1)
        self.assertEqual(fp_only[0]["id"], "lp-fp")

    def test_get_learning_patterns_empty(self):
        patterns = self.db.get_learning_patterns()
        self.assertEqual(patterns, [])

    def test_update_learning_pattern_usage(self):
        lp = _make_learning_pattern(
            pattern_id="lp-usage",
            source_audit_id="lp-parent",
            usage_count=0,
            success_rate=0.0,
        )
        self.db.save_learning_pattern(lp)
        result = self.db.update_learning_pattern_usage("lp-usage", success=True)
        self.assertTrue(result)
        # Verify updated
        patterns = self.db.get_learning_patterns()
        self.assertEqual(len(patterns), 1)
        self.assertGreater(patterns[0]["usage_count"], 0)

    def test_update_learning_pattern_usage_nonexistent(self):
        result = self.db.update_learning_pattern_usage("no-such-pattern", success=True)
        self.assertFalse(result)


class TestAetherDatabaseAuditMetrics(unittest.TestCase):
    """Tests for audit metrics in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_audit_metrics(self):
        metrics = _make_audit_metrics(metrics_id="adb-met-001")
        result = self.db.save_audit_metrics(metrics)
        self.assertTrue(result)
        # Verify via raw SQL
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_metrics WHERE id = ?", ("adb-met-001",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["total_findings"], 10)
        self.assertAlmostEqual(row["f1_score"], 0.79)

    def test_store_audit_metrics(self):
        metrics = _make_audit_metrics(metrics_id="adb-store-001")
        self.db.store_audit_metrics(metrics)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT id FROM audit_metrics WHERE id = ?", ("adb-store-001",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)


class TestAetherDatabaseAuditStatistics(unittest.TestCase):
    """Tests for aggregated audit statistics in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_audit_statistics_empty(self):
        stats = self.db.get_audit_statistics()
        self.assertEqual(stats["total_audits"], 0)
        self.assertEqual(stats["total_vulnerabilities"], 0)

    def test_get_audit_statistics_with_data(self):
        for i in range(3):
            ar = _make_audit_result(
                audit_id=f"stat-{i}",
                total_vulnerabilities=i + 1,
                created_at=time.time(),
            )
            self.db.save_audit_result(ar)
        stats = self.db.get_audit_statistics()
        self.assertEqual(stats["total_audits"], 3)
        self.assertEqual(stats["total_vulnerabilities"], 6)  # 1+2+3
        self.assertIn("audits_by_status", stats)
        self.assertIn("completed", stats["audits_by_status"])
        self.assertEqual(stats["audits_by_status"]["completed"], 3)

    def test_get_audit_statistics_severity_distribution(self):
        ar = _make_audit_result(audit_id="sev-dist-001")
        self.db.save_audit_result(ar)
        findings = [
            _make_vulnerability_finding(
                finding_id=f"sev-{i}", audit_result_id="sev-dist-001", severity=sev
            )
            for i, sev in enumerate(["high", "high", "medium", "low"])
        ]
        self.db.save_vulnerability_findings(findings)
        stats = self.db.get_audit_statistics()
        self.assertEqual(stats["vulnerabilities_by_severity"].get("high", 0), 2)
        self.assertEqual(stats["vulnerabilities_by_severity"].get("medium", 0), 1)
        self.assertEqual(stats["vulnerabilities_by_severity"].get("low", 0), 1)

    def test_recent_audits_count(self):
        # Insert an audit with current timestamp
        ar = _make_audit_result(audit_id="recent-001", created_at=time.time())
        self.db.save_audit_result(ar)
        # Insert an audit with an old timestamp (>30 days ago)
        old_time = time.time() - (31 * 24 * 3600)
        ar_old = _make_audit_result(audit_id="old-001", created_at=old_time)
        self.db.save_audit_result(ar_old)
        stats = self.db.get_audit_statistics()
        self.assertEqual(stats["recent_audits_30d"], 1)


class TestAetherDatabaseScopeManagement(unittest.TestCase):
    """Tests for audit scope persistence and management."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(
            url="https://github.com/scope/test", repo_name="test", owner="scope"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_audit_scope(self):
        contracts = ["src/A.sol", "src/B.sol", "src/C.sol"]
        scope = self.db.save_audit_scope(self.project["id"], contracts, scope_name="Scope_1")
        self.assertIsNotNone(scope)
        self.assertEqual(scope["project_id"], self.project["id"])
        self.assertEqual(scope["contracts"], 3)
        self.assertEqual(scope["status"], "active")

    def test_get_active_scope(self):
        contracts = ["src/X.sol", "src/Y.sol"]
        self.db.save_audit_scope(self.project["id"], contracts)
        active = self.db.get_active_scope(self.project["id"])
        self.assertIsNotNone(active)
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["selected_contracts"], contracts)
        self.assertEqual(active["total_selected"], 2)

    def test_get_active_scope_none(self):
        result = self.db.get_active_scope(99999)
        self.assertIsNone(result)

    def test_save_scope_archives_previous(self):
        """Creating a new active scope should archive the previous one."""
        self.db.save_audit_scope(self.project["id"], ["a.sol"], scope_name="First")
        self.db.save_audit_scope(self.project["id"], ["b.sol"], scope_name="Second")
        all_scopes = self.db.get_all_scopes(self.project["id"])
        active_count = sum(1 for s in all_scopes if s["status"] == "active")
        archived_count = sum(1 for s in all_scopes if s["status"] == "archived")
        self.assertEqual(active_count, 1)
        self.assertEqual(archived_count, 1)

    def test_update_scope_progress(self):
        scope = self.db.save_audit_scope(self.project["id"], ["a.sol", "b.sol", "c.sol"])
        self.assertTrue(self.db.update_scope_progress(scope["id"], contract_id=1, audited_count=1, pending_count=2))
        active = self.db.get_active_scope(self.project["id"])
        self.assertEqual(active["total_audited"], 1)
        self.assertEqual(active["total_pending"], 2)

    def test_update_scope_contracts(self):
        scope = self.db.save_audit_scope(self.project["id"], ["a.sol"])
        new_contracts = ["a.sol", "b.sol", "c.sol", "d.sol"]
        self.assertTrue(self.db.update_scope_contracts(scope["id"], new_contracts))
        active = self.db.get_active_scope(self.project["id"])
        self.assertEqual(active["selected_contracts"], new_contracts)
        self.assertEqual(active["total_selected"], 4)

    def test_complete_scope(self):
        scope = self.db.save_audit_scope(self.project["id"], ["a.sol"])
        self.assertTrue(self.db.complete_scope(scope["id"]))
        active = self.db.get_active_scope(self.project["id"])
        self.assertIsNone(active)  # No active scope anymore
        last = self.db.get_last_scope(self.project["id"])
        self.assertEqual(last["status"], "completed")
        self.assertEqual(last["total_pending"], 0)

    def test_reactivate_scope(self):
        scope = self.db.save_audit_scope(self.project["id"], ["a.sol"])
        self.db.complete_scope(scope["id"])
        self.assertTrue(self.db.reactivate_scope(scope["id"]))
        active = self.db.get_active_scope(self.project["id"])
        self.assertIsNotNone(active)
        self.assertEqual(active["status"], "active")

    def test_get_last_scope(self):
        """get_last_scope returns the most recent scope regardless of status."""
        self.db.save_audit_scope(self.project["id"], ["a.sol"], scope_name="First")
        # Sleep briefly so CURRENT_TIMESTAMP differs (SQLite second resolution)
        time.sleep(1.1)
        scope2 = self.db.save_audit_scope(self.project["id"], ["b.sol"], scope_name="Second")
        self.db.complete_scope(scope2["id"])
        last = self.db.get_last_scope(self.project["id"])
        self.assertIsNotNone(last)
        self.assertEqual(last["scope_name"], "Second")

    def test_get_all_scopes(self):
        self.db.save_audit_scope(self.project["id"], ["a.sol"], scope_name="S1")
        self.db.save_audit_scope(self.project["id"], ["b.sol"], scope_name="S2")
        all_scopes = self.db.get_all_scopes(self.project["id"])
        self.assertEqual(len(all_scopes), 2)

    def test_get_scope_history(self):
        self.db.save_audit_scope(self.project["id"], ["a.sol"], scope_name="H1")
        # Sleep briefly so CURRENT_TIMESTAMP differs (SQLite second resolution)
        time.sleep(1.1)
        self.db.save_audit_scope(self.project["id"], ["b.sol"], scope_name="H2")
        history = self.db.get_scope_history(self.project["id"], limit=10)
        self.assertEqual(len(history), 2)
        # Most recent first
        self.assertEqual(history[0]["scope_name"], "H2")

    def test_get_scope_by_id(self):
        scope = self.db.save_audit_scope(self.project["id"], ["x.sol", "y.sol"], scope_name="ById")
        result = self.db.get_scope_by_id(scope["id"])
        self.assertIsNotNone(result)
        self.assertEqual(result["scope_name"], "ById")
        self.assertEqual(result["selected_contracts"], ["x.sol", "y.sol"])

    def test_get_scope_by_id_nonexistent(self):
        result = self.db.get_scope_by_id(99999)
        self.assertIsNone(result)

    def test_reset_scope_for_reaudit(self):
        contracts = ["a.sol", "b.sol"]
        scope = self.db.save_audit_scope(self.project["id"], contracts)
        self.db.update_scope_progress(scope["id"], contract_id=1, audited_count=2, pending_count=0)
        self.assertTrue(self.db.reset_scope_for_reaudit(scope["id"]))
        active = self.db.get_active_scope(self.project["id"])
        self.assertEqual(active["total_audited"], 0)
        self.assertEqual(active["total_pending"], 2)

    def test_reset_scope_for_reaudit_nonexistent(self):
        result = self.db.reset_scope_for_reaudit(99999)
        self.assertFalse(result)


class TestAetherDatabaseProjectStatistics(unittest.TestCase):
    """Tests for project-level statistics in AetherDatabase."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(
            url="https://github.com/stats/proj", repo_name="proj", owner="stats"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_project_statistics_empty(self):
        stats = self.db.get_project_statistics(self.project["id"])
        self.assertEqual(stats["total_contracts"], 0)
        self.assertEqual(stats["total_findings"], 0)

    def test_get_project_statistics_with_data(self):
        c1 = self.db.save_contract(self.project["id"], "src/A.sol", {"contract_name": "A"})
        c2 = self.db.save_contract(self.project["id"], "src/B.sol", {"contract_name": "B"})
        findings1 = {
            "total_findings": 3,
            "severity_counts": {"critical": 1, "high": 1, "medium": 1},
        }
        findings2 = {
            "total_findings": 2,
            "severity_counts": {"high": 1, "low": 1},
        }
        self.db.save_analysis_result(c1["id"], "static", findings1, "success")
        self.db.save_analysis_result(c2["id"], "static", findings2, "success")
        stats = self.db.get_project_statistics(self.project["id"])
        self.assertEqual(stats["total_contracts"], 2)
        self.assertEqual(stats["total_findings"], 5)
        self.assertEqual(stats["critical_findings"], 1)
        self.assertEqual(stats["high_findings"], 2)
        self.assertEqual(stats["medium_findings"], 1)
        self.assertEqual(stats["low_findings"], 1)

    def test_get_project_statistics_counts_failed(self):
        c1 = self.db.save_contract(self.project["id"], "src/Fail.sol", {"contract_name": "Fail"})
        self.db.save_analysis_result(c1["id"], "static", {}, "error", error_log="compilation failed")
        stats = self.db.get_project_statistics(self.project["id"])
        self.assertEqual(stats["failed_analyses"], 1)


class TestAetherDatabaseIsAnalysisComplete(unittest.TestCase):
    """Tests for the is_analysis_complete check."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(
            url="https://github.com/comp/check", repo_name="check", owner="comp"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_empty_project_not_complete(self):
        self.assertFalse(self.db.is_analysis_complete(self.project["id"]))

    def test_all_analyzed_is_complete(self):
        c1 = self.db.save_contract(self.project["id"], "a.sol")
        c2 = self.db.save_contract(self.project["id"], "b.sol")
        self.db.save_analysis_result(c1["id"], "static", {}, "success")
        self.db.save_analysis_result(c2["id"], "static", {}, "success")
        self.assertTrue(self.db.is_analysis_complete(self.project["id"]))

    def test_partial_analysis_not_complete(self):
        c1 = self.db.save_contract(self.project["id"], "a.sol")
        self.db.save_contract(self.project["id"], "b.sol")
        self.db.save_analysis_result(c1["id"], "static", {}, "success")
        self.assertFalse(self.db.is_analysis_complete(self.project["id"]))


class TestAetherDatabaseClose(unittest.TestCase):
    """Tests for close/shutdown methods."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_close_does_not_raise(self):
        self.db.close()

    def test_internal_close_alias(self):
        self.db._close()


class TestAetherDatabaseUtcConversion(unittest.TestCase):
    """Tests for the UTC-to-local timestamp conversion helper."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_convert_valid_timestamp(self):
        result = self.db._convert_utc_to_local("2025-01-15 12:00:00")
        # Should return a string in YYYY-MM-DD HH:MM:SS format
        self.assertRegex(result, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

    def test_convert_empty_timestamp(self):
        result = self.db._convert_utc_to_local("")
        self.assertEqual(result, "Unknown")

    def test_convert_none_timestamp(self):
        result = self.db._convert_utc_to_local(None)
        self.assertEqual(result, "Unknown")

    def test_convert_invalid_format(self):
        """Malformed timestamps should be returned as-is."""
        result = self.db._convert_utc_to_local("not-a-date")
        self.assertEqual(result, "not-a-date")


class TestAetherDatabaseRecalculateScopeProgress(unittest.TestCase):
    """Tests for recalculate_scope_progress."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_github_audit.db")
        self.db = AetherDatabase(db_path=self.db_path)
        self.project = self.db.create_project(
            url="https://github.com/recalc/proj", repo_name="proj", owner="recalc"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_recalculate_with_analyzed_contracts(self):
        c1 = self.db.save_contract(self.project["id"], "src/A.sol")
        c2 = self.db.save_contract(self.project["id"], "src/B.sol")
        self.db.save_analysis_result(c1["id"], "static", {}, "success")
        scope = self.db.save_audit_scope(self.project["id"], ["src/A.sol", "src/B.sol"])
        progress = self.db.recalculate_scope_progress(scope["id"])
        self.assertEqual(progress["total_selected"], 2)
        self.assertEqual(progress["total_audited"], 1)
        self.assertEqual(progress["total_pending"], 1)

    def test_recalculate_nonexistent_scope(self):
        progress = self.db.recalculate_scope_progress(99999)
        self.assertEqual(progress["total_selected"], 0)
        self.assertEqual(progress["total_audited"], 0)


if __name__ == "__main__":
    unittest.main()
