#!/usr/bin/env python3
"""
SQLite Database Manager for AetherAudit

Provides persistent storage for audit results, learning data, patterns, and metrics.
"""

import sqlite3
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from rich.console import Console

from core.config_manager import ConfigManager


@dataclass
class AuditResult:
    """Audit result record."""
    id: str
    contract_address: str
    contract_name: str
    network: str
    audit_type: str  # 'static', 'dynamic', 'comprehensive'
    total_vulnerabilities: int
    high_severity_count: int
    critical_severity_count: int
    false_positives: int
    execution_time: float
    created_at: float
    metadata: Dict[str, Any]
    status: str  # 'completed', 'error', 'in_progress'


@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding record."""
    id: str
    audit_result_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    line_number: int
    swc_id: str
    file_path: str
    contract_name: str
    status: str  # 'confirmed', 'false_positive', 'investigating'
    validation_confidence: float
    validation_reasoning: str
    created_at: float
    updated_at: float


@dataclass
class LearningPattern:
    """Learning pattern record for false positive correction."""
    id: str
    pattern_type: str  # 'false_positive', 'severity_correction', 'pattern_update'
    contract_pattern: str
    vulnerability_type: str
    original_classification: str
    corrected_classification: str
    confidence_threshold: float
    reasoning: str
    source_audit_id: str
    created_at: float
    usage_count: int
    success_rate: float


@dataclass
class AuditMetrics:
    """Audit performance metrics."""
    id: str
    audit_result_id: str
    total_findings: int
    confirmed_findings: int
    false_positives: int
    accuracy_score: float
    precision_score: float
    recall_score: float
    f1_score: float
    execution_time: float
    llm_calls: int
    cache_hits: int
    created_at: float


class DatabaseManager:
    """SQLite database manager for AetherAudit."""

    def __init__(self, config_manager: Optional[ConfigManager] = None):
        self.console = Console()
        self.config_manager = config_manager or ConfigManager()

        # Database file location
        self.db_path = Path.home() / '.aether' / 'aetheraudit.db'
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('PRAGMA foreign_keys = ON')
            conn.execute('PRAGMA journal_mode = WAL')  # Better concurrency

            # Create audit_results table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_results (
                    id TEXT PRIMARY KEY,
                    contract_address TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    network TEXT NOT NULL,
                    audit_type TEXT NOT NULL,
                    total_vulnerabilities INTEGER NOT NULL,
                    high_severity_count INTEGER NOT NULL,
                    critical_severity_count INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    execution_time REAL NOT NULL,
                    created_at REAL NOT NULL,
                    metadata TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            ''')

            # Create vulnerability_findings table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_findings (
                    id TEXT PRIMARY KEY,
                    audit_result_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    swc_id TEXT,
                    file_path TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    validation_confidence REAL NOT NULL,
                    validation_reasoning TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (audit_result_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # Create learning_patterns table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS learning_patterns (
                    id TEXT PRIMARY KEY,
                    pattern_type TEXT NOT NULL,
                    contract_pattern TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    original_classification TEXT NOT NULL,
                    corrected_classification TEXT NOT NULL,
                    confidence_threshold REAL NOT NULL,
                    reasoning TEXT NOT NULL,
                    source_audit_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    usage_count INTEGER NOT NULL DEFAULT 0,
                    success_rate REAL NOT NULL DEFAULT 0.0,
                    FOREIGN KEY (source_audit_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # Create slither_project_cache table for caching Slither results per project
            conn.execute('''
                CREATE TABLE IF NOT EXISTS slither_project_cache (
                    project_root TEXT PRIMARY KEY,
                    findings_json TEXT NOT NULL,
                    analyzed_at REAL NOT NULL,
                    contract_count INTEGER NOT NULL,
                    framework TEXT,
                    last_accessed REAL NOT NULL
                )
            ''')
            
            # Create index for faster queries
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_slither_cache_accessed 
                ON slither_project_cache(last_accessed)
            ''')

            # Create audit_metrics table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_metrics (
                    id TEXT PRIMARY KEY,
                    audit_result_id TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    confirmed_findings INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    accuracy_score REAL NOT NULL,
                    precision_score REAL NOT NULL,
                    recall_score REAL NOT NULL,
                    f1_score REAL NOT NULL,
                    execution_time REAL NOT NULL,
                    llm_calls INTEGER NOT NULL,
                    cache_hits INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (audit_result_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # Create indexes for better performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_results_created_at ON audit_results(created_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_results_contract_address ON audit_results(contract_address)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_audit_id ON vulnerability_findings(audit_result_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_type ON vulnerability_findings(vulnerability_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_learning_patterns_type ON learning_patterns(pattern_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_metrics_audit_id ON audit_metrics(audit_result_id)')

    def save_audit_result(self, audit_result: AuditResult) -> bool:
        """Save audit result to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_results
                    (id, contract_address, contract_name, network, audit_type,
                     total_vulnerabilities, high_severity_count, critical_severity_count,
                     false_positives, execution_time, created_at, metadata, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    audit_result.id,
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit result: {e}[/red]")
            return False

    def save_audit_metrics(self, metrics: AuditMetrics) -> bool:
        """Save audit metrics to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings,
                     false_positives, accuracy_score, precision_score, recall_score,
                     f1_score, execution_time, llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit metrics: {e}[/red]")
            return False

    def get_slither_cache(self, project_root: str) -> Optional[Dict[str, Any]]:
        """Get cached Slither results for a project."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT findings_json, analyzed_at, contract_count, framework
                    FROM slither_project_cache
                    WHERE project_root = ?
                ''', (project_root,))
                
                row = cursor.fetchone()
                if row:
                    # Update last_accessed
                    conn.execute('''
                        UPDATE slither_project_cache
                        SET last_accessed = ?
                        WHERE project_root = ?
                    ''', (time.time(), project_root))
                    
                    return {
                        'findings': json.loads(row[0]),
                        'analyzed_at': row[1],
                        'contract_count': row[2],
                        'framework': row[3]
                    }
                return None
        except Exception as e:
            self.console.print(f"[yellow]⚠️  Failed to get Slither cache: {e}[/yellow]")
            return None

    def save_slither_cache(self, project_root: str, findings: List[Dict[str, Any]], 
                          framework: Optional[str] = None) -> bool:
        """Save Slither results to cache for a project."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                current_time = time.time()
                conn.execute('''
                    INSERT OR REPLACE INTO slither_project_cache
                    (project_root, findings_json, analyzed_at, contract_count, framework, last_accessed)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    project_root,
                    json.dumps(findings),
                    current_time,
                    len(findings),
                    framework,
                    current_time
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save Slither cache: {e}[/red]")
            return False

    def clear_old_slither_cache(self, days: int = 7) -> int:
        """Clear Slither cache entries older than specified days."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cutoff_time = time.time() - (days * 24 * 60 * 60)
                cursor = conn.execute('''
                    DELETE FROM slither_project_cache
                    WHERE last_accessed < ?
                ''', (cutoff_time,))
                return cursor.rowcount
        except Exception as e:
            self.console.print(f"[red]❌ Failed to clear old Slither cache: {e}[/red]")
            return 0

    def store_audit_metrics(self, metrics: AuditMetrics) -> None:
        """Store audit metrics in the database (alias for save_audit_metrics for compatibility)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings, false_positives,
                     accuracy_score, precision_score, recall_score, f1_score, execution_time,
                     llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
        except Exception as e:
            self.console.print(f"[red]❌ Failed to store audit metrics: {e}[/red]")
            raise

class AetherDatabase:
    """SQLite database for GitHub audit orchestration (projects/contracts/results/cache/errors/stats).

    This class is additive and does not interfere with the existing DatabaseManager used by
    other parts of the system. It uses a distinct database file by default to avoid schema conflicts.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.console = Console()
        default_path = Path.home() / '.aether' / 'aether_github_audit.db'
        self.db_path = Path(db_path) if db_path else default_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
        conn.row_factory = sqlite3.Row
        return conn

    def _convert_utc_to_local(self, utc_timestamp: str) -> str:
        """Convert UTC timestamp from SQLite to local timezone."""
        if not utc_timestamp:
            return 'Unknown'
        try:
            from datetime import datetime
            import time
            
            # Parse the UTC timestamp (SQLite format: YYYY-MM-DD HH:MM:SS)
            utc_dt = datetime.strptime(utc_timestamp, '%Y-%m-%d %H:%M:%S')
            
            # Convert to local time by adding the timezone offset
            # time.timezone gives the offset in seconds (negative for timezones ahead of UTC)
            local_offset = -time.timezone if not time.daylight else -time.altzone
            from datetime import timedelta
            local_dt = utc_dt + timedelta(seconds=local_offset)
            
            return local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            # If parsing fails, return the original timestamp
            return utc_timestamp

    # Convenience helpers used by CLI
    def get_project_by_id(self, project_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                row = conn.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
                return dict(row) if row else None
        except Exception:
            return None

    def get_scope_by_id(self, scope_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                row = conn.execute('SELECT * FROM audit_scopes WHERE id = ?', (scope_id,)).fetchone()
                if not row:
                    return None
                import json as _json
                return {
                    'id': row['id'],
                    'project_id': row['project_id'],
                    'scope_name': row['scope_name'],
                    'selected_contracts': _json.loads(row['selected_contracts']) if row['selected_contracts'] else [],
                    'status': row['status'],
                }
        except Exception:
            return None

    def init_schema(self) -> None:
        """Create tables required by the GitHub audit workflow if they do not exist."""
        with self._connect() as conn:
            # projects
            conn.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    repo_name TEXT NOT NULL,
                    owner TEXT,
                    framework TEXT,
                    cloned_at DATETIME,
                    last_updated DATETIME,
                    last_analyzed DATETIME,
                    cache_path TEXT,
                    build_status TEXT,
                    build_log TEXT,
                    solc_version TEXT,
                    is_private BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(owner, repo_name)
                )
            ''')

            # contracts
            conn.execute('''
                CREATE TABLE IF NOT EXISTS contracts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    contract_name TEXT,
                    solc_version TEXT,
                    discovered_at DATETIME,
                    line_count INTEGER,
                    dependencies TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    UNIQUE(project_id, file_path)
                )
            ''')

            # analysis_results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract_id INTEGER NOT NULL,
                    analysis_type TEXT NOT NULL,
                    findings TEXT,
                    analyzed_at DATETIME,
                    status TEXT,
                    error_log TEXT,
                    analysis_duration_ms INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(contract_id) REFERENCES contracts(id) ON DELETE CASCADE,
                    UNIQUE(contract_id, analysis_type)
                )
            ''')

            # audit_scopes (for scope persistence and resume)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_scopes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    scope_name TEXT,
                    selected_contracts TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    total_selected INTEGER,
                    total_audited INTEGER DEFAULT 0,
                    total_pending INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    modified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_audited_contract_id INTEGER,
                    metadata TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')

            # build_artifacts
            conn.execute('''
                CREATE TABLE IF NOT EXISTS build_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    artifact_path TEXT,
                    artifact_hash TEXT,
                    solc_version TEXT,
                    dependencies_hash TEXT,
                    created_at DATETIME,
                    last_accessed DATETIME,
                    size_mb REAL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    UNIQUE(project_id)
                )
            ''')

            # analysis_errors
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analysis_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER,
                    contract_id INTEGER,
                    error_type TEXT,
                    error_message TEXT,
                    tool_that_failed TEXT,
                    contract_path TEXT,
                    full_error_log TEXT,
                    occurred_at DATETIME,
                    status TEXT,
                    resolution_notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(project_id) REFERENCES projects(id),
                    FOREIGN KEY(contract_id) REFERENCES contracts(id)
                )
            ''')

            # project_statistics
            conn.execute('''
                CREATE TABLE IF NOT EXISTS project_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL UNIQUE,
                    total_contracts INTEGER,
                    total_findings INTEGER,
                    critical_findings INTEGER,
                    high_findings INTEGER,
                    medium_findings INTEGER,
                    low_findings INTEGER,
                    fallback_analyses INTEGER,
                    failed_analyses INTEGER,
                    analysis_time_seconds REAL,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
            ''')

            # audit_results (for enhanced audit engine compatibility)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_results (
                    id TEXT PRIMARY KEY,
                    contract_address TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    network TEXT NOT NULL,
                    audit_type TEXT NOT NULL,
                    total_vulnerabilities INTEGER NOT NULL,
                    high_severity_count INTEGER NOT NULL,
                    critical_severity_count INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    execution_time REAL NOT NULL,
                    created_at REAL NOT NULL,
                    metadata TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            ''')

            # vulnerability_findings (for enhanced audit engine compatibility)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_findings (
                    id TEXT PRIMARY KEY,
                    audit_result_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    swc_id TEXT,
                    file_path TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    validation_confidence REAL NOT NULL,
                    validation_reasoning TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (audit_result_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # learning_patterns (for enhanced audit engine compatibility)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS learning_patterns (
                    id TEXT PRIMARY KEY,
                    pattern_type TEXT NOT NULL,
                    contract_pattern TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    original_classification TEXT NOT NULL,
                    corrected_classification TEXT NOT NULL,
                    confidence_threshold REAL NOT NULL,
                    reasoning TEXT NOT NULL,
                    source_audit_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    usage_count INTEGER NOT NULL DEFAULT 0,
                    success_rate REAL NOT NULL DEFAULT 0.0,
                    FOREIGN KEY (source_audit_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # audit_metrics (for enhanced audit engine compatibility)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_metrics (
                    id TEXT PRIMARY KEY,
                    audit_result_id TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    confirmed_findings INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    accuracy_score REAL NOT NULL,
                    precision_score REAL NOT NULL,
                    recall_score REAL NOT NULL,
                    f1_score REAL NOT NULL,
                    execution_time REAL NOT NULL,
                    llm_calls INTEGER NOT NULL,
                    cache_hits INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (audit_result_id) REFERENCES audit_results (id) ON DELETE CASCADE
                )
            ''')

            # helpful indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_contracts_project ON contracts(project_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_results_contract ON analysis_results(contract_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_errors_project ON analysis_errors(project_id)')

    # Project operations
    def get_project(self, github_url: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM projects WHERE url = ?', (github_url,)).fetchone()
            return dict(row) if row else None

    def create_project(self, url: str, repo_name: str, framework: Optional[str] = None, owner: Optional[str] = None, cache_path: Optional[str] = None) -> Dict[str, Any]:
        with self._connect() as conn:
            conn.execute('''
                INSERT OR IGNORE INTO projects (url, repo_name, owner, framework, cloned_at, cache_path)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            ''', (url, repo_name, owner, framework, cache_path))
            row = conn.execute('SELECT * FROM projects WHERE url = ?', (url,)).fetchone()
            return dict(row) if row else {}

    def update_project(self, project_id: int, **fields: Any) -> None:
        if not fields:
            return
        columns = ', '.join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [project_id]
        with self._connect() as conn:
            conn.execute(f'UPDATE projects SET {columns} WHERE id = ?', values)

    # Contract operations
    def get_contracts(self, project_id: int) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM contracts WHERE project_id = ? ORDER BY id', (project_id,)).fetchall()
            return [dict(r) for r in rows]

    def save_contract(self, project_id: int, file_path: str, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        info = info or {}
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO contracts (project_id, file_path, contract_name, solc_version, discovered_at, line_count, dependencies)
                VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?)
                ON CONFLICT(project_id, file_path) DO UPDATE SET
                    contract_name = excluded.contract_name,
                    solc_version = excluded.solc_version,
                    line_count = excluded.line_count,
                    dependencies = excluded.dependencies
            ''', (
                project_id,
                file_path,
                info.get('contract_name'),
                info.get('solc_version'),
                info.get('discovered_at'),
                info.get('line_count'),
                json.dumps(info.get('dependencies', []))
            ))
            row = conn.execute('SELECT * FROM contracts WHERE project_id = ? AND file_path = ?', (project_id, file_path)).fetchone()
            return dict(row) if row else {}

    # Analysis results
    def get_analysis_results(self, contract_id: int) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM analysis_results WHERE contract_id = ?', (contract_id,)).fetchall()
            return [dict(r) for r in rows]

    def save_analysis_result(self, contract_id: int, analysis_type: str, findings: Dict[str, Any], status: str, error_log: Optional[str] = None, analysis_duration_ms: Optional[int] = None, analyzed_at: Optional[str] = None) -> None:
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO analysis_results (contract_id, analysis_type, findings, analyzed_at, status, error_log, analysis_duration_ms)
                VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?)
                ON CONFLICT(contract_id, analysis_type) DO UPDATE SET
                    findings = excluded.findings,
                    analyzed_at = excluded.analyzed_at,
                    status = excluded.status,
                    error_log = excluded.error_log,
                    analysis_duration_ms = excluded.analysis_duration_ms
            ''', (
                contract_id,
                analysis_type,
                json.dumps(findings),
                analyzed_at,
                status,
                error_log,
                analysis_duration_ms
            ))

    # Build artifacts
    def get_build_artifacts(self, project_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM build_artifacts WHERE project_id = ?', (project_id,)).fetchone()
            return dict(row) if row else None

    def save_build_artifacts(self, project_id: int, artifact_path: str, artifact_hash: str, solc_version: Optional[str] = None, dependencies_hash: Optional[str] = None, size_mb: Optional[float] = None) -> None:
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO build_artifacts (project_id, artifact_path, artifact_hash, solc_version, dependencies_hash, created_at, last_accessed, size_mb)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    artifact_path = excluded.artifact_path,
                    artifact_hash = excluded.artifact_hash,
                    solc_version = excluded.solc_version,
                    dependencies_hash = excluded.dependencies_hash,
                    last_accessed = excluded.last_accessed,
                    size_mb = excluded.size_mb
            ''', (project_id, artifact_path, artifact_hash, solc_version, dependencies_hash, size_mb))

    # Errors
    def log_error(self, error_info: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO analysis_errors (project_id, contract_id, error_type, error_message, tool_that_failed, contract_path, full_error_log, occurred_at, status, resolution_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?)
            ''', (
                error_info.get('project_id'),
                error_info.get('contract_id'),
                error_info.get('error_type'),
                error_info.get('error_message'),
                error_info.get('tool_that_failed'),
                error_info.get('contract_path'),
                error_info.get('full_error_log'),
                error_info.get('occurred_at'),
                error_info.get('status'),
                error_info.get('resolution_notes')
            ))

    def get_error_patterns(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute('''
                SELECT error_type, COUNT(*) as frequency
                FROM analysis_errors
                GROUP BY error_type
                ORDER BY frequency DESC
                LIMIT 50
            ''').fetchall()
            return [dict(r) for r in rows]

    # Stats
    def get_project_statistics(self, project_id: int) -> Dict[str, Any]:
        with self._connect() as conn:
            # Calculate derived stats
            total_contracts = conn.execute('SELECT COUNT(*) FROM contracts WHERE project_id = ?', (project_id,)).fetchone()[0]
            total_findings = 0
            critical = 0
            high = 0
            medium = 0
            low = 0
            failed = conn.execute('SELECT COUNT(*) FROM analysis_results WHERE contract_id IN (SELECT id FROM contracts WHERE project_id = ?) AND status = "error"', (project_id,)).fetchone()[0]
            fallback = conn.execute('SELECT COUNT(*) FROM analysis_results WHERE contract_id IN (SELECT id FROM contracts WHERE project_id = ?) AND status = "fallback"', (project_id,)).fetchone()[0]

            # Attempt to aggregate severities if findings JSON contains a standard structure
            rows = conn.execute('SELECT findings FROM analysis_results WHERE contract_id IN (SELECT id FROM contracts WHERE project_id = ?)', (project_id,)).fetchall()
            for r in rows:
                try:
                    f = json.loads(r[0]) if r[0] else {}
                    sev = f.get('severity_counts') or {}
                    total_findings += int(f.get('total_findings', 0))
                    critical += int(sev.get('critical', 0))
                    high += int(sev.get('high', 0))
                    medium += int(sev.get('medium', 0))
                    low += int(sev.get('low', 0))
                except Exception:
                    continue

            stats = {
                'project_id': project_id,
                'total_contracts': total_contracts,
                'total_findings': total_findings,
                'critical_findings': critical,
                'high_findings': high,
                'medium_findings': medium,
                'low_findings': low,
                'fallback_analyses': fallback,
                'failed_analyses': failed,
            }

            # Upsert into project_statistics
            conn.execute('''
                INSERT INTO project_statistics (project_id, total_contracts, total_findings, critical_findings, high_findings, medium_findings, low_findings, fallback_analyses, failed_analyses, analysis_time_seconds, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP)
                ON CONFLICT(project_id) DO UPDATE SET
                    total_contracts = excluded.total_contracts,
                    total_findings = excluded.total_findings,
                    critical_findings = excluded.critical_findings,
                    high_findings = excluded.high_findings,
                    medium_findings = excluded.medium_findings,
                    low_findings = excluded.low_findings,
                    fallback_analyses = excluded.fallback_analyses,
                    failed_analyses = excluded.failed_analyses,
                    last_updated = excluded.last_updated
            ''', (
                project_id,
                stats['total_contracts'],
                stats['total_findings'],
                stats['critical_findings'],
                stats['high_findings'],
                stats['medium_findings'],
                stats['low_findings'],
                stats['fallback_analyses'],
                stats['failed_analyses']
            ))

            return stats

    def is_analysis_complete(self, project_id: int) -> bool:
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) FROM contracts WHERE project_id = ?', (project_id,)).fetchone()[0]
            analyzed = conn.execute('''
                SELECT COUNT(DISTINCT contract_id) FROM analysis_results
                WHERE contract_id IN (SELECT id FROM contracts WHERE project_id = ?)
            ''', (project_id,)).fetchone()[0]
            return total > 0 and analyzed >= total

    def save_audit_result(self, audit_result: AuditResult) -> bool:
        """Save audit result to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_results
                    (id, contract_address, contract_name, network, audit_type,
                     total_vulnerabilities, high_severity_count, critical_severity_count,
                     false_positives, execution_time, created_at, metadata, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    audit_result.id,
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit result: {e}[/red]")
            return False

    def update_audit_result(self, audit_result: AuditResult) -> bool:
        """Update existing audit result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE audit_results
                    SET contract_address = ?, contract_name = ?, network = ?, audit_type = ?,
                        total_vulnerabilities = ?, high_severity_count = ?, critical_severity_count = ?,
                        false_positives = ?, execution_time = ?, created_at = ?, metadata = ?, status = ?
                    WHERE id = ?
                ''', (
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status,
                    audit_result.id
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update audit result: {e}[/red]")
            return False

    def save_audit_metrics(self, metrics: AuditMetrics) -> bool:
        """Save audit metrics to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings,
                     false_positives, accuracy_score, precision_score, recall_score,
                     f1_score, execution_time, llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit metrics: {e}[/red]")
            return False

    def save_vulnerability_findings(self, findings: List[VulnerabilityFinding]) -> bool:
        """Save vulnerability findings to database."""
        if not findings:
            return True

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany('''
                    INSERT OR REPLACE INTO vulnerability_findings
                    (id, audit_result_id, vulnerability_type, severity, confidence,
                     description, line_number, swc_id, file_path, contract_name,
                     status, validation_confidence, validation_reasoning,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', [
                    (
                        finding.id,
                        finding.audit_result_id,
                        finding.vulnerability_type,
                        finding.severity,
                        finding.confidence,
                        finding.description,
                        finding.line_number,
                        finding.swc_id,
                        finding.file_path,
                        finding.contract_name,
                        finding.status,
                        finding.validation_confidence,
                        finding.validation_reasoning,
                        finding.created_at,
                        finding.updated_at
                    ) for finding in findings
                ])
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save vulnerability findings: {e}[/red]")
            return False

    def save_learning_pattern(self, pattern: LearningPattern) -> bool:
        """Save learning pattern to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO learning_patterns
                    (id, pattern_type, contract_pattern, vulnerability_type,
                     original_classification, corrected_classification,
                     confidence_threshold, reasoning, source_audit_id,
                     created_at, usage_count, success_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.id,
                    pattern.pattern_type,
                    pattern.contract_pattern,
                    pattern.vulnerability_type,
                    pattern.original_classification,
                    pattern.corrected_classification,
                    pattern.confidence_threshold,
                    pattern.reasoning,
                    pattern.source_audit_id,
                    pattern.created_at,
                    pattern.usage_count,
                    pattern.success_rate
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save learning pattern: {e}[/red]")
            return False

    def save_audit_metrics(self, metrics: AuditMetrics) -> bool:
        """Save audit metrics to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings,
                     false_positives, accuracy_score, precision_score, recall_score,
                     f1_score, execution_time, llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit metrics: {e}[/red]")
            return False

    def get_audit_results(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get audit results with pagination."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM audit_results
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get audit results: {e}[/red]")
            return []

    def get_audit_result(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Get specific audit result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM audit_results WHERE id = ?', (audit_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get audit result: {e}[/red]")
            return None

    def find_audit_by_contract(self, contract_path: str, contract_name: str, contract_address: str = "unknown") -> Optional[Dict[str, Any]]:
        """Find existing audit result for the same contract."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM audit_results
                    WHERE (contract_name = ? OR contract_address = ?)
                    AND metadata LIKE ?
                    ORDER BY created_at DESC
                    LIMIT 1
                ''', (contract_name, contract_address, f'%{contract_path}%'))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]❌ Failed to find audit by contract: {e}[/red]")
            return None

    def update_audit_result(self, audit_result: AuditResult) -> bool:
        """Update existing audit result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE audit_results
                    SET contract_address = ?, contract_name = ?, network = ?, audit_type = ?,
                        total_vulnerabilities = ?, high_severity_count = ?, critical_severity_count = ?,
                        false_positives = ?, execution_time = ?, created_at = ?, metadata = ?, status = ?
                    WHERE id = ?
                ''', (
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status,
                    audit_result.id
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update audit result: {e}[/red]")
            return False

    def delete_vulnerability_findings(self, audit_result_id: str) -> bool:
        """Delete all vulnerability findings for an audit result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM vulnerability_findings WHERE audit_result_id = ?', (audit_result_id,))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to delete vulnerability findings: {e}[/red]")
            return False

    def get_vulnerability_findings(self, audit_result_id: str) -> List[Dict[str, Any]]:
        """Get vulnerability findings for an audit."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM vulnerability_findings
                    WHERE audit_result_id = ?
                    ORDER BY created_at DESC
                ''', (audit_result_id,))

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get vulnerability findings: {e}[/red]")
            return []

    def get_learning_patterns(self, pattern_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get learning patterns, optionally filtered by type."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                if pattern_type:
                    cursor = conn.execute('''
                        SELECT * FROM learning_patterns
                        WHERE pattern_type = ?
                        ORDER BY success_rate DESC, usage_count DESC
                    ''', (pattern_type,))
                else:
                    cursor = conn.execute('''
                        SELECT * FROM learning_patterns
                        ORDER BY success_rate DESC, usage_count DESC
                    ''')

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get learning patterns: {e}[/red]")
            return []

    def update_learning_pattern_usage(self, pattern_id: str, success: bool) -> bool:
        """Update learning pattern usage statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get current pattern
                cursor = conn.execute('SELECT * FROM learning_patterns WHERE id = ?', (pattern_id,))
                row = cursor.fetchone()

                if not row:
                    return False

                usage_count = row[10] + 1  # usage_count column index
                success_rate = (row[11] * usage_count + (1 if success else 0)) / (usage_count + 1)  # success_rate

                conn.execute('''
                    UPDATE learning_patterns
                    SET usage_count = ?, success_rate = ?
                    WHERE id = ?
                ''', (usage_count, success_rate, pattern_id))

            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update learning pattern: {e}[/red]")
            return False

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get overall audit statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total audits
                total_audits = conn.execute('SELECT COUNT(*) FROM audit_results').fetchone()[0]

                # Audits by status
                status_counts = {}
                for row in conn.execute('SELECT status, COUNT(*) FROM audit_results GROUP BY status'):
                    status_counts[row[0]] = row[1]

                # Total vulnerabilities
                total_vulnerabilities = conn.execute('SELECT SUM(total_vulnerabilities) FROM audit_results').fetchone()[0] or 0

                # Severity distribution
                severity_counts = {}
                for row in conn.execute('SELECT severity, COUNT(*) FROM vulnerability_findings GROUP BY severity'):
                    severity_counts[row[0]] = row[1]

                # Average execution time
                avg_execution_time = conn.execute('SELECT AVG(execution_time) FROM audit_results').fetchone()[0] or 0

                # Recent activity (last 30 days)
                thirty_days_ago = time.time() - (30 * 24 * 3600)
                recent_audits = conn.execute(
                    'SELECT COUNT(*) FROM audit_results WHERE created_at > ?',
                    (thirty_days_ago,)
                ).fetchone()[0]

                return {
                    'total_audits': total_audits,
                    'audits_by_status': status_counts,
                    'total_vulnerabilities': total_vulnerabilities,
                    'vulnerabilities_by_severity': severity_counts,
                    'average_execution_time': avg_execution_time,
                    'recent_audits_30d': recent_audits,
                    'learning_patterns_count': conn.execute('SELECT COUNT(*) FROM learning_patterns').fetchone()[0]
                }
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get audit statistics: {e}[/red]")
            return {}

    def delete_audit_result(self, audit_id: str) -> bool:
        """Delete audit result and all related data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Delete in correct order due to foreign keys
                conn.execute('DELETE FROM vulnerability_findings WHERE audit_result_id = ?', (audit_id,))
                conn.execute('DELETE FROM audit_metrics WHERE audit_result_id = ?', (audit_id,))
                conn.execute('DELETE FROM audit_results WHERE id = ?', (audit_id,))

            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to delete audit result: {e}[/red]")
            return False

    def find_audit_by_contract(self, contract_path: str, contract_name: str, contract_address: str = "unknown") -> Optional[Dict[str, Any]]:
        """Find existing audit result for the same contract."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM audit_results
                    WHERE (contract_name = ? OR contract_address = ?)
                    AND metadata LIKE ?
                    ORDER BY created_at DESC
                    LIMIT 1
                ''', (contract_name, contract_address, f'%{contract_path}%'))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]❌ Failed to find audit by contract: {e}[/red]")
            return None

    def save_vulnerability_findings(self, findings: List[VulnerabilityFinding]) -> bool:
        """Save vulnerability findings to database."""
        if not findings:
            return True

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany('''
                    INSERT OR REPLACE INTO vulnerability_findings
                    (id, audit_result_id, vulnerability_type, severity, confidence,
                     description, line_number, swc_id, file_path, contract_name,
                     status, validation_confidence, validation_reasoning,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', [
                    (
                        finding.id,
                        finding.audit_result_id,
                        finding.vulnerability_type,
                        finding.severity,
                        finding.confidence,
                        finding.description,
                        finding.line_number,
                        finding.swc_id,
                        finding.file_path,
                        finding.contract_name,
                        finding.status,
                        finding.validation_confidence,
                        finding.validation_reasoning,
                        finding.created_at,
                        finding.updated_at
                    ) for finding in findings
                ])
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save vulnerability findings: {e}[/red]")
            return False

    def save_learning_pattern(self, pattern: LearningPattern) -> bool:
        """Save learning pattern to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO learning_patterns
                    (id, pattern_type, contract_pattern, vulnerability_type, original_classification,
                     corrected_classification, confidence_threshold, reasoning, source_audit_id,
                     created_at, usage_count, success_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.id,
                    pattern.pattern_type,
                    pattern.contract_pattern,
                    pattern.vulnerability_type,
                    pattern.original_classification,
                    pattern.corrected_classification,
                    pattern.confidence_threshold,
                    pattern.reasoning,
                    pattern.source_audit_id,
                    pattern.created_at,
                    pattern.usage_count,
                    pattern.success_rate
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save learning pattern: {e}[/red]")
            return False

    def save_audit_result(self, audit_result: AuditResult) -> bool:
        """Save audit result to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_results
                    (id, contract_address, contract_name, network, audit_type,
                     total_vulnerabilities, high_severity_count, critical_severity_count,
                     false_positives, execution_time, created_at, metadata, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    audit_result.id,
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit result: {e}[/red]")
            return False

    def update_audit_result(self, audit_result: AuditResult) -> bool:
        """Update existing audit result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE audit_results
                    SET contract_address = ?, contract_name = ?, network = ?, audit_type = ?,
                        total_vulnerabilities = ?, high_severity_count = ?, critical_severity_count = ?,
                        false_positives = ?, execution_time = ?, created_at = ?, metadata = ?, status = ?
                    WHERE id = ?
                ''', (
                    audit_result.contract_address,
                    audit_result.contract_name,
                    audit_result.network,
                    audit_result.audit_type,
                    audit_result.total_vulnerabilities,
                    audit_result.high_severity_count,
                    audit_result.critical_severity_count,
                    audit_result.false_positives,
                    audit_result.execution_time,
                    audit_result.created_at,
                    json.dumps(audit_result.metadata),
                    audit_result.status,
                    audit_result.id
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update audit result: {e}[/red]")
            return False

    def save_audit_metrics(self, metrics: AuditMetrics) -> bool:
        """Save audit metrics to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings,
                     false_positives, accuracy_score, precision_score, recall_score,
                     f1_score, execution_time, llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit metrics: {e}[/red]")
            return False

    def store_audit_metrics(self, metrics: AuditMetrics) -> None:
        """Store audit metrics in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_metrics
                    (id, audit_result_id, total_findings, confirmed_findings, false_positives,
                     accuracy_score, precision_score, recall_score, f1_score, execution_time,
                     llm_calls, cache_hits, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.id,
                    metrics.audit_result_id,
                    metrics.total_findings,
                    metrics.confirmed_findings,
                    metrics.false_positives,
                    metrics.accuracy_score,
                    metrics.precision_score,
                    metrics.recall_score,
                    metrics.f1_score,
                    metrics.execution_time,
                    metrics.llm_calls,
                    metrics.cache_hits,
                    metrics.created_at
                ))
        except Exception as e:
            self.console.print(f"[red]❌ Failed to store audit metrics: {e}[/red]")
            raise

    # ========== SCOPE PERSISTENCE METHODS ==========
    
    def save_audit_scope(self, project_id: int, selected_contract_paths: List[str], scope_name: Optional[str] = None) -> Dict[str, Any]:
        """Save audit scope to database for resume capability."""
        try:
            with self._connect() as conn:
                # Archive any existing active scope
                conn.execute('''
                    UPDATE audit_scopes 
                    SET status = 'archived'
                    WHERE project_id = ? AND status = 'active'
                ''', (project_id,))
                
                # Create new scope
                cursor = conn.execute('''
                    INSERT INTO audit_scopes 
                    (project_id, scope_name, selected_contracts, status, total_selected, total_pending, modified_at)
                    VALUES (?, ?, ?, 'active', ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    project_id,
                    scope_name or f"Scope_{int(time.time())}",
                    json.dumps(selected_contract_paths),
                    len(selected_contract_paths),
                    len(selected_contract_paths)
                ))
                conn.commit()
                
                return {
                    'id': cursor.lastrowid,
                    'project_id': project_id,
                    'contracts': len(selected_contract_paths),
                    'status': 'active'
                }
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save audit scope: {e}[/red]")
            raise

    def get_active_scope(self, project_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve active audit scope for a project."""
        try:
            with self._connect() as conn:
                cursor = conn.execute('''
                    SELECT id, project_id, scope_name, selected_contracts, status,
                           total_selected, total_audited, total_pending, last_audited_contract_id,
                           created_at, modified_at
                    FROM audit_scopes
                    WHERE project_id = ? AND status = 'active'
                    ORDER BY modified_at DESC
                    LIMIT 1
                ''', (project_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                return {
                    'id': row[0],
                    'project_id': row[1],
                    'scope_name': row[2],
                    'selected_contracts': json.loads(row[3]),
                    'status': row[4],
                    'total_selected': row[5],
                    'total_audited': row[6],
                    'total_pending': row[7],
                    'last_audited_contract_id': row[8],
                    'created_at': self._convert_utc_to_local(row[9]),
                    'modified_at': self._convert_utc_to_local(row[10])
                }
        except Exception as e:
            self.console.print(f"[red]❌ Failed to retrieve active scope: {e}[/red]")
            return None
    
    def get_last_scope(self, project_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent audit scope for a project (any status)."""
        try:
            with self._connect() as conn:
                cursor = conn.execute('''
                    SELECT id, project_id, scope_name, selected_contracts, status,
                           total_selected, total_audited, total_pending, last_audited_contract_id,
                           created_at, modified_at
                    FROM audit_scopes
                    WHERE project_id = ?
                    ORDER BY modified_at DESC
                    LIMIT 1
                ''', (project_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                return {
                    'id': row[0],
                    'project_id': row[1],
                    'scope_name': row[2],
                    'selected_contracts': json.loads(row[3]),
                    'status': row[4],
                    'total_selected': row[5],
                    'total_audited': row[6],
                    'total_pending': row[7],
                    'last_audited_contract_id': row[8],
                    'created_at': self._convert_utc_to_local(row[9]),
                    'modified_at': self._convert_utc_to_local(row[10])
                }
        except Exception as e:
            self.console.print(f"[red]❌ Failed to retrieve last scope: {e}[/red]")
            return None
    
    def get_all_scopes(self, project_id: int) -> List[Dict[str, Any]]:
        """Retrieve all audit scopes for a project (any status)."""
        try:
            with self._connect() as conn:
                cursor = conn.execute('''
                    SELECT id, project_id, scope_name, selected_contracts, status,
                           total_selected, total_audited, total_pending, last_audited_contract_id,
                           created_at, modified_at
                    FROM audit_scopes
                    WHERE project_id = ?
                    ORDER BY modified_at DESC
                ''', (project_id,))
                
                rows = cursor.fetchall()
                scopes = []
                for row in rows:
                    scopes.append({
                        'id': row[0],
                        'project_id': row[1],
                        'scope_name': row[2],
                        'selected_contracts': json.loads(row[3]),
                        'status': row[4],
                        'total_selected': row[5],
                        'total_audited': row[6],
                        'total_pending': row[7],
                        'last_audited_contract_id': row[8],
                        'created_at': self._convert_utc_to_local(row[9]),
                        'modified_at': self._convert_utc_to_local(row[10])
                    })
                return scopes
        except Exception as e:
            self.console.print(f"[red]❌ Failed to retrieve scopes: {e}[/red]")
            return []

    def update_scope_progress(self, scope_id: int, contract_id: int, audited_count: int, pending_count: int) -> bool:
        """Update scope progress after analyzing a contract."""
        try:
            with self._connect() as conn:
                conn.execute('''
                    UPDATE audit_scopes
                    SET total_audited = ?, total_pending = ?, last_audited_contract_id = ?, modified_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (audited_count, pending_count, contract_id, scope_id))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update scope progress: {e}[/red]")
            return False

    def update_scope_contracts(self, scope_id: int, selected_contract_paths: List[str]) -> bool:
        """Update the list of selected contracts in a scope."""
        try:
            with self._connect() as conn:
                conn.execute('''
                    UPDATE audit_scopes
                    SET selected_contracts = ?, total_selected = ?, total_pending = ?, modified_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (
                    json.dumps(selected_contract_paths),
                    len(selected_contract_paths),
                    len(selected_contract_paths),  # Reset pending to total when updating
                    scope_id
                ))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to update scope contracts: {e}[/red]")
            return False

    def complete_scope(self, scope_id: int) -> bool:
        """Mark a scope as completed."""
        try:
            with self._connect() as conn:
                conn.execute('''
                    UPDATE audit_scopes
                    SET status = 'completed', total_pending = 0, modified_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (scope_id,))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to complete scope: {e}[/red]")
            return False
    
    def reactivate_scope(self, scope_id: int) -> bool:
        """Reactivate a completed scope for adding more contracts."""
        try:
            with self._connect() as conn:
                conn.execute('''
                    UPDATE audit_scopes
                    SET status = 'active', modified_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (scope_id,))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to reactivate scope: {e}[/red]")
            return False

    def reset_scope_for_reaudit(self, scope_id: int) -> bool:
        """Reset scope for fresh re-analysis of all contracts."""
        try:
            with self._connect() as conn:
                # Get scope info
                cursor = conn.execute('SELECT selected_contracts FROM audit_scopes WHERE id = ?', (scope_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                
                contracts = json.loads(row[0])
                
                # Reset progress
                conn.execute('''
                    UPDATE audit_scopes
                    SET total_audited = 0, total_pending = ?, last_audited_contract_id = NULL, modified_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (len(contracts), scope_id))
                
                # Delete existing findings for contracts in this scope
                conn.execute('''
                    DELETE FROM analysis_results
                    WHERE contract_id IN (
                        SELECT id FROM contracts WHERE project_id = (
                            SELECT project_id FROM audit_scopes WHERE id = ?
                        )
                    ) AND status = 'success'
                ''', (scope_id,))
                
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to reset scope for re-audit: {e}[/red]")
            return False

    def get_scope_history(self, project_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Get history of all scopes for a project."""
        try:
            with self._connect() as conn:
                cursor = conn.execute('''
                    SELECT id, scope_name, selected_contracts, status, total_selected, total_audited, created_at
                    FROM audit_scopes
                    WHERE project_id = ?
                    ORDER BY modified_at DESC
                    LIMIT ?
                ''', (project_id, limit))
                
                scopes = []
                for row in cursor.fetchall():
                    scopes.append({
                        'id': row[0],
                        'scope_name': row[1],
                        'contracts': json.loads(row[2]),
                        'status': row[3],
                        'total_selected': row[4],
                        'total_audited': row[5],
                        'created_at': self._convert_utc_to_local(row[6])
                    })
                return scopes
        except Exception as e:
            self.console.print(f"[red]❌ Failed to retrieve scope history: {e}[/red]")
            return []
    
    def close(self) -> None:
        """Close database connection. This method is called on graceful shutdown."""
        try:
            # SQLite connections are automatically closed when the connection object
            # goes out of scope or is garbage collected, so this is mainly for consistency
            # with other database managers that might have persistent connections
            pass
        except Exception as e:
            self.console.print(f"[yellow]⚠️  Warning during database close: {e}[/yellow]")
    
    def _close(self) -> None:
        """Alias for close() to support different shutdown protocols."""
        self.close()
    
    def recalculate_scope_progress(self, scope_id: int) -> Dict[str, int]:
        """
        Recalculate audit progress for a scope by checking which selected contracts
        have actually been analyzed in the database.
        
        Args:
            scope_id: The audit scope ID
            
        Returns:
            Dict with keys: total_selected, total_audited, total_pending, last_audited_contract_id
        """
        try:
            with self._connect() as conn:
                # Get the scope and its selected contracts
                cursor = conn.execute(
                    'SELECT selected_contracts FROM audit_scopes WHERE id = ?',
                    (scope_id,)
                )
                scope_row = cursor.fetchone()
                if not scope_row:
                    return {'total_selected': 0, 'total_audited': 0, 'total_pending': 0}
                
                selected_contracts = json.loads(scope_row[0])
                total_selected = len(selected_contracts)
                
                # Get all contracts with their analysis status
                # Use a subquery to properly count success results per contract
                cursor = conn.execute('''
                    SELECT c.id, c.file_path, 
                           (SELECT COUNT(*) FROM analysis_results ar 
                            WHERE ar.contract_id = c.id AND ar.status = 'success') as has_success
                    FROM contracts c
                    WHERE c.project_id = (SELECT project_id FROM audit_scopes WHERE id = ?)
                ''', (scope_id,))
                
                # Build a map of file_path -> (contract_id, analyzed)
                path_to_status = {}
                for row in cursor.fetchall():
                    contract_id = row[0]
                    file_path = row[1]
                    has_success = row[2] > 0  # Check if count > 0
                    path_to_status[file_path] = (contract_id, has_success)
                
                # Count how many selected contracts have been analyzed
                total_audited = 0
                last_audited_id = None
                for path in selected_contracts:
                    if path in path_to_status:
                        contract_id, analyzed = path_to_status[path]
                        if analyzed:
                            total_audited += 1
                            last_audited_id = contract_id
                
                total_pending = total_selected - total_audited
                
                # Update the scope record with actual progress
                conn.execute('''
                    UPDATE audit_scopes
                    SET total_audited = ?, total_pending = ?, last_audited_contract_id = ?
                    WHERE id = ?
                ''', (total_audited, total_pending, last_audited_id, scope_id))
                conn.commit()
                
                return {
                    'total_selected': total_selected,
                    'total_audited': total_audited,
                    'total_pending': total_pending,
                    'last_audited_contract_id': last_audited_id
                }
        except Exception as e:
            self.console.print(f"[yellow]⚠️  Warning: Could not recalculate scope progress: {e}[/yellow]")
            return {'total_selected': 0, 'total_audited': 0, 'total_pending': 0}
