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
    status: str  # 'completed', 'failed', 'in_progress'


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

    def vacuum_database(self) -> bool:
        """Optimize database by rebuilding it."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('VACUUM')
            self.console.print("[green]✅ Database vacuumed successfully[/green]")
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Failed to vacuum database: {e}[/red]")
            return False

    def export_data(self, format: str = 'json') -> str:
        """Export all data for backup or migration."""
        try:
            if format.lower() == 'json':
                return self._export_to_json()
            else:
                raise ValueError(f"Unsupported export format: {format}")
        except Exception as e:
            self.console.print(f"[red]❌ Failed to export data: {e}[/red]")
            return ""

    def _export_to_json(self) -> str:
        """Export database to JSON format."""
        data = {
            'audit_results': [],
            'vulnerability_findings': [],
            'learning_patterns': [],
            'audit_metrics': [],
            'exported_at': time.time()
        }

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # Export audit results
                for row in conn.execute('SELECT * FROM audit_results'):
                    data['audit_results'].append(dict(row))

                # Export vulnerability findings
                for row in conn.execute('SELECT * FROM vulnerability_findings'):
                    data['vulnerability_findings'].append(dict(row))

                # Export learning patterns
                for row in conn.execute('SELECT * FROM learning_patterns'):
                    data['learning_patterns'].append(dict(row))

                # Export audit metrics
                for row in conn.execute('SELECT * FROM audit_metrics'):
                    data['audit_metrics'].append(dict(row))

            return json.dumps(data, indent=2)
        except Exception as e:
            self.console.print(f"[red]❌ Failed to export to JSON: {e}[/red]")
            return ""

    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Database size
                db_size = self.db_path.stat().st_size

                # Table row counts
                table_counts = {}
                for table in ['audit_results', 'vulnerability_findings', 'learning_patterns', 'audit_metrics']:
                    count = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                    table_counts[table] = count

                # Database version
                version = conn.execute('SELECT sqlite_version()').fetchone()[0]

                return {
                    'database_path': str(self.db_path),
                    'database_size_bytes': db_size,
                    'table_counts': table_counts,
                    'sqlite_version': version,
                    'created_at': self.db_path.stat().st_mtime
                }
        except Exception as e:
            self.console.print(f"[red]❌ Failed to get database info: {e}[/red]")
            return {}

    def store_learning_pattern(self, pattern: LearningPattern) -> None:
        """Store a learning pattern in the database."""
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
        except Exception as e:
            self.console.print(f"[red]❌ Failed to store learning pattern: {e}[/red]")
            raise

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
