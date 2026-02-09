"""GitHub audit helper — decomposed methods for Textual TUI integration.

Wraps GitHubAuditor, AetherDatabase, RepositoryManager, and related classes
to provide atomic operations callable from Textual screens without raw
terminal access.  Does NOT modify core/github_auditor.py.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class GitHubAuditHelper:
    """Provides decomposed GitHub audit operations for the TUI."""

    def __init__(self):
        self._db = None
        self._repo_manager = None

    def _get_db(self):
        if self._db is None:
            from core.database_manager import AetherDatabase
            self._db = AetherDatabase()
        return self._db

    def _get_repo_manager(self):
        if self._repo_manager is None:
            from core.repository_manager import RepositoryManager
            self._repo_manager = RepositoryManager(db=self._get_db())
        return self._repo_manager

    # ── Clone & discover ──────────────────────────────────────────

    def clone_and_discover(
        self,
        url: str,
        fresh: bool = False,
    ) -> Dict[str, Any]:
        """Clone a repo and discover contracts.

        Returns:
            {
                "project_id": int,
                "repo_name": str,
                "contracts": List[Dict],  # [{contract_name, file_path}, ...]
                "repo_dir": str,
                "framework": str | None,
            }
        """
        from core.framework_detector import FrameworkDetector
        from core.discovery import ContractDiscovery
        from core.builder import ProjectBuilder

        db = self._get_db()
        repo_manager = self._get_repo_manager()

        # Normalize URL
        normalized = repo_manager._normalize_github_url(url)

        # Clone or get cached
        clone_result = repo_manager.clone_or_get(normalized, force_fresh=fresh)
        repo_path = clone_result.repo_path

        # Extract owner/repo for naming
        parts = normalized.rstrip("/").rstrip(".git").split("/")
        repo_name = parts[-1] if parts else "unknown"
        owner = parts[-2] if len(parts) >= 2 else ""

        # Detect framework
        detector = FrameworkDetector()
        framework = detector.detect(repo_path)

        # Create or update project in DB
        existing = db.get_project(normalized)
        if existing:
            project_id = existing["id"]
            db.update_project(project_id, framework=framework)
        else:
            project = db.create_project(
                url=normalized,
                repo_name=repo_name,
                framework=framework,
                owner=owner,
                cache_path=str(repo_path),
            )
            project_id = project["id"]

        # Build project (non-interactive)
        try:
            builder = ProjectBuilder(db=db)
            builder.build(project_id, repo_path, framework)
        except Exception:
            pass  # Build failures shouldn't block discovery

        # Discover contracts
        discovery = ContractDiscovery(db=db)
        contract_infos = discovery.discover(project_id, repo_path)

        contracts = []
        for ci in contract_infos:
            contracts.append({
                "contract_name": ci.contract_name or ci.file_path.stem,
                "file_path": str(ci.file_path),
                "line_count": ci.line_count,
            })

        return {
            "project_id": project_id,
            "repo_name": repo_name,
            "contracts": contracts,
            "repo_dir": str(repo_path),
            "framework": framework,
        }

    # ── Scope state queries ───────────────────────────────────────

    def get_scope_state(self, project_id: int) -> Dict[str, Any]:
        """Get the scope state for a project without any interactive prompts.

        Returns:
            {
                "has_scopes": bool,
                "scopes": List[Dict],
                "active_scope": Dict | None,
                "completed_scopes": List[Dict],
            }
        """
        db = self._get_db()

        active = db.get_active_scope(project_id)
        all_scopes = db.get_all_scopes(project_id)
        completed = [s for s in all_scopes if s.get("status") == "completed"]

        return {
            "has_scopes": len(all_scopes) > 0,
            "scopes": all_scopes,
            "active_scope": active,
            "completed_scopes": completed,
        }

    def get_contracts_for_project(self, project_id: int) -> List[Dict[str, Any]]:
        """Get all discovered contracts for a project from the DB."""
        db = self._get_db()
        return db.get_contracts(project_id)

    # ── Scope management ──────────────────────────────────────────

    def save_new_scope(
        self,
        project_id: int,
        selected_paths: List[str],
        scope_name: Optional[str] = None,
    ) -> int:
        """Save a new audit scope with the given selected contract paths.

        Returns the scope_id.
        """
        db = self._get_db()
        result = db.save_audit_scope(project_id, selected_paths, scope_name)
        return result["id"]

    def get_pending_contracts(self, scope_id: int) -> List[str]:
        """Get contract paths that haven't been audited yet in this scope.

        Returns list of relative file paths.
        """
        db = self._get_db()
        # Get scope details
        try:
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT selected_contracts, total_audited FROM audit_scopes WHERE id = ?",
                (scope_id,),
            ).fetchone()
            conn.close()

            if not row:
                return []

            import json
            selected = json.loads(row["selected_contracts"]) if row["selected_contracts"] else []
            total_audited = row["total_audited"] or 0

            if total_audited >= len(selected):
                return []

            # Return the pending portion
            return selected[total_audited:]
        except Exception:
            return []

    def handle_reaudit(self, scope_id: int) -> bool:
        """Reset a scope for re-audit.

        Returns True on success.
        """
        db = self._get_db()
        return db.reset_scope_for_reaudit(scope_id)

    def get_previously_audited_paths(self, project_id: int) -> List[str]:
        """Get all contract paths that have been audited in any scope for this project."""
        db = self._get_db()
        all_scopes = db.get_all_scopes(project_id)
        audited_paths = set()
        for scope in all_scopes:
            selected = scope.get("selected_contracts", [])
            if isinstance(selected, str):
                import json
                try:
                    selected = json.loads(selected)
                except (json.JSONDecodeError, TypeError):
                    selected = []
            total_audited = scope.get("total_audited", 0) or 0
            for path in selected[:total_audited]:
                audited_paths.add(path)
        return list(audited_paths)
