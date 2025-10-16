#!/usr/bin/env python3
"""
Project Builder for GitHub Audit (Phase 2)

Supports Foundry and Hardhat builds with basic caching and log capture.
Persists build artifact metadata via `AetherDatabase` when successful.
"""

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from rich.console import Console

from core.database_manager import AetherDatabase


def _run(cmd: list[str], cwd: Optional[Union[str, Path]] = None, env: Optional[dict] = None) -> Tuple[int, str, str]:
    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env if env is not None else os.environ.copy(),
    )
    out, err = process.communicate()
    return process.returncode, out, err


def _hash_path(path: Union[str, Path]) -> str:
    path = Path(path)
    hasher = hashlib.sha256()
    if not path.exists():
        return hasher.hexdigest()
    for root, _, files in os.walk(path):
        for f in sorted(files):
            fp = Path(root) / f
            try:
                hasher.update(fp.read_bytes())
            except Exception:
                continue
    return hasher.hexdigest()


@dataclass
class BuildResult:
    success: bool
    log: str
    artifact_path: Optional[Path]
    solc_version: Optional[str]


class ProjectBuilder:
    def __init__(self, db: Optional[AetherDatabase] = None):
        self.console = Console()
        self.db = db or AetherDatabase()

    def build(self, framework: Optional[str], project_path: Union[str, Path], project_id: Optional[int] = None, skip: bool = False) -> BuildResult:
        if skip or not framework:
            return BuildResult(success=True, log='build skipped', artifact_path=None, solc_version=None)

        project_path = Path(project_path)
        if framework == 'foundry':
            return self._build_foundry(project_path, project_id)
        if framework == 'hardhat':
            return self._build_hardhat(project_path, project_id)
        return BuildResult(success=True, log=f'no build needed for framework={framework}', artifact_path=None, solc_version=None)

    def _build_foundry(self, project_path: Path, project_id: Optional[int]) -> BuildResult:
        cache_dir = project_path / 'out'
        deps_hash = _hash_path(project_path / 'lib')
        code, out, err = _run(['forge', 'build', '-q'], cwd=project_path)
        success = code == 0
        log = (out or '') + ("\n" + err if err else '')
        solc_version = self._extract_solc_version_from_foundry(project_path)
        artifact = cache_dir if cache_dir.exists() else None
        if success and project_id is not None and artifact:
            self.db.save_build_artifacts(
                project_id=project_id,
                artifact_path=str(artifact),
                artifact_hash=_hash_path(artifact),
                solc_version=solc_version,
                dependencies_hash=deps_hash,
                size_mb=self._dir_size_mb(artifact),
            )
            self.db.update_project(project_id, build_status='success', build_log=log, solc_version=solc_version)
        elif project_id is not None:
            self.db.update_project(project_id, build_status='failed', build_log=log)
        return BuildResult(success=success, log=log, artifact_path=artifact, solc_version=solc_version)

    def _build_hardhat(self, project_path: Path, project_id: Optional[int]) -> BuildResult:
        cache_dir = project_path / 'artifacts'
        deps_hash = _hash_path(project_path / 'node_modules')
        # Try npx hardhat compile first, fallback to yarn/npm scripts
        code, out, err = _run(['npx', '--yes', 'hardhat', 'compile'], cwd=project_path)
        if code != 0:
            code, out, err = _run(['npm', 'run', 'build'], cwd=project_path)
        success = code == 0
        log = (out or '') + ("\n" + err if err else '')
        solc_version = self._extract_solc_version_from_hardhat(project_path)
        artifact = cache_dir if cache_dir.exists() else None
        if success and project_id is not None and artifact:
            self.db.save_build_artifacts(
                project_id=project_id,
                artifact_path=str(artifact),
                artifact_hash=_hash_path(artifact),
                solc_version=solc_version,
                dependencies_hash=deps_hash,
                size_mb=self._dir_size_mb(artifact),
            )
            self.db.update_project(project_id, build_status='success', build_log=log, solc_version=solc_version)
        elif project_id is not None:
            self.db.update_project(project_id, build_status='failed', build_log=log)
        return BuildResult(success=success, log=log, artifact_path=artifact, solc_version=solc_version)

    def _dir_size_mb(self, path: Path) -> float:
        total = 0
        for root, _, files in os.walk(path):
            for f in files:
                try:
                    total += (Path(root) / f).stat().st_size
                except OSError:
                    continue
        return round(total / (1024 * 1024), 3)

    def _extract_solc_version_from_foundry(self, project_path: Path) -> Optional[str]:
        toml = project_path / 'foundry.toml'
        if not toml.exists():
            return None
        try:
            text = toml.read_text(encoding='utf-8')
            for line in text.splitlines():
                if 'solc_version' in line or 'solc' in line:
                    return line.split('=')[-1].strip().strip('"').strip("'")
        except Exception:
            return None
        return None

    def _extract_solc_version_from_hardhat(self, project_path: Path) -> Optional[str]:
        # Try to read hardhat config JSON if exists
        config_json = project_path / 'hardhat.config.json'
        if config_json.exists():
            try:
                cfg = json.loads(config_json.read_text(encoding='utf-8'))
                return cfg.get('solidity', {}).get('version') if isinstance(cfg.get('solidity'), dict) else None
            except Exception:
                return None
        return None


