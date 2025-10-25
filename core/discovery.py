#!/usr/bin/env python3
"""
Contract Discovery (Phase 2)

Enumerates Solidity contracts, captures simple metadata, and persists via DB.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

from rich.console import Console

from core.database_manager import AetherDatabase


@dataclass
class ContractInfo:
    file_path: Path
    contract_name: Optional[str]
    solc_version: Optional[str]
    line_count: int
    dependencies: List[str]


class ContractDiscovery:
    def __init__(self, db: Optional[AetherDatabase] = None):
        self.console = Console()
        self.db = db or AetherDatabase()

    def discover(self, project_id: int, project_path: Union[str, Path]) -> List[ContractInfo]:
        project_path = Path(project_path)
        contracts: List[ContractInfo] = []
        
        # Directories to skip (dependencies, build artifacts, tests)
        SKIP_DIRS = {
            'lib', 'libs', 'node_modules', 'out', 'artifacts', 'cache', 
            'build', 'dist', '.git', 'venv', 'env', 'test', 'tests'
        }
        
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories (modifies dirs in-place to prune walk)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            # Also skip if path contains these patterns
            root_path = Path(root)
            if any(skip in root_path.parts for skip in SKIP_DIRS):
                continue
            
            for f in files:
                if f.endswith('.sol'):
                    fp = Path(root) / f
                    info = self._extract_contract_info(fp)
                    contracts.append(info)
                    self.db.save_contract(
                        project_id=project_id,
                        file_path=str(fp.relative_to(project_path)),
                        info={
                            'contract_name': info.contract_name,
                            'solc_version': info.solc_version,
                            'line_count': info.line_count,
                            'dependencies': info.dependencies,
                        },
                    )
        return contracts

    def _extract_contract_info(self, file_path: Path) -> ContractInfo:
        try:
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            text = ''
        lines = text.splitlines()
        line_count = len(lines)
        solc_version = None
        contract_name = None
        dependencies: List[str] = []
        for line in lines[:100]:  # quick scan of top lines
            if line.strip().startswith('pragma solidity'):
                solc_version = line.strip()
            if line.strip().startswith('import '):
                try:
                    dep = line.split('import', 1)[1].strip().strip(';').strip('"').strip("'")
                    dependencies.append(dep)
                except Exception:
                    continue
            if 'contract ' in line:
                try:
                    after = line.split('contract', 1)[1].strip()
                    name = after.split('{', 1)[0].split('is', 1)[0].strip()
                    if name:
                        contract_name = name.split()[0]
                except Exception:
                    continue
        return ContractInfo(file_path=file_path, contract_name=contract_name, solc_version=solc_version, line_count=line_count, dependencies=dependencies)


