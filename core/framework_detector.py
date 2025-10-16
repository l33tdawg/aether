#!/usr/bin/env python3
"""
FrameworkDetector

Detects Solidity project frameworks (Foundry/Hardhat/Truffle) and extracts
useful configuration like remappings/lib paths and suggested solc version.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from rich.console import Console


class FrameworkDetector:
    def __init__(self):
        self.console = Console()

    def detect(self, repo_path: Union[str, Path]) -> Optional[str]:
        repo_path = Path(repo_path)
        if (repo_path / 'foundry.toml').exists():
            return 'foundry'
        if (repo_path / 'hardhat.config.js').exists() or (repo_path / 'hardhat.config.ts').exists():
            return 'hardhat'
        if (repo_path / 'truffle-config.js').exists():
            return 'truffle'
        return None

    def read_config(self, repo_path: Union[str, Path]) -> Dict[str, Union[str, Dict, List]]:
        repo_path = Path(repo_path)
        framework = self.detect(repo_path)
        config: Dict[str, Union[str, Dict, List]] = {'framework': framework or 'unknown'}

        if framework == 'foundry':
            config_path = repo_path / 'foundry.toml'
            try:
                content = config_path.read_text(encoding='utf-8')
                config['raw'] = content
            except Exception:
                pass
        elif framework == 'hardhat':
            # Hardhat config is JS/TS; we return filename reference only
            if (repo_path / 'hardhat.config.ts').exists():
                config['file'] = 'hardhat.config.ts'
            else:
                config['file'] = 'hardhat.config.js'
        elif framework == 'truffle':
            config['file'] = 'truffle-config.js'

        return config

    def get_solc_version(self, repo_path: Union[str, Path]) -> Optional[str]:
        repo_path = Path(repo_path)
        framework = self.detect(repo_path)
        if framework == 'foundry':
            # Heuristic: try to parse solc version from foundry.toml
            try:
                text = (repo_path / 'foundry.toml').read_text(encoding='utf-8')
                for line in text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('solc_version') or line.lower().startswith('solc'):
                        if '"' in line:
                            return line.split('"')[1]
                        if "'" in line:
                            return line.split("'")[1]
                        if '=' in line:
                            return line.split('=', 1)[1].strip()
            except Exception:
                return None
        # For hardhat/truffle we skip parsing JS; future improvement could evaluate config.
        return None

    def get_remappings(self, repo_path: Union[str, Path]) -> Dict[str, str]:
        repo_path = Path(repo_path)
        framework = self.detect(repo_path)
        remap: Dict[str, str] = {}
        if framework == 'foundry':
            try:
                remap_file = repo_path / 'remappings.txt'
                if remap_file.exists():
                    for line in remap_file.read_text(encoding='utf-8').splitlines():
                        line = line.strip()
                        if not line or '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        remap[k.strip()] = v.strip()
            except Exception:
                return remap
        return remap

    def get_lib_paths(self, repo_path: Union[str, Path]) -> List[str]:
        repo_path = Path(repo_path)
        libs: List[str] = []
        for candidate in ['lib', 'node_modules']:
            p = repo_path / candidate
            if p.exists():
                libs.append(str(p))
        return libs

    def supports_framework(self, repo_path: Union[str, Path]) -> bool:
        return self.detect(repo_path) is not None


