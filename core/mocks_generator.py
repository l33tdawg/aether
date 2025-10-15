#!/usr/bin/env python3
"""
Mocks/Interfaces Hydration Utility

Resolves imported Solidity files via project remappings and extracts concrete
interface and struct definitions into a per-suite vendor/ folder. Adds a
vendor remapping for the suite to prefer these local copies when needed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional


class MocksGenerator:
    def __init__(self, project_root: Path, remappings: Optional[List[str]] = None) -> None:
        self.project_root = project_root.resolve()
        self.remappings = remappings or []

    def set_remappings(self, remappings: List[str]) -> None:
        self.remappings = remappings

    def hydrate_suite(self, contract_code: str, suite_dir: str) -> Dict[str, str]:
        """Extract real interfaces/structs from imported files into vendor/.

        Returns mapping of name -> file path written.
        """
        if not contract_code:
            return {}

        imports = self._parse_imports(contract_code)
        if not imports:
            return {}

        vendor_dir = Path(suite_dir) / "vendor"
        vendor_dir.mkdir(parents=True, exist_ok=True)

        written: Dict[str, str] = {}
        for imp in imports:
            abs_path = self._resolve_import_path(imp)
            if not abs_path:
                continue
            defs = self._extract_defs_from_file(abs_path)
            for name, code in defs.items():
                target_file = vendor_dir / f"{name}.sol"
                if name in written:
                    continue
                try:
                    target_file.write_text(code)
                    written[name] = str(target_file)
                except Exception:
                    pass

        # Append vendor remapping to foundry.toml if present
        self._ensure_vendor_remap(Path(suite_dir))

        return written

    def hydrate_vendor_files(self, contract_code: str, suite_dir: str) -> Dict[str, str]:
        """Copy missing imported files into vendor/ preserving prefix directories (e.g., src/, oz/).

        Adds remaps like:
          - src/=./vendor/src/
          - oz/=./vendor/oz/

        Recursively processes imports discovered in copied files.
        Returns mapping of import path -> vendor destination path.
        """
        if not contract_code:
            return {}

        vendor_root = Path(suite_dir) / "vendor"
        vendor_root.mkdir(parents=True, exist_ok=True)

        copied: Dict[str, str] = {}
        queue: List[str] = self._parse_imports(contract_code)
        seen: set[str] = set(queue)

        def write_and_queue(abs_path: Path, import_path: str) -> None:
            # Determine prefix (e.g., src/, oz/) and relative
            parts = import_path.split('/')
            if len(parts) > 1:
                prefix = parts[0]
                rel = '/'.join(parts[1:])
            else:
                prefix = ''
                rel = import_path
            dest_dir = vendor_root / (prefix if prefix else '.')
            if prefix:
                dest_dir = vendor_root / prefix
            dest_path = dest_dir / rel
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest_path.write_text(abs_path.read_text())
                copied[import_path] = str(dest_path)
                # Parse imports inside this copied file and enqueue if unseen
                inner_imports = self._parse_imports(abs_path.read_text())
                for ip in inner_imports:
                    if ip not in seen:
                        seen.add(ip)
                        queue.append(ip)
            except Exception:
                pass

        # BFS over imports
        i = 0
        while i < len(queue):
            imp = queue[i]
            i += 1
            # Skip if resolvable by existing remaps (let forge/slither handle)
            abs_path = self._resolve_import_path(imp)
            if abs_path:
                write_and_queue(abs_path, imp)
                continue
            # Try workspace search heuristics
            candidate = self._search_workspace_for(imp)
            if candidate:
                write_and_queue(candidate, imp)

        # Add prefix remaps for known prefixes used
        prefixes = {p.split('/')[0] for p in copied.keys() if '/' in p}
        # Only enforce vendor remaps for project-local prefix 'src'
        prefixes = {p for p in prefixes if p == 'src'}
        self._ensure_prefix_remaps(Path(suite_dir), prefixes)

        return copied

    def _parse_imports(self, code: str) -> List[str]:
        imports: List[str] = []
        for m in re.findall(r'import\s+["\']([^"\']+)["\'];', code):
            imports.append(m)
        # uniq, preserve order
        seen = set()
        ordered = []
        for p in imports:
            if p not in seen:
                ordered.append(p)
                seen.add(p)
        return ordered

    def _resolve_import_path(self, import_path: str) -> Optional[Path]:
        # Absolute
        if import_path.startswith('/'):
            p = Path(import_path)
            return p if p.exists() else None

        for m in self.remappings:
            if '=' not in m:
                continue
            prefix, target = m.split('=', 1)
            if import_path.startswith(prefix):
                rel = import_path[len(prefix):]
                candidate = Path(target) / rel
                if candidate.exists():
                    return candidate

        candidate = self.project_root / import_path
        return candidate if candidate.exists() else None

    def _extract_defs_from_file(self, abs_path: Path) -> Dict[str, str]:
        out: Dict[str, str] = {}
        try:
            src = abs_path.read_text()
        except Exception:
            return out

        # interfaces
        for m in re.finditer(r'(interface\s+(\w+)\s*\{[\s\S]*?\})', src, re.MULTILINE):
            block, name = m.group(1), m.group(2)
            out[name] = f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\n{block}\n"

        # structs
        for m in re.finditer(r'(struct\s+(\w+)\s*\{[\s\S]*?\})', src, re.MULTILINE):
            block, name = m.group(1), m.group(2)
            out[name] = f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\n{block}\n"

        return out

    def _ensure_vendor_remap(self, suite_dir: Path) -> None:
        try:
            toml = suite_dir / "foundry.toml"
            if not toml.exists():
                return
            content = toml.read_text()
            # Add vendor remap with precedence (prepend)
            existing = self._normalize_remaps(content)
            # If already present, keep order
            if any(r.startswith("vendor/=") for r in existing):
                return
            # Prepend vendor remap
            new_arr = ["vendor/=./vendor/"] + existing
            content = self._replace_or_append_remaps(content, new_arr)
            toml.write_text(content)
        except Exception:
            pass

    def _ensure_prefix_remaps(self, suite_dir: Path, prefixes: set[str]) -> None:
        try:
            if not prefixes:
                return
            toml = suite_dir / "foundry.toml"
            if not toml.exists():
                return
            content = toml.read_text()
            existing = self._normalize_remaps(content)
            # Build map of key->remap keeping existing order
            def key_of(r: str) -> str:
                return r.split('=', 1)[0] if '=' in r else r
            existing_keys = [key_of(r) for r in existing]
            # Prepare vendor prefix remaps (src/, oz/, etc.) and prepend them
            vendor_prefix_remaps = [f"{p}/=./vendor/{p}/" for p in prefixes]
            # Filter out any existing entries with same keys to ensure vendor precedence
            filtered_existing = [r for r in existing if key_of(r) not in prefixes]
            new_arr = vendor_prefix_remaps + filtered_existing
            content = self._replace_or_append_remaps(content, new_arr)
            toml.write_text(content)
        except Exception:
            pass

    def _normalize_remaps(self, content: str) -> List[str]:
        # Attempt to parse existing remappings array
        matches = re.findall(r'remappings\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if not matches:
            return []
        inside = matches[-1]
        items = re.findall(r'"([^"]+)"', inside)
        return items

    def _replace_or_append_remaps(self, content: str, remaps: List[str]) -> str:
        block = "remappings = [\n" + ",\n".join([f"  \"{r}\"" for r in remaps]) + "\n]"
        if "remappings = [" in content:
            return re.sub(r'remappings\s*=\s*\[(.*?)\]', block, content, flags=re.DOTALL)
        return content.rstrip() + "\n" + block + "\n"

    def _search_workspace_for(self, import_path: str) -> Optional[Path]:
        """Heuristically search project tree for a file matching the import path.

        Tries exact suffix match, then basename match.
        """
        try:
            # Exact suffix search
            suffix = import_path
            for p in self.project_root.rglob('*'):
                if p.is_file():
                    try:
                        rp = str(p.resolve())
                        if rp.endswith(suffix):
                            return p
                    except Exception:
                        continue
            # Basename fallback
            base = Path(import_path).name
            for p in self.project_root.rglob(base):
                if p.is_file():
                    return p
        except Exception:
            return None
        return None


