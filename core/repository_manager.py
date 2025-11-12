#!/usr/bin/env python3
"""
RepositoryManager

Provides clone/cache/pull operations for GitHub repositories used by the
GitHub audit workflow. Uses a local cache directory to avoid repeated clones.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from rich.console import Console

from core.database_manager import AetherDatabase


def _run(cmd: list[str], cwd: Optional[Union[str, Path]] = None, timeout: int = 30) -> Tuple[int, str, str]:
    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, 'GIT_ASKPASS': '/bin/echo'}  # Prevent interactive prompts
        )
        out, err = process.communicate(timeout=timeout)
        return process.returncode, out, err
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "", f"Command timed out after {timeout} seconds: {' '.join(cmd)}"


def _strip_credentials(remote_url: str) -> str:
    if '@' in remote_url and '://' in remote_url:
        scheme, rest = remote_url.split('://', 1)
        if '@' in rest:
            rest = rest.split('@', 1)[1]
        return f"{scheme}://{rest}"
    return remote_url


def _parse_github_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    # Supports https URLs primarily. SSH format will return (None, None).
    try:
        if url.endswith('.git'):
            url = url[:-4]
        if 'github.com/' in url:
            parts = url.split('github.com/', 1)[1].split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
                return owner, repo
        return None, None
    except Exception:
        return None, None


@dataclass
class CloneResult:
    repo_path: Path
    is_new_clone: bool


class RepositoryManager:
    def __init__(self, cache_dir: Optional[Union[str, Path]] = None, db: Optional[AetherDatabase] = None, github_token: Optional[str] = None):
        self.console = Console()
        self.github_token = github_token
        self.db = db
        default_cache = Path.home() / '.aether' / 'repos'
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def clone_or_get(self, github_url: str, force_fresh: bool = False) -> CloneResult:
        # Normalize common GitHub web URLs like .../tree/<branch> or .../blob/<branch>/path
        normalized_url = self._normalize_github_url(github_url)
        owner, repo = _parse_github_url(normalized_url)
        repo_name = repo or 'unknown'
        repo_dir = self.cache_dir / (f"{owner}_{repo_name}" if owner else repo_name)

        if force_fresh and repo_dir.exists():
            self.clear_cache(repo_dir)

        if repo_dir.exists():
            return CloneResult(repo_path=repo_dir, is_new_clone=False)

        # Build authenticated URL if token provided and URL is https
        clone_url = normalized_url
        if self.github_token and normalized_url.startswith('https://'):
            clone_url = normalized_url.replace('https://', f"https://{self.github_token}@", 1)

        code, out, err = _run(['git', 'clone', '--depth', '1', clone_url, str(repo_dir)])
        if code != 0:
            # Attempt without token if first attempt failed with token
            if self.github_token and '@' in clone_url:
                code2, out2, err2 = _run(['git', 'clone', '--depth', '1', normalized_url, str(repo_dir)])
                if code2 != 0:
                    raise RuntimeError(f"git clone failed: {err or err2}")
            else:
                raise RuntimeError(f"git clone failed: {err}")

        # In test environments where git is mocked, ensure the target directory exists
        if not repo_dir.exists():
            repo_dir.mkdir(parents=True, exist_ok=True)

        if self.db and owner and repo:
            self.db.create_project(url=normalized_url, repo_name=repo, framework=None, owner=owner, cache_path=str(repo_dir))
        return CloneResult(repo_path=repo_dir, is_new_clone=True)

    def pull_updates(self, repo_path: Union[str, Path]) -> bool:
        code, out, err = _run(['git', 'pull', '--ff-only'], cwd=repo_path)
        if code != 0:
            if code == -1:  # Timeout
                self.console.print(f"[red]❌ git pull timed out: {err}[/red]")
                return False
            else:
                self.console.print(f"[yellow]⚠️ git pull failed: {err.strip()}[/yellow]")
                return False
        return True

    def is_cache_valid(self, repo_path: Union[str, Path], github_url: str) -> bool:
        repo_path = Path(repo_path)
        if not (repo_path.exists() and (repo_path / '.git').exists()):
            return False
        code, out, err = _run(['git', 'remote', 'get-url', 'origin'], cwd=repo_path)
        if code != 0:
            return False
        origin = _strip_credentials(out.strip())
        target = _strip_credentials(self._normalize_github_url(github_url))
        return origin.endswith(target) or target.endswith(origin)

    def get_cache_size(self, repo_path: Union[str, Path]) -> int:
        repo_path = Path(repo_path)
        total = 0
        for root, _, files in os.walk(repo_path):
            for f in files:
                try:
                    total += (Path(root) / f).stat().st_size
                except OSError:
                    continue
        return total

    def clear_cache(self, repo_path: Union[str, Path]) -> None:
        repo_path = Path(repo_path)
        if repo_path.exists():
            shutil.rmtree(repo_path)

    def validate_repo_structure(self, repo_path: Union[str, Path]) -> bool:
        repo_path = Path(repo_path)
        # Basic sanity: must contain common solidity directories
        return (repo_path / 'src').exists() or (repo_path / 'contracts').exists()


    def _normalize_github_url(self, url: str) -> str:
        """Convert common GitHub web URLs to a cloneable repository URL.
        Examples:
          - https://github.com/owner/repo -> same
          - https://github.com/owner/repo.git -> same
          - https://github.com/owner/repo/ -> https://github.com/owner/repo
          - https://github.com/owner/repo/tree/branch -> https://github.com/owner/repo
          - https://github.com/owner/repo/blob/branch/path -> https://github.com/owner/repo
        """
        try:
            if not url:
                return url
            # Trim whitespace
            cleaned = url.strip()
            # Remove trailing .git for parsing, we'll accept both
            suffix_git = cleaned.endswith('.git')
            if suffix_git:
                cleaned = cleaned[:-4]
            # Only handle https GitHub URLs here; SSH and others pass through
            if 'github.com/' not in cleaned:
                return url
            base = cleaned.split('github.com/', 1)[0] + 'github.com/'
            rest = cleaned.split('github.com/', 1)[1]
            parts = [p for p in rest.split('/') if p]
            if len(parts) < 2:
                return url
            owner, repo = parts[0], parts[1]
            normalized = f"{base}{owner}/{repo}"
            # Re-append .git if original had it
            if suffix_git:
                normalized += '.git'
            return normalized
        except Exception:
            return url

