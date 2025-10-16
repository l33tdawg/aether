"""Minimal BeautifulSoup stub for tests.

This stub provides only the attributes used by the codebase to avoid
installing external dependencies during CI/test runs in constrained envs.
"""

from typing import List, Any


class BeautifulSoup:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def find_all(self, *_args: Any, **_kwargs: Any) -> List[Any]:
        return []


