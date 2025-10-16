"""
Test-time environment customization.

Provides a minimal stub for the 'rich' package to avoid external dependency
installation when running tests in constrained environments.
"""

import sys
import types
from contextlib import contextmanager


def _install_rich_stub() -> None:
    if 'rich' in sys.modules and 'rich.console' in sys.modules:
        return

    rich_mod = types.ModuleType('rich')
    console_mod = types.ModuleType('rich.console')
    progress_mod = types.ModuleType('rich.progress')

    class Console:  # minimal API used in codebase
        def print(self, *args, **kwargs):
            pass

        @contextmanager
        def status(self, *_args, **_kwargs):
            yield

    console_mod.Console = Console
    rich_mod.console = console_mod
    
    # Minimal progress API used in codebase
    class Progress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def add_task(self, *args, **kwargs):
            return 0

        def update(self, *args, **kwargs):
            pass

    class SpinnerColumn:
        pass

    class TextColumn:
        def __init__(self, *args, **kwargs):
            pass

    progress_mod.Progress = Progress
    progress_mod.SpinnerColumn = SpinnerColumn
    progress_mod.TextColumn = TextColumn
    rich_mod.progress = progress_mod

    sys.modules['rich'] = rich_mod
    sys.modules['rich.console'] = console_mod
    sys.modules['rich.progress'] = progress_mod


def _install_bs4_stub() -> None:
    if 'bs4' in sys.modules:
        return
    bs4_mod = types.ModuleType('bs4')

    class BeautifulSoup:
        def __init__(self, *args, **kwargs):
            pass

        def find_all(self, *args, **kwargs):
            return []

    bs4_mod.BeautifulSoup = BeautifulSoup
    sys.modules['bs4'] = bs4_mod


def _install_requests_stub() -> None:
    if 'requests' in sys.modules:
        return
    requests_mod = types.ModuleType('requests')

    class _Resp:
        def __init__(self, status_code: int = 200, content: bytes = b""):
            self.status_code = status_code
            self.content = content

        def raise_for_status(self):
            pass

    def get(*args, **kwargs):
        return _Resp()

    requests_mod.get = get
    sys.modules['requests'] = requests_mod


try:
    _install_rich_stub()
    _install_bs4_stub()
    _install_requests_stub()
except Exception:
    # Never fail import due to stubbing
    pass


