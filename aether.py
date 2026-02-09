#!/usr/bin/env python3
"""
Aether v3.0 — Smart Contract Security Analysis Framework

Sole entry point. Launches the persistent full-screen Textual TUI dashboard.

Usage:
    python aether.py
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

import warnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources is deprecated.*")

from cli.interactive_menu import main

if __name__ == "__main__":
    sys.exit(main())
