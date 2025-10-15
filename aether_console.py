#!/usr/bin/env python3
"""
AetherAudit Console Launcher

Starts the Metasploit-style CLI for smart contract security auditing.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli.console import main

if __name__ == '__main__':
    sys.exit(main())
