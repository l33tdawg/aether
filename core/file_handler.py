#!/usr/bin/env python3
"""
File Handler for AetherAudit

Simple file operations for reading and writing contract files.
"""

import os
from typing import Optional


class FileHandler:
    """Simple file handler for contract files."""
    
    def __init__(self):
        pass
    
    def read_file(self, file_path: str) -> str:
        """Read a file and return its content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {e}")
    
    def write_file(self, file_path: str, content: str) -> None:
        """Write content to a file."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            raise Exception(f"Error writing file {file_path}: {e}")
    
    def file_exists(self, file_path: str) -> bool:
        """Check if a file exists."""
        return os.path.exists(file_path)
    
    def get_file_size(self, file_path: str) -> int:
        """Get file size in bytes."""
        try:
            return os.path.getsize(file_path)
        except Exception:
            return 0
