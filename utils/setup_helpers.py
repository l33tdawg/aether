#!/usr/bin/env python3
"""
Setup Helpers for Aether Installation
Provides reusable functions for dependency detection, installation, and validation.
"""

import os
import sys
import subprocess
import re
import shutil
import platform
from typing import Dict, Any, Optional, Tuple
from pathlib import Path


class DependencyDetector:
    """Detects and validates system dependencies."""
    
    REQUIRED_TOOLS = {
        'forge': {
            'description': 'Foundry (forge/anvil)',
            'check_cmd': ['forge', '--version'],
            'version_pattern': r'forge Version: ([^\s]+)',
            'install_instructions': 'curl -L https://foundry.paradigm.xyz | bash && foundryup',
            'required': True
        },
        'anvil': {
            'description': 'Foundry Anvil (local testnet)',
            'check_cmd': ['anvil', '--version'],
            'version_pattern': r'anvil Version: ([^\s]+)',
            'install_instructions': 'Installed with Foundry',
            'required': True
        },
        'slither': {
            'description': 'Slither static analyzer',
            'check_cmd': ['slither', '--version'],
            'version_pattern': r'(\d+\.\d+(?:\.\d+)?)',
            'install_instructions': 'pip install slither-analyzer',
            'required': False
        },
        'solc': {
            'description': 'Solidity compiler',
            'check_cmd': ['solc', '--version'],
            'version_pattern': r'Version: (\d+\.\d+\.\d+)',
            'install_instructions': 'pip install solc-select && solc-select install latest',
            'required': False
        }
    }
    
    def __init__(self):
        self.detected_tools = {}
    
    def detect_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detect all tools and return their status."""
        detected = {}
        
        for tool_name, tool_info in self.REQUIRED_TOOLS.items():
            detected[tool_name] = self.detect_tool(tool_name)
        
        self.detected_tools = detected
        return detected
    
    def detect_tool(self, tool_name: str) -> Dict[str, Any]:
        """Detect a specific tool."""
        if tool_name not in self.REQUIRED_TOOLS:
            return {'installed': False, 'version': None, 'error': 'Unknown tool'}
        
        tool_info = self.REQUIRED_TOOLS[tool_name]
        
        try:
            result = subprocess.run(
                tool_info['check_cmd'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract version
                output = result.stdout + result.stderr
                version_match = re.search(tool_info['version_pattern'], output)
                version = version_match.group(1) if version_match else 'Unknown'
                
                return {
                    'installed': True,
                    'version': version,
                    'description': tool_info['description'],
                    'required': tool_info['required']
                }
            else:
                return {
                    'installed': False,
                    'version': None,
                    'description': tool_info['description'],
                    'required': tool_info['required'],
                    'install_instructions': tool_info['install_instructions']
                }
        
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            return {
                'installed': False,
                'version': None,
                'description': tool_info['description'],
                'required': tool_info['required'],
                'install_instructions': tool_info['install_instructions'],
                'error': str(e)
            }
    
    def check_python_version(self) -> Tuple[bool, str]:
        """Check if Python version meets requirements (3.11+)."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"
        
        if version.major == 3 and version.minor >= 11:
            return True, version_str
        else:
            return False, version_str
    
    def check_foundry_in_path(self) -> bool:
        """Check if Foundry binaries are in PATH."""
        foundry_bin = os.path.expanduser("~/.foundry/bin")
        path_env = os.environ.get('PATH', '')
        
        return foundry_bin in path_env or shutil.which('forge') is not None
    
    def get_foundry_path_instructions(self) -> str:
        """Get instructions for adding Foundry to PATH."""
        foundry_bin = os.path.expanduser("~/.foundry/bin")
        
        shell = os.environ.get('SHELL', '/bin/bash')
        
        if 'zsh' in shell:
            rc_file = '~/.zshrc'
        elif 'bash' in shell:
            rc_file = '~/.bashrc'
        else:
            rc_file = '~/.profile'
        
        return f"""
Add the following line to your {rc_file}:
  export PATH="$PATH:{foundry_bin}"

Then run:
  source {rc_file}
"""


class APIKeyValidator:
    """Validates API keys by making test calls."""
    
    @staticmethod
    def validate_openai_key(api_key: str) -> Tuple[bool, str]:
        """Validate OpenAI API key."""
        if not api_key or not api_key.startswith('sk-'):
            return False, "Invalid format (should start with 'sk-')"
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            
            # Make a minimal test call
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5
            )
            
            return True, "Valid"
        
        except Exception as e:
            error_msg = str(e)
            if "invalid" in error_msg.lower() or "incorrect" in error_msg.lower():
                return False, "Invalid API key"
            elif "quota" in error_msg.lower():
                return True, "Valid (but quota exceeded)"
            else:
                return False, f"Validation failed: {error_msg[:100]}"
    
    @staticmethod
    def validate_gemini_key(api_key: str) -> Tuple[bool, str]:
        """Validate Gemini API key."""
        if not api_key:
            return False, "Empty API key"
        
        try:
            import httpx
            
            # Test Gemini API with a minimal request
            url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + api_key
            
            response = httpx.get(url, timeout=10)
            
            if response.status_code == 200:
                return True, "Valid"
            elif response.status_code == 400:
                return False, "Invalid API key"
            elif response.status_code == 403:
                return False, "API key forbidden or restricted"
            else:
                return False, f"Validation failed (status {response.status_code})"
        
        except Exception as e:
            return False, f"Validation error: {str(e)[:100]}"
    
    @staticmethod
    def validate_etherscan_key(api_key: str, network: str = 'mainnet') -> Tuple[bool, str]:
        """Validate Etherscan API key."""
        if not api_key:
            return False, "Empty API key"
        
        try:
            import httpx
            
            # Test with a simple API call
            base_urls = {
                'mainnet': 'https://api.etherscan.io/api',
                'polygon': 'https://api.polygonscan.com/api',
                'arbitrum': 'https://api.arbiscan.io/api',
                'base': 'https://api.basescan.org/api'
            }
            
            base_url = base_urls.get(network, base_urls['mainnet'])
            
            url = f"{base_url}?module=stats&action=ethsupply&apikey={api_key}"
            response = httpx.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    return True, "Valid"
                elif 'invalid' in data.get('result', '').lower():
                    return False, "Invalid API key"
                else:
                    return False, f"API returned: {data.get('result', 'Unknown error')}"
            else:
                return False, f"HTTP {response.status_code}"
        
        except Exception as e:
            return False, f"Validation error: {str(e)[:100]}"


class FoundryInstaller:
    """Handles Foundry installation."""
    
    @staticmethod
    def detect_os() -> str:
        """Detect operating system."""
        system = platform.system().lower()
        
        if system == 'darwin':
            return 'macos'
        elif system == 'linux':
            return 'linux'
        elif system == 'windows':
            return 'windows'
        else:
            return 'unknown'
    
    @staticmethod
    def install_foundry() -> Tuple[bool, str]:
        """Install Foundry based on OS."""
        os_type = FoundryInstaller.detect_os()
        
        if os_type == 'windows':
            return False, "Windows installation requires manual setup. Please visit https://book.getfoundry.sh/getting-started/installation"
        
        try:
            # Run foundryup installer
            print("Downloading and installing Foundry...")
            
            # Download foundryup
            download_cmd = "curl -L https://foundry.paradigm.xyz | bash"
            
            result = subprocess.run(
                download_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                return False, f"Download failed: {result.stderr}"
            
            # Run foundryup to install
            foundryup_path = os.path.expanduser("~/.foundry/bin/foundryup")
            
            if os.path.exists(foundryup_path):
                result = subprocess.run(
                    [foundryup_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    return True, "Foundry installed successfully"
                else:
                    return False, f"Installation failed: {result.stderr}"
            else:
                return False, "foundryup not found after download"
        
        except subprocess.TimeoutExpired:
            return False, "Installation timed out (network issue?)"
        except Exception as e:
            return False, f"Installation error: {str(e)}"
    
    @staticmethod
    def add_to_path_instructions() -> str:
        """Get instructions for adding Foundry to PATH."""
        detector = DependencyDetector()
        return detector.get_foundry_path_instructions()


class VirtualEnvHelper:
    """Helps with virtual environment setup."""
    
    @staticmethod
    def is_in_virtualenv() -> bool:
        """Check if currently in a virtual environment."""
        return hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
        )
    
    @staticmethod
    def find_venv_in_project(project_dir: Path) -> Optional[Path]:
        """Find existing venv in project directory."""
        common_names = ['venv', '.venv', 'env', '.env']
        
        for name in common_names:
            venv_path = project_dir / name
            if venv_path.exists() and (venv_path / 'bin' / 'python').exists():
                return venv_path
        
        return None
    
    @staticmethod
    def create_virtualenv(project_dir: Path, name: str = 'venv') -> Tuple[bool, str]:
        """Create a new virtual environment."""
        venv_path = project_dir / name
        
        try:
            import venv
            
            print(f"Creating virtual environment at {venv_path}...")
            venv.create(venv_path, with_pip=True)
            
            return True, str(venv_path)
        
        except Exception as e:
            return False, f"Failed to create venv: {str(e)}"
    
    @staticmethod
    def get_activation_command(venv_path: Path) -> str:
        """Get the command to activate the virtual environment."""
        if platform.system().lower() == 'windows':
            return str(venv_path / 'Scripts' / 'activate.bat')
        else:
            return f"source {venv_path / 'bin' / 'activate'}"
    
    @staticmethod
    def install_requirements(requirements_file: Path) -> Tuple[bool, str]:
        """Install requirements from requirements.txt."""
        if not requirements_file.exists():
            return False, f"Requirements file not found: {requirements_file}"
        
        try:
            print(f"Installing Python dependencies from {requirements_file}...")
            
            # Use the current Python interpreter's pip
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            if result.returncode == 0:
                return True, "Dependencies installed successfully"
            else:
                return False, f"Installation failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"


def check_directory_writable(directory: Path) -> Tuple[bool, str]:
    """Check if a directory is writable."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        
        # Try to create a test file
        test_file = directory / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
        
        return True, "Writable"
    
    except Exception as e:
        return False, f"Not writable: {str(e)}"


def test_import(module_name: str) -> Tuple[bool, str]:
    """Test if a Python module can be imported."""
    try:
        __import__(module_name)
        return True, "OK"
    except ImportError as e:
        # Handle common package name variations
        variations = {
            'pyyaml': 'yaml',
            'yaml': 'pyyaml'
        }
        alt_name = variations.get(module_name.lower())
        if alt_name:
            try:
                __import__(alt_name)
                return True, f"OK (imported as {alt_name})"
            except ImportError:
                pass
        return False, f"Import failed: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"

