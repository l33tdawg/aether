#!/usr/bin/env python3
"""
Aether Installer & Configurator
Interactive setup script for first-time installation and configuration.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from utils.setup_helpers import (
    DependencyDetector,
    APIKeyValidator,
    FoundryInstaller,
    VirtualEnvHelper,
    check_directory_writable,
    test_import
)

def fetch_available_models(api_key: str) -> Dict[str, List[str]]:
    """Fetch available models from OpenAI API.
    
    Returns a dict with categorized models:
    - gpt5_models: List of GPT-5 models
    - gpt4_models: List of GPT-4 models
    - all_models: All available GPT models
    """
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        
        # Fetch all models
        models = client.models.list()
        model_ids = [m.id for m in models.data if 'gpt' in m.id.lower()]
        
        # Categorize models
        gpt5_models = sorted([m for m in model_ids if m.startswith('gpt-5')], reverse=True)
        gpt4_models = sorted([m for m in model_ids if m.startswith('gpt-4')], reverse=True)
        
        return {
            'gpt5_models': gpt5_models,
            'gpt4_models': gpt4_models,
            'all_models': sorted(model_ids, reverse=True)
        }
    except Exception as e:
        print(f"⚠️  Could not fetch models from API: {e}")
        # Fallback to known models
        return {
            'gpt5_models': ['gpt-5-chat-latest', 'gpt-5-pro', 'gpt-5-mini', 'gpt-5-nano'],
            'gpt4_models': ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'],
            'all_models': ['gpt-5-chat-latest', 'gpt-5-pro', 'gpt-5-mini', 'gpt-5-nano', 'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo']
        }

def fetch_available_gemini_models(api_key: str) -> Dict[str, List[str]]:
    """Fetch available Gemini models.
    
    Note: Gemini API doesn't have a models.list() endpoint like OpenAI,
    so we query available models via API call or use known models.
    
    Returns a dict with categorized models:
    - gemini_2_5_models: List of Gemini 2.5 models
    - gemini_1_5_models: List of Gemini 1.5 models
    - all_models: All available Gemini models
    """
    try:
        import requests
        
        # Try to list models via Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            models = data.get('models', [])
            
            # Extract model names that support generateContent
            model_names = []
            for model in models:
                name = model.get('name', '').replace('models/', '')
                # Only include models that support generateContent
                if 'generateContent' in model.get('supportedGenerationMethods', []):
                    model_names.append(name)
            
            # Categorize models
            gemini_2_5_models = sorted([m for m in model_names if m.startswith('gemini-2.5')], reverse=True)
            gemini_1_5_models = sorted([m for m in model_names if m.startswith('gemini-1.5')], reverse=True)
            
            return {
                'gemini_2_5_models': gemini_2_5_models,
                'gemini_1_5_models': gemini_1_5_models,
                'all_models': sorted(model_names, reverse=True)
            }
    except Exception as e:
        print(f"⚠️  Could not fetch Gemini models from API: {e}")
    
    # Fallback to known models
    return {
        'gemini_2_5_models': ['gemini-2.5-flash', 'gemini-2.5-pro'],
        'gemini_1_5_models': ['gemini-1.5-flash', 'gemini-1.5-pro'],
        'all_models': ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-1.5-flash', 'gemini-1.5-pro']
    }


class AetherSetup:
    """Main setup class for Aether installation and configuration."""
    
    def __init__(self, interactive: bool = True, reconfigure_all: bool = False, reconfigure_keys: bool = False, reconfigure_models: bool = False):
        self.console = Console()
        self.interactive = interactive
        self.reconfigure_all = reconfigure_all
        self.reconfigure_keys = reconfigure_keys
        self.reconfigure_models = reconfigure_models
        self.project_root = PROJECT_ROOT
        self.config_dir = Path.home() / '.aether'
        self.config_file = self.config_dir / 'config.yaml'
        
        self.setup_status = {
            'python_version': False,
            'foundry': False,
            'slither': False,
            'venv': False,
            'dependencies': False,
            'api_keys': False,
            'config': False,
            'verification': False
        }
        
        self.api_keys = {}
        self.existing_config = None
        
        # Load existing configuration if available
        self._load_existing_config()
    
    def _load_existing_config(self):
        """Load existing configuration if available."""
        try:
            if self.config_file.exists():
                from core.config_manager import ConfigManager
                config_manager = ConfigManager()
                self.existing_config = config_manager.config
                
                # Debug output
                print(f"DEBUG: Loaded existing config from {self.config_file}")
                print(f"DEBUG: Config has OpenAI key: {bool(getattr(self.existing_config, 'openai_api_key', ''))}")
                print(f"DEBUG: Config has Gemini key: {bool(getattr(self.existing_config, 'gemini_api_key', ''))}")
                
                # Mark what's already configured
                if getattr(self.existing_config, 'openai_api_key', ''):
                    self.setup_status['api_keys'] = True
                if self.config_file.exists():
                    self.setup_status['config'] = True
            else:
                print(f"DEBUG: Config file does not exist: {self.config_file}")
                self.existing_config = None
        except Exception as e:
            # If config is corrupted, we'll reconfigure
            print(f"DEBUG: Error loading config: {e}")
            self.existing_config = None
    
    def _show_existing_config(self):
        """Show existing configuration summary."""
        if not self.existing_config:
            return
        
        self.console.print("\n[bold cyan]Existing Configuration Detected[/bold cyan]")
        
        # Show API keys (masked)
        table = Table(title="Current Settings")
        table.add_column("Setting", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Value")
        
        openai_key = getattr(self.existing_config, 'openai_api_key', '')
        if openai_key:
            table.add_row("OpenAI API Key", "✓ Configured", f"{openai_key[:10]}...")
        else:
            table.add_row("OpenAI API Key", "✗ Not set", "-")
        
        gemini_key = getattr(self.existing_config, 'gemini_api_key', '')
        if gemini_key:
            table.add_row("Gemini API Key", "✓ Configured", f"{gemini_key[:10]}...")
        else:
            table.add_row("Gemini API Key", "✗ Not set", "-")
        
        etherscan_key = getattr(self.existing_config, 'etherscan_api_key', '')
        if etherscan_key:
            table.add_row("Etherscan API Key", "✓ Configured", f"{etherscan_key[:10]}...")
        else:
            table.add_row("Etherscan API Key", "✗ Not set", "-")
        
        # Show model selections
        if openai_key:
            table.add_row("OpenAI Validation Model", "✓ Set", getattr(self.existing_config, 'openai_validation_model', 'gpt-5-chat-latest'))
            table.add_row("OpenAI Analysis Model", "✓ Set", getattr(self.existing_config, 'openai_analysis_model', 'gpt-5-chat-latest'))
            table.add_row("OpenAI Generation Model", "✓ Set", getattr(self.existing_config, 'openai_generation_model', 'gpt-5-mini'))
        
        if gemini_key:
            table.add_row("Gemini Validation Model", "✓ Set", getattr(self.existing_config, 'gemini_validation_model', 'gemini-2.5-flash'))
            table.add_row("Gemini Analysis Model", "✓ Set", getattr(self.existing_config, 'gemini_analysis_model', 'gemini-2.5-flash'))
            table.add_row("Gemini Generation Model", "✓ Set", getattr(self.existing_config, 'gemini_generation_model', 'gemini-2.5-flash'))
        
        self.console.print(table)
        self.console.print("\n[yellow]Tip:[/yellow] Use flags to reconfigure specific parts:")
        self.console.print("  --reconfigure-all     Reconfigure everything")
        self.console.print("  --reconfigure-keys    Reconfigure API keys only")
        self.console.print("  --reconfigure-models  Reconfigure model selections only")
    
    def run(self):
        """Run the complete setup process."""
        print(f"DEBUG: existing_config = {self.existing_config is not None}")
        print(f"DEBUG: reconfigure_all = {self.reconfigure_all}")
        
        self.print_welcome()
        
        # Show existing configuration if available
        if self.existing_config and not self.reconfigure_all:
            print("DEBUG: Showing existing config...")
            self._show_existing_config()
            
            if self.interactive:
                if not Confirm.ask("\nProceed with setup?", default=True):
                    self.console.print("[yellow]Setup cancelled.[/yellow]")
                    return True
        else:
            print(f"DEBUG: Skipping existing config display (existing={self.existing_config is not None}, reconfigure_all={self.reconfigure_all})")
        
        # Step 1: Check Python version
        if not self.check_python_version():
            return False
        
        # Step 2: Detect and install dependencies
        if not self.setup_dependencies():
            return False
        
        # Step 3: Setup virtual environment and install Python packages
        if not self.setup_python_environment():
            return False
        
        # Step 4: Configure API keys
        if not self.configure_api_keys():
            return False
        
        # Step 5: Create configuration file
        if not self.create_configuration():
            return False
        
        # Step 6: Verify installation
        if not self.verify_installation():
            return False
        
        # Step 7: Print next steps
        self.print_next_steps()
        
        return True
    
    def print_welcome(self):
        """Print welcome message."""
        welcome_text = """
[bold cyan]Aether - Smart Contract Security Analysis Framework[/bold cyan]

Welcome to the Aether installer! This script will guide you through
the installation and configuration process.

What this installer will do:
  ✓ Check system requirements (Python 3.11+)
  ✓ Install Foundry (forge/anvil) if needed
  ✓ Set up Python virtual environment
  ✓ Install Python dependencies
  ✓ Configure API keys (OpenAI, Gemini, Etherscan)
  ✓ Create configuration files
  ✓ Verify everything works

Let's get started!
"""
        self.console.print(Panel(welcome_text, border_style="cyan"))
        
        if self.interactive:
            if not Confirm.ask("\nContinue with installation?", default=True):
                self.console.print("[yellow]Setup cancelled.[/yellow]")
                sys.exit(0)
    
    def check_python_version(self) -> bool:
        """Check Python version meets requirements."""
        self.console.print("\n[bold]Step 1: Checking Python version...[/bold]")
        
        detector = DependencyDetector()
        is_valid, version = detector.check_python_version()
        
        if is_valid:
            self.console.print(f"  ✓ Python {version} [green](OK)[/green]")
            self.setup_status['python_version'] = True
            return True
        else:
            self.console.print(f"  ✗ Python {version} [red](Python 3.11+ required)[/red]")
            self.console.print("\n[red]Please upgrade Python to version 3.11 or higher.[/red]")
            self.console.print("Visit: https://www.python.org/downloads/")
            return False
    
    def setup_dependencies(self) -> bool:
        """Detect and install system dependencies."""
        self.console.print("\n[bold]Step 2: Checking system dependencies...[/bold]")
        
        detector = DependencyDetector()
        tools = detector.detect_all_tools()
        
        # Display detection results
        table = Table(title="Dependency Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Version")
        table.add_column("Required")
        
        for tool_name, tool_info in tools.items():
            status = "✓ Installed" if tool_info['installed'] else "✗ Missing"
            status_style = "green" if tool_info['installed'] else "red"
            version = tool_info.get('version', 'N/A')
            required = "Yes" if tool_info.get('required') else "No"
            
            table.add_row(
                tool_name,
                f"[{status_style}]{status}[/{status_style}]",
                version,
                required
            )
        
        self.console.print(table)
        
        # Check if Foundry is installed
        if not tools['forge']['installed']:
            self.console.print("\n[yellow]Foundry (forge/anvil) is required for PoC generation and testing.[/yellow]")
            
            if self.interactive:
                install_foundry = Confirm.ask("Install Foundry now?", default=True)
                
                if install_foundry:
                    with self.console.status("[bold green]Installing Foundry..."):
                        success, message = FoundryInstaller.install_foundry()
                    
                    if success:
                        self.console.print(f"  ✓ {message}")
                        self.console.print("\n[yellow]Important:[/yellow] You may need to add Foundry to your PATH:")
                        self.console.print(FoundryInstaller.add_to_path_instructions())
                        
                        if Confirm.ask("\nHave you added Foundry to your PATH?", default=False):
                            # Re-check
                            tools = detector.detect_all_tools()
                            if tools['forge']['installed']:
                                self.console.print("  ✓ Foundry is now available")
                                self.setup_status['foundry'] = True
                            else:
                                self.console.print("  [yellow]Foundry still not found. You may need to restart your terminal.[/yellow]")
                        else:
                            self.console.print("  [yellow]Please add Foundry to PATH and re-run setup.[/yellow]")
                            return False
                    else:
                        self.console.print(f"  ✗ {message}")
                        self.console.print("\n[yellow]Manual installation required.[/yellow]")
                        self.console.print("Visit: https://book.getfoundry.sh/getting-started/installation")
                        
                        if not Confirm.ask("Continue without Foundry?", default=False):
                            return False
                else:
                    self.console.print("[yellow]Note: Some features will be unavailable without Foundry.[/yellow]")
            else:
                self.console.print("[yellow]Non-interactive mode: Please install Foundry manually.[/yellow]")
                return False
        else:
            self.setup_status['foundry'] = True
        
        # Check Slither (optional)
        if not tools['slither']['installed']:
            self.console.print("\n[yellow]Slither is optional but recommended for static analysis.[/yellow]")
            
            if self.interactive and Confirm.ask("Install Slither now?", default=True):
                self.console.print("Slither will be installed with Python dependencies in the next step.")
        else:
            self.setup_status['slither'] = True
        
        return True
    
    def setup_python_environment(self) -> bool:
        """Setup Python virtual environment and install dependencies."""
        self.console.print("\n[bold]Step 3: Setting up Python environment...[/bold]")
        
        venv_helper = VirtualEnvHelper()
        
        # Check if already in a venv
        if venv_helper.is_in_virtualenv():
            self.console.print("  ✓ Already in a virtual environment")
            self.setup_status['venv'] = True
        else:
            # Look for existing venv
            existing_venv = venv_helper.find_venv_in_project(self.project_root)
            
            if existing_venv:
                self.console.print(f"  ✓ Found existing virtual environment: {existing_venv}")
                self.console.print(f"\n[yellow]Please activate it with:[/yellow]")
                self.console.print(f"  {venv_helper.get_activation_command(existing_venv)}")
                self.console.print("\nThen re-run this setup script.")
                return False
            else:
                if self.interactive and Confirm.ask("Create virtual environment?", default=True):
                    success, message = venv_helper.create_virtualenv(self.project_root)
                    
                    if success:
                        venv_path = Path(message)
                        self.console.print(f"  ✓ Virtual environment created: {venv_path}")
                        self.console.print(f"\n[yellow]Please activate it with:[/yellow]")
                        self.console.print(f"  {venv_helper.get_activation_command(venv_path)}")
                        self.console.print("\nThen re-run this setup script.")
                        return False
                    else:
                        self.console.print(f"  ✗ {message}")
                        return False
                else:
                    self.console.print("[yellow]Virtual environment recommended but skipped.[/yellow]")
        
        # Install Python dependencies
        requirements_file = self.project_root / 'requirements.txt'
        
        if requirements_file.exists():
            self.console.print("\nInstalling Python dependencies...")
            
            if self.interactive and not Confirm.ask("Install from requirements.txt?", default=True):
                self.console.print("[yellow]Skipping dependency installation.[/yellow]")
                return True
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Installing packages...", total=None)
                success, message = venv_helper.install_requirements(requirements_file)
            
            if success:
                self.console.print(f"  ✓ {message}")
                self.setup_status['dependencies'] = True
            else:
                self.console.print(f"  ✗ {message}")
                
                if not self.interactive or not Confirm.ask("Continue anyway?", default=False):
                    return False
        else:
            self.console.print(f"  [yellow]requirements.txt not found[/yellow]")
        
        return True
    
    def configure_api_keys(self) -> bool:
        """Configure API keys interactively."""
        self.console.print("\n[bold]Step 4: Configuring API keys...[/bold]")
        
        # Skip if already configured and not reconfiguring
        if self.existing_config and not self.reconfigure_all and not self.reconfigure_keys:
            existing_openai = getattr(self.existing_config, 'openai_api_key', '')
            existing_gemini = getattr(self.existing_config, 'gemini_api_key', '')
            
            if existing_openai or existing_gemini:
                self.console.print("  [green]✓ API keys already configured[/green]")
                
                if self.interactive and not Confirm.ask("  Reconfigure API keys?", default=False):
                    # Use existing keys
                    if existing_openai:
                        self.api_keys['OPENAI_API_KEY'] = existing_openai
                    if existing_gemini:
                        self.api_keys['GEMINI_API_KEY'] = existing_gemini
                    if getattr(self.existing_config, 'etherscan_api_key', ''):
                        self.api_keys['ETHERSCAN_API_KEY'] = self.existing_config.etherscan_api_key
                    
                    self.setup_status['api_keys'] = True
                    
                    # Skip to model selection if not reconfiguring models
                    if not self.reconfigure_models:
                        return self._configure_model_selection()
                    return True
        
        self.console.print("\n[cyan]API keys enable LLM-powered vulnerability analysis.[/cyan]")
        self.console.print("You can configure them now or later via environment variables.\n")
        
        validator = APIKeyValidator()
        
        # OpenAI API Key
        self.console.print("[bold]OpenAI API Key[/bold] (for GPT models)")
        # Check existing config first, then env var
        existing_openai = getattr(self.existing_config, 'openai_api_key', '') if self.existing_config else ''
        openai_key = existing_openai or os.getenv('OPENAI_API_KEY', '')
        
        if openai_key:
            self.console.print(f"  Found existing key: {openai_key[:10]}...")
            
            if self.interactive and not Confirm.ask("Use this key?", default=True):
                openai_key = ''
        
        if not openai_key and self.interactive:
            openai_key = Prompt.ask("  Enter OpenAI API key (or press Enter to skip)", default="")
        
        if openai_key:
            with self.console.status("[bold green]Validating OpenAI key..."):
                is_valid, message = validator.validate_openai_key(openai_key)
            
            if is_valid:
                self.console.print(f"  ✓ OpenAI key validated: {message}")
                self.api_keys['OPENAI_API_KEY'] = openai_key
            else:
                self.console.print(f"  ✗ OpenAI key validation failed: {message}")
                
                if self.interactive and Confirm.ask("  Use anyway?", default=False):
                    self.api_keys['OPENAI_API_KEY'] = openai_key
        else:
            self.console.print("  [yellow]Skipped OpenAI key configuration[/yellow]")
        
        # Gemini API Key
        self.console.print("\n[bold]Gemini API Key[/bold] (for Gemini models)")
        existing_gemini = getattr(self.existing_config, 'gemini_api_key', '') if self.existing_config else ''
        gemini_key = existing_gemini or os.getenv('GEMINI_API_KEY', '')
        
        if gemini_key:
            self.console.print(f"  Found existing key: {gemini_key[:10]}...")
            
            if self.interactive and not Confirm.ask("Use this key?", default=True):
                gemini_key = ''
        
        if not gemini_key and self.interactive:
            gemini_key = Prompt.ask("  Enter Gemini API key (or press Enter to skip)", default="")
        
        if gemini_key:
            with self.console.status("[bold green]Validating Gemini key..."):
                is_valid, message = validator.validate_gemini_key(gemini_key)
            
            if is_valid:
                self.console.print(f"  ✓ Gemini key validated: {message}")
                self.api_keys['GEMINI_API_KEY'] = gemini_key
            else:
                self.console.print(f"  ✗ Gemini key validation failed: {message}")
                
                if self.interactive and Confirm.ask("  Use anyway?", default=False):
                    self.api_keys['GEMINI_API_KEY'] = gemini_key
        else:
            self.console.print("  [yellow]Skipped Gemini key configuration[/yellow]")
        
        # Etherscan API Key (optional)
        self.console.print("\n[bold]Etherscan API Key[/bold] (optional, for fetching verified contracts)")
        existing_etherscan = getattr(self.existing_config, 'etherscan_api_key', '') if self.existing_config else ''
        etherscan_key = existing_etherscan or os.getenv('ETHERSCAN_API_KEY', '')
        
        if etherscan_key:
            self.console.print(f"  Found existing key: {etherscan_key[:10]}...")
            
            if self.interactive and not Confirm.ask("Use this key?", default=True):
                etherscan_key = ''
        
        if not etherscan_key and self.interactive:
            if Confirm.ask("  Configure Etherscan key?", default=False):
                etherscan_key = Prompt.ask("  Enter Etherscan API key", default="")
        
        if etherscan_key:
            with self.console.status("[bold green]Validating Etherscan key..."):
                is_valid, message = validator.validate_etherscan_key(etherscan_key)
            
            if is_valid:
                self.console.print(f"  ✓ Etherscan key validated: {message}")
                self.api_keys['ETHERSCAN_API_KEY'] = etherscan_key
            else:
                self.console.print(f"  ✗ Etherscan key validation failed: {message}")
                
                if self.interactive and Confirm.ask("  Use anyway?", default=False):
                    self.api_keys['ETHERSCAN_API_KEY'] = etherscan_key
        else:
            self.console.print("  [yellow]Skipped Etherscan key configuration[/yellow]")
        
        # Configure model selections
        return self._configure_model_selection()
    
    def _configure_model_selection(self) -> bool:
        """Configure model selections for OpenAI and Gemini."""
        # Skip if already configured and not reconfiguring
        if self.existing_config and not self.reconfigure_all and not self.reconfigure_models:
            existing_openai = getattr(self.existing_config, 'openai_api_key', '')
            existing_gemini = getattr(self.existing_config, 'gemini_api_key', '')
            
            if existing_openai or existing_gemini:
                self.console.print("\n[bold]Model Selection[/bold]")
                self.console.print("  [green]✓ Models already configured[/green]")
                
                if self.interactive and not Confirm.ask("  Reconfigure models?", default=False):
                    # Use existing model selections
                    if existing_openai:
                        self.api_keys['VALIDATION_MODEL'] = getattr(self.existing_config, 'openai_validation_model', 'gpt-5-chat-latest')
                        self.api_keys['ANALYSIS_MODEL'] = getattr(self.existing_config, 'openai_analysis_model', 'gpt-5-chat-latest')
                        self.api_keys['GENERATION_MODEL'] = getattr(self.existing_config, 'openai_generation_model', 'gpt-5-mini')
                    
                    if existing_gemini:
                        self.api_keys['GEMINI_VALIDATION_MODEL'] = getattr(self.existing_config, 'gemini_validation_model', 'gemini-2.5-flash')
                        self.api_keys['GEMINI_ANALYSIS_MODEL'] = getattr(self.existing_config, 'gemini_analysis_model', 'gemini-2.5-flash')
                        self.api_keys['GEMINI_GENERATION_MODEL'] = getattr(self.existing_config, 'gemini_generation_model', 'gemini-2.5-flash')
                    
                    return True
        
        # Model Selection
        has_openai = self.api_keys.get('OPENAI_API_KEY')
        has_gemini = self.api_keys.get('GEMINI_API_KEY')
        
        if has_openai or has_gemini:
            self.console.print("\n[bold]Model Selection[/bold] (Choose provider and model per task)")
            self.console.print("\n[cyan]You can mix providers:[/cyan]")
            self.console.print("  Example: Use Gemini for validation (2M context) + OpenAI for generation")
            
        # Fetch available models
        available_openai = None
        available_gemini = None
        
        if has_openai:
            with self.console.status("[bold green]Fetching available OpenAI models..."):
                available_openai = fetch_available_models(self.api_keys['OPENAI_API_KEY'])
            
            # Display available models
            if available_openai['gpt5_models']:
                self.console.print("\n[bold cyan]Available GPT-5 Models:[/bold cyan] (400K context, superior retrieval)")
                for model in available_openai['gpt5_models'][:5]:  # Show top 5
                    self.console.print(f"  • {model}")
            
            if available_openai['gpt4_models']:
                self.console.print("\n[bold cyan]Available GPT-4 Models:[/bold cyan] (128K context)")
                for model in available_openai['gpt4_models'][:5]:  # Show top 5
                    self.console.print(f"  • {model}")
        
        if has_gemini:
            with self.console.status("[bold green]Fetching available Gemini models..."):
                available_gemini = fetch_available_gemini_models(self.api_keys['GEMINI_API_KEY'])
            
            if available_gemini['gemini_2_5_models']:
                self.console.print("\n[bold cyan]Available Gemini 2.5 Models:[/bold cyan] (2M context, thinking mode)")
                for model in available_gemini['gemini_2_5_models']:
                    self.console.print(f"  • {model}")
            
            if available_gemini['gemini_1_5_models']:
                self.console.print("\n[bold cyan]Available Gemini 1.5 Models:[/bold cyan] (1M context)")
                for model in available_gemini['gemini_1_5_models']:
                    self.console.print(f"  • {model}")
            
            if self.interactive:
                # Configure each task type with provider + model selection
                for task_name, task_desc in [
                    ('validation', 'false positive filtering - critical accuracy'),
                    ('analysis', 'vulnerability detection - balanced quality'),
                    ('generation', 'PoC/test generation - can use faster model')
                ]:
                    self.console.print(f"\n[bold]{task_name.title()} Task[/bold] (for {task_desc})")
                    
                    # Choose provider if both are available
                    if has_openai and has_gemini:
                        provider_choices = []
                        provider_display = {}
                        
                        if has_openai:
                            provider_choices.append("openai")
                            provider_display["openai"] = "OpenAI (GPT-5: 400K context, superior retrieval)"
                        if has_gemini:
                            provider_choices.append("gemini")
                            provider_display["gemini"] = "Gemini (2.5: 2M context, thinking mode)"
                        
                        self.console.print(f"  [cyan]Available providers:[/cyan]")
                        for prov in provider_choices:
                            self.console.print(f"    • {prov}: {provider_display[prov]}")
                        
                        provider = Prompt.ask(
                            "  Select provider",
                            choices=provider_choices,
                            default="openai" if task_name != "validation" else "gemini"  # Recommend Gemini for validation (2M context!)
                        )
                        
                        self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider
                    elif has_openai:
                        provider = "openai"
                        self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider
                    elif has_gemini:
                        provider = "gemini"
                        self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider
                    else:
                        continue
                    
                    # Select model from chosen provider
                    if provider == "openai" and available_openai:
                        choice_list = available_openai['gpt5_models'][:10] + available_openai['gpt4_models'][:5]
                        default_model = available_openai['gpt5_models'][0] if available_openai['gpt5_models'] else available_openai['all_models'][0]
                        if task_name == 'generation' and available_openai['gpt5_models']:
                            # Prefer mini for generation
                            default_model = next((m for m in available_openai['gpt5_models'] if 'mini' in m), default_model)
                    else:  # gemini
                        choice_list = available_gemini['gemini_2_5_models'] + available_gemini['gemini_1_5_models']
                        default_model = available_gemini['gemini_2_5_models'][0] if available_gemini['gemini_2_5_models'] else available_gemini['all_models'][0]
                    
                    model = Prompt.ask(
                        f"  Select {provider} model",
                        choices=choice_list,
                        default=default_model
                    )
                    
                    # Store both provider and model
                    if provider == "openai":
                        self.api_keys[f'{task_name.upper()}_MODEL'] = model
                    else:
                        self.api_keys[f'GEMINI_{task_name.upper()}_MODEL'] = model
                
                # Show summary
                self.console.print(f"\n  ✓ Model configuration:")
                for task in ['validation', 'analysis', 'generation']:
                    provider = self.api_keys.get(f'{task.upper()}_PROVIDER', 'openai')
                    if provider == 'openai':
                        model = self.api_keys.get(f'{task.upper()}_MODEL', 'N/A')
                    else:
                        model = self.api_keys.get(f'GEMINI_{task.upper()}_MODEL', 'N/A')
                    self.console.print(f"    {task.title()}: {provider}/{model}")
            else:
                # Non-interactive defaults
                if has_openai and available_openai:
                    self.api_keys['VALIDATION_PROVIDER'] = 'openai'
                    self.api_keys['ANALYSIS_PROVIDER'] = 'openai'
                    self.api_keys['GENERATION_PROVIDER'] = 'openai'
                    self.api_keys['VALIDATION_MODEL'] = available_openai['gpt5_models'][0] if available_openai['gpt5_models'] else available_openai['all_models'][0]
                    self.api_keys['ANALYSIS_MODEL'] = available_openai['gpt5_models'][0] if available_openai['gpt5_models'] else available_openai['all_models'][0]
                    self.api_keys['GENERATION_MODEL'] = next((m for m in available_openai['gpt5_models'] if 'mini' in m), 
                                                              available_openai['gpt5_models'][0] if available_openai['gpt5_models'] else available_openai['all_models'][0])
                elif has_gemini and available_gemini:
                    self.api_keys['VALIDATION_PROVIDER'] = 'gemini'
                    self.api_keys['ANALYSIS_PROVIDER'] = 'gemini'
                    self.api_keys['GENERATION_PROVIDER'] = 'gemini'
                    self.api_keys['GEMINI_VALIDATION_MODEL'] = available_gemini['gemini_2_5_models'][0] if available_gemini['gemini_2_5_models'] else available_gemini['all_models'][0]
                    self.api_keys['GEMINI_ANALYSIS_MODEL'] = available_gemini['gemini_2_5_models'][0] if available_gemini['gemini_2_5_models'] else available_gemini['all_models'][0]
                    self.api_keys['GEMINI_GENERATION_MODEL'] = next((m for m in available_gemini['gemini_2_5_models'] if 'flash' in m), 
                                                                    available_gemini['gemini_2_5_models'][0] if available_gemini['gemini_2_5_models'] else available_gemini['all_models'][0])
        
        # Summary
        if self.api_keys:
            self.console.print(f"\n  ✓ Configured {len([k for k in self.api_keys if 'KEY' in k])} API key(s)")
            self.setup_status['api_keys'] = True
        else:
            self.console.print("\n  [yellow]No API keys configured. LLM features will be unavailable.[/yellow]")
        
        return True
    
    def create_configuration(self) -> bool:
        """Create Aether configuration file."""
        self.console.print("\n[bold]Step 5: Creating configuration...[/bold]")
        
        # Ensure config directory exists
        is_writable, message = check_directory_writable(self.config_dir)
        
        if not is_writable:
            self.console.print(f"  ✗ Cannot create config directory: {message}")
            return False
        
        self.console.print(f"  ✓ Config directory: {self.config_dir}")
        
        # Import config manager
        try:
            from core.config_manager import ConfigManager
            
            config_manager = ConfigManager()
            
            # Set API keys and model selections
            for key, value in self.api_keys.items():
                if key == 'OPENAI_API_KEY':
                    config_manager.config.openai_api_key = value
                elif key == 'GEMINI_API_KEY':
                    config_manager.config.gemini_api_key = value
                elif key == 'ETHERSCAN_API_KEY':
                    config_manager.config.etherscan_api_key = value
                # Provider selections
                elif key == 'VALIDATION_PROVIDER':
                    config_manager.config.validation_provider = value
                elif key == 'ANALYSIS_PROVIDER':
                    config_manager.config.analysis_provider = value
                elif key == 'GENERATION_PROVIDER':
                    config_manager.config.generation_provider = value
                # OpenAI model selections
                elif key == 'VALIDATION_MODEL':
                    config_manager.config.openai_validation_model = value
                elif key == 'ANALYSIS_MODEL':
                    config_manager.config.openai_analysis_model = value
                elif key == 'GENERATION_MODEL':
                    config_manager.config.openai_generation_model = value
                # Gemini model selections
                elif key == 'GEMINI_VALIDATION_MODEL':
                    config_manager.config.gemini_validation_model = value
                elif key == 'GEMINI_ANALYSIS_MODEL':
                    config_manager.config.gemini_analysis_model = value
                elif key == 'GEMINI_GENERATION_MODEL':
                    config_manager.config.gemini_generation_model = value
            
            # Save configuration
            config_manager.save_config()
            
            self.console.print(f"  ✓ Configuration saved to {self.config_file}")
            self.setup_status['config'] = True
            
            return True
        
        except Exception as e:
            self.console.print(f"  ✗ Failed to create config: {e}")
            return False
    
    def verify_installation(self) -> bool:
        """Verify the installation is working."""
        self.console.print("\n[bold]Step 6: Verifying installation...[/bold]")
        
        checks = [
            ("Python version", lambda: DependencyDetector().check_python_version()[0]),
            ("Foundry (forge)", lambda: DependencyDetector().detect_tool('forge')['installed']),
            ("Config directory writable", lambda: check_directory_writable(self.config_dir)[0]),
            ("Import: rich", lambda: test_import('rich')[0]),
            ("Import: web3", lambda: test_import('web3')[0]),
            ("Import: openai", lambda: test_import('openai')[0]),
            ("Config file exists", lambda: self.config_file.exists()),
        ]
        
        results = []
        all_passed = True
        
        for check_name, check_func in checks:
            try:
                passed = check_func()
                results.append((check_name, passed))
                
                if passed:
                    self.console.print(f"  ✓ {check_name}")
                else:
                    self.console.print(f"  ✗ {check_name}")
                    all_passed = False
            
            except Exception as e:
                self.console.print(f"  ✗ {check_name}: {str(e)[:50]}")
                results.append((check_name, False))
                all_passed = False
        
        if all_passed:
            self.console.print("\n[green]✓ All checks passed![/green]")
            self.setup_status['verification'] = True
        else:
            self.console.print("\n[yellow]Some checks failed. Review the errors above.[/yellow]")
        
        return all_passed
    
    def print_next_steps(self):
        """Print next steps and quick start guide."""
        next_steps = """
[bold green]✓ Installation Complete![/bold green]

[bold]Quick Start:[/bold]

1. Audit a local contract:
   [cyan]python main.py audit ./contracts/MyContract.sol --enhanced --ai-ensemble[/cyan]

2. Audit a GitHub repository:
   [cyan]python main.py audit https://github.com/owner/repo --interactive-scope[/cyan]

3. Generate Foundry PoCs from findings:
   [cyan]python main.py generate-foundry --from-results ./output/results.json --out ./output/pocs[/cyan]

4. Run fork verification:
   [cyan]python main.py fork-verify ./output/pocs --rpc-url YOUR_RPC_URL[/cyan]

[bold]Configuration:[/bold]
  Config file: ~/.aether/config.yaml
  View config: [cyan]python main.py config --show[/cyan]

[bold]Environment Variables:[/bold]
"""
        
        if self.api_keys:
            next_steps += "\nAdd these to your ~/.bashrc or ~/.zshrc:\n"
            for key, value in self.api_keys.items():
                next_steps += f"  export {key}='{value}'\n"
        
        next_steps += """
[bold]Documentation:[/bold]
  README.md - Full documentation
  python main.py --help - CLI help
  python main.py <command> --help - Command-specific help

[bold cyan]Happy auditing! 🔍[/bold cyan]
"""
        
        self.console.print(Panel(next_steps, border_style="green"))


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Aether Installer & Configurator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup.py                     # Smart setup (skips configured items)
  python setup.py --reconfigure-all   # Reconfigure everything
  python setup.py --reconfigure-keys  # Reconfigure API keys only
  python setup.py --reconfigure-models # Reconfigure model selections only
        """
    )
    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Run in non-interactive mode (use env vars)'
    )
    parser.add_argument(
        '--reconfigure-all',
        action='store_true',
        help='Reconfigure all settings (ignore existing configuration)'
    )
    parser.add_argument(
        '--reconfigure-keys',
        action='store_true',
        help='Reconfigure API keys only'
    )
    parser.add_argument(
        '--reconfigure-models',
        action='store_true',
        help='Reconfigure model selections only'
    )
    
    args = parser.parse_args()
    
    setup = AetherSetup(
        interactive=not args.non_interactive,
        reconfigure_all=args.reconfigure_all,
        reconfigure_keys=args.reconfigure_keys,
        reconfigure_models=args.reconfigure_models
    )
    
    try:
        success = setup.run()
        sys.exit(0 if success else 1)
    
    except KeyboardInterrupt:
        setup.console.print("\n\n[yellow]Setup cancelled by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        setup.console.print(f"\n[red]Setup failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

