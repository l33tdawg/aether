#!/usr/bin/env python3
"""
Aether Installer & Configurator
Interactive setup script for first-time installation and configuration.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

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


class AetherSetup:
    """Main setup class for Aether installation and configuration."""
    
    def __init__(self, interactive: bool = True):
        self.console = Console()
        self.interactive = interactive
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
    
    def run(self):
        """Run the complete setup process."""
        self.print_welcome()
        
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
        
        self.console.print("\n[cyan]API keys enable LLM-powered vulnerability analysis.[/cyan]")
        self.console.print("You can configure them now or later via environment variables.\n")
        
        validator = APIKeyValidator()
        
        # OpenAI API Key
        self.console.print("[bold]OpenAI API Key[/bold] (for GPT models)")
        openai_key = os.getenv('OPENAI_API_KEY', '')
        
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
        gemini_key = os.getenv('GEMINI_API_KEY', '')
        
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
        etherscan_key = os.getenv('ETHERSCAN_API_KEY', '')
        
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
        
        # Summary
        if self.api_keys:
            self.console.print(f"\n  ✓ Configured {len(self.api_keys)} API key(s)")
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
            
            # Set API keys
            for key, value in self.api_keys.items():
                if key == 'OPENAI_API_KEY':
                    config_manager.config.openai_api_key = value
                elif key == 'GEMINI_API_KEY':
                    config_manager.config.gemini_api_key = value
                elif key == 'ETHERSCAN_API_KEY':
                    config_manager.config.etherscan_api_key = value
            
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
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Run in non-interactive mode (use env vars)'
    )
    
    args = parser.parse_args()
    
    setup = AetherSetup(interactive=not args.non_interactive)
    
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

