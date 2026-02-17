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
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
import questionary
from questionary import Style

from utils.setup_helpers import (
    DependencyDetector,
    APIKeyValidator,
    FoundryInstaller,
    VirtualEnvHelper,
    check_directory_writable,
    test_import
)

def _check_halmos_available() -> bool:
    """Check if halmos binary is available (optional dependency)."""
    import shutil
    return shutil.which("halmos") is not None


# Custom style for questionary (matches rich theme)
custom_style = Style([
    ('qmark', 'fg:#00d7ff bold'),       # Cyan question mark
    ('question', 'bold'),                # Bold question
    ('answer', 'fg:#00d7ff bold'),      # Cyan answer
    ('pointer', 'fg:#00d7ff bold'),     # Cyan pointer
    ('highlighted', 'fg:#00d7ff bold'), # Cyan highlight
    ('selected', 'fg:#00d7ff'),         # Cyan selected
    ('separator', 'fg:#666666'),        # Gray separator
    ('instruction', ''),                # Default instruction
    ('text', ''),                       # Default text
])

def select_with_arrows(prompt_text: str, choices: List[str], default: Optional[str] = None) -> str:
    """Interactive selector with arrow keys, space to select, enter to confirm.
    
    Args:
        prompt_text: Prompt text to display
        choices: List of items to choose from
        default: Default selection (item from choices list)
    
    Returns:
        The selected item
    """
    try:
        result = questionary.select(
            prompt_text,
            choices=choices,
            default=default if default in choices else (choices[0] if choices else None),
            style=custom_style,
            use_shortcuts=True,
            use_arrow_keys=True,
            use_jk_keys=False
        ).ask()
        
        return result if result else (default if default else choices[0])
    except (KeyboardInterrupt, EOFError):
        # User cancelled - return default
        return default if default else choices[0]


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
            'gpt5_models': ['gpt-5.3-chat-latest', 'gpt-5.3-mini', 'gpt-5-chat-latest', 'gpt-5-pro', 'gpt-5-mini', 'gpt-5-nano'],
            'gpt4_models': ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'],
            'all_models': ['gpt-5.3-chat-latest', 'gpt-5.3-mini', 'gpt-5-chat-latest', 'gpt-5-pro', 'gpt-5-mini', 'gpt-5-nano', 'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo']
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
        'gemini_2_5_models': ['gemini-3.0-flash', 'gemini-3.0-pro', 'gemini-2.5-flash', 'gemini-2.5-pro'],
        'gemini_1_5_models': ['gemini-1.5-flash', 'gemini-1.5-pro'],
        'all_models': ['gemini-3.0-flash', 'gemini-3.0-pro', 'gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-1.5-flash', 'gemini-1.5-pro']
    }


def fetch_available_anthropic_models(api_key: str) -> Dict[str, List[str]]:
    """Fetch available Anthropic Claude models.

    Returns a dict with categorized models:
    - claude_4_models: List of Claude 4.x models
    - all_models: All available Claude models
    """
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        # Anthropic doesn't have a models.list() endpoint, use known models
        # Try a minimal call to verify the key works
        client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=5,
            messages=[{"role": "user", "content": "test"}],
        )

        # Key is valid, return known models
        return {
            'claude_4_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001'],
            'all_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001']
        }
    except ImportError:
        print("⚠️  anthropic package not installed")
        return {
            'claude_4_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001'],
            'all_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001']
        }
    except Exception as e:
        print(f"⚠️  Could not validate Anthropic API key: {e}")
        # Fallback to known models
        return {
            'claude_4_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001'],
            'all_models': ['claude-opus-4-6', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001']
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

        anthropic_key = getattr(self.existing_config, 'anthropic_api_key', '')
        if anthropic_key:
            table.add_row("Anthropic API Key", "✓ Configured", f"{anthropic_key[:10]}...")
        else:
            table.add_row("Anthropic API Key", "✗ Not set", "-")

        etherscan_key = getattr(self.existing_config, 'etherscan_api_key', '')
        if etherscan_key:
            table.add_row("Etherscan API Key", "✓ Configured", f"{etherscan_key[:10]}...")
        else:
            table.add_row("Etherscan API Key", "✗ Not set", "-")
        
        # Show active model selections (based on provider)
        validation_provider = getattr(self.existing_config, 'validation_provider', 'openai')
        analysis_provider = getattr(self.existing_config, 'analysis_provider', 'openai')
        generation_provider = getattr(self.existing_config, 'generation_provider', 'openai')
        
        # Get the active model for each task
        if validation_provider == 'anthropic':
            validation_model = getattr(self.existing_config, 'anthropic_validation_model', 'claude-sonnet-4-5-20250929')
        elif validation_provider == 'openai':
            validation_model = getattr(self.existing_config, 'openai_validation_model', 'gpt-5-chat-latest')
        else:
            validation_model = getattr(self.existing_config, 'gemini_validation_model', 'gemini-2.5-flash')

        if analysis_provider == 'anthropic':
            analysis_model = getattr(self.existing_config, 'anthropic_analysis_model', 'claude-opus-4-6')
        elif analysis_provider == 'openai':
            analysis_model = getattr(self.existing_config, 'openai_analysis_model', 'gpt-5-chat-latest')
        else:
            analysis_model = getattr(self.existing_config, 'gemini_analysis_model', 'gemini-2.5-flash')

        if generation_provider == 'anthropic':
            generation_model = getattr(self.existing_config, 'anthropic_generation_model', 'claude-sonnet-4-5-20250929')
        elif generation_provider == 'openai':
            generation_model = getattr(self.existing_config, 'openai_generation_model', 'gpt-5-mini')
        else:
            generation_model = getattr(self.existing_config, 'gemini_generation_model', 'gemini-2.5-flash')
        
        # Display active models
        table.add_row("Active Validation Model", "✓ Set", f"{validation_provider} / {validation_model}")
        table.add_row("Active Analysis Model", "✓ Set", f"{analysis_provider} / {analysis_model}")
        table.add_row("Active Generation Model", "✓ Set", f"{generation_provider} / {generation_model}")
        
        self.console.print(table)
    
    def _show_reconfiguration_menu(self) -> bool:
        """Show interactive menu for reconfiguration options."""
        while True:
            self.console.print("\n[bold]What would you like to do?[/bold]")
            self.console.print("  [cyan]1[/cyan] - Reconfigure API Keys")
            self.console.print("  [cyan]2[/cyan] - Reconfigure Model Selections")
            self.console.print("  [cyan]3[/cyan] - Full Reconfiguration (everything)")
            self.console.print("  [cyan]4[/cyan] - Verify Installation")
            self.console.print("  [cyan]5[/cyan] - View Configuration Again")
            self.console.print("  [cyan]0[/cyan] - Exit (configuration is already complete)")
            
            choice = Prompt.ask(
                "\nSelect option",
                choices=["0", "1", "2", "3", "4", "5"],
                default="0"
            )
            
            if choice == "0":
                self.console.print("\n[green]✓ Setup complete. Your configuration is ready![/green]")
                return True
            
            elif choice == "1":
                # Reconfigure API keys only
                self.console.print("\n[bold]Reconfiguring API Keys...[/bold]")
                self.reconfigure_keys = True
                if not self.configure_api_keys():
                    return False
                if not self.create_configuration():
                    return False
                self.console.print("[green]✓ API keys updated successfully![/green]")
                
                # Reload config to show updated values
                self._load_existing_config()
                self._show_existing_config()
            
            elif choice == "2":
                # Show model selection submenu
                if not self._show_model_selection_menu():
                    return False
                
                # Reload config to show updated values
                self._load_existing_config()
                self._show_existing_config()
            
            elif choice == "3":
                # Full reconfiguration
                self.console.print("\n[bold yellow]Full Reconfiguration[/bold yellow]")
                if Confirm.ask("This will reconfigure everything. Continue?", default=False):
                    self.reconfigure_all = True
                    # Start fresh setup process
                    return self.run()
                else:
                    self.console.print("[yellow]Cancelled full reconfiguration.[/yellow]")
            
            elif choice == "4":
                # Verify installation
                self.console.print("\n[bold]Verifying Installation...[/bold]")
                if self.verify_installation():
                    self.console.print("[green]✓ All checks passed![/green]")
                else:
                    self.console.print("[yellow]Some verification checks failed. See above.[/yellow]")
            
            elif choice == "5":
                # View configuration again
                self._show_existing_config()
            
            # Loop back to menu
    
    def _show_model_selection_menu(self) -> bool:
        """Show submenu for model selection with current assignments."""
        # Load existing keys
        if not self.api_keys:
            existing_openai = getattr(self.existing_config, 'openai_api_key', '')
            existing_gemini = getattr(self.existing_config, 'gemini_api_key', '')
            existing_anthropic = getattr(self.existing_config, 'anthropic_api_key', '')
            if existing_openai:
                self.api_keys['OPENAI_API_KEY'] = existing_openai
            if existing_gemini:
                self.api_keys['GEMINI_API_KEY'] = existing_gemini
            if existing_anthropic:
                self.api_keys['ANTHROPIC_API_KEY'] = existing_anthropic
        
        while True:
            self.console.print("\n[bold]Model Selection Manager[/bold]")
            self.console.print("\n[bold cyan]Current Model Assignments:[/bold cyan]")
            
            # Show current assignments
            tasks = ['validation', 'analysis', 'generation']
            for task in tasks:
                provider = getattr(self.existing_config, f'{task}_provider', 'openai')
                if provider == 'anthropic':
                    model = getattr(self.existing_config, f'anthropic_{task}_model', 'N/A')
                elif provider == 'openai':
                    model = getattr(self.existing_config, f'openai_{task}_model', 'N/A')
                else:
                    model = getattr(self.existing_config, f'gemini_{task}_model', 'N/A')

                self.console.print(f"  {task.title()}: [cyan]{provider}[/cyan] / [yellow]{model}[/yellow]")
            
            self.console.print("\n[bold]Select task to reconfigure:[/bold]")
            self.console.print("  [cyan]1[/cyan] - Validation Model")
            self.console.print("  [cyan]2[/cyan] - Analysis Model")
            self.console.print("  [cyan]3[/cyan] - Generation Model")
            self.console.print("  [cyan]4[/cyan] - AI Ensemble Agents (4 specialist agents)")
            self.console.print("  [cyan]5[/cyan] - Reconfigure All Models")
            self.console.print("  [cyan]0[/cyan] - Back to Main Menu")
            
            choice = Prompt.ask(
                "\nSelect option",
                choices=["0", "1", "2", "3", "4", "5"],
                default="0"
            )
            
            if choice == "0":
                return True
            elif choice == "1" or choice == "2" or choice == "3":
                # Reconfigure specific task
                task_map = {"1": "validation", "2": "analysis", "3": "generation"}
                task_name = task_map[choice]
                
                if not self._configure_single_task_model(task_name):
                    return False
                if not self.create_configuration():
                    return False
                self.console.print(f"[green]✓ {task_name.title()} model updated![/green]")
                self._load_existing_config()
            elif choice == "4":
                # Configure AI Ensemble agents
                if not self._configure_ensemble_agents():
                    return False
                if not self.create_configuration():
                    return False
                self.console.print("[green]✓ Ensemble agent models updated![/green]")
                self._load_existing_config()
            elif choice == "5":
                # Reconfigure all models
                self.reconfigure_models = True
                if not self._configure_model_selection():
                    return False
                if not self.create_configuration():
                    return False
                self.console.print("[green]✓ All models updated![/green]")
                self._load_existing_config()
    
    def _configure_single_task_model(self, task_name: str) -> bool:
        """Configure model for a single task type.

        Args:
            task_name: One of 'validation', 'analysis', or 'generation'
        """
        has_openai = self.api_keys.get('OPENAI_API_KEY')
        has_gemini = self.api_keys.get('GEMINI_API_KEY')
        has_anthropic = self.api_keys.get('ANTHROPIC_API_KEY')

        if not has_openai and not has_gemini and not has_anthropic:
            self.console.print("[red]No API keys configured![/red]")
            return False

        # Fetch available models
        available_openai = None
        available_gemini = None
        available_anthropic = None

        if has_openai:
            with self.console.status("[bold green]Fetching OpenAI models..."):
                available_openai = fetch_available_models(self.api_keys['OPENAI_API_KEY'])

        if has_gemini:
            with self.console.status("[bold green]Fetching Gemini models..."):
                available_gemini = fetch_available_gemini_models(self.api_keys['GEMINI_API_KEY'])

        if has_anthropic:
            with self.console.status("[bold green]Fetching Anthropic models..."):
                available_anthropic = fetch_available_anthropic_models(self.api_keys['ANTHROPIC_API_KEY'])

        task_desc = {
            'validation': 'false positive filtering - needs critical accuracy',
            'analysis': 'vulnerability detection - balanced quality',
            'generation': 'PoC/test generation - can use faster model'
        }

        self.console.print(f"\n[bold]Configure {task_name.title()} Model[/bold] (for {task_desc[task_name]})")

        # Choose provider
        provider = None
        provider_choices = []
        if has_openai:
            provider_choices.append("openai")
        if has_gemini:
            provider_choices.append("gemini")
        if has_anthropic:
            provider_choices.append("anthropic")

        if len(provider_choices) > 1:
            current_provider = getattr(self.existing_config, f'{task_name}_provider', 'openai')

            self.console.print(f"\n  Current: [cyan]{current_provider}[/cyan]")
            provider = select_with_arrows(
                "Select provider (use arrow keys, Enter to confirm)",
                provider_choices,
                default=current_provider if current_provider in provider_choices else provider_choices[0]
            )
            self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider
        elif len(provider_choices) == 1:
            provider = provider_choices[0]
            self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider

        # Select model from chosen provider
        if provider == "openai" and available_openai:
            choice_list = available_openai['gpt5_models'][:10] + available_openai['gpt4_models'][:5]
            current_model = getattr(self.existing_config, f'openai_{task_name}_model', choice_list[0])

            self.console.print(f"\n  Current: [yellow]{current_model}[/yellow]")
            model = select_with_arrows(
                "Select OpenAI model (use arrow keys, Enter to confirm)",
                choice_list,
                default=current_model if current_model in choice_list else choice_list[0]
            )
            self.api_keys[f'{task_name.upper()}_MODEL'] = model

        elif provider == "gemini" and available_gemini:
            choice_list = available_gemini['gemini_2_5_models'] + available_gemini['gemini_1_5_models']
            current_model = getattr(self.existing_config, f'gemini_{task_name}_model', choice_list[0])

            self.console.print(f"\n  Current: [yellow]{current_model}[/yellow]")
            model = select_with_arrows(
                "Select Gemini model (use arrow keys, Enter to confirm)",
                choice_list,
                default=current_model if current_model in choice_list else choice_list[0]
            )
            self.api_keys[f'GEMINI_{task_name.upper()}_MODEL'] = model

        elif provider == "anthropic" and available_anthropic:
            choice_list = available_anthropic['claude_4_models']
            current_model = getattr(self.existing_config, f'anthropic_{task_name}_model', choice_list[0])

            self.console.print(f"\n  Current: [yellow]{current_model}[/yellow]")
            model = select_with_arrows(
                "Select Anthropic model (use arrow keys, Enter to confirm)",
                choice_list,
                default=current_model if current_model in choice_list else choice_list[0]
            )
            self.api_keys[f'ANTHROPIC_{task_name.upper()}_MODEL'] = model

        return True
    
    def _configure_ensemble_agents(self) -> bool:
        """Configure models for each AI ensemble agent."""
        self.console.print("\n[bold]AI Ensemble Agent Configuration[/bold]")
        self.console.print("Configure models for each specialist agent\n")
        
        # Show current agent assignments
        agents = [
            ('gpt5_security', 'GPT-5 Security Auditor', 'Security vulnerabilities (access control, reentrancy, etc.)'),
            ('gpt5_defi', 'GPT-5 DeFi Specialist', 'DeFi protocols (AMM, lending, oracle manipulation)'),
            ('gemini_security', 'Gemini Security Hunter', 'Security patterns (external calls, delegatecall, etc.)'),
            ('gemini_verification', 'Gemini Formal Verifier', 'Formal verification (arithmetic, overflow, precision)'),
            ('anthropic_security', 'Anthropic Security Auditor', 'Deep security analysis (Claude Opus 4.6)'),
            ('anthropic_reasoning', 'Anthropic Reasoning Specialist', 'Extended reasoning for complex vulnerabilities'),
        ]
        
        self.console.print("[bold cyan]Current Agent Models:[/bold cyan]")
        for agent_key, agent_name, agent_focus in agents:
            current_model = getattr(self.existing_config, f'agent_{agent_key}_model', 'N/A')
            self.console.print(f"  {agent_name}: [yellow]{current_model}[/yellow]")
            self.console.print(f"    Focus: [dim]{agent_focus}[/dim]")
        
        # Fetch available models
        has_openai = self.api_keys.get('OPENAI_API_KEY')
        has_gemini = self.api_keys.get('GEMINI_API_KEY')
        has_anthropic = self.api_keys.get('ANTHROPIC_API_KEY')

        available_openai = None
        available_gemini = None
        available_anthropic = None

        if has_openai:
            with self.console.status("[bold green]Fetching OpenAI models..."):
                available_openai = fetch_available_models(self.api_keys['OPENAI_API_KEY'])

        if has_gemini:
            with self.console.status("[bold green]Fetching Gemini models..."):
                available_gemini = fetch_available_gemini_models(self.api_keys['GEMINI_API_KEY'])

        if has_anthropic:
            with self.console.status("[bold green]Fetching Anthropic models..."):
                available_anthropic = fetch_available_anthropic_models(self.api_keys['ANTHROPIC_API_KEY'])

        # Configure each agent
        for agent_key, agent_name, agent_focus in agents:
            self.console.print(f"\n[bold]{agent_name}[/bold]")
            self.console.print(f"[dim]Focus: {agent_focus}[/dim]")

            current_model = getattr(self.existing_config, f'agent_{agent_key}_model', 'N/A')
            self.console.print(f"Current: [yellow]{current_model}[/yellow]")

            # Determine which provider this agent uses
            is_gemini_agent = 'gemini' in agent_key
            is_anthropic_agent = 'anthropic' in agent_key

            if is_anthropic_agent and available_anthropic:
                # Anthropic agent - select from Claude models
                choice_list = available_anthropic['claude_4_models']
                model = select_with_arrows(
                    f"Select Anthropic model for {agent_name} (use arrow keys, Enter to confirm)",
                    choice_list,
                    default=current_model if current_model in choice_list else choice_list[0]
                )
            elif is_gemini_agent and available_gemini:
                # Gemini agent - select from Gemini models
                choice_list = available_gemini['gemini_2_5_models'] + available_gemini['gemini_1_5_models']
                model = select_with_arrows(
                    f"Select Gemini model for {agent_name} (use arrow keys, Enter to confirm)",
                    choice_list,
                    default=current_model if current_model in choice_list else choice_list[0]
                )
            elif not is_gemini_agent and not is_anthropic_agent and available_openai:
                # GPT-5 agent - select from OpenAI models
                choice_list = available_openai['gpt5_models'][:10] + available_openai['gpt4_models'][:5]
                model = select_with_arrows(
                    f"Select OpenAI model for {agent_name} (use arrow keys, Enter to confirm)",
                    choice_list,
                    default=current_model if current_model in choice_list else choice_list[0]
                )
            else:
                self.console.print(f"[yellow]Skipping - no API key for this agent[/yellow]")
                continue
            
            # Store the agent model selection
            self.api_keys[f'AGENT_{agent_key.upper()}_MODEL'] = model
        
        return True
    
    def run(self):
        """Run the complete setup process."""
        print(f"DEBUG: existing_config = {self.existing_config is not None}")
        print(f"DEBUG: reconfigure_all = {self.reconfigure_all}")
        
        # Check if this is a fresh install or reconfiguration
        is_fresh_install = not self.existing_config or self.reconfigure_all
        
        if is_fresh_install:
            # Fresh install - show full welcome and proceed
            self.print_welcome()
        else:
            # Existing config - show menu-driven reconfiguration options
            self.console.print("\n[bold cyan]Aether Setup - Configuration Manager[/bold cyan]")
            self.console.print("Configuration already exists. Checking current settings...\n")
            
            print("DEBUG: Showing existing config...")
            self._show_existing_config()
            
            if self.interactive:
                # Show menu
                return self._show_reconfiguration_menu()
            else:
                # Non-interactive with existing config - just exit
                self.console.print("[green]✓ Configuration already exists[/green]")
                return True
        
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
  ✓ Configure API keys (OpenAI, Gemini, Anthropic, Etherscan)
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
            
            # Check for version warnings
            if tool_info.get('installed') and not tool_info.get('version_ok', True):
                status = "⚠ Old Version"
                status_style = "yellow"
            
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
        
        # Check for Node.js version warnings
        if tools.get('node', {}).get('installed') and not tools.get('node', {}).get('version_ok', True):
            warning = tools['node'].get('warning', 'Node.js version too old')
            self.console.print(f"\n[yellow]⚠️  {warning}[/yellow]")
            if tools['node'].get('install_instructions'):
                self.console.print(f"   {tools['node']['install_instructions']}")
            
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
            existing_anthropic = getattr(self.existing_config, 'anthropic_api_key', '')

            if existing_openai or existing_gemini or existing_anthropic:
                self.console.print("  [green]✓ API keys already configured[/green]")

                if self.interactive and not Confirm.ask("  Reconfigure API keys?", default=False):
                    # Use existing keys
                    if existing_openai:
                        self.api_keys['OPENAI_API_KEY'] = existing_openai
                    if existing_gemini:
                        self.api_keys['GEMINI_API_KEY'] = existing_gemini
                    if existing_anthropic:
                        self.api_keys['ANTHROPIC_API_KEY'] = existing_anthropic
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
        
        # Anthropic API Key
        self.console.print("\n[bold]Anthropic API Key[/bold] (for Claude models)")
        existing_anthropic = getattr(self.existing_config, 'anthropic_api_key', '') if self.existing_config else ''
        anthropic_key = existing_anthropic or os.getenv('ANTHROPIC_API_KEY', '')

        if anthropic_key:
            self.console.print(f"  Found existing key: {anthropic_key[:10]}...")

            if self.interactive and not Confirm.ask("Use this key?", default=True):
                anthropic_key = ''

        if not anthropic_key and self.interactive:
            anthropic_key = Prompt.ask("  Enter Anthropic API key (or press Enter to skip)", default="")

        if anthropic_key:
            with self.console.status("[bold green]Validating Anthropic key..."):
                is_valid, message = validator.validate_anthropic_key(anthropic_key)

            if is_valid:
                self.console.print(f"  ✓ Anthropic key validated: {message}")
                self.api_keys['ANTHROPIC_API_KEY'] = anthropic_key
            else:
                self.console.print(f"  ✗ Anthropic key validation failed: {message}")

                if self.interactive and Confirm.ask("  Use anyway?", default=False):
                    self.api_keys['ANTHROPIC_API_KEY'] = anthropic_key
        else:
            self.console.print("  [yellow]Skipped Anthropic key configuration[/yellow]")

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
            existing_anthropic = getattr(self.existing_config, 'anthropic_api_key', '')

            if existing_openai or existing_gemini or existing_anthropic:
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

                    if existing_anthropic:
                        self.api_keys['ANTHROPIC_VALIDATION_MODEL'] = getattr(self.existing_config, 'anthropic_validation_model', 'claude-sonnet-4-5-20250929')
                        self.api_keys['ANTHROPIC_ANALYSIS_MODEL'] = getattr(self.existing_config, 'anthropic_analysis_model', 'claude-opus-4-6')
                        self.api_keys['ANTHROPIC_GENERATION_MODEL'] = getattr(self.existing_config, 'anthropic_generation_model', 'claude-sonnet-4-5-20250929')

                    return True
        
        # Model Selection
        has_openai = self.api_keys.get('OPENAI_API_KEY')
        has_gemini = self.api_keys.get('GEMINI_API_KEY')
        has_anthropic = self.api_keys.get('ANTHROPIC_API_KEY')

        if has_openai or has_gemini or has_anthropic:
            self.console.print("\n[bold]Model Selection[/bold] (Choose provider and model per task)")
            self.console.print("\n[cyan]You can mix providers:[/cyan]")
            self.console.print("  Example: Use Gemini for validation (2M context) + OpenAI for generation + Anthropic for analysis")

        # Fetch available models
        available_openai = None
        available_gemini = None
        available_anthropic = None

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

        if has_anthropic:
            with self.console.status("[bold green]Fetching available Anthropic models..."):
                available_anthropic = fetch_available_anthropic_models(self.api_keys['ANTHROPIC_API_KEY'])

            if available_anthropic['claude_4_models']:
                self.console.print("\n[bold cyan]Available Claude Models:[/bold cyan] (200K context, extended thinking)")
                for model in available_anthropic['claude_4_models']:
                    self.console.print(f"  • {model}")

            if self.interactive:
                # Configure each task type with provider + model selection
                for task_name, task_desc in [
                    ('validation', 'false positive filtering - critical accuracy'),
                    ('analysis', 'vulnerability detection - balanced quality'),
                    ('generation', 'PoC/test generation - can use faster model')
                ]:
                    self.console.print(f"\n[bold]{task_name.title()} Task[/bold] (for {task_desc})")
                    
                    # Choose provider if multiple are available
                    provider_choices = []
                    if has_openai:
                        provider_choices.append("openai")
                    if has_gemini:
                        provider_choices.append("gemini")
                    if has_anthropic:
                        provider_choices.append("anthropic")

                    if len(provider_choices) > 1:
                        default_provider = "gemini" if task_name == "validation" and "gemini" in provider_choices else "openai" if "openai" in provider_choices else provider_choices[0]

                        provider = select_with_arrows(
                            f"Select provider for {task_name} (use arrow keys, Enter to confirm)",
                            provider_choices,
                            default=default_provider
                        )

                        self.api_keys[f'{task_name.upper()}_PROVIDER'] = provider
                    elif len(provider_choices) == 1:
                        provider = provider_choices[0]
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
                    elif provider == "anthropic" and available_anthropic:
                        choice_list = available_anthropic['claude_4_models']
                        default_model = 'claude-opus-4-6' if task_name == 'analysis' else 'claude-sonnet-4-5-20250929'
                    else:  # gemini
                        choice_list = available_gemini['gemini_2_5_models'] + available_gemini['gemini_1_5_models']
                        default_model = available_gemini['gemini_2_5_models'][0] if available_gemini['gemini_2_5_models'] else available_gemini['all_models'][0]

                    model = select_with_arrows(
                        f"Select {provider} model for {task_name} (use arrow keys, Enter to confirm)",
                        choice_list,
                        default=default_model if default_model in choice_list else choice_list[0]
                    )

                    # Store both provider and model
                    if provider == "openai":
                        self.api_keys[f'{task_name.upper()}_MODEL'] = model
                    elif provider == "anthropic":
                        self.api_keys[f'ANTHROPIC_{task_name.upper()}_MODEL'] = model
                    else:
                        self.api_keys[f'GEMINI_{task_name.upper()}_MODEL'] = model
                
                # Show summary
                self.console.print(f"\n  ✓ Model configuration:")
                for task in ['validation', 'analysis', 'generation']:
                    provider = self.api_keys.get(f'{task.upper()}_PROVIDER', 'openai')
                    if provider == 'anthropic':
                        model = self.api_keys.get(f'ANTHROPIC_{task.upper()}_MODEL', 'N/A')
                    elif provider == 'openai':
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
                elif has_anthropic and available_anthropic:
                    self.api_keys['VALIDATION_PROVIDER'] = 'anthropic'
                    self.api_keys['ANALYSIS_PROVIDER'] = 'anthropic'
                    self.api_keys['GENERATION_PROVIDER'] = 'anthropic'
                    self.api_keys['ANTHROPIC_VALIDATION_MODEL'] = 'claude-sonnet-4-5-20250929'
                    self.api_keys['ANTHROPIC_ANALYSIS_MODEL'] = 'claude-opus-4-6'
                    self.api_keys['ANTHROPIC_GENERATION_MODEL'] = 'claude-sonnet-4-5-20250929'
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
                elif key == 'ANTHROPIC_API_KEY':
                    config_manager.config.anthropic_api_key = value
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
                # Anthropic model selections
                elif key == 'ANTHROPIC_VALIDATION_MODEL':
                    config_manager.config.anthropic_validation_model = value
                elif key == 'ANTHROPIC_ANALYSIS_MODEL':
                    config_manager.config.anthropic_analysis_model = value
                elif key == 'ANTHROPIC_GENERATION_MODEL':
                    config_manager.config.anthropic_generation_model = value
                # AI Ensemble agent model selections
                elif key == 'AGENT_GPT5_SECURITY_MODEL':
                    config_manager.config.agent_gpt5_security_model = value
                elif key == 'AGENT_GPT5_DEFI_MODEL':
                    config_manager.config.agent_gpt5_defi_model = value
                elif key == 'AGENT_GEMINI_SECURITY_MODEL':
                    config_manager.config.agent_gemini_security_model = value
                elif key == 'AGENT_GEMINI_VERIFICATION_MODEL':
                    config_manager.config.agent_gemini_verification_model = value
                elif key == 'AGENT_ANTHROPIC_SECURITY_MODEL':
                    config_manager.config.agent_anthropic_security_model = value
                elif key == 'AGENT_ANTHROPIC_REASONING_MODEL':
                    config_manager.config.agent_anthropic_reasoning_model = value
            
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
            ("Halmos (optional)", lambda: _check_halmos_available()),
            ("Config directory writable", lambda: check_directory_writable(self.config_dir)[0]),
            ("Import: rich", lambda: test_import('rich')[0]),
            ("Import: web3", lambda: test_import('web3')[0]),
            ("Import: openai", lambda: test_import('openai')[0]),
            ("Import: anthropic", lambda: test_import('anthropic')[0]),
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

