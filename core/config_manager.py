#!/usr/bin/env python3
"""
Configuration Manager for AetherAudit

Manages tool configurations, user preferences, and environment settings.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from rich.console import Console


@dataclass
class ToolConfig:
    """Configuration for a specific security tool."""
    name: str
    enabled: bool = True
    timeout: int = 300
    options: Dict[str, Any] = None

    def __post_init__(self):
        if self.options is None:
            self.options = {}


@dataclass
class AetherConfig:
    """Main configuration for AetherAudit."""

    # Core settings
    workspace: str = "./workspace"
    output_dir: str = "./output"
    reports_dir: str = "./reports"

    # Tool configurations
    tools: Dict[str, ToolConfig] = None

    # Analysis settings
    max_analysis_time: int = 3600  # 1 hour
    parallel_analysis: bool = True
    max_concurrent_contracts: int = 5

    # Reporting settings
    report_format: str = "comprehensive"  # comprehensive, summary, json
    include_exploit_pocs: bool = True
    include_fix_suggestions: bool = True

    # Bug bounty settings
    bug_bounty_mode: bool = False
    include_impact_analysis: bool = True
    generate_exploit_scripts: bool = False

    # API settings (for LLM features)
    openai_api_key: str = ""
    gemini_api_key: str = ""
    
    # Model Provider Selection (per task type)
    # Choose which provider to use for each task: "openai" or "gemini"
    validation_provider: str = "gemini"   # Provider for validation (false positive filtering) - Gemini has 2M TPM vs OpenAI's 30K
    analysis_provider: str = "openai"     # Provider for vulnerability analysis
    generation_provider: str = "openai"   # Provider for PoC/test generation
    
    # OpenAI Model selection - Different models for different purposes
    # Validation model (for false positive filtering) - needs highest accuracy
    openai_validation_model: str = "gpt-5-chat-latest"
    # Analysis model (for vulnerability detection) - balanced quality
    openai_analysis_model: str = "gpt-5-chat-latest"
    # Generation model (for PoC/test generation) - can be faster/cheaper
    openai_generation_model: str = "gpt-5-mini"
    # Deprecated: kept for backwards compatibility
    openai_model: str = "gpt-5-chat-latest"
    
    # Gemini Model selection (alternative to OpenAI)
    # Validation model - Gemini 2.5 Flash has thinking mode and 2M context
    gemini_validation_model: str = "gemini-2.5-flash"
    # Analysis model - can use Pro for best quality or Flash for speed
    gemini_analysis_model: str = "gemini-2.5-flash"
    # Generation model - Flash is fast and cost-effective
    gemini_generation_model: str = "gemini-2.5-flash"
    
    # AI Ensemble Agent Models (individual specialist agents)
    # Each agent can use a different model for specialized analysis
    agent_gpt5_security_model: str = "gpt-5-chat-latest"      # Security vulnerability auditor
    agent_gpt5_defi_model: str = "gpt-5-chat-latest"          # DeFi protocol specialist
    agent_gemini_security_model: str = "gemini-2.5-flash"     # Gemini security hunter (2M context)
    agent_gemini_verification_model: str = "gemini-2.5-pro"   # Formal verification (use Pro for best quality)
    
    max_tokens: int = 4000
    
    # Triage/LLM settings
    triage_min_severity: str = "medium"
    triage_min_confidence: float = 0.40
    triage_max_items: int = 200
    triage_max_per_type: int = 30
    llm_only_consensus: bool = False
    llm_triage_min_severity: str = "medium"
    llm_triage_min_confidence: float = 0.40
    llm_triage_max_items: int = 200
    llm_triage_max_per_type: int = 30

    # Foundry settings
    foundry_only_consensus: bool = True
    foundry_max_items: int = 80
    
    # Etherscan API settings
    etherscan_api_key: str = ""
    etherscan_base_url: str = "https://api.etherscan.io/v2/api"

    def __post_init__(self):
        if self.tools is None:
            self.tools = {
                'slither': ToolConfig('slither', True, 300),
                'mythril': ToolConfig('mythril', True, 600),
                'pattern': ToolConfig('pattern', True, 60),
                'llm': ToolConfig('llm', True, 120)
            }


def get_model_for_task(task_type: str) -> str:
    """Get the configured model for a specific task type.
    
    Args:
        task_type: One of 'validation', 'analysis', or 'generation'
    
    Returns:
        The model name to use (e.g., 'gpt-5-chat-latest' or 'gemini-2.5-flash')
    """
    try:
        config_manager = ConfigManager()
        
        # Get the provider for this task
        provider_attr = f"{task_type}_provider"
        provider = getattr(config_manager.config, provider_attr, "openai")
        
        # Get the model from the appropriate provider
        model_attr = f"{provider}_{task_type}_model"
        model = getattr(config_manager.config, model_attr, None)
        
        # Fallback logic
        if not model:
            if provider == "gemini":
                model = "gemini-2.5-flash"
            else:
                model = "gpt-5-chat-latest" if task_type == "validation" or task_type == "analysis" else "gpt-5-mini"
        
        return model
    except Exception:
        # Ultimate fallback
        return "gpt-5-chat-latest" if task_type == "validation" or task_type == "analysis" else "gpt-5-mini"


class ConfigManager:
    """Manages AetherAudit configuration."""

    def __init__(self, config_file: str = "~/.aether/config.yaml"):
        self.config_file = Path(config_file).expanduser()
        self.console = Console()
        self.config = AetherConfig()

        # Ensure config directory exists
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = yaml.safe_load(f)

                if data:
                    # Update config with loaded data
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            if key == 'tools' and isinstance(value, dict):
                                # Handle tools configuration
                                tools_dict = {}
                                for tool_name, tool_data in value.items():
                                    if isinstance(tool_data, dict):
                                        # Remove 'name' from tool_data if it exists to avoid duplicate argument
                                        tool_data_copy = tool_data.copy()
                                        tool_data_copy.pop('name', None)
                                        tools_dict[tool_name] = ToolConfig(
                                            name=tool_name,
                                            **tool_data_copy
                                        )
                                    else:
                                        tools_dict[tool_name] = ToolConfig(tool_name, enabled=tool_data)
                                setattr(self.config, key, tools_dict)
                            else:
                                setattr(self.config, key, value)

            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not load config file: {e}[/yellow]")
                self._create_default_config()

    def save_config(self) -> None:
        """Save current configuration to file."""
        try:
            # Convert dataclasses to dicts for YAML serialization
            config_dict = asdict(self.config)

            # Convert ToolConfig objects to dicts
            if 'tools' in config_dict and config_dict['tools']:
                tools_dict = {}
                for tool_name, tool_config in config_dict['tools'].items():
                    if isinstance(tool_config, ToolConfig):
                        tools_dict[tool_name] = asdict(tool_config)
                    else:
                        tools_dict[tool_name] = tool_config
                config_dict['tools'] = tools_dict

            with open(self.config_file, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)

            self.console.print(f"[green]✓ Configuration saved to {self.config_file}[/green]")

        except Exception as e:
            self.console.print(f"[red]✗ Failed to save config: {e}[/red]")

    def _create_default_config(self) -> None:
        """Create a default configuration file."""
        self.save_config()

    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """Get configuration for a specific tool."""
        return self.config.tools.get(tool_name) if self.config.tools else None

    def set_tool_config(self, tool_name: str, **kwargs) -> None:
        """Update configuration for a specific tool."""
        if tool_name not in self.config.tools:
            self.config.tools[tool_name] = ToolConfig(tool_name)

        for key, value in kwargs.items():
            if hasattr(self.config.tools[tool_name], key):
                setattr(self.config.tools[tool_name], key, value)

    def enable_tool(self, tool_name: str) -> bool:
        """Enable a specific tool."""
        if tool_name in self.config.tools:
            self.config.tools[tool_name].enabled = True
            self.console.print(f"[green]✓ Enabled {tool_name}[/green]")
            return True
        else:
            self.console.print(f"[red]✗ Unknown tool: {tool_name}[/red]")
            return False

    def disable_tool(self, tool_name: str) -> bool:
        """Disable a specific tool."""
        if tool_name in self.config.tools:
            self.config.tools[tool_name].enabled = False
            self.console.print(f"[yellow]⚠ Disabled {tool_name}[/yellow]")
            return True
        else:
            self.console.print(f"[red]✗ Unknown tool: {tool_name}[/red]")
            return False

    def show_config(self) -> None:
        """Display current configuration."""
        from rich.table import Table
        from rich.panel import Panel

        # Main config table
        main_table = Table(title="⚙️ Main Configuration")
        main_table.add_column("Setting", style="cyan")
        main_table.add_column("Value", style="green")

        main_table.add_row("Workspace", self.config.workspace)
        main_table.add_row("Output Directory", self.config.output_dir)
        main_table.add_row("Reports Directory", self.config.reports_dir)
        main_table.add_row("Max Analysis Time", f"{self.config.max_analysis_time}s")
        main_table.add_row("Parallel Analysis", "Yes" if self.config.parallel_analysis else "No")
        main_table.add_row("Bug Bounty Mode", "Yes" if self.config.bug_bounty_mode else "No")

        self.console.print(main_table)

        # Tools config table
        tools_table = Table(title="🔧 Tool Configuration")
        tools_table.add_column("Tool", style="cyan")
        tools_table.add_column("Enabled", style="green")
        tools_table.add_column("Timeout", style="yellow")
        tools_table.add_column("Options", style="white")

        for tool_name, tool_config in self.config.tools.items():
            enabled = "✅ Yes" if tool_config.enabled else "❌ No"
            timeout = f"{tool_config.timeout}s"
            options = str(tool_config.options) if tool_config.options else "None"

            tools_table.add_row(tool_name, enabled, timeout, options)

        self.console.print(tools_table)

        # Triage/LLM settings table
        triage_table = Table(title="🗂 Triage & LLM Settings")
        triage_table.add_column("Setting", style="cyan")
        triage_table.add_column("Value", style="green")
        triage_table.add_row("triage_min_severity", str(self.config.triage_min_severity))
        triage_table.add_row("triage_min_confidence", str(self.config.triage_min_confidence))
        triage_table.add_row("triage_max_items", str(self.config.triage_max_items))
        triage_table.add_row("triage_max_per_type", str(self.config.triage_max_per_type))
        triage_table.add_row("llm_only_consensus", "Yes" if self.config.llm_only_consensus else "No")
        triage_table.add_row("llm_triage_min_severity", str(self.config.llm_triage_min_severity))
        triage_table.add_row("llm_triage_min_confidence", str(self.config.llm_triage_min_confidence))
        triage_table.add_row("llm_triage_max_items", str(self.config.llm_triage_max_items))
        triage_table.add_row("llm_triage_max_per_type", str(self.config.llm_triage_max_per_type))
        self.console.print(triage_table)

        # Foundry settings table
        foundry_table = Table(title="🔨 Foundry Settings")
        foundry_table.add_column("Setting", style="cyan")
        foundry_table.add_column("Value", style="green")
        foundry_table.add_row("foundry_only_consensus", "Yes" if self.config.foundry_only_consensus else "No")
        foundry_table.add_row("foundry_max_items", str(self.config.foundry_max_items))
        self.console.print(foundry_table)

        # Show config file location
        self.console.print(f"\n[bold cyan]Config File:[/bold cyan] {self.config_file}")

    def interactive_config(self) -> None:
        """Interactive configuration setup."""
        self.console.print("[bold cyan]🔧 Interactive Configuration Setup[/bold cyan]")

        # Main settings
        self.console.print("\n[bold]Main Settings:[/bold]")

        if self.console.input("Change workspace directory? (y/N): ").lower() == 'y':
            workspace = self.console.input("Workspace directory: ")
            if workspace:
                self.config.workspace = workspace

        if self.console.input("Change output directory? (y/N): ").lower() == 'y':
            output_dir = self.console.input("Output directory: ")
            if output_dir:
                self.config.output_dir = output_dir

        if self.console.input("Enable bug bounty mode? (y/N): ").lower() == 'y':
            self.config.bug_bounty_mode = True
            self.config.include_exploit_pocs = True
            self.config.include_impact_analysis = True
            self.console.print("[green]✓ Bug bounty mode enabled[/green]")

        # Tool configuration
        self.console.print("\n[bold]Tool Configuration:[/bold]")

        for tool_name in self.config.tools.keys():
            current_config = self.config.tools[tool_name]

            if self.console.input(f"Configure {tool_name}? (y/N): ").lower() == 'y':
                enabled = self.console.input(f"Enable {tool_name}? (Y/n): ").lower() != 'n'
                current_config.enabled = enabled

                timeout_str = self.console.input(f"Timeout for {tool_name} (seconds, current: {current_config.timeout}): ")
                if timeout_str.isdigit():
                    current_config.timeout = int(timeout_str)

        # Save configuration
        if self.console.input("Save configuration? (Y/n): ").lower() != 'n':
            self.save_config()

    def set_openai_key(self, api_key: str) -> None:
        """Set OpenAI API key for LLM features."""
        self.config.openai_api_key = api_key
        self.save_config()
        self.console.print("[green]✓ OpenAI API key configured[/green]")

    def set_etherscan_key(self, api_key: str) -> None:
        """Set Etherscan API key for contract fetching."""
        self.config.etherscan_api_key = api_key
        self.save_config()
        self.console.print("[green]✓ Etherscan API key configured[/green]")
    
    def set_gemini_key(self, api_key: str) -> None:
        """Set Gemini API key for LLM features."""
        self.config.gemini_api_key = api_key
        self.save_config()
        self.console.print("[green]✓ Gemini API key configured[/green]")
    
    def validate_openai_key(self, api_key: Optional[str] = None) -> tuple[bool, str]:
        """Validate OpenAI API key by making a test call.
        
        Args:
            api_key: API key to validate. If None, uses configured key.
            
        Returns:
            Tuple of (is_valid, message)
        """
        key_to_test = api_key or self.config.openai_api_key
        
        if not key_to_test:
            return False, "No API key provided"
        
        if not key_to_test.startswith('sk-'):
            return False, "Invalid format (should start with 'sk-')"
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=key_to_test)
            
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
    
    def validate_gemini_key(self, api_key: Optional[str] = None) -> tuple[bool, str]:
        """Validate Gemini API key by making a test call.
        
        Args:
            api_key: API key to validate. If None, uses configured key.
            
        Returns:
            Tuple of (is_valid, message)
        """
        key_to_test = api_key or self.config.gemini_api_key
        
        if not key_to_test:
            return False, "No API key provided"
        
        try:
            import httpx
            
            # Test Gemini API with a minimal request
            url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + key_to_test
            
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
    
    def validate_etherscan_key(self, api_key: Optional[str] = None, network: str = 'mainnet') -> tuple[bool, str]:
        """Validate Etherscan API key by making a test call.
        
        Args:
            api_key: API key to validate. If None, uses configured key.
            network: Network to test against (mainnet, polygon, arbitrum, base)
            
        Returns:
            Tuple of (is_valid, message)
        """
        key_to_test = api_key or self.config.etherscan_api_key
        
        if not key_to_test:
            return False, "No API key provided"
        
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
            
            url = f"{base_url}?module=stats&action=ethsupply&apikey={key_to_test}"
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

    def get_workspace_path(self) -> Path:
        """Get workspace path as Path object."""
        return Path(self.config.workspace).expanduser().resolve()

    def get_output_path(self) -> Path:
        """Get output path as Path object."""
        return Path(self.config.output_dir).expanduser().resolve()

    def get_reports_path(self) -> Path:
        """Get reports path as Path object."""
        return Path(self.config.reports_dir).expanduser().resolve()
