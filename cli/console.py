#!/usr/bin/env python3
"""
AetherAudit Console - Metasploit-style CLI for Smart Contract Security Auditing

Interactive console with modular agents for comprehensive vulnerability analysis.
"""

import asyncio
import cmd
import os
import sys
import json
import shlex
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.flow_executor import FlowExecutor
from core.report_generator import ReportGenerator
from core.config_manager import ConfigManager
from core.exploit_validator import ExploitValidator
from utils.file_handler import FileHandler


class ToolManager:
    """Manages detection and installation of security analysis tools."""

    REQUIRED_TOOLS = {
        'slither': {
            'description': 'Static analysis tool for Solidity',
            'install_cmd': 'pip install slither-analyzer',
            'check_cmd': 'slither --version',
            'version_pattern': r'Slither (\d+\.\d+\.\d+)'
        },
        'mythril': {
            'description': 'Symbolic execution tool for EVM bytecode',
            'install_cmd': 'pip install mythril',
            'check_cmd': 'mythril --version',
            'version_pattern': r'Mythril (\d+\.\d+\.\d+)'
        },
        'foundry': {
            'description': 'Ethereum development framework',
            'install_cmd': 'curl -L https://foundry.paradigm.xyz | bash && foundryup',
            'check_cmd': 'forge --version',
            'version_pattern': r'forge (\d+\.\d+\.\d+)'
        },
        'solc': {
            'description': 'Solidity compiler',
            'install_cmd': 'pip install solc-select && solc-select install latest',
            'check_cmd': 'solc --version',
            'version_pattern': r'Version: (\d+\.\d+\.\d+)'
        }
    }

    def __init__(self):
        self.console = Console()
        self.installed_tools = {}

    def detect_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detect which tools are installed and their versions."""
        detected = {}

        for tool_name, tool_info in self.REQUIRED_TOOLS.items():
            try:
                # Check if tool exists in PATH
                import subprocess
                import re

                result = subprocess.run(
                    tool_info['check_cmd'].split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    # Extract version
                    version_match = re.search(tool_info['version_pattern'], result.stdout)
                    version = version_match.group(1) if version_match else 'Unknown'

                    detected[tool_name] = {
                        'installed': True,
                        'version': version,
                        'description': tool_info['description']
                    }
                else:
                    detected[tool_name] = {
                        'installed': False,
                        'version': None,
                        'description': tool_info['description']
                    }

            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                detected[tool_name] = {
                    'installed': False,
                    'version': None,
                    'description': tool_info['description']
                }

        self.installed_tools = detected
        return detected

    def install_tool(self, tool_name: str) -> bool:
        """Install a specific tool."""
        if tool_name not in self.REQUIRED_TOOLS:
            self.console.print(f"[red]Unknown tool: {tool_name}[/red]")
            return False

        tool_info = self.REQUIRED_TOOLS[tool_name]

        with self.console.status(f"[bold green]Installing {tool_name}..."):
            try:
                import subprocess

                if tool_name == 'foundry':
                    # Special handling for Foundry installation
                    result = subprocess.run(
                        tool_info['install_cmd'].split(),
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                else:
                    result = subprocess.run(
                        tool_info['install_cmd'].split(),
                        capture_output=True,
                        text=True,
                        timeout=120
                    )

                if result.returncode == 0:
                    self.console.print(f"[green]✓ {tool_name} installed successfully[/green]")
                    return True
                else:
                    self.console.print(f"[red]✗ Failed to install {tool_name}: {result.stderr}[/red]")
                    return False

            except Exception as e:
                self.console.print(f"[red]✗ Error installing {tool_name}: {e}[/red]")
                return False

    def show_tool_status(self):
        """Display current tool installation status."""
        tools = self.detect_tools()

        table = Table(title="🔧 Tool Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Version", style="yellow")
        table.add_column("Description", style="white")

        for tool_name, info in tools.items():
            status = "✅ Installed" if info['installed'] else "❌ Missing"
            version = info['version'] if info['version'] else "N/A"
            status_style = "green" if info['installed'] else "red"

            table.add_row(
                tool_name,
                f"[{status_style}]{status}[/{status_style}]",
                version,
                info['description']
            )

        self.console.print(table)

        missing_tools = [name for name, info in tools.items() if not info['installed']]
        if missing_tools:
            if Confirm.ask(f"\nInstall missing tools? ({', '.join(missing_tools)})", default=True):
                for tool in missing_tools:
                    self.install_tool(tool)


class AetherConsole(cmd.Cmd):
    """Metasploit-style interactive console for AetherAudit."""

    intro = """
       A      E      T      H      E      R      A     U      D      I      T 
     ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        Adaptive Exploit & Threat Hunting Engine for EVM-based Repositories 
                                l33tdawg@hitb.org
                                
                            Type help to view commands
    """

    prompt = ">> "

    def __init__(self):
        super().__init__()
        self.console = Console()
        self.tool_manager = ToolManager()
        self.config_manager = ConfigManager()
        self.current_module = None
        self.module_options = {}
        self.flow_executor = FlowExecutor()
        self.report_generator = ReportGenerator()
        self.exploit_validator = ExploitValidator()
        self.file_handler = FileHandler()

        # Available modules
        self.modules = {
            'audit': {
                'description': 'Comprehensive smart contract security audit',
                'options': {
                    'CONTRACT': {'value': None, 'required': True, 'description': 'Path to Solidity contract'},
                    'OUTPUT_DIR': {'value': './output', 'required': False, 'description': 'Output directory for reports'},
                    'VERBOSE': {'value': False, 'required': False, 'description': 'Enable verbose output'},
                    'FLOW_CONFIG': {'value': 'configs/default_audit.yaml', 'required': False, 'description': 'YAML flow configuration'}
                }
            },
            'fuzz': {
                'description': 'Dynamic fuzzing and exploit validation',
                'options': {
                    'CONTRACT': {'value': None, 'required': True, 'description': 'Path to Solidity contract'},
                    'FUZZ_TIME': {'value': 60, 'required': False, 'description': 'Fuzzing duration in seconds'},
                    'CORPUS_SIZE': {'value': 1000, 'required': False, 'description': 'Number of test cases to generate'}
                }
            },
            'pattern': {
                'description': 'Pattern-based vulnerability detection',
                'options': {
                    'CONTRACT': {'value': None, 'required': True, 'description': 'Path to Solidity contract'},
                    'PATTERNS': {'value': 'all', 'required': False, 'description': 'Comma-separated pattern categories'}
                }
            },
            'slither': {
                'description': 'Slither static analysis integration',
                'options': {
                    'CONTRACT': {'value': None, 'required': True, 'description': 'Path to Solidity contract'},
                    'EXCLUDE_DEPS': {'value': True, 'required': False, 'description': 'Exclude dependency analysis'}
                }
            },
            'mythril': {
                'description': 'Mythril symbolic execution',
                'options': {
                    'CONTRACT': {'value': None, 'required': True, 'description': 'Path to Solidity contract'},
                    'TIMEOUT': {'value': 300, 'required': False, 'description': 'Analysis timeout in seconds'}
                }
            }
        }

    def do_use(self, args):
        """Use a specific module: use [module_name]"""
        args = args.strip()
        if not args:
            self.console.print("[red]Usage: use [module_name][/red]")
            return

        if args in self.modules:
            self.current_module = args
            self.module_options = self.modules[args]['options'].copy()
            self.console.print(f"[green]Using module: {args}[/green]")
            self.console.print(f"[cyan]{self.modules[args]['description']}[/cyan]")
            self.do_show_options("")
        else:
            self.console.print(f"[red]Unknown module: {args}[/red]")
            self.console.print(f"[yellow]Available modules: {', '.join(self.modules.keys())}[/yellow]")

    def do_show(self, args):
        """Show various information: show [options|modules|tools|config]"""
        args = args.strip()

        if args == 'modules':
            self._show_modules()
        elif args == 'tools':
            self.tool_manager.show_tool_status()
        elif args == 'options' or args == '':
            self.do_show_options(args)
        elif args == 'config':
            self.config_manager.show_config()
        else:
            self.console.print("[red]Usage: show [options|modules|tools|config][/red]")

    def do_show_options(self, args):
        """Show current module options"""
        if not self.current_module:
            self.console.print("[yellow]No module selected. Use 'use [module]' first.[/yellow]")
            return

        table = Table(title=f"📋 Module Options: {self.current_module}")
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Required", style="yellow")
        table.add_column("Description", style="white")

        for option, info in self.module_options.items():
            required = "Yes" if info['required'] else "No"
            value = str(info['value']) if info['value'] is not None else "Not set"
            table.add_row(option, value, required, info['description'])

        self.console.print(table)

    def do_set(self, args):
        """Set module option: set [option] [value]"""
        if not self.current_module:
            self.console.print("[yellow]No module selected. Use 'use [module]' first.[/yellow]")
            return

        try:
            option, value = args.split(None, 1)
        except ValueError:
            self.console.print("[red]Usage: set [option] [value][/red]")
            return

        if option in self.module_options:
            # Type conversion for common types
            if isinstance(self.module_options[option]['value'], bool):
                value = value.lower() in ('true', '1', 'yes', 'on')
            elif isinstance(self.module_options[option]['value'], int):
                try:
                    value = int(value)
                except ValueError:
                    self.console.print(f"[red]Invalid integer value for {option}[/red]")
                    return

            self.module_options[option]['value'] = value
            self.console.print(f"[green]{option} => {value}[/green]")
        else:
            self.console.print(f"[red]Unknown option: {option}[/red]")

    def do_run(self, args):
        """Run the current module or full pipeline"""
        if self.current_module:
            asyncio.run(self._run_module())
        else:
            self.console.print("[yellow]No module selected. Use 'use [module]' first or run full pipeline.[/yellow]")
            if Confirm.ask("Run full pipeline?", default=True):
                asyncio.run(self._run_full_pipeline(args.strip()))

    def do_exploit(self, args):
        """Exploit validation and PoC generation"""
        if not self.current_module:
            self.console.print("[yellow]No module selected. Use 'use audit' first.[/yellow]")
            return

        contract_path = self.module_options.get('CONTRACT', {}).get('value')
        if not contract_path:
            self.console.print("[red]No contract specified. Set CONTRACT option first.[/red]")
            return

        asyncio.run(self._exploit_validation(contract_path))

    def do_config(self, args):
        """Configuration management: config [show|interactive|set_api_key]"""
        args = args.strip()

        if not args:
            self.config_manager.show_config()
        elif args == 'interactive':
            self.config_manager.interactive_config()
        elif args.startswith('set_api_key'):
            try:
                _, api_key = args.split(None, 1)
                self.config_manager.set_openai_key(api_key)
            except ValueError:
                self.console.print("[red]Usage: config set_api_key [api_key][/red]")
        elif args == 'enable_tools':
            # Enable all tools
            for tool_name in self.config_manager.config.tools.keys():
                self.config_manager.enable_tool(tool_name)
        elif args == 'disable_tools':
            # Disable all tools
            for tool_name in self.config_manager.config.tools.keys():
                self.config_manager.disable_tool(tool_name)
        else:
            self.console.print("[red]Usage: config [show|interactive|set_api_key|enable_tools|disable_tools][/red]")

    def do_search(self, args):
        """Search for vulnerabilities: search [pattern]"""
        if not args:
            self.console.print("[red]Usage: search [pattern][/red]")
            return

        self._search_vulnerabilities(args)

    def do_db_status(self, args):
        """Check database and workspace status"""
        self._show_workspace_status()

    def do_exit(self, args):
        """Exit the console"""
        self.console.print("[bold cyan]Goodbye![/bold cyan]")
        return True

    def do_quit(self, args):
        """Exit the console"""
        return self.do_exit(args)

    def do_EOF(self, args):
        """Handle Ctrl+D"""
        return self.do_exit(args)

    # Helper methods

    def _show_modules(self):
        """Display available modules."""
        table = Table(title="🔧 Available Modules")
        table.add_column("Module", style="cyan")
        table.add_column("Description", style="white")

        for name, info in self.modules.items():
            table.add_row(name, info['description'])

        self.console.print(table)

    def _show_config(self):
        """Display current configuration."""
        config = {
            'Current Module': self.current_module or 'None',
            'Workspace': os.getcwd(),
            'Python Version': sys.version,
            'Tools Detected': len([t for t in self.tool_manager.detect_tools().values() if t['installed']])
        }

        content = ""
        for key, value in config.items():
            content += f"[bold cyan]{key}:[/bold cyan] {value}\n"

        self.console.print(Panel(content, title="⚙️  Configuration"))

    def _show_workspace_status(self):
        """Display workspace and output status."""
        output_dirs = [d for d in Path('./output').iterdir() if d.is_dir()] if Path('./output').exists() else []

        content = f"""
[bold cyan]Workspace Status[/bold cyan]
• Current Directory: {os.getcwd()}
• Output Directory: ./output
• Reports Generated: {len(output_dirs)}
• Last Report: {max(output_dirs, key=lambda x: x.stat().st_mtime).name if output_dirs else 'None'}
        """

        self.console.print(Panel(content, title="📊 Workspace Status"))

    async def _run_module(self):
        """Run the currently selected module."""
        if not self.current_module:
            return

        module_name = self.current_module
        options = {k: v['value'] for k, v in self.module_options.items() if v['value'] is not None}

        with self.console.status(f"[bold green]Running {module_name} module..."):
            try:
                if module_name == 'audit':
                    await self._run_audit(options)
                elif module_name == 'fuzz':
                    await self._run_fuzz(options)
                elif module_name == 'pattern':
                    await self._run_pattern(options)
                elif module_name == 'slither':
                    await self._run_slither(options)
                elif module_name == 'mythril':
                    await self._run_mythril(options)

                self.console.print(f"[green]✓ {module_name} completed successfully[/green]")

            except Exception as e:
                self.console.print(f"[red]✗ Module execution failed: {e}[/red]")

    async def _run_audit(self, options):
        """Run comprehensive audit."""
        contract_path = options.get('CONTRACT')
        if not contract_path:
            raise ValueError("CONTRACT option is required")

        # Run the audit pipeline
        results = await self.flow_executor.execute_flow(
            flow_config=options.get('FLOW_CONFIG', 'configs/default_audit.yaml'),
            contract_files=[contract_path],
            output_dir=options.get('OUTPUT_DIR', './output'),
            verbose=options.get('VERBOSE', False)
        )

        # Generate report with contract name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        contract_name = self._extract_contract_name_from_results(results)
        report_path = Path(options.get('OUTPUT_DIR', './output')) / f"audit_{contract_name}_{timestamp}"
        report_path.mkdir(parents=True, exist_ok=True)

        report_data = self._transform_results_for_report(results)
        report_file = report_path / f"{contract_name}-comprehensive_report.md"
        self.report_generator.generate_comprehensive_report(report_data, str(report_file))

        self.console.print(f"[green]📄 Report generated: {report_file}[/green]")

    async def _run_fuzz(self, options):
        """Run fuzzing module."""
        # Placeholder for fuzzing implementation
        self.console.print("[yellow]Fuzzing module not yet implemented[/yellow]")

    async def _run_pattern(self, options):
        """Run pattern-based detection."""
        contract_path = options.get('CONTRACT')
        if not contract_path:
            raise ValueError("CONTRACT option is required")

        # Run pattern analysis
        from core.vulnerability_detector import VulnerabilityDetector
        detector = VulnerabilityDetector()

        vulnerabilities = detector.detect_vulnerabilities([contract_path])
        self.console.print(f"[green]Found {len(vulnerabilities)} vulnerabilities using pattern analysis[/green]")

        for vuln in vulnerabilities:
            self.console.print(f"  • {vuln['title']} ({vuln['severity']})")

    async def _run_slither(self, options):
        """Run Slither analysis."""
        contract_path = options.get('CONTRACT')
        if not contract_path:
            raise ValueError("CONTRACT option is required")

        # Check if Slither is available
        tools = self.tool_manager.detect_tools()
        if not tools.get('slither', {}).get('installed', False):
            if Confirm.ask("Slither not found. Install it?", default=True):
                self.tool_manager.install_tool('slither')
            else:
                raise ValueError("Slither is required for this module")

        # Run Slither
        import subprocess
        cmd = ['slither', contract_path, '--json', '-']

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                detectors = data.get('results', {}).get('detectors', [])
                self.console.print(f"[green]Slither found {len(detectors)} issues[/green]")
            except:
                self.console.print("[yellow]Could not parse Slither output[/yellow]")
        else:
            self.console.print(f"[red]Slither failed: {result.stderr}[/red]")

    async def _run_mythril(self, options):
        """Run Mythril analysis."""
        # Placeholder for Mythril implementation
        self.console.print("[yellow]Mythril module not yet implemented[/yellow]")

    async def _run_full_pipeline(self, target_contract=None):
        """Run the complete audit pipeline."""
        if target_contract:
            self.module_options = self.modules['audit']['options'].copy()
            self.module_options['CONTRACT']['value'] = target_contract

        await self._run_audit(self.module_options)

    async def _exploit_validation(self, contract_path):
        """Validate exploits and generate PoCs."""
        self.console.print("[bold cyan]🔍 Exploit Validation[/bold cyan]")

        # Get vulnerabilities from the current audit results
        # For now, we'll run a quick pattern analysis to get vulnerabilities
        from core.vulnerability_detector import VulnerabilityDetector

        with self.console.status("[bold green]Analyzing contract for vulnerabilities..."):
            detector = VulnerabilityDetector()
            vulnerabilities = detector.detect_vulnerabilities([contract_path])

        if not vulnerabilities:
            self.console.print("[yellow]No vulnerabilities found to validate[/yellow]")
            return

        self.console.print(f"[green]Found {len(vulnerabilities)} vulnerabilities to validate[/green]")

        # Validate each vulnerability
        with self.console.status("[bold green]Validating exploits..."):
            exploit_results = await self.exploit_validator.validate_vulnerabilities(contract_path, vulnerabilities)

        # Generate exploit report
        output_dir = self.module_options.get('OUTPUT_DIR', {}).get('value', './output')
        report_path = self.exploit_validator.generate_exploit_report(exploit_results, output_dir)

        self.console.print(f"[green]📄 Exploit validation report: {report_path}[/green]")

        # Show summary
        successful_exploits = len([r for r in exploit_results if r.exploit_successful])
        poc_generated = len([r for r in exploit_results if r.poc_code])

        self.console.print(f"\n[bold cyan]Exploit Validation Summary:[/bold cyan]")
        self.console.print(f"• Total Vulnerabilities: {len(exploit_results)}")
        self.console.print(f"• Successfully Exploited: {successful_exploits}")
        self.console.print(f"• PoCs Generated: {poc_generated}")

        # Show details for each result
        for result in exploit_results:
            status_icon = "✅" if result.exploit_successful else "❌"
            self.console.print(f"{status_icon} {result.vulnerability_id}: {result.vulnerability_type.title()} - {result.impact_assessment}")

    def _search_vulnerabilities(self, pattern):
        """Search for vulnerabilities by pattern."""
        # Placeholder for vulnerability search
        self.console.print(f"[cyan]Searching for: {pattern}[/cyan]")
        self.console.print("[yellow]Vulnerability search not yet implemented[/yellow]")

    def _extract_contract_name_from_results(self, results: Dict[str, Any]) -> str:
        """Extract contract name from results for better organization."""
        # Try to get contract name from various sources
        contract_name = "UnknownContract"

        # First try from reportnode data
        if 'reportnode' in results and isinstance(results['reportnode'], dict):
            reportnode_data = results['reportnode']
            vulnerabilities = reportnode_data.get('results', {}).get('vulnerabilities', [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    if hasattr(vuln, 'context') and vuln.context.get('contract_name'):
                        contract_name = vuln.context['contract_name']
                        break

        # Fallback: try from other vulnerability sources
        if contract_name == "UnknownContract":
            for key, value in results.items():
                if isinstance(value, dict) and 'vulnerabilities' in value:
                    for vuln in value['vulnerabilities']:
                        if hasattr(vuln, 'context') and vuln.context.get('contract_name'):
                            contract_name = vuln.context['contract_name']
                            break
                        elif isinstance(vuln, dict) and vuln.get('context', {}).get('contract_name'):
                            contract_name = vuln['context']['contract_name']
                            break
                    if contract_name != "UnknownContract":
                        break

        # Clean contract name for filename use
        if contract_name != "UnknownContract":
            # Remove file extension and clean for filesystem
            contract_name = contract_name.replace('.sol', '').replace(' ', '_').replace('-', '_')
            # Ensure it's a valid filename component
            contract_name = "".join(c for c in contract_name if c.isalnum() or c in ('_', '-'))

        return contract_name

    def _transform_results_for_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Transform flow execution results into expected report structure."""
        # Extract data from various sources in the results
        vulnerabilities = []
        high_severity_count = 0

        # Get vulnerabilities from different modules
        for module_name, module_data in results.items():
            if isinstance(module_data, dict) and 'vulnerabilities' in module_data:
                module_vulns = module_data['vulnerabilities']
                if isinstance(module_vulns, list):
                    vulnerabilities.extend(module_vulns)
                    # Count high severity
                    high_severity_count += len([
                        v for v in module_vulns
                        if v.get('severity', '').lower() in ['high', 'critical']
                    ])

        return {
            'audit_results': {
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'high_severity_count': high_severity_count
            },
            'execution_time': results.get('execution_time', 0)
        }


def main():
    """Main entry point for AetherAudit Console."""
    console = AetherConsole()

    try:
        console.cmdloop()
    except KeyboardInterrupt:
        console.console.print("\n[bold cyan]Goodbye![/bold cyan]")
    except Exception as e:
        console.console.print(f"[red]Fatal error: {e}[/red]")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
