#!/usr/bin/env python3
"""
AetherAudit + AetherFuzz: Agentic Smart Contract Auditing & Fuzzing Framework

Main entry point for the CLI interface.
"""

import warnings

# Suppress pkg_resources deprecation warning from slither
# This is a known issue in slither 0.10.0 that will be fixed in future versions
# See: https://github.com/crytic/slither/issues
warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources is deprecated.*")

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from cli.main import AetherCLI
from core.graceful_shutdown import get_shutdown_handler
from core.exploit_tester import ExploitTester


def check_basic_setup(skip_check: bool = False) -> bool:
    """Quick validation before running commands.
    
    Args:
        skip_check: If True, skip the pre-flight check
        
    Returns:
        True if setup looks good, False otherwise
    """
    if skip_check:
        return True
    
    import os
    import shutil
    
    issues = []
    warnings = []
    
    # Check for Foundry (required for many features)
    if not shutil.which('forge'):
        issues.append("Foundry not found in PATH")
        issues.append("  Install: curl -L https://foundry.paradigm.xyz | bash && foundryup")
        issues.append("  Then add to PATH: export PATH=\"$PATH:$HOME/.foundry/bin\"")
    
    # Check for LLM API keys (required for AI features)
    has_openai = bool(os.getenv('OPENAI_API_KEY'))
    has_gemini = bool(os.getenv('GEMINI_API_KEY'))
    
    # Also check config file if not in environment
    if not has_openai or not has_gemini:
        try:
            from core.config_manager import ConfigManager
            config_manager = ConfigManager()
            if not has_openai and getattr(config_manager.config, 'openai_api_key', ''):
                has_openai = True
                # Load it into environment for use by engines
                os.environ['OPENAI_API_KEY'] = config_manager.config.openai_api_key
            if not has_gemini and getattr(config_manager.config, 'gemini_api_key', ''):
                has_gemini = True
                # Load it into environment for use by engines
                os.environ['GEMINI_API_KEY'] = config_manager.config.gemini_api_key
        except Exception:
            pass
    
    if not has_openai and not has_gemini:
        warnings.append("No LLM API keys configured (OPENAI_API_KEY or GEMINI_API_KEY)")
        warnings.append("  LLM-powered analysis will be unavailable")
    
    # Check config directory
    config_dir = Path.home() / '.aether'
    if not config_dir.exists():
        warnings.append(f"Config directory not found: {config_dir}")
        warnings.append("  Run 'python setup.py' for guided setup")
    
    # Display issues if any
    if issues or warnings:
        print("⚠️  Setup Check:")
        
        if issues:
            print("\n❌ Issues detected:")
            for issue in issues:
                print(f"  {issue}")
        
        if warnings:
            print("\n⚠️  Warnings:")
            for warning in warnings:
                print(f"  {warning}")
        
        if issues:
            print("\n💡 Run 'python setup.py' for guided installation and configuration")
            print("   Or use '--skip-setup-check' to bypass this check\n")
            return False
        else:
            # Only warnings, continue
            print("\n💡 Tip: Run 'python setup.py' to configure all features\n")
            return True
    
    return True


def main():
    """Main entry point for Aether CLI."""
    # Set up graceful shutdown handler for Ctrl+C
    shutdown_handler = get_shutdown_handler()
    
    parser = argparse.ArgumentParser(
        description="AetherAudit + AetherFuzz: Agentic Smart Contract Auditing & Fuzzing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aether audit contracts/MyToken.sol --flow configs/audit.yaml
  aether fuzz contracts/MyToken.sol --max-runs 1000
  aether run contracts/MyToken.sol --end-to-end
        """
    )
    
    # Global options
    parser.add_argument(
        '--skip-setup-check',
        action='store_true',
        help='Skip the pre-flight dependency check'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Audit command
    audit_parser = subparsers.add_parser('audit', help='Run static analysis and AI audit')
    audit_parser.add_argument('contract', help='Path to smart contract file/directory or GitHub URL')
    audit_parser.add_argument('--flow', default='configs/default_audit.yaml', help='YAML flow configuration file')
    audit_parser.add_argument('--output', '-o', help='Output directory for reports')
    audit_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    audit_parser.add_argument('--enhanced', action='store_true', help='Use enhanced audit engine with improved accuracy')
    audit_parser.add_argument('--phase3', action='store_true', help='Enable Phase 3 AI features (AI ensemble, learning system, formal verification)')
    audit_parser.add_argument('--ai-ensemble', action='store_true', help='Use enhanced AI ensemble with specialized GPT-5-mini agents')
    audit_parser.add_argument('--foundry', action='store_true', help='Enable Foundry validation with PoC generation for bug bounty submissions')
    audit_parser.add_argument('--llm-validation', action='store_true', help='Enable LLM-based false positive filtering and Foundry test generation')
    audit_parser.add_argument('--enhanced-reports', action='store_true', help='Generate enhanced reports with dashboards, compliance, and multiple formats')
    audit_parser.add_argument('--per-contract-reports', action='store_true', help='Generate separate enhanced reports for each contract in scope-based directory structure')
    audit_parser.add_argument('--compliance-only', action='store_true', help='Generate only compliance reports (SOC2, PCI-DSS, GDPR, etc.)')
    audit_parser.add_argument('--export-formats', nargs='+', choices=['json', 'xml', 'excel', 'pdf'], default=['json'], help='Export formats for results (default: json)')
    # GitHub audit options (activated when argument is a GitHub URL)
    audit_parser.add_argument('--scope', help='Filter to specific contracts (comma-separated) [GitHub audit]')
    audit_parser.add_argument('--min-severity', help='Minimum severity to include [GitHub audit]')
    audit_parser.add_argument('--format', choices=['display', 'json', 'immunefi', 'csv'], default='display', help='Output format [GitHub audit]')
    audit_parser.add_argument('--fresh', action='store_true', help='Ignore cache and force fresh analysis [GitHub audit]')
    audit_parser.add_argument('--reanalyze', action='store_true', help='Re-run analysis even if cached [GitHub audit]')
    audit_parser.add_argument('--retry-failed', action='store_true', help='Only analyze contracts that failed last time [GitHub audit]')
    audit_parser.add_argument('--clear-cache', action='store_true', help='Remove cached project before analysis [GitHub audit]')
    audit_parser.add_argument('--skip-build', action='store_true', help='Use existing build artifacts [GitHub audit]')
    audit_parser.add_argument('--no-cache', action='store_true', help='Do not cache results [GitHub audit]')
    audit_parser.add_argument('--dry-run', action='store_true', help='Show what would be analyzed, do not analyze [GitHub audit]')
    audit_parser.add_argument('--github-token', help='GitHub token for private repositories [GitHub audit]')
    audit_parser.add_argument('--interactive-scope', action='store_true', default=True, help='Interactively select which contracts to audit (for bug bounty scoping) - enabled by default for GitHub audits [GitHub audit]')
    audit_parser.add_argument('--skip-scope-selector', action='store_true', help='Skip the interactive contract selector for GitHub audits [GitHub audit]')

    # Fuzz command
    fuzz_parser = subparsers.add_parser('fuzz', help='Run dynamic fuzzing and exploit validation')
    fuzz_parser.add_argument('contract', help='Path to smart contract file or directory')
    fuzz_parser.add_argument('--max-runs', type=int, default=1000, help='Maximum fuzzing runs')
    fuzz_parser.add_argument('--timeout', type=int, default=300, help='Fuzzing timeout in seconds')
    fuzz_parser.add_argument('--output', '-o', help='Output directory for fuzz results')
    fuzz_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Run command (full pipeline)
    run_parser = subparsers.add_parser('run', help='Run full audit + fuzz pipeline')
    run_parser.add_argument('contract', help='Path to smart contract file or directory')
    run_parser.add_argument('--end-to-end', action='store_true', help='Run complete audit-fix-fuzz cycle')
    run_parser.add_argument('--enhanced', action='store_true', help='Use enhanced audit engine with improved accuracy')
    run_parser.add_argument('--phase3', action='store_true', help='Enable Phase 3 AI features (AI ensemble, learning system, formal verification)')
    run_parser.add_argument('--ai-ensemble', action='store_true', help='Use enhanced AI ensemble with specialized GPT-5-mini agents')
    run_parser.add_argument('--enhanced-reports', action='store_true', help='Generate enhanced reports with dashboards, compliance, and multiple formats')
    run_parser.add_argument('--per-contract-reports', action='store_true', help='Generate separate enhanced reports for each contract in scope-based directory structure')
    run_parser.add_argument('--compliance-only', action='store_true', help='Generate only compliance reports (SOC2, PCI-DSS, GDPR, etc.)')
    run_parser.add_argument('--export-formats', nargs='+', choices=['json', 'xml', 'excel', 'pdf'], default=['json'], help='Export formats for results (default: json)')
    run_parser.add_argument('--flow', default='configs/full_pipeline.yaml', help='YAML flow configuration')
    run_parser.add_argument('--output', '-o', help='Output directory for complete report')
    run_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    run_parser.add_argument('--foundry', action='store_true', help='Enable Foundry validation with PoC generation for bug bounty submissions')

    # Foundry command (bug bounty validation)
    foundry_parser = subparsers.add_parser('foundry', help='Run Foundry validation with PoC generation for bug bounty submissions')
    # Fork verify command
    fork_parser = subparsers.add_parser('fork-verify', help='Run generated Foundry tests against an anvil fork')
    fork_parser.add_argument('output', help='Output directory containing vulnerability_* suites')
    fork_parser.add_argument('--rpc-url', required=True, help='RPC URL to fork (e.g., https://mainnet.infura.io/v3/KEY)')
    fork_parser.add_argument('--block', type=int, help='Optional fork block number')
    foundry_parser.add_argument('contract', help='Path to smart contract file or directory')
    foundry_parser.add_argument('--output', '-o', help='Output directory for Foundry tests and PoCs')
    foundry_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Generate Foundry PoCs post-report
    genf_parser = subparsers.add_parser('generate-foundry', help='Generate Foundry PoCs from results.json, report, or database')
    genf_parser.add_argument('--from-results', help='Path to structured results.json (preferred)')
    genf_parser.add_argument('--from-report', help='Path to audit_report.md (fallback parser)')
    genf_parser.add_argument('--out', help='Output directory for generated suites')
    genf_parser.add_argument('--project-id', type=int, help='Load findings from database by project ID')
    genf_parser.add_argument('--scope-id', type=int, help='Restrict to findings/contracts in specific audit scope ID')
    genf_parser.add_argument('--max-items', type=int, default=20, help='Max findings to generate tests for')
    genf_parser.add_argument('--min-severity', default='low', help='Min severity filter (low|medium|high|critical)')
    genf_parser.add_argument('--types', help='CSV of vulnerability types to include (match title/category)')
    genf_parser.add_argument('--only-consensus', action='store_true', help='Restrict to consensus findings only')
    genf_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Report command (generate reports from GitHub audit database)
    report_parser = subparsers.add_parser('report', help='Generate audit reports from GitHub audit database findings')
    report_parser.add_argument('--output', '-o', help='Output directory for reports (default: ./output/reports)')
    report_parser.add_argument('--format', choices=['markdown', 'json', 'html', 'all'], default='markdown', help='Report format (default: markdown)')
    report_parser.add_argument('--scope-id', type=int, help='Generate report for specific audit scope ID')
    report_parser.add_argument('--project-id', type=int, help='Generate report for specific project ID')
    report_parser.add_argument('--contract-id', type=int, help='Restrict report to a single contract ID within the project')
    report_parser.add_argument('--list-projects', action='store_true', help='List all projects in database')
    report_parser.add_argument('--list-scopes', type=int, metavar='PROJECT_ID', help='List all audit scopes for a project')
    report_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Exploit test command (test generated POC code against real contracts)
    exploit_test_parser = subparsers.add_parser('exploit-test', help='Test generated exploit code against real audited contracts')
    exploit_test_parser.add_argument('project_name', help='Name of the project to test exploits for')
    exploit_test_parser.add_argument('--fork-url', help='RPC URL for mainnet fork testing (default: local Anvil)')
    exploit_test_parser.add_argument('--anvil-port', type=int, default=8545, help='Port for Anvil local node (default: 8545)')
    exploit_test_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Console command (interactive CLI)
    console_parser = subparsers.add_parser('console', help='Launch interactive Metasploit-style console')
    console_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Config command
    config_parser = subparsers.add_parser('config', help='Manage configuration settings')
    config_parser.add_argument('--set-etherscan-key', help='Set Etherscan API key')
    config_parser.add_argument('--set-openai-key', help='Set OpenAI API key')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')
    config_parser.add_argument('--test-etherscan', action='store_true', help='Test Etherscan API connection')
    config_parser.add_argument('--list-networks', action='store_true', help='List supported EVM networks')
    config_parser.add_argument('--test-network', help='Test API connection for specific network')
    config_parser.add_argument('--clear-etherscan-cache', action='store_true', help='Clear Etherscan contract cache')
    config_parser.add_argument('--etherscan-cache-stats', action='store_true', help='Show Etherscan cache statistics')
    # Triage/consensus settings
    config_parser.add_argument('--triage-min-severity', help='Set triage minimum severity (low|medium|high|critical)')
    config_parser.add_argument('--triage-min-confidence', type=float, help='Set triage minimum confidence (0.0-1.0)')
    config_parser.add_argument('--triage-max-items', type=int, help='Set triage max items overall')
    config_parser.add_argument('--triage-max-per-type', type=int, help='Set triage max items per type')
    config_parser.add_argument('--llm-only-consensus', action='store_true', help='Restrict LLM validation to AI ensemble consensus findings')
    config_parser.add_argument('--no-llm-only-consensus', action='store_true', help='Disable consensus-only restriction for LLM')
    config_parser.add_argument('--llm-triage-min-severity', help='Set LLM triage minimum severity (low|medium|high|critical)')
    config_parser.add_argument('--llm-triage-min-confidence', type=float, help='Set LLM triage minimum confidence (0.0-1.0)')
    config_parser.add_argument('--llm-triage-max-items', type=int, help='Set LLM triage max items overall')
    config_parser.add_argument('--llm-triage-max-per-type', type=int, help='Set LLM triage max items per type')
    config_parser.add_argument('--foundry-only-consensus', action='store_true', help='Restrict Foundry collection to AI ensemble consensus findings')
    config_parser.add_argument('--no-foundry-only-consensus', action='store_true', help='Disable consensus-only restriction for Foundry')
    config_parser.add_argument('--foundry-max-items', type=int, help='Set Foundry max items to collect')

    # Fetch command (enhanced multi-chain integration)
    fetch_parser = subparsers.add_parser('fetch', help='Fetch contract source code from multiple blockchain networks')
    fetch_parser.add_argument('address', nargs='?', help='Contract address to fetch')
    fetch_parser.add_argument('--network', help='Network to fetch from (ethereum, polygon, arbitrum, optimism, bsc, base, polygon_zkevm, avalanche, fantom)')
    fetch_parser.add_argument('--output', '-o', help='Output directory for contract source')
    fetch_parser.add_argument('--validate-functions', help='CSV of expected function names to validate ABI against')
    fetch_parser.add_argument('--no-cache', action='store_true', help='Skip cache and force fresh fetch')
    fetch_parser.add_argument('--list-networks', action='store_true', help='List all supported networks')
    fetch_parser.add_argument('--test-network', metavar='NETWORK', help='Test connection to specific network')

    # Database command
    db_parser = subparsers.add_parser('db', help='Database management and queries')
    db_parser.add_argument('--stats', action='store_true', help='Show database statistics')
    db_parser.add_argument('--list-audits', type=int, nargs='?', const=20, metavar='LIMIT', help='List recent audits (default: 20)')
    db_parser.add_argument('--audit-details', metavar='AUDIT_ID', help='Show details for specific audit')
    db_parser.add_argument('--export', choices=['json'], default='json', help='Export database data (default: json)')
    db_parser.add_argument('--vacuum', action='store_true', help='Optimize database by rebuilding it')
    db_parser.add_argument('--delete-audit', metavar='AUDIT_ID', help='Delete specific audit and related data')

    # Version command
    subparsers.add_parser('version', help='Show version information')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1
    
    # Run pre-flight setup check (unless skipped or running certain commands)
    skip_check_commands = ['version', 'config']  # Commands that don't need full setup
    
    if args.command not in skip_check_commands:
        skip_check = getattr(args, 'skip_setup_check', False)
        
        if not check_basic_setup(skip_check=skip_check):
            return 1

    # Handle special cases that don't need full CLI initialization
    if args.command == 'fetch' and args.list_networks:
        # List networks without initializing full CLI
        from core.etherscan_fetcher import EtherscanFetcher
        from core.config_manager import ConfigManager

        config_manager = ConfigManager()
        fetcher = EtherscanFetcher(config_manager)

        all_networks = fetcher.get_all_supported_networks()
        print("📋 Supported Networks:")
        for network in all_networks:
            print(f"  • {network}")
        return 0

    # Initialize CLI
    cli = AetherCLI()

    try:
        if args.command == 'audit':
            # Parse Etherscan URL if provided
            contract_input = args.contract
            if isinstance(contract_input, str) and ('etherscan.io/' in contract_input.lower() or 
                                                     'polygonscan.com/' in contract_input.lower() or
                                                     'arbiscan.io/' in contract_input.lower() or
                                                     'bscscan.com/' in contract_input.lower() or
                                                     'basescan.org/' in contract_input.lower() or
                                                     'optimistic.etherscan.io/' in contract_input.lower() or
                                                     'snowtrace.io/' in contract_input.lower() or
                                                     'ftmscan.com/' in contract_input.lower()):
                network, address = cli.etherscan_fetcher.parse_explorer_url(contract_input)
                if network and address:
                    print(f"🔍 Detected {network} contract: {address}")
                    # Set the network in the fetcher
                    cli.etherscan_fetcher.set_network(network)
                    # Update contract_input to just the address
                    contract_input = address
                else:
                    print(f"❌ Failed to parse Etherscan URL: {contract_input}")
                    return 1
            
            # Route to GitHub auditor when a GitHub URL is provided
            if isinstance(contract_input, str) and ('github.com/' in contract_input or contract_input.startswith('http')):
                return cli.run_github_audit_command(
                    github_url=contract_input,
                    scope=args.scope,
                    min_severity=args.min_severity,
                    output=args.output,
                    fmt=args.format,
                    fresh=args.fresh,
                    reanalyze=args.reanalyze,
                    retry_failed=args.retry_failed,
                    clear_cache=args.clear_cache,
                    skip_build=args.skip_build,
                    no_cache=args.no_cache,
                    verbose=args.verbose,
                    dry_run=args.dry_run,
                    github_token=args.github_token,
                    interactive_scope=args.interactive_scope,
                    skip_scope_selector=args.skip_scope_selector
                )

            result = asyncio.run(cli.run_audit(
                contract_path=contract_input,
                flow_config=args.flow,
                output_dir=args.output,
                verbose=args.verbose,
                enhanced=args.enhanced,
                phase3=args.phase3,
                ai_ensemble=args.ai_ensemble,
                enhanced_reports=args.enhanced_reports,
                per_contract_reports=args.per_contract_reports,
                compliance_only=args.compliance_only,
                export_formats=args.export_formats,
                foundry=args.foundry,
                llm_validation=args.llm_validation,
                interactive_scope=args.interactive_scope
            ))
            # For CLI, return 0 for success, handle results internally
            if args.verbose and result:
                # Compute summary from returned structure (prefer reportnode.summary)
                total_vulnerabilities = 0
                high_severity = 0

                if isinstance(result, dict):
                    reportnode = result.get('reportnode')
                    if isinstance(reportnode, dict):
                        summary = reportnode.get('summary', {})
                        if isinstance(summary, dict) and summary:
                            total_vulnerabilities = int(summary.get('total_vulnerabilities', 0) or 0)
                            high_severity = int(summary.get('high_severity_count', 0) or 0)
                        else:
                            results_obj = reportnode.get('results', {}) if isinstance(reportnode.get('results'), dict) else {}
                            vulns = results_obj.get('vulnerabilities', []) if isinstance(results_obj, dict) else []
                            total_vulnerabilities = len(vulns)
                            high_severity = len([v for v in vulns if isinstance(v, dict) and v.get('severity', '').lower() in ['high', 'critical']])

                    # Fallback: aggregate vulnerabilities from any node outputs
                    if total_vulnerabilities == 0:
                        all_vulns = []
                        for value in result.values():
                            if isinstance(value, dict) and isinstance(value.get('vulnerabilities'), list):
                                all_vulns.extend(value['vulnerabilities'])
                        if all_vulns:
                            total_vulnerabilities = len(all_vulns)
                            high_severity = len([v for v in all_vulns if isinstance(v, dict) and v.get('severity', '').lower() in ['high', 'critical']])

                print(f"\n📋 Audit Results Summary:")
                print(f"   Total vulnerabilities: {total_vulnerabilities}")
                if high_severity > 0:
                    print(f"   ⚠️  High severity issues: {high_severity}")
                else:
                    print(f"   ✅ No critical issues found")
            return 0
        elif args.command == 'console':
            # Launch the Metasploit-style console
            from cli.console import main as console_main
            return console_main()
        elif args.command == 'interactive':
            # Launch the interactive console (alias for console)
            from cli.console import main as console_main
            return console_main()
        elif args.command == 'fuzz':
            result = asyncio.run(cli.run_fuzz(
                contract_path=args.contract,
                max_runs=args.max_runs,
                timeout=args.timeout,
                output_dir=args.output,
                verbose=args.verbose
            ))
            return 0
        elif args.command == 'run':
            result = asyncio.run(cli.run_full_pipeline(
                contract_path=args.contract,
                end_to_end=args.end_to_end,
                flow_config=args.flow,
                output_dir=args.output,
                verbose=args.verbose,
                enhanced=args.enhanced,
                phase3=args.phase3,
                ai_ensemble=args.ai_ensemble,
                enhanced_reports=args.enhanced_reports,
                per_contract_reports=args.per_contract_reports,
                compliance_only=args.compliance_only,
                export_formats=args.export_formats,
                foundry=args.foundry
            ))
            return 0
        elif args.command == 'foundry':
            result = asyncio.run(cli.run_foundry_validation(
                contract_path=args.contract,
                output_dir=args.output,
                verbose=args.verbose
            ))
            return 0
        elif args.command == 'generate-foundry':
            rc = asyncio.run(cli.run_generate_foundry(
                from_results=args.from_results,
                from_report=args.from_report,
                out_dir=args.out,
                max_items=args.max_items,
                min_severity=args.min_severity,
                types_filter=args.types,
                only_consensus=args.only_consensus,
                project_id=getattr(args, 'project_id', None),
                scope_id=getattr(args, 'scope_id', None),
                verbose=args.verbose
            ))
            return rc
        elif args.command == 'report':
            rc = asyncio.run(cli.run_generate_report(
                output_dir=args.output,
                format=args.format,
                scope_id=args.scope_id,
                project_id=args.project_id,
                contract_id=getattr(args, 'contract_id', None),
                list_projects=args.list_projects,
                list_scopes=args.list_scopes,
                verbose=args.verbose
            ))
            return rc
        elif args.command == 'exploit-test':
            rc = asyncio.run(cli.run_exploit_tests(
                project_name=args.project_name,
                fork_url=args.fork_url,
                anvil_port=args.anvil_port,
                verbose=args.verbose
            ))
            return rc
        elif args.command == 'config':
            if args.set_etherscan_key:
                cli.config_manager.set_etherscan_key(args.set_etherscan_key)
                return 0
            elif args.set_openai_key:
                cli.config_manager.set_openai_key(args.set_openai_key)
                return 0
            elif args.show:
                cli.config_manager.show_config()
                return 0
            elif args.test_etherscan:
                success = cli.etherscan_fetcher.test_api_connection()
                return 0 if success else 1
            elif args.list_networks:
                cli.etherscan_fetcher.list_supported_networks()
                return 0
            elif args.test_network:
                success = cli.etherscan_fetcher.test_api_connection(args.test_network)
                return 0 if success else 1
            elif args.clear_etherscan_cache:
                count = cli.etherscan_fetcher.clear_cache()
                print(f"Cleared {count} cached entries")
                return 0
            elif args.etherscan_cache_stats:
                stats = cli.etherscan_fetcher.get_cache_stats()
                print(f"Cache stats: {stats['total_cached_contracts']} contracts, {stats['total_cache_size_bytes']} bytes")
                print(f"Cache directory: {stats['cache_directory']}")
                return 0
            elif args.command == 'fetch':
                # Handle enhanced multi-chain fetch command

                # Address is required for all other operations
                if not args.address:
                    print("❌ Contract address is required for fetch operations")
                    return 1

                # Parse URL if provided
                address_input = args.address
                detected_network = args.network  # User-specified network takes precedence
                
                if '/' in address_input:  # Likely a URL
                    network, address = cli.etherscan_fetcher.parse_explorer_url(address_input)
                    if network and address:
                        print(f"🔍 Detected {network} contract: {address}")
                        if not detected_network:  # Only use detected network if not explicitly specified
                            detected_network = network
                        address_input = address
                    else:
                        print(f"❌ Failed to parse URL: {address_input}")
                        return 1
                
                address = address_input

                # Test network connection if requested
                if args.test_network:
                    network = args.test_network
                    if not cli.etherscan_fetcher.set_network(network):
                        return 1

                    # Import blockchain manager for testing
                    from core.blockchain_abstraction import BlockchainManager
                    blockchain_manager = BlockchainManager(cli.config_manager.config.etherscan_api_key)

                    if asyncio.run(blockchain_manager.test_connection(network)):
                        print(f"✅ Network connection test successful for {network}")
                        return 0
                    else:
                        print(f"❌ Network connection test failed for {network}")
                        return 1

                # Set network if specified or detected
                if detected_network:
                    if not cli.etherscan_fetcher.set_network(detected_network):
                        return 1

                # Parse expected functions if provided
                expected_functions = None
                if args.validate_functions:
                    expected_functions = [f.strip() for f in args.validate_functions.split(',')]

                # Fetch contract
                if args.no_cache:
                    # Clear cache for this address first
                    cli.etherscan_fetcher.clear_cache()

                contract_data = cli.etherscan_fetcher.fetch_contract_for_poc_generation(address, expected_functions)

                if not contract_data.get('success'):
                    print(f"❌ Failed to fetch contract: {contract_data.get('error')}")
                    return 1

                # Save to output directory if specified, otherwise use default (~/.aether/contracts)
                output_dir = args.output if args.output else None
                try:
                    file_path = cli.etherscan_fetcher.save_contract_source(contract_data, output_dir)
                    print(f"✅ Contract saved to: {file_path}")
                    print(f"🔗 Explorer URL: {contract_data.get('explorer_url', 'N/A')}")
                    return 0
                except Exception as e:
                    print(f"❌ Failed to save contract: {e}")
                    return 1
            elif args.command == 'db':
                # Handle database commands
                from core.database_manager import DatabaseManager

                db = DatabaseManager()

                if args.stats:
                    stats = db.get_audit_statistics()
                    print(f"📊 Database Statistics:")
                    print(f"  Total Audits: {stats.get('total_audits', 0)}")
                    print(f"  Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
                    print(f"  Learning Patterns: {stats.get('learning_patterns_count', 0)}")
                    print(f"  Average Execution Time: {stats.get('average_execution_time', 0):.2f}s")
                    print(f"  Recent Audits (30d): {stats.get('recent_audits_30d', 0)}")

                    # Show severity distribution
                    severity_dist = stats.get('vulnerabilities_by_severity', {})
                    if severity_dist:
                        print(f"  Severity Distribution: {severity_dist}")

                    # Show database info
                    db_info = db.get_database_info()
                    print(f"  Database Size: {db_info.get('database_size_bytes', 0)} bytes")
                    print(f"  SQLite Version: {db_info.get('sqlite_version', 'Unknown')}")

                elif args.list_audits:
                    audits = db.get_audit_results(limit=args.list_audits)
                    print(f"📋 Recent Audits ({len(audits)}):")
                    for audit in audits:
                        print(f"  {audit['id'][:8]}... | {audit['contract_name']} | {audit['network']} | "
                              f"{audit['total_vulnerabilities']} vulns | {audit['created_at']}")

                elif args.audit_details:
                    audit = db.get_audit_result(args.audit_details)
                    if audit:
                        print(f"📋 Audit Details ({args.audit_details[:8]}...):")
                        print(f"  Contract: {audit['contract_name']} ({audit['contract_address']})")
                        print(f"  Network: {audit['network']}")
                        print(f"  Type: {audit['audit_type']}")
                        print(f"  Vulnerabilities: {audit['total_vulnerabilities']}")
                        print(f"  Execution Time: {audit['execution_time']:.2f}s")
                        print(f"  Status: {audit['status']}")
                        print(f"  Created: {audit['created_at']}")

                        # Show findings
                        findings = db.get_vulnerability_findings(audit['id'])
                        if findings:
                            print(f"  Findings ({len(findings)}):")
                            for finding in findings[:5]:  # Show first 5
                                print(f"    - {finding['vulnerability_type']} ({finding['severity']})")
                            if len(findings) > 5:
                                print(f"    ... and {len(findings) - 5} more")
                    else:
                        print(f"❌ Audit not found: {args.audit_details}")

                elif args.export:
                    data = db.export_data(args.export)
                    if data:
                        output_file = f"aetheraudit_export_{int(time.time())}.json"
                        with open(output_file, 'w') as f:
                            f.write(data)
                        print(f"✅ Database exported to: {output_file}")
                    else:
                        print("❌ Export failed")

                elif args.vacuum:
                    if db.vacuum_database():
                        print("✅ Database optimized successfully")
                    else:
                        print("❌ Database optimization failed")

                elif args.delete_audit:
                    if db.delete_audit_result(args.delete_audit):
                        print(f"✅ Audit {args.delete_audit[:8]}... deleted")
                    else:
                        print(f"❌ Failed to delete audit: {args.delete_audit}")

                else:
                    print("Database commands: --stats, --list-audits, --audit-details, --export, --vacuum, --delete-audit")

                return 0
            else:
                # Apply triage/consensus settings if provided
                cfg = cli.config_manager.config
                updated = False
                if args.triage_min_severity:
                    cfg.triage_min_severity = args.triage_min_severity
                    updated = True
                if args.triage_min_confidence is not None:
                    cfg.triage_min_confidence = args.triage_min_confidence
                    updated = True
                if args.triage_max_items is not None:
                    cfg.triage_max_items = args.triage_max_items
                    updated = True
                if args.triage_max_per_type is not None:
                    cfg.triage_max_per_type = args.triage_max_per_type
                    updated = True
                if args.llm_only_consensus:
                    cfg.llm_only_consensus = True
                    updated = True
                if args.no_llm_only_consensus:
                    cfg.llm_only_consensus = False
                    updated = True
                if args.llm_triage_min_severity:
                    cfg.llm_triage_min_severity = args.llm_triage_min_severity
                    updated = True
                if args.llm_triage_min_confidence is not None:
                    cfg.llm_triage_min_confidence = args.llm_triage_min_confidence
                    updated = True
                if args.llm_triage_max_items is not None:
                    cfg.llm_triage_max_items = args.llm_triage_max_items
                    updated = True
                if args.llm_triage_max_per_type is not None:
                    cfg.llm_triage_max_per_type = args.llm_triage_max_per_type
                    updated = True
                if args.foundry_only_consensus:
                    cfg.foundry_only_consensus = True
                    updated = True
                if args.no_foundry_only_consensus:
                    cfg.foundry_only_consensus = False
                    updated = True
                if args.foundry_max_items is not None:
                    cfg.foundry_max_items = args.foundry_max_items
                    updated = True

                if updated:
                    cli.config_manager.save_config()
                    print("✅ Configuration updated")
                    return 0

                config_parser.print_help()
                return 1
        elif args.command == 'version':
            cli.show_version()
            return 0
        elif args.command == 'fork-verify':
            from core.fork_verifier import run_fork_verification
            results = run_fork_verification(args.output, args.rpc_url, args.block)
            ok = results.get('aggregate', {}).get('total_failed', 0) == 0
            print(json.dumps(results, indent=2))
            return 0 if ok else 1

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
