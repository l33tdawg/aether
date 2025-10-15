#!/usr/bin/env python3
"""
Foundry PoC Generation CLI

Main entry point for the Foundry PoC generation system with feedback-in-the-loop.
Provides command-line interface for generating comprehensive PoC suites from audit findings.

Usage:
    python scripts/generate_foundry_pocs.py --results results.json --contract contract.sol --output output/
"""

import argparse
import asyncio
import sys
import os
from pathlib import Path

# Add core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))

try:
    from foundry_poc_generator import FoundryPoCGenerator, GenerationManifest
except ImportError:
    from core.foundry_poc_generator import FoundryPoCGenerator, GenerationManifest


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate Foundry PoCs from audit findings with feedback-in-the-loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with results.json and contract source
  python scripts/generate_foundry_pocs.py --results results.json --contract contract.sol --output output/

  # With fork verification
  python scripts/generate_foundry_pocs.py --results results.json --contract contract.sol --output output/ --rpc-url https://mainnet.infura.io/v3/YOUR_KEY

  # Filter findings by type and severity
  python scripts/generate_foundry_pocs.py --results results.json --contract contract.sol --output output/ --types "Access Control" "Oracle Manipulation" --min-severity high

  # Limit number of findings
  python scripts/generate_foundry_pocs.py --results results.json --contract contract.sol --output output/ --max-items 5
        """
    )

    # Required arguments
    parser.add_argument(
        '--results',
        required=True,
        help='Path to results.json file containing audit findings'
    )

    parser.add_argument(
        '--contract',
        required=True,
        help='Path to the Solidity contract source file'
    )

    parser.add_argument(
        '--output',
        required=True,
        help='Output directory for generated PoC suites'
    )

    # Finding filters
    parser.add_argument(
        '--types',
        nargs='+',
        help='Only process findings of these vulnerability types'
    )

    parser.add_argument(
        '--min-severity',
        choices=['low', 'medium', 'high', 'critical'],
        default='low',
        help='Minimum severity level to process (default: low)'
    )

    parser.add_argument(
        '--max-items',
        type=int,
        help='Maximum number of findings to process'
    )

    parser.add_argument(
        '--only-consensus',
        action='store_true',
        help='Only process findings with consensus from multiple models'
    )

    # Generation options
    parser.add_argument(
        '--max-compile-attempts',
        type=int,
        default=3,
        help='Maximum compilation attempts per test (default: 3)'
    )

    parser.add_argument(
        '--max-runtime-attempts',
        type=int,
        default=1,
        help='Maximum runtime repair attempts (default: 1)'
    )

    # Fork verification
    parser.add_argument(
        '--rpc-url',
        help='RPC URL for fork verification (e.g., Infura, Alchemy)'
    )

    parser.add_argument(
        '--fork-block',
        type=int,
        help='Block number to fork from (default: latest)'
    )

    # Logging and output
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be generated without actually doing it'
    )

    parser.add_argument(
        '--template-only',
        action='store_true',
        help='Bypass LLM and generate tests from templates only (faster, offline)'
    )

    return parser.parse_args()


def setup_logging(verbose: bool):
    """Setup logging configuration."""
    import logging

    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('foundry_poc_generation.log')
        ]
    )


def validate_inputs(args) -> bool:
    """Validate input arguments."""
    errors = []

    # Check if files exist
    if not os.path.exists(args.results):
        errors.append(f"Results file not found: {args.results}")

    if not os.path.exists(args.contract):
        errors.append(f"Contract file not found: {args.contract}")

    # Check if output directory is writable
    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Test write permission
        test_file = output_dir / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
    except Exception as e:
        errors.append(f"Cannot write to output directory: {e}")

    # Validate RPC URL format if provided
    if args.rpc_url:
        if not (args.rpc_url.startswith('http') or args.rpc_url.startswith('ws')):
            errors.append("RPC URL should start with http:// or https:// or ws://")

    if errors:
        print("Validation errors:")
        for error in errors:
            print(f"  - {error}")
        return False

    return True


async def main():
    """Main CLI entry point."""
    args = parse_arguments()

    # Setup logging
    setup_logging(args.verbose)

    # Validate inputs
    if not validate_inputs(args):
        sys.exit(1)

    print("🔧 Foundry PoC Generation: Feedback-in-the-Loop System")
    print("=" * 60)

    if args.dry_run:
        print("DRY RUN MODE - No files will be generated")
        print()

    # Display configuration
    print("Configuration:")
    print(f"  Results file: {args.results}")
    print(f"  Contract file: {args.contract}")
    print(f"  Output directory: {args.output}")
    print(f"  Max compile attempts: {args.max_compile_attempts}")
    print(f"  Max runtime attempts: {args.max_runtime_attempts}")

    if args.rpc_url:
        print(f"  RPC URL: {args.rpc_url}")
        if args.fork_block:
            print(f"  Fork block: {args.fork_block}")

    if args.types:
        print(f"  Vulnerability types: {', '.join(args.types)}")

    print(f"  Min severity: {args.min_severity}")

    if args.max_items:
        print(f"  Max findings: {args.max_items}")

    if args.only_consensus:
        print("  Only consensus findings: Yes")

    print()

    # Check if we're in dry run mode
    if args.dry_run:
        print("Dry run complete - configuration looks good!")
        return

    try:
        # Create generator with configuration
        config = {
            'max_compile_attempts': args.max_compile_attempts,
            'max_runtime_attempts': args.max_runtime_attempts,
            'enable_fork_run': args.rpc_url is not None,
            'fork_url': args.rpc_url,
            'fork_block': args.fork_block,
            'types': args.types or [],
            'min_severity': args.min_severity,
            'max_items': args.max_items,
            'only_consensus': args.only_consensus,
            'template_only': args.template_only
        }

        generator = FoundryPoCGenerator(config)

        # Generate PoC suite
        print("🚀 Starting PoC generation...")
        manifest = await generator.generate_comprehensive_poc_suite(
            args.results,
            args.contract,
            args.output
        )

        # Display results
        print()
        print("📊 Generation Results:")
        print("=" * 60)
        print(f"Generation ID: {manifest.generation_id}")
        print(f"Timestamp: {manifest.timestamp}")
        print(f"Total findings: {manifest.total_findings}")
        print(f"Processed findings: {manifest.processed_findings}")
        print(".1f")
        print(f"Average attempts per test: {manifest.average_attempts_per_test:.1f}")

        if args.rpc_url:
            print(".1f")

        if manifest.error_taxonomy:
            print()
            print("Error Taxonomy:")
            for category, count in manifest.error_taxonomy.items():
                print(f"  {category}: {count}")

        print()
        print("✅ PoC generation completed!")

        # Exit with appropriate code
        if manifest.successful_compilations == manifest.processed_findings:
            print("🎉 All tests compiled successfully!")
            sys.exit(0)
        elif manifest.successful_compilations > 0:
            print("⚠️  Some tests compiled successfully, others failed")
            sys.exit(0)
        else:
            print("❌ No tests compiled successfully")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n⚠️  Generation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Generation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
