#!/usr/bin/env python3
"""
Manual historical testing approach for RocketPool vulnerability.
Uses known block numbers or allows manual specification.
"""
import subprocess
import json
from pathlib import Path
from rich.console import Console

console = Console()

def run_command(cmd, check=True):
    """Run a shell command."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Command failed: {cmd}[/red]")
        console.print(f"[red]Error: {e.stderr}[/red]")
        return None

def test_with_historical_block(block_number):
    """Test exploit against a specific historical block."""
    console.print(f"[cyan]🔍 Testing against historical block {block_number}...[/cyan]")

    # Contract addresses
    auction_manager = "0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE"
    exploit_contract = "0x0000000000000000000000000000000000000000"  # Will be deployed

    # Step 1: Start anvil fork at historical block
    console.print("[cyan]1️⃣ Starting Anvil fork...[/cyan]")
    anvil_cmd = f"anvil --fork-url https://eth.llamarpc.com --fork-block-number {block_number}"
    console.print(f"[green]✅ Fork command: {anvil_cmd}[/green]")

    # Step 2: Check auction state at this block
    console.print("[cyan]2️⃣ Checking auction state...[/cyan]")

    # Check lot count
    lot_count_cmd = f"cast call {auction_manager} 'getLotCount()' --rpc-url http://localhost:8545"
    lot_count = run_command(lot_count_cmd)

    if lot_count:
        lot_count_int = int(lot_count, 16)
        console.print(f"[green]✅ Lot count: {lot_count_int}[/green]")

        if lot_count_int == 0:
            console.print("[yellow]⚠️  No lots found at this block[/yellow]")
            console.print("Try a different block number with auction activity")
            return False
    else:
        console.print("[red]❌ Failed to check lot count[/red]")
        return False

    # Step 3: Deploy exploit contract
    console.print("[cyan]3️⃣ Deploying exploit contract...[/cyan]")

    # For now, we'll use a placeholder - in real testing you'd deploy your exploit
    console.print("[yellow]📝 Deploy exploit contract here[/yellow]")
    console.print("Use: cast send --rpc-url http://localhost:8545 ...")

    return True

def main():
    """Main function for manual historical testing."""
    console.print("[bold cyan]🚀 Manual Historical RocketPool Testing[/bold cyan]")
    console.print("=" * 60)

    # Known blocks with potential auction activity (you can find these manually)
    # These are example blocks - you'll need to find real ones
    test_blocks = [
        18650000,  # Example block - replace with real auction blocks
        18645000,
        18640000,
    ]

    console.print("[cyan]📋 Test Strategy:[/cyan]")
    console.print("1. Try known blocks with auction activity")
    console.print("2. Check for active auction lots")
    console.print("3. Test exploit against real historical state")
    console.print("4. Prove vulnerability with real data")

    for block in test_blocks:
        console.print(f"\\n[cyan]Testing block {block}...[/cyan]")
        success = test_with_historical_block(block)

        if success:
            console.print(f"[green]✅ Block {block} looks promising![/green]")
            break
        else:
            console.print(f"[yellow]⚠️  Block {block} not suitable[/yellow]")

    console.print("\\n[bold cyan]🎯 Next Steps:[/bold cyan]")
    console.print("1. Find real block numbers with auction activity")
    console.print("2. Use: https://etherscan.io/address/0x1a2f00d187c9388fda3bf2dc46a6b4740849ecce")
    console.print("3. Look for createLot() and claimBid() transactions")
    console.print("4. Use those block numbers for anvil --fork-block-number")

if __name__ == "__main__":
    main()
