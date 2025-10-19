#!/usr/bin/env python3
"""
RocketPool Historical Vulnerability Test
Fork mainnet at a specific block and test against real state

USAGE:
------
1. In Terminal 1, start Anvil fork:
   anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/xtYAM1LOYlQryoaMfPNjl --fork-block-number 13325237

2. In Terminal 2, run this script:
   python3 complete_historical_test.py
   
   Or with a specific block:
   python3 complete_historical_test.py 1

BLOCKS AVAILABLE:
-----------------
Block 1 (13325237): Post-deployment block (right after contract creation)
Block 2 (13500000): Early post-deployment activity
Block 3 (14000000): 1M+ blocks after deployment
Block 4 (15000000): Historical auction activity
Block 5 (16000000): More historical activity

WHAT THIS DOES:
---------------
1. Waits for Anvil fork to be ready
2. Checks how many auction lots exist at that block
3. Optionally runs forge tests against the fork
4. Provides commands for manual testing

EXAMPLE:
--------
Terminal 1:
  $ anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/xtYAM1LOYlQryoaMfPNjl --fork-block-number 13325237

Terminal 2:
  $ python3 complete_historical_test.py 1
  $ cast call 0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE 'getLotCount()' --rpc-url http://localhost:8545

ETHERSCAN API:
--------------
Contract: 0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE
Deployment block: 13325236
Deployment tx: 0xceba25c953b1a7770fc79f4e35f945523109824cc42ec24000d05c522d7cfd12

Found with: export ETHERSCAN_API_KEY='HENA4UQ37GFJ8A5D4ANX9WW6JQ51Q2GTUF'
"""
import subprocess
import json
import time
import sys
from pathlib import Path
from rich.console import Console

console = Console()

BLOCKS_TO_TEST = {
    "1": {"block": 13325237, "desc": "Post-deployment block (right after contract creation)"},
    "2": {"block": 13500000, "desc": "Early post-deployment activity"},
    "3": {"block": 14000000, "desc": "1M+ blocks after deployment"},
    "4": {"block": 15000000, "desc": "Historical auction activity"},
    "5": {"block": 16000000, "desc": "More historical activity"},
}

def run_cmd(cmd):
    """Run shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.returncode, result.stderr.strip()

def start_anvil(block):
    """Display anvil startup instructions."""
    console.print(f"\n[bold cyan]🚀 Starting Anvil Fork at Block {block}[/bold cyan]")
    
    cmd = f"anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/xtYAM1LOYlQryoaMfPNjl --fork-block-number {block} --host 0.0.0.0"
    
    console.print("\n[yellow]📋 Run this command in another terminal:[/yellow]")
    console.print(f"[bold green]{cmd}[/bold green]")
    console.print()
    
    # Copy to clipboard
    try:
        subprocess.run(f'echo "{cmd}" | pbcopy', shell=True)
        console.print("[green]✅ Command copied to clipboard![/green]")
    except:
        pass
    
    console.print("[yellow]Press Enter once Anvil is running...[/yellow]")
    input()

def wait_anvil():
    """Wait for Anvil to be ready."""
    console.print("\n[cyan]⏳ Waiting for Anvil...[/cyan]")
    
    for attempt in range(30):
        stdout, code, _ = run_cmd("cast block-number --rpc-url http://localhost:8545 2>/dev/null")
        if code == 0 and stdout.isdigit():
            console.print(f"[green]✅ Anvil ready! Block: {stdout}[/green]")
            return True
        
        if attempt % 5 == 0 and attempt > 0:
            console.print(f"[yellow]Waiting... ({attempt}/30)[/yellow]")
        time.sleep(1)
    
    console.print("[red]❌ Anvil timeout[/red]")
    return False

def check_auction():
    """Check if RocketAuctionManager has any lots."""
    console.print("\n[cyan]🔍 Checking auction state...[/cyan]")
    
    AUCTION = "0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE"
    cmd = f"cast call {AUCTION} 'getLotCount()' --rpc-url http://localhost:8545 2>/dev/null"
    stdout, code, _ = run_cmd(cmd)
    
    if code == 0 and stdout:
        try:
            count = int(stdout, 16) if stdout.startswith('0x') else int(stdout)
            console.print(f"[green]✅ Lot count: {count}[/green]")
            return count
        except:
            pass
    
    console.print("[yellow]⚠️  Could not get lot count[/yellow]")
    return 0

def run_forge_tests():
    """Run forge tests."""
    console.print("\n[cyan]⚔️  Running forge tests...[/cyan]")
    
    test_env = "/Users/l33tdawg/nodejs-projects/bugbounty/output/rocketpool_full_test_env"
    if not Path(test_env).exists():
        console.print(f"[yellow]⚠️  Test env not found at {test_env}[/yellow]")
        return False
    
    cmd = f"cd {test_env} && forge test --rpc-url http://localhost:8545 -vvv 2>&1 | head -100"
    stdout, code, _ = run_cmd(cmd)
    
    if stdout:
        console.print(stdout)
    
    return code == 0

def main():
    """Main workflow."""
    console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]")
    console.print("[bold cyan]RocketPool Vulnerability - Historical Testing[/bold cyan]")
    console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
    
    if len(sys.argv) > 1 and sys.argv[1] in BLOCKS_TO_TEST:
        choice = sys.argv[1]
    else:
        console.print("[cyan]📋 Available blocks to test:[/cyan]\n")
        for key, info in BLOCKS_TO_TEST.items():
            console.print(f"  {key}. Block {info['block']} - {info['desc']}")
        console.print()
        
        choice = input("Choose block [1-5]: ").strip()
    
    if choice not in BLOCKS_TO_TEST:
        console.print("[red]❌ Invalid choice[/red]")
        sys.exit(1)
    
    block_info = BLOCKS_TO_TEST[choice]
    block = block_info["block"]
    
    console.print(f"\n[bold green]📍 Using: Block {block}[/bold green]")
    console.print(f"   {block_info['desc']}")
    
    # Start Anvil
    start_anvil(block)
    
    # Wait for Anvil
    if not wait_anvil():
        return
    
    # Check auction state
    lot_count = check_auction()
    
    if lot_count > 0:
        console.print(f"[bold green]🎉 Found {lot_count} auction lots![/bold green]")
    else:
        console.print("[yellow]No auctions at this block (expected for early blocks)[/yellow]")
    
    # Ask about tests
    console.print()
    run_tests = input("Run forge tests? [y/n]: ").strip().lower() == 'y'
    
    if run_tests:
        run_forge_tests()
    
    # Summary
    console.print("\n[bold cyan]📊 Test Summary[/bold cyan]")
    console.print(f"✅ Block: {block}")
    console.print(f"✅ Auction lots: {lot_count}")
    console.print(f"✅ Anvil: http://localhost:8545")
    console.print()
    console.print("[cyan]Available commands:[/cyan]")
    console.print("  cast call 0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE 'getLotCount()' --rpc-url http://localhost:8545")
    console.print("  forge test --rpc-url http://localhost:8545 -vvv")
    console.print()
    console.print("[green]Your fork is ready! Test your exploit now.[/green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        sys.exit(0)
