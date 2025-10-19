#!/usr/bin/env python3
"""
Find historical RocketPool auction lots for vulnerability testing.
This searches for past auctions so we can fork from those blocks and test exploits.
"""
import requests
import json
import os
from datetime import datetime
from rich.console import Console
from pathlib import Path

console = Console()

def get_etherscan_data(module, action, params, api_key):
    """Get data from Etherscan API."""
    url = "https://api.etherscan.io/api"

    all_params = {
        'module': module,
        'action': action,
        'apikey': api_key,
        **params
    }

    try:
        response = requests.get(url, params=all_params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get('status') == '1':
            return data.get('result', [])
        else:
            console.print(f"[yellow]API message: {data.get('message', 'Unknown')}[/yellow]")
            return []

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return []
    except json.JSONDecodeError as e:
        console.print(f"[red]JSON decode error: {e}[/red]")
        return []

def find_auction_transactions(api_key):
    """Find transactions related to RocketAuctionManager."""
    console.print("[cyan]🔍 Searching for RocketAuctionManager transactions...[/cyan]")

    auction_manager = "0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE"

    # Get normal transactions (createLot, claimBid, etc.)
    # Search from block 16000000 onwards
    params = {
        'address': auction_manager,
        'startblock': 16000000,
        'endblock': 99999999,
        'page': 1,
        'offset': 10000,
        'sort': 'desc'
    }

    console.print(f"[cyan]Querying Etherscan for {auction_manager}...[/cyan]")
    transactions = get_etherscan_data('account', 'txlist', params, api_key)

    if transactions:
        console.print(f"[green]✅ Found {len(transactions)} transactions[/green]")
    else:
        console.print("[yellow]⚠️  No transactions found[/yellow]")

    return transactions

def analyze_transactions_for_auctions(transactions):
    """Analyze transactions to find auction-related activity."""
    console.print("[cyan]📊 Analyzing transactions for auction patterns...[/cyan]")

    auction_lots = []

    # Function selectors for RocketAuctionManager
    create_lot_sigs = [
        "0x2c7d20d7",  # createLot()
    ]

    claim_bid_sigs = [
        "0x379607f5",  # claimBid(uint256)
    ]

    for tx in transactions:
        try:
            tx_hash = tx.get('hash', '')
            block_number = int(tx.get('blockNumber', '0'))
            from_addr = tx.get('from', '')
            input_data = tx.get('input', '')
            timestamp = int(tx.get('timeStamp', '0'))

            # Check for createLot calls
            if any(sig in input_data for sig in create_lot_sigs):
                ts = datetime.fromtimestamp(timestamp) if timestamp else "N/A"
                auction_lots.append({
                    'type': 'create_lot',
                    'block': block_number,
                    'tx_hash': tx_hash,
                    'from': from_addr,
                    'timestamp': str(ts)
                })
                console.print(f"[green]✅ Found createLot at block {block_number}[/green]")

            # Check for claimBid calls
            elif any(sig in input_data for sig in claim_bid_sigs):
                ts = datetime.fromtimestamp(timestamp) if timestamp else "N/A"
                auction_lots.append({
                    'type': 'claim_bid',
                    'block': block_number,
                    'tx_hash': tx_hash,
                    'from': from_addr,
                    'timestamp': str(ts)
                })
                console.print(f"[blue]📋 Found claimBid at block {block_number}[/blue]")
        except (ValueError, KeyError) as e:
            continue

    return auction_lots

def find_best_fork_blocks(auction_lots):
    """Find the best blocks to fork from for testing."""
    console.print("[cyan]🎯 Finding optimal blocks for forking...[/cyan]")

    if not auction_lots:
        console.print("[red]❌ No auction activity found[/red]")
        return []

    # Group by block and find blocks with most activity
    blocks_with_activity = {}
    for lot in auction_lots:
        block = lot['block']
        if block not in blocks_with_activity:
            blocks_with_activity[block] = []
        blocks_with_activity[block].append(lot)

    # Sort by block (most recent first) and activity count
    best_blocks = []
    for block, activities in sorted(blocks_with_activity.items(), reverse=True):
        best_blocks.append({
            'block': block,
            'activities': activities,
            'activity_count': len(activities)
        })

    console.print(f"[green]✅ Found {len(best_blocks)} blocks with auction activity[/green]")

    # Show top blocks
    for block_info in best_blocks[:10]:
        console.print(f"  📍 Block {block_info['block']}: {block_info['activity_count']} transactions")

    return best_blocks[:20]  # Return top 20 blocks

def main():
    """Main function to find historical auction data."""
    console.print("[bold cyan]🚀 Finding Historical RocketPool Auction Data[/bold cyan]")
    console.print("=" * 70)

    api_key = os.environ.get('ETHERSCAN_API_KEY')
    if not api_key:
        console.print("[red]❌ ETHERSCAN_API_KEY not found in environment[/red]")
        console.print("\n[cyan]📋 To get an API key:[/cyan]")
        console.print("1. Go to: https://etherscan.io/myapikey")
        console.print("2. Sign up or log in")
        console.print("3. Create a new API key")
        console.print("4. Set it: export ETHERSCAN_API_KEY='your_key_here'")
        console.print("\n[cyan]📚 Or manually find blocks:[/cyan]")
        console.print("Go to: https://etherscan.io/address/0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE#txs")
        console.print("Look for createLot() and claimBid() transactions")
        return

    # Find auction transactions
    transactions = find_auction_transactions(api_key)

    if not transactions:
        console.print("[red]❌ No transactions found[/red]")
        console.print("\n[yellow]This could mean:[/yellow]")
        console.print("1. API key is invalid or rate limited")
        console.print("2. No recent auction activity")
        console.print("3. Network issue")
        return

    console.print(f"[green]✅ Found {len(transactions)} transactions[/green]")

    # Analyze for auction patterns
    auction_lots = analyze_transactions_for_auctions(transactions)

    if not auction_lots:
        console.print("[red]❌ No auction function calls found[/red]")
        console.print("[yellow]This is unusual - check the transaction data manually[/yellow]")
        return

    console.print(f"[green]✅ Found {len(auction_lots)} auction-related transactions[/green]")

    # Find best blocks for forking
    best_blocks = find_best_fork_blocks(auction_lots)

    if not best_blocks:
        console.print("[red]❌ No blocks found[/red]")
        return

    # Save results
    results = {
        'best_blocks': best_blocks,
        'auction_lots': auction_lots,
        'search_timestamp': datetime.now().isoformat(),
        'note': 'Real historical auction data from Etherscan'
    }

    output_file = Path('/Users/l33tdawg/nodejs-projects/bugbounty/historical_auction_data.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[green]✅ Saved {len(best_blocks)} blocks to historical_auction_data.json[/green]")
    
    console.print("\n[bold cyan]📊 Top 5 Recommended Blocks:[/bold cyan]")
    for i, block_info in enumerate(best_blocks[:5], 1):
        console.print(f"{i}. Block {block_info['block']} ({block_info['activity_count']} transactions)")
    
    console.print("\n[bold cyan]🎯 Next Steps:[/bold cyan]")
    console.print("1. Start Anvil fork:")
    console.print(f"   anvil --fork-url https://eth.llamarpc.com --fork-block-number {best_blocks[0]['block']}")
    console.print("\n2. Run the test:")
    console.print("   python3 complete_historical_test.py")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
