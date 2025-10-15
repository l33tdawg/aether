#!/bin/bash

# DepositPool Vulnerability Testing Script
# This script sets up an Anvil fork and runs tests to validate vulnerabilities

echo "=== DepositPool Vulnerability Testing ==="

# Check if Anvil is running
if ! pgrep -x "anvil" > /dev/null; then
    echo "Starting Anvil fork..."
    anvil --fork-url $ETH_RPC_URL --port 8545 &
    ANVIL_PID=$!
    sleep 5
    echo "Anvil started with PID: $ANVIL_PID"
else
    echo "Anvil already running"
fi

# Set environment variables
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Anvil dev key
export ETH_RPC_URL="http://localhost:8545"

echo "Running DepositPool vulnerability tests..."

# Run the PoC script
echo "=== Running PoC Script ==="
forge script depositpool_poc.sol:DepositPoolPoC --fork-url $ETH_RPC_URL --broadcast

echo ""
echo "=== Running Foundry Tests ==="
forge test --fork-url $ETH_RPC_URL -vvv

echo ""
echo "=== Test Results Summary ==="
echo "Check the output above for vulnerability confirmations"
echo "❌ = Vulnerability confirmed"
echo "✅ = Function properly protected"

# Cleanup
if [ ! -z "$ANVIL_PID" ]; then
    echo "Stopping Anvil..."
    kill $ANVIL_PID
fi

echo "Testing complete!"
