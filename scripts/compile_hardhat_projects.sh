#!/bin/bash
# Helper script to pre-compile Hardhat/Truffle projects before running Slither analysis
# This avoids permission issues with Hardhat cache writes during subprocess calls

set -e

PROJECT_DIR="$1"

if [ -z "$PROJECT_DIR" ]; then
    echo "Usage: $0 <project_directory>"
    exit 1
fi

if [ ! -d "$PROJECT_DIR" ]; then
    echo "Error: Directory $PROJECT_DIR does not exist"
    exit 1
fi

cd "$PROJECT_DIR"

# Check if it's a Hardhat project
if [ -f "hardhat.config.js" ] || [ -f "hardhat.config.ts" ]; then
    echo "📦 Detected Hardhat project"
    
    # Use NVM if .nvmrc exists
    if [ -f ".nvmrc" ]; then
        if [ -s "$HOME/.nvm/nvm.sh" ]; then
            source "$HOME/.nvm/nvm.sh"
            nvm use
        fi
    fi
    
    # Compile
    echo "🔨 Compiling Hardhat project..."
    npx hardhat compile
    echo "✅ Hardhat compilation complete"
    
# Check if it's a Truffle project
elif [ -f "truffle-config.js" ]; then
    echo "📦 Detected Truffle project"
    
    # Use NVM if .nvmrc exists
    if [ -f ".nvmrc" ]; then
        if [ -s "$HOME/.nvm/nvm.sh" ]; then
            source "$HOME/.nvm/nvm.sh"
            nvm use
        fi
    fi
    
    # Compile
    echo "🔨 Compiling Truffle project..."
    npx truffle compile
    echo "✅ Truffle compilation complete"
else
    echo "⚠️  Not a Hardhat or Truffle project"
    exit 1
fi

