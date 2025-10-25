#!/bin/bash
# Helper script to set up Node.js 22 for Aether
# This ensures Hardhat projects can compile correctly during Slither analysis

echo "🔧 Aether Node.js Setup"
echo "======================"
echo ""

# Check if NVM is installed
if [ ! -d "$HOME/.nvm" ]; then
    echo "❌ NVM not found at ~/.nvm"
    echo "💡 Install NVM from: https://github.com/nvm-sh/nvm"
    echo "   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
    exit 1
fi

# Source NVM
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Check current Node version
CURRENT_NODE=$(node --version 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "📌 Current Node.js version: $CURRENT_NODE"
else
    echo "⚠️  No Node.js version currently active"
fi

# Install Node 22 if not installed
echo ""
echo "📦 Checking for Node.js 22..."
if ! nvm ls 22 >/dev/null 2>&1; then
    echo "📥 Installing Node.js 22 (latest LTS)..."
    nvm install 22
else
    echo "✅ Node.js 22 is already installed"
fi

# Use Node 22
echo ""
echo "🔄 Switching to Node.js 22..."
nvm use 22

# Verify
NEW_NODE=$(node --version)
echo ""
echo "✅ Setup complete!"
echo "   Node.js version: $NEW_NODE"
echo "   npm version: $(npm --version)"
echo ""
echo "💡 To make this permanent, run:"
echo "   nvm alias default 22"
echo ""
echo "💡 To use this in your current shell, run:"
echo "   source ~/.nvm/nvm.sh && nvm use 22"

