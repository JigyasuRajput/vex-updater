#!/bin/bash

# Alternative installation script for VEX Updater Tool
# This script installs the package directly without virtual environment activation

set -e

echo "🚀 VEX Updater Tool - Direct Installation"
echo "=========================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not found."
    echo "Please install Python 3.8 or higher and try again."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
MIN_VERSION="3.8"

if [ "$(printf '%s\n' "$MIN_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
    echo "❌ Error: Python $PYTHON_VERSION found, but Python $MIN_VERSION or higher is required."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION found"

# Upgrade pip
echo "⬆️  Upgrading pip..."
python3 -m pip install --upgrade pip

# Determine what to install based on arguments
if [ "$1" = "dev" ]; then
    echo "🛠️  Installing development dependencies..."
    python3 -m pip install -r requirements-dev.txt
else
    echo "📋 Installing runtime dependencies..."
    python3 -m pip install -r requirements.txt
fi

# Install the package
echo "🔧 Installing VEX Updater Tool..."
python3 -m pip install -e .

echo ""
echo "✅ Installation complete!"
echo ""
echo "To use the tool:"
echo "vex-updater --help"
echo ""

if [ "$1" = "dev" ]; then
    echo "Development setup complete! You can also:"
    echo "• Run tests: python3 -m pytest"
    echo "• Run examples: ./examples.sh"
    echo ""
fi

echo "🎯 Quick test:"
if command -v vex-updater &> /dev/null; then
    vex-updater --version
else
    echo "⚠️  Tool not found in PATH. Try: python3 -m vex_updater_tool.main --version"
fi

echo ""
echo "🚀 Ready to update VEX documents!"
