#!/bin/bash

# VEX Generate Tool - Quick Setup Script
# This script helps users quickly set up the VEX Generate Tool

set -e

echo "🚀 VEX Generate Tool - Quick Setup"
echo "=================================="
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

# Create virtual environment
echo "📦 Creating virtual environment..."
if [ -d ".venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing and recreating..."
    rm -rf .venv
fi

python3 -m venv .venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Determine what to install based on arguments
if [ "$1" = "dev" ]; then
    echo "🛠️  Installing development dependencies..."
    pip install -r requirements-dev.txt
else
    echo "📋 Installing runtime dependencies..."
    pip install -r requirements.txt
fi

# Install the package
echo "🔧 Installing VEX Generate Tool..."
pip install -e .

echo ""
echo "✅ Setup complete!"
echo ""
echo "To use the tool:"
echo "1. Activate the virtual environment: source .venv/bin/activate"
echo "2. Run the tool: vex-generate-tool --help"
echo ""

if [ "$1" = "dev" ]; then
    echo "Development setup complete! You can also:"
    echo "• Run tests: pytest"
    echo "• Run examples: ./examples.sh"
    echo "• Check code quality: black vex_generate_tool/ tests/"
    echo ""
fi

echo "🎯 Quick test:"
.venv/bin/vex-generate-tool --version

echo ""
echo "🚀 Ready to generate VEX documents!"
