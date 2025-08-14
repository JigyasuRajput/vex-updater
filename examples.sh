#!/bin/bash

# VEX Generate Tool - Comprehensive Example Script
# This script demonstrates all the features of the vex-generate-tool

echo "=== VEX Generate Tool - Comprehensive Examples ==="
echo ""

# Navigate to the tool directory
cd "$(dirname "$0")"

# Path to the virtual environment and tool
VENV_PATH=".venv/bin"
TOOL_PATH="$VENV_PATH/vex-generate-tool"

echo "1. Testing tool help and version information:"
echo "=============================================="
$TOOL_PATH --help
echo ""
$TOOL_PATH --version
echo ""

echo "2. Example 1: not_affected status with justification"
echo "===================================================="
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected \
  --justification vulnerable_code_not_present \
  --impact-statement "The vulnerable function is never called in our product." \
  --output example1_not_affected.json

echo "Generated: example1_not_affected.json"
echo ""

echo "3. Example 2: affected status"
echo "============================="
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status affected \
  --impact-statement "This vulnerability affects our application severely." \
  --output example2_affected.json

echo "Generated: example2_affected.json"
echo ""

echo "4. Example 3: fixed status"
echo "=========================="
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status fixed \
  --impact-statement "This vulnerability has been patched in our latest version." \
  --output example3_fixed.json

echo "Generated: example3_fixed.json"
echo ""

echo "5. Example 4: under_investigation status"
echo "========================================"
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status under_investigation \
  --impact-statement "We are currently investigating the impact of this vulnerability." \
  --output example4_under_investigation.json

echo "Generated: example4_under_investigation.json"
echo ""

echo "6. Example 5: Output to stdout (no file)"
echo "========================================"
echo "Output will be printed below:"
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected \
  --justification vulnerable_code_not_in_execute_path
echo ""

echo "7. Testing error cases:"
echo "======================"

echo "7a. Missing justification for not_affected:"
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected || echo "Error correctly caught"
echo ""

echo "7b. Non-existent vulnerability:"
$TOOL_PATH --cve-bin-json sample_input.json \
  --vuln-id CVE-9999-99999 \
  --status affected || echo "Error correctly caught"
echo ""

echo "7c. Non-existent input file:"
$TOOL_PATH --cve-bin-json non_existent.json \
  --vuln-id CVE-2021-44228 \
  --status affected || echo "Error correctly caught"
echo ""

echo "=== All examples completed! ==="
echo ""
echo "Generated files:"
ls -la example*.json 2>/dev/null || echo "No example files found"
