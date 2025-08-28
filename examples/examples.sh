#!/bin/bash

# VEX Updater Tool - Comprehensive Example Script
# This script demonstrates all the features of the new vex-updater tool

echo "=== VEX Updater Tool - Comprehensive Examples ==="
echo ""

# Navigate to the tool directory
cd "$(dirname "$0")"

# Path to the virtual environment and tool
VENV_PATH=".venv/bin"
TOOL_PATH="$VENV_PATH/vex-updater"

echo "🚀 VEX Updater Workflow Demonstrations"
echo "======================================="
echo ""

echo "1. Testing tool help and version information:"
echo "=============================================="
$TOOL_PATH --help
echo ""
$TOOL_PATH --version
echo ""

echo "🎯 PRIMARY WORKFLOW: VEX UPDATING FROM SCAN REPORTS"
echo "=================================================="
echo ""

echo "2. Example 1: Basic VEX Update (Dry Run First)"
echo "============================================="
echo "Step 1: Preview what would change (safe preview)"
$TOOL_PATH --scan-report data/samples/sample_input.json --vex-file data/samples/existing_vex_sample.json --dry-run
echo ""
echo "Step 2: Show detailed differences"
$TOOL_PATH --scan-report data/samples/sample_input.json --vex-file data/samples/existing_vex_sample.json --diff-only
echo ""

echo "3. Example 2: Safe VEX Update with Backup"
echo "========================================="
echo "Update VEX document with backup and output to new file"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --output-file example_updated_with_backup.json \
  --backup
echo "Generated: example_updated_with_backup.json (with backup created)"
echo ""

echo "4. Example 3: Component-Granular Multi-CVE Scenario"
echo "================================================="
echo "Demonstrating how same CVE can have different statuses per component"
echo "(This would normally be interactive, but we'll show the concept)"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --auto-skip-existing \
  --output-file example_multi_component.json
echo "Generated: example_multi_component.json"
echo ""

echo "5. Example 4: Validation and Error Checking"
echo "=========================================="
echo "Validate inputs without making changes"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --validate-only
echo ""

echo "🔧 LEGACY MODE: Backward Compatibility Examples"
echo "=============================================="
echo ""

echo "6. Legacy Example 1: Single Vulnerability Update"
echo "=============================================="
$TOOL_PATH --input-vex data/samples/existing_vex_sample.json \
  --vuln-id CVE-2021-44228 \
  --status fixed \
  --impact-statement "Updated via legacy mode - patched in version 2.15.0." \
  --output example_legacy_fixed.json

echo "Generated: example_legacy_fixed.json"
echo ""

echo "7. Legacy Example 2: not_affected status with justification"
echo "========================================================"
$TOOL_PATH --cve-bin-json data/samples/sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected \
  --justification vulnerable_code_not_present \
  --impact-statement "The vulnerable function is never called in our product." \
  --output example_legacy_not_affected.json

echo "Generated: example_legacy_not_affected.json"
echo ""

echo "8. Legacy Example 3: Output to stdout (no file)"
echo "=============================================="
echo "Output will be printed below:"
$TOOL_PATH --cve-bin-json data/samples/sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status under_investigation \
  --impact-statement "Legacy mode stdout example"
echo ""

echo "🧪 ADVANCED FEATURES: Error Handling and Safety"
echo "============================================="
echo ""

echo "9. Example 5: Built-in Help and Explanations"
echo "==========================================="
echo "Show VEX status explanations:"
$TOOL_PATH --explain status
echo ""
echo "Show justification explanations:"
$TOOL_PATH --explain justification
echo ""

echo "10. Example 6: Error Handling Demonstrations"
echo "=========================================="

echo "10a. Missing required arguments (new workflow):"
$TOOL_PATH --scan-report data/samples/sample_input.json || echo "✅ Error correctly caught - missing --vex-file"
echo ""

echo "10b. Missing justification for not_affected (legacy):"
$TOOL_PATH --cve-bin-json data/samples/sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected || echo "✅ Error correctly caught"
echo ""

echo "10c. Non-existent input file:"
$TOOL_PATH --scan-report non_existent.json \
  --vex-file also_non_existent.json || echo "✅ Error correctly caught"
echo ""

echo "🎉 COMPREHENSIVE WORKFLOW EXAMPLE"
echo "================================"
echo ""

echo "11. Complete End-to-End Workflow"
echo "==============================="
echo "This demonstrates the recommended production workflow:"
echo ""
echo "Step 1: Validate inputs"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --validate-only
echo ""

echo "Step 2: Preview changes (dry run)"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --dry-run
echo ""

echo "Step 3: Apply updates with safety measures"
$TOOL_PATH --scan-report data/samples/sample_input.json \
  --vex-file data/samples/existing_vex_sample.json \
  --output-file production_ready_vex.json \
  --backup \
  --auto-skip-existing
echo ""

echo "✅ Production-ready VEX document created: production_ready_vex.json"
echo ""

echo "=== VEX Updater Examples Completed! ==="
echo ""
echo "📋 Summary of Generated Files:"
echo "=============================="
echo "Primary Workflow Examples:"
ls -la example_updated_with_backup.json example_multi_component.json production_ready_vex.json 2>/dev/null || echo "Files will be generated when examples run successfully"
echo ""
echo "Legacy Mode Examples:"
ls -la example_legacy_*.json 2>/dev/null || echo "Legacy files will be generated when examples run successfully"
echo ""
echo "🚀 Next Steps:"
echo "- Try interactive mode: vex-updater --scan-report your_scan.json --vex-file your_vex.json"
echo "- Explore built-in help: vex-updater --explain workflow"
echo "- Check the comprehensive README.md for advanced usage patterns"
