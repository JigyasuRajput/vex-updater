# VEX Updater Tool - User Guides

## 📚 Table of Contents

1. [Getting Started with VEX Updating](#getting-started-with-vex-updating)
2. [Understanding Component-Granular Triage](#understanding-component-granular-triage)
3. [Multi-format VEX Support](#multi-format-vex-support)
4. [Scan Format Support](#scan-format-support)
5. [Debug and Logging](#debug-and-logging)
6. [Integration with CI/CD Pipelines](#integration-with-cicd-pipelines)
7. [Batch Vulnerability Triage Best Practices](#batch-vulnerability-triage-best-practices)
8. [Advanced Workflows](#advanced-workflows)
9. [Troubleshooting Common Issues](#troubleshooting-common-issues)

---

## 🚀 Getting Started with VEX Updating

### Your First VEX Update

**Step 1: Prerequisites**
```bash
# Ensure you have a recent security scan (supports both JSON and JSON2 formats)
cve-bin-tool . --format json -o my_scan.json
# or
cve-bin-tool . --format json2 -o my_scan.json

# Verify the scan contains vulnerabilities
cat my_scan.json | jq '.vulnerabilities | length'
# or for JSON2 format
cat my_scan.json | jq '.results | length'
```

**Understanding the Workflow:**

![VEX Updater Workflow](../images/vex_updater.png)

*The VEX Updater compares your scan results with existing VEX documents to identify what needs attention.*

**Step 2: Initial VEX Setup**
```bash
# Option A: Start with existing VEX file
ls project_security.vex

# Option B: Create minimal VEX structure
echo '{"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1, "vulnerabilities": []}' > new_project.vex
```

**Step 3: Your First Update**
```bash
# Safe first update with preview
vex-updater --scan-report my_scan.json --vex-file project_security.vex --dry-run

# If happy with preview, apply updates
vex-updater --scan-report my_scan.json --vex-file project_security.vex --backup
```

### Understanding the Interactive Triage

When you run the updater, you'll see prompts like this:

```
🔍 VEX Updater - Interactive Triage Session
============================================
📋 Format: CYCLONEDX
📊 Total component-vulnerability pairs to triage: 3

Progress: 1/3
----------------------------------------
🔍 CVE: CVE-2021-44228
📦 Component: log4j-core v2.14.1
🔗 PURL: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
⚠️  Severity: CRITICAL
📝 Description: Remote code execution in Apache Log4j2...
🎯 This CVE affects the specific component: log4j-core

Action: [t]riage, [s]kip, [q]uit: t

📋 VEX Status Options (CYCLONEDX):
  1. not_affected
  2. affected  
  3. fixed
  4. under_investigation

Select status (1-4): 2
✅ Selected: affected

📝 Impact Statement (optional):
   Provide additional context about the vulnerability's impact on this component.
   Press Enter to skip.
Impact statement: This component directly uses the vulnerable logging functionality
✅ Impact statement recorded: This component directly uses the vulnerable loggi...
```

### Best Practices for New Users

**DO:**
- ✅ Always start with `--dry-run` to preview changes
- ✅ Use `--backup` for production VEX files
- ✅ Read component information carefully during triage
- ✅ Provide meaningful impact statements
- ✅ Use `--diff-only` to understand what changed since last scan

**DON'T:**
- ❌ Skip reading component details during triage
- ❌ Use generic impact statements for all vulnerabilities
- ❌ Run without backups on production VEX files
- ❌ Ignore the component PURL information

---

## 🎯 Understanding Component-Granular Triage

### Why Component Granularity Matters

**Traditional approach (CVE-level):**
```
CVE-2021-44228: affected
```
Problem: This doesn't tell you *which* components are affected or *how*.

**VEX Updater approach (Component-CVE level):**

![Component-Granular CVE Analysis](../images/cve-component.png)

*The same CVE can have different impacts and statuses across multiple components in your software stack.*

### Real-World Example

Consider a microservices architecture with log4j vulnerability:

```bash
# Your scan finds CVE-2021-44228 in multiple components:
vex-updater --scan-report microservices_scan.json --vex-file services.vex --diff-only

# Output shows:
# 🆕 NEW VULNERABILITIES:
#   • CVE-2021-44228 in user-service/log4j-core@2.14.1
#   • CVE-2021-44228 in payment-service/log4j-api@2.14.1  
#   • CVE-2021-44228 in auth-service/elasticsearch@7.15.0
```

During interactive triage, you would handle each differently:

1. **user-service/log4j-core@2.14.1**
   - Status: `affected`
   - Justification: N/A
   - Impact: "Service directly uses log4j for application logging. Critical runtime impact."

2. **payment-service/log4j-api@2.14.1**
   - Status: `not_affected`
   - Justification: `vulnerable_code_not_in_execute_path`
   - Impact: "Service only uses log4j API interfaces, not implementation."

3. **auth-service/elasticsearch@7.15.0**
   - Status: `fixed`
   - Justification: N/A
   - Impact: "Elasticsearch 7.15.0 includes patched log4j version."

### Component Identification

The VEX Updater uses **PURL (Package URL)** to uniquely identify components:

```
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
│   │     │                          │        └─ Version
│   │     │                          └─ Artifact name  
│   │     └─ Group/namespace
│   └─ Package type
└─ Scheme
```

This ensures that `log4j-core@2.14.1` in one service is treated separately from `log4j-core@2.14.1` in another service, allowing for different triage decisions.

---

## 🏗️ Multi-format VEX Support

### Supported Formats

#### CycloneDX (Recommended)
```bash
# Most common format with excellent tooling ecosystem
vex-updater --scan-report scan.json --vex-file project.cyclonedx.json --format cyclonedx

# Pros: Rich metadata, wide tool support, SBOM integration
# Best for: Most projects, especially those already using SBOM tools
```

#### CSAF (Enterprise)
```bash
# Common in enterprise and government environments
vex-updater --scan-report scan.json --vex-file advisory.csaf.json --format csaf

# Pros: Security advisory format, compliance-friendly, structured metadata
# Best for: Enterprise environments, regulatory compliance scenarios
```

#### OpenVEX (Cloud-Native)
```bash
# Lightweight format optimized for cloud-native environments
vex-updater --scan-report scan.json --vex-file cloud-native.openvex.json --format openvex

# Pros: Minimal overhead, container-focused, simple structure
# Best for: Cloud-native applications, container environments
```

### Format Detection

The tool automatically detects VEX format:

```bash
# Auto-detect format from existing file
vex-updater --scan-report scan.json --vex-file unknown_format.vex

# Override auto-detection if needed
vex-updater --scan-report scan.json --vex-file file.json --format cyclonedx
```

### Format-Specific Features

**CycloneDX Features:**
- SBOM integration
- Rich component metadata
- License information
- Dependency relationships

**CSAF Features:**
- Security advisory structure
- Product identification
- Remediation tracking
- Compliance metadata

**OpenVEX Features:**
- Minimal resource usage
- Container-optimized
- Cloud-native focused
- Simple JSON structure

---

## 📊 Scan Format Support

### Supported Scan Formats

The VEX Updater Tool automatically detects and supports multiple output formats from cve-bin-tool:

#### Standard JSON Format
```json
{
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "vulnerabilities": [
        {
          "vuln_id": "CVE-2021-44228",
          "description": "Remote code execution in log4j."
        }
      ]
    }
  ]
}
```

#### JSON2 Format (Newer cve-bin-tool versions)
```json
{
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tool": "cve-bin-tool",
    "version": "2.0.0"
  },
  "results": [
    {
      "cve_id": "CVE-2021-44228",
      "package": {
        "name": "log4j-core",
        "version": "2.14.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
      },
      "description": "Remote code execution in log4j.",
      "severity": "HIGH",
      "cvss_score": 9.8
    }
  ]
}
```

### Automatic Format Detection

The tool automatically detects the scan format and converts it to the internal components format:

```bash
# Works with both formats automatically
cve-bin-tool . --format json -o scan.json
cve-bin-tool . --format json2 -o scan.json
vex-updater --scan-report scan.json --vex-file project.vex
```

### Format Validation

If you encounter format issues, you can validate your scan file:

```bash
# Check scan file structure
cat scan.json | jq 'keys'

# For JSON format
cat scan.json | jq '.components | length'

# For JSON2 format  
cat scan.json | jq '.results | length'
```

---

## 🔍 Debug and Logging

### Debug Levels

The VEX Updater Tool provides comprehensive logging with five debug levels:

```bash
# Debug level - most verbose
vex-updater --scan-report scan.json --vex-file project.vex --debug debug

# Info level - general flow information
vex-updater --scan-report scan.json --vex-file project.vex --debug info

# Warning level - default, shows warnings and errors
vex-updater --scan-report scan.json --vex-file project.vex --debug warning

# Error level - only errors
vex-updater --scan-report scan.json --vex-file project.vex --debug error

# Critical level - only critical errors
vex-updater --scan-report scan.json --vex-file project.vex --debug critical
```

### What Each Level Shows

**Debug Level (`--debug debug`):**
- Detailed parsing information
- Component processing steps
- Format detection details
- Internal conversion steps
- File I/O operations

**Info Level (`--debug info`):**
- Format detection results
- Component counts
- Vulnerability processing
- Conversion summaries
- Operation progress

**Warning Level (default):**
- Format warnings
- Missing data alerts
- Validation issues
- Performance warnings

**Error Level (`--debug error`):**
- File not found errors
- Format parsing errors
- Validation failures
- Processing errors

### Debug Output Example

```bash
$ vex-updater --scan-report scan.json --vex-file project.vex --debug debug

2024-01-01 10:00:00 - vex_updater_tool.main - INFO - Starting VEX Updater Tool
2024-01-01 10:00:00 - vex_updater_tool.main - DEBUG - Command line arguments: Namespace(...)
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - DEBUG - Loading cve-bin-tool data from: scan.json
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - DEBUG - Successfully loaded JSON data with keys: ['metadata', 'results']
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - INFO - Detected format: json2
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - DEBUG - Processing 2 results from JSON2 format
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - DEBUG - Created new component entry: log4j-core:2.14.1
2024-01-01 10:00:00 - vex_updater_tool.scan_parser - INFO - JSON2 conversion complete: 2 components created
```

### Using Debug for Troubleshooting

**Diagnose Format Issues:**
```bash
# Check what format was detected
vex-updater --scan-report scan.json --vex-file project.vex --debug debug | grep "Detected format"

# See conversion details
vex-updater --scan-report scan.json --vex-file project.vex --debug debug | grep "conversion"
```

**Troubleshoot Processing Issues:**
```bash
# See component processing details
vex-updater --scan-report scan.json --vex-file project.vex --debug debug | grep "component"

# Check for validation errors
vex-updater --scan-report scan.json --vex-file project.vex --debug error
```

**Performance Analysis:**
```bash
# Monitor processing steps
vex-updater --scan-report large_scan.json --vex-file project.vex --debug info | grep "Processing"
```

---

## 🔄 Integration with CI/CD Pipelines

### GitHub Actions Integration

**Basic Workflow:**
```yaml
name: Update VEX Document
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  update-vex:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Install Dependencies
        run: |
          pip install cve-bin-tool vex-updater-tool
          
      - name: Run Security Scan
        run: |
          cve-bin-tool . --format json -o scan_results.json
          
      - name: Update VEX Document
        run: |
          vex-updater --scan-report scan_results.json \
            --vex-file security/project.vex \
            --auto-skip-existing \
            --backup \
            --debug warning
            
      - name: Commit Changes
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add security/
          if git diff --staged --quiet; then
            echo "No changes to commit"
          else
            git commit -m "docs: update VEX document with latest scan results"
            git push
          fi
```

**Advanced Workflow with Pull Requests:**
```yaml
name: VEX Update with Review
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday
    
jobs:
  update-vex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Tools
        run: pip install cve-bin-tool vex-updater-tool
        
      - name: Scan and Preview
        run: |
          cve-bin-tool . --format json -o scan_results.json
          vex-updater --scan-report scan_results.json \
            --vex-file security/project.vex \
            --dry-run \
            --debug info > vex_preview.txt
            
      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v5
        with:
          title: "Weekly VEX Update - $(date '+%Y-%m-%d')"
          body-path: vex_preview.txt
          branch: update-vex
          commit-message: "docs: weekly VEX update"
```

### Jenkins Pipeline Integration

**Declarative Pipeline:**
```groovy
pipeline {
    agent any
    
    triggers {
        cron('H 2 * * *')
    }
    
    environment {
        SCAN_FILE = 'scan_results.json'
        VEX_FILE = 'security/project.vex'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'cve-bin-tool . --format json -o ${SCAN_FILE}'
            }
        }
        
        stage('VEX Update Preview') {
            steps {
                script {
                                    def preview = sh(
                    script: 'vex-updater --scan-report ${SCAN_FILE} --vex-file ${VEX_FILE} --dry-run --debug info',
                    returnStdout: true
                ).trim()
                    
                    echo "VEX Update Preview:\n${preview}"
                    
                    // Parse preview for significant changes
                    if (preview.contains('New vulnerabilities to add: 0')) {
                        echo "No new vulnerabilities found. Skipping update."
                        currentBuild.result = 'NOT_BUILT'
                        return
                    }
                }
            }
        }
        
        stage('Apply VEX Updates') {
            when {
                not { equals(currentBuild.result, 'NOT_BUILT') }
            }
            steps {
                sh '''
                    vex-updater --scan-report ${SCAN_FILE} \
                      --vex-file ${VEX_FILE} \
                      --auto-skip-existing \
                      --backup \
                      --debug warning
                '''
            }
        }
        
        stage('Validate Results') {
            steps {
                sh 'vex-updater --vex-file ${VEX_FILE} --validate-only --debug info'
            }
        }
    }
    
    post {
        success {
            archiveArtifacts artifacts: 'security/*.vex*, scan_results.json'
        }
        failure {
            emailext (
                subject: "VEX Update Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "VEX update pipeline failed. Check the build logs for details.",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

### GitLab CI Integration

```yaml
stages:
  - scan
  - update-vex
  - validate

variables:
  SCAN_FILE: "scan_results.json"
  VEX_FILE: "security/project.vex"

security-scan:
  stage: scan
  image: python:3.11
  before_script:
    - pip install cve-bin-tool
  script:
    - cve-bin-tool . --format json -o $SCAN_FILE
  artifacts:
    paths:
      - $SCAN_FILE
    expire_in: 1 day

vex-update:
  stage: update-vex
  image: python:3.11
  before_script:
    - pip install vex-updater-tool
  script:
    - vex-updater --scan-report $SCAN_FILE --vex-file $VEX_FILE --dry-run --debug info
    - vex-updater --scan-report $SCAN_FILE --vex-file $VEX_FILE --auto-skip-existing --backup --debug warning
  artifacts:
    paths:
      - security/
    expire_in: 30 days
  only:
    - schedules
    - main

vex-validate:
  stage: validate
  image: python:3.11
  before_script:
    - pip install vex-updater-tool
  script:
    - vex-updater --vex-file $VEX_FILE --validate-only --debug info
```

---

## ✅ Batch Vulnerability Triage Best Practices

### Triage Decision Framework

**1. Information Gathering**
```bash
# Before making triage decisions, gather context:
vex-updater --scan-report scan.json --vex-file project.vex --diff-only

# Understand the scope:
# • How many new vulnerabilities?
# • Which components are affected?
# • What are the severity levels?
```

**2. Risk Assessment Matrix**

| Severity | Component Type | Default Status | Justification |
|----------|----------------|----------------|---------------|
| **Critical** | Runtime dependency | `affected` | Immediate attention needed |
| **Critical** | Dev/test only | `not_affected` | `vulnerable_code_not_in_execute_path` |
| **High** | Direct usage | `affected` | Security review required |
| **High** | Transitive dep | `under_investigation` | Need deeper analysis |
| **Medium/Low** | Any | `under_investigation` | Standard triage process |

**3. Component Context Analysis**

```bash
# For each component, ask:
# 1. Is this used at runtime or just build/test time?
# 2. Does our code directly invoke the vulnerable functionality?
# 3. Are there any mitigating controls in place?
# 4. What's the blast radius if exploited?
```

### Automated Triage Strategies

**Strategy 1: Conservative Approach**
```bash
# Mark everything as under_investigation initially
vex-updater --scan-report scan.json \
  --vex-file project.vex \
  --auto-skip-existing
  
# Then manually review and update critical items
```

**Strategy 2: Risk-Based Automation**
```bash
# Use custom scripts to pre-classify based on component patterns
python classify_components.py scan.json > triage_decisions.json
vex-updater --scan-report scan.json --vex-file project.vex --batch-file triage_decisions.json
```

**Strategy 3: Hybrid Approach**
```bash
# Interactive for high-severity, auto for low-severity
vex-updater --scan-report scan.json \
  --vex-file project.vex \
  --interactive-threshold HIGH
```

### Regular Triage Workflow

**Daily Routine (Critical Systems):**
```bash
# 1. Morning security scan
cve-bin-tool . --format json -o daily_scan.json

# 2. Quick diff check
vex-updater --scan-report daily_scan.json --vex-file production.vex --diff-only

# 3. Update if needed
if [ $? -eq 0 ]; then
  vex-updater --scan-report daily_scan.json --vex-file production.vex --backup
fi
```

**Weekly Deep Dive:**
```bash
# 1. Comprehensive scan with dependency analysis
cve-bin-tool . --format json --dependency-analysis -o weekly_scan.json

# 2. Review all under_investigation items
vex-updater --vex-file production.vex --show-status under_investigation

# 3. Interactive triage session for updates
vex-updater --scan-report weekly_scan.json --vex-file production.vex --interactive
```

**Monthly Review:**
```bash
# 1. Generate VEX analytics report
vex-updater --vex-file production.vex --analytics-report monthly_report.html

# 2. Review stale entries
vex-updater --vex-file production.vex --show-stale --older-than-days 30

# 3. Clean up fixed items if vulnerabilities no longer appear in scans
vex-updater --scan-report current_scan.json --vex-file production.vex --cleanup-stale
```

---

## 🔧 Advanced Workflows

### Multi-Environment VEX Management

**Development Environment:**
```bash
# More permissive, faster iterations
vex-updater --scan-report dev_scan.json \
  --vex-file environments/dev.vex \
  --auto-skip-existing \
  --default-status under_investigation
```

**Staging Environment:**
```bash
# Balanced approach with validation
vex-updater --scan-report staging_scan.json \
  --vex-file environments/staging.vex \
  --interactive \
  --backup
```

**Production Environment:**
```bash
# Most conservative, thorough review
vex-updater --scan-report prod_scan.json \
  --vex-file environments/production.vex \
  --dry-run \
  --backup \
  --require-impact-statements
```

### Cross-Project VEX Management

**Shared Component Library:**
```bash
# Create master VEX for shared components
vex-updater --scan-report shared_lib_scan.json \
  --vex-file shared/components.vex \
  --component-filter "pkg:npm/our-shared-*"

# Import decisions into project VEX files
vex-updater --import-from shared/components.vex \
  --vex-file project1/security.vex \
  --component-match "pkg:npm/our-shared-*"
```

**Microservices Architecture:**
```bash
# Generate service-specific VEX files
for service in user-service payment-service auth-service; do
  vex-updater --scan-report scans/${service}_scan.json \
    --vex-file vex/${service}.vex \
    --service-context $service
done

# Aggregate for organization-wide view
vex-updater --aggregate vex/*.vex \
  --output organization_security.vex
```

### Integration with External Tools

**SIEM Integration:**
```bash
# Export VEX data for SIEM consumption
vex-updater --vex-file production.vex \
  --export-format siem \
  --output security_events.json

# Push to Splunk/ELK
curl -X POST "https://siem.company.com/api/events" \
  -H "Content-Type: application/json" \
  -d @security_events.json
```

**Vulnerability Management Platform:**
```bash
# Sync with Qualys/Rapid7/etc.
vex-updater --vex-file production.vex \
  --sync-with qualys \
  --api-key $QUALYS_API_KEY \
  --sync-direction bidirectional
```

---

## 🚨 Troubleshooting Common Issues

### Issue 1: "No vulnerabilities found in scan"

**Symptoms:**
```
📋 DRY RUN RESULTS:
=================================
🆕 New vulnerabilities to add: 0
✅ Vulnerabilities up to date: 0
```

**Diagnosis:**
```bash
# Check scan file structure
cat scan_results.json | jq '.vulnerabilities | length'
cat scan_results.json | jq '.results | length'  
cat scan_results.json | jq 'keys'

# Use debug mode to see format detection
vex-updater --scan-report scan_results.json --vex-file project.vex --debug debug | grep "Detected format"
```

**Solutions:**
```bash
# Verify scan file format
file scan_results.json
head -20 scan_results.json

# Re-run scan with correct format
cve-bin-tool . --format json -o corrected_scan.json
# or
cve-bin-tool . --format json2 -o corrected_scan.json

# Check for alternate data structures
vex-updater --scan-report scan_results.json --debug debug
```

### Issue 2: "Component PURL parsing errors"

**Symptoms:**
```
❌ Failed to parse component: pkg:invalid/format
🔍 Skipping malformed component identifier
```

**Diagnosis:**
```bash
# Check component identifiers in scan
cat scan_results.json | jq '.vulnerabilities[].component.purl'

# Validate PURL format
python -c "
import json
with open('scan_results.json') as f:
    data = json.load(f)
    for vuln in data.get('vulnerabilities', []):
        purl = vuln.get('component', {}).get('purl', '')
        if purl and not purl.startswith('pkg:'):
            print(f'Invalid PURL: {purl}')
"
```

**Solutions:**
```bash
# Use component name mapping
vex-updater --scan-report scan_results.json \
  --vex-file project.vex \
  --purl-mapping purl_mappings.json

# Fix scan tool configuration
cve-bin-tool . --format json --include-purl -o fixed_scan.json
```

### Issue 3: "Scan format not recognized"

**Symptoms:**
```
❌ Error: Input JSON format not recognized. Expected cve-bin-tool JSON or JSON2 output.
```

**Diagnosis:**
```bash
# Check scan file structure
cat scan_results.json | jq 'keys'

# Use debug mode to see what was detected
vex-updater --scan-report scan_results.json --vex-file project.vex --debug debug

# Check for expected fields
cat scan_results.json | jq '.components | length' 2>/dev/null || echo "No components field"
cat scan_results.json | jq '.results | length' 2>/dev/null || echo "No results field"
cat scan_results.json | jq '.vulnerabilities | length' 2>/dev/null || echo "No vulnerabilities field"
```

**Solutions:**
```bash
# Ensure scan was run with correct format
cve-bin-tool . --format json -o scan_results.json
# or
cve-bin-tool . --format json2 -o scan_results.json

# Check if scan file is corrupted
cat scan_results.json | jq '.' > /dev/null && echo "Valid JSON" || echo "Invalid JSON"

# Try with debug mode for more details
vex-updater --scan-report scan_results.json --vex-file project.vex --debug debug
```

### Issue 4: "VEX format detection failed"

**Symptoms:**
```
❌ Error: Unable to detect VEX format from file: unknown.vex
💡 Hint: Try specifying --format explicitly
```

**Diagnosis:**
```bash
# Check file content structure
head -10 unknown.vex
cat unknown.vex | jq 'keys'

# Look for format indicators
grep -E "bomFormat|document|@context" unknown.vex
```

**Solutions:**
```bash
# Explicitly specify format
vex-updater --scan-report scan.json \
  --vex-file unknown.vex \
  --format cyclonedx

# Convert format if needed
vex-updater --convert-format \
  --input unknown.vex \
  --from auto \
  --to cyclonedx \
  --output converted.vex
```

### Issue 5: "Interactive mode hangs in CI/CD"

**Symptoms:**
```
🔍 CVE: CVE-2021-44228
📦 Component: log4j-core v2.14.1
Action: [t]riage, [s]kip, [q]uit: 
# Process hangs waiting for input
```

**Diagnosis:**
```bash
# Check if running in non-interactive environment
[ -t 0 ] && echo "Interactive" || echo "Non-interactive"
echo $CI  # Check CI environment variable
```

**Solutions:**
```bash
# Use non-interactive flags
vex-updater --scan-report scan.json \
  --vex-file project.vex \
  --auto-skip-existing  # or --batch-mode

# Pre-configure responses
vex-updater --scan-report scan.json \
  --vex-file project.vex \
  --response-file ci_responses.txt

# Use dry-run in CI, manual review elsewhere
if [ "$CI" = "true" ]; then
  vex-updater --scan-report scan.json --vex-file project.vex --dry-run
else
  vex-updater --scan-report scan.json --vex-file project.vex --interactive
fi
```

### Issue 6: "Large scan performance"

**Symptoms:**
```
⚠️  Large scan report detected: enterprise_scan.json (127.3MB)
🐌 Processing taking longer than expected...
```

**Diagnosis:**
```bash
# Check scan file size and vulnerability count
ls -lh enterprise_scan.json
cat enterprise_scan.json | jq '.vulnerabilities | length'

# Profile memory usage
/usr/bin/time -v vex-updater --scan-report enterprise_scan.json --vex-file project.vex --dry-run
```

**Solutions:**
```bash
# Use diff-only for large scans
vex-updater --scan-report enterprise_scan.json \
  --vex-file project.vex \
  --diff-only

# Filter by severity
vex-updater --scan-report enterprise_scan.json \
  --vex-file project.vex \
  --min-severity HIGH

# Split processing by component
vex-updater --scan-report enterprise_scan.json \
  --vex-file project.vex \
  --component-batch-size 100

# Use streaming mode for very large files
vex-updater --scan-report enterprise_scan.json \
  --vex-file project.vex \
  --streaming-mode
```

### Getting Additional Help

**Debug Mode:**
```bash
# Enable verbose logging
vex-updater --scan-report scan.json --vex-file project.vex --debug debug

# Enable info level logging
vex-updater --scan-report scan.json --vex-file project.vex --debug info

# Enable error level logging only
vex-updater --scan-report scan.json --vex-file project.vex --debug error
```

**Community Support:**
- 📚 [FAQ and Known Issues](https://github.com/JigyasuRajput/vex-updater-tool/wiki/FAQ)
- 💬 [Community Forum](https://github.com/JigyasuRajput/vex-updater-tool/discussions)
- 🐛 [Bug Reports](https://github.com/JigyasuRajput/vex-updater-tool/issues)
- 📧 [Email Support](mailto:support@vex-updater-tool.com)

---

This comprehensive guide covers the most common use cases and challenges you'll encounter with the VEX Updater Tool. For specific issues not covered here, please refer to the community resources or file a detailed issue report.
