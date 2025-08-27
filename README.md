# VEX Edit Tool

A standalone Python command-line tool for editing VEX (Vulnerability Exploitability eXchange) documents in CycloneDX, CSAF, and OpenVEX JSON formats from cve-bin-tool output or existing VEX documents.

## Features

- **Standalone**: No dependency on cve-bin-tool - operates as an independent tool
- **Multi-Format Support**: Edits VEX documents in CycloneDX, CSAF, and OpenVEX formats
- **Edit Existing VEX**: Can edit existing VEX documents or generate new ones from cve-bin-tool output
- **Standards Compliant**: Supports VEX documents compliant with CycloneDX 1.4, CSAF, and OpenVEX specifications  
- **Comprehensive CLI**: Supports all VEX statuses and justifications
- **Robust Error Handling**: Clear error messages for invalid inputs and missing files
- **Flexible Output**: Output to file or stdout with pretty-printed JSON
- **Well Tested**: Comprehensive test suite with high code coverage

## Installation

### Quick Setup (Recommended)

For the fastest setup, use the provided setup script:

```bash
# Clone the repository
git clone https://github.com/JigyasuRajput/vex-generate-tool.git
cd vex-generate-tool

# Quick setup for users
./setup.sh

# Or for development setup (includes testing tools)
./setup.sh dev

# Activate the environment and start using
source .venv/bin/activate
vex-edit-tool --help
```

### Manual Installation Options

#### Option 1: Install from Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/JigyasuRajput/vex-generate-tool.git
cd vex-generate-tool

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install runtime dependencies  
pip install -r requirements.txt

# Install the tool in development mode
pip install -e .
```

### Option 2: Install Runtime Dependencies Only

```bash
# Install only the runtime dependencies
pip install lib4vex>=0.2.0 cyclonedx-python-lib>=3.0.0

# Clone and install
git clone https://github.com/JigyasuRajput/vex-edit-tool.git
cd vex-edit-tool
pip install -e .
```

### Option 3: Development Setup

For contributing or development work:

```bash
# Clone the repository
git clone https://github.com/JigyasuRajput/vex-generate-tool.git
cd vex-generate-tool

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies (includes testing tools)
pip install -r requirements-dev.txt

# Install the tool in development mode
pip install -e .

# Verify installation
vex-edit-tool --help
pytest
```

## Usage

### Basic Usage

Generate a new VEX document from cve-bin-tool JSON output:

```bash
vex-edit-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 --status not_affected --justification vulnerable_code_not_present --output vex_output.json
```

Edit an existing VEX document:

```bash
vex-edit-tool --input-vex existing_vex.json --vuln-id CVE-2021-44228 --status fixed --impact-statement "Patched in version 2.15.0"
```

### Command Line Options

**Input Sources (choose one):**
- `--cve-bin-json`: Path to the JSON output file from cve-bin-tool (for generating new VEX)
- `--input-vex`: Path to existing VEX document to edit

**Required Arguments:**
- `--vuln-id`: The CVE identifier (e.g., CVE-2021-44228)
- `--status`: VEX status (not_affected, affected, fixed, under_investigation)

**Optional Arguments:**
- `--justification`: Justification for the status (required for not_affected)
- `--impact-statement`: Detailed description of the impact
- `--output`: Path to save the VEX file (prints to stdout if not provided, overwrites input when editing)
- `--format`: Output format for new VEX documents (cyclonedx, csaf, openvex - default: cyclonedx)

### Supported VEX Statuses

- `not_affected`: Component is not affected by the vulnerability
- `affected`: Component is affected by the vulnerability  
- `fixed`: Vulnerability has been fixed in the component
- `under_investigation`: The impact is being investigated

### Justification Values (for not_affected status)

- `vulnerable_code_not_present`: The vulnerable code is not present
- `vulnerable_code_not_in_execute_path`: The vulnerable code is present but not in the execution path
- `vulnerable_code_cannot_be_controlled_by_adversary`: The vulnerable code cannot be controlled by an adversary
- `inline_mitigations_already_exist`: Inline mitigations already exist

## Examples

### Example 1: Generate New VEX - Not Affected Status

```bash
vex-edit-tool --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status not_affected \
  --justification vulnerable_code_not_present \
  --impact-statement "The vulnerable function is never called in our product." \
  --output not_affected.json
```

### Example 2: Edit Existing VEX - Update Status to Fixed

```bash
vex-edit-tool --input-vex existing_vex.json \
  --vuln-id CVE-2021-44228 \
  --status fixed \
  --impact-statement "Vulnerability patched in version 2.15.0." \
  --output fixed.json
```

### Example 3: Generate New VEX - Affected Status

```bash
vex-edit-tool --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status affected \
  --impact-statement "This vulnerability affects our application severely." \
  --output affected.json
```

### Example 4: Edit Existing VEX In-Place

```bash
vex-edit-tool --input-vex existing_vex.json \
  --vuln-id CVE-2021-44228 \
  --status under_investigation
```

### Example 5: Output to stdout

```bash
vex-edit-tool --cve-bin-json sample_input.json \
  --vuln-id CVE-2021-44228 \
  --status under_investigation
```

## Input Format

The tool expects JSON input in the format produced by cve-bin-tool:

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

## Output Formats

The tool supports multiple VEX document formats:

### CycloneDX Format

The tool can generate/edit CycloneDX 1.4 compliant VEX documents:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "type": "library",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      },
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_present",
        "detail": "The vulnerable function is never called in our product."
      }
    }
  ]
}
```

### CSAF Format Support

Support for CSAF (Common Security Advisory Framework) VEX documents is planned for future releases.

### OpenVEX Format Support  

Support for OpenVEX format documents is planned for future releases.

## Testing

Run the comprehensive test suite:

```bash
pytest
```

Run tests with coverage report:

```bash
pytest --cov=vex_generate_tool --cov-report=term-missing --cov-report=html
```

The test suite includes:
- **CLI Argument Parsing**: All argument combinations and validation
- **VEX Generation Logic**: All statuses and justifications
- **File I/O**: Input validation and output generation
- **Error Handling**: Invalid inputs, missing files, edge cases
- **Integration Tests**: End-to-end functionality testing

## Project Structure

```
vex-generate-tool/
├── vex_generate_tool/
│   ├── __init__.py
│   ├── main.py         # CLI entry point and argument parsing
│   └── generator.py    # Core logic for VEX document generation
├── tests/
│   ├── __init__.py
│   ├── test_generator.py # Tests for the VEX generation logic
│   └── test_main.py      # Tests for the CLI
├── pyproject.toml      # Project metadata and dependencies
├── README.md           # This file
├── sample_input.json   # Example input file
└── examples.sh         # Comprehensive examples script
```

## Error Handling

The tool provides clear error messages for common issues:

- Missing required justification for `not_affected` status
- Vulnerability ID not found in input data
- Invalid input file format or missing files
- Invalid status or justification values

## Development

To contribute to the project:

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up development environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements-dev.txt
   pip install -e .
   ```
4. **Make your changes** and add tests
5. **Run tests**: `pytest --cov=vex_generate_tool --cov-report=term-missing`
6. **Check code quality**:
   ```bash
   black vex_generate_tool/ tests/
   isort vex_generate_tool/ tests/
   flake8 vex_generate_tool/ tests/
   ```
7. **Submit a pull request**

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## License

This is a personal project with no specific license.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Setting up the development environment
- Running tests and code quality checks
- Submitting pull requests
- Reporting issues and feature requests

## Repository

- **GitHub**: https://github.com/JigyasuRajput/vex-generate-tool
- **Issues**: https://github.com/JigyasuRajput/vex-generate-tool/issues
- **Pull Requests**: https://github.com/JigyasuRajput/vex-generate-tool/pulls
