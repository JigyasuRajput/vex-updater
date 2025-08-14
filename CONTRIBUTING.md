# Contributing to VEX Generate Tool

Thank you for your interest in contributing to the VEX Generate Tool! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git

### Setting Up Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JigyasuRajput/vex-generate-tool.git
   cd vex-generate-tool
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Install the package in development mode:**
   ```bash
   pip install -e .
   ```

5. **Verify the installation:**
   ```bash
   vex-generate-tool --help
   pytest
   ```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vex_generate_tool --cov-report=term-missing --cov-report=html

# Run specific test file
pytest tests/test_generator.py

# Run specific test
pytest tests/test_generator.py::TestVEXGenerator::test_validate_status_valid
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code with Black
black vex_generate_tool/ tests/

# Sort imports with isort
isort vex_generate_tool/ tests/

# Lint with flake8
flake8 vex_generate_tool/ tests/

# Type checking with mypy
mypy vex_generate_tool/
```

### Running Examples

```bash
# Run the comprehensive examples script
./examples.sh
```

## Project Structure

```
vex-generate-tool/
├── vex_generate_tool/          # Main package
│   ├── __init__.py            # Package initialization
│   ├── main.py                # CLI entry point
│   └── generator.py           # VEX generation logic
├── tests/                     # Test suite
│   ├── __init__.py           
│   ├── test_generator.py      # Generator tests
│   └── test_main.py           # CLI tests
├── .gitignore                 # Git ignore rules
├── pyproject.toml             # Project configuration
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Development dependencies
├── README.md                  # Project documentation
├── CONTRIBUTING.md            # This file
├── sample_input.json          # Example input
└── examples.sh               # Example usage script
```

## Contributing Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use Black for code formatting
- Use isort for import sorting
- Maximum line length: 88 characters (Black default)
- Use type hints where appropriate

### Testing

- Write tests for all new features
- Maintain or improve test coverage (currently 97%)
- Follow the existing test patterns
- Use descriptive test names and docstrings

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Keep the first line under 50 characters
- Add detailed description if needed

### Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the guidelines above
3. **Write or update tests** for your changes
4. **Run the test suite** and ensure all tests pass
5. **Run code quality checks** (black, isort, flake8, mypy)
6. **Update documentation** if needed
7. **Submit a pull request** with a clear description

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes**
- **New features** (VEX-related functionality)
- **Documentation improvements**
- **Test improvements**
- **Performance optimizations**
- **Code quality improvements**

### Reporting Issues

When reporting issues, please include:

- **Clear description** of the problem
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (Python version, OS, etc.)
- **Error messages** (if any)
- **Sample input data** (if relevant)

### Feature Requests

For feature requests, please:

- **Describe the use case** clearly
- **Explain the expected behavior**
- **Consider VEX specification compliance**
- **Discuss implementation approach** (if you have ideas)

## Development Notes

### Key Components

1. **`generator.py`**: Core VEX generation logic
   - Input validation and parsing
   - CycloneDX BOM creation
   - VEX vulnerability analysis

2. **`main.py`**: CLI interface
   - Argument parsing
   - Input validation
   - Output handling

3. **Test suite**: Comprehensive testing
   - Unit tests for core logic
   - CLI integration tests
   - Error handling tests

### Adding New Features

When adding new features:

1. **Check VEX specification** for compliance
2. **Add appropriate tests** before implementation
3. **Update CLI help** and documentation
4. **Consider backward compatibility**
5. **Update examples** if relevant

### Dependencies

- **Runtime**: Keep minimal (currently just cyclonedx-python-lib)
- **Development**: Tools for quality and testing
- **Version pinning**: Use minimum versions with `>=`

## Questions and Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Contact**: [Add contact information if available]

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project.

Thank you for contributing to the VEX Generate Tool!
