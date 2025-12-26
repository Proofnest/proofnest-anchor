# Contributing to ProofNest Anchor

Thank you for your interest in contributing! This document provides guidelines for contributing.

## Code of Conduct

Be respectful, inclusive, and professional.

## How to Contribute

### Reporting Bugs

1. Check existing issues first
2. Create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS
   - Version (`pip show proofnest-anchor`)

### Suggesting Features

1. Check existing issues
2. Open a feature request issue
3. Describe the use case

### Submitting Code

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make changes** following our style guide
4. **Test** your changes
5. **Commit** with clear messages
6. **Push** and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/proofnest-anchor.git
cd proofnest-anchor

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
black proofnest_anchor
ruff check proofnest_anchor
```

## Style Guide

- **Python**: Follow PEP 8, use Black formatter
- **Type hints**: Required for all public functions
- **Docstrings**: Google style
- **Tests**: Required for new features

### Commit Messages

```
feat: add batch verification
fix: handle symlink attacks
docs: update CLI reference
test: add registry tests
```

## Pull Request Process

1. Update README.md if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Request review

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] No security vulnerabilities

## Areas for Contribution

### High Priority
- Test coverage
- Documentation
- Error handling improvements

### Good First Issues
- Look for `good first issue` labels
- Documentation improvements
- Test additions

## Questions?

- Open a GitHub Discussion
- Email: admin@stellanium.io

## License

Contributions are licensed under Apache 2.0.
