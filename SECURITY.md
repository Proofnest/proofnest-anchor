# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email us at:

**security@stellanium.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Scope

The following are in scope:
- proofnest-anchor CLI tool
- File hashing and verification
- OpenTimestamps integration
- Registry file handling
- Path traversal prevention

### Out of Scope

- OpenTimestamps calendar servers (report to OTS maintainers)
- Third-party dependencies
- Social engineering attacks
- Physical attacks

## Security Features

ProofNest Anchor implements:

1. **Path Traversal Prevention**: All file paths sanitized
2. **Symlink Attack Prevention**: Symlinks rejected in proof files
3. **Input Validation**: File size and count limits
4. **Safe Path Resolution**: No directory escape possible

## Security Best Practices

When using ProofNest Anchor:

1. **Keep .anchor/ Private**: Add to .gitignore if not sharing proofs
2. **Verify Proofs**: Use `anchor verify` before trusting timestamps
3. **Backup Registry**: The registry.json contains all file hashes
4. **Check OTS Status**: Ensure proofs are confirmed on Bitcoin

## Acknowledgments

We thank security researchers who help keep ProofNest secure.

---

*Last updated: December 2025*
