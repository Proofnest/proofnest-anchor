# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2025-12-26

### Changed
- Version bump for production release alignment with proofnest-lib v1.2.2

## [1.0.1] - 2025-12-24

### Added
- Initial public release
- `pn-anchor` CLI tool for timestamping files
- Bitcoin timestamping via OpenTimestamps (mainnet)
- SHA-256 hashing of file contents
- Proof file generation (`.proof.json`)
- Verification command (`pn-anchor verify`)
- GitHub Actions CI/CD pipeline
- SECURITY.md and CONTRIBUTING.md

### Security
- SHA-256 cryptographic hashing
- Tamper-evident proof files
- Bitcoin blockchain immutability via OpenTimestamps

[Unreleased]: https://github.com/Proofnest/proofnest-anchor/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Proofnest/proofnest-anchor/releases/tag/v1.0.1
