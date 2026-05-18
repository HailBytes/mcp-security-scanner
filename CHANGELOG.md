# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffold: project structure, TypeScript configuration, and package metadata.
- Added real scanner implementation with 8 security rules, CLI, Jest test suite, ESLint config.
  - Auth rules: NO_AUTH, WEAK_API_KEY, MISSING_TLS
  - Injection rules: TOOL_DESC_INJECTION, UNSAFE_TOOL_OUTPUT_PATH
  - Config rules: WILDCARD_CORS, VERBOSE_ERRORS, OVERPRIVILEGED_TOOL
  - CLI entry point (`mcp-security-scanner <config-path-or-url>`)
  - Jest test suite with 35 tests across scanner and scorer
  - ESLint + @typescript-eslint wired up with zero warnings

[Unreleased]: https://github.com/HailBytes/mcp-security-scanner/compare/HEAD...HEAD
