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
- Added 5 new runtime security rules (`src/rules/runtime-rules.ts`):
  - `INSECURE_TRANSPORT` (HIGH): fires when `transport.url` uses unencrypted `ws://`
  - `MISSING_RATE_LIMIT` (MEDIUM): fires when `rateLimit` is absent or `enabled: false`
  - `DEBUG_MODE_ENABLED` (LOW): fires when `debug: true` is set
  - `EXPOSED_SECRETS` (CRITICAL): scans all raw string values for common secret patterns (OpenAI API key, GitHub PAT, AWS access key, password assignments)
  - `UNRESTRICTED_FILE_ACCESS` (HIGH): fires when a tool has `filesystem:*` or both `filesystem:read` and `filesystem:write` permissions
- Added SARIF 2.1.0 output support (`src/sarif.ts`):
  - `toSarif(report, configPath?)` converts a `SecurityReport` to a minimal SARIF 2.1.0 document
  - Severity mapping: critical/high → `error`, medium → `warning`, low/info → `note`
  - Includes tool driver metadata and per-result artifact locations
- Enhanced CLI with rich flag parsing (`src/cli.ts`):
  - `--format=json|sarif|table` (default: json)
  - `--exit-code` — exit 1 on any finding regardless of score
  - `--fail-on=critical|high|medium|low` — force fail at a minimum severity level
  - `--rule=RULE_ID` — filter to specific rules (repeatable)
  - `--help` / `-h` — display usage information
  - `--format=table` renders an ASCII table sorted by severity with a summary line
- Implemented `failOn` in `scan()` (`src/scanner.ts`): forces `passed=false` when any finding meets or exceeds the configured severity threshold
- Updated `ParsedMcpConfig` with `rawStrings?: string[]` field populated from all string values in the raw config object (used by `EXPOSED_SECRETS` rule)
- Added example configuration files:
  - `examples/secure-config.json` — a passing config with auth, HTTPS/WSS, scoped CORS, rate limiting, no debug
  - `examples/vulnerable-config.json` — a deliberately failing config triggering 8+ rules
  - `examples/minimal-config.json` — bare minimum valid config with just a `serverUrl`
- Expanded test suite to 70 tests (added `sarif.test.ts` and new cases in `scanner.test.ts`)

[Unreleased]: https://github.com/HailBytes/mcp-security-scanner/compare/HEAD...HEAD
