# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `NO_AUTH`: fixed a CRITICAL false negative where declaring
  `transport.auth.type: "none"` (or `disabled`/`off`/`false`/`anonymous`)
  satisfied the auth check, so an explicitly unauthenticated server passed the
  gate. An auth `type` now only counts as authentication when it names a real
  mechanism; placeholder/disabled values are treated as no auth.
- Restored the test suite / green CI: `import.meta.url` in `src/sarif.ts` could
  not compile under the Jest `module: CommonJS` transform, so the `sarif` and
  `scanner` test suites silently failed to run (and the test gate had been
  effectively disabled). Jest now runs ts-jest in ESM mode, matching the
  package's published ESM build. Also fixed a stale SARIF version assertion that
  was hard-coded to `0.0.1`; it now reads the version from `package.json`.
- CLI: accept `--output=` as an alias for `--format=`. The README and dev.to
  launch post documented `--output=sarif`, but the CLI rejected it as an unknown
  flag (exit 2), so the documented quick-start command failed.

### Changed
- Extracted CLI argument parsing into a pure, side-effect-free `parseArgs()`
  (`src/args.ts`) with direct unit-test coverage (`src/__tests__/args.test.ts`).

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

### Fixed
- `EXPOSED_SECRETS` no longer misses hardcoded passwords in structured configs. `extractStrings` (`src/parser.ts`) collected string values in isolation, so the key-aware password pattern (`password: <value>`) could never match a JSON/YAML config — a `"password": "..."` field was silently ignored. String values are now extracted with their key context (`"key: value"`), so key-dependent patterns fire while token-shaped patterns (`sk-`, `ghp_`, `AKIA`) continue to match. Added `src/__tests__/parser.test.ts` covering this regression.

[Unreleased]: https://github.com/HailBytes/mcp-security-scanner/compare/HEAD...HEAD
