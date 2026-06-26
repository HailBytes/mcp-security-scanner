# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `--exit-code` no longer fails on the informational `URL_SCAN_LIMITED` note.
  Scanning a secure `https://`/`wss://` endpoint with `--exit-code` printed
  `PASSED` but still exited `1`, because the INFO note counted as a "finding" —
  failing CI on every secure endpoint and contradicting the note's documented
  "never fails a gate" contract. The exit-code gate now ignores INFO-severity
  findings and trips only on actionable (LOW+) ones.
- URL/endpoint mode no longer produces false findings (#27). Scanning a URL
  previously ran every config rule against an effectively empty config, so any
  endpoint always emitted a CRITICAL `NO_AUTH` and a MEDIUM `MISSING_RATE_LIMIT`
  and always failed — even for a secure, authenticated server. URL mode now runs
  only the rules a URL can actually answer (`MISSING_TLS`, `INSECURE_TRANSPORT`)
  and emits an INFO `URL_SCAN_LIMITED` note explaining that live introspection
  is not performed and that a config file is required for the full rule set.
- `WEAK_API_KEY`: now also length-checks `auth.token`, not just `auth.apiKey`
  (#26). A short (< 32 char) opaque bearer token previously passed the gate even
  though an identical value in `apiKey` was flagged HIGH. JWT-shaped tokens are
  exempt (structured, effectively always > 32 chars); finding evidence now names
  the offending field (`apiKey` vs `token`).
- YAML configs are now parsed correctly (#19). The previous hand-rolled parser
  only handled flat scalar keys, silently dropping nested `transport.auth` (a
  false `NO_AUTH`) and the `tools:` sequence-of-maps (all tool rules skipped). A
  YAML config and its JSON equivalent now produce identical results. Still
  zero-dependency — the parser is indentation-driven.
- `MISSING_TLS`: scoped to the HTTP family so a secure `wss://` transport is no
  longer flagged "uses plain HTTP", and `ws://` is no longer double-counted
  (it remains covered by `INSECURE_TRANSPORT`).
- CLI: `--rule` now rejects unknown/typo'd rule IDs with exit code 2 (#11).
  Previously an unrecognized rule filtered the rule set to nothing, producing a
  silent false "PASSED" — a security gate bypassed by a typo. `--help` now lists
  the valid rule IDs.
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

[Unreleased]: https://github.com/HailBytes/mcp-security-scanner/compare/HEAD...HEAD
