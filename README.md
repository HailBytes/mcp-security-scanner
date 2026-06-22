# @hailbytes/mcp-security-scanner

> Scans Model Context Protocol (MCP) server configurations for common security issues: overprivileged tools, missing auth, prompt injection surface, and unsafe defaults.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fmcp-security-scanner.svg)](https://www.npmjs.com/package/%40hailbytes%2Fmcp-security-scanner)
[![npm downloads](https://img.shields.io/npm/dw/%40hailbytes%2Fmcp-security-scanner.svg)](https://www.npmjs.com/package/@hailbytes/mcp-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/%40hailbytes%2Fmcp-security-scanner)](https://bundlephobia.com/package/@hailbytes/mcp-security-scanner)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-davidhailbytes-blue?logo=linkedin&style=flat)](https://www.linkedin.com/in/davidhailbytes/)

---

## What it does

Audit MCP server configurations and endpoints for the most common AI security mistakes — overprivileged tools, missing authentication, prompt injection attack surface, and insecure transport defaults. Integrates into CI/CD as a gate or run on-demand via CLI.

---

## Install

```bash
npm install -g @hailbytes/mcp-security-scanner
# or use directly via npx
npx @hailbytes/mcp-security-scanner ./mcp-config.json
```

---

## Quick Start

### CLI

```bash
# Scan a local config file
npx @hailbytes/mcp-security-scanner ./mcp-config.json

# Scan a server endpoint URL (transport checks only — see note below)
npx @hailbytes/mcp-security-scanner https://my-mcp-server.example.com

# Output SARIF for GitHub Code Scanning + fail on findings
npx @hailbytes/mcp-security-scanner ./config.json --format=sarif --exit-code
```

> **URL mode vs. config-file mode.** When the target is a **URL**, the scanner
> does not connect to or introspect the live server — it evaluates only the
> transport security derivable from the URL itself (`MISSING_TLS` for `http://`,
> `INSECURE_TRANSPORT` for `ws://`). It emits a `URL_SCAN_LIMITED` info note to
> make this explicit. Authentication, rate limiting, CORS, tool, and secret
> rules require a **config file** (`.json`/`.yaml`) to evaluate. Point the
> scanner at your MCP server configuration to run the full rule set.

### Programmatic

```ts
import { scan } from "@hailbytes/mcp-security-scanner";

const report = await scan({ configPath: "./mcp-config.json" });

console.log(report.findings);  // Finding[] — individual security issues
console.log(report.score);     // 0–100 risk score (higher = riskier)
console.log(report.passed);    // boolean — use as CI gate
```

---

## What It Checks

- **Overprivileged tools** — tools granted broader permissions than their declared function requires
- **Missing or weak authentication** — unauthenticated transports, missing token validation
- **Prompt injection surface** — tool descriptions or output paths susceptible to injection
- **Unsafe defaults** — insecure transport defaults, verbose error exposure, CORS wildcards

---

## See Also

- [`@hailbytes/mcp-server-template`](https://github.com/HailBytes/mcp-server-template) — production-ready MCP server scaffold with auth built-in
- [HailBytes MCP documentation](https://hailbytes.com/mcp)

---

*Part of the [HailBytes](https://hailbytes.com) open-source security toolkit.*