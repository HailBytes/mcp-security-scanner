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

# Scan a running MCP server endpoint
npx @hailbytes/mcp-security-scanner https://my-mcp-server.example.com

# Output SARIF for GitHub Code Scanning + fail on findings
npx @hailbytes/mcp-security-scanner ./config.json --output=sarif --exit-code
```

### Programmatic

```ts
import { scan } from "@hailbytes/mcp-security-scanner";

const report = await scan({ configPath: "./mcp-config.json" });

console.log(report.findings);  // Finding[] — individual security issues
console.log(report.score);     // 0–100 risk score (lower = riskier)
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