# @hailbytes/mcp-security-scanner

> Scans Model Context Protocol (MCP) server configurations for common security issues.

![Status: Incubation — not yet published to npm](https://img.shields.io/badge/status-incubation-orange)

**Planned npm name:** `@hailbytes/mcp-security-scanner`

---

## ⚠️ Incubation Notice

This package is in early incubation and **has not yet been published to npm**. The API may change without notice. Follow [hailbytes.com](https://hailbytes.com) for release announcements.

---

## Overview

`@hailbytes/mcp-security-scanner` audits MCP server configurations and running endpoints for:

- **Overprivileged tools** — tools granted broader permissions than their declared function requires
- **Missing or weak authentication** — unauthenticated transports, missing token validation
- **Prompt injection surface** — tool descriptions or output paths susceptible to injection
- **Unsafe defaults** — insecure transport defaults, verbose error exposure, CORS wildcards

> Part of HailBytes' MCP security research initiative. See [hailbytes.com/mcp](https://hailbytes.com/mcp) for our MCP server documentation.

---

## Planned Audience

Security engineers, platform teams, and AI/LLM developers who build or operate MCP servers and want automated, continuous security checks integrated into their CI/CD pipelines.

---

## Planned API Sketch

### CLI

```bash
npx @hailbytes/mcp-security-scanner <server-url-or-config>

# Examples
npx @hailbytes/mcp-security-scanner ./mcp-config.json
npx @hailbytes/mcp-security-scanner https://my-mcp-server.example.com
npx @hailbytes/mcp-security-scanner ./config.json --output=sarif --exit-code
```

### Programmatic

```ts
import { scan } from "@hailbytes/mcp-security-scanner";

const report: SecurityReport = await scan({
  configPath: "./mcp-config.json",
  // or serverUrl: "https://..."
});

console.log(report.findings);   // Finding[]
console.log(report.score);      // 0–100 risk score
console.log(report.passed);     // boolean
```

---

## See Also

- [@hailbytes/mcp-server-template](https://github.com/HailBytes/mcp-server-template) — production-ready MCP server scaffold

---

## Links

- [hailbytes.com](https://hailbytes.com)
- [hailbytes.com/mcp](https://hailbytes.com/mcp) — MCP server documentation
- [GitHub Issues](https://github.com/HailBytes/mcp-security-scanner/issues)


[![npm downloads](https://img.shields.io/npm/dw/%40hailbytes%2Fmcp-security-scanner.svg)](https://www.npmjs.com/package/@hailbytes/mcp-security-scanner)