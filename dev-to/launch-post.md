---
title: "Your MCP Server Is Probably Overprivileged — Here's a Scanner For It"
published: false
description: MCP servers expose tools to LLMs, but most configs grant tools broader permissions than they need, ship without auth, and leak prompt-injection surface in tool descriptions. This scanner finds it before your model does.
tags: ai, security, llm, javascript
cover_image: <COVER_IMAGE_URL>
canonical_url: https://github.com/hailbytes/mcp-security-scanner
published_at: 2026-05-20 13:00 +0000
---

<!--
COVER IMAGE PROMPT (1000x420, 2.4:1 banner):

Flat vector illustration, isometric perspective. A stylized server rack on the right, with a
large translucent magnifying glass hovering over it. Inside the lens: red warning triangles
and a small unlock / open-padlock icon, hinting at exposed surface. A subtle silhouette of an
AI brain / neural-net node-graph faintly visible in the background, suggesting the LLM
consumer. Dark navy (#0a1628) background, electric cyan (#00d4ff) for the server and
magnifier, red (#ff4d6d) only for the warning indicators, amber accent on the brain motif.
Banner composition, generous negative space. No text in the image.

Suggested generators: Midjourney v6+ with `--ar 1000:420 --style raw`, DALL-E 3, or Flux.
After generation, host on Cloudinary or GitHub raw and replace <COVER_IMAGE_URL> above.
-->

Most MCP servers I've audited in the last few months had the same three issues:

1. A `shell` or `fs` tool was scoped to the entire filesystem when the use case needed exactly one directory.
2. The transport ran without auth because the local-dev SSE config got promoted to prod.
3. Tool descriptions echoed verbatim into prompts with no sanitization — a perfect injection surface.

[`@hailbytes/mcp-security-scanner`](https://www.npmjs.com/package/@hailbytes/mcp-security-scanner) is what I wish I'd had on day one of building MCP servers. It's a static + dynamic scanner for MCP configs and live endpoints that flags these patterns.

## CLI

```bash
# Scan a local config
npx @hailbytes/mcp-security-scanner ./mcp-config.json

# Scan a live endpoint
npx @hailbytes/mcp-security-scanner https://my-mcp-server.example.com

# SARIF output + fail the build
npx @hailbytes/mcp-security-scanner ./config.json --format=sarif --exit-code
```

## Programmatic

```ts
import { scan } from "@hailbytes/mcp-security-scanner";

const report = await scan({ configPath: "./mcp-config.json" });

if (!report.passed) {
  console.error(report.findings);
  process.exit(1);
}
```

## What it checks

- **Overprivileged tools** — broader permissions than the declared function needs (filesystem scope, shell access, network egress)
- **Missing or weak authentication** — unauthenticated transports, missing token validation, plaintext secrets in config
- **Prompt injection surface** — tool descriptions and output paths that pass through to model context without sanitization
- **Unsafe defaults** — insecure transport defaults, verbose error exposure, CORS wildcards

The SARIF output drops straight into GitHub Code Scanning, so findings show up as alerts on PRs — same place your SAST results live.

```bash
npm install -g @hailbytes/mcp-security-scanner
```

Source: [github.com/hailbytes/mcp-security-scanner](https://github.com/hailbytes/mcp-security-scanner) — MIT licensed. Pairs nicely with [`@hailbytes/mcp-server-template`](https://github.com/hailbytes/mcp-server-template) if you want a scaffold that comes up secure by default.
