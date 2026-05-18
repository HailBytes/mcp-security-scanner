#!/usr/bin/env node
/**
 * mcp-security-scanner CLI
 *
 * Usage:
 *   mcp-security-scanner <config-path-or-url>
 *
 * Exits with code 1 if the scan fails (score >= 50 or critical findings).
 */

import { scan } from './scanner.js';

async function main(): Promise<void> {
  const arg = process.argv[2];

  if (!arg) {
    console.error('Usage: mcp-security-scanner <config-path-or-url>');
    console.error('');
    console.error('Examples:');
    console.error('  mcp-security-scanner ./mcp-server.json');
    console.error('  mcp-security-scanner https://my-mcp-server.example.com');
    process.exit(2);
  }

  const isUrl = arg.startsWith('http://') || arg.startsWith('https://');

  try {
    const report = await scan(
      isUrl ? { serverUrl: arg } : { configPath: arg }
    );

    console.log(JSON.stringify(report, null, 2));

    if (!report.passed) {
      process.exit(1);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(2);
  }
}

main();
