import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

const INJECTION_PATTERNS = [
  /\bignore\b/i,
  /\bdisregard\b/i,
  /\boverride\b/i,
  /\bsystem\s+prompt\b/i,
  /\bforget\s+(all\s+)?previous\b/i,
  /\byou\s+are\s+now\b/i,
  /\bact\s+as\b/i,
];

const UNSAFE_OUTPUT_DIRS = ['/etc', '/proc', '/sys', '/boot', '/root', '/dev'];

export const injectionRules: Rule[] = [
  {
    id: RuleId.TOOL_DESC_INJECTION,
    severity: Severity.HIGH,
    title: 'Potential Prompt Injection in Tool Description',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        if (!tool.description) continue;
        const matched = INJECTION_PATTERNS.find((p) => p.test(tool.description!));
        if (matched) {
          findings.push({
            ruleId: RuleId.TOOL_DESC_INJECTION,
            severity: Severity.HIGH,
            title: 'Potential Prompt Injection in Tool Description',
            description:
              `Tool "${tool.name}" has a description that contains prompt injection language. ` +
              'Malicious descriptions can hijack LLM behaviour when the tool is presented to a model.',
            evidence: `tool: ${tool.name}, description: "${tool.description}"`,
            remediation:
              'Review tool descriptions and remove any instruction-like language. ' +
              'Descriptions should be neutral, factual, and focused on what the tool does.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/TOOL_DESC_INJECTION',
          });
        }
      }
      return findings;
    },
  },

  {
    id: RuleId.UNSAFE_TOOL_OUTPUT_PATH,
    severity: Severity.CRITICAL,
    title: 'Tool Output Path Points to System Directory',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        if (!tool.outputPath) continue;
        const isUnsafe = UNSAFE_OUTPUT_DIRS.some((dir) =>
          tool.outputPath!.startsWith(dir)
        );
        if (isUnsafe) {
          findings.push({
            ruleId: RuleId.UNSAFE_TOOL_OUTPUT_PATH,
            severity: Severity.CRITICAL,
            title: 'Tool Output Path Points to System Directory',
            description:
              `Tool "${tool.name}" writes output to "${tool.outputPath}", ` +
              'which is a sensitive system directory. Writing to these paths can compromise the host OS.',
            evidence: `tool: ${tool.name}, outputPath: "${tool.outputPath}"`,
            remediation:
              'Restrict tool output paths to application-owned directories. ' +
              'Never allow tools to write to /etc, /proc, /sys, or other system paths.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/UNSAFE_TOOL_OUTPUT_PATH',
          });
        }
      }
      return findings;
    },
  },
];
