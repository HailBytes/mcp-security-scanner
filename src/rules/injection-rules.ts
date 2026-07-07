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
  // Tool-poisoning directives seen in real-world MCP attacks (e.g. the Invariant
  // Labs proof-of-concept): a hidden <IMPORTANT> block, a concealment
  // instruction ("do not tell the user…"), and injected replacement
  // instructions ("your new instructions are…"). The model reads tool metadata
  // verbatim, so these hijack behaviour without ever being shown to the user.
  /<\s*important\s*>/i,
  /\bdo\s+not\s+(tell|mention|inform|reveal|disclose|notify|report)\b/i,
  /\bnew\s+instructions?\b/i,
];

/**
 * Tool metadata fields that are fed to the model when the tool is presented and
 * are therefore an injection surface. Descriptions are the classic vector, but
 * an attacker controls the tool `name` too, so both must be inspected.
 */
const INJECTABLE_FIELDS: Array<'name' | 'description'> = ['name', 'description'];

/**
 * True if any injection pattern matches the value. Tool names are commonly
 * `snake_case`/`kebab-case`/`camelCase`, where `_` counts as a word character
 * and defeats the `\b`-anchored patterns (e.g. `ignore_previous` would slip past
 * `/\bignore\b/`). Test the raw value and a separator-normalized copy so that a
 * name like `ignore_previous_instructions` is caught the same as free text.
 */
function matchesInjection(value: string): boolean {
  const normalized = value
    .replace(/[_-]+/g, ' ') // snake_case / kebab-case → spaced words
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2'); // camelCase → spaced words
  return INJECTION_PATTERNS.some((p) => p.test(value) || p.test(normalized));
}

const UNSAFE_OUTPUT_DIRS = ['/etc', '/proc', '/sys', '/boot', '/root', '/dev'];

export const injectionRules: Rule[] = [
  {
    id: RuleId.TOOL_DESC_INJECTION,
    severity: Severity.HIGH,
    title: 'Potential Prompt Injection in Tool Metadata',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        // Inspect every injectable field, but report at most one finding per
        // tool (the first field that matches) to avoid double-counting a tool
        // that is poisoned in both its name and description.
        for (const field of INJECTABLE_FIELDS) {
          const value = tool[field];
          if (!value) continue;
          if (!matchesInjection(value)) continue;

          findings.push({
            ruleId: RuleId.TOOL_DESC_INJECTION,
            severity: Severity.HIGH,
            title: 'Potential Prompt Injection in Tool Metadata',
            description:
              `Tool "${tool.name}" has a ${field} that contains prompt injection / ` +
              'tool-poisoning language. Tool names and descriptions are fed to the model ' +
              'verbatim when the tool is presented, so instruction-like text here can hijack ' +
              'LLM behaviour — often without the user ever seeing it.',
            evidence: `tool: ${tool.name}, ${field}: "${value}"`,
            remediation:
              'Review tool names and descriptions and remove any instruction-like language ' +
              '(e.g. "ignore previous instructions", "do not tell the user", <IMPORTANT> blocks). ' +
              'Tool metadata should be neutral, factual, and focused on what the tool does.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/TOOL_DESC_INJECTION',
          });
          break;
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
        const isUnsafe = UNSAFE_OUTPUT_DIRS.some((dir) => {
          const p = tool.outputPath!;
          return p === dir || p.startsWith(dir + '/');
        });
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
