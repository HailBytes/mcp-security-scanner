import { posix as pathPosix } from 'path';
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

/**
 * Windows system locations that are just as dangerous to write into as the
 * POSIX dirs above. Matched on the raw path (backslash- or forward-slash
 * separated, drive letter case-insensitive) so Claude Desktop / Cursor configs
 * authored on Windows are covered too.
 */
const WINDOWS_UNSAFE_PATTERNS: RegExp[] = [
  /^[a-z]:[\\/]windows(?:[\\/]|$)/i,
  /^[a-z]:[\\/]program files(?: \(x86\))?(?:[\\/]|$)/i,
  /^[a-z]:[\\/]programdata(?:[\\/]|$)/i,
];

/**
 * Decide whether a tool output path targets a sensitive system directory.
 *
 * POSIX paths are normalized first so that interior traversal cannot mask a
 * system directory — e.g. `/var/app/logs/../../../etc/passwd` resolves to
 * `/etc/passwd` and is flagged, where a raw prefix match would miss it.
 * Normalization preserves the existing prefix-boundary behaviour (`/etcfoo`
 * stays safe) because it only collapses `.`/`..` segments.
 */
function isUnsafeOutputPath(rawPath: string): boolean {
  if (WINDOWS_UNSAFE_PATTERNS.some((re) => re.test(rawPath))) {
    return true;
  }

  if (rawPath.startsWith('/')) {
    const normalized = pathPosix.normalize(rawPath);
    return UNSAFE_OUTPUT_DIRS.some(
      (dir) => normalized === dir || normalized.startsWith(dir + '/')
    );
  }

  return false;
}

/**
 * Non-printable / invisible Unicode characters that have no legitimate place in
 * a tool name or description, grouped by the attack technique they enable.
 *
 * These are the mechanism behind MCP "tool poisoning": text that a human
 * reviewer cannot see, but which the model reads in full, is smuggled into the
 * metadata presented to the LLM. The visible description looks benign while
 * hidden characters carry reordered text or an encoded ASCII payload.
 */
const HIDDEN_CHAR_CATEGORIES: Array<{ label: string; test: (cp: number) => boolean }> = [
  {
    // U+E0000–U+E007F, the Unicode Tags block — used to encode an entire
    // invisible ASCII payload. Essentially never legitimate in plain text.
    label: 'Unicode Tag (ASCII smuggling)',
    test: (cp) => cp >= 0xe0000 && cp <= 0xe007f,
  },
  {
    // Trojan-Source style reordering controls: the rendered order differs from
    // the logical order the model consumes.
    label: 'bidirectional override',
    test: (cp) =>
      cp === 0x061c || // ARABIC LETTER MARK
      cp === 0x200e || // LEFT-TO-RIGHT MARK
      cp === 0x200f || // RIGHT-TO-LEFT MARK
      (cp >= 0x202a && cp <= 0x202e) || // LRE RLE PDF LRO RLO
      (cp >= 0x2066 && cp <= 0x2069), // LRI RLI FSI PDI
  },
  {
    // Zero-width and other invisible formatting characters — used to break up
    // keywords (evading text-based rules) or hide content outright.
    label: 'zero-width / invisible formatting',
    test: (cp) =>
      cp === 0x00ad || // SOFT HYPHEN
      cp === 0x180e || // MONGOLIAN VOWEL SEPARATOR
      (cp >= 0x200b && cp <= 0x200d) || // ZWSP ZWNJ ZWJ
      (cp >= 0x2060 && cp <= 0x2064) || // WORD JOINER + invisible math operators
      (cp >= 0x206a && cp <= 0x206f) || // deprecated format controls
      cp === 0xfeff || // ZERO WIDTH NO-BREAK SPACE (BOM)
      (cp >= 0xfff9 && cp <= 0xfffb), // interlinear annotation anchors
  },
  {
    // C0/C1 control characters, excluding the ordinary whitespace a
    // description may legitimately contain (tab, newline, carriage return).
    label: 'control character',
    test: (cp) =>
      (cp <= 0x001f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) ||
      (cp >= 0x007f && cp <= 0x009f),
  },
];

/** Render a code point as a `U+XXXX` label (never echoes the raw hidden char). */
function formatCodePoint(cp: number): string {
  return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
}

/** Collect every hidden character in `text` with the category it belongs to. */
function findHiddenChars(text: string): Array<{ cp: number; label: string }> {
  const hits: Array<{ cp: number; label: string }> = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    const category = HIDDEN_CHAR_CATEGORIES.find((c) => c.test(cp));
    if (category) hits.push({ cp, label: category.label });
  }
  return hits;
}

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
    id: RuleId.HIDDEN_TOOL_METADATA,
    severity: Severity.HIGH,
    title: 'Hidden Characters in Tool Metadata',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        const fields: Array<{ field: string; value?: string }> = [
          { field: 'name', value: tool.name },
          { field: 'description', value: tool.description },
        ];

        const parts: string[] = [];
        const labels = new Set<string>();
        const affectedFields: string[] = [];

        for (const { field, value } of fields) {
          if (!value) continue;
          const hits = findHiddenChars(value);
          if (hits.length === 0) continue;
          affectedFields.push(field);
          hits.forEach((h) => labels.add(h.label));
          const codePoints = [...new Set(hits.map((h) => formatCodePoint(h.cp)))].slice(0, 5);
          parts.push(`${field}: ${hits.length} hidden char(s) [${codePoints.join(', ')}]`);
        }

        if (parts.length === 0) continue;

        findings.push({
          ruleId: RuleId.HIDDEN_TOOL_METADATA,
          severity: Severity.HIGH,
          title: 'Hidden Characters in Tool Metadata',
          description:
            `Tool "${tool.name}" has non-printable or invisible Unicode characters ` +
            `(${[...labels].join(', ')}) in its ${affectedFields.join(' and ')}. ` +
            'Such characters are invisible to a human reviewer but read in full by the model, ' +
            'and are the core mechanism of MCP "tool poisoning" attacks — hidden instructions or ' +
            'smuggled ASCII that can hijack the model while the visible text looks benign.',
          evidence: parts.join('; '),
          remediation:
            'Remove all non-printable and invisible Unicode characters from tool names and ' +
            'descriptions. Metadata presented to an LLM should contain only visible, printable text. ' +
            'Reject tool definitions from untrusted MCP servers that include hidden characters.',
          docsUrl: 'https://hailbytes.com/mcp/docs/rules/HIDDEN_TOOL_METADATA',
        });
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
        if (isUnsafeOutputPath(tool.outputPath)) {
          const resolved = pathPosix.normalize(tool.outputPath);
          findings.push({
            ruleId: RuleId.UNSAFE_TOOL_OUTPUT_PATH,
            severity: Severity.CRITICAL,
            title: 'Tool Output Path Points to System Directory',
            description:
              `Tool "${tool.name}" writes output to "${tool.outputPath}"` +
              (resolved === tool.outputPath ? '' : ` (which resolves to "${resolved}")`) +
              ', which is a sensitive system directory. Writing to these paths can compromise the host OS.',
            evidence: `tool: ${tool.name}, outputPath: "${tool.outputPath}"` +
              (resolved === tool.outputPath ? '' : ` (resolves to "${resolved}")`),
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
