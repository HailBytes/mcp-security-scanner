import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

const DANGEROUS_PERMISSIONS = ['filesystem:write', 'network:*', 'shell:exec'];

export const configRules: Rule[] = [
  {
    id: RuleId.WILDCARD_CORS,
    severity: Severity.MEDIUM,
    title: 'Wildcard CORS Origin Configured',
    check(config: ParsedMcpConfig): Finding[] {
      const origins = config.cors?.origins ?? [];
      if (origins.includes('*')) {
        return [
          {
            ruleId: RuleId.WILDCARD_CORS,
            severity: Severity.MEDIUM,
            title: 'Wildcard CORS Origin Configured',
            description:
              'The CORS configuration allows requests from any origin ("*"). ' +
              'This can expose MCP endpoints to cross-site request forgery (CSRF) attacks ' +
              'and allows any web page to interact with the server.',
            evidence: 'cors.origins: ["*"]',
            remediation:
              'Replace the wildcard origin with a specific allow-list of trusted origins ' +
              '(e.g., "https://your-app.example.com").',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/WILDCARD_CORS',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.VERBOSE_ERRORS,
    severity: Severity.LOW,
    title: 'Verbose Error Reporting Enabled',
    check(config: ParsedMcpConfig): Finding[] {
      if (config.verboseErrors === true) {
        return [
          {
            ruleId: RuleId.VERBOSE_ERRORS,
            severity: Severity.LOW,
            title: 'Verbose Error Reporting Enabled',
            description:
              'The server is configured to return verbose error messages. ' +
              'Detailed stack traces and internal error messages can leak implementation details ' +
              'that help attackers understand server internals.',
            evidence: 'verboseErrors: true',
            remediation:
              'Set verboseErrors to false in production. ' +
              'Log detailed errors server-side, but return generic messages to clients.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/VERBOSE_ERRORS',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.OVERPRIVILEGED_TOOL,
    severity: Severity.HIGH,
    title: 'Tool Has Dangerous Permissions',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        if (!tool.permissions || tool.permissions.length === 0) continue;
        const matched = tool.permissions.filter((p) =>
          DANGEROUS_PERMISSIONS.includes(p)
        );
        if (matched.length > 0) {
          findings.push({
            ruleId: RuleId.OVERPRIVILEGED_TOOL,
            severity: Severity.HIGH,
            title: 'Tool Has Dangerous Permissions',
            description:
              `Tool "${tool.name}" has been granted dangerous permissions: ${matched.join(', ')}. ` +
              'Overprivileged tools can be exploited to exfiltrate data, execute arbitrary commands, ' +
              'or compromise the host system.',
            evidence: `tool: ${tool.name}, permissions: [${matched.join(', ')}]`,
            remediation:
              'Apply the principle of least privilege. Grant tools only the permissions ' +
              'they strictly need. Avoid filesystem:write, network:*, and shell:exec unless absolutely required.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/OVERPRIVILEGED_TOOL',
          });
        }
      }
      return findings;
    },
  },
];
