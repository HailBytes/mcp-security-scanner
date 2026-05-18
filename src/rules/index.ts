import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';

/**
 * A security rule that checks a parsed MCP config.
 */
export interface Rule {
  id: RuleId;
  severity: Severity;
  title: string;
  check(config: ParsedMcpConfig): Finding[];
}

// Lazy imports to avoid circular deps at build time
import { authRules } from './auth-rules.js';
import { injectionRules } from './injection-rules.js';
import { configRules } from './config-rules.js';

/**
 * Return all registered security rules.
 */
export function getAllRules(): Rule[] {
  return [...authRules, ...injectionRules, ...configRules];
}
