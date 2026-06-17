import { promises as fs } from 'fs';
import { ScanConfig } from './types.js';

/**
 * A parsed, normalized representation of an MCP server configuration.
 */
export interface ParsedMcpConfig {
  serverUrl?: string;
  transport?: {
    url?: string;
    tls?: boolean;
    auth?: {
      type?: string;
      apiKey?: string;
      token?: string;
    };
  };
  cors?: {
    origins?: string[];
  };
  verboseErrors?: boolean;
  debug?: boolean;
  rateLimit?: {
    enabled?: boolean;
    requestsPerMinute?: number;
  };
  tools?: Array<{
    name: string;
    description?: string;
    outputPath?: string;
    permissions?: string[];
  }>;
  /** All string values extracted from the raw config (for secret scanning). */
  rawStrings?: string[];
}

/**
 * Parse a minimal YAML config into a flat key-value object.
 * Supports simple "key: value" lines and basic nested sections.
 */
function parseSimpleYaml(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = content.split('\n');
  let currentSection: string | null = null;
  let currentSectionObj: Record<string, unknown> = {};
  let currentList: string[] | null = null;
  let currentListKey: string | null = null;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip comments and blank lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Detect indented list items
    if (trimmed.startsWith('- ') && currentListKey) {
      if (!currentList) {
        currentList = [];
        if (currentSection) {
          (currentSectionObj as Record<string, unknown>)[currentListKey] = currentList;
        } else {
          result[currentListKey] = currentList;
        }
      }
      currentList.push(trimmed.slice(2).trim());
      continue;
    }

    // Detect section header (key with no value, indented content follows)
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();

    // Detect indented key (part of a section)
    const isIndented = line.startsWith('  ') || line.startsWith('\t');

    if (!value) {
      // Section header
      if (currentSection && currentSectionObj) {
        result[currentSection] = currentSectionObj;
      }
      if (!isIndented) {
        currentSection = key;
        currentSectionObj = {};
        currentList = null;
        currentListKey = key;
      }
    } else {
      currentList = null;
      currentListKey = key;

      // Parse booleans and numbers
      let parsedValue: unknown = value;
      if (value === 'true') parsedValue = true;
      else if (value === 'false') parsedValue = false;
      else if (!isNaN(Number(value)) && value !== '') parsedValue = Number(value);
      else if ((value.startsWith('"') && value.endsWith('"')) ||
               (value.startsWith("'") && value.endsWith("'"))) {
        parsedValue = value.slice(1, -1);
      }

      if (isIndented && currentSection) {
        currentSectionObj[key] = parsedValue;
      } else {
        if (currentSection) {
          result[currentSection] = currentSectionObj;
          currentSection = null;
          currentSectionObj = {};
        }
        result[key] = parsedValue;
      }
    }
  }

  // Flush last section
  if (currentSection) {
    result[currentSection] = currentSectionObj;
  }

  return result;
}

/**
 * Recursively extract all string values from a parsed object for secret scanning.
 *
 * For an object's string value we push a reconstructed `"key: value"` form
 * rather than the bare value. This preserves the surrounding key context that
 * patterns like the password detector (`password: <value>`) depend on — without
 * it, those key-aware patterns can never match a structured JSON/YAML config,
 * because the value ("hunter2") is extracted in isolation from its "password"
 * key. Token-shaped patterns (`sk-...`, `ghp_...`, `AKIA...`) are unanchored and
 * still match inside the `"key: value"` form. Strings inside arrays (which have
 * no key context) are pushed bare.
 */
function extractStrings(value: unknown, result: string[] = []): string[] {
  if (typeof value === 'string') {
    result.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) extractStrings(item, result);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === 'string') {
        result.push(`${key}: ${v}`);
      } else {
        extractStrings(v, result);
      }
    }
  }
  return result;
}

/**
 * Map a raw config object to a normalized ParsedMcpConfig.
 */
function normalizeConfig(raw: Record<string, unknown>): ParsedMcpConfig {
  const config: ParsedMcpConfig = {};

  if (typeof raw['serverUrl'] === 'string') {
    config.serverUrl = raw['serverUrl'];
  }

  if (raw['transport'] && typeof raw['transport'] === 'object') {
    const t = raw['transport'] as Record<string, unknown>;
    config.transport = {};
    if (typeof t['url'] === 'string') config.transport.url = t['url'];
    if (typeof t['tls'] === 'boolean') config.transport.tls = t['tls'];
    if (t['auth'] && typeof t['auth'] === 'object') {
      const a = t['auth'] as Record<string, unknown>;
      config.transport.auth = {};
      if (typeof a['type'] === 'string') config.transport.auth.type = a['type'];
      if (typeof a['apiKey'] === 'string') config.transport.auth.apiKey = a['apiKey'];
      if (typeof a['token'] === 'string') config.transport.auth.token = a['token'];
    }
  }

  if (raw['cors'] && typeof raw['cors'] === 'object') {
    const c = raw['cors'] as Record<string, unknown>;
    config.cors = {};
    if (Array.isArray(c['origins'])) {
      config.cors.origins = c['origins'] as string[];
    }
  }

  if (typeof raw['verboseErrors'] === 'boolean') {
    config.verboseErrors = raw['verboseErrors'];
  }

  if (typeof raw['debug'] === 'boolean') {
    config.debug = raw['debug'];
  }

  if (raw['rateLimit'] && typeof raw['rateLimit'] === 'object') {
    const r = raw['rateLimit'] as Record<string, unknown>;
    config.rateLimit = {};
    if (typeof r['enabled'] === 'boolean') config.rateLimit.enabled = r['enabled'];
    if (typeof r['requestsPerMinute'] === 'number') {
      config.rateLimit.requestsPerMinute = r['requestsPerMinute'];
    }
  }

  if (Array.isArray(raw['tools'])) {
    config.tools = (raw['tools'] as Record<string, unknown>[]).map((tool) => ({
      name: typeof tool['name'] === 'string' ? tool['name'] : 'unknown',
      description: typeof tool['description'] === 'string' ? tool['description'] : undefined,
      outputPath: typeof tool['outputPath'] === 'string' ? tool['outputPath'] : undefined,
      permissions: Array.isArray(tool['permissions']) ? (tool['permissions'] as string[]) : undefined,
    }));
  }

  // Populate rawStrings for secret-scanning rules
  config.rawStrings = extractStrings(raw);

  return config;
}

/**
 * Parse a ScanConfig into a normalized ParsedMcpConfig.
 * Reads from a file if configPath is set, or constructs from serverUrl.
 */
export async function parseConfig(config: ScanConfig): Promise<ParsedMcpConfig> {
  const parsed: ParsedMcpConfig = {};

  if (config.serverUrl) {
    parsed.serverUrl = config.serverUrl;
    parsed.transport = {
      url: config.serverUrl,
      tls: config.serverUrl.startsWith('https://'),
    };
  }

  if (config.configPath) {
    const content = await fs.readFile(config.configPath, 'utf-8');
    let raw: Record<string, unknown>;

    if (config.configPath.endsWith('.json')) {
      raw = JSON.parse(content) as Record<string, unknown>;
    } else if (config.configPath.endsWith('.yaml') || config.configPath.endsWith('.yml')) {
      raw = parseSimpleYaml(content);
    } else {
      // Try JSON first, fall back to YAML
      try {
        raw = JSON.parse(content) as Record<string, unknown>;
      } catch {
        raw = parseSimpleYaml(content);
      }
    }

    const fileConfig = normalizeConfig(raw);

    // Merge file config into parsed (file config wins)
    return { ...parsed, ...fileConfig };
  }

  return parsed;
}
