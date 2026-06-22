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

/** A non-blank YAML line, with its leading-space indentation measured. */
interface YamlLine {
  indent: number;
  text: string;
}

/**
 * Strip a YAML comment from a line. A `#` only starts a comment when it is at
 * the start of the (trimmed) line or preceded by whitespace, so values such as
 * URLs (`https://…`) are left intact.
 */
function stripYamlComment(line: string): string {
  if (line.trimStart().startsWith('#')) return '';
  const idx = line.search(/\s#/);
  return idx === -1 ? line : line.slice(0, idx);
}

/**
 * Find the index of the key/value separator colon in a mapping entry. Per YAML,
 * a colon only separates a key from its value when it is followed by whitespace
 * or ends the line — so `url: wss://x` splits at the first colon, while a plain
 * scalar like `shell:exec` or `filesystem:*` has no separator (returns -1).
 */
function findMappingColon(text: string): number {
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ':' && (i === text.length - 1 || text[i + 1] === ' ')) {
      return i;
    }
  }
  return -1;
}

/** Coerce a scalar YAML token into a boolean, number, or (unquoted) string. */
function parseYamlScalar(value: string): unknown {
  if (value === '' || value === '~' || value === 'null') return null;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  if (!isNaN(Number(value))) return Number(value);
  return value;
}

/**
 * Parse a mapping block whose entries all sit at exactly `indent` columns,
 * starting at line `start`. Returns the parsed object and the index of the
 * first line that no longer belongs to the block.
 */
function parseYamlMap(
  lines: YamlLine[],
  start: number,
  indent: number
): [Record<string, unknown>, number] {
  const obj: Record<string, unknown> = {};
  let i = start;

  while (i < lines.length) {
    const line = lines[i];
    if (line.indent < indent) break; // dedent → end of this block
    if (line.indent > indent || line.text.startsWith('- ')) {
      // Unexpected deeper content or a sequence at this level: stop and let the
      // caller handle it rather than mis-attributing it to a key.
      break;
    }

    const colon = findMappingColon(line.text);
    if (colon === -1) break; // not a mapping entry

    const key = line.text.slice(0, colon).trim();
    const rest = line.text.slice(colon + 1).trim();

    if (rest !== '') {
      obj[key] = parseYamlScalar(rest);
      i += 1;
      continue;
    }

    // Empty value → a nested block (map or sequence) follows, if anything does.
    const childStart = i + 1;
    if (childStart < lines.length) {
      const child = lines[childStart];
      if (child.text.startsWith('- ') && child.indent >= indent) {
        const [seq, next] = parseYamlSequence(lines, childStart, child.indent);
        obj[key] = seq;
        i = next;
        continue;
      }
      if (child.indent > indent) {
        const [map, next] = parseYamlMap(lines, childStart, child.indent);
        obj[key] = map;
        i = next;
        continue;
      }
    }
    obj[key] = null;
    i = childStart;
  }

  return [obj, i];
}

/**
 * Parse a sequence block whose `- ` items sit at exactly `indent` columns.
 * Handles scalar items (`- shell:exec`) and map items (`- name: foo` plus any
 * subsequent indented keys).
 */
function parseYamlSequence(
  lines: YamlLine[],
  start: number,
  indent: number
): [unknown[], number] {
  const arr: unknown[] = [];
  let i = start;

  while (i < lines.length) {
    const line = lines[i];
    if (line.indent < indent) break;
    if (line.indent > indent || !line.text.startsWith('- ')) break;

    const itemText = line.text.slice(2).trim();
    const colon = itemText === '' ? -1 : findMappingColon(itemText);

    if (colon === -1) {
      // Scalar list item (or an empty dash with a nested block beneath it).
      if (itemText === '' && i + 1 < lines.length && lines[i + 1].indent > indent) {
        const [map, next] = parseYamlMap(lines, i + 1, lines[i + 1].indent);
        arr.push(map);
        i = next;
      } else {
        arr.push(parseYamlScalar(itemText));
        i += 1;
      }
      continue;
    }

    // Map item: the inline `key: value` plus any continuation keys indented to
    // the column just after the "- ". Rewrite the dash line as a plain mapping
    // entry at that column and let parseYamlMap consume it and its siblings.
    const contentIndent = indent + 2;
    lines[i] = { indent: contentIndent, text: itemText };
    const [map, next] = parseYamlMap(lines, i, contentIndent);
    arr.push(map);
    i = next;
  }

  return [arr, i];
}

/**
 * Parse a YAML config into a nested key-value object.
 *
 * Supports the structures an MCP config actually uses: scalars, nested maps of
 * arbitrary depth (e.g. `transport.auth.*`), sequences of scalars (e.g.
 * `permissions:`), and sequences of maps (e.g. `tools:`). Indentation-driven,
 * with no external dependency.
 */
function parseSimpleYaml(content: string): Record<string, unknown> {
  const lines: YamlLine[] = [];
  for (const raw of content.split('\n')) {
    const stripped = stripYamlComment(raw);
    if (stripped.trim() === '') continue;
    lines.push({ indent: stripped.length - stripped.trimStart().length, text: stripped.trim() });
  }

  if (lines.length === 0) return {};
  const [value] = parseYamlMap(lines, 0, lines[0].indent);
  return value;
}

/**
 * Recursively extract all string values from a parsed object.
 */
function extractStrings(value: unknown, result: string[] = []): string[] {
  if (typeof value === 'string') {
    result.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) extractStrings(item, result);
  } else if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      extractStrings(v, result);
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
