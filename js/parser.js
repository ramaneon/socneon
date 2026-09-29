/**
 * SOC Log Analyzer — parser.js
 * Handles: CSV, JSON array, JSONL/NDJSON, syslog (RFC 3164 / RFC 5424 / common text)
 * All parsing runs client-side; no data leaves the browser.
 */

'use strict';

/* ─── Field Normalization Map ─────────────────────────────────────────────── */
const FIELD_ALIASES = {
  // Timestamp
  timestamp: ['timestamp', 'time', 'datetime', 'date', '@timestamp', 'event_time',
               'log_time', 'ts', 'created_at', 'occurred_at'],
  // Source IP
  src_ip: ['src_ip', 'source_ip', 'srcip', 'src', 'source', 'client_ip',
            'remote_addr', 'remote_ip', 'attacker_ip', 'orig_h'],
  // Destination IP
  dst_ip: ['dst_ip', 'dest_ip', 'destination_ip', 'dstip', 'dst', 'dest',
            'server_ip', 'target_ip', 'resp_h'],
  // Source port
  src_port: ['src_port', 'sport', 'srcport', 'source_port', 'orig_p'],
  // Destination port
  dst_port: ['dst_port', 'dport', 'dstport', 'dest_port', 'destination_port', 'port', 'resp_p'],
  // Protocol
  protocol: ['protocol', 'proto', 'transport', 'l4_proto'],
  // Action / disposition
  action: ['action', 'disposition', 'verdict', 'result', 'outcome', 'status'],
  // Event type
  event_type: ['event_type', 'type', 'category', 'event_category', 'log_type',
               'event_id', 'eventid', 'event.type'],
  // Username
  username: ['username', 'user', 'user_name', 'account', 'login', 'actor',
              'initiator', 'subject_user', 'winlog.event_data.TargetUserName'],
  // Hostname
  hostname: ['hostname', 'host', 'computer', 'device', 'machine', 'endpoint',
              'node', 'agent_hostname'],
  // Process
  process: ['process', 'process_name', 'proc', 'application', 'app', 'program',
             'image', 'winlog.event_data.Image'],
  // Message / raw
  message: ['message', 'msg', 'description', 'details', 'raw', 'log', 'content', 'text'],
  // Severity
  severity: ['severity', 'level', 'priority', 'log_level', 'loglevel', 'syslog_severity'],
  // Bytes
  bytes: ['bytes', 'byte_count', 'total_bytes', 'bytes_total', 'network_bytes'],
  // URL / URI
  url: ['url', 'uri', 'request_url', 'http.request.url', 'dest_url'],
  // HTTP method
  http_method: ['method', 'http_method', 'request_method', 'http.request.method'],
  // HTTP status
  http_status: ['status_code', 'http_status', 'response_code', 'http.response.status_code'],
  // Country
  country: ['country', 'geo_country', 'src_country', 'geoip.country_name'],
  // File path
  file_path: ['file_path', 'filepath', 'file', 'path', 'filename'],
  // Hash
  hash: ['hash', 'md5', 'sha1', 'sha256', 'file_hash', 'checksum'],
};

/**
 * Normalize a raw record's fields into a canonical shape.
 * @param {Object} raw - flat key-value object
 * @returns {Object} normalized event
 */
function normalizeRecord(raw) {
  const norm = { _raw: raw, _normalized: true };

  for (const [canonical, aliases] of Object.entries(FIELD_ALIASES)) {
    for (const alias of aliases) {
      // Case-insensitive match
      const key = Object.keys(raw).find(
        k => k.toLowerCase() === alias.toLowerCase()
      );
      if (key !== undefined && raw[key] !== undefined && raw[key] !== '') {
        norm[canonical] = String(raw[key]).trim();
        break;
      }
    }
  }

  // Carry over any remaining unmapped fields
  for (const [k, v] of Object.entries(raw)) {
    if (!Object.values(FIELD_ALIASES).flat().includes(k.toLowerCase())) {
      norm[`_extra_${k}`] = v;
    }
  }

  // Parse / normalise timestamp
  if (norm.timestamp) {
    const parsed = tryParseDate(norm.timestamp);
    if (parsed) norm._ts = parsed;
  }

  return norm;
}

function tryParseDate(str) {
  if (!str) return null;
  // Epoch seconds / ms
  const num = Number(str);
  if (!isNaN(num) && num > 0) {
    return num < 1e12 ? new Date(num * 1000) : new Date(num);
  }
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
}

/* ─── CSV Parser ──────────────────────────────────────────────────────────── */
function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) throw new Error('CSV must have a header row and at least one data row.');

  const headers = splitCSVLine(lines[0]);
  const records = [];
  const errors  = [];

  for (let i = 1; i < lines.length; i++) {
    try {
      const values = splitCSVLine(lines[i]);
      if (values.every(v => v === '')) continue;
      const obj = {};
      headers.forEach((h, idx) => {
        obj[h.trim()] = values[idx] !== undefined ? values[idx] : '';
      });
      records.push(normalizeRecord(obj));
    } catch (e) {
      errors.push({ line: i + 1, error: e.message });
    }
  }
  return { records, errors, format: 'CSV', total: records.length };
}

function splitCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

/* ─── JSON Array Parser ───────────────────────────────────────────────────── */
function parseJSONArray(text) {
  let data;
  try { data = JSON.parse(text); } catch (e) {
    throw new Error(`Invalid JSON: ${e.message}`);
  }
  if (!Array.isArray(data)) {
    // Single object → wrap
    if (typeof data === 'object' && data !== null) data = [data];
    else throw new Error('JSON must be an array of objects or a single object.');
  }
  const records = data.map(item => normalizeRecord(flattenObject(item)));
  return { records, errors: [], format: 'JSON', total: records.length };
}

/* ─── JSONL / NDJSON Parser ───────────────────────────────────────────────── */
function parseJSONL(text) {
  const lines   = text.split(/\r?\n/).filter(l => l.trim());
  const records = [];
  const errors  = [];

  for (let i = 0; i < lines.length; i++) {
    try {
      const obj = JSON.parse(lines[i]);
      records.push(normalizeRecord(flattenObject(obj)));
    } catch (e) {
      errors.push({ line: i + 1, error: e.message });
    }
  }
  if (records.length === 0) throw new Error('No valid JSON lines found.');
  return { records, errors, format: 'JSONL', total: records.length };
}

/** Recursively flatten nested object → dot-notation keys */
function flattenObject(obj, prefix = '', depth = 0) {
  if (depth > 8) return { [prefix]: JSON.stringify(obj) };
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      Object.assign(out, flattenObject(v, key, depth + 1));
    } else if (Array.isArray(v)) {
      out[key] = v.join(', ');
    } else {
      out[key] = v;
    }
  }
  return out;
}

/* ─── Syslog Parser ───────────────────────────────────────────────────────── */
// Supports RFC 3164, RFC 5424, and common plain-text log formats
const SYSLOG_RFC5424 = /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/;
const SYSLOG_RFC3164 = /^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)/;
const SYSLOG_PLAIN   = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+(?:\[\d+\])?):\s*(.*)/;
const COMMON_LOG     = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)/;

const SYSLOG_SEVERITY = ['Emergency','Alert','Critical','Error','Warning','Notice','Informational','Debug'];
const SYSLOG_FACILITY = ['kern','user','mail','daemon','auth','syslog','lpr','news',
                          'uucp','cron','security','ftp','ntp','audit','alert','clock',
                          'local0','local1','local2','local3','local4','local5','local6','local7'];

function parseSyslog(text) {
  const lines   = text.split(/\r?\n/).filter(l => l.trim());
  const records = [];
  const errors  = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    try {
      let raw = null;

      let m = SYSLOG_RFC5424.exec(line);
      if (m) {
        const pri = parseInt(m[1]);
        raw = {
          timestamp: m[3], hostname: m[4], process: m[5],
          event_id: m[6], structured: m[7], message: m[8],
          severity: SYSLOG_SEVERITY[pri & 7],
          facility: SYSLOG_FACILITY[pri >> 3] || String(pri >> 3),
        };
      }

      if (!raw) {
        m = SYSLOG_RFC3164.exec(line);
        if (m) {
          const pri = parseInt(m[1]);
          raw = {
            timestamp: m[2], hostname: m[3], process: m[4], message: m[5],
            severity: SYSLOG_SEVERITY[pri & 7],
            facility: SYSLOG_FACILITY[pri >> 3] || String(pri >> 3),
          };
        }
      }

      if (!raw) {
        m = SYSLOG_PLAIN.exec(line);
        if (m) raw = { timestamp: m[1], hostname: m[2], process: m[3], message: m[4] };
      }

      if (!raw) {
        m = COMMON_LOG.exec(line);
        if (m) {
          const parts = m[4].split(' ');
          raw = {
            src_ip: m[1], username: m[2], timestamp: m[3],
            http_method: parts[0], url: parts[1],
            http_status: m[5], bytes: m[6], message: m[4],
          };
        }
      }

      if (!raw) {
        // Fallback: treat entire line as message
        raw = { message: line, timestamp: null };
      }

      raw._line_number = i + 1;
      raw._raw_line    = line;
      records.push(normalizeRecord(raw));
    } catch (e) {
      errors.push({ line: i + 1, error: e.message });
    }
  }

  if (records.length === 0) throw new Error('No syslog records parsed.');
  return { records, errors, format: 'Syslog', total: records.length };
}

/* ─── Auto-detect & dispatch ──────────────────────────────────────────────── */
/**
 * Auto-detect log format and parse.
 * @param {string} text - raw file content
 * @param {string} [hint] - optional format hint: 'csv'|'json'|'jsonl'|'syslog'
 * @returns {{ records, errors, format, total }}
 */
function parseLogs(text, hint = null) {
  const trimmed = text.trimStart();

  if (hint === 'csv') return parseCSV(text);
  if (hint === 'json') return parseJSONArray(text);
  if (hint === 'jsonl') return parseJSONL(text);
  if (hint === 'syslog') return parseSyslog(text);

  // Auto-detect
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    // Might be JSON array or JSONL
    if (trimmed.startsWith('[')) {
      try { return parseJSONArray(text); } catch (_) { /* fall through */ }
    }
    // Try JSONL
    const firstLine = trimmed.split('\n')[0].trim();
    if (firstLine.startsWith('{')) {
      try { return parseJSONL(text); } catch (_) { /* fall through */ }
    }
    // Last resort JSON
    try { return parseJSONArray(text); } catch (e) {
      throw new Error(`Could not parse as JSON/JSONL: ${e.message}`);
    }
  }

  // CSV: first line contains commas and no syslog patterns
  const firstLine = trimmed.split('\n')[0];
  const looksCSV  = (firstLine.match(/,/g) || []).length >= 2 &&
                    !SYSLOG_RFC3164.test(firstLine) &&
                    !SYSLOG_PLAIN.test(firstLine);
  if (looksCSV) {
    try { return parseCSV(text); } catch (_) { /* fall through */ }
  }

  // Syslog / plain text
  return parseSyslog(text);
}

/* ─── Exports ─────────────────────────────────────────────────────────────── */
window.SOCParser = { parseLogs, normalizeRecord, FIELD_ALIASES };
