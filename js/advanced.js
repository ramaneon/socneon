/**
 * SOCNeon ÔÇö advanced.js
 * IOC Extraction ┬À MITRE ATT&CK Mapping ┬À Threat Scoring
 * Correlation Engine ┬À Custom Rules Engine ┬À Report Generator
 * Advanced Search Parser
 */
'use strict';

window.SOCNeonAdvanced = (() => {

  /* ÔöÇÔöÇÔöÇ MITRE ATT&CK Data ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  const MITRE_TACTICS = [
    { id: 'TA0043', name: 'Reconnaissance',      short: 'Recon' },
    { id: 'TA0001', name: 'Initial Access',       short: 'Init Access' },
    { id: 'TA0002', name: 'Execution',            short: 'Execution' },
    { id: 'TA0003', name: 'Persistence',          short: 'Persistence' },
    { id: 'TA0004', name: 'Privilege Escalation', short: 'Priv Esc' },
    { id: 'TA0005', name: 'Defense Evasion',      short: 'Def Evasion' },
    { id: 'TA0006', name: 'Credential Access',    short: 'Cred Access' },
    { id: 'TA0007', name: 'Discovery',            short: 'Discovery' },
    { id: 'TA0008', name: 'Lateral Movement',     short: 'Lateral Mvmt' },
    { id: 'TA0011', name: 'Command & Control',    short: 'C2' },
    { id: 'TA0010', name: 'Exfiltration',         short: 'Exfil' },
    { id: 'TA0040', name: 'Impact',               short: 'Impact' },
  ];

  // technique ÔåÆ tactics mapping (only techniques relevant to our ruleset)
  const TECHNIQUES = [
    { id: 'T1595', name: 'Active Scanning',            tactics: ['TA0043'], rules: ['WEB-004','WEB-005'] },
    { id: 'T1190', name: 'Exploit Public-Facing App',  tactics: ['TA0001'], rules: ['WEB-001','WEB-002','WEB-003'] },
    { id: 'T1078', name: 'Valid Accounts',             tactics: ['TA0001','TA0003','TA0004'], rules: ['AUTH-003','ANOM-001'] },
    { id: 'T1059', name: 'Command/Script Interpreter', tactics: ['TA0002'], rules: ['SYS-001'] },
    { id: 'T1204', name: 'User Execution',             tactics: ['TA0002'], rules: ['SYS-004'] },
    { id: 'T1053', name: 'Scheduled Task/Job',         tactics: ['TA0002','TA0003'], rules: ['SYS-003'] },
    { id: 'T1136', name: 'Create Account',             tactics: ['TA0003'], rules: ['SYS-002'] },
    { id: 'T1027', name: 'Obfuscated Files/Info',      tactics: ['TA0005'], rules: ['MAL-002'] },
    { id: 'T1110', name: 'Brute Force',                tactics: ['TA0006'], rules: ['AUTH-001','AUTH-002'] },
    { id: 'T1003', name: 'OS Credential Dumping',      tactics: ['TA0006'], rules: ['SYS-001'] },
    { id: 'T1046', name: 'Network Service Discovery',  tactics: ['TA0007'], rules: ['NET-001','FW-001'] },
    { id: 'T1021', name: 'Remote Services',            tactics: ['TA0008'], rules: ['NET-004'] },
    { id: 'T1071', name: 'App Layer Protocol',         tactics: ['TA0011'], rules: ['MAL-001','NET-005'] },
    { id: 'T1571', name: 'Non-Standard Port',          tactics: ['TA0011'], rules: ['NET-002'] },
    { id: 'T1041', name: 'Exfil Over C2',              tactics: ['TA0010'], rules: ['NET-003'] },
    { id: 'T1499', name: 'Endpoint DoS',               tactics: ['TA0040'], rules: ['ANOM-002'] },
  ];

  function getMITREMappings(findings) {
    const firedRules = new Set(findings.map(f => f.ruleId));
    return TECHNIQUES.map(t => ({
      ...t,
      fired: t.rules.some(r => firedRules.has(r)),
      matchedRules: t.rules.filter(r => firedRules.has(r)),
      count: findings.filter(f => t.rules.includes(f.ruleId)).length,
    }));
  }

  /* ÔöÇÔöÇÔöÇ IOC Extractor ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  const RE_IPV4    = /\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const RE_DOMAIN  = /\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,})\b/gi;
  const RE_MD5     = /\b[a-f0-9]{32}\b/gi;
  const RE_SHA1    = /\b[a-f0-9]{40}\b/gi;
  const RE_SHA256  = /\b[a-f0-9]{64}\b/gi;
  const RE_URL     = /https?:\/\/[^\s"'<>]+/gi;
  const RE_EMAIL   = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/g;
  const RE_CVE     = /CVE-\d{4}-\d{4,7}/gi;

  const PRIVATE_RANGES = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./,
                          /^169\.254\./, /^0\./, /^255\.255\.255\.255$/];
  const isPrivate = ip => PRIVATE_RANGES.some(r => r.test(ip));
  const BENIGN_DOMAINS = new Set(['www.google.com','fonts.googleapis.com','fonts.gstatic.com',
    'cdn.jsdelivr.net','cloudflare.com','amazonaws.com']);

  function extractIOCs(events) {
    const ips      = new Map(); // ip ÔåÆ { count, isPrivate, seenIn[] }
    const domains  = new Map();
    const hashes   = new Map();
    const urls     = new Map();
    const emails   = new Set();
    const cves     = new Set();
    const users    = new Map();
    const hosts    = new Map();

    events.forEach((ev, idx) => {
      // Structured fields
      ['src_ip','dst_ip'].forEach(f => {
        if (ev[f] && /^\d+\.\d+/.test(ev[f])) {
          const e = ips.get(ev[f]) || { count: 0, private: isPrivate(ev[f]), events: [] };
          e.count++; e.events.push(idx);
          ips.set(ev[f], e);
        }
      });
      if (ev.username && ev.username !== '-') {
        const e = users.get(ev.username) || { count: 0, events: [] };
        e.count++; e.events.push(idx);
        users.set(ev.username, e);
      }
      if (ev.hostname && ev.hostname !== '-') {
        const e = hosts.get(ev.hostname) || { count: 0, events: [] };
        e.count++; e.events.push(idx);
        hosts.set(ev.hostname, e);
      }
      if (ev.url) {
        const e = urls.get(ev.url) || { count: 0, events: [] };
        e.count++; e.events.push(idx);
        urls.set(ev.url, e);
      }
      if (ev.hash) {
        const h = ev.hash.toLowerCase().trim();
        const e = hashes.get(h) || { count: 0, events: [], type: h.length === 32 ? 'MD5' : h.length === 40 ? 'SHA1' : 'SHA256' };
        e.count++; e.events.push(idx);
        hashes.set(h, e);
      }

      // Free-text scan on message and raw line
      const text = [ev.message, ev._raw_line].filter(Boolean).join(' ');
      if (!text) return;

      for (const m of (text.match(RE_IPV4) || [])) {
        if (!ips.has(m)) ips.set(m, { count: 0, private: isPrivate(m), events: [] });
        ips.get(m).count++;
      }
      for (const m of (text.match(RE_URL) || [])) {
        if (!urls.has(m)) urls.set(m, { count: 0, events: [] });
        urls.get(m).count++;
      }
      for (const m of (text.match(RE_SHA256) || [])) {
        if (!hashes.has(m)) hashes.set(m, { count: 0, events: [], type: 'SHA256' });
        hashes.get(m).count++;
      }
      for (const m of (text.match(RE_MD5) || [])) {
        if (!hashes.has(m)) hashes.set(m, { count: 0, events: [], type: 'MD5' });
        hashes.get(m).count++;
      }
      for (const m of (text.match(RE_EMAIL) || [])) emails.add(m);
      for (const m of (text.match(RE_CVE) || [])) cves.add(m.toUpperCase());
    });

    // Sort by count desc
    const sortMap = m => [...m.entries()].sort((a, b) => b[1].count - a[1].count);

    return {
      ips:     sortMap(ips),
      domains: sortMap(domains),
      hashes:  sortMap(hashes),
      urls:    sortMap(urls),
      users:   sortMap(users),
      hosts:   sortMap(hosts),
      emails:  [...emails],
      cves:    [...cves],
    };
  }

  /* ÔöÇÔöÇÔöÇ Threat Score ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  function calculateThreatScore(findings, events) {
    if (!findings.length) return { score: 0, label: 'Clean', breakdown: {} };

    const weights = { critical: 25, high: 10, medium: 4, low: 1, info: 0.2 };
    const maxPossible = 100;

    let raw = 0;
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };

    findings.forEach(f => {
      const w = weights[f.severity] || 0;
      const conf = f.confidence / 100;
      raw += w * conf;
      if (breakdown[f.severity] !== undefined) breakdown[f.severity] += w * conf;
    });

    // Normalize + cap
    const score = Math.min(100, Math.round(raw));

    const label = score >= 80 ? 'CRITICAL RISK'
                : score >= 60 ? 'HIGH RISK'
                : score >= 40 ? 'MEDIUM RISK'
                : score >= 20 ? 'LOW RISK'
                : 'MINIMAL';

    return { score, label, breakdown, total: findings.length };
  }

  /* ÔöÇÔöÇÔöÇ Correlation Engine ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  function correlateEvents(findings, events) {
    if (!findings.length) return [];

    const WINDOW_MS = 30 * 60 * 1000; // 30 min correlation window

    // Group findings by source IP
    const byIP = new Map();
    findings.forEach(f => {
      const ip = f.event?.src_ip || f.event?.hostname || 'unknown';
      if (!byIP.has(ip)) byIP.set(ip, []);
      byIP.get(ip).push(f);
    });

    const chains = [];

    byIP.forEach((fList, ip) => {
      if (fList.length < 2) return; // Need at least 2 findings to correlate

      // Sort by timestamp
      const sorted = fList.filter(f => f.timestamp)
                          .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      if (sorted.length < 2) return;

      // Build kill chain stage
      const STAGE_MAP = {
        'Reconnaissance': 1, 'Initial Access': 2, 'Web Attack': 2,
        'Authentication': 3, 'Credential Access': 3,
        'Execution': 4, 'Endpoint': 4,
        'Persistence': 5, 'Privilege Escalation': 5,
        'Lateral Movement': 6, 'Network': 6,
        'Command & Control': 7, 'Malware': 7,
        'Exfiltration': 8, 'Firewall': 2,
        'Anomaly': 3,
      };

      const maxSev = sorted.reduce((max, f) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[f.severity] || 4) < (order[max] || 4) ? f.severity : max;
      }, 'info');

      const stages = [...new Set(sorted.map(f => STAGE_MAP[f.category] || 0))]
        .sort((a, b) => a - b);

      const isKillChain = stages.length >= 3; // 3+ distinct stages = kill chain

      const timespan = sorted.length >= 2
        ? new Date(sorted[sorted.length - 1].timestamp) - new Date(sorted[0].timestamp)
        : 0;

      chains.push({
        ip,
        findings: sorted,
        severity: maxSev,
        categories: [...new Set(sorted.map(f => f.category))],
        stages,
        isKillChain,
        timespan,
        startTime: sorted[0].timestamp,
        endTime: sorted[sorted.length - 1].timestamp,
        ruleIds: [...new Set(sorted.map(f => f.ruleId))],
      });
    });

    // Sort by severity + finding count
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return chains.sort((a, b) =>
      (sevOrder[a.severity] - sevOrder[b.severity]) || (b.findings.length - a.findings.length)
    );
  }

  /* ÔöÇÔöÇÔöÇ Custom Rules Engine ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  const CUSTOM_RULES_KEY = 'socneon_custom_rules';

  function loadCustomRules() {
    try {
      return JSON.parse(localStorage.getItem(CUSTOM_RULES_KEY) || '[]');
    } catch { return []; }
  }

  function saveCustomRules(rules) {
    localStorage.setItem(CUSTOM_RULES_KEY, JSON.stringify(rules));
  }

  function applyCustomRules(events, customRules) {
    const findings = [];
    customRules.forEach(rule => {
      events.forEach((event, idx) => {
        let matched = false;
        try {
          const val = String(event[rule.field] || event[`_extra_${rule.field}`] || '').toLowerCase();
          const target = rule.value.toLowerCase();
          switch (rule.operator) {
            case 'contains': matched = val.includes(target); break;
            case 'equals':   matched = val === target; break;
            case 'starts':   matched = val.startsWith(target); break;
            case 'ends':     matched = val.endsWith(target); break;
            case 'regex':    matched = new RegExp(rule.value, 'i').test(val); break;
            case 'gt':       matched = parseFloat(val) > parseFloat(target); break;
            case 'lt':       matched = parseFloat(val) < parseFloat(target); break;
          }
        } catch (_) {}

        if (matched) {
          findings.push({
            id: `CUSTOM-${rule.id}-${idx}`,
            eventIndex: idx,
            event,
            ruleId: `CUST-${rule.id.toString().slice(-3)}`,
            title: rule.name,
            severity: rule.severity,
            category: 'Custom',
            confidence: 80,
            explanation: `Custom rule "${rule.name}": field "${rule.field}" ${rule.operator} "${rule.value}"`,
            evidence: { field: rule.field, value: String(event[rule.field] || '').slice(0, 100) },
            description: rule.name,
            timestamp: event._ts ? event._ts.toISOString() : null,
            isCustom: true,
          });
        }
      });
    });
    return findings;
  }

  /* ÔöÇÔöÇÔöÇ Advanced Search Parser ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  /**
   * Parses queries like:
   *   src_ip:10.0.0.1         ÔåÆ field:value
   *   NOT ssh                 ÔåÆ negation
   *   attack OR scan          ÔåÆ OR logic
   *   failed AND login        ÔåÆ AND logic (default)
   *   /pattern/               ÔåÆ regex
   */
  function buildSearchFilter(query) {
    if (!query || !query.trim()) return () => true;

    const q = query.trim();

    // Field:value syntax
    const fieldMatch = q.match(/^(\w+):\s*"?(.+?)"?$/);
    if (fieldMatch) {
      const [, field, value] = fieldMatch;
      const v = value.toLowerCase();
      return ev => String(ev[field] || '').toLowerCase().includes(v);
    }

    // Regex /pattern/
    const regexMatch = q.match(/^\/(.+)\/([gimsuy]*)$/);
    if (regexMatch) {
      try {
        const re = new RegExp(regexMatch[1], regexMatch[2] || 'i');
        return ev => Object.values(ev).some(val => re.test(String(val)));
      } catch { /* fall through */ }
    }

    // OR logic
    if (q.toUpperCase().includes(' OR ')) {
      const parts = q.split(/\s+OR\s+/i).map(p => p.trim());
      const filters = parts.map(buildSearchFilter);
      return ev => filters.some(f => f(ev));
    }

    // AND logic (explicit or implicit)
    if (q.toUpperCase().includes(' AND ')) {
      const parts = q.split(/\s+AND\s+/i).map(p => p.trim());
      const filters = parts.map(buildSearchFilter);
      return ev => filters.every(f => f(ev));
    }

    // NOT prefix
    if (q.toUpperCase().startsWith('NOT ')) {
      const inner = buildSearchFilter(q.slice(4).trim());
      return ev => !inner(ev);
    }

    // Default: full-text search
    const lower = q.toLowerCase();
    return ev => Object.values(ev).some(v => String(v).toLowerCase().includes(lower));
  }

  /* ÔöÇÔöÇÔöÇ Report Generator ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ */
  function generateReport(state) {
    const { raw, findings, filtered } = state;
    const score = calculateThreatScore(findings, filtered);
    const iocs  = extractIOCs(filtered);
    const mitreData = getMITREMappings(findings);
    const firedTechniques = mitreData.filter(t => t.fired);
    const now = new Date().toLocaleString();

    const sevColors = { critical: '#ff3860', high: '#ff8c00', medium: '#ffd700', low: '#00e5ff', info: '#8892b0' };

    const topAlerts = findings.slice(0, 15).map(f => `
      <tr>
        <td style="color:${sevColors[f.severity] || '#fff'};font-weight:700;white-space:nowrap">${f.severity.toUpperCase()}</td>
        <td><code style="font-size:11px">${f.ruleId}</code></td>
        <td>${f.title}</td>
        <td>${f.confidence}%</td>
        <td style="font-size:11px;color:#8892b0">${f.timestamp ? new Date(f.timestamp).toLocaleString() : 'ÔÇö'}</td>
      </tr>`).join('');

    const topIPs = iocs.ips.slice(0, 10).map(([ip, data]) =>
      `<tr><td style="font-family:monospace">${ip}</td>
           <td>${data.private ? 'Internal' : '<span style="color:#ff3860">External</span>'}</td>
           <td>${data.count}</td></tr>`
    ).join('');

    const mitreRows = firedTechniques.map(t =>
      `<tr><td><code>${t.id}</code></td><td>${t.name}</td>
           <td>${t.matchedRules.join(', ')}</td><td>${t.count}</td></tr>`
    ).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SOCNeon Report ÔÇö ${now}</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #050a13; color: #e2e8f5; margin: 0; padding: 2rem; }
  h1 { color: #00e5ff; font-size: 2rem; } h2 { color: #8892b0; border-bottom: 1px solid #1e2d4a; padding-bottom: .5rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th { background: #0d1626; color: #8892b0; text-align: left; padding: .5rem .75rem; font-size: .75rem; text-transform: uppercase; }
  td { padding: .45rem .75rem; border-bottom: 1px solid #1e2d4a; font-size: .85rem; }
  .score { font-size: 4rem; color: ${sevColors[score.score >= 80 ? 'critical' : score.score >= 60 ? 'high' : score.score >= 40 ? 'medium' : 'low'] || '#00e5ff'}; font-weight: 700; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 12px; font-size: .7rem; font-weight: 700; background: #1e2d4a; }
  @media print { body { background: white; color: black; } th { background: #f0f0f0; color: #333; } }
</style>
</head>
<body>
<h1>­ƒøí SOCNeon Security Report</h1>
<p style="color:#8892b0">Generated: ${now} | Format: ${raw?.format || 'ÔÇö'} | Events: ${raw?.total?.toLocaleString() || 0}</p>

<h2>Threat Score</h2>
<div class="score">${score.score}/100</div>
<p style="color:#8892b0">${score.label} ÔÇö ${score.total} total findings</p>

<h2>Findings Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
${['critical','high','medium','low','info'].map(s =>
  `<tr><td style="color:${sevColors[s]};font-weight:700">${s.toUpperCase()}</td><td>${
    findings.filter(f=>f.severity===s).length}</td></tr>`).join('')}
</table>

<h2>Top 15 Alerts</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Confidence</th><th>Time</th></tr>${topAlerts}</table>

<h2>Extracted IOCs ÔÇö Top IPs</h2>
<table><tr><th>IP Address</th><th>Type</th><th>Event Count</th></tr>${topIPs || '<tr><td colspan="3">No IPs extracted</td></tr>'}</table>

<h2>MITRE ATT&CK Coverage (${firedTechniques.length} techniques)</h2>
<table><tr><th>Technique</th><th>Name</th><th>Rules</th><th>Findings</th></tr>${mitreRows || '<tr><td colspan="4">No techniques mapped</td></tr>'}</table>

<p style="color:#4a5568;font-size:.75rem;margin-top:3rem">SOCNeon ÔÇö All analysis is client-side. This report contains no external links or tracking.</p>
</body></html>`;

    return html;
  }

  return {
    MITRE_TACTICS, TECHNIQUES,
    getMITREMappings,
    extractIOCs,
    calculateThreatScore,
    correlateEvents,
    loadCustomRules, saveCustomRules, applyCustomRules,
    buildSearchFilter,
    generateReport,
  };
})();
