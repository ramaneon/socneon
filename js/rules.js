/**
 * SOC Log Analyzer — rules.js
 * Explainable, client-side detection rules engine.
 * Each rule produces a finding with: id, title, severity, confidence, explanation, evidence.
 */

'use strict';

/* ─── Severity Enum ───────────────────────────────────────────────────────── */
const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };

/* ─── Helper predicates ───────────────────────────────────────────────────── */
const contains = (haystack, needle) =>
  typeof haystack === 'string' && haystack.toLowerCase().includes(needle.toLowerCase());

const matches = (val, regex) =>
  typeof val === 'string' && regex.test(val);

const isPrivateIP = ip => {
  if (!ip || typeof ip !== 'string') return false;
  return /^10\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
         /^192\.168\./.test(ip) || /^127\./.test(ip) || /^::1$/.test(ip) ||
         /^fc[0-9a-f]{2}:/i.test(ip);
};

const isPublicIP = ip => ip && !isPrivateIP(ip) && ip !== '-' && /^\d{1,3}\.\d{1,3}\./.test(ip);

/** Count events matching a predicate within a time window (ms) */
function countInWindow(events, predicate, anchorTs, windowMs) {
  return events.filter(e =>
    predicate(e) &&
    e._ts instanceof Date &&
    Math.abs(e._ts.getTime() - anchorTs) <= windowMs
  ).length;
}

/** Group events by a key extractor */
function groupBy(events, keyFn) {
  const map = new Map();
  for (const e of events) {
    const k = keyFn(e);
    if (k == null) continue;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(e);
  }
  return map;
}

/* ─── Individual Rule Definitions ────────────────────────────────────────────
 *  Each rule: { id, title, severity, category, description, check(event, allEvents) }
 *  check() returns null | { matched: bool, confidence, explanation, evidence }
 * ─────────────────────────────────────────────────────────────────────────── */
const RULES = [

  /* ── Authentication ─────────────────────────────────────────────────────── */
  {
    id: 'AUTH-001',
    title: 'Brute-Force Login Attempt',
    severity: SEVERITY.HIGH,
    category: 'Authentication',
    description: 'Multiple failed login events from the same source within a short window.',
    check(event, allEvents) {
      const failWords = ['fail', 'failure', 'invalid', 'wrong', 'incorrect', 'denied',
                         'authentication failure', 'bad password', 'logon failure'];
      const isFailedAuth = failWords.some(w =>
        contains(event.message, w) || contains(event.action, w) || contains(event.event_type, w)
      );
      if (!isFailedAuth) return null;

      const srcKey = event.src_ip || event.username || event.hostname;
      if (!srcKey) return null;

      const windowMs = 5 * 60 * 1000; // 5 minutes
      const anchorTs = event._ts ? event._ts.getTime() : null;

      if (!anchorTs) {
        // No timestamp: match on keyword alone, low confidence
        return {
          matched: true, confidence: 40,
          explanation: 'Failed authentication keyword detected, but no timestamp to correlate rate.',
          evidence: { message: event.message, action: event.action },
        };
      }

      const count = countInWindow(allEvents, e => {
        const isFail = failWords.some(w =>
          contains(e.message, w) || contains(e.action, w));
        const sameSource = (e.src_ip === event.src_ip && event.src_ip) ||
                           (e.username === event.username && event.username);
        return isFail && sameSource;
      }, anchorTs, windowMs);

      if (count < 3) return null;

      const confidence = Math.min(95, 50 + count * 5);
      return {
        matched: true, confidence,
        explanation: `${count} failed login attempts from "${srcKey}" within 5 minutes. ` +
                     `Threshold: ≥3 failures in 5 min. Suggests automated brute-force or password spray.`,
        evidence: { source: srcKey, failure_count: count, window: '5 min' },
      };
    },
  },

  {
    id: 'AUTH-002',
    title: 'Successful Login After Multiple Failures',
    severity: SEVERITY.HIGH,
    category: 'Authentication',
    description: 'A successful login was preceded by failed attempts from the same source — classic brute-force success indicator.',
    check(event, allEvents) {
      const successWords = ['success', 'accepted', 'logged in', 'authenticated', 'logon success'];
      const isSuccess = successWords.some(w =>
        contains(event.message, w) || contains(event.action, w));
      if (!isSuccess) return null;

      const src = event.src_ip || event.username;
      if (!src) return null;

      const windowMs = 30 * 60 * 1000;
      const anchorTs = event._ts ? event._ts.getTime() : null;
      if (!anchorTs) return null;

      const failWords = ['fail', 'failure', 'invalid', 'wrong', 'incorrect', 'denied'];
      const priorFails = allEvents.filter(e => {
        const t = e._ts ? e._ts.getTime() : null;
        if (!t || t >= anchorTs) return false;
        const isFail = failWords.some(w => contains(e.message, w) || contains(e.action, w));
        const sameSource = (e.src_ip === event.src_ip && event.src_ip) ||
                           (e.username === event.username && event.username);
        return isFail && sameSource && (anchorTs - t) <= windowMs;
      }).length;

      if (priorFails < 3) return null;

      return {
        matched: true, confidence: 85,
        explanation: `Successful authentication from "${src}" was preceded by ${priorFails} failures ` +
                     `in the prior 30 minutes. This is a strong indicator of successful brute-force.`,
        evidence: { source: src, prior_failures: priorFails, window: '30 min' },
      };
    },
  },

  {
    id: 'AUTH-003',
    title: 'Login from Unusual Hour',
    severity: SEVERITY.MEDIUM,
    category: 'Authentication',
    description: 'Successful authentication at an unusual time (00:00–05:00 local).',
    check(event) {
      const successWords = ['success', 'accepted', 'logged in', 'authenticated'];
      const isSuccess = successWords.some(w =>
        contains(event.message, w) || contains(event.action, w));
      if (!isSuccess || !event._ts) return null;

      const hour = event._ts.getHours();
      if (hour < 0 || hour >= 5) return null;

      return {
        matched: true, confidence: 55,
        explanation: `Authentication succeeded at ${event._ts.toLocaleTimeString()} (hour ${hour}), ` +
                     `which falls in the 00:00–05:00 window flagged as off-hours. ` +
                     `Could be legitimate remote work or an attacker using a compromised account.`,
        evidence: { time: event._ts.toISOString(), hour },
      };
    },
  },

  /* ── Network / Firewall ──────────────────────────────────────────────────── */
  {
    id: 'NET-001',
    title: 'Port Scan Detected',
    severity: SEVERITY.HIGH,
    category: 'Network',
    description: 'A single source IP contacted an unusual number of distinct destination ports.',
    check(event, allEvents) {
      if (!event.src_ip || !event.dst_port) return null;
      if (!event._ts) return null;

      const windowMs = 60 * 1000; // 1 minute
      const anchorTs = event._ts.getTime();

      const ports = new Set(
        allEvents
          .filter(e =>
            e.src_ip === event.src_ip &&
            e._ts instanceof Date &&
            Math.abs(e._ts.getTime() - anchorTs) <= windowMs &&
            e.dst_port)
          .map(e => e.dst_port)
      );

      if (ports.size < 10) return null;

      const confidence = Math.min(95, 60 + ports.size * 2);
      return {
        matched: true, confidence,
        explanation: `Source ${event.src_ip} contacted ${ports.size} distinct ports within 1 minute. ` +
                     `Threshold: ≥10 unique ports/min. Consistent with a TCP/UDP port scan.`,
        evidence: { src_ip: event.src_ip, unique_ports: ports.size, sample_ports: [...ports].slice(0, 10) },
      };
    },
  },

  {
    id: 'NET-002',
    title: 'Connection to Known Malicious Port',
    severity: SEVERITY.HIGH,
    category: 'Network',
    description: 'Traffic to/from a port commonly used by malware C2 or exploitation frameworks.',
    check(event) {
      const SUSPICIOUS_PORTS = {
        4444: 'Metasploit default listener',
        1337: 'Common backdoor/C2 port',
        31337: 'Elite/BackOrifice backdoor',
        6666: 'IRC botnet C2',
        6667: 'IRC botnet C2',
        9090: 'Common RAT/proxy port',
        8080: 'Alternate HTTP (often proxied C2)',
        4545: 'Common C2 port',
        5555: 'ADB Android debug (exposed)',
        2323: 'Telnet alternative (IoT malware)',
        23: 'Telnet (unencrypted remote)',
      };
      const port = parseInt(event.dst_port || event.src_port);
      if (!SUSPICIOUS_PORTS[port]) return null;

      return {
        matched: true, confidence: 70,
        explanation: `Port ${port} is flagged: "${SUSPICIOUS_PORTS[port]}". ` +
                     `While not conclusive, traffic on this port warrants investigation.`,
        evidence: { port, reason: SUSPICIOUS_PORTS[port], src: event.src_ip, dst: event.dst_ip },
      };
    },
  },

  {
    id: 'NET-003',
    title: 'Large Data Exfiltration (Bytes)',
    severity: SEVERITY.HIGH,
    category: 'Network',
    description: 'Unusually large outbound data transfer detected.',
    check(event) {
      const bytes = parseInt(event.bytes);
      if (isNaN(bytes) || bytes < 100_000_000) return null; // < 100 MB threshold

      const mb = (bytes / 1_048_576).toFixed(1);
      const confidence = bytes > 1_073_741_824 ? 85 : 65; // >1 GB → higher confidence

      return {
        matched: true, confidence,
        explanation: `${mb} MB transferred in a single session/record. ` +
                     `Threshold: >100 MB. Large transfers to external IPs can indicate data exfiltration.`,
        evidence: { bytes, megabytes: mb, src: event.src_ip, dst: event.dst_ip },
      };
    },
  },

  {
    id: 'NET-004',
    title: 'Internal-to-Internal Lateral Movement',
    severity: SEVERITY.MEDIUM,
    category: 'Network',
    description: 'Connection between two internal IPs on a sensitive port.',
    check(event) {
      const sensitivePorts = [22, 23, 3389, 5985, 5986, 135, 139, 445, 1433, 3306, 5432];
      const port = parseInt(event.dst_port);
      if (!sensitivePorts.includes(port)) return null;
      if (!isPrivateIP(event.src_ip) || !isPrivateIP(event.dst_ip)) return null;

      const portNames = {22:'SSH',23:'Telnet',3389:'RDP',5985:'WinRM',5986:'WinRM-SSL',
                         135:'RPC',139:'NetBIOS',445:'SMB',1433:'MSSQL',3306:'MySQL',5432:'PostgreSQL'};
      return {
        matched: true, confidence: 60,
        explanation: `Internal host ${event.src_ip} connected to ${event.dst_ip} on port ${port} (${portNames[port]}). ` +
                     `Lateral movement often uses RDP, SMB, WinRM, or SSH between internal hosts.`,
        evidence: { src: event.src_ip, dst: event.dst_ip, port, protocol_name: portNames[port] },
      };
    },
  },

  {
    id: 'NET-005',
    title: 'DNS Tunneling Indicator',
    severity: SEVERITY.MEDIUM,
    category: 'Network',
    description: 'Unusually long DNS query or high query frequency — possible DNS tunneling.',
    check(event) {
      const isDNS = parseInt(event.dst_port) === 53 || parseInt(event.src_port) === 53;
      if (!isDNS) return null;

      const urlLen = event.url ? event.url.length : 0;
      const msgLen = event.message ? event.message.length : 0;

      if (urlLen > 100 || msgLen > 200) {
        return {
          matched: true, confidence: 65,
          explanation: `DNS record with unusually long payload (URL: ${urlLen} chars, message: ${msgLen} chars). ` +
                       `DNS tunneling tools encode C2 data in subdomains, producing long queries.`,
          evidence: { url_length: urlLen, message_length: msgLen, url: (event.url || '').slice(0, 100) },
        };
      }
      return null;
    },
  },

  /* ── Web / HTTP ──────────────────────────────────────────────────────────── */
  {
    id: 'WEB-001',
    title: 'SQL Injection Attempt',
    severity: SEVERITY.CRITICAL,
    category: 'Web Attack',
    description: 'SQL injection patterns detected in HTTP request.',
    check(event) {
      const sqli = [
        /['"](\s*)(OR|AND)(\s+)\d+(\s*)=(\s*)\d+/i,
        /UNION(\s+)ALL(\s+)SELECT/i,
        /UNION(\s+)SELECT/i,
        /DROP(\s+)TABLE/i,
        /INSERT(\s+)INTO/i,
        /DELETE(\s+)FROM/i,
        /EXEC(\s*)\(/i,
        /xp_cmdshell/i,
        /information_schema/i,
        /sleep\(\d+\)/i,
        /benchmark\(\d+/i,
        /'(\s*)--/,
        /1=1/,
      ];
      const targets = [event.url, event.message, event._raw_line].filter(Boolean).join(' ');
      const hit = sqli.find(r => r.test(targets));
      if (!hit) return null;

      return {
        matched: true, confidence: 85,
        explanation: `SQL injection pattern matched: "${hit.source.slice(0, 60)}". ` +
                     `Request URL or message contains SQL keywords typical of injection attacks.`,
        evidence: { pattern: hit.source.slice(0, 80), url: event.url, src_ip: event.src_ip },
      };
    },
  },

  {
    id: 'WEB-002',
    title: 'Cross-Site Scripting (XSS) Attempt',
    severity: SEVERITY.HIGH,
    category: 'Web Attack',
    description: 'XSS payload patterns detected in HTTP request.',
    check(event) {
      const xss = [
        /<script[\s>]/i, /javascript:/i, /on\w+\s*=/i,
        /<img[^>]+src\s*=\s*['"]?javascript/i,
        /eval\s*\(/i, /document\.cookie/i, /window\.location/i,
        /&#x?[0-9a-f]+;/i,
        /alert\s*\(/i,
      ];
      const targets = [event.url, event.message].filter(Boolean).join(' ');
      const hit = xss.find(r => r.test(targets));
      if (!hit) return null;

      return {
        matched: true, confidence: 80,
        explanation: `XSS pattern matched: "${hit.source.slice(0, 60)}". ` +
                     `The request contains script injection markers.`,
        evidence: { pattern: hit.source.slice(0, 80), url: event.url, src_ip: event.src_ip },
      };
    },
  },

  {
    id: 'WEB-003',
    title: 'Path Traversal Attempt',
    severity: SEVERITY.HIGH,
    category: 'Web Attack',
    description: 'Directory traversal sequences detected in URL or request.',
    check(event) {
      const traversal = /(\.\.[\/\\]){2,}|%2e%2e[%2f%5c]/i;
      const targets = [event.url, event.message].filter(Boolean).join(' ');
      if (!traversal.test(targets)) return null;

      return {
        matched: true, confidence: 85,
        explanation: `Path traversal sequence (../ or %2e%2e) detected in request. ` +
                     `Attackers use traversal to access files outside the web root.`,
        evidence: { url: event.url, src_ip: event.src_ip },
      };
    },
  },

  {
    id: 'WEB-004',
    title: 'Scanner / Vulnerability Tool Detected',
    severity: SEVERITY.MEDIUM,
    category: 'Web Attack',
    description: 'Known security scanner user-agent or characteristic request pattern detected.',
    check(event) {
      const scanners = ['nikto', 'nmap', 'masscan', 'sqlmap', 'burpsuite', 'zap', 'wfuzz',
                        'dirb', 'dirbuster', 'gobuster', 'nuclei', 'metasploit', 'w3af',
                        'acunetix', 'nessus', 'openvas'];
      const target = [event.message, event.url].filter(Boolean).join(' ').toLowerCase();
      const found = scanners.find(s => target.includes(s));
      if (!found) return null;

      return {
        matched: true, confidence: 90,
        explanation: `Known security scanner identified: "${found}". ` +
                     `This string appears in the request, indicating automated scanning activity.`,
        evidence: { scanner: found, src_ip: event.src_ip },
      };
    },
  },

  {
    id: 'WEB-005',
    title: 'HTTP Error Storm (4xx/5xx)',
    severity: SEVERITY.MEDIUM,
    category: 'Web Attack',
    description: 'High volume of HTTP error responses from the same source.',
    check(event, allEvents) {
      const status = parseInt(event.http_status);
      if (!(status >= 400)) return null;
      if (!event.src_ip || !event._ts) return null;

      const windowMs = 60 * 1000;
      const anchorTs = event._ts.getTime();

      const count = countInWindow(allEvents, e => {
        const s = parseInt(e.http_status);
        return s >= 400 && e.src_ip === event.src_ip;
      }, anchorTs, windowMs);

      if (count < 20) return null;

      return {
        matched: true, confidence: 75,
        explanation: `${count} HTTP error responses (4xx/5xx) from ${event.src_ip} in 1 minute. ` +
                     `High error rates may indicate scanning, fuzzing, or credential stuffing.`,
        evidence: { src_ip: event.src_ip, error_count: count, sample_status: status },
      };
    },
  },

  /* ── System / Endpoint ───────────────────────────────────────────────────── */
  {
    id: 'SYS-001',
    title: 'Privileged Command Execution',
    severity: SEVERITY.HIGH,
    category: 'Endpoint',
    description: 'Commands associated with privilege escalation or administrative tool abuse.',
    check(event) {
      const suspCmds = [
        'whoami', 'net user', 'net localgroup', 'net group',
        'mimikatz', 'lsass', 'procdump', 'wce.exe', 'fgdump',
        'psexec', 'wmic', 'powershell -enc', 'powershell -e ',
        'cmd /c', 'rundll32', 'regsvr32', 'mshta', 'cscript',
        'wscript', 'certutil', 'bitsadmin', 'schtasks', 'at.exe',
      ];
      const target = [event.message, event.process, event.url].filter(Boolean).join(' ').toLowerCase();
      const found = suspCmds.find(c => target.includes(c.toLowerCase()));
      if (!found) return null;

      const severity = ['mimikatz','lsass','procdump','wce.exe','psexec'].includes(found)
        ? SEVERITY.CRITICAL : SEVERITY.HIGH;

      return {
        matched: true, confidence: 75, severity,
        explanation: `Suspicious command/process detected: "${found}". ` +
                     `This is associated with post-exploitation, credential dumping, or lateral movement.`,
        evidence: { command: found, process: event.process, host: event.hostname },
      };
    },
  },

  {
    id: 'SYS-002',
    title: 'New User Account Created',
    severity: SEVERITY.MEDIUM,
    category: 'Endpoint',
    description: 'A new user account was created — possible persistence mechanism.',
    check(event) {
      const patterns = [
        /user.*creat/i, /new.*account/i, /account.*creat/i,
        /useradd/i, /net user.*\/add/i, /event.?id.*4720/i,
      ];
      const target = [event.message, event.event_type].filter(Boolean).join(' ');
      if (!patterns.some(r => r.test(target))) return null;

      return {
        matched: true, confidence: 70,
        explanation: `User account creation event detected. ` +
                     `Attackers create accounts for persistence (Windows Event 4720 or useradd).`,
        evidence: { username: event.username, host: event.hostname, message: event.message?.slice(0, 120) },
      };
    },
  },

  {
    id: 'SYS-003',
    title: 'Scheduled Task / Cron Job Created',
    severity: SEVERITY.MEDIUM,
    category: 'Endpoint',
    description: 'Scheduled task or cron job creation — common persistence technique.',
    check(event) {
      const patterns = [/schtask/i, /cron/i, /at\.exe/i, /task.*creat/i, /event.?id.*4698/i];
      const target = [event.message, event.event_type, event.process].filter(Boolean).join(' ');
      if (!patterns.some(r => r.test(target))) return null;

      return {
        matched: true, confidence: 65,
        explanation: `Scheduled task/cron creation detected. ` +
                     `Persistence via scheduled tasks is a common APT technique (MITRE T1053).`,
        evidence: { host: event.hostname, message: event.message?.slice(0, 120) },
      };
    },
  },

  {
    id: 'SYS-004',
    title: 'Suspicious File Hash (Known Malware)',
    severity: SEVERITY.CRITICAL,
    category: 'Endpoint',
    description: 'File hash matches a known-bad indicator.',
    check(event) {
      // Sample known-bad hashes (MD5) for demo — replace with real threat intel feed
      const KNOWN_BAD = new Set([
        'd41d8cd98f00b204e9800998ecf8427e', // empty file (demo)
        '44d88612fea8a8f36de82e1278abb02f', // EICAR test signature MD5
        '275a021bbfb6489e54d471899f7db9d1', // EICAR SHA-1
      ]);
      const hash = (event.hash || '').toLowerCase().trim();
      if (!hash || !KNOWN_BAD.has(hash)) return null;

      return {
        matched: true, confidence: 98,
        explanation: `File hash "${hash}" matches a known malicious indicator in the local threat intelligence list.`,
        evidence: { hash, file: event.file_path, host: event.hostname },
      };
    },
  },

  /* ── Firewall / Access Control ───────────────────────────────────────────── */
  {
    id: 'FW-001',
    title: 'Firewall Rule Bypassed / Denied Traffic Spike',
    severity: SEVERITY.MEDIUM,
    category: 'Firewall',
    description: 'Repeated denied connections from a single source.',
    check(event, allEvents) {
      const denyWords = ['deny', 'denied', 'block', 'blocked', 'drop', 'reject', 'rejected'];
      const isDeny = denyWords.some(w => contains(event.action, w) || contains(event.message, w));
      if (!isDeny || !event.src_ip || !event._ts) return null;

      const windowMs = 5 * 60 * 1000;
      const anchorTs = event._ts.getTime();

      const count = countInWindow(allEvents, e => {
        const deny = denyWords.some(w => contains(e.action, w) || contains(e.message, w));
        return deny && e.src_ip === event.src_ip;
      }, anchorTs, windowMs);

      if (count < 15) return null;

      return {
        matched: true, confidence: 70,
        explanation: `${count} firewall DENY events from ${event.src_ip} in 5 minutes. ` +
                     `Could indicate reconnaissance, scanning, or failed exploitation attempts.`,
        evidence: { src_ip: event.src_ip, deny_count: count },
      };
    },
  },

  /* ── Malware / Indicators ────────────────────────────────────────────────── */
  {
    id: 'MAL-001',
    title: 'Known Malware C2 Domain / IP',
    severity: SEVERITY.CRITICAL,
    category: 'Malware',
    description: 'Connection to a known C2 infrastructure indicator.',
    check(event) {
      // Demo IOCs — in production, load from a threat intel feed
      const BAD_DOMAINS = ['evil.com', 'malware-c2.net', 'badactor.ru', 'ransomware-c2.onion'];
      const BAD_IPS     = ['185.220.101.1', '198.51.100.99', '203.0.113.50'];

      const url = (event.url || '').toLowerCase();
      const dst = (event.dst_ip || '').toLowerCase();
      const msg = (event.message || '').toLowerCase();

      const domainHit = BAD_DOMAINS.find(d => url.includes(d) || msg.includes(d));
      const ipHit     = BAD_IPS.find(ip => dst === ip || msg.includes(ip));

      if (!domainHit && !ipHit) return null;
      const indicator = domainHit || ipHit;

      return {
        matched: true, confidence: 90,
        explanation: `Connection to known malicious indicator: "${indicator}". ` +
                     `This IP/domain is listed in the local threat intelligence database.`,
        evidence: { indicator, src_ip: event.src_ip, dst_ip: event.dst_ip, url: event.url },
      };
    },
  },

  {
    id: 'MAL-002',
    title: 'Base64 Encoded Command',
    severity: SEVERITY.HIGH,
    category: 'Malware',
    description: 'Base64 encoded payload in command line — often used to obfuscate malicious commands.',
    check(event) {
      // Look for powershell -enc or long base64 strings
      const b64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
      const encPattern = /(-enc|-encoded|-EncodedCommand)/i;
      const target = [event.message, event.process].filter(Boolean).join(' ');

      if (!encPattern.test(target) && !b64Pattern.test(target)) return null;
      if (!encPattern.test(target)) return null; // Require -enc flag to reduce false positives

      return {
        matched: true, confidence: 75,
        explanation: `Base64-encoded command parameter detected (PowerShell -EncodedCommand or similar). ` +
                     `Attackers encode payloads to evade signature-based detection.`,
        evidence: { process: event.process, host: event.hostname },
      };
    },
  },

  /* ── Anomalous Behavior ──────────────────────────────────────────────────── */
  {
    id: 'ANOM-001',
    title: 'Service Account Interactive Login',
    severity: SEVERITY.MEDIUM,
    category: 'Anomaly',
    description: 'A service or system account performed an interactive login.',
    check(event) {
      const svcPatterns = [/^svc[-_]/i, /^service[-_]/i, /SYSTEM$/i, /^NT AUTHORITY/i];
      const user = event.username || '';
      if (!svcPatterns.some(p => p.test(user))) return null;

      const interactiveWords = ['interactive', 'console', 'logon type 2', 'type: 2'];
      const target = [event.message, event.event_type].filter(Boolean).join(' ');
      if (!interactiveWords.some(w => contains(target, w))) return null;

      return {
        matched: true, confidence: 75,
        explanation: `Service account "${user}" performed an interactive login. ` +
                     `Service accounts should not log in interactively; this may indicate compromise.`,
        evidence: { username: user, host: event.hostname, message: event.message?.slice(0, 120) },
      };
    },
  },

  {
    id: 'ANOM-002',
    title: 'High-Frequency Event (Possible Flooding)',
    severity: SEVERITY.LOW,
    category: 'Anomaly',
    description: 'Extremely high event rate from a single source — possible log flooding or DoS.',
    check(event, allEvents) {
      if (!event.src_ip || !event._ts) return null;
      const windowMs = 10 * 1000; // 10 seconds
      const anchorTs = event._ts.getTime();

      const count = countInWindow(allEvents,
        e => e.src_ip === event.src_ip, anchorTs, windowMs);

      if (count < 100) return null;

      return {
        matched: true, confidence: 60,
        explanation: `${count} events from ${event.src_ip} in 10 seconds. ` +
                     `May indicate log flooding, DoS, or a misconfigured device.`,
        evidence: { src_ip: event.src_ip, event_count: count, window: '10s' },
      };
    },
  },
];

/* ─── Detection Engine ────────────────────────────────────────────────────── */
/**
 * Run all rules against a parsed event list.
 * @param {Array} events - normalized event objects
 * @returns {Array} findings, each: { eventIndex, event, ruleId, title, severity, confidence, explanation, evidence }
 */
function detectAll(events) {
  const findings = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    for (const rule of RULES) {
      try {
        const result = rule.check(event, events);
        if (result && result.matched) {
          findings.push({
            id: `${rule.id}-${i}`,
            eventIndex: i,
            event,
            ruleId: rule.id,
            title: rule.title,
            severity: result.severity || rule.severity,
            category: rule.category,
            confidence: result.confidence,
            explanation: result.explanation,
            evidence: result.evidence,
            description: rule.description,
            timestamp: event._ts ? event._ts.toISOString() : null,
          });
        }
      } catch (e) {
        console.warn(`Rule ${rule.id} threw on event ${i}:`, e);
      }
    }
  }

  // Sort: critical first, then by confidence desc
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) =>
    (ORDER[a.severity] - ORDER[b.severity]) || (b.confidence - a.confidence)
  );

  return findings;
}

/**
 * Aggregate findings into a summary.
 */
function summarizeFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  const byRule = {};

  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
  }

  return { counts, byCategory, byRule, total: findings.length };
}

window.SOCRules = { RULES, SEVERITY, detectAll, summarizeFindings };
