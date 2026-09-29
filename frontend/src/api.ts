// SOCNeon — WebSocket + API client
const API = import.meta.env.VITE_API_URL || ''

export interface Finding {
  id: string
  ruleId: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  category: string
  explanation: string
  evidence: Record<string, string>
  event: Record<string, unknown>
  timestamp?: string
  mitre: string[]
}

export interface AnalysisResult {
  filename: string
  format: string
  total: number
  errors: number
  findings: Finding[]
  iocs: { ips: string[]; domains: string[]; hashes: string[]; urls: string[] }
  threatScore: { score: number; level: string }
  correlations: { ip: string; count: number; tactics: string[] }[]
}

export type WsMessage =
  | { type: 'connected'; cid: string }
  | { type: 'progress'; msg: string; pct: number }
  | { type: 'alert'; finding: Finding }
  | { type: 'done'; result: AnalysisResult }
  | { type: 'pong'; ts: number }

// ─── WebSocket ─────────────────────────────────────────────────────────────────
export function createWsClient(
  onMessage: (msg: WsMessage) => void,
  onError?: (e: Event) => void
) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const host = API ? new URL(API).host : location.host
  const ws = new WebSocket(`${proto}://${host}/ws/alerts`)
  let pingInterval: ReturnType<typeof setInterval> | null = null

  ws.onopen = () => {
    pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }))
      }
    }, 25_000)
  }
  ws.onmessage = e => {
    try { onMessage(JSON.parse(e.data)) } catch { /* ignore malformed */ }
  }
  ws.onerror = onError ?? (() => {})
  ws.onclose = () => { if (pingInterval) clearInterval(pingInterval) }

  return {
    cid: null as string | null,
    close: () => ws.close(),
    ws,
  }
}

// ─── REST Helpers ──────────────────────────────────────────────────────────────
export async function analyzeFile(file: File, wsCid?: string): Promise<AnalysisResult> {
  const fd = new FormData()
  fd.append('file', file)
  if (wsCid) fd.append('ws_cid', wsCid)
  const r = await fetch(`${API}/api/analyze`, { method: 'POST', body: fd })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function analyzeText(text: string, wsCid?: string): Promise<AnalysisResult> {
  const r = await fetch(`${API}/api/analyze/text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, filename: 'pasted-text', ws_cid: wsCid }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function runDemo(fmt: string, wsCid?: string): Promise<AnalysisResult> {
  const r = await fetch(`${API}/api/demo/${fmt}${wsCid ? `?ws_cid=${wsCid}` : ''}`)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}
