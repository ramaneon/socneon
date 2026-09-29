import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend,
} from 'recharts'
import {
  Shield, Upload, Clipboard, Zap, AlertTriangle, Activity,
  Link2, FileText, X, Search,
  Sun, Moon, Wifi, WifiOff, RefreshCw, Download,
} from 'lucide-react'
import {
  type Finding, type AnalysisResult, type WsMessage,
  createWsClient, analyzeFile, analyzeText, runDemo,
} from './api'
import './App.css'

// ─── Severity config ────────────────────────────────────────────────────────────
const SEV: Record<string, { color: string; bg: string }> = {
  critical: { color: '#ff3860', bg: 'rgba(255,56,96,.08)' },
  high:     { color: '#ff7f00', bg: 'rgba(255,127,0,.08)' },
  medium:   { color: '#ffd700', bg: 'rgba(255,215,0,.08)' },
  low:      { color: '#00e5ff', bg: 'rgba(0,229,255,.08)' },
  info:     { color: '#8892b0', bg: 'rgba(136,146,176,.08)' },
}

const TABS = [
  { id: 'alerts',       icon: <AlertTriangle size={14}/>, label: 'Alerts'      },
  { id: 'events',       icon: <Activity     size={14}/>, label: 'Events'      },
  { id: 'iocs',         icon: <Link2        size={14}/>, label: 'IOCs'        },
  { id: 'mitre',        icon: <Shield       size={14}/>, label: 'MITRE'       },
  { id: 'correlations', icon: <Zap          size={14}/>, label: 'Chains'      },
  { id: 'charts',       icon: <Activity     size={14}/>, label: 'Charts'      },
  { id: 'report',       icon: <FileText     size={14}/>, label: 'Report'      },
]

// ─── Particle Canvas (MotionSites ambient) ──────────────────────────────────────
function ParticleCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const c = canvasRef.current!
    const ctx = c.getContext('2d')!
    let W = c.width = window.innerWidth
    let H = c.height = window.innerHeight
    let raf: number

    const pts = Array.from({ length: 90 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      r: Math.random() * 1.2 + 0.3,
      vx: (Math.random() - .5) * .28, vy: (Math.random() - .5) * .28,
      a: Math.random() * .35 + .05,
      col: Math.random() > .55 ? '#00e5ff' : '#7b2fff',
    }))

    const resize = () => { W = c.width = window.innerWidth; H = c.height = window.innerHeight }
    window.addEventListener('resize', resize)

    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      pts.forEach(p => {
        p.x = (p.x + p.vx + W) % W
        p.y = (p.y + p.vy + H) % H
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = p.col; ctx.globalAlpha = p.a; ctx.fill()
      })
      for (let i = 0; i < pts.length; i++)
        for (let j = i + 1; j < pts.length; j++) {
          const d = Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y)
          if (d < 85) {
            ctx.beginPath(); ctx.strokeStyle = '#00e5ff'
            ctx.globalAlpha = (1 - d / 85) * .06; ctx.lineWidth = .5
            ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y)
            ctx.stroke()
          }
        }
      ctx.globalAlpha = 1
      raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  }, [])

  return <canvas ref={canvasRef} style={{
    position: 'fixed', inset: 0, width: '100%', height: '100%',
    pointerEvents: 'none', zIndex: 0, opacity: .65,
  }} />
}

// ─── Stat Card ──────────────────────────────────────────────────────────────────
function StatCard({ label, value, accent }: { label: string; value: string | number; accent: string }) {
  return (
    <div className="stat-card">
      <div className="stat-bar" style={{ background: accent, boxShadow: `0 0 10px ${accent}80` }} />
      <div className="stat-number" style={{ color: accent === 'var(--text-primary)' ? 'var(--text-primary)' : undefined }}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

// ─── Alert Card ─────────────────────────────────────────────────────────────────
function AlertCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  const sev = SEV[f.severity] ?? SEV.info
  return (
    <article className={`alert-card sev-${f.severity}`} style={{ borderLeftColor: sev.color }}>
      <div className="alert-header">
        <div className="alert-title-row">
          <span className="sev-dot" style={{ background: sev.color, boxShadow: `0 0 6px ${sev.color}` }} />
          <span className="sev-label" style={{ color: sev.color }}>{f.severity.toUpperCase()}</span>
          <code className="rule-id">{f.ruleId}</code>
          {f.mitre.map(m => <span key={m} className="mitre-tag">{m}</span>)}
          <h3 className="alert-title">{f.title}</h3>
        </div>
        <div className="alert-meta">
          <span className="conf-wrap" title={`${f.confidence}% confidence`}>
            <span className="conf-bar">
              <span className="conf-fill" style={{ width: `${f.confidence}%`, background: sev.color }} />
            </span>
            <span className="conf-pct">{f.confidence}%</span>
          </span>
          <span className="category-tag">{f.category}</span>
        </div>
      </div>
      <p className="alert-explain">{f.explanation}</p>
      {Object.keys(f.evidence).length > 0 && (
        <div className="evidence-row">
          {Object.entries(f.evidence).map(([k, v]) => (
            <span key={k} className="ev-badge">
              <span className="ev-key">{k}</span>
              <span className="ev-val">{String(v).slice(0, 80)}</span>
            </span>
          ))}
        </div>
      )}
      <button className="btn-link mt-2" onClick={() => setOpen(o => !o)}>
        {open ? 'Hide' : 'Show'} raw event ▾
      </button>
      {open && (
        <pre className="raw-event">{JSON.stringify(f.event, null, 2).slice(0, 2000)}</pre>
      )}
    </article>
  )
}

// ─── Main App ───────────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState<'landing' | 'dashboard'>('landing')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [liveAlerts, setLiveAlerts] = useState<Finding[]>([])
  const [progress, setProgress] = useState<{ msg: string; pct: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('alerts')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [searchQ, setSearchQ] = useState('')
  const [wsState, setWsState] = useState<'disconnected' | 'connected'>('disconnected')
  const [wsCid, setWsCid] = useState<string | null>(null)
  const [darkMode, setDarkMode] = useState(true)
  const [dragging, setDragging] = useState(false)
  const [pasteOpen, setPasteOpen] = useState(false)
  const [pasteText, setPasteText] = useState('')
  const wsRef = useRef<ReturnType<typeof createWsClient> | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // WebSocket connection
  useEffect(() => {
    const client = createWsClient(
      (msg: WsMessage) => {
        if (msg.type === 'connected') {
          setWsCid(msg.cid)
          setWsState('connected')
        } else if (msg.type === 'progress') {
          setProgress({ msg: msg.msg, pct: msg.pct })
        } else if (msg.type === 'alert') {
          setLiveAlerts(a => [...a, msg.finding])
        } else if (msg.type === 'done') {
          setResult(msg.result)
          setProgress(null)
          setLiveAlerts([])
          setScreen('dashboard')
        }
      },
      () => setWsState('disconnected')
    )
    wsRef.current = client
    return () => client.close()
  }, [])

  const showError = (msg: string) => {
    setError(msg)
    setTimeout(() => setError(null), 6000)
  }

  const handleFile = useCallback(async (file: File) => {
    setLiveAlerts([])
    setProgress({ msg: 'Reading file…', pct: 5 })
    try {
      const r = await analyzeFile(file, wsCid ?? undefined)
      setResult(r); setScreen('dashboard'); setProgress(null)
    } catch (e: unknown) {
      showError((e as Error).message)
      setProgress(null)
    }
  }, [wsCid])

  const handleDemo = useCallback(async (fmt: string) => {
    setLiveAlerts([])
    setProgress({ msg: 'Loading demo…', pct: 5 })
    try {
      const r = await runDemo(fmt, wsCid ?? undefined)
      setResult(r); setScreen('dashboard'); setProgress(null)
    } catch (e: unknown) {
      showError((e as Error).message)
      setProgress(null)
    }
  }, [wsCid])

  const handlePaste = useCallback(async () => {
    if (!pasteText.trim()) return
    setLiveAlerts([])
    setProgress({ msg: 'Analyzing…', pct: 5 })
    setPasteOpen(false)
    try {
      const r = await analyzeText(pasteText, wsCid ?? undefined)
      setResult(r); setScreen('dashboard'); setProgress(null)
    } catch (e: unknown) {
      showError((e as Error).message)
      setProgress(null)
    }
  }, [pasteText, wsCid])

  // Filtered findings
  const filteredFindings = useMemo(() => {
    if (!result) return []
    let f = result.findings
    if (severityFilter !== 'all') f = f.filter(x => x.severity === severityFilter)
    if (searchQ) {
      const q = searchQ.toLowerCase()
      f = f.filter(x => JSON.stringify(x).toLowerCase().includes(q))
    }
    return f
  }, [result, severityFilter, searchQ])

  const counts = useMemo(() => {
    if (!result) return {} as Record<string, number>
    return result.findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1
      return acc
    }, {} as Record<string, number>)
  }, [result])

  // Chart data
  const sevChartData = useMemo(() => [
    { name: 'Critical', value: counts.critical ?? 0, color: '#ff3860' },
    { name: 'High',     value: counts.high     ?? 0, color: '#ff7f00' },
    { name: 'Medium',   value: counts.medium   ?? 0, color: '#ffd700' },
    { name: 'Low',      value: counts.low      ?? 0, color: '#00e5ff' },
  ], [counts])

  const categoryData = useMemo(() => {
    if (!result) return []
    const map: Record<string, number> = {}
    result.findings.forEach(f => { map[f.category] = (map[f.category] ?? 0) + 1 })
    return Object.entries(map).map(([name, value]) => ({ name, value }))
  }, [result])

  // Keyboard shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        document.getElementById('search-input')?.focus()
      }
      if ((e.ctrlKey || e.metaKey) && e.key === 'o') {
        e.preventDefault()
        fileInputRef.current?.click()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // ─── Export helpers ─────────────────────────────────────────────────────────
  const exportJson = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `socneon-${result.filename}.json`; a.click()
  }

  const exportCsv = () => {
    if (!result) return
    const rows = [
      ['ID', 'Rule', 'Title', 'Severity', 'Category', 'Confidence', 'Explanation'],
      ...result.findings.map(f => [f.ruleId, f.id, f.title, f.severity, f.category, f.confidence, f.explanation])
    ]
    const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `socneon-${result?.filename}.csv`; a.click()
  }

  // ─── RENDER ─────────────────────────────────────────────────────────────────
  return (
    <div className={`app-root ${darkMode ? 'dark' : 'light'}`}>
      {screen === 'landing' && <ParticleCanvas />}

      {/* Progress Overlay */}
      {progress && (
        <div className="loading-overlay">
          <div className="loader-ring">
            <div className="loader-inner" />
            <span className="loader-shield">🛡️</span>
          </div>
          <p className="loading-msg">{progress.msg}</p>
          <div className="progress-bar-wrap">
            <div className="progress-bar-fill" style={{ width: `${progress.pct}%` }} />
          </div>
          {/* Live alert stream count */}
          {liveAlerts.length > 0 && (
            <p className="live-count">
              <Zap size={12} style={{ color: '#00e5ff', marginRight: 4 }} />
              {liveAlerts.length} alert{liveAlerts.length !== 1 ? 's' : ''} detected via WebSocket
            </p>
          )}
        </div>
      )}

      {/* Error Toast */}
      {error && (
        <div className="error-toast">
          <AlertTriangle size={14} />
          {error}
          <button onClick={() => setError(null)} className="toast-close"><X size={12}/></button>
        </div>
      )}

      {/* Paste Modal */}
      {pasteOpen && (
        <div className="modal-overlay" onClick={() => setPasteOpen(false)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>📋 Paste Log Content</h2>
              <button onClick={() => setPasteOpen(false)} className="modal-close"><X size={16}/></button>
            </div>
            <textarea
              className="paste-area"
              value={pasteText}
              onChange={e => setPasteText(e.target.value)}
              placeholder="Paste CSV, JSON, JSONL, or syslog text here…"
              autoFocus
            />
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setPasteOpen(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handlePaste}>Analyze ↵</button>
            </div>
          </div>
        </div>
      )}

      {/* ─── HEADER ─────────────────────────────────────────────────────────── */}
      <header className="app-header">
        <div className="brand" onClick={() => setScreen('landing')} style={{ cursor: 'pointer' }}>
          <Shield size={28} style={{ color: '#00e5ff', filter: 'drop-shadow(0 0 8px #00e5ff88)' }} />
          <div>
            <div className="brand-title">SOCNeon</div>
            <div className="brand-sub">SOC Log Analyzer</div>
          </div>
        </div>
        <div className="header-right">
          <div className="ws-badge" title={wsState === 'connected' ? 'WebSocket connected' : 'WebSocket offline'}>
            {wsState === 'connected'
              ? <><Wifi size={12} style={{ color: '#00ff9d' }} /><span style={{ color: '#00ff9d' }}>Live</span></>
              : <><WifiOff size={12} style={{ color: '#ff3860' }} /><span style={{ color: '#ff3860' }}>Offline</span></>
            }
          </div>
          <div className="privacy-badge">
            <span className="priv-dot" />
            100% Offline
          </div>
          <button className="icon-btn" onClick={() => setDarkMode(d => !d)} title="Toggle theme">
            {darkMode ? <Sun size={16}/> : <Moon size={16}/>}
          </button>
        </div>
      </header>

      {/* ─── LANDING ─────────────────────────────────────────────────────────── */}
      {screen === 'landing' && (
        <main className="landing-main" style={{ position: 'relative', zIndex: 1 }}>
          {/* Hero */}
          <section className="hero">
            <div className="hero-eyebrow">
              <span className="eyebrow-dot" />
              Python FastAPI + React + WebSockets · Privacy-First
            </div>
            <h1 className="hero-title">
              <span>SOC</span><span className="accent">Neon</span>
            </h1>
            <p className="hero-sub">
              Real-time security log analysis.<br/>
              FastAPI backend streams alerts via WebSocket to your React dashboard.<br/>
              No data leaves your network.
            </p>
            <div className="hero-pills">
              {['⚡ Fully Offline', '🐍 Python FastAPI', '⚛ React', '🔌 WebSockets',
                '🎯 12 Detection Rules', '🗺 MITRE ATT&CK', '💉 IOC Extraction',
                '🔗 Correlation Engine', '📊 Live Charts'].map(p => (
                <span key={p} className="pill">{p}</span>
              ))}
            </div>
          </section>

          {/* Upload Zone */}
          <div className="upload-zone-wrap">
            <div
              className={`drop-zone ${dragging ? 'drag-over' : ''}`}
              onDragOver={e => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={e => {
                e.preventDefault(); setDragging(false)
                if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0])
              }}
              onClick={() => fileInputRef.current?.click()}
              role="button" tabIndex={0}
              onKeyDown={e => e.key === 'Enter' && fileInputRef.current?.click()}
            >
              <div className="drop-glow" />
              <div className="drop-content">
                <Upload size={36} style={{ color: '#00e5ff', filter: 'drop-shadow(0 0 10px #00e5ff66)' }} />
                <div className="drop-title">Drop your log file here</div>
                <p className="drop-sub">or click to browse — file never leaves your browser</p>
                <div className="format-chips">
                  {['.csv', '.json', '.jsonl', '.log / syslog'].map(f => (
                    <span key={f} className="fchip">{f}</span>
                  ))}
                </div>
              </div>
            </div>
            <input ref={fileInputRef} type="file" style={{ display: 'none' }}
              accept=".csv,.json,.jsonl,.ndjson,.log,.txt,.syslog"
              onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])} />
            <button className="btn btn-outline mt-3" onClick={() => setPasteOpen(true)}>
              <Clipboard size={14}/> Paste Text
            </button>
          </div>

          {/* Demo buttons */}
          <div className="demo-section">
            <div className="demo-divider"><span>Try demo data</span></div>
            <div className="demo-row">
              {(['csv', 'json', 'jsonl', 'syslog'] as const).map(fmt => (
                <button key={fmt} className="demo-btn" onClick={() => handleDemo(fmt)}>
                  <span className={`demo-chip ${fmt}`}>{fmt.toUpperCase()}</span>
                  {{ csv: 'Firewall Logs', json: 'ECS Format', jsonl: 'Web Access', syslog: 'RFC 3164' }[fmt]}
                </button>
              ))}
            </div>
          </div>

          {/* Feature Cards */}
          <div className="feat-grid">
            {[
              { icon: '🔒', title: 'Privacy First', desc: 'Zero network requests. Works air-gapped. WebSocket only talks to YOUR backend.', cls: 'offline' },
              { icon: '🐍', title: 'Python FastAPI', desc: '12 detection rules ported to Python with real-time WebSocket streaming of every alert.', cls: '' },
              { icon: '⚛', title: 'React Frontend', desc: 'Live dashboard with Recharts, WebSocket updates, and no page reloads ever.', cls: '' },
              { icon: '🗺', title: 'MITRE ATT&CK', desc: 'Every finding tagged with ATT&CK technique IDs across 8 tactics.', cls: 'mitre' },
              { icon: '🔗', title: 'Attack Chains', desc: 'Source IP correlation engine identifies multi-stage attack progressions.', cls: 'corr' },
            ].map(c => (
              <div key={c.title} className={`feat-card ${c.cls}`}>
                <div className="feat-glow" />
                <div className="feat-icon">{c.icon}</div>
                <div className="feat-title">{c.title}</div>
                <div className="feat-desc">{c.desc}</div>
                <div className="feat-shimmer" />
              </div>
            ))}
          </div>
        </main>
      )}

      {/* ─── DASHBOARD ───────────────────────────────────────────────────────── */}
      {screen === 'dashboard' && result && (
        <main className="dash-main">
          {/* Toolbar */}
          <div className="dash-toolbar">
            <div className="meta-bar">
              <span>📁 <strong>{result.filename}</strong></span>
              <span className="sep">·</span>
              <span>Format: <strong>{result.format.toUpperCase()}</strong></span>
              <span className="sep">·</span>
              <span>Events: <strong>{result.total.toLocaleString()}</strong></span>
              <span className="sep">·</span>
              <span>Errors: <strong>{result.errors}</strong></span>
            </div>
            <div style={{ display: 'flex', gap: '.5rem' }}>
              <button className="btn btn-ghost btn-sm" onClick={exportJson}><Download size={12}/> JSON</button>
              <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={12}/> CSV</button>
              <button className="btn btn-ghost btn-sm" onClick={() => { setScreen('landing'); setResult(null) }}>
                <RefreshCw size={12}/> New File
              </button>
            </div>
          </div>

          {/* Stat Cards */}
          <div className="stat-grid">
            <StatCard label="Critical" value={counts.critical ?? 0} accent="#ff3860" />
            <StatCard label="High"     value={counts.high     ?? 0} accent="#ff7f00" />
            <StatCard label="Medium"   value={counts.medium   ?? 0} accent="#ffd700" />
            <StatCard label="Low"      value={counts.low      ?? 0} accent="#00e5ff" />
            <StatCard label="Events"   value={result.total.toLocaleString()} accent="#00e5ff" />
            <StatCard label="Findings" value={result.findings.length} accent="#7b2fff" />
            <StatCard label="Threat Score" value={result.threatScore.score} accent={
              result.threatScore.score >= 70 ? '#ff3860' : result.threatScore.score >= 40 ? '#ff7f00' : '#00e5ff'
            } />
          </div>

          {/* Search */}
          <div className="search-row">
            <div className="search-wrap">
              <Search size={14} className="search-icon" />
              <input id="search-input" className="search-input" type="search"
                placeholder="Search findings, IPs, rules… (Ctrl+K)"
                value={searchQ} onChange={e => setSearchQ(e.target.value)} />
            </div>
          </div>

          {/* Tabs */}
          <nav className="tabs-bar">
            {TABS.map(t => (
              <button key={t.id} className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
                onClick={() => setActiveTab(t.id)}>
                {t.icon} {t.label}
              </button>
            ))}
          </nav>

          {/* ─── ALERTS ─── */}
          {activeTab === 'alerts' && (
            <div className="tab-content">
              <div className="sev-filters">
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
                  <button key={s}
                    className={`sev-btn ${severityFilter === s ? 'active' : ''} ${s}`}
                    onClick={() => setSeverityFilter(s)}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                    <span className="badge">{s === 'all' ? result.findings.length : (counts[s] ?? 0)}</span>
                  </button>
                ))}
              </div>
              <div className="panel-hdr">
                <span className="ev-count">{filteredFindings.length} alerts</span>
              </div>
              {filteredFindings.length === 0
                ? <div className="empty-state">✅ No alerts match filter</div>
                : filteredFindings.map(f => <AlertCard key={f.id} f={f} />)
              }
            </div>
          )}

          {/* ─── EVENTS ─── */}
          {activeTab === 'events' && (
            <div className="tab-content">
              <div className="panel-hdr">
                <span className="ev-count">{result.total.toLocaleString()} events</span>
              </div>
              <div className="table-wrap">
                <table className="ev-table">
                  <thead>
                    <tr>
                      {['#', 'Timestamp', 'src_ip', 'dst_ip', 'action', 'message'].map(h => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.findings.slice(0, 200).map((f, i) => (
                      <tr key={i}>
                        <td className="mono">{i + 1}</td>
                        <td className="mono">{f.timestamp?.slice(0, 19) || '—'}</td>
                        <td className="mono">{String(f.event?.src_ip ?? '—')}</td>
                        <td className="mono">{String(f.event?.dst_ip ?? '—')}</td>
                        <td className="mono">{String(f.event?.action ?? '—')}</td>
                        <td>{String(f.explanation).slice(0, 80)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ─── IOCs ─── */}
          {activeTab === 'iocs' && (
            <div className="tab-content">
              {[
                { label: '🌐 IP Addresses', items: result.iocs.ips },
                { label: '🔗 Domains', items: result.iocs.domains },
                { label: '🔑 Hashes', items: result.iocs.hashes },
                { label: '📎 URLs', items: result.iocs.urls },
              ].map(({ label, items }) => items.length > 0 && (
                <div key={label} className="ioc-section">
                  <h3 className="ioc-heading">{label} <span className="ioc-count">{items.length}</span></h3>
                  <div className="ioc-list">
                    {items.map((v, i) => <span key={i} className="ioc-item">{v}</span>)}
                  </div>
                </div>
              ))}
              {!result.iocs.ips.length && !result.iocs.domains.length && (
                <div className="empty-state">✅ No IOCs extracted</div>
              )}
            </div>
          )}

          {/* ─── MITRE ─── */}
          {activeTab === 'mitre' && (
            <div className="tab-content">
              <div className="mitre-grid">
                {result.findings.flatMap(f => f.mitre).filter((v, i, a) => a.indexOf(v) === i).map(tid => {
                  const count = result.findings.filter(f => f.mitre.includes(tid)).length
                  return (
                    <div key={tid} className="mitre-cell">
                      <div className="mitre-tid">{tid}</div>
                      <div className="mitre-count">{count} finding{count !== 1 ? 's' : ''}</div>
                    </div>
                  )
                })}
              </div>
              {result.findings.every(f => f.mitre.length === 0) && (
                <div className="empty-state">No MITRE mappings in this result</div>
              )}
            </div>
          )}

          {/* ─── CORRELATIONS ─── */}
          {activeTab === 'correlations' && (
            <div className="tab-content">
              {result.correlations.length === 0
                ? <div className="empty-state">✅ No correlated attack chains found</div>
                : result.correlations.map((c, i) => (
                  <div key={i} className="corr-card">
                    <div className="corr-ip">{c.ip}</div>
                    <div className="corr-meta">{c.count} findings across {c.tactics.length} tactics</div>
                    <div className="corr-tactics">
                      {c.tactics.map(t => <span key={t} className="tactic-tag">{t}</span>)}
                    </div>
                  </div>
                ))
              }
            </div>
          )}

          {/* ─── CHARTS ─── */}
          {activeTab === 'charts' && (
            <div className="tab-content charts-grid">
              <div className="chart-card">
                <h3>Severity Distribution</h3>
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={sevChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: '#8892b0', fontSize: 11 }} />
                    <YAxis tick={{ fill: '#8892b0', fontSize: 11 }} />
                    <Tooltip contentStyle={{ background: '#161618', border: '1px solid #2a2a2e', borderRadius: 8, color: '#e8eaf0' }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {sevChartData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card">
                <h3>Category Breakdown</h3>
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={categoryData} dataKey="value" nameKey="name"
                      cx="50%" cy="50%" outerRadius={80} innerRadius={40}
                      stroke="none">
                      {categoryData.map((_, i) => (
                        <Cell key={i} fill={['#00e5ff', '#7b2fff', '#ff3860', '#ff7f00', '#ffd700', '#00ff9d'][i % 6]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#161618', border: '1px solid #2a2a2e', borderRadius: 8, color: '#e8eaf0' }} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#8892b0' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card">
                <h3>Threat Radar</h3>
                <ResponsiveContainer width="100%" height={240}>
                  <RadarChart data={categoryData.slice(0, 8)}>
                    <PolarGrid stroke="#2a2a2e" />
                    <PolarAngleAxis dataKey="name" tick={{ fill: '#8892b0', fontSize: 10 }} />
                    <Radar dataKey="value" stroke="#00e5ff" fill="#00e5ff" fillOpacity={0.15} dot={false} />
                    <Tooltip contentStyle={{ background: '#161618', border: '1px solid #2a2a2e', borderRadius: 8, color: '#e8eaf0' }} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* Threat Score Gauge */}
              <div className="chart-card score-card">
                <h3>Threat Score</h3>
                <div className="score-display">
                  <div className="score-number" style={{
                    color: result.threatScore.score >= 70 ? '#ff3860' : result.threatScore.score >= 40 ? '#ff7f00' : '#00e5ff'
                  }}>
                    {result.threatScore.score}
                  </div>
                  <div className="score-level">{result.threatScore.level}</div>
                  <div className="score-bar-wrap">
                    <div className="score-bar-fill" style={{
                      width: `${result.threatScore.score}%`,
                      background: result.threatScore.score >= 70 ? '#ff3860' : result.threatScore.score >= 40 ? '#ff7f00' : '#00e5ff',
                    }} />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ─── REPORT ─── */}
          {activeTab === 'report' && (
            <div className="tab-content">
              <div className="report-actions">
                <button className="btn btn-primary" onClick={exportJson}><Download size={14}/> Export JSON</button>
                <button className="btn btn-outline" onClick={exportCsv}><Download size={14}/> Export CSV</button>
              </div>
              <div className="report-box">
                <h2>SOCNeon Analysis Report</h2>
                <p><strong>File:</strong> {result.filename}</p>
                <p><strong>Format:</strong> {result.format.toUpperCase()}</p>
                <p><strong>Total Events:</strong> {result.total.toLocaleString()}</p>
                <p><strong>Threat Score:</strong> {result.threatScore.score}/100 ({result.threatScore.level})</p>
                <hr />
                <h3>Findings Summary</h3>
                <ul>
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => (
                    <li key={s}><strong>{s.toUpperCase()}:</strong> {counts[s] ?? 0}</li>
                  ))}
                </ul>
                <hr />
                <h3>IOC Summary</h3>
                <p>IPs: {result.iocs.ips.length} · Domains: {result.iocs.domains.length} · Hashes: {result.iocs.hashes.length}</p>
                <hr />
                <h3>Top Findings</h3>
                {result.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 10).map(f => (
                  <div key={f.id} style={{ marginBottom: '.5rem' }}>
                    <strong>[{f.severity.toUpperCase()}]</strong> {f.title} — {f.explanation}
                  </div>
                ))}
              </div>
            </div>
          )}

        </main>
      )}

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-left">
          <span className="footer-brand">SOCNeon</span>
          <span className="footer-sep">·</span>
          <span>React + FastAPI + WebSockets</span>
          <span className="footer-sep">·</span>
          <span style={{ color: '#00ff9d' }}>⚡ Offline-ready</span>
        </div>
        <div className="footer-right">
          <span><kbd>Ctrl+K</kbd> search · <kbd>Ctrl+O</kbd> open</span>
          <span className="footer-ver">v2.1.0</span>
        </div>
      </footer>
    </div>
  )
}
