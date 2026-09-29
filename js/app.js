/**
 * SOCNeon — app.js  v2.0
 * Full UI controller: 9 tabs, advanced search, all feature integrations.
 * All processing is client-side. No data leaves the browser.
 */
'use strict';

/* ─── State ───────────────────────────────────────────────────────────────── */
const State = {
  raw: null, findings: [], filtered: [], filteredFindings: [],
  iocs: null, correlations: [], threatScore: null,
  searchQuery: '', advancedFilter: null,
  severityFilter: 'all', activeTab: 'alerts',
  currentPage: 1, pageSize: 50,
  sortField: null, sortAsc: true,
  customRules: [],
  dismissedAlerts: new Set(),
  alertNotes: {},
};

const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const SEV_CONFIG = {
  critical: { label:'Critical', color:'#ff3860', icon:'🔴', order:0 },
  high:     { label:'High',     color:'#ff8c00', icon:'🟠', order:1 },
  medium:   { label:'Medium',   color:'#ffd700', icon:'🟡', order:2 },
  low:      { label:'Low',      color:'#00e5ff', icon:'🔵', order:3 },
  info:     { label:'Info',     color:'#8892b0', icon:'⚪', order:4 },
};

function sanitize(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ─── Boot ────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  State.customRules = SOCNeonAdvanced.loadCustomRules();
  initDropZone(); initDemoButtons(); initTabs(); initSearch();
  initSeverityFilter(); initExport(); initThemeToggle();
  initKeyboardShortcuts(); initCustomRuleBuilder(); animateHeader();

  const fbBtn = $('header-feedback-btn');
  if (fbBtn && window.SOCKillerFeatures) {
    fbBtn.addEventListener('click', () => SOCKillerFeatures.openFeedbackModal());
  }
});

function animateHeader() {
  const t = document.querySelector('.brand-title');
  if (!t) return;
  t.innerHTML = 'SOCNeon'.split('').map((c, i) =>
    `<span style="animation-delay:${i*0.08}s">${c}</span>`).join('');
}

/* ─── Drop Zone ───────────────────────────────────────────────────────────── */
function initDropZone() {
  const zone = $('drop-zone'), fileIn = $('file-input');
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag-over'); if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });
  zone.addEventListener('click', () => fileIn.click());
  fileIn.addEventListener('change', e => { if (e.target.files[0]) readFile(e.target.files[0]); });

  $('paste-btn').addEventListener('click', () => {
    $('paste-modal').classList.add('active'); $('paste-area').value=''; $('paste-area').focus();
  });
  $('paste-confirm').addEventListener('click', () => {
    const t = $('paste-area').value.trim();
    if (t) processText(t, null);
    $('paste-modal').classList.remove('active');
  });
  $('paste-cancel').addEventListener('click', () => $('paste-modal').classList.remove('active'));
  $('paste-modal').addEventListener('click', e => { if (e.target===$('paste-modal')) $('paste-modal').classList.remove('active'); });
}

function readFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();
  const hint = {csv:'csv',json:'json',jsonl:'jsonl',ndjson:'jsonl',log:'syslog',txt:'syslog',syslog:'syslog'}[ext]||null;
  showLoading(true, `Reading ${sanitize(file.name)}…`);
  const reader = new FileReader();
  reader.onload = e => processText(e.target.result, hint, file.name);
  reader.onerror = () => showError('Failed to read file.');
  reader.readAsText(file, 'UTF-8');
}

function processText(text, hint=null, filename='pasted text') {
  showLoading(true, 'Parsing logs…');
  setTimeout(() => {
    try {
      const result = SOCParser.parseLogs(text, hint);
      State.raw = result;
      showLoading(true, `Running ${SOCRules.RULES.length} rules + ${State.customRules.length} custom rules…`);
      setTimeout(() => {
        try {
          const builtinFindings = SOCRules.detectAll(result.records);
          const customFindings  = SOCNeonAdvanced.applyCustomRules(result.records, State.customRules);
          State.findings    = [...builtinFindings, ...customFindings];
          State.iocs        = SOCNeonAdvanced.extractIOCs(result.records);
          State.correlations= SOCNeonAdvanced.correlateEvents(State.findings, result.records);
          State.threatScore = SOCNeonAdvanced.calculateThreatScore(State.findings, result.records);
          State.dismissedAlerts.clear();
          applyFilters();
          renderDashboard(filename);
          showSection('dashboard');
          showLoading(false);
        } catch (e) { showError(`Detection error: ${e.message}`); }
      }, 60);
    } catch (e) { showError(`Parse error: ${e.message}`); }
  }, 80);
}

function initDemoButtons() {
  $$('[data-demo]').forEach(btn => {
    btn.addEventListener('click', () => {
      const fmt = btn.dataset.demo;
      const data = SOCDemoData[fmt];
      if (!data) return;
      processText(data, {syslog:'syslog',csv:'csv',json:'json',jsonl:'jsonl'}[fmt] || null, `demo-${fmt}.${fmt}`);
    });
  });
}

/* ─── Loading / Error ─────────────────────────────────────────────────────── */
function showLoading(on, msg='Processing…') {
  const el = $('loading-overlay');
  if (on) { $('loading-msg').textContent = msg; el.classList.add('active'); }
  else el.classList.remove('active');
}
function showError(msg) {
  showLoading(false);
  $('error-msg').textContent = msg;
  $('error-toast').classList.add('active');
  setTimeout(() => $('error-toast').classList.remove('active'), 6000);
}
function showSection(name) {
  $$('.app-section').forEach(s => s.classList.remove('active'));
  const t = $(`section-${name}`); if (t) t.classList.add('active');
}

/* ─── Tabs ────────────────────────────────────────────────────────────────── */
function initTabs() {
  $$('[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      State.activeTab = btn.dataset.tab;
      $$('[data-tab]').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
      btn.classList.add('active'); btn.setAttribute('aria-selected','true');
      $$('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = $(`tab-${btn.dataset.tab}`);
      if (panel) panel.classList.add('active');
      renderCurrentTab();
    });
  });
}

/* ─── Search ──────────────────────────────────────────────────────────────── */
function initSearch() {
  const input = $('search-input');
  let debounce;
  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const q = input.value.trim();
      State.searchQuery = q.toLowerCase();
      State.advancedFilter = SOCNeonAdvanced.buildSearchFilter(q);
      State.currentPage = 1;
      applyFilters(); renderCurrentTab();
    }, 220);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { input.value=''; input.dispatchEvent(new Event('input')); }
  });

  // Search syntax hint
  input.setAttribute('placeholder', 'Search: src_ip:10.0.0.1 | /regex/ | term AND term | NOT keyword  (Ctrl+K)');
}

/* ─── Severity Filter ─────────────────────────────────────────────────────── */
function initSeverityFilter() {
  $$('[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('[data-sev]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      State.severityFilter = btn.dataset.sev;
      State.currentPage = 1;
      applyFilters(); renderCurrentTab();
    });
  });
}

/* ─── Filter Logic ────────────────────────────────────────────────────────── */
function applyFilters() {
  const filter = State.advancedFilter;
  State.filtered = (State.raw?.records || []).filter(ev => !filter || filter(ev));
  State.filteredFindings = State.findings.filter(f => {
    if (State.dismissedAlerts.has(f.id)) return false;
    const sevOk = State.severityFilter === 'all' || f.severity === State.severityFilter;
    if (!sevOk) return false;
    if (!filter) return true;
    return filter(f.event || {});
  });
}

/* ─── Dashboard ───────────────────────────────────────────────────────────── */
function renderDashboard(filename) {
  const r = State.raw;
  const sc = SOCRules.summarizeFindings(State.findings);
  $('meta-filename').textContent = filename;
  $('meta-format').textContent   = r.format;
  $('meta-total').textContent    = r.total.toLocaleString();
  $('meta-errors').textContent   = r.errors.length;

  for (const [sev] of Object.entries(SEV_CONFIG)) {
    const el = $(`stat-${sev}`);
    if (el) el.textContent = (sc.counts[sev] || 0).toLocaleString();
  }
  $('stat-events').textContent = r.total.toLocaleString();
  $('stat-rules').textContent  = State.findings.length.toLocaleString();

  const ts = State.threatScore;
  const tEl = $('stat-threat-score');
  if (tEl) { tEl.textContent = ts.score; tEl.style.color = ts.score >= 60 ? '#ff3860' : ts.score >= 40 ? '#ff8c00' : '#00e5ff'; }

  updateSeverityBadges(sc.counts);
  renderCurrentTab();
}

function renderCurrentTab() {
  applyFilters();
  switch (State.activeTab) {
    case 'alerts':       renderAlerts();       break;
    case 'copilot':      renderCopilot();      break;
    case 'events':       renderEvents();       break;
    case 'summary':      renderSummary();      break;
    case 'timeline':     renderTimeline();     break;
    case 'iocs':         renderIOCs();         break;
    case 'mitre':        renderMITRE();        break;
    case 'correlations': renderCorrelations(); break;
    case 'siem':         renderSIEM();         break;
    case 'playbook':     renderPlaybook();     break;
    case 'rules':        renderCustomRules();  break;
    case 'report':       renderReport();       break;
  }
}

function updateSeverityBadges(counts) {
  $$('[data-sev]').forEach(btn => {
    const badge = btn.querySelector('.badge');
    if (!badge) return;
    const sev = btn.dataset.sev;
    badge.textContent = sev === 'all' ? State.findings.length : (counts[sev] || 0);
  });
}

/* ─── ALERTS TAB ──────────────────────────────────────────────────────────── */
function renderAlerts() {
  const container = $('alerts-list');
  const findings  = State.filteredFindings;
  $('alerts-count').textContent = `${findings.length} alert${findings.length !== 1 ? 's' : ''}`;

  if (!findings.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div><p>${State.searchQuery ? 'No alerts match filter.' : 'No suspicious activity detected.'}</p></div>`;
    return;
  }

  container.innerHTML = findings.map((f, idx) => {
    const cfg  = SEV_CONFIG[f.severity] || SEV_CONFIG.info;
    const evid = Object.entries(f.evidence || {}).map(([k,v]) =>
      `<span class="ev-badge"><span class="ev-key">${sanitize(k)}</span><span class="ev-val">${sanitize(String(v).slice(0,80))}</span></span>`
    ).join('');
    const mitreTags = SOCNeonAdvanced.TECHNIQUES.filter(t => t.rules.includes(f.ruleId))
      .map(t => `<span class="mitre-tag" title="${sanitize(t.name)}">${sanitize(t.id)}</span>`).join('');
    const note = State.alertNotes[f.id] || '';

    return `<article class="alert-card sev-${f.severity}" tabindex="0" aria-label="${sanitize(f.title)}">
      <div class="alert-header">
        <div class="alert-title-row">
          <span class="sev-dot" style="background:${cfg.color}"></span>
          <span class="sev-label" style="color:${cfg.color}">${cfg.label}</span>
          <code class="rule-id">${sanitize(f.ruleId)}</code>
          ${mitreTags}
          ${f.isCustom ? '<span class="chip-custom">CUSTOM</span>' : ''}
          <h3 class="alert-title">${sanitize(f.title)}</h3>
        </div>
        <div class="alert-meta">
          <span class="confidence-bar" title="${f.confidence}% confidence">
            <span class="cb-fill" style="width:${f.confidence}%;background:${cfg.color}"></span>
          </span>
          <span class="confidence-pct">${f.confidence}%</span>
          ${f.timestamp ? `<time class="alert-time">${formatTime(f.timestamp)}</time>` : ''}
          <span class="category-tag">${sanitize(f.category)}</span>
          <button class="btn-icon-sm" data-dismiss="${sanitize(f.id)}" title="Dismiss alert" aria-label="Dismiss">✕</button>
        </div>
      </div>
      <div class="alert-body">
        <p class="alert-explain">${sanitize(f.explanation)}</p>
        ${evid ? `<div class="evidence-row">${evid}</div>` : ''}
        <div class="alert-actions">
          <button class="btn-link raw-toggle" data-idx="${idx}">Show raw event ▾</button>
          <button class="btn-link note-toggle" data-id="${sanitize(f.id)}">📝 Note</button>
          ${f.event?.src_ip ? `<button class="btn-link pivot-ip" data-ip="${sanitize(f.event.src_ip)}">🔍 Pivot on ${sanitize(f.event.src_ip)}</button>` : ''}
        </div>
        <pre class="raw-event" id="raw-${idx}" hidden>${sanitize(JSON.stringify(f.event?._raw || {}, null, 2)).slice(0,2000)}</pre>
        <div class="note-box" id="note-${sanitize(f.id)}" hidden>
          <textarea class="note-input" placeholder="Add analysis note…" aria-label="Alert note">${sanitize(note)}</textarea>
          <button class="btn btn-sm save-note" data-id="${sanitize(f.id)}">Save Note</button>
        </div>
      </div>
    </article>`;
  }).join('');

  // Wire interactions
  container.querySelectorAll('.raw-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const pre = $(`raw-${btn.dataset.idx}`); const open = !pre.hidden;
      pre.hidden = open; btn.textContent = open ? 'Show raw event ▾' : 'Hide raw event ▴';
    });
  });
  container.querySelectorAll('[data-dismiss]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      State.dismissedAlerts.add(btn.dataset.dismiss);
      applyFilters(); renderAlerts();
    });
  });
  container.querySelectorAll('.note-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const box = $(`note-${btn.dataset.id}`);
      if (box) box.hidden = !box.hidden;
    });
  });
  container.querySelectorAll('.save-note').forEach(btn => {
    btn.addEventListener('click', () => {
      const box = $(`note-${btn.dataset.id}`);
      if (box) State.alertNotes[btn.dataset.id] = box.querySelector('textarea').value;
      if (box) box.hidden = true;
    });
  });
  container.querySelectorAll('.pivot-ip').forEach(btn => {
    btn.addEventListener('click', () => {
      const ip = btn.dataset.ip;
      $('search-input').value = `src_ip:${ip}`;
      $('search-input').dispatchEvent(new Event('input'));
      // Switch to events tab
      $$('[data-tab="events"]')[0]?.click();
    });
  });
}

/* ─── EVENTS TAB ──────────────────────────────────────────────────────────── */
function renderEvents() {
  const events = State.filtered;
  const start  = (State.currentPage - 1) * State.pageSize;
  const page   = events.slice(start, start + State.pageSize);
  const container = $('events-table-wrap');

  $('events-count').textContent = `${events.length.toLocaleString()} event${events.length !== 1 ? 's' : ''}`;

  if (!events.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">📭</div><p>No events match the filter.</p></div>`;
    renderPagination(0, 0); return;
  }

  const NORM_COLS = ['timestamp','src_ip','dst_ip','dst_port','protocol','action','severity','event_type','username','hostname','message'];
  const sample = events.slice(0, 20);
  const cols   = NORM_COLS.filter(c => sample.some(e => e[c]));
  const findingEventSet = new Set(State.findings.map(f => f.event));

  const thead = `<thead><tr>${cols.map(c =>
    `<th scope="col" class="sortable" data-col="${c}" tabindex="0">${sanitize(c.replace(/_/g,' '))} <span class="sort-icon">⇕</span></th>`
  ).join('')}</tr></thead>`;

  const tbody = `<tbody>${page.map(ev => {
    const flagged = findingEventSet.has(ev) ? 'flagged-row' : '';
    return `<tr class="${flagged}" tabindex="0">
      ${cols.map(c => {
        const val = sanitize(String(ev[c] || '').slice(0, 120));
        // Make IPs clickable pivots
        const isIP = (c === 'src_ip' || c === 'dst_ip') && ev[c];
        return isIP
          ? `<td data-label="${sanitize(c)}"><button class="btn-link pivot-ip" data-ip="${sanitize(ev[c])}">${val}</button></td>`
          : `<td data-label="${sanitize(c)}">${val}</td>`;
      }).join('')}
    </tr>`;
  }).join('')}</tbody>`;

  container.innerHTML = `<div class="table-scroll"><table class="events-table" role="grid">${thead}${tbody}</table></div>`;
  renderPagination(events.length, State.currentPage);

  container.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (State.sortField === col) State.sortAsc = !State.sortAsc;
      else { State.sortField = col; State.sortAsc = true; }
      State.filtered.sort((a, b) => {
        const av = String(a[col]||''), bv = String(b[col]||'');
        return State.sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      State.currentPage = 1; renderEvents();
    });
    th.addEventListener('keydown', e => { if (e.key==='Enter') th.click(); });
  });
  container.querySelectorAll('.pivot-ip').forEach(btn => {
    btn.addEventListener('click', () => {
      $('search-input').value = `src_ip:${btn.dataset.ip}`;
      $('search-input').dispatchEvent(new Event('input'));
    });
  });
}

/* ─── SUMMARY TAB ─────────────────────────────────────────────────────────── */
function renderSummary() {
  if (!State.raw) return;
  const summary = SOCRules.summarizeFindings(State.findings);
  const container = $('summary-content');

  const catRows = Object.entries(summary.byCategory).sort((a,b)=>b[1]-a[1]).map(([cat,count]) => {
    const pct = Math.round((count/State.findings.length)*100)||0;
    return `<div class="summary-row"><span class="sum-label">${sanitize(cat)}</span>
      <div class="sum-bar-wrap"><div class="sum-bar" style="width:${pct}%"></div></div>
      <span class="sum-count">${count}</span></div>`;
  }).join('') || '<p class="muted">No findings.</p>';

  const ipMap = new Map();
  State.findings.forEach(f => { const ip=f.event?.src_ip; if(ip) ipMap.set(ip,(ipMap.get(ip)||0)+1); });
  const topIPs = [...ipMap.entries()].sort((a,b)=>b[1]-a[1]).slice(0,10);
  const ipRows = topIPs.map(([ip,cnt]) => `
    <div class="summary-row">
      <span class="sum-label ip-label"><button class="btn-link pivot-ip" data-ip="${sanitize(ip)}">${sanitize(ip)}</button></span>
      <div class="sum-bar-wrap"><div class="sum-bar ip-bar" style="width:${Math.round(cnt/topIPs[0][1]*100)}%"></div></div>
      <span class="sum-count">${cnt}</span>
    </div>`).join('') || '<p class="muted">No IP data.</p>';

  const ruleRows = Object.entries(summary.byRule).sort((a,b)=>b[1]-a[1]).map(([ruleId,count]) => {
    const rule = SOCRules.RULES.find(r=>r.id===ruleId);
    return `<div class="summary-row">
      <span class="sum-label"><code>${sanitize(ruleId)}</code> ${sanitize(rule?.title||'')}</span>
      <div class="sum-bar-wrap"><div class="sum-bar rule-bar" style="width:${Math.round(count/State.findings.length*100)}%"></div></div>
      <span class="sum-count">${count}</span></div>`;
  }).join('') || '<p class="muted">No findings.</p>';

  const errSection = State.raw.errors.length ? `<div class="summary-card">
    <h3>⚠ Parse Errors (${State.raw.errors.length})</h3>
    <ul class="error-list">${State.raw.errors.slice(0,20).map(e=>`<li>Line ${sanitize(String(e.line))}: ${sanitize(e.error)}</li>`).join('')}</ul>
  </div>` : '';

  container.innerHTML = `<div class="summary-grid">
    <div class="summary-card"><h3>🎯 Findings by Category</h3>${catRows}</div>
    <div class="summary-card"><h3>🌐 Top Source IPs (Findings)</h3>${ipRows}</div>
    <div class="summary-card full-width"><h3>📋 Rules Fired</h3>${ruleRows}</div>
    ${errSection}
  </div>`;

  container.querySelectorAll('.pivot-ip').forEach(btn => {
    btn.addEventListener('click', () => {
      $('search-input').value = `src_ip:${btn.dataset.ip}`;
      $('search-input').dispatchEvent(new Event('input'));
      $$('[data-tab="events"]')[0]?.click();
    });
  });
}

/* ─── TIMELINE TAB ────────────────────────────────────────────────────────── */
function renderTimeline() {
  const container = $('tab-timeline');
  if (!State.raw) return;

  container.innerHTML = `
    <div class="chart-section">
      <div class="chart-card">
        <h3>📈 Event Timeline</h3>
        <div class="chart-wrap"><canvas id="chart-timeline"></canvas></div>
      </div>
      <div class="chart-row">
        <div class="chart-card half">
          <h3>🔵 Findings by Severity</h3>
          <div class="chart-wrap small"><canvas id="chart-donut"></canvas></div>
        </div>
        <div class="chart-card half">
          <h3>🌡 24h Activity Heatmap</h3>
          <div class="chart-wrap small"><canvas id="chart-heatmap"></canvas></div>
        </div>
      </div>
      <div class="chart-row">
        <div class="chart-card half">
          <h3>🎯 Threat Score</h3>
          <div class="chart-wrap small"><canvas id="chart-gauge"></canvas></div>
        </div>
        <div class="chart-card half">
          <h3>📁 Top Categories</h3>
          <div class="chart-wrap small"><canvas id="chart-cats"></canvas></div>
        </div>
      </div>
    </div>`;

  // Draw after paint
  requestAnimationFrame(() => {
    SOCNeonCharts.drawTimeline('chart-timeline', State.raw.records, State.findings);
    SOCNeonCharts.drawDonut('chart-donut', SOCRules.summarizeFindings(State.findings).counts);
    SOCNeonCharts.drawHeatmap('chart-heatmap', State.raw.records);
    const ts = State.threatScore;
    SOCNeonCharts.drawGauge('chart-gauge', ts.score, ts.label);
    const catData = Object.entries(SOCRules.summarizeFindings(State.findings).byCategory)
      .sort((a,b)=>b[1]-a[1]).slice(0,8)
      .map(([label,value]) => ({ label, value }));
    SOCNeonCharts.drawHBar('chart-cats', catData);
  });
}

/* ─── IOCs TAB ────────────────────────────────────────────────────────────── */
function renderIOCs() {
  const container = $('tab-iocs');
  const iocs = State.iocs;
  if (!iocs) { container.innerHTML = '<div class="empty-state"><p>No log data loaded.</p></div>'; return; }

  function iocTable(title, rows, cols, emptyMsg = 'None found', isRawHtml = false) {
    if (!rows.length) return `<div class="ioc-card"><h3>${title}</h3><p class="muted">${emptyMsg}</p></div>`;
    const header = cols.map(c => `<th>${sanitize(c)}</th>`).join('');
    const body   = rows.map(r => `<tr>${r.map(c => `<td>${isRawHtml ? c : sanitize(String(c))}</td>`).join('')}</tr>`).join('');
    return `<div class="ioc-card">
      <div class="ioc-header"><h3>${title} <span class="badge">${rows.length}</span></h3>
        <button class="btn btn-sm export-ioc-csv" data-title="${sanitize(title)}">⬇ CSV</button></div>
      <div class="table-scroll"><table class="events-table ioc-table"><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table></div>
    </div>`;
  }

  const ipRows = iocs.ips.slice(0,100).map(([ip,d]) => {
    let intel = '';
    if (!d.private && window.SOCKillerFeatures) {
      const l = SOCKillerFeatures.getIntelLinks(ip);
      intel = `
        <span style="display:inline-flex;gap:4px;margin-left:6px;">
          <a href="${l.virustotal}" target="_blank" rel="noopener" class="badge" style="background:#00e5ff;color:#000;text-decoration:none;font-size:0.65rem;" title="Search VirusTotal">VT ↗</a>
          <a href="${l.abuseipdb}" target="_blank" rel="noopener" class="badge" style="background:#ff3860;color:#fff;text-decoration:none;font-size:0.65rem;" title="Search AbuseIPDB">Abuse ↗</a>
          <a href="${l.otx}" target="_blank" rel="noopener" class="badge" style="background:#7b2fff;color:#fff;text-decoration:none;font-size:0.65rem;" title="Search AlienVault OTX">OTX ↗</a>
        </span>
      `;
    }
    return [
      `<code>${sanitize(ip)}</code> ${intel}`,
      d.private ? '🔒 Internal' : '🌐 External',
      d.count
    ];
  });
  const hashRows = iocs.hashes.slice(0,50).map(([h,d]) => [h.slice(0,20)+'…', d.type, d.count]);
  const urlRows  = iocs.urls.slice(0,50).map(([u,d]) => [u.slice(0,60), d.count]);
  const userRows = iocs.users.slice(0,30).map(([u,d]) => [u, d.count]);
  const hostRows = iocs.hosts.slice(0,30).map(([h,d]) => [h, d.count]);
  const cveRows  = iocs.cves.slice(0,20).map(c => [c]);
  const emailRows = iocs.emails.slice(0,20).map(e => [e]);

  container.innerHTML = `
    <div class="ioc-toolbar">
      <span class="events-count">IOCs auto-extracted from all events</span>
      <button class="btn btn-sm" id="export-all-iocs">⬇ Export All IOCs (JSON)</button>
    </div>
    <div class="ioc-grid">
      ${iocTable('🌐 IP Addresses', ipRows, ['IP','Type','Events'], 'None found', true)}
      ${iocTable('🔗 URLs / Paths', urlRows, ['URL/Path','Events'])}
      ${iocTable('🔑 File Hashes', hashRows, ['Hash (truncated)','Type','Events'])}
      ${iocTable('👤 Usernames', userRows, ['Username','Events'])}
      ${iocTable('💻 Hostnames', hostRows, ['Hostname','Events'])}
      ${cveRows.length ? iocTable('🛡 CVEs Referenced', cveRows, ['CVE ID']) : ''}
      ${emailRows.length ? iocTable('📧 Email Addresses', emailRows, ['Email']) : ''}
    </div>`;

  $('export-all-iocs').addEventListener('click', () => {
    const out = {
      ips:     iocs.ips.map(([ip,d]) => ({ ip, type: d.private?'internal':'external', count: d.count })),
      urls:    iocs.urls.map(([u,d]) => ({ url: u, count: d.count })),
      hashes:  iocs.hashes.map(([h,d]) => ({ hash: h, type: d.type, count: d.count })),
      users:   iocs.users.map(([u,d]) => ({ username: u, count: d.count })),
      cves:    iocs.cves,
      emails:  iocs.emails,
    };
    download('socneon-iocs.json', JSON.stringify(out, null, 2), 'application/json');
  });
}

/* ─── MITRE ATT&CK TAB ────────────────────────────────────────────────────── */
function renderMITRE() {
  const container = $('tab-mitre');
  const mappings  = SOCNeonAdvanced.getMITREMappings(State.findings);
  const tactics   = SOCNeonAdvanced.MITRE_TACTICS;

  const firedCount  = mappings.filter(t=>t.fired).length;
  const totalCount  = mappings.length;

  container.innerHTML = `
    <div class="mitre-header">
      <div>
        <h3>MITRE ATT&CK® Coverage</h3>
        <p class="muted">${firedCount} of ${totalCount} mapped techniques triggered by detected activity</p>
      </div>
      <div class="mitre-legend">
        <span class="mitre-legend-item fired">⬛ Technique Detected</span>
        <span class="mitre-legend-item">⬜ Not Detected</span>
      </div>
    </div>
    <div class="mitre-matrix" role="grid" aria-label="MITRE ATT&CK Matrix">
      ${tactics.map(tac => {
        const techs = mappings.filter(t => t.tactics.includes(tac.id));
        return `<div class="tactic-col">
          <div class="tactic-header" title="${sanitize(tac.name)}">${sanitize(tac.short)}</div>
          ${techs.map(t => `
            <button class="technique-cell ${t.fired ? 'fired' : ''}"
                    title="${sanitize(t.id)}: ${sanitize(t.name)}&#10;Rules: ${sanitize(t.matchedRules.join(', ')||'none')}&#10;Findings: ${t.count}"
                    data-tid="${sanitize(t.id)}"
                    aria-label="${sanitize(t.id)} ${sanitize(t.name)} ${t.fired?'detected':'not detected'}">
              <span class="tech-id">${sanitize(t.id)}</span>
              <span class="tech-name">${sanitize(t.name.slice(0,22))}</span>
              ${t.count ? `<span class="tech-count">${t.count}</span>` : ''}
            </button>`).join('')}
        </div>`;
      }).join('')}
    </div>
    <div id="mitre-detail" class="mitre-detail" hidden></div>`;

  container.querySelectorAll('.technique-cell.fired').forEach(btn => {
    btn.addEventListener('click', () => {
      const tid = btn.dataset.tid;
      const tech = mappings.find(t => t.id === tid);
      if (!tech) return;
      const related = State.findings.filter(f => tech.rules.includes(f.ruleId));
      const detail = $('mitre-detail');
      detail.hidden = false;
      detail.innerHTML = `
        <div class="mitre-detail-card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem">
            <h3>🎯 ${sanitize(tech.id)} — ${sanitize(tech.name)}</h3>
            <button class="btn-icon-sm" id="close-mitre-detail">✕</button>
          </div>
          <p class="muted">Tactics: ${sanitize(tech.tactics.join(', '))} | Rules: ${sanitize(tech.matchedRules.join(', '))} | ${related.length} findings</p>
          ${related.slice(0,5).map(f => `<div class="alert-card sev-${f.severity}" style="margin:.5rem 0">
            <span class="sev-label" style="color:${SEV_CONFIG[f.severity]?.color}">${f.severity.toUpperCase()}</span>
            <strong style="margin-left:.5rem">${sanitize(f.title)}</strong>
            <p style="font-size:.8rem;color:#8892b0;margin:.25rem 0 0">${sanitize(f.explanation.slice(0,150))}</p>
          </div>`).join('')}
          ${related.length > 5 ? `<p class="muted">+ ${related.length - 5} more findings</p>` : ''}
        </div>`;
      $('close-mitre-detail').addEventListener('click', () => { detail.hidden = true; });
    });
  });
}

/* ─── CORRELATIONS TAB ────────────────────────────────────────────────────── */
function renderCorrelations() {
  const container = $('tab-correlations');
  const chains    = State.correlations;

  if (!chains.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">🔗</div>
      <p>No correlated attack chains detected.<br><span class="muted">Correlation requires ≥2 findings from the same source IP.</span></p></div>`;
    return;
  }

  container.innerHTML = `
    <div class="corr-header">
      <h3>${chains.length} Attack Chain${chains.length!==1?'s':''} Detected</h3>
      <p class="muted">Events grouped by source IP, sorted by severity</p>
    </div>
    ${chains.map((chain, ci) => {
      const cfg = SEV_CONFIG[chain.severity] || SEV_CONFIG.info;
      const dur = formatDuration(chain.timespan);
      const STAGE_NAMES = {1:'Recon',2:'Initial Access',3:'Cred Access',4:'Execution',5:'Persistence',6:'Lateral Mvmt',7:'C2',8:'Exfil'};

      return `<div class="chain-card">
        <div class="chain-header">
          <div class="chain-title">
            <span class="sev-dot" style="background:${cfg.color}"></span>
            <code class="chain-ip">${sanitize(chain.ip)}</code>
            ${chain.isKillChain ? '<span class="kill-chain-badge">⚡ Kill Chain</span>' : ''}
            <span class="chain-meta">${chain.findings.length} alerts · ${sanitize(dur)} · ${sanitize(chain.ruleIds.join(', '))}</span>
          </div>
          <div class="chain-cats">${chain.categories.map(c=>`<span class="category-tag">${sanitize(c)}</span>`).join('')}</div>
        </div>

        <!-- Kill chain stage progress -->
        <div class="stage-track">
          ${[1,2,3,4,5,6,7,8].map(s => {
            const active = chain.stages.includes(s);
            return `<div class="stage-step ${active?'active':''}" title="${STAGE_NAMES[s]||''}">
              <div class="stage-dot"></div>
              <span class="stage-name">${STAGE_NAMES[s]||''}</span>
            </div>`;
          }).join('<div class="stage-line"></div>')}
        </div>

        <!-- Finding timeline -->
        <div class="chain-findings">
          ${chain.findings.map((f, fi) => `
            <div class="chain-finding">
              <div class="chain-time">${f.timestamp ? formatTime(f.timestamp) : '—'}</div>
              <div class="chain-connector">
                <div class="chain-dot sev-${f.severity}"></div>
                ${fi < chain.findings.length-1 ? '<div class="chain-line"></div>' : ''}
              </div>
              <div class="chain-finding-body">
                <span class="sev-label" style="color:${SEV_CONFIG[f.severity]?.color||'#8892b0'};font-size:.7rem">${f.severity.toUpperCase()}</span>
                <strong style="font-size:.85rem">${sanitize(f.title)}</strong>
                <code class="rule-id">${sanitize(f.ruleId)}</code>
                <p style="font-size:.78rem;color:#8892b0;margin:.15rem 0 0">${sanitize(f.explanation.slice(0,100))}…</p>
              </div>
            </div>`).join('')}
        </div>
      </div>`;
    }).join('')}`;
}

/* ─── CUSTOM RULES TAB ────────────────────────────────────────────────────── */
function initCustomRuleBuilder() {
  // Handled via renderCustomRules
}

function renderCustomRules() {
  const container = $('tab-rules');
  const rules = State.customRules;

  container.innerHTML = `
    <div class="crules-layout">
      <!-- Builder form -->
      <div class="crule-builder">
        <h3>⚙ Add Custom Rule</h3>
        <div class="form-grid">
          <label class="form-label">Rule Name
            <input class="form-input" id="cr-name" placeholder="My custom rule" />
          </label>
          <label class="form-label">Field
            <select class="form-input" id="cr-field">
              ${['message','src_ip','dst_ip','dst_port','protocol','action','username','hostname',
                 'process','event_type','url','http_method','http_status','severity','bytes'].map(f =>
                `<option value="${f}">${f}</option>`).join('')}
            </select>
          </label>
          <label class="form-label">Operator
            <select class="form-input" id="cr-operator">
              <option value="contains">contains</option>
              <option value="equals">equals</option>
              <option value="starts">starts with</option>
              <option value="ends">ends with</option>
              <option value="regex">regex</option>
              <option value="gt">greater than (number)</option>
              <option value="lt">less than (number)</option>
            </select>
          </label>
          <label class="form-label">Value
            <input class="form-input" id="cr-value" placeholder="e.g. mimikatz" />
          </label>
          <label class="form-label">Severity
            <select class="form-input" id="cr-severity">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium" selected>Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>
        </div>
        <div style="display:flex;gap:.5rem;margin-top:.75rem">
          <button class="btn btn-primary" id="cr-add">+ Add Rule</button>
          <button class="btn btn-sm" id="cr-test">🧪 Test on Loaded Events</button>
        </div>
        <div id="cr-test-result" class="cr-test-result" hidden></div>
      </div>

      <!-- Existing rules -->
      <div class="crule-list">
        <div class="crule-list-header">
          <h3>📋 Custom Rules (${rules.length})</h3>
          ${rules.length ? '<button class="btn btn-sm" id="cr-clear-all">Clear All</button>' : ''}
        </div>
        ${rules.length ? rules.map(r => `
          <div class="crule-item">
            <div class="crule-info">
              <span class="sev-dot" style="background:${SEV_CONFIG[r.severity]?.color||'#8892b0'}"></span>
              <strong>${sanitize(r.name)}</strong>
              <code class="rule-id">${sanitize(r.field)}</code>
              <span class="muted">${sanitize(r.operator)}</span>
              <code class="rule-id">${sanitize(r.value)}</code>
            </div>
            <button class="btn-icon-sm delete-crule" data-id="${r.id}" aria-label="Delete rule">🗑</button>
          </div>`).join('')
        : '<p class="muted" style="padding:.5rem">No custom rules yet. Add one above.</p>'}
      </div>
    </div>`;

  $('cr-add').addEventListener('click', () => {
    const name = $('cr-name').value.trim();
    const field = $('cr-field').value;
    const operator = $('cr-operator').value;
    const value = $('cr-value').value.trim();
    const severity = $('cr-severity').value;
    if (!name || !value) { showError('Rule name and value are required.'); return; }

    const rule = { id: Date.now(), name, field, operator, value, severity };
    State.customRules.push(rule);
    SOCNeonAdvanced.saveCustomRules(State.customRules);
    // Re-run detection with new rule
    const newFindings = SOCNeonAdvanced.applyCustomRules(State.raw?.records || [], [rule]);
    State.findings.push(...newFindings);
    renderCustomRules();
    updateSeverityBadges(SOCRules.summarizeFindings(State.findings).counts);
  });

  $('cr-test')?.addEventListener('click', () => {
    const field = $('cr-field').value;
    const operator = $('cr-operator').value;
    const value = $('cr-value').value.trim();
    if (!value) return;
    const dummyRule = { id: 0, name: 'Test', field, operator, value, severity: 'info' };
    const hits = SOCNeonAdvanced.applyCustomRules(State.raw?.records || [], [dummyRule]);
    const res = $('cr-test-result');
    res.hidden = false;
    res.innerHTML = hits.length
      ? `<span style="color:var(--accent3)">✅ ${hits.length} event${hits.length!==1?'s':''} matched</span>`
      : `<span style="color:var(--text-muted)">⭕ No events matched</span>`;
  });

  container.querySelectorAll('.delete-crule').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id);
      State.customRules = State.customRules.filter(r => r.id !== id);
      State.findings = State.findings.filter(f => !f.id?.includes(`CUSTOM-${id}`));
      SOCNeonAdvanced.saveCustomRules(State.customRules);
      renderCustomRules();
    });
  });

  $('cr-clear-all')?.addEventListener('click', () => {
    State.customRules = []; SOCNeonAdvanced.saveCustomRules([]);
    State.findings = State.findings.filter(f => !f.isCustom);
    renderCustomRules();
  });
}

/* ─── REPORT TAB ──────────────────────────────────────────────────────────── */
function renderReport() {
  const container = $('tab-report');
  if (!State.raw) {
    container.innerHTML = '<div class="empty-state"><p>Load log data first to generate a report.</p></div>';
    return;
  }
  const ts = State.threatScore;
  const sc = SEV_CONFIG[ts.score >= 80 ? 'critical' : ts.score >= 60 ? 'high' : ts.score >= 40 ? 'medium' : 'low'] || SEV_CONFIG.info;

  container.innerHTML = `
    <div class="report-toolbar">
      <h3>📄 Security Report</h3>
      <div style="display:flex;gap:.5rem">
        <button class="btn" id="report-print">🖨 Print / Save PDF</button>
        <button class="btn btn-primary" id="report-html">⬇ Export HTML</button>
      </div>
    </div>
    <div class="report-preview">
      <div class="rp-header">
        <h1>🛡 SOCNeon Security Report</h1>
        <p class="muted">Generated: ${new Date().toLocaleString()} · Format: ${sanitize(State.raw.format)} · Events: ${State.raw.total.toLocaleString()}</p>
      </div>
      <div class="rp-score-row">
        <div class="rp-score-card" style="border-color:${sc.color}">
          <div class="rp-score-num" style="color:${sc.color}">${ts.score}</div>
          <div class="rp-score-label">${sanitize(ts.label)}</div>
          <div class="muted" style="font-size:.75rem">Threat Score / 100</div>
        </div>
        ${['critical','high','medium','low'].map(sev => `
          <div class="rp-sev-card">
            <div class="rp-sev-num" style="color:${SEV_CONFIG[sev].color}">${State.findings.filter(f=>f.severity===sev).length}</div>
            <div class="rp-sev-label">${sev.charAt(0).toUpperCase()+sev.slice(1)}</div>
          </div>`).join('')}
      </div>
      <div class="rp-section">
        <h2>Top Alerts</h2>
        <table class="events-table"><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Confidence</th><th>Time</th></tr></thead>
        <tbody>${State.findings.slice(0,10).map(f => `<tr>
          <td style="color:${SEV_CONFIG[f.severity]?.color};font-weight:700">${f.severity.toUpperCase()}</td>
          <td><code>${sanitize(f.ruleId)}</code></td>
          <td>${sanitize(f.title)}</td>
          <td>${f.confidence}%</td>
          <td style="font-size:.75rem;color:#8892b0">${f.timestamp ? formatTime(f.timestamp) : '—'}</td>
        </tr>`).join('')}</tbody></table>
      </div>
      <div class="rp-section">
        <h2>MITRE ATT&CK Techniques Detected</h2>
        ${SOCNeonAdvanced.getMITREMappings(State.findings).filter(t=>t.fired).map(t =>
          `<span class="mitre-tag fired" style="margin:.2rem">${sanitize(t.id)} ${sanitize(t.name)}</span>`
        ).join('') || '<p class="muted">None</p>'}
      </div>
      <div class="rp-section">
        <h2>Top External IPs</h2>
        ${(State.iocs?.ips||[]).filter(([ip,d])=>!d.private).slice(0,10).map(([ip,d]) =>
          `<code style="display:inline-block;margin:.15rem;padding:.2rem .5rem;background:var(--bg-card2);border-radius:4px;font-size:.8rem">${sanitize(ip)} ×${d.count}</code>`
        ).join('') || '<p class="muted">None</p>'}
      </div>
    </div>`;

  $('report-print').addEventListener('click', () => window.print());
  $('report-html').addEventListener('click', () => {
    const html = SOCNeonAdvanced.generateReport(State);
    download('socneon-report.html', html, 'text/html');
  });
}

/* ─── Pagination ──────────────────────────────────────────────────────────── */
function renderPagination(total, current) {
  const pages = Math.ceil(total / State.pageSize);
  const el = $('pagination');
  if (pages <= 1) { el.innerHTML=''; return; }
  const btns = pages <= 7
    ? Array.from({length:pages},(_,i)=>i+1)
    : [1,2,'…',current-1,current,current+1,'…',pages-1,pages]
        .filter((v,i,a)=>v==='…'||(v>=1&&v<=pages))
        .filter((v,i,a)=>v!=='…'||a[i-1]!=='…');

  el.innerHTML = `
    <button class="page-btn" ${current===1?'disabled':''} data-page="${current-1}" aria-label="Previous">‹</button>
    ${btns.map(p=>p==='…'?`<span class="page-ellipsis">…</span>`
      :`<button class="page-btn ${p===current?'active':''}" data-page="${p}">${p}</button>`).join('')}
    <button class="page-btn" ${current===pages?'disabled':''} data-page="${current+1}" aria-label="Next">›</button>`;

  el.querySelectorAll('[data-page]').forEach(btn => {
    btn.addEventListener('click', () => {
      State.currentPage = parseInt(btn.dataset.page);
      renderEvents();
      $('tab-events').scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
}

/* ─── Export ──────────────────────────────────────────────────────────────── */
function initExport() {
  $('export-csv-alerts').addEventListener('click',  () => exportCSV(State.filteredFindings,'socneon-alerts'));
  $('export-json-alerts').addEventListener('click', () => exportJSON(State.filteredFindings,'socneon-alerts'));
  $('export-csv-events').addEventListener('click',  () => exportCSV(State.filtered,'socneon-events'));
  $('export-json-events').addEventListener('click', () => exportJSON(State.filtered,'socneon-events'));
}
function exportCSV(data, name) {
  if (!data.length) { showError('No data to export.'); return; }
  const keys = [...new Set(data.flatMap(r=>Object.keys(r).filter(k=>!k.startsWith('_'))))];
  const esc  = v => `"${String(v??'').replace(/"/g,'""')}"`;
  const csv  = [keys.map(esc).join(','),(data.map(r=>keys.map(k=>esc(r[k]??'')).join(',')))].flat().join('\r\n');
  download(`${name}.csv`, csv, 'text/csv');
}
function exportJSON(data, name) {
  if (!data.length) { showError('No data to export.'); return; }
  const clean = data.map(r => { const o={}; for(const [k,v] of Object.entries(r)) if(!k.startsWith('_')) o[k]=v; return o; });
  download(`${name}.json`, JSON.stringify(clean,null,2), 'application/json');
}
function download(filename, content, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content],{type:mime}));
  a.download = filename; a.click();
  URL.revokeObjectURL(a.href);
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */
function formatTime(iso) {
  try { return new Date(iso).toLocaleString(undefined,{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  catch { return iso; }
}
function formatDuration(ms) {
  if (!ms) return '<1s';
  if (ms < 60000)    return `${Math.round(ms/1000)}s`;
  if (ms < 3600000)  return `${Math.round(ms/60000)}m`;
  return `${Math.round(ms/3600000)}h`;
}

/* ─── Theme & Shortcuts ───────────────────────────────────────────────────── */
function initThemeToggle() {
  const btn = $('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
    btn.textContent = document.body.classList.contains('light-mode') ? '🌙' : '☀️';
    // Redraw charts if on timeline tab
    if (State.activeTab === 'timeline') renderTimeline();
  });
}
function initKeyboardShortcuts() {
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey||e.metaKey) && e.key==='k') { e.preventDefault(); $('search-input')?.focus(); }
    if ((e.ctrlKey||e.metaKey) && e.key==='o') { e.preventDefault(); $('file-input')?.click(); }
    if (e.key==='Escape') { $$('.modal.active').forEach(m=>m.classList.remove('active')); }
  });
}

/* ─── Killer Features: Copilot, SIEM & Playbook Rendering ───────────────── */
function renderCopilot() {
  const container = $('copilot-content');
  if (!container || !window.SOCKillerFeatures) return;

  const data = SOCKillerFeatures.runCopilotAnalysis(State.findings, State.raw?.records || [], State.iocs, State.threatScore);

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:1.5rem;max-width:1100px;margin:0 auto;padding:1rem 0;">
      <!-- Hero AI Verdict Card -->
      <div style="background:var(--bg-card);border:1px solid #00e5ff;border-radius:var(--radius-lg);padding:1.5rem;position:relative;overflow:hidden;box-shadow:0 0 25px rgba(0,229,255,0.15);">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
          <div style="display:flex;align-items:center;gap:0.75rem;">
            <span style="font-size:1.8rem;">🤖</span>
            <div>
              <h2 style="font-size:1.25rem;font-weight:700;color:#00ff9d;">AI Forensic Investigation Copilot</h2>
              <p style="font-size:0.75rem;color:var(--text-sec);">Automated Triaged Analysis · MITRE Alignment · Containment Playbooks</p>
            </div>
          </div>
          <span style="padding:0.4rem 0.8rem;border-radius:100px;font-size:0.75rem;font-weight:700;letter-spacing:0.06em;background:rgba(255,56,96,0.15);border:1px solid #ff3860;color:#ff3860;">
            ${sanitize(data.verdict)}
          </span>
        </div>
        <p style="font-size:0.95rem;color:var(--text-primary);line-height:1.65;background:rgba(0,0,0,0.25);border-radius:var(--radius);padding:1rem;border-left:3px solid #00e5ff;">
          ${sanitize(data.summary)}
        </p>
      </div>

      <!-- Containment Actions & Live Remediation -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.5rem;">
        <h3 style="color:#ffd700;display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;font-size:0.95rem;">
          🛡 Instant Incident Containment Checklist (Playbook)
        </h3>
        <ul style="list-style:none;display:flex;flex-direction:column;gap:0.6rem;">
          ${data.containment.map((c, i) => `
            <li style="display:flex;align-items:flex-start;gap:0.75rem;font-size:0.88rem;color:var(--text-primary);background:var(--bg-card2);padding:0.75rem;border-radius:var(--radius);border:1px solid var(--border);">
              <span style="background:#00e5ff;color:#000;font-weight:700;font-size:0.7rem;width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">${i+1}</span>
              <span>${sanitize(c)}</span>
            </li>
          `).join('')}
        </ul>
      </div>

      <!-- Quick Action Buttons -->
      <div style="display:flex;gap:1rem;flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="showTab('siem')">⚡ Inspect SIEM Hunting Queries</button>
        <button class="btn btn-outline" onclick="showTab('playbook')">📋 Export Full Incident Ticket</button>
        <button class="btn btn-ghost" onclick="SOCKillerFeatures.openFeedbackModal()">💬 Send Feedback to Founder</button>
      </div>
    </div>
  `;
}

function renderSIEM() {
  const container = $('siem-content');
  if (!container || !window.SOCKillerFeatures) return;

  const queries = SOCKillerFeatures.generateSIEMQueries(State.findings, State.iocs);

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:1.5rem;max-width:1100px;margin:0 auto;padding:1rem 0;">
      <div>
        <h3>⚡ Cross-SIEM Hunting Query Generator</h3>
        <p class="muted">1-Click hunting rules generated directly from your analyzed log indicators</p>
      </div>

      <!-- Splunk SPL -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.25rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
          <strong style="color:#00e5ff;font-size:0.9rem;">Splunk SPL Query</strong>
          <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard.writeText(this.dataset.query);this.textContent='✓ Copied';" data-query="${encodeURIComponent(queries.splunk)}">Copy SPL</button>
        </div>
        <pre style="background:#070a12;border:1px solid var(--border);border-radius:var(--radius);padding:1rem;color:#7ee787;overflow-x:auto;"><code>${sanitize(queries.splunk)}</code></pre>
      </div>

      <!-- Microsoft Sentinel KQL -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.25rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
          <strong style="color:#7b2fff;font-size:0.9rem;">Microsoft Sentinel / Defender KQL</strong>
          <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard.writeText(this.dataset.query);this.textContent='✓ Copied';" data-query="${encodeURIComponent(queries.sentinelKQL)}">Copy KQL</button>
        </div>
        <pre style="background:#070a12;border:1px solid var(--border);border-radius:var(--radius);padding:1rem;color:#7ee787;overflow-x:auto;"><code>${sanitize(queries.sentinelKQL)}</code></pre>
      </div>

      <!-- Elastic / OpenSearch KQL -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.25rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
          <strong style="color:#00ff9d;font-size:0.9rem;">Elastic / Kibana KQL Query</strong>
          <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard.writeText(this.dataset.query);this.textContent='✓ Copied';" data-query="${encodeURIComponent(queries.elasticKQL)}">Copy Elastic</button>
        </div>
        <pre style="background:#070a12;border:1px solid var(--border);border-radius:var(--radius);padding:1rem;color:#7ee787;overflow-x:auto;"><code>${sanitize(queries.elasticKQL)}</code></pre>
      </div>

      <!-- Sigma YAML Rule -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.25rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
          <strong style="color:#ffd700;font-size:0.9rem;">Sigma Rule (Generic Detection YAML)</strong>
          <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard.writeText(this.dataset.query);this.textContent='✓ Copied';" data-query="${encodeURIComponent(queries.sigma)}">Copy Sigma</button>
        </div>
        <pre style="background:#070a12;border:1px solid var(--border);border-radius:var(--radius);padding:1rem;color:#7ee787;overflow-x:auto;"><code>${sanitize(queries.sigma)}</code></pre>
      </div>
    </div>
  `;
}

function renderPlaybook() {
  const container = $('playbook-content');
  if (!container || !window.SOCKillerFeatures) return;

  const ticketMd = SOCKillerFeatures.generateIncidentTicket(State.findings, State.raw?.records || [], State.iocs, State.threatScore, State.raw?.filename);

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:1.5rem;max-width:1100px;margin:0 auto;padding:1rem 0;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
        <div>
          <h3>🛡 Incident Response Playbook & Ticket Export</h3>
          <p class="muted">Ready-to-file incident report formatted for Jira, TheHive, GitHub Issues, or Slack</p>
        </div>
        <div style="display:flex;gap:0.5rem;">
          <button class="btn btn-sm btn-primary" id="copy-ticket-btn">📋 Copy Ticket Markdown</button>
          <button class="btn btn-sm btn-outline" id="download-ticket-btn">⬇ Download Ticket (.md)</button>
        </div>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.5rem;">
        <pre style="background:#070a12;border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;color:#e2e8f5;font-size:0.83rem;line-height:1.6;white-space:pre-wrap;overflow-x:auto;"><code>${sanitize(ticketMd)}</code></pre>
      </div>
    </div>
  `;

  $('copy-ticket-btn').addEventListener('click', () => {
    navigator.clipboard.writeText(ticketMd);
    $('copy-ticket-btn').textContent = '✓ Copied!';
    setTimeout(() => $('copy-ticket-btn').textContent = '📋 Copy Ticket Markdown', 2000);
  });

  $('download-ticket-btn').addEventListener('click', () => {
    download('socneon-incident-ticket.md', ticketMd, 'text/markdown');
  });
}
