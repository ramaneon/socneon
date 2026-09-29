// ─── SOCNeon Killer Features Module (v2.5) ──────────────────────────────
// 1. Neon AI Threat Engine & Natural Language Investigation
// 2. Threat Intel Enrichment (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan)
// 3. SIEM Query Generator (Splunk SPL, Elastic KQL, Sentinel KQL, Sigma YAML)
// 4. Incident Response Playbook & Ticket Export (Jira, TheHive, Markdown)
// 5. Direct Effortless Feedback Modal (techineonbusiness@gmail.com)
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

window.SOCKillerFeatures = (() => {

  // ─── 1. Neon AI Incident Analysis ─────────────────────────────────────────
  function runNeonAnalysis(findings, records, iocs, threatScore) {
    if (!findings || findings.length === 0) {
      return {
        summary: "No anomalous security findings detected in the provided telemetry.",
        verdict: "BENIGN / NORMAL ACTIVITY",
        tactics: [],
        containment: ["Continue standard passive endpoint and perimeter monitoring."],
        queries: { splunk: "# No threat indicators to hunt", kql: "// No threat indicators", sigma: "# No rule" }
      };
    }

    const topFinding = findings[0];
    const criticals = findings.filter(f => f.severity === 'critical');
    const highs = findings.filter(f => f.severity === 'high');
    const ips = Object.keys(iocs?.ips || {});
    const topIP = ips.length > 0 ? ips[0] : 'N/A';

    let verdict = 'SUSPICIOUS ACTIVITY';
    if (criticals.length > 0 || (threatScore && threatScore.score >= 75)) {
      verdict = 'ACTIVE COMPROMISE DETECTED (HIGH SEVERITY)';
    } else if (highs.length > 0) {
      verdict = 'POTENTIAL THREAT / LATERAL PROBING';
    }

    // Build intelligent narrative
    let narrative = `Analysis of ${records.length} events identified ${findings.length} security alerts with an overall Threat Score of ${threatScore?.score ?? 0}/100. `;
    if (criticals.length > 0) {
      narrative += `Critical priority alert: "${criticals[0].ruleName}" was triggered. Evidence indicates high-confidence hostile activity targeting host/network assets. `;
    } else {
      narrative += `Primary detection: "${topFinding.ruleName}". `;
    }
    if (ips.length > 0) {
      narrative += `Associated suspicious IP addresses include ${ips.slice(0, 3).join(', ')}.`;
    }

    // Recommended Containment Playbook Actions
    const containment = [];
    if (criticals.some(f => f.ruleId === 'SMB_LATERAL' || f.ruleId === 'RDP_SUSPICIOUS')) {
      containment.push('Isolate affected endpoint(s) from internal VLAN to prevent lateral spread.');
      containment.push('Revoke compromised Active Directory kerberos tickets and force immediate password reset.');
    }
    if (criticals.some(f => f.ruleId === 'C2_BEACON' || f.ruleId === 'DATA_EXFIL')) {
      containment.push(`Block outbound C2 communications at perimeter firewall/proxy for target IP(s): ${ips.slice(0, 3).join(', ')}.`);
      containment.push('Capture memory dump of the infected workstation/server for rootkit & beacon extraction.');
    }
    if (findings.some(f => f.ruleId === 'PORT_SCAN' || f.ruleId === 'BRUTE_FORCE')) {
      containment.push(`Enforce temporary IP rate-limiting / drop rule for external source: ${topIP}.`);
      containment.push('Audit authentication logs for successful logins originating from anomalous IPs.');
    }
    if (containment.length === 0) {
      containment.push('Review system logs for unauthorized service installations or process executions.');
      containment.push('Verify hash signatures of newly dropped binaries against known good baselines.');
    }

    return {
      summary: narrative,
      verdict,
      topIP,
      containment,
      queries: generateSIEMQueries(findings, iocs)
    };
  }

  // ─── 2. SIEM Query Generator ─────────────────────────────────────────────
  function generateSIEMQueries(findings, iocs) {
    const ips = Object.keys(iocs?.ips || {});
    const ipList = ips.slice(0, 5);
    const ipFilterSplunk = ipList.length > 0 ? `(src_ip IN (${ipList.map(ip => `"${ip}"`).join(', ')}) OR dest_ip IN (${ipList.map(ip => `"${ip}"`).join(', ')}))` : `event_id IN (4624, 4625, 4688)`;
    const ipFilterKQL = ipList.length > 0 ? `| where SourceIP in (${ipList.map(ip => `"${ip}"`).join(', ')}) or DestinationIP in (${ipList.map(ip => `"${ip}"`).join(', ')})` : `| where EventID in (4624, 4625, 4688)`;

    const splunk = `index=* sourcetype=security ${ipFilterSplunk}
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip, dest_ip, action, signature
| where count > 1
| sort - count`;

    const sentinelKQL = `SecurityEvent
${ipFilterKQL}
| summarize AlertCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Account, Computer, EventID
| order by AlertCount desc`;

    const elasticKQL = ipList.length > 0 ? `(source.ip: (${ipList.join(' OR ')}) OR destination.ip: (${ipList.join(' OR ')})) AND event.outcome: ("failure" OR "denied")` : `event.category: "authentication" AND event.outcome: "failure"`;

    const sigma = `title: Detect Suspicious Activity Identified by SOCNeon
id: ${Math.random().toString(36).substring(2, 10)}-${Date.now()}
status: experimental
description: Auto-generated hunting rule from SOCNeon forensic analysis
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
${ipList.map(ip => `            - '${ip}'`).join('\n') || "            - '10.0.0.0/8'"}
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1078`;

    return { splunk, sentinelKQL, elasticKQL, sigma };
  }

  // ─── 3. Threat Intel Enrichment Links ────────────────────────────────────
  function getIntelLinks(ipOrHash) {
    return {
      virustotal: `https://www.virustotal.com/gui/search/${encodeURIComponent(ipOrHash)}`,
      abuseipdb: `https://www.abuseipdb.com/check/${encodeURIComponent(ipOrHash)}`,
      otx: `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(ipOrHash)}`,
      shodan: `https://www.shodan.io/host/${encodeURIComponent(ipOrHash)}`,
      threatfox: `https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent(ipOrHash)}`
    };
  }

  // ─── 4. Incident Response Playbook & TheHive/Jira Markdown ───────────────
  function generateIncidentTicket(findings, records, iocs, threatScore, filename) {
    const analysis = runNeonAnalysis(findings, records, iocs, threatScore);
    const date = new Date().toISOString();
    const ips = Object.keys(iocs?.ips || {});

    return `## [INCIDENT TICKET] Security Anomaly Detected in ${filename || 'Log Stream'}
**Date / Timestamp:** ${date}
**Severity Verdict:** ${analysis.verdict}
**Overall Threat Score:** ${threatScore?.score ?? 0}/100
**Total Log Events:** ${records?.length || 0} | **Findings Triggered:** ${findings?.length || 0}

---

### Executive Incident Summary
${analysis.summary}

---

### High Priority IOCs
- **Primary Source / Target IPs:** ${ips.slice(0, 8).join(', ') || 'None identified'}
- **Associated MITRE Tactics:** ${findings.map(f => f.category).filter((v, i, a) => a.indexOf(v) === i).join(', ') || 'Discovery, Execution'}

---

### Containment & Response Checklist (Playbook)
${analysis.containment.map((c, i) => `- [ ] **Step ${i + 1}:** ${c}`).join('\n')}

---

### Hunting & Detection Queries
#### Splunk SPL
\`\`\`splunk
${analysis.queries.splunk}
\`\`\`

#### Microsoft Sentinel KQL
\`\`\`kql
${analysis.queries.sentinelKQL}
\`\`\`

#### Sigma Rule YAML
\`\`\`yaml
${analysis.queries.sigma}
\`\`\`

*Generated automatically by SOCNeon Forensic AI Engine.*`;
  }

  // ─── 5. Direct Effortless Feedback (techineonbusiness@gmail.com) ──────────
  function openFeedbackModal() {
    let modal = document.getElementById('feedback-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'feedback-modal';
      modal.className = 'modal active';
      modal.innerHTML = `
        <div class="modal-box feedback-box" style="max-width:560px;background:rgba(15,18,28,0.95);border:1.5px solid #00e5ff;box-shadow:0 0 35px rgba(0,229,255,0.2);">
          <div class="modal-header">
            <h2 style="display:flex;align-items:center;gap:0.5rem;font-size:1.15rem;color:#00e5ff;">
              <span>⚡</span> Direct Feedback to Founder
            </h2>
            <button class="modal-close" id="close-feedback-btn">✕</button>
          </div>
          <div style="padding:1rem 0;">
            <p style="font-size:0.85rem;color:var(--text-sec);margin-bottom:1.25rem;line-height:1.5;">
              Send your bug reports, feature requests, or collaboration notes directly to <strong style="color:#00ff9d;">techineonbusiness@gmail.com</strong>.
            </p>

            <div style="margin-bottom:0.75rem;">
              <label style="font-size:0.72rem;color:var(--text-muted);display:block;margin-bottom:0.3rem;letter-spacing:0.06em;font-weight:600;">YOUR NAME OR ROLE (OPTIONAL)</label>
              <input type="text" id="fb-sender" class="search-input" placeholder="e.g. Alex (Security Analyst) / user@company.com" style="width:100%;height:38px;background:#090d16;" />
            </div>

            <div style="margin-bottom:1rem;">
              <label style="font-size:0.72rem;color:var(--text-muted);display:block;margin-bottom:0.3rem;letter-spacing:0.06em;font-weight:600;">FEEDBACK MESSAGE *</label>
              <textarea id="fb-comment" class="paste-textarea" style="height:120px;width:100%;font-size:0.85rem;background:#090d16;" placeholder="Describe what isn't working or the features you'd like added..."></textarea>
            </div>

            <div id="fb-alert-box" style="display:none;padding:0.6rem 0.9rem;border-radius:8px;font-size:0.82rem;margin-bottom:1rem;"></div>

            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.75rem;">
              <div style="display:flex;gap:0.5rem;">
                <button type="button" class="btn btn-sm btn-ghost" id="fb-gmail-btn" title="Open directly in Gmail in a new tab">
                  ✉️ Open Gmail Web
                </button>
                <button type="button" class="btn btn-sm btn-ghost" id="fb-copy-btn" title="Copy formatted feedback to clipboard">
                  📋 Copy Text
                </button>
              </div>
              <button type="button" class="btn btn-primary" id="fb-send-btn">
                🚀 Send Instantly
              </button>
            </div>
          </div>
        </div>
      `;
      document.body.appendChild(modal);

      const closeBtn = document.getElementById('close-feedback-btn');
      closeBtn.addEventListener('click', () => modal.classList.remove('active'));
      modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });

      // Direct AJAX FormSubmit to techineonbusiness@gmail.com
      document.getElementById('fb-send-btn').addEventListener('click', async () => {
        const sender = document.getElementById('fb-sender').value.trim() || 'Anonymous User';
        const comment = document.getElementById('fb-comment').value.trim();
        const alertBox = document.getElementById('fb-alert-box');
        const sendBtn = document.getElementById('fb-send-btn');

        if (!comment) {
          alertBox.style.display = 'block';
          alertBox.style.background = 'rgba(255,56,96,0.15)';
          alertBox.style.border = '1px solid #ff3860';
          alertBox.style.color = '#ff6685';
          alertBox.textContent = 'Please enter your message before sending.';
          return;
        }

        sendBtn.disabled = true;
        sendBtn.textContent = '⏳ Sending…';
        alertBox.style.display = 'none';

        try {
          const res = await fetch('https://formsubmit.co/ajax/techineonbusiness@gmail.com', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({
              name: sender,
              _subject: `[SOCNeon Feedback] from ${sender}`,
              message: comment,
              timestamp: new Date().toUTCString(),
              source: window.location.href
            })
          });

          if (res.ok) {
            alertBox.style.display = 'block';
            alertBox.style.background = 'rgba(0,255,157,0.15)';
            alertBox.style.border = '1px solid #00ff9d';
            alertBox.style.color = '#00ff9d';
            alertBox.textContent = '✓ Feedback sent successfully to techineonbusiness@gmail.com! Thank you!';
            document.getElementById('fb-comment').value = '';
            setTimeout(() => { modal.classList.remove('active'); alertBox.style.display = 'none'; }, 2200);
          } else {
            throw new Error('API submission error');
          }
        } catch (_) {
          // Automatic seamless fallback to Gmail Web Compose
          const subject = encodeURIComponent(`[SOCNeon Feedback] from ${sender}`);
          const body = encodeURIComponent(`Hi Techineon Team,\n\nFeedback from: ${sender}\n\nMessage:\n${comment}\n\nSent via SOCNeon Web App`);
          window.open(`https://mail.google.com/mail/?view=cm&fs=1&to=techineonbusiness@gmail.com&su=${subject}&body=${body}`, '_blank');

          alertBox.style.display = 'block';
          alertBox.style.background = 'rgba(0,229,255,0.15)';
          alertBox.style.border = '1px solid #00e5ff';
          alertBox.style.color = '#00e5ff';
          alertBox.textContent = '✓ Gmail Web opened with your message pre-filled to techineonbusiness@gmail.com!';
        } finally {
          sendBtn.disabled = false;
          sendBtn.textContent = '🚀 Send Instantly';
        }
      });

      // 1-Click Gmail Web Compose
      document.getElementById('fb-gmail-btn').addEventListener('click', () => {
        const sender = document.getElementById('fb-sender').value.trim() || 'Anonymous User';
        const comment = document.getElementById('fb-comment').value.trim() || 'Feedback regarding SOCNeon';
        const subject = encodeURIComponent(`[SOCNeon Feedback] from ${sender}`);
        const body = encodeURIComponent(`Hi Techineon Team,\n\nFeedback from: ${sender}\n\nMessage:\n${comment}\n\nSent via SOCNeon Web App`);
        window.open(`https://mail.google.com/mail/?view=cm&fs=1&to=techineonbusiness@gmail.com&su=${subject}&body=${body}`, '_blank');
      });

      // 1-Click Copy to Clipboard
      document.getElementById('fb-copy-btn').addEventListener('click', () => {
        const sender = document.getElementById('fb-sender').value.trim() || 'Anonymous User';
        const comment = document.getElementById('fb-comment').value.trim();
        const textToCopy = `To: techineonbusiness@gmail.com\nSubject: [SOCNeon Feedback] from ${sender}\n\n${comment || 'No comment provided'}`;
        navigator.clipboard.writeText(textToCopy);
        const copyBtn = document.getElementById('fb-copy-btn');
        copyBtn.textContent = '✓ Copied!';
        setTimeout(() => copyBtn.textContent = '📋 Copy Text', 2000);
      });

    } else {
      modal.classList.add('active');
    }
  }

  return {
    runNeonAnalysis,
    generateSIEMQueries,
    getIntelLinks,
    generateIncidentTicket,
    openFeedbackModal
  };

})();
