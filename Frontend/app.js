/* ============================================================
   WebCure — app.js
   OWASP Top 10 (2021) Vulnerability Scanner
   Author  : Chandransh Ranjan
   Project : WebCure v2.4
   API     : POST /api/scan  |  POST /api/report
   ============================================================ */

// ── Global state ──────────────────────────────────────────────────────────────
let lastScanData = null;   // Holds last WebCure scan result for PDF export

// ── Option chip toggles ────────────────────────────────────────────────────────
document.querySelectorAll('.option-chip').forEach(chip => {
  const cb    = chip.querySelector('input');
  const check = chip.querySelector('.check');
  chip.addEventListener('click', () => {
    cb.checked = !cb.checked;
    check.textContent = cb.checked ? '✓' : '';
    chip.classList.toggle('active', cb.checked);
  });
});

// ── Button listeners ───────────────────────────────────────────────────────────
document.getElementById('scanBtn').addEventListener('click', startScan);
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
document.getElementById('downloadBtn').addEventListener('click', downloadReport);

// ── Severity → CSS class map ───────────────────────────────────────────────────
const SEV_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
  INFO:     'sev-info',
};

// ── WebCure progress steps ─────────────────────────────────────────────────────
const WEBCURE_PROGRESS_STEPS = [
  [10, 'WebCure: Initializing engine…'],
  [20, 'WebCure: Resolving DNS records…'],
  [35, 'WebCure: Probing HTTP headers…'],
  [50, 'WebCure: Checking SSL/TLS certificates…'],
  [62, 'WebCure: Testing for injection vectors…'],
  [75, 'WebCure: Analyzing components & versions…'],
  [88, 'WebCure: Running CORS & auth checks…'],
];

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ── Helpers ────────────────────────────────────────────────────────────────────
function getSelectedOptions() {
  const selected = [];
  document.querySelectorAll('.option-chip input:checked').forEach(cb => {
    selected.push(cb.closest('.option-chip').textContent.trim());
  });
  return selected;
}

function setProgress(pct, msg) {
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressMsg').textContent  = msg;
  document.getElementById('progressPct').textContent  = pct + '%';
}

function escapeHtml(str = '') {
  return str
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Render scan results ────────────────────────────────────────────────────────
function renderResults(data) {
  lastScanData = data;

  const vulnList = document.getElementById('vulnList');
  vulnList.innerHTML = '';

  let critical = 0, high = 0, med = 0, low = 0;

  (data.vulnerabilities || []).forEach(v => {
    const sev = (v.severity || 'INFO').toUpperCase();
    if      (sev === 'CRITICAL') critical++;
    else if (sev === 'HIGH')     high++;
    else if (sev === 'MEDIUM')   med++;
    else                         low++;

    const el = document.createElement('div');
    el.className = 'vuln-item';
    el.innerHTML = `
      <span class="severity ${SEV_CLASS[sev] || 'sev-info'}">${sev}</span>
      <div style="flex:1;min-width:0">
        <div class="vuln-name">${escapeHtml(v.name)}</div>
        <div class="vuln-desc">${escapeHtml(v.description)}</div>
        ${v.owasp_id ? `<div class="vuln-desc" style="margin-top:3px;color:#3a5060">${escapeHtml(v.owasp_id)} — ${escapeHtml(v.owasp_name || '')}</div>` : ''}
        ${v.remediation ? `<div class="vuln-fix">⚡ ${escapeHtml(v.remediation)}</div>` : ''}
      </div>
      ${v.cvss ? `<div class="vuln-cvss" title="CVSS Score">${parseFloat(v.cvss).toFixed(1)}</div>` : ''}
    `;
    vulnList.appendChild(el);
  });

  document.getElementById('riskScore').textContent = data.risk_score ?? 0;
  document.getElementById('countHigh').textContent = critical + high;
  document.getElementById('countMed').textContent  = med;
  document.getElementById('countLow').textContent  = low;

  document.getElementById('results').classList.add('visible');
  document.getElementById('downloadBtn').classList.add('visible');
}

// ── Main scan function ─────────────────────────────────────────────────────────
async function startScan() {
  const rawUrl = document.getElementById('urlInput').value.trim();
  if (!rawUrl) { document.getElementById('urlInput').focus(); return; }

  const targetUrl = rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl;
  const btn       = document.getElementById('scanBtn');
  const pw        = document.getElementById('progressWrap');

  // Reset UI
  lastScanData = null;
  document.getElementById('downloadBtn').classList.remove('visible');
  document.getElementById('results').classList.remove('visible');
  document.querySelectorAll('.alert-error').forEach(el => el.remove());

  btn.classList.add('loading');
  btn.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
         stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0"/>
    </svg>
    WebCure Scanning…
  `;
  pw.classList.add('visible');
  setProgress(0, 'WebCure: Initializing engine…');

  try {
    // Animated progress while backend runs
    let stepIndex = 0;
    const ticker = setInterval(() => {
      if (stepIndex < WEBCURE_PROGRESS_STEPS.length) {
        const [pct, msg] = WEBCURE_PROGRESS_STEPS[stepIndex++];
        setProgress(pct, msg);
      }
    }, 950);

    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url:     targetUrl,
        options: getSelectedOptions(),
        tool:    'WebCure',
        author:  'Chandransh Ranjan',
      }),
    });

    clearInterval(ticker);

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || `WebCure server error: ${response.status}`);
    }

    const data = await response.json();

    setProgress(100, 'WebCure: Compiling report…');
    await delay(500);
    pw.classList.remove('visible');

    renderResults(data);

  } catch (err) {
    pw.classList.remove('visible');
    showError('WebCure Error: ' + err.message);
  } finally {
    btn.classList.remove('loading');
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
           stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      Rescan
    `;
  }
}

// ── Download WebCure PDF Report ────────────────────────────────────────────────
async function downloadReport() {
  if (!lastScanData) return;

  const btn = document.getElementById('downloadBtn');
  btn.classList.add('loading');
  btn.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
         stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0"/>
    </svg>
    <span>WebCure: Generating PDF…</span>
  `;

  try {
    const response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(lastScanData),
    });

    if (!response.ok) throw new Error('WebCure report generation failed');

    const blob   = await response.blob();
    const url    = URL.createObjectURL(blob);
    const a      = document.createElement('a');
    const domain = new URL(lastScanData.url).hostname.replace('www.', '');
    const date   = new Date().toISOString().slice(0, 10);

    a.href     = url;
    a.download = `WebCure_Report_${domain}_${date}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

  } catch (err) {
    showError('WebCure PDF Error: ' + err.message);
  } finally {
    btn.classList.remove('loading');
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
           stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      <span>Download WebCure Report (PDF)</span>
    `;
  }
}

// ── Inline error alert ─────────────────────────────────────────────────────────
function showError(message) {
  document.querySelectorAll('.alert-error').forEach(el => el.remove());
  const alertEl = document.createElement('div');
  alertEl.className = 'alert alert-warn alert-error';
  alertEl.innerHTML = `<span class="alert-icon">✕</span><div>${escapeHtml(message)}</div>`;
  const card = document.querySelector('.card');
  const inputGroup = document.getElementById('urlInput').closest('.input-group');
  card.insertBefore(alertEl, inputGroup.nextSibling);
  setTimeout(() => alertEl.remove(), 7000);
}
