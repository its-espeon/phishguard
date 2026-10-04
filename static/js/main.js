/* =========================================================
   PhishGuard – Main JavaScript
   ========================================================= */

const form         = document.getElementById('scan-form');
const urlInput     = document.getElementById('url-input');
const scanBtn      = document.getElementById('scan-btn');
const btnText      = scanBtn.querySelector('.btn-text');
const spinner      = document.getElementById('spinner');
const resultsSection = document.getElementById('results-section');
const errorBanner  = document.getElementById('error-banner');
const errorText    = document.getElementById('error-text');

// Verdict card elements
const verdictCard  = document.getElementById('verdict-card');
const verdictIcon  = document.getElementById('verdict-icon');
const verdictText  = document.getElementById('verdict-text');
const scoreNumber  = document.getElementById('score-number');
const ringFill     = document.getElementById('ring-fill');
const scannedUrlDisplay = document.getElementById('scanned-url-display');

// Stat values
const statAgeValue       = document.getElementById('stat-age-value');
const statHttpsValue     = document.getElementById('stat-https-value');
const statVtValue        = document.getElementById('stat-vt-value');
const statShortenerValue = document.getElementById('stat-shortener-value');

// Detail sections
const flagsList        = document.getElementById('flags-list');
const vtContent        = document.getElementById('vt-content');
const heuristicGrid    = document.getElementById('heuristic-grid');

// Ring circumference (2 * pi * 52)
const RING_CIRC = 2 * Math.PI * 52; // ≈ 326.73

const VERDICT_CONFIG = {
  safe:       { icon: '✅', color: '#00e5a0', ringColor: '#00e5a0' },
  caution:    { icon: '⚠️', color: '#ffd166', ringColor: '#ffd166' },
  suspicious: { icon: '🚨', color: '#ff9a3c', ringColor: '#ff9a3c' },
  dangerous:  { icon: '☠️', color: '#ff4d6d', ringColor: '#ff4d6d' },
};

/* ---- Utilities ---- */
function setLoading(loading) {
  scanBtn.disabled = loading;
  if (loading) {
    btnText.classList.add('hidden');
    spinner.classList.remove('hidden');
  } else {
    btnText.classList.remove('hidden');
    spinner.classList.add('hidden');
  }
}

function showError(msg) {
  errorText.textContent = msg;
  errorBanner.classList.remove('hidden');
  resultsSection.classList.add('hidden');
}

function hideError() {
  errorBanner.classList.add('hidden');
}

function animateScore(targetScore, color) {
  ringFill.style.stroke = color;
  const offset = RING_CIRC * (1 - targetScore / 100);
  ringFill.style.strokeDashoffset = offset;

  let current = 0;
  const duration = 1200;
  const start = performance.now();
  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    current = Math.round(eased * targetScore);
    scoreNumber.textContent = current;
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function formatAge(domain_age) {
  if (domain_age.error && !domain_age.age_days) {
    return domain_age.error.includes('key') ? 'Lookup Error' : 'Unknown';
  }
  if (domain_age.age_days === null || domain_age.age_days === undefined) return 'Unknown';
  const days = domain_age.age_days;
  if (days < 30)   return `${days} day${days !== 1 ? 's' : ''} old`;
  if (days < 365)  return `${Math.floor(days / 30)} months old`;
  const years = (days / 365).toFixed(1);
  return `${years} years old`;
}

function renderFlags(flags) {
  flagsList.innerHTML = '';
  if (!flags || flags.length === 0) {
    flagsList.innerHTML = '<p class="no-flags">✅ No suspicious indicators detected.</p>';
    return;
  }
  flags.forEach((flag, i) => {
    const div = document.createElement('div');
    div.className = `flag-item ${flag.severity}`;
    div.style.animationDelay = `${i * 0.06}s`;
    div.innerHTML = `
      <span class="flag-severity">${flag.severity.toUpperCase()}</span>
      <span>${escapeHtml(flag.label)}</span>
    `;
    flagsList.appendChild(div);
  });
}

function renderVT(vt) {
  vtContent.innerHTML = '';
  if (vt.error) {
    vtContent.innerHTML = `<p class="vt-error">⚠️ ${escapeHtml(vt.error)}</p>`;
    return;
  }
  const positives = vt.positives ?? 0;
  const total     = vt.total ?? 0;
  const clean     = total - positives;

  const statsHtml = `
    <div class="vt-stat-row">
      <div class="vt-stat malicious">
        <div class="vt-stat-num">${positives}</div>
        <div class="vt-stat-lbl">Flagged</div>
      </div>
      <div class="vt-stat clean">
        <div class="vt-stat-num">${clean}</div>
        <div class="vt-stat-lbl">Clean</div>
      </div>
      <div class="vt-stat total">
        <div class="vt-stat-num">${total}</div>
        <div class="vt-stat-lbl">Engines</div>
      </div>
    </div>
  `;

  let enginesHtml = '';
  if (vt.flagged_by && vt.flagged_by.length > 0) {
    const chips = vt.flagged_by.map(e => `<span class="vt-engine-chip">${escapeHtml(e)}</span>`).join('');
    enginesHtml = `
      <p class="vt-engines-label">Flagged by:</p>
      <div class="vt-engines">${chips}</div>
    `;
  }

  vtContent.innerHTML = statsHtml + enginesHtml;

  // Update VT stat card
  statVtValue.textContent = total > 0 ? `${positives}/${total} flagged` : 'Not available';
}

function renderHeuristics(findings) {
  heuristicGrid.innerHTML = '';
  const items = [
    { key: 'HTTPS',             val: findings.uses_https,          yesOk: true },
    { key: 'IP as Host',        val: findings.has_ip_address,      yesOk: false },
    { key: 'URL Shortener',     val: findings.is_url_shortener,    yesOk: false },
    { key: 'Suspicious TLD',    val: findings.suspicious_tld,      yesOk: false },
    { key: 'Excessive Subdomains', val: findings.excessive_subdomains, yesOk: false },
    { key: 'Long URL',          val: findings.long_url,            yesOk: false },
    { key: '@ Symbol in URL',   val: findings.has_at_symbol,       yesOk: false },
    { key: 'Double Slash Redirect', val: findings.has_double_slash, yesOk: false },
    { key: 'Hyphen in Domain',  val: findings.hyphen_in_domain,    yesOk: false },
    { key: 'URL Length',        val: `${findings.url_length} chars`, raw: true },
    { key: 'Special Chars',     val: findings.special_char_count,  raw: true },
  ];

  items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'heuristic-item';
    let valHtml;
    if (item.raw) {
      valHtml = `<span class="heuristic-val neutral">${escapeHtml(String(item.val))}</span>`;
    } else {
      const isGood = item.yesOk ? item.val : !item.val;
      const cls    = isGood ? 'ok' : 'bad';
      valHtml = `<span class="heuristic-val ${cls}">${item.val ? 'Yes' : 'No'}</span>`;
    }
    div.innerHTML = `<span class="heuristic-key">${escapeHtml(item.key)}</span>${valHtml}`;
    heuristicGrid.appendChild(div);
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ---- Main Scan ---- */
async function scanUrl(url) {
  setLoading(true);
  hideError();
  resultsSection.classList.add('hidden');

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Server error');
    }

    const data = await resp.json();
    renderResults(data);

  } catch (err) {
    showError(`❌ ${err.message}`);
  } finally {
    setLoading(false);
  }
}

function renderResults(data) {
  const cfg = VERDICT_CONFIG[data.verdict_class] || VERDICT_CONFIG['caution'];

  // Verdict card
  verdictCard.className = `verdict-card glass-card ${data.verdict_class}`;
  verdictIcon.textContent = cfg.icon;
  verdictText.textContent = data.verdict;
  verdictText.className   = `verdict-text ${data.verdict_class}`;
  scannedUrlDisplay.textContent = data.url;

  // Score ring animation
  animateScore(data.final_score, cfg.ringColor);

  // Stat cards
  // Domain Age
  const ageStr = formatAge(data.domain_age);
  statAgeValue.textContent = ageStr;
  if (data.domain_age.age_days !== null && data.domain_age.age_days < 180) {
    statAgeValue.style.color = 'var(--dangerous)';
  } else {
    statAgeValue.style.color = 'var(--text)';
  }

  // HTTPS
  statHttpsValue.textContent = data.findings.uses_https ? 'HTTPS ✅' : 'HTTP ⚠️';
  statHttpsValue.style.color = data.findings.uses_https ? 'var(--safe)' : 'var(--suspicious)';

  // Shortener
  statShortenerValue.textContent = data.findings.is_url_shortener ? 'Detected ⚠️' : 'Not Detected ✅';
  statShortenerValue.style.color = data.findings.is_url_shortener ? 'var(--suspicious)' : 'var(--safe)';

  // Render sections
  renderVT(data.virustotal);
  renderFlags(data.flags);
  renderHeuristics(data.findings);

  // Show
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---- Event Listeners ---- */
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    showError('Please enter a URL to scan.');
    return;
  }
  scanUrl(url);
});

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') form.dispatchEvent(new Event('submit'));
});
