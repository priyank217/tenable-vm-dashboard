const PAGE_SIZE = 25;
const POLL_MS = 4000;

let allCerts = [];
let filteredCerts = [];
let currentFilter = 'all';
let healthFilter = null; // 'valid' | 'expiring' | 'expired' | null (Certificate Health bars)
let currentPage = 1;
let pollTimer = null;

const el = (id) => document.getElementById(id);

function fmtNumber(n) {
  if (n == null || Number.isNaN(n)) return '—';
  return Number(n).toLocaleString();
}

function fmtDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

function setSyncStatus(state, label) {
  const dot = el('status-dot');
  const text = el('last-sync');
  dot.className = 'status-dot' + (state ? ` ${state}` : '');
  if (label) text.textContent = label;
}

function showError(message) {
  el('error-banner').classList.remove('hidden');
  el('error-message').textContent = message || 'Unknown error';
}

function hideError() {
  el('error-banner').classList.add('hidden');
}

function setLoading(on, message) {
  const banner = el('loading-banner');
  const btn = el('refresh-btn');
  const icon = el('refresh-icon');
  const label = el('refresh-label');
  if (on) {
    banner.classList.remove('hidden');
    if (message) el('loading-message').textContent = message;
    btn.disabled = true;
    icon.classList.add('spinner');
    label.textContent = 'Syncing…';
    setSyncStatus('loading');
  } else {
    banner.classList.add('hidden');
    btn.disabled = false;
    icon.classList.remove('spinner');
    label.textContent = 'Refresh';
  }
}

function statusPillClass(status, days) {
  if (status === 'expired' || (typeof days === 'number' && days < 0)) return 'red';
  if (status === 'expiring' || (typeof days === 'number' && days <= 30)) return 'amber';
  if (status === 'valid') return 'green';
  return 'blue';
}

function statusLabel(cert) {
  const days = cert.daysRemaining;
  if (typeof days === 'number') {
    if (days < 0) return `Expired ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago`;
    if (days === 0) return 'Expires today';
    return `${days} day${days === 1 ? '' : 's'}`;
  }
  return cert.status || 'Unknown';
}

function certMatchesHealth(cert, filter) {
  const days = cert.daysRemaining;
  const status = (cert.status || '').toLowerCase();
  if (filter === 'valid') {
    return status === 'valid' || (typeof days === 'number' && days > 30);
  }
  if (filter === 'expiring') {
    return status === 'expiring' || (typeof days === 'number' && days >= 0 && days <= 30);
  }
  if (filter === 'expired') {
    return typeof days === 'number' ? days < 0 : status === 'expired';
  }
  return true;
}

function applyFilter() {
  filteredCerts = allCerts.filter((cert) => {
    const days = cert.daysRemaining;
    const internet = !!cert.internetFacing;

    if (healthFilter) return certMatchesHealth(cert, healthFilter);

    if (currentFilter === 'all') return true;
    if (currentFilter === 'valid') return certMatchesHealth(cert, 'valid');
    if (currentFilter === 'expiring') return certMatchesHealth(cert, 'expiring');
    if (currentFilter === 'expired') return certMatchesHealth(cert, 'expired');
    if (currentFilter === '7') return typeof days === 'number' && days >= 0 && days <= 7;
    if (currentFilter === '30') return typeof days === 'number' && days >= 0 && days <= 30;
    if (currentFilter === 'internet') return internet;
    return true;
  });
  currentPage = 1;
  syncFilterUi();
  renderTable();
}

function syncFilterUi() {
  document.querySelectorAll('.ssl-bar-row[data-health-filter]').forEach((row) => {
    const value = row.dataset.healthFilter;
    const isSelected = healthFilter === value;
    row.classList.toggle('is-selected', isSelected);
    row.classList.toggle('is-dimmed', !!(healthFilter && !isSelected));
    row.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    row.title = isSelected
      ? 'Clear health filter'
      : `Filter table to ${value.charAt(0).toUpperCase()}${value.slice(1)} certificates`;
  });

  document.querySelectorAll('.ssl-filter').forEach((btn) => {
    const chip = btn.dataset.filter;
    let active = false;
    if (healthFilter) {
      if (healthFilter === 'expired' && chip === 'expired') active = true;
      else if (healthFilter === 'expiring' && chip === '30') active = true;
    } else {
      active = chip === currentFilter;
    }
    btn.classList.toggle('active', active);
  });
}

function setHealthFilter(value) {
  healthFilter = healthFilter === value ? null : value;
  if (!healthFilter) currentFilter = 'all';
  applyFilter();
}

function setChipFilter(value) {
  healthFilter = null;
  currentFilter = value || 'all';
  applyFilter();
}

function renderKpis(summary) {
  const s = summary || {};
  el('kpi-total').textContent = fmtNumber(s.total);
  el('kpi-valid').textContent = fmtNumber(s.valid);
  el('kpi-valid-meta').textContent = s.total
    ? `${s.validPct ?? 0}% of certificates`
    : '—';
  el('kpi-exp30').textContent = fmtNumber(s.expiring30);
  el('kpi-exp7').textContent = fmtNumber(s.expiring7);
  el('kpi-expired').textContent = fmtNumber(s.expired);
  el('kpi-internet').textContent = fmtNumber(s.internetFacing);

  const validPct = s.validPct || 0;
  const expPct = s.expiringPct || 0;
  const expiredPct = s.expiredPct || 0;
  el('bar-valid').style.width = `${validPct}%`;
  el('bar-expiring').style.width = `${expPct}%`;
  el('bar-expired').style.width = `${expiredPct}%`;
  el('bar-valid-count').textContent = fmtNumber(s.valid);
  el('bar-expiring-count').textContent = fmtNumber(s.expiring30);
  el('bar-expired-count').textContent = fmtNumber(s.expired);

  const inet = s.internet || {};
  const inetTotal = inet.total || 0;
  el('donut-number').textContent = fmtNumber(inetTotal);
  el('exp-valid').textContent = fmtNumber(inet.valid);
  el('exp-expiring').textContent = fmtNumber(inet.expiring);
  el('exp-expired').textContent = fmtNumber(inet.expired);

  const donut = el('ssl-donut');
  if (inetTotal > 0) {
    const v = ((inet.valid || 0) / inetTotal) * 100;
    const e = ((inet.expiring || 0) / inetTotal) * 100;
    const x = ((inet.expired || 0) / inetTotal) * 100;
    const a = v;
    const b = v + e;
    donut.style.background = `conic-gradient(#0d9488 0 ${a}%, #d97706 ${a}% ${b}%, #dc2626 ${b}% 100%)`;
  } else {
    donut.style.background = 'conic-gradient(#e2e8f0 0 100%)';
  }

  const tl = s.timeline || {};
  el('tl-expired').textContent = fmtNumber(tl.expired);
  el('tl-7').textContent = fmtNumber(tl.next7);
  el('tl-30').textContent = fmtNumber(tl.days8to30);
  el('tl-90').textContent = fmtNumber(tl.days31to90);
}

function renderTable() {
  const tbody = el('ssl-tbody');
  const total = filteredCerts.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > pages) currentPage = pages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageRows = filteredCerts.slice(start, start + PAGE_SIZE);

  el('table-count').textContent = `${fmtNumber(total)} certificate${total === 1 ? '' : 's'}`;
  el('page-info').textContent = `Page ${currentPage} of ${pages}`;
  el('prev-page').disabled = currentPage <= 1;
  el('next-page').disabled = currentPage >= pages;

  if (!pageRows.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4">
          <div class="empty-state">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
            <p>No certificates match this filter.</p>
          </div>
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = pageRows.map((cert, idx) => {
    const globalIndex = start + idx;
    const name = cert.assetName || '—';
    const ip = cert.ipAddress || '—';
    const sources = cert.sources || '—';
    const expiry = fmtDate(cert.valid_to);
    const pillClass = statusPillClass(cert.status, cert.daysRemaining);
    return `
      <tr class="ssl-row" data-index="${globalIndex}" tabindex="0">
        <td><div class="ssl-asset-name">${escapeHtml(name)}</div></td>
        <td>${escapeHtml(ip)}</td>
        <td>${escapeHtml(sources)}</td>
        <td><span class="ssl-pill ${pillClass}">${escapeHtml(expiry)}</span></td>
      </tr>`;
  }).join('');

  tbody.querySelectorAll('.ssl-row').forEach((row) => {
    row.addEventListener('click', () => openDrawer(Number(row.dataset.index)));
    row.addEventListener('keydown', (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        openDrawer(Number(row.dataset.index));
      }
    });
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function openDrawer(index) {
  const cert = filteredCerts[index];
  if (!cert) return;
  const days = cert.daysRemaining;
  const pill = el('drawer-status');
  pill.textContent = statusLabel(cert);
  pill.className = `ssl-pill ${statusPillClass(cert.status, days)}`;

  el('drawer-asset').textContent = cert.assetName || '—';
  el('drawer-subject').textContent = cert.subject_cn || cert.subject || '—';
  el('drawer-issuer').textContent = cert.issuer_cn || cert.issuer || '—';
  el('drawer-from').textContent = fmtDate(cert.valid_from);
  el('drawer-to').textContent = fmtDate(cert.valid_to);
  el('drawer-ip').textContent = cert.ipAddress || '—';
  el('drawer-port').textContent = cert.port != null
    ? `${cert.port}${cert.protocol ? ` / ${cert.protocol}` : ''}`
    : '—';
  el('drawer-source').textContent = cert.sources || '—';
  el('drawer-exposure').textContent = cert.internetFacing
    ? 'Internet-facing (Nessus Scan)'
    : 'Internal / Agent';
  el('drawer-first').textContent = fmtDate(cert.first_found);
  el('drawer-last').textContent = fmtDate(cert.last_found);

  el('ssl-drawer').classList.add('open');
  el('ssl-drawer-backdrop').classList.add('open');
  el('ssl-drawer').setAttribute('aria-hidden', 'false');
}

function closeDrawer() {
  el('ssl-drawer').classList.remove('open');
  el('ssl-drawer-backdrop').classList.remove('open');
  el('ssl-drawer').setAttribute('aria-hidden', 'true');
}

function applyPayload(data) {
  allCerts = data.certs || [];
  renderKpis(data.summary || {});
  applyFilter();

  if (data.lastSync) {
    setSyncStatus('live', `Last sync: ${fmtDate(data.lastSync)}`);
  } else {
    setSyncStatus('', 'Last sync: Never');
  }

  if (data.warning && !allCerts.length) {
    showError(data.warning);
  } else {
    hideError();
  }
}

async function fetchStatus() {
  const res = await fetch('/api/ssl-certificates/status');
  if (!res.ok) return null;
  return res.json();
}

async function loadCerts({ refresh = false } = {}) {
  hideError();
  const url = refresh ? '/api/ssl-certificates?refresh=1' : '/api/ssl-certificates';
  setLoading(true, refresh
    ? 'Requesting plugin 10863 export from Tenable…'
    : 'Loading SSL certificates…');

  try {
    const res = await fetch(url);
    const data = await res.json().catch(() => ({}));

    if (res.status === 409 || data.sync_in_progress) {
      setLoading(true, data.progress?.message || 'SSL certificate sync in progress…');
      applyPayload(data.certs ? data : { certs: allCerts, summary: {} });
      startPolling();
      return;
    }

    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }

    applyPayload(data);

    if (data.sync_in_progress) {
      setLoading(true, data.progress?.message || 'Syncing…');
      startPolling();
    } else {
      setLoading(false);
      stopPolling();
    }
  } catch (err) {
    setLoading(false);
    showError(err.message || String(err));
    setSyncStatus('error', 'Sync failed');
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(async () => {
    try {
      const status = await fetchStatus();
      if (!status) return;
      const progress = status.progress || {};
      if (status.sync_in_progress) {
        setLoading(true, progress.message || 'Syncing SSL certificates…');
        return;
      }
      stopPolling();
      if (progress.phase === 'error' && progress.error) {
        setLoading(false);
        showError(`SSL certificate sync failed: ${progress.error}`);
        setSyncStatus('error', 'Sync failed');
        return;
      }
      await loadCerts({ refresh: false });
    } catch (_) {
    }
  }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function bindEvents() {
  el('refresh-btn').addEventListener('click', () => loadCerts({ refresh: true }));
  el('prev-page').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage -= 1;
      renderTable();
    }
  });
  el('next-page').addEventListener('click', () => {
    const pages = Math.max(1, Math.ceil(filteredCerts.length / PAGE_SIZE));
    if (currentPage < pages) {
      currentPage += 1;
      renderTable();
    }
  });

  document.querySelectorAll('.ssl-filter').forEach((btn) => {
    btn.addEventListener('click', () => {
      setChipFilter(btn.dataset.filter);
    });
  });

  const healthBars = el('ssl-health-bars');
  if (healthBars) {
    healthBars.addEventListener('click', (e) => {
      const row = e.target.closest('.ssl-bar-row[data-health-filter]');
      if (!row || !healthBars.contains(row)) return;
      e.preventDefault();
      setHealthFilter(row.dataset.healthFilter);
    });
  }

  el('drawer-close').addEventListener('click', closeDrawer);
  el('ssl-drawer-backdrop').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (evt) => {
    if (evt.key === 'Escape') closeDrawer();
  });
}

bindEvents();
loadCerts();
