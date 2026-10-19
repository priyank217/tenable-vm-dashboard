/* Dashboard Lumin Index — frozen monthly remediation flow. */

const C = {
  start: '#64748b',
  new: '#f97316',
  res: '#eab308',
  fixed: '#22c55e',
  end: '#0d9488',
  line: '#1d4ed8',
  critHigh: '#dc2626',
  medLow: '#0ea5e9',
  grid: '#e2e8f0',
  text: '#64748b',
};

const $ = (id) => document.getElementById(id);

let charts = {};
let generatedAt = null;
let syncPollTimer = null;
let dashboardData = null;
let lastSyncStatus = null;
let selectedTagUuid = '';
let tagOptionsLoaded = false;
let metricsRefreshDepth = 0;
let expandedRecastIndexes = new Set();
let recastRowsCache = [];
let expandedFixBefore = new Set();
let expandedFixAfter = new Set();
let fixBeforeCache = [];
let fixAfterCache = [];
let mtdNewAllRows = [];
let mtdNewRowsCache = [];
let mtdNewPage = 1;
let mtdNewPageSize = 25;
let mtdNewOpenFilterCol = null;
let mtdNewGroupBy = 'none'; // none | hostname | plugin_id
let mtdNewExpandedGroups = new Set();
let mtdNewGroupsCache = [];

const MTD_NEW_COLUMN_META = {
  hostname: { label: 'Hostname', type: 'text', getText: (r) => r.hostname || '' },
  ipv4: { label: 'IP', type: 'text', getText: (r) => r.ipv4 || '' },
  plugin_id: { label: 'Plugin ID', type: 'text', getText: (r) => r.plugin_id || '' },
  plugin_name: { label: 'Plugin Name', type: 'text', getText: (r) => r.plugin_name || '' },
  vpr_score: {
    label: 'VPR',
    type: 'values',
    getValues: (r) => (r.vpr_score != null ? [Number(r.vpr_score).toFixed(1)] : []),
  },
  vpr_tier: {
    label: 'Tier',
    type: 'values',
    getValues: (r) => (r.vpr_tier ? [String(r.vpr_tier).toLowerCase()] : []),
  },
  state: {
    label: 'State',
    type: 'values',
    getValues: (r) => (r.state ? [String(r.state)] : []),
  },
  first_found: {
    label: 'First Seen',
    type: 'text',
    getText: (r) => formatIsoDate(r.first_found),
  },
};

function emptyMtdNewFilters() {
  const filters = {};
  Object.keys(MTD_NEW_COLUMN_META).forEach((key) => {
    filters[key] = MTD_NEW_COLUMN_META[key].type === 'values'
      ? { selected: new Set() }
      : { text: '' };
  });
  return filters;
}

let mtdNewColFilters = emptyMtdNewFilters();

function escapeAttr(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

/* ───────────── formatting ───────────── */

const fmt = (n) => (n == null || Number.isNaN(n) ? '—' : new Intl.NumberFormat().format(n));
const pct = (n) => (n == null || Number.isNaN(n) ? '—' : `${Number(n).toFixed(1)}%`);
const days = (n) => (n == null || Number.isNaN(n) ? '—' : `${Number(n).toFixed(1)} d`);
const signed = (n) => (n == null ? '—' : `${n > 0 ? '+' : ''}${fmt(n)}`);

function esc(text) {
  const div = document.createElement('div');
  div.textContent = text ?? '';
  return div.innerHTML;
}

function monthLabel(ym) {
  if (!ym) return '—';
  const [y, m] = ym.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleString(undefined, { month: 'short', year: '2-digit', timeZone: 'UTC' });
}

function relativeTime(iso) {
  if (!iso) return 'unknown';
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  const d = Math.floor(hrs / 24);
  return d === 1 ? '1 day ago' : `${d} days ago`;
}

function rateBadge(rate) {
  if (rate == null) return '—';
  const cls = rate >= 60 ? 'rate-good' : rate >= 40 ? 'rate-amber' : 'rate-bad';
  return `<span class="rate-badge ${cls}">${pct(rate)}</span>`;
}

function slaBadge(rate) {
  if (rate == null) return '—';
  const cls = rate >= 90 ? 'rate-good' : rate >= 75 ? 'rate-amber' : 'rate-bad';
  return `<span class="rate-badge ${cls}">${pct(rate)}</span>`;
}

function methodBadge(method) {
  const m = (method || '').toLowerCase() || 'reconstructed';
  return `<span class="lumin-badge method-${esc(m)}">${esc(m)}</span>`;
}

function sevPill(sev, count) {
  if (!count) return '<span class="sev-pill empty">0</span>';
  return `<span class="sev-pill ${sev}">${count}</span>`;
}

/* ───────────── sync panel (same behaviour as main dashboard) ───────────── */

function syncProgressPct(p) {
  if (!p) return 0;
  if (p.phase === 'complete' || p.phase === 'error') return 100;
  const pollMax = p.poll_max || 1;
  if (p.phase === 'requesting') return 5;
  if (p.phase === 'polling') return 5 + Math.round(((p.poll_attempt || 0) / pollMax) * 35);
  if (p.phase === 'downloading' && p.chunks_total) return 40 + Math.round((p.chunks_done / p.chunks_total) * 35);
  if (p.phase === 'importing' && p.chunks_total) return 75 + Math.round((p.chunks_done / p.chunks_total) * 20);
  if (p.phase === 'importing') return 85;
  return 0;
}

function renderSyncPhases(phase) {
  const order = ['requesting', 'polling', 'downloading', 'importing', 'complete'];
  const active = order.indexOf(phase);
  document.querySelectorAll('.sync-phase[data-phase]').forEach((el) => {
    const idx = order.indexOf(el.getAttribute('data-phase'));
    el.classList.remove('is-active', 'is-done');
    if (phase === 'error') return;
    if (idx < active) el.classList.add('is-done');
    else if (idx === active) el.classList.add('is-active');
  });
}

function renderSyncPanel(status) {
  const panel = $('sync-panel');
  if (!panel) return;
  const inProgress = status?.sync_in_progress;
  const p = status?.progress || {};
  const phase = p.phase || 'idle';

  if (inProgress || phase === 'error') panel.classList.remove('hidden');
  else if (phase === 'complete') { panel.classList.remove('hidden'); setTimeout(() => panel.classList.add('hidden'), 8000); }
  else panel.classList.add('hidden');

  const v = syncProgressPct(p);
  $('sync-progress-pct').textContent = `${v}%`;
  $('sync-progress-bar').style.width = `${v}%`;
  $('sync-panel-title').textContent = phase === 'error' ? 'Sync failed' : phase === 'complete' ? 'Sync complete' : `Synchronizing (${p.mode || 'sync'})`;
  $('sync-panel-message').textContent = p.message || (inProgress ? 'Working…' : '—');

  const parts = [];
  if (status?.vulnerability_count != null) parts.push(`${fmt(status.vulnerability_count)} records`);
  if (status?.last_sync_iso) parts.push(`Last sync ${new Date(status.last_sync_iso).toLocaleString()}`);
  if (p.export_status) parts.push(`Tenable: ${p.export_status}`);
  if (p.chunks_total) parts.push(`Chunks ${p.chunks_done || 0}/${p.chunks_total}`);
  if (p.records_upserted) parts.push(`${fmt(p.records_upserted)} imported`);
  $('sync-meta').textContent = parts.join(' · ') || '—';

  renderSyncPhases(phase);
  const dot = $('status-dot');
  dot.classList.toggle('loading', !!inProgress);
  dot.classList.toggle('online', !inProgress && !!status?.last_sync_iso);
  dot.classList.toggle('error', phase === 'error');
}

function updateEmptyState(status) {
  const hasData = (status?.vulnerability_count || 0) > 0;
  if (!hasData && !status?.sync_in_progress) {
    $('dashboard-empty').classList.remove('hidden');
    $('dashboard-content').classList.add('hidden');
  } else if (hasData) {
    $('dashboard-empty').classList.add('hidden');
  }
}

async function parseApiResponse(res) {
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    throw new Error(`Server returned non-JSON (HTTP ${res.status}). Start the app with: python app.py`);
  }
  return res.json();
}

async function pollSyncStatus() {
  try {
    const res = await fetch('/api/sync/status', { cache: 'no-store' });
    const status = await parseApiResponse(res);
    const wasSyncing = lastSyncStatus?.sync_in_progress;
    lastSyncStatus = status;
    renderSyncPanel(status);
    updateEmptyState(status);
    if (status.last_sync_iso) $('last-updated').textContent = `Last sync: ${relativeTime(status.last_sync_iso)}`;

    if (wasSyncing && !status.sync_in_progress) {
      if (status.progress?.phase === 'complete') await loadMetrics({ quiet: true, refreshing: true });
      else if (status.progress?.phase === 'error') showError(status.progress.error || 'Sync failed.');
    }
    if (status.sync_in_progress && !syncPollTimer) syncPollTimer = setInterval(pollSyncStatus, 3000);
    if (!status.sync_in_progress && syncPollTimer) { clearInterval(syncPollTimer); syncPollTimer = null; }
  } catch (err) {
    console.warn('Sync status poll failed:', err);
  }
}

async function startSync({ full = false, daily = false } = {}) {
  ['sync-daily-btn', 'sync-full-btn'].forEach((id) => { $(id).disabled = true; });
  try {
    const params = new URLSearchParams();
    if (full) params.set('full', '1');
    if (daily) params.set('daily', '1');
    const res = await fetch(`/api/sync?${params}`, { method: 'POST' });
    const data = await parseApiResponse(res);
    if (!res.ok && res.status !== 202) throw new Error(data.error || 'Failed to start sync');
    $('sync-panel').classList.remove('hidden');
    $('dashboard-empty').classList.add('hidden');
    await pollSyncStatus();
    if (!syncPollTimer) syncPollTimer = setInterval(pollSyncStatus, 3000);
  } catch (err) {
    showError(err.message || 'Could not start sync.');
  } finally {
    ['sync-daily-btn', 'sync-full-btn'].forEach((id) => { $(id).disabled = false; });
  }
}

/* ───────────── charts ───────────── */

const valueLabels = {
  id: 'valueLabels',
  afterDatasetsDraw(chart) {
    const { ctx } = chart;
    chart.data.datasets.forEach((ds, di) => {
      if (ds.hideLabels) return;
      const meta = chart.getDatasetMeta(di);
      if (!meta.visible) return;
      meta.data.forEach((el, i) => {
        let raw = ds.data[i];
        if (Array.isArray(raw)) raw = raw[1] - raw[0];
        if (raw == null || Number.isNaN(Number(raw))) return;
        const { x, y } = el.tooltipPosition();
        ctx.save();
        ctx.font = '600 10px Inter, system-ui, sans-serif';
        ctx.fillStyle = '#334155';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(ds.labelFormat ? ds.labelFormat(raw) : fmt(Math.abs(raw)), x, y - 4);
        ctx.restore();
      });
    });
  },
};

function baseScales() {
  return {
    x: { grid: { display: false }, ticks: { color: C.text, font: { family: 'Inter', size: 11 } } },
    y: { grid: { color: C.grid }, ticks: { color: C.text, font: { family: 'Inter', size: 11 } }, beginAtZero: true, grace: '12%' },
  };
}

function destroyCharts() {
  Object.values(charts).forEach((c) => c.destroy());
  charts = {};
}

function endOf(m) {
  return m.backlog_end_observed != null ? m.backlog_end_observed : m.backlog_end;
}

function renderBacklogChart(months) {
  const el = $('backlog-chart');
  if (!el || !window.Chart) return;
  charts.backlog = new Chart(el, {
    type: 'line',
    plugins: [valueLabels],
    data: {
      labels: months.map((m) => monthLabel(m.month)),
      datasets: [
        { label: 'Start', data: months.map((m) => m.backlog_start), borderColor: C.start, backgroundColor: 'rgba(100,116,139,0.10)', fill: true, tension: 0.3, pointRadius: 4 },
        { label: 'End', data: months.map(endOf), borderColor: C.end, backgroundColor: 'rgba(13,148,136,0.10)', fill: true, tension: 0.3, pointRadius: 4 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, layout: { padding: { top: 24 } },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: baseScales(),
    },
  });
}

function renderWaterfall(m) {
  const el = $('waterfall-chart');
  if (!el || !window.Chart) return;
  const hint = $('waterfall-hint');
  if (!m) { if (hint) hint.textContent = 'No closed month yet'; return; }
  const start = m.backlog_start, nw = m.new_findings, rs = m.resurfaced, fx = m.fixed, end = endOf(m);
  const gap = m.flow_gap || 0;
  const s1 = start + nw, s2 = s1 + rs, s3 = s2 - fx;
  const bars = [
    { l: 'Start', r: [0, start], c: C.start },
    { l: '+New', r: [start, s1], c: C.new },
    { l: '+Resurfaced', r: [s1, s2], c: C.res },
    { l: '−Fixed', r: [s3, s2], c: C.fixed },
  ];
  if (gap) bars.push({ l: gap < 0 ? '−Hidden fixes' : '+Unattributed', r: gap < 0 ? [s3 + gap, s3] : [s3, s3 + gap], c: '#94a3b8' });
  bars.push({ l: 'End', r: [0, end], c: C.end });

  if (hint) hint.textContent = `${monthLabel(m.month)} · ${fmt(start)} → ${fmt(end)} (${signed(end - start)}) · ${methodLabel(m.method)}`;

  charts.waterfall = new Chart(el, {
    type: 'bar',
    plugins: [valueLabels],
    data: {
      labels: bars.map((b) => b.l),
      datasets: [{ data: bars.map((b) => b.r), backgroundColor: bars.map((b) => b.c), borderRadius: 3, borderSkipped: false }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, layout: { padding: { top: 24 } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (ctx) => fmt(Math.abs(ctx.raw[1] - ctx.raw[0])) } } },
      scales: baseScales(),
    },
  });
}

function methodLabel(m) {
  return m === 'frozen' ? 'frozen from history' : m === 'live' ? 'live (tag scope)' : 'reconstructed from timestamps';
}

function renderMttrChart(months) {
  const el = $('mttr-chart');
  if (!el || !window.Chart) return;
  charts.mttr = new Chart(el, {
    type: 'line',
    plugins: [valueLabels],
    data: {
      labels: months.map((m) => monthLabel(m.month)),
      datasets: [
        { label: 'Critical/High', data: months.map((m) => m.median_days_to_fix_crit_high), borderColor: C.critHigh, backgroundColor: C.critHigh, tension: 0.3, pointRadius: 4, labelFormat: (v) => `${Number(v).toFixed(1)}` },
        { label: 'Medium/Low', data: months.map((m) => m.median_days_to_fix_med_low), borderColor: C.medLow, backgroundColor: C.medLow, tension: 0.3, pointRadius: 4, labelFormat: (v) => `${Number(v).toFixed(1)}` },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, layout: { padding: { top: 24 } },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: { ...baseScales(), y: { ...baseScales().y, title: { display: true, text: 'days', color: C.text, font: { size: 11 } } } },
    },
  });
}

function renderSlaChart(months) {
  const el = $('sla-chart');
  if (!el || !window.Chart) return;
  charts.sla = new Chart(el, {
    type: 'bar',
    plugins: [valueLabels],
    data: {
      labels: months.map((m) => monthLabel(m.month)),
      datasets: [{
        data: months.map((m) => m.sla_attainment_pct),
        backgroundColor: months.map((m) => (m.sla_attainment_pct >= 90 ? C.fixed : m.sla_attainment_pct >= 75 ? C.res : C.critHigh)),
        borderRadius: 3, labelFormat: (v) => `${Number(v).toFixed(1)}%`,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, layout: { padding: { top: 24 } },
      plugins: { legend: { display: false } },
      scales: { ...baseScales(), y: { ...baseScales().y, min: 0, max: 100, ticks: { callback: (v) => `${v}%`, color: C.text, font: { size: 11 } } } },
    },
  });
}

function renderFixPluginTable(side) {
  const isBefore = side === 'before';
  const tbody = $(isBefore ? 'fix-before-body' : 'fix-after-body');
  if (!tbody) return;
  const cache = isBefore ? fixBeforeCache : fixAfterCache;
  const expanded = isBefore ? expandedFixBefore : expandedFixAfter;
  const rowClass = isBefore ? 'fix-before-row' : 'fix-after-row';
  const dataAttr = isBefore ? 'data-fix-before-index' : 'data-fix-after-index';

  if (!cache.length) {
    expanded.clear();
    tbody.innerHTML = '<tr><td colspan="5" class="cell-time">No plugins on this side of the median</td></tr>';
    return;
  }

  [...expanded].forEach((idx) => {
    if (idx < 0 || idx >= cache.length) expanded.delete(idx);
  });

  tbody.innerHTML = cache.map((r, index) => {
    const isOpen = expanded.has(index);
    const hosts = Array.isArray(r.hosts) ? r.hosts : [];
    const header = `
    <tr class="asset-group-row ${rowClass}${isOpen ? ' is-expanded' : ''}" ${dataAttr}="${index}" tabindex="0" role="button" aria-expanded="${isOpen ? 'true' : 'false'}">
      <td>
        <span class="asset-group-toggle">
          <span class="asset-group-chevron" aria-hidden="true">▶</span>
          <span class="cell-name cell-ellipsis" title="${esc(r.plugin_name || '—')}">${esc(r.plugin_name || '—')}</span>
        </span>
      </td>
      <td><code>${esc(r.plugin_id || '—')}</code></td>
      <td>${fmt(r.fixed_count)}</td>
      <td><span class="badge asset-group-count">${fmt(r.host_count)}</span></td>
      <td><strong>${days(r.median_days)}</strong></td>
    </tr>`;

    if (!isOpen) return header;
    if (!hosts.length) {
      return `${header}<tr class="port-child-row"><td colspan="5" class="cell-time">No hosts listed for this plugin</td></tr>`;
    }
    const children = hosts.map((h) => `
      <tr class="port-child-row">
        <td><span class="port-child-label">${esc(h.hostname || '—')}</span></td>
        <td colspan="2">${esc(h.ipv4 || '—')}</td>
        <td><span class="badge asset-group-count">${fmt(h.finding_count)} fix${Number(h.finding_count) === 1 ? '' : 'es'}</span></td>
        <td>${days(h.days_to_fix)}</td>
      </tr>`).join('');
    return header + children;
  }).join('');
}

function toggleFixPluginRow(side, index) {
  const idx = Number(index);
  if (!Number.isFinite(idx)) return;
  const expanded = side === 'before' ? expandedFixBefore : expandedFixAfter;
  if (expanded.has(idx)) expanded.delete(idx);
  else expanded.add(idx);
  renderFixPluginTable(side);
}

function renderFixTimeInsights(data) {
  const dist = data?.distribution || {};
  const monthMedian = data?.month_median_days ?? dist.median_days;
  const frozen = data?.median_source === 'frozen';
  const label = data?.month ? monthLabel(data.month) : 'last closed month';

  fixBeforeCache = Array.isArray(data?.plugins_before_median) ? data.plugins_before_median : [];
  fixAfterCache = Array.isArray(data?.plugins_after_median) ? data.plugins_after_median : [];
  expandedFixBefore.clear();
  expandedFixAfter.clear();

  const beforeHint = $('fix-before-hint');
  const afterHint = $('fix-after-hint');
  const beforeCount = $('fix-before-count');
  const afterCount = $('fix-after-count');
  if (beforeHint) {
    beforeHint.textContent = monthMedian != null
      ? `vs ${frozen ? 'frozen ' : ''}${label} median ${Number(monthMedian).toFixed(1)} d · click row for hosts`
      : 'Plugin median < month median · click row for hosts';
  }
  if (afterHint) {
    afterHint.textContent = monthMedian != null
      ? `vs ${frozen ? 'frozen ' : ''}${label} median ${Number(monthMedian).toFixed(1)} d · click row for hosts`
      : 'Plugin median > month median · click row for hosts';
  }
  if (beforeCount) {
    beforeCount.textContent = `${fmt(data?.plugins_before_count ?? fixBeforeCache.length)} plugins`;
  }
  if (afterCount) {
    afterCount.textContent = `${fmt(data?.plugins_after_count ?? fixAfterCache.length)} plugins`;
  }

  const hasPlugins = fixBeforeCache.length || fixAfterCache.length;
  if (!hasPlugins) {
    const empty = '<tr><td colspan="5" class="cell-time">No Critical/High fixes in last closed month</td></tr>';
    if ($('fix-before-body')) $('fix-before-body').innerHTML = empty;
    if ($('fix-after-body')) $('fix-after-body').innerHTML = empty;
    return;
  }
  renderFixPluginTable('before');
  renderFixPluginTable('after');
}

/* ───────────── sections ───────────── */

function renderNow(now) {
  $('kpi-active').textContent = fmt(now.active);
  const delta = $('kpi-active-delta');
  if (now.change_vs_last_month_end != null) {
    delta.textContent = `${signed(now.change_vs_last_month_end)} vs last month end (${fmt(now.last_month_end)})`;
    delta.className = `exec-kpi-delta ${now.change_vs_last_month_end > 0 ? 'up' : now.change_vs_last_month_end < 0 ? 'down' : ''}`;
  } else {
    delta.textContent = 'vs last month end: —';
  }
  $('kpi-crit-high').textContent = fmt(now.critical_high);
  $('kpi-crit-high-split').textContent = `Critical ${fmt(now.critical)} · High ${fmt(now.high)}`;
  $('kpi-sla-critical').textContent = fmt(now.sla_breach_critical);
  $('kpi-sla-high').textContent = fmt(now.sla_breach_high);
  $('kpi-resurfaced').textContent = fmt(now.resurfaced_active);
  $('kpi-weaponized').textContent = fmt(now.weaponized);
}

function formatIsoDate(value) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
    }) + ' UTC';
  } catch {
    return String(value).slice(0, 10);
  }
}

function isMtdNewFilterActive(col) {
  const meta = MTD_NEW_COLUMN_META[col];
  const f = mtdNewColFilters[col];
  if (!meta || !f) return false;
  if (meta.type === 'values') return f.selected.size > 0;
  return Boolean(f.text && f.text.trim());
}

function updateMtdNewFilterButtons() {
  document.querySelectorAll('#mtd-new-table .col-filter-btn').forEach((btn) => {
    btn.classList.toggle('is-active', isMtdNewFilterActive(btn.dataset.filter));
  });
}

function mtdNewColumnText(row, col) {
  const meta = MTD_NEW_COLUMN_META[col];
  if (meta?.getText) return meta.getText(row);
  return String(row[col] == null ? '' : row[col]);
}

function applyMtdNewFilters() {
  mtdNewRowsCache = mtdNewAllRows.filter((row) => (
    Object.keys(MTD_NEW_COLUMN_META).every((col) => {
      const meta = MTD_NEW_COLUMN_META[col];
      const f = mtdNewColFilters[col];
      if (meta.type === 'values') {
        if (!f.selected.size) return true;
        const values = meta.getValues(row);
        return values.some((v) => f.selected.has(String(v)));
      }
      const q = (f.text || '').trim().toLowerCase();
      if (!q) return true;
      return mtdNewColumnText(row, col).toLowerCase().includes(q);
    })
  ));
  mtdNewPage = 1;
  mtdNewExpandedGroups.clear();
  rebuildMtdNewGroups();
  updateMtdNewFilterButtons();
  renderMtdNewPage();
}

function rebuildMtdNewGroups() {
  if (mtdNewGroupBy === 'none') {
    mtdNewGroupsCache = [];
    return;
  }

  const map = new Map();
  mtdNewRowsCache.forEach((row) => {
    let key;
    let label;
    let sublabel = '';
    if (mtdNewGroupBy === 'hostname') {
      key = String(row.hostname || '').trim() || '(no hostname)';
      label = row.hostname || '(no hostname)';
      sublabel = row.ipv4 || '';
    } else {
      key = String(row.plugin_id || '').trim() || '(no plugin)';
      label = row.plugin_id || '(no plugin)';
      sublabel = row.plugin_name || '';
    }

    let group = map.get(key);
    if (!group) {
      group = {
        key,
        label,
        sublabel,
        ipv4: row.ipv4 || '',
        plugin_id: row.plugin_id || '',
        plugin_name: row.plugin_name || '',
        rows: [],
        max_vpr: null,
      };
      map.set(key, group);
    }
    group.rows.push(row);
    if (row.vpr_score != null) {
      const score = Number(row.vpr_score);
      if (group.max_vpr == null || score > group.max_vpr) group.max_vpr = score;
    }
    if (mtdNewGroupBy === 'hostname' && row.ipv4 && !group.ipv4) group.ipv4 = row.ipv4;
    if (mtdNewGroupBy === 'plugin_id' && row.plugin_name) group.plugin_name = row.plugin_name;
  });

  mtdNewGroupsCache = [...map.values()].sort((a, b) => {
    const av = a.max_vpr == null ? -1 : a.max_vpr;
    const bv = b.max_vpr == null ? -1 : b.max_vpr;
    if (bv !== av) return bv - av;
    return String(a.label).localeCompare(String(b.label));
  });
}

function setMtdNewGroupBy(mode) {
  if (!['none', 'hostname', 'plugin_id'].includes(mode)) return;
  mtdNewGroupBy = mode;
  mtdNewPage = 1;
  mtdNewExpandedGroups.clear();
  document.querySelectorAll('[data-mtd-group]').forEach((btn) => {
    const active = btn.dataset.mtdGroup === mode;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
  });
  const sizeLabel = document.querySelector('.lumin-mtd-new-footer .page-size-wrap span');
  if (sizeLabel) {
    sizeLabel.textContent = mode === 'none' ? 'Rows per page' : 'Groups per page';
  }
  rebuildMtdNewGroups();
  renderMtdNewPage();
}

function toggleMtdNewGroup(key) {
  if (mtdNewExpandedGroups.has(key)) mtdNewExpandedGroups.delete(key);
  else mtdNewExpandedGroups.add(key);
  renderMtdNewPage();
}

function uniqueMtdNewColumnValues(col) {
  const meta = MTD_NEW_COLUMN_META[col];
  const counts = new Map();
  mtdNewAllRows.forEach((row) => {
    meta.getValues(row).forEach((raw) => {
      const key = String(raw);
      if (!counts.has(key)) counts.set(key, { raw: key, label: key, count: 0 });
      counts.get(key).count += 1;
    });
  });
  return [...counts.values()].sort((a, b) => String(a.label).localeCompare(String(b.label)));
}

function closeMtdNewFilterMenu() {
  const menu = $('col-filter-menu');
  if (!menu) return;
  menu.classList.add('hidden');
  menu.setAttribute('aria-hidden', 'true');
  mtdNewOpenFilterCol = null;
}

function positionMtdNewFilterMenu(anchor) {
  const menu = $('col-filter-menu');
  const rect = anchor.getBoundingClientRect();
  const margin = 8;
  let left = rect.left;
  let top = rect.bottom + 4;

  menu.classList.remove('hidden');
  menu.setAttribute('aria-hidden', 'false');

  const menuRect = menu.getBoundingClientRect();
  if (left + menuRect.width > window.innerWidth - margin) {
    left = window.innerWidth - menuRect.width - margin;
  }
  if (top + menuRect.height > window.innerHeight - margin) {
    top = rect.top - menuRect.height - 4;
  }

  menu.style.left = `${Math.max(margin, left)}px`;
  menu.style.top = `${Math.max(margin, top)}px`;
}

function buildMtdNewFilterBody(col) {
  const meta = MTD_NEW_COLUMN_META[col];
  const body = $('col-filter-body');
  const f = mtdNewColFilters[col];

  if (meta.type === 'text') {
    body.innerHTML = `
      <input type="text" id="col-filter-text" class="col-filter-text"
        placeholder="Contains…" value="${escapeAttr(f.text || '')}" autocomplete="off">`;
    const input = $('col-filter-text');
    input.focus();
    input.select();
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') applyMtdNewFilterMenu();
    });
    return;
  }

  const values = uniqueMtdNewColumnValues(col);
  const selected = f.selected;
  body.innerHTML = `
    <input type="text" id="col-filter-search" class="col-filter-search"
      placeholder="Search values…" autocomplete="off">
    <div id="col-filter-list" class="col-filter-list"></div>`;

  const list = $('col-filter-list');
  const renderList = (query) => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? values.filter((v) => String(v.label).toLowerCase().includes(q))
      : values;
    if (!filtered.length) {
      list.innerHTML = '<p class="cell-time">No values found</p>';
      return;
    }
    list.innerHTML = filtered.map((v) => `
      <label class="col-filter-option">
        <input type="checkbox" value="${escapeAttr(v.raw)}" ${selected.has(v.raw) ? 'checked' : ''}>
        <span>${esc(v.label)} <span class="cell-time">(${v.count})</span></span>
      </label>`).join('');
  };

  renderList('');
  $('col-filter-search').addEventListener('input', (e) => renderList(e.target.value));
  $('col-filter-search').focus();
}

function openMtdNewFilterMenu(col, anchor) {
  if (mtdNewOpenFilterCol === col && !$('col-filter-menu').classList.contains('hidden')) {
    closeMtdNewFilterMenu();
    return;
  }
  mtdNewOpenFilterCol = col;
  $('col-filter-title').textContent = `Filter: ${MTD_NEW_COLUMN_META[col].label}`;
  buildMtdNewFilterBody(col);
  positionMtdNewFilterMenu(anchor);
}

function applyMtdNewFilterMenu() {
  const col = mtdNewOpenFilterCol;
  if (!col) return;
  const meta = MTD_NEW_COLUMN_META[col];
  const f = mtdNewColFilters[col];
  if (meta.type === 'text') {
    const input = $('col-filter-text');
    f.text = input ? input.value : '';
  } else {
    f.selected = new Set();
    document.querySelectorAll('#col-filter-list input[type="checkbox"]:checked').forEach((cb) => {
      f.selected.add(cb.value);
    });
  }
  closeMtdNewFilterMenu();
  applyMtdNewFilters();
}

function clearMtdNewFilterMenu() {
  const col = mtdNewOpenFilterCol;
  if (!col) return;
  const meta = MTD_NEW_COLUMN_META[col];
  if (meta.type === 'text') {
    mtdNewColFilters[col].text = '';
    const input = $('col-filter-text');
    if (input) input.value = '';
  } else {
    mtdNewColFilters[col].selected = new Set();
    document.querySelectorAll('#col-filter-list input[type="checkbox"]').forEach((cb) => {
      cb.checked = false;
    });
  }
  closeMtdNewFilterMenu();
  applyMtdNewFilters();
}

function initMtdNewColFilters() {
  document.querySelectorAll('#mtd-new-table .col-filter-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openMtdNewFilterMenu(btn.dataset.filter, btn);
    });
  });
  $('col-filter-apply')?.addEventListener('click', applyMtdNewFilterMenu);
  $('col-filter-clear')?.addEventListener('click', clearMtdNewFilterMenu);
  $('col-filter-close')?.addEventListener('click', closeMtdNewFilterMenu);
  document.addEventListener('click', (e) => {
    const menu = $('col-filter-menu');
    if (!menu || menu.classList.contains('hidden')) return;
    if (menu.contains(e.target) || e.target.closest('#mtd-new-table .col-filter-btn')) return;
    closeMtdNewFilterMenu();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMtdNewFilterMenu();
  });
}

function updateMtdNewPager() {
  const findingCount = mtdNewRowsCache.length;
  const allCount = mtdNewAllRows.length;
  const itemCount = mtdNewGroupBy === 'none' ? findingCount : mtdNewGroupsCache.length;
  const totalPages = Math.max(1, Math.ceil(itemCount / mtdNewPageSize) || 1);
  if (mtdNewPage > totalPages) mtdNewPage = totalPages;
  if (mtdNewPage < 1) mtdNewPage = 1;

  const info = $('mtd-new-page-info');
  const prev = $('mtd-new-prev');
  const next = $('mtd-new-next');
  const countEl = $('mtd-new-count');

  if (countEl && allCount) {
    if (mtdNewGroupBy === 'none') {
      countEl.textContent = findingCount !== allCount
        ? `${fmt(findingCount)} of ${fmt(allCount)} findings`
        : `${fmt(findingCount)} finding${findingCount === 1 ? '' : 's'}`;
    } else {
      const unit = mtdNewGroupBy === 'hostname' ? 'host' : 'plugin';
      countEl.textContent = `${fmt(itemCount)} ${unit}${itemCount === 1 ? '' : 's'} · ${fmt(findingCount)} finding${findingCount === 1 ? '' : 's'}`;
    }
  }

  if (info) {
    if (!itemCount) {
      info.textContent = 'Page 1 of 1';
    } else if (mtdNewGroupBy !== 'none') {
      const unit = mtdNewGroupBy === 'hostname' ? 'hosts' : 'plugins';
      info.textContent = `Page ${mtdNewPage} of ${totalPages} · ${fmt(itemCount)} ${unit}`;
    } else if (findingCount !== allCount) {
      info.textContent = `Page ${mtdNewPage} of ${totalPages} · ${fmt(findingCount)} of ${fmt(allCount)} findings`;
    } else {
      info.textContent = `Page ${mtdNewPage} of ${totalPages} · ${fmt(findingCount)} findings`;
    }
  }
  if (prev) prev.disabled = mtdNewPage <= 1 || !itemCount;
  if (next) next.disabled = mtdNewPage >= totalPages || !itemCount;
}

function renderMtdNewFlatRows(pageRows) {
  return pageRows.map((r) => {
    const tier = (r.vpr_tier || 'low').toLowerCase();
    const name = r.plugin_name || '—';
    return `
    <tr>
      <td title="${esc(r.hostname || '—')}"><strong class="cell-ellipsis">${esc(r.hostname || '—')}</strong></td>
      <td title="${esc(r.ipv4 || '—')}">${esc(r.ipv4 || '—')}</td>
      <td><code>${esc(r.plugin_id || '—')}</code></td>
      <td title="${esc(name)}"><span class="cell-name cell-ellipsis">${esc(name)}</span></td>
      <td>${r.vpr_score != null ? Number(r.vpr_score).toFixed(1) : '—'}</td>
      <td><span class="sev-pill ${esc(tier)}">${esc(tier)}</span></td>
      <td>${esc(r.state || '—')}</td>
      <td class="cell-time" title="${esc(formatIsoDate(r.first_found))}">${esc(formatIsoDate(r.first_found))}</td>
    </tr>`;
  }).join('');
}

function renderMtdNewChildRow(r) {
  const tier = (r.vpr_tier || 'low').toLowerCase();
  const name = r.plugin_name || '—';
  return `
  <tr class="mtd-child-row">
    <td title="${esc(r.hostname || '—')}"><span class="cell-ellipsis">${esc(r.hostname || '—')}</span></td>
    <td title="${esc(r.ipv4 || '—')}">${esc(r.ipv4 || '—')}</td>
    <td><code>${esc(r.plugin_id || '—')}</code></td>
    <td title="${esc(name)}"><span class="cell-name cell-ellipsis">${esc(name)}</span></td>
    <td>${r.vpr_score != null ? Number(r.vpr_score).toFixed(1) : '—'}</td>
    <td><span class="sev-pill ${esc(tier)}">${esc(tier)}</span></td>
    <td>${esc(r.state || '—')}</td>
    <td class="cell-time" title="${esc(formatIsoDate(r.first_found))}">${esc(formatIsoDate(r.first_found))}</td>
  </tr>`;
}

function renderMtdNewGroupedRows(pageGroups) {
  return pageGroups.map((group) => {
    const expanded = mtdNewExpandedGroups.has(group.key);
    const count = group.rows.length;
    const maxVpr = group.max_vpr != null ? Number(group.max_vpr).toFixed(1) : '—';
    let primary;
    if (mtdNewGroupBy === 'hostname') {
      primary = `
        <td colspan="2">
          <span class="asset-group-toggle">
            <span class="asset-group-chevron" aria-hidden="true">▶</span>
            <strong class="cell-ellipsis" title="${esc(group.label)}">${esc(group.label)}</strong>
          </span>
          ${group.ipv4 ? `<span class="cell-time" style="margin-left:0.5rem">${esc(group.ipv4)}</span>` : ''}
        </td>
        <td colspan="2"><span class="badge asset-group-count">${fmt(count)} finding${count === 1 ? '' : 's'}</span></td>`;
    } else {
      primary = `
        <td colspan="2">
          <span class="asset-group-toggle">
            <span class="asset-group-chevron" aria-hidden="true">▶</span>
            <code title="${esc(group.label)}">${esc(group.label)}</code>
          </span>
        </td>
        <td colspan="2">
          <span class="cell-name cell-ellipsis" title="${esc(group.plugin_name || '—')}">${esc(group.plugin_name || '—')}</span>
          <span class="badge asset-group-count" style="margin-left:0.5rem">${fmt(count)}</span>
        </td>`;
    }

    const header = `
    <tr class="asset-group-row${expanded ? ' is-expanded' : ''}" data-mtd-group-key="${esc(group.key)}" tabindex="0" role="button" aria-expanded="${expanded ? 'true' : 'false'}">
      ${primary}
      <td>${maxVpr}</td>
      <td colspan="3" class="cell-time">Click to ${expanded ? 'collapse' : 'expand'}</td>
    </tr>`;

    if (!expanded) return header;
    const children = group.rows
      .slice()
      .sort((a, b) => (Number(b.vpr_score) || 0) - (Number(a.vpr_score) || 0))
      .map(renderMtdNewChildRow)
      .join('');
    return header + children;
  }).join('');
}

function renderMtdNewPage() {
  const tbody = $('mtd-new-table-body');
  if (!tbody) return;

  const list = mtdNewRowsCache;
  if (!list.length) {
    const msg = mtdNewAllRows.length
      ? 'No findings match your column filters'
      : 'No new vulnerabilities so far this month';
    tbody.innerHTML = `<tr><td colspan="8" class="cell-time">${msg}</td></tr>`;
    updateMtdNewPager();
    updateMtdNewFilterButtons();
    return;
  }

  if (mtdNewGroupBy === 'none') {
    const start = (mtdNewPage - 1) * mtdNewPageSize;
    const pageRows = list.slice(start, start + mtdNewPageSize);
    tbody.innerHTML = renderMtdNewFlatRows(pageRows);
  } else {
    const start = (mtdNewPage - 1) * mtdNewPageSize;
    const pageGroups = mtdNewGroupsCache.slice(start, start + mtdNewPageSize);
    tbody.innerHTML = renderMtdNewGroupedRows(pageGroups);
  }

  updateMtdNewPager();
  updateMtdNewFilterButtons();
}

function renderMtdNewTable(rows, expectedCount) {
  const tbody = $('mtd-new-table-body');
  const countEl = $('mtd-new-count');
  const hint = $('mtd-new-hint');
  if (!tbody) return;

  const list = Array.isArray(rows) ? rows : [];
  const expected = Number(expectedCount) || 0;
  mtdNewAllRows = list;
  mtdNewColFilters = emptyMtdNewFilters();
  mtdNewPage = 1;
  mtdNewExpandedGroups.clear();

  if (countEl) {
    countEl.textContent = list.length
      ? `${fmt(list.length)} finding${list.length === 1 ? '' : 's'}`
      : `${fmt(expected)} finding${expected === 1 ? '' : 's'}`;
  }
  if (hint) {
    hint.textContent = list.length
      ? 'First Seen this month · Risk Modified = NONE · VPR ≥ 0.1 · filter columns or group by Hostname / Plugin ID'
      : 'No new findings first-seen this month for the selected scope';
  }

  if (!list.length && expected > 0 && !Array.isArray(rows)) {
    mtdNewRowsCache = [];
    mtdNewGroupsCache = [];
    tbody.innerHTML =
      '<tr><td colspan="8" class="cell-time">New findings list unavailable — restart the app (`python app.py`) and hard-refresh the page</td></tr>';
    updateMtdNewPager();
    return;
  }

  applyMtdNewFilters();
}

function renderMtd(mtd) {
  if (!mtd) return;
  $('mtd-title').textContent = `Month to date — ${monthLabel(mtd.month)} (day ${mtd.days_elapsed})`;
  $('mtd-start').textContent = fmt(mtd.backlog_start);
  $('mtd-start-method').textContent = methodLabel(mtd.method);
  $('mtd-new').textContent = fmt(mtd.new_findings);
  $('mtd-res').textContent = fmt(mtd.resurfaced);
  $('mtd-fixed').textContent = fmt(mtd.fixed);
  $('mtd-active').textContent = fmt(mtd.active_now);
  $('mtd-coverage').textContent = pct(mtd.coverage_pct);
  $('mtd-mttr').textContent = days(mtd.median_days_to_fix_crit_high);
  $('mtd-sla').textContent = pct(mtd.sla_attainment_pct);
  renderMtdNewTable(mtd.new_findings_rows, mtd.new_findings);
}

function renderTable(months) {
  const tbody = $('patch-table-body');
  if (!months?.length) {
    tbody.innerHTML = '<tr><td colspan="13" class="cell-time">No closed months yet — sync from Tenable first</td></tr>';
    return;
  }
  tbody.innerHTML = months.map((m) => {
    const end = endOf(m);
    const net = end != null && m.backlog_start != null ? end - m.backlog_start : null;
    return `
      <tr>
        <td><strong>${esc(monthLabel(m.month))}</strong></td>
        <td>${fmt(m.backlog_start)}</td>
        <td>${fmt(m.new_findings)}</td>
        <td>${fmt(m.resurfaced)}</td>
        <td>${fmt(m.fixed)}</td>
        <td><strong>${fmt(end)}</strong></td>
        <td class="${net > 0 ? 'lumin-net-up' : net < 0 ? 'lumin-net-down' : ''}">${signed(net)}</td>
        <td>${rateBadge(m.resolved_pct)}</td>
        <td>${pct(m.backlog_cleared_pct)}</td>
        <td>${days(m.median_days_to_fix_crit_high)}</td>
        <td>${days(m.median_days_to_fix_med_low)}</td>
        <td>${slaBadge(m.sla_attainment_pct)}</td>
        <td>${methodBadge(m.method)}</td>
      </tr>`;
  }).join('');

  const gaps = months.filter((m) => m.flow_gap);
  const note = $('flow-gap-note');
  if (gaps.length) {
    const worst = gaps.reduce((a, b) => (Math.abs(b.flow_gap) > Math.abs(a.flow_gap) ? b : a));
    note.textContent =
      `Reconstructed months: "Fixed" shows only the latest fix Tenable still reports. ` +
      `A finding fixed, resurfaced and fixed again has its earlier fix erased, so Start + New + Resurfaced − Fixed can exceed the observed End ` +
      `(largest hidden-fix gap: ${monthLabel(worst.month)}, ${fmt(Math.abs(worst.flow_gap))}). ` +
      `Resolved % uses the observed End and is not affected. Months frozen from history do not have this gap.`;
  } else {
    note.textContent = '';
  }
}

function renderAssets(rows) {
  const tbody = $('assets-table-body');
  if (!rows?.length) { tbody.innerHTML = '<tr><td colspan="9" class="cell-time">No active findings for the selected scope</td></tr>'; return; }
  tbody.innerHTML = rows.map((r, i) => `
    <tr>
      <td><span class="asset-rank">${i + 1}</span></td>
      <td><strong>${esc(r.hostname || '—')}</strong></td>
      <td>${esc(r.ipv4 || '—')}</td>
      <td>${sevPill('critical', r.critical)}</td>
      <td>${sevPill('high', r.high)}</td>
      <td>${sevPill('medium', r.medium)}</td>
      <td>${sevPill('low', r.low)}</td>
      <td>${r.vpr_score != null ? Number(r.vpr_score).toFixed(1) : '—'}</td>
      <td>${fmt(r.total_vulns)}</td>
    </tr>`).join('');
}

function renderRecast(rows) {
  const tbody = $('recast-accept-table-body');
  if (!tbody) return;
  recastRowsCache = Array.isArray(rows) ? rows : [];
  if (!recastRowsCache.length) {
    expandedRecastIndexes.clear();
    tbody.innerHTML = '<tr><td colspan="7" class="cell-time">No recast or accept risk findings for the selected scope</td></tr>';
    return;
  }

  [...expandedRecastIndexes].forEach((idx) => {
    if (idx < 0 || idx >= recastRowsCache.length) expandedRecastIndexes.delete(idx);
  });

  tbody.innerHTML = recastRowsCache.map((r, index) => {
    const expanded = expandedRecastIndexes.has(index);
    const assets = Array.isArray(r.assets) ? r.assets : [];
    const badgeCls = (r.risk_type || '').toLowerCase() === 'accept' ? 'risk-accept' : 'risk-recast';
    const header = `
    <tr class="asset-group-row recast-plugin-row${expanded ? ' is-expanded' : ''}" data-recast-index="${index}" tabindex="0" role="button" aria-expanded="${expanded ? 'true' : 'false'}">
      <td>
        <span class="asset-group-toggle">
          <span class="asset-group-chevron" aria-hidden="true">▶</span>
          <span class="cell-name cell-ellipsis" title="${esc(r.plugin_name || '—')}">${esc(r.plugin_name || '—')}</span>
        </span>
      </td>
      <td><code>${esc(r.plugin_id || '—')}</code></td>
      <td><span class="risk-mod-badge ${badgeCls}">${esc(r.risk_type || '—')}</span></td>
      <td><span class="badge asset-group-count">${fmt(r.asset_count)}</span></td>
      <td>${fmt(r.finding_count)}</td>
      <td>${esc(r.created_at_display || '—')}</td>
      <td>${esc(r.expires_at_display || '—')}</td>
    </tr>`;

    if (!expanded) return header;

    if (!assets.length) {
      return `${header}<tr class="port-child-row recast-asset-row"><td colspan="7" class="cell-time">No assets listed for this plugin</td></tr>`;
    }

    const children = assets.map((a) => `
      <tr class="port-child-row recast-asset-row">
        <td><span class="port-child-label">${esc(a.hostname || '—')}</span></td>
        <td colspan="2">${esc(a.ipv4 || '—')}</td>
        <td colspan="2"><span class="badge asset-group-count">${fmt(a.finding_count)} finding${Number(a.finding_count) === 1 ? '' : 's'}</span></td>
        <td colspan="2"></td>
      </tr>`).join('');
    return header + children;
  }).join('');
}

function toggleRecastRow(index) {
  const idx = Number(index);
  if (!Number.isFinite(idx)) return;
  if (expandedRecastIndexes.has(idx)) expandedRecastIndexes.delete(idx);
  else expandedRecastIndexes.add(idx);
  renderRecast(recastRowsCache);
}

function updateScopeHints(data) {
  const tag = data?.tag_filter;
  if (tag?.label) {
    const n = tag.asset_count ?? data.scoped_asset_count ?? 0;
    $('dashboard-scope-hint').textContent = `Tag: ${tag.label} · ${fmt(n)} assets · months computed live for this scope (not frozen)`;
    $('top-assets-hint').textContent = `Top assets with tag ${tag.label} — active findings by VPR tier`;
    $('recast-accept-hint').textContent = `Recast/accept active findings on assets tagged ${tag.label}`;
  } else {
    $('dashboard-scope-hint').textContent = 'Closed months are frozen · current month shown separately as provisional';
    $('top-assets-hint').textContent = 'Highest combined VPR exposure — active findings by VPR tier';
    $('recast-accept-hint').textContent = 'Active findings with accepted or recasted risk — excluded from all counts above';
  }
}

/* ───────────── page state ───────────── */

function showLoading() {
  $('dashboard-loading').classList.remove('hidden');
  $('dashboard-error').classList.add('hidden');
  $('dashboard-content').classList.add('hidden');
}

function showError(message) {
  $('dashboard-loading').classList.add('hidden');
  $('dashboard-error').classList.remove('hidden');
  $('dashboard-error-message').textContent = message;
}

function setRefreshing(active) {
  metricsRefreshDepth = Math.max(0, metricsRefreshDepth + (active ? 1 : -1));
  const on = metricsRefreshDepth > 0;
  $('dashboard-metrics-panel').classList.toggle('is-refreshing', on);
  $('dashboard-metrics-overlay').classList.toggle('hidden', !on);
  $('dashboard-refresh-bar').classList.toggle('hidden', !on);
  $('dashboard-tag-select').disabled = on;
  $('refresh-dashboard-btn').disabled = on;
}

function applyDashboard(data) {
  $('dashboard-loading').classList.add('hidden');
  $('dashboard-error').classList.add('hidden');
  $('dashboard-empty').classList.add('hidden');
  $('dashboard-content').classList.remove('hidden');

  generatedAt = data.generated_at;
  $('report-generated').textContent = data.computed_at ? `Computed ${new Date(data.computed_at).toLocaleString()}` : '—';
  $('last-updated').textContent = `Last updated: ${relativeTime(generatedAt)}`;
  $('status-dot').classList.toggle('online', !!generatedAt);

  const months = data.closed_months || [];
  destroyCharts();
  renderNow(data.now || {});
  renderBacklogChart(months);
  renderWaterfall(months[months.length - 1]);
  renderMttrChart(months);
  renderSlaChart(months);
  renderFixTimeInsights(data.fix_time_insights || {});
  renderMtd(data.month_to_date);
  renderTable(months);
  renderAssets(data.top_risky_assets);
  renderRecast(data.recast_accept_risks);
  updateScopeHints(data);

  dashboardData = data;
  $('export-report-btn').disabled = false;
  if (lastSyncStatus) updateEmptyState(lastSyncStatus);
}

async function fetchMetrics() {
  const params = new URLSearchParams();
  if (selectedTagUuid) params.set('tag_uuid', selectedTagUuid);
  const qs = params.toString();
  const res = await fetch(`/api/lumin/metrics${qs ? `?${qs}` : ''}`, { cache: 'no-store' });
  const data = await parseApiResponse(res);
  if (!res.ok) throw new Error(data.detail || data.error || 'Failed to load Lumin Index metrics');
  return data;
}

async function loadTagOptions() {
  const select = $('dashboard-tag-select');
  if (tagOptionsLoaded) return;
  try {
    const res = await fetch('/api/dashboard/tags', { cache: 'no-store' });
    const data = await parseApiResponse(res);
    if (!res.ok) return;
    select.innerHTML = '<option value="">All assets</option>' + (data.options || []).map((o) =>
      `<option value="${esc(o.uuid)}">${esc(o.label)} (${fmt(o.asset_count)})</option>`).join('');
    select.value = selectedTagUuid;
    tagOptionsLoaded = true;
  } catch (err) {
    console.warn('Tag options load failed:', err);
  }
}

async function loadMetrics({ quiet = false, refreshing = false } = {}) {
  if (!quiet) showLoading();
  if (refreshing) setRefreshing(true);
  try {
    const data = await fetchMetrics();
    applyDashboard(data);
    if (data.warning && !quiet) {
      $('dashboard-error').classList.remove('hidden');
      $('dashboard-error-message').textContent = data.warning;
    }
  } catch (err) {
    if (!quiet) showError(err.message || 'No metrics available — sync from Tenable first.');
  } finally {
    if (refreshing) setRefreshing(false);
  }
}

function exportReport() {
  if (!dashboardData) return;
  const blob = new Blob([JSON.stringify(dashboardData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `lumin-index-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

document.addEventListener('DOMContentLoaded', () => {
  $('refresh-dashboard-btn').addEventListener('click', () => loadMetrics({ refreshing: !$('dashboard-content').classList.contains('hidden') }));
  $('sync-daily-btn').addEventListener('click', () => startSync({ daily: true }));
  $('sync-full-btn').addEventListener('click', () => {
    if (confirm('Full export since epoch (all states). This can take several minutes. Continue?')) startSync({ full: true });
  });
  $('export-report-btn').addEventListener('click', exportReport);
  $('dashboard-tag-select').addEventListener('change', (e) => {
    selectedTagUuid = e.target.value || '';
    loadMetrics({ quiet: true, refreshing: true });
  });

  const mtdPageSize = $('mtd-new-page-size');
  if (mtdPageSize) {
    mtdNewPageSize = parseInt(mtdPageSize.value, 10) || 25;
    mtdPageSize.addEventListener('change', (e) => {
      mtdNewPageSize = parseInt(e.target.value, 10) || 25;
      mtdNewPage = 1;
      renderMtdNewPage();
    });
  }
  const mtdPrev = $('mtd-new-prev');
  const mtdNext = $('mtd-new-next');
  if (mtdPrev) {
    mtdPrev.addEventListener('click', () => {
      if (mtdNewPage <= 1) return;
      mtdNewPage -= 1;
      renderMtdNewPage();
    });
  }
  if (mtdNext) {
    mtdNext.addEventListener('click', () => {
      const itemCount = mtdNewGroupBy === 'none'
        ? mtdNewRowsCache.length
        : mtdNewGroupsCache.length;
      const totalPages = Math.max(1, Math.ceil(itemCount / mtdNewPageSize) || 1);
      if (mtdNewPage >= totalPages) return;
      mtdNewPage += 1;
      renderMtdNewPage();
    });
  }
  initMtdNewColFilters();

  document.querySelectorAll('[data-mtd-group]').forEach((btn) => {
    btn.addEventListener('click', () => setMtdNewGroupBy(btn.dataset.mtdGroup));
  });

  const mtdBody = $('mtd-new-table-body');
  if (mtdBody) {
    mtdBody.addEventListener('click', (e) => {
      const row = e.target.closest('.asset-group-row');
      if (!row) return;
      toggleMtdNewGroup(row.dataset.mtdGroupKey);
    });
    mtdBody.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const row = e.target.closest('.asset-group-row');
      if (!row) return;
      e.preventDefault();
      toggleMtdNewGroup(row.dataset.mtdGroupKey);
    });
  }

  const recastBody = $('recast-accept-table-body');
  if (recastBody) {
    recastBody.addEventListener('click', (e) => {
      const row = e.target.closest('.recast-plugin-row');
      if (!row) return;
      toggleRecastRow(row.dataset.recastIndex);
    });
    recastBody.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const row = e.target.closest('.recast-plugin-row');
      if (!row) return;
      e.preventDefault();
      toggleRecastRow(row.dataset.recastIndex);
    });
  }

  [
    ['fix-before-body', 'fix-before-row', 'fixBeforeIndex', 'before'],
    ['fix-after-body', 'fix-after-row', 'fixAfterIndex', 'after'],
  ].forEach(([bodyId, rowCls, datasetKey, side]) => {
    const body = $(bodyId);
    if (!body) return;
    body.addEventListener('click', (e) => {
      const row = e.target.closest(`.${rowCls}`);
      if (!row) return;
      toggleFixPluginRow(side, row.dataset[datasetKey]);
    });
    body.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const row = e.target.closest(`.${rowCls}`);
      if (!row) return;
      e.preventDefault();
      toggleFixPluginRow(side, row.dataset[datasetKey]);
    });
  });
  setInterval(() => { if (generatedAt) $('last-updated').textContent = `Last updated: ${relativeTime(generatedAt)}`; }, 30000);
  loadTagOptions().then(() => pollSyncStatus().then(() => loadMetrics()));
});
