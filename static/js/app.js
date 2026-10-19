const PAGE_SIZE_DEFAULT = 25;
const NEW_ASSET_DAYS = 7;
const COL_WIDTHS_KEY = 'tenable-asset-col-widths';

const SOURCE_LABELS = {
  NESSUS_AGENT: 'Agent',
  NESSUS_SCAN: 'Scan',
  PVS: 'NNM',
  WAS: 'WAS',
  AWS: 'AWS',
  CloudDiscoveryConnector: 'Cloud',
};

const DEFAULT_COL_WIDTHS = {
  name: 18,
  ipAddress: 11,
  operatingSystem: 18,
  sources: 14,
  tags: 18,
  firstSeen: 10,
  lastSeen: 11,
};

const COLUMN_META = {
  name: { label: 'Asset Name', type: 'text' },
  ipAddress: { label: 'IP Address', type: 'text' },
  operatingSystem: {
    label: 'Operating System',
    type: 'values',
    getValues: (a) => a.operatingSystemsRaw || [],
  },
  sources: {
    label: 'Sources',
    type: 'values',
    getValues: (a) => a.sourcesRaw || [],
    formatValue: (v) => formatSourceLabel(v),
  },
  tags: {
    label: 'Tags',
    type: 'values',
    getValues: (a) => (a.tags || []).map((t) => t.label),
  },
  firstSeen: {
    label: 'First Seen',
    type: 'text',
    getText: (a) => formatDate(a.firstSeen),
  },
  lastSeen: {
    label: 'Last Seen',
    type: 'text',
    getText: (a) => formatRelative(a.lastSeen),
  },
};

function emptyColFilters() {
  const filters = {};
  Object.keys(COLUMN_META).forEach((key) => {
    filters[key] = COLUMN_META[key].type === 'values'
      ? { selected: new Set() }
      : { text: '' };
  });
  return filters;
}

const state = {
  assets: [],
  filtered: [],
  sortKey: 'name',
  sortDir: 'asc',
  page: 1,
  pageSize: PAGE_SIZE_DEFAULT,
  loading: false,
  lastSync: null,
  colFilters: emptyColFilters(),
  openFilterCol: null,
};

const $ = (id) => document.getElementById(id);

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatRelative(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return formatDate(iso);
}

function isRecent(iso) {
  if (!iso) return false;
  const d = new Date(iso);
  return Date.now() - d.getTime() < 24 * 60 * 60 * 1000;
}

function formatSync(iso, cached = false) {
  if (!iso) return 'Never synced';
  const prefix = cached ? 'Cached · synced' : 'Synced';
  return `${prefix} ${new Date(iso).toLocaleString()}`;
}

function formatNumber(n) {
  return new Intl.NumberFormat().format(n);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function escapeAttr(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function setStatus(mode) {
  const dot = $('status-dot');
  dot.className = 'status-dot';
  if (mode === 'live') dot.classList.add('live');
  else if (mode === 'loading') dot.classList.add('loading');
  else if (mode === 'error') dot.classList.add('error');
}

function setLoading(loading, message) {
  state.loading = loading;
  $('loading-banner').classList.toggle('hidden', !loading);
  $('table-card').classList.toggle('table-loading', loading);
  $('table-card').classList.toggle('is-loading', loading);
  $('loading-message').textContent = message || 'Fetching assets from Tenable…';
  $('refresh-btn').disabled = loading;
  $('refresh-icon').classList.toggle('spinner', loading);
  $('refresh-label').textContent = loading ? 'Syncing…' : 'Refresh';
  setStatus(loading ? 'loading' : (state.lastSync ? 'live' : ''));
}

function showError(message) {
  $('error-banner').classList.remove('hidden');
  $('error-message').textContent = message;
  setStatus('error');
}

function hideError() {
  $('error-banner').classList.add('hidden');
}

function osCategory(os) {
  const lower = (os || '').toLowerCase();
  if (lower.includes('windows')) return 'windows';
  if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('centos') || lower.includes('red hat') || lower.includes('oracle')) return 'linux';
  if (lower.includes('mac') || lower.includes('darwin') || lower.includes('os x')) return 'macos';
  return 'other';
}

function updateKpis(assets) {
  const cutoff = Date.now() - NEW_ASSET_DAYS * 24 * 60 * 60 * 1000;
  let windows = 0; let linux = 0; let macos = 0; let newAssets = 0;

  assets.forEach((a) => {
    const cats = new Set((a.operatingSystemsRaw || []).map(osCategory));
    if (cats.has('windows')) windows += 1;
    if (cats.has('linux')) linux += 1;
    if (cats.has('macos')) macos += 1;
    if (a.firstSeen && new Date(a.firstSeen).getTime() >= cutoff) newAssets += 1;
  });

  $('kpi-total').textContent = formatNumber(assets.length);
  $('kpi-windows').textContent = formatNumber(windows);
  $('kpi-linux').textContent = formatNumber(linux);
  $('kpi-macos').textContent = formatNumber(macos);
  $('kpi-new').textContent = formatNumber(newAssets);
}

function isFilterActive(col) {
  const meta = COLUMN_META[col];
  const f = state.colFilters[col];
  if (!meta || !f) return false;
  if (meta.type === 'values') return f.selected.size > 0;
  return Boolean(f.text && f.text.trim());
}

function updateFilterButtonStates() {
  document.querySelectorAll('.col-filter-btn').forEach((btn) => {
    btn.classList.toggle('is-active', isFilterActive(btn.dataset.filter));
  });
}

function columnCellText(asset, col) {
  const meta = COLUMN_META[col];
  if (meta.getText) return meta.getText(asset);
  if (col === 'tags') return (asset.tags || []).map((t) => t.label).join(', ');
  if (col === 'sources') {
    return (asset.sourcesRaw || []).map(formatSourceLabel).join(', ');
  }
  return String(asset[col] || '');
}

function applyFilters() {
  state.filtered = state.assets.filter((asset) => {
    return Object.keys(COLUMN_META).every((col) => {
      const meta = COLUMN_META[col];
      const f = state.colFilters[col];

      if (meta.type === 'values') {
        if (!f.selected.size) return true;
        const values = meta.getValues(asset);
        return values.some((v) => f.selected.has(v));
      }

      const q = (f.text || '').trim().toLowerCase();
      if (!q) return true;
      return columnCellText(asset, col).toLowerCase().includes(q);
    });
  });

  state.page = 1;
  updateFilterButtonStates();
  sortAndRender();
}

function sortValue(asset, key) {
  if (key === 'firstSeen' || key === 'lastSeen') {
    const v = asset[key];
    return v ? new Date(v).getTime() : 0;
  }
  if (key === 'tags') {
    return (asset.tags || []).map((t) => t.label).join(', ').toLowerCase();
  }
  if (key === 'sources') {
    return (asset.sourcesRaw || []).map(formatSourceLabel).join(', ').toLowerCase();
  }
  return String(asset[key] || '').toLowerCase();
}

function formatSourceLabel(s) {
  return SOURCE_LABELS[s] || s.replace(/_/g, ' ');
}

function sourcesDisplayText(asset) {
  const sources = asset.sourcesRaw || [];
  if (!sources.length) return '—';
  return sources.map(formatSourceLabel).join(', ');
}

function tagsDisplayText(tags) {
  if (!tags || !tags.length) return '—';
  return tags.map((t) => t.label).join(', ');
}

function renderEmpty(message, isError = false) {
  return `<tr><td colspan="7"><div class="empty-state">
    <svg fill="none" stroke="${isError ? '#dc2626' : 'currentColor'}" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
    </svg>
    <p>${escapeHtml(message)}</p>
  </div></td></tr>`;
}

function sortAndRender() {
  const { sortKey, sortDir } = state;
  const sorted = [...state.filtered].sort((a, b) => {
    const av = sortValue(a, sortKey);
    const bv = sortValue(b, sortKey);
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  document.querySelectorAll('.th-sort.sortable').forEach((btn) => {
    const th = btn.closest('.col-th');
    const icon = btn.querySelector('.sort-icon');
    if (btn.dataset.sort === sortKey) {
      icon.textContent = sortDir === 'asc' ? ' ↑' : ' ↓';
      th.classList.add('sort-active');
    } else {
      icon.textContent = '';
      th.classList.remove('sort-active');
    }
  });

  const totalPages = Math.max(1, Math.ceil(sorted.length / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;

  const start = (state.page - 1) * state.pageSize;
  const pageItems = sorted.slice(start, start + state.pageSize);

  $('table-count').textContent = `${formatNumber(sorted.length)} asset${sorted.length === 1 ? '' : 's'}`;
  $('page-info').textContent = `Page ${state.page} of ${totalPages}`;
  $('prev-page').disabled = state.page <= 1;
  $('next-page').disabled = state.page >= totalPages;

  const tbody = $('asset-tbody');
  if (pageItems.length === 0) {
    tbody.innerHTML = renderEmpty('No assets match your filters.');
    return;
  }

  tbody.innerHTML = pageItems.map((a) => {
    const ips = (a.ipAddress || '—').split(', ');
    const ipText = a.ipAddress || '—';
    const ipHtml = ips[0] === '—'
      ? '<span class="cell-time">—</span>'
      : `<span class="cell-ip cell-ellipsis" title="${escapeAttr(ipText)}">${escapeHtml(ips[0])}</span>${ips.length > 1 ? ` <span class="badge badge-more">+${ips.length - 1}</span>` : ''}`;

    const osText = a.operatingSystem || '—';
    const sourcesText = sourcesDisplayText(a);
    const tagsText = tagsDisplayText(a.tags);
    const lastSeenClass = isRecent(a.lastSeen) ? 'cell-time recent' : 'cell-time';

    return `<tr>
      <td><span class="cell-name cell-ellipsis" title="${escapeAttr(a.name)}">${escapeHtml(a.name)}</span></td>
      <td>${ipHtml}</td>
      <td><span class="cell-os cell-ellipsis" title="${escapeAttr(osText)}">${escapeHtml(osText)}</span></td>
      <td class="cell-sources"><span class="cell-ellipsis" title="${escapeAttr(sourcesText)}">${escapeHtml(sourcesText)}</span></td>
      <td class="cell-tags"><span class="cell-ellipsis" title="${escapeAttr(tagsText)}">${escapeHtml(tagsText)}</span></td>
      <td><span class="cell-time">${formatDate(a.firstSeen)}</span></td>
      <td><span class="${lastSeenClass}">${formatRelative(a.lastSeen)}</span></td>
    </tr>`;
  }).join('');
}

function loadColWidths() {
  try {
    const saved = JSON.parse(localStorage.getItem(COL_WIDTHS_KEY) || '{}');
    return { ...DEFAULT_COL_WIDTHS, ...saved };
  } catch {
    return { ...DEFAULT_COL_WIDTHS };
  }
}

function saveColWidths(widths) {
  try {
    localStorage.setItem(COL_WIDTHS_KEY, JSON.stringify(widths));
  } catch {
  }
}

function applyColWidths() {
  const widths = loadColWidths();
  document.querySelectorAll('#asset-table col[data-col]').forEach((col) => {
    const key = col.dataset.col;
    col.style.width = `${widths[key] ?? DEFAULT_COL_WIDTHS[key]}%`;
  });
}

function initColResize() {
  const table = $('asset-table');
  let active = null;

  const onMove = (e) => {
    if (!active) return;
    const tableWidth = table.getBoundingClientRect().width;
    if (!tableWidth) return;

    const delta = e.clientX - active.startX;
    const newPx = Math.max(48, active.startWidth + delta);
    const newPct = (newPx / tableWidth) * 100;
    const widths = loadColWidths();
    const totalOther = Object.keys(widths).reduce((sum, k) => (
      k === active.col ? sum : sum + widths[k]
    ), 0);
    const maxPct = Math.min(60, 100 - totalOther + widths[active.col] - 5);
    const clamped = Math.max(5, Math.min(maxPct, newPct));

    widths[active.col] = Math.round(clamped * 10) / 10;
    saveColWidths(widths);
    applyColWidths();
  };

  const onUp = () => {
    if (active) active.th.classList.remove('is-resizing');
    document.body.classList.remove('is-col-resizing');
    active = null;
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
  };

  document.querySelectorAll('.col-th .col-resize-handle').forEach((handle) => {
    handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const th = handle.closest('.col-th');
      active = {
        col: th.dataset.col,
        th,
        startX: e.clientX,
        startWidth: th.getBoundingClientRect().width,
      };
      th.classList.add('is-resizing');
      document.body.classList.add('is-col-resizing');
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });
}

function uniqueColumnValues(col) {
  const meta = COLUMN_META[col];
  const counts = new Map();

  state.assets.forEach((asset) => {
    meta.getValues(asset).forEach((raw) => {
      const label = meta.formatValue ? meta.formatValue(raw) : raw;
      if (!counts.has(raw)) counts.set(raw, { raw, label, count: 0 });
      counts.get(raw).count += 1;
    });
  });

  return [...counts.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function closeColFilterMenu() {
  const menu = $('col-filter-menu');
  menu.classList.add('hidden');
  menu.setAttribute('aria-hidden', 'true');
  state.openFilterCol = null;
}

function positionColFilterMenu(anchor) {
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

function buildColFilterBody(col) {
  const meta = COLUMN_META[col];
  const body = $('col-filter-body');
  const f = state.colFilters[col];

  if (meta.type === 'text') {
    body.innerHTML = `
      <input type="text" id="col-filter-text" class="col-filter-text"
        placeholder="Contains…" value="${escapeAttr(f.text || '')}" autocomplete="off">`;
    const input = $('col-filter-text');
    input.focus();
    input.select();
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') applyColFilterMenu();
    });
    return;
  }

  const values = uniqueColumnValues(col);
  const selected = f.selected;
  body.innerHTML = `
    <input type="text" id="col-filter-search" class="col-filter-search"
      placeholder="Search values…" autocomplete="off">
    <div id="col-filter-list" class="col-filter-list"></div>`;

  const list = $('col-filter-list');
  const renderList = (query) => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? values.filter((v) => v.label.toLowerCase().includes(q))
      : values;

    if (!filtered.length) {
      list.innerHTML = '<p class="cell-time">No values found</p>';
      return;
    }

    list.innerHTML = filtered.map((v) => `
      <label class="col-filter-option">
        <input type="checkbox" value="${escapeAttr(v.raw)}" ${selected.has(v.raw) ? 'checked' : ''}>
        <span>${escapeHtml(v.label)} <span class="cell-time">(${v.count})</span></span>
      </label>`).join('');
  };

  renderList('');
  $('col-filter-search').addEventListener('input', (e) => renderList(e.target.value));
  $('col-filter-search').focus();
}

function openColFilterMenu(col, anchor) {
  if (state.openFilterCol === col && !$('col-filter-menu').classList.contains('hidden')) {
    closeColFilterMenu();
    return;
  }

  state.openFilterCol = col;
  $('col-filter-title').textContent = `Filter: ${COLUMN_META[col].label}`;
  buildColFilterBody(col);
  positionColFilterMenu(anchor);
}

function applyColFilterMenu() {
  const col = state.openFilterCol;
  if (!col) return;

  const meta = COLUMN_META[col];
  const f = state.colFilters[col];

  if (meta.type === 'text') {
    const input = $('col-filter-text');
    f.text = input ? input.value : '';
  } else {
    f.selected = new Set();
    document.querySelectorAll('#col-filter-list input[type="checkbox"]:checked').forEach((cb) => {
      f.selected.add(cb.value);
    });
  }

  closeColFilterMenu();
  applyFilters();
}

function clearColFilterMenu() {
  const col = state.openFilterCol;
  if (!col) return;

  const meta = COLUMN_META[col];
  if (meta.type === 'text') {
    state.colFilters[col].text = '';
    const input = $('col-filter-text');
    if (input) input.value = '';
  } else {
    state.colFilters[col].selected = new Set();
    document.querySelectorAll('#col-filter-list input[type="checkbox"]').forEach((cb) => {
      cb.checked = false;
    });
  }

  closeColFilterMenu();
  applyFilters();
}

function initColFilters() {
  document.querySelectorAll('.col-filter-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openColFilterMenu(btn.dataset.filter, btn);
    });
  });

  $('col-filter-apply').addEventListener('click', applyColFilterMenu);
  $('col-filter-clear').addEventListener('click', clearColFilterMenu);
  $('col-filter-close').addEventListener('click', closeColFilterMenu);

  document.addEventListener('click', (e) => {
    const menu = $('col-filter-menu');
    if (menu.classList.contains('hidden')) return;
    if (menu.contains(e.target) || e.target.closest('.col-filter-btn')) return;
    closeColFilterMenu();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeColFilterMenu();
  });
}

async function loadAssets(forceRefresh = false) {
  hideError();
  const message = forceRefresh
    ? 'Exporting assets from Tenable — this may take up to a minute…'
    : 'Loading assets…';
  setLoading(true, message);

  try {
    const url = forceRefresh ? '/api/assets?refresh=1' : '/api/assets';
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load assets');

    state.assets = data.assets || [];
    state.lastSync = data.lastSync;
    $('last-sync').textContent = formatSync(state.lastSync, data.cached);
    setStatus(data.stale ? 'error' : 'live');

    if (data.warning) showError(data.warning);

    updateKpis(state.assets);
    applyFilters();
  } catch (err) {
    showError(err.message);
    $('asset-tbody').innerHTML = renderEmpty('Failed to load assets. Check your API keys and try again.', true);
  } finally {
    setLoading(false);
  }
}

function exportCsv() {
  const rows = state.filtered.length ? state.filtered : state.assets;
  if (!rows.length) return;

  const headers = ['Asset Name', 'IP Address', 'Operating System', 'Sources', 'Tags', 'First Seen', 'Last Seen'];
  const csvRows = [headers.join(',')];

  rows.forEach((a) => {
    const tags = (a.tags || []).map((t) => t.label).join('; ');
    csvRows.push([
      `"${(a.name || '').replace(/"/g, '""')}"`,
      `"${(a.ipAddress || '').replace(/"/g, '""')}"`,
      `"${(a.operatingSystem || '').replace(/"/g, '""')}"`,
      `"${(a.sources || '').replace(/"/g, '""')}"`,
      `"${tags.replace(/"/g, '""')}"`,
      `"${formatDate(a.firstSeen)}"`,
      `"${formatDate(a.lastSeen)}"`,
    ].join(','));
  });

  const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `asset-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

document.querySelectorAll('.th-sort.sortable').forEach((btn) => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.sort;
    if (state.sortKey === key) {
      state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortKey = key;
      state.sortDir = 'asc';
    }
    sortAndRender();
  });
});

$('page-size').addEventListener('change', (e) => {
  state.pageSize = parseInt(e.target.value, 10);
  state.page = 1;
  sortAndRender();
});
$('prev-page').addEventListener('click', () => { state.page -= 1; sortAndRender(); });
$('next-page').addEventListener('click', () => { state.page += 1; sortAndRender(); });
$('refresh-btn').addEventListener('click', () => loadAssets(true));
$('export-csv-btn').addEventListener('click', exportCsv);

applyColWidths();
initColResize();
initColFilters();
loadAssets();
