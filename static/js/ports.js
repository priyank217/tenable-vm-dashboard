const PAGE_SIZE_DEFAULT = 25;
const COL_WIDTHS_KEY = 'tenable-ports-col-widths';

const SOURCE_LABELS = {
  NESSUS_AGENT: 'Agent',
  NESSUS_SCAN: 'Scan',
  PVS: 'NNM',
  WAS: 'WAS',
  AWS: 'AWS',
  CloudDiscoveryConnector: 'Cloud',
};

const WELL_KNOWN_SERVICES = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPC',
  123: 'NTP',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  500: 'IKE',
  587: 'SMTP',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6443: 'Kubernetes API',
  8080: 'HTTP-ALT',
  8443: 'HTTPS-ALT',
  9100: 'Printer',
};

const SERVICE_ALIASES = {
  www: 'HTTP',
  'www-http': 'HTTP',
  http: 'HTTP',
  https: 'HTTPS',
  ssl: 'HTTPS',
  ssh: 'SSH',
  domain: 'DNS',
  dns: 'DNS',
  cifs: 'SMB',
  'microsoft-ds': 'SMB',
  'ms-wbt-server': 'RDP',
  snmp: 'SNMP',
  ldap: 'LDAP',
  smtp: 'SMTP',
  ftp: 'FTP',
};

const DEFAULT_COL_WIDTHS = {
  name: 28,
  ipAddress: 16,
  port: 14,
  service: 22,
  sources: 20,
};

const COLUMN_META = {
  name: { label: 'Asset Name', type: 'text' },
  ipAddress: { label: 'IP Address', type: 'text' },
  port: {
    label: 'Port',
    type: 'values',
    getValues: (row) => {
      const port = row.port;
      if (port == null) return [];
      const proto = row.protocol && row.protocol !== '—' ? row.protocol : '';
      return [proto ? `${port}/${proto}` : String(port)];
    },
  },
  service: {
    label: 'Service',
    type: 'values',
    getValues: (row) => {
      const s = resolveService(row);
      if (!s || s === '—') return [];
      return [s];
    },
  },
  sources: {
    label: 'Source',
    type: 'values',
    getValues: (row) => row.sourcesRaw || [],
    formatValue: (v) => formatSourceLabel(v),
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
  ports: [],
  filtered: [],
  groups: [],
  viewMode: 'asset', // best practice: group by asset name + IP
  sortKey: 'name',
  sortDir: 'asc',
  page: 1,
  pageSize: PAGE_SIZE_DEFAULT,
  loading: false,
  lastSync: null,
  colFilters: emptyColFilters(),
  openFilterCol: null,
  expanded: new Set(),
  selectedPort: null, // Most Observed Ports highlight (string port number)
};

const $ = (id) => document.getElementById(id);

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
  div.textContent = text == null ? '' : String(text);
  return div.innerHTML;
}

function escapeAttr(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function formatSourceLabel(s) {
  return SOURCE_LABELS[s] || String(s || '').replace(/_/g, ' ');
}

function sourcesDisplayText(row) {
  const sources = row.sourcesRaw || [];
  if (!sources.length) return row.sources || '—';
  return sources.map(formatSourceLabel).join(', ');
}

function portDisplayText(row) {
  if (row.port == null) return '—';
  const proto = row.protocol && row.protocol !== '—' ? row.protocol : '';
  return proto ? `${row.port}/${proto}` : String(row.port);
}

function resolveService(row) {
  const raw = String(row.service || '').trim();
  const port = Number(row.port);
  const known = Number.isFinite(port) ? WELL_KNOWN_SERVICES[port] : null;

  if (raw && raw !== '—') {
    const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
    const aliased = parts.map((s) => SERVICE_ALIASES[s.toLowerCase()] || s);
    const lower = aliased.map((s) => s.toLowerCase());
    if (known && lower.some((s) => ['www', 'http', 'https', 'ssl'].includes(s))) {
      return known;
    }
    return [...new Set(aliased)].join(', ');
  }
  return known || '—';
}

function portChipText(row) {
  const portText = portDisplayText(row);
  const service = resolveService(row);
  if (!service || service === '—') return portText;
  return `${portText} · ${service}`;
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
  $('loading-message').textContent = message || 'Fetching open ports from Tenable…';
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

function updateKpis(ports) {
  let tcp = 0;
  let udp = 0;
  const assets = new Set();
  const uniquePorts = new Set();

  ports.forEach((row) => {
    if (row.assetId) assets.add(row.assetId);
    if (row.port != null) uniquePorts.add(`${row.port}/${row.protocol || ''}`);
    const proto = String(row.protocol || '').toUpperCase();
    if (proto === 'TCP') tcp += 1;
    else if (proto === 'UDP') udp += 1;
  });

  $('kpi-total').textContent = formatNumber(ports.length);
  $('kpi-assets').textContent = formatNumber(assets.size);
  $('kpi-tcp').textContent = formatNumber(tcp);
  $('kpi-udp').textContent = formatNumber(udp);
  $('kpi-unique').textContent = formatNumber(uniquePorts.size);
}

function renderExposureOverview() {
  const data = state.ports || [];
  const counts = new Map();
  let tcp = 0;
  let udp = 0;

  data.forEach((row) => {
    const port = row.port;
    if (port == null) return;
    const key = String(port);
    const service = resolveService(row);
    const item = counts.get(key) || {
      port: key,
      service: service !== '—' ? service : 'Unknown',
      count: 0,
    };
    item.count += 1;
    if ((item.service === 'Unknown' || !item.service) && service && service !== '—') {
      item.service = service;
    }
    counts.set(key, item);

    const proto = String(row.protocol || '').toUpperCase();
    if (proto === 'UDP') udp += 1;
    else if (proto === 'TCP') tcp += 1;
  });

  const top = [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 6);
  const max = top[0]?.count || 1;
  const bars = $('exposure-bars');
  const selected = state.selectedPort != null ? String(state.selectedPort) : null;

  if (bars) {
    if (!top.length) {
      bars.innerHTML = '<p class="cell-time" style="padding:0.5rem 0">No port data available.</p>';
    } else {
      bars.innerHTML = top.map((item, index) => {
        const isSelected = selected === String(item.port);
        const dimmed = selected && !isSelected;
        const cls = [
          'exposure-bar-row',
          isSelected ? 'is-selected' : '',
          dimmed ? 'is-dimmed' : '',
        ].filter(Boolean).join(' ');
        return `
        <button type="button" class="${cls}" data-filter-port="${escapeAttr(item.port)}"
          aria-pressed="${isSelected ? 'true' : 'false'}"
          title="${isSelected ? 'Clear port highlight' : `Highlight port ${escapeAttr(item.port)}`}">
          <span class="exposure-port">${escapeHtml(item.port)}</span>
          <span class="exposure-service">${escapeHtml(item.service || 'Unknown')}</span>
          <span class="exposure-track">
            <span class="exposure-fill rank-${index + 1}" style="width:${Math.max(4, (item.count / max) * 100)}%"></span>
          </span>
          <strong>${formatNumber(item.count)}</strong>
        </button>`;
      }).join('');
    }
  }

  const total = tcp + udp;
  const tcpPct = total ? Math.round((tcp / total) * 100) : 0;
  const udpPct = total ? 100 - tcpPct : 0;

  if ($('exposure-unique')) $('exposure-unique').textContent = formatNumber(counts.size);
  if ($('protocol-total')) $('protocol-total').textContent = formatNumber(total);
  if ($('protocol-tcp')) $('protocol-tcp').textContent = formatNumber(tcp);
  if ($('protocol-udp')) $('protocol-udp').textContent = formatNumber(udp);
  if ($('protocol-tcp-pct')) $('protocol-tcp-pct').textContent = `${tcpPct}%`;
  if ($('protocol-udp-pct')) $('protocol-udp-pct').textContent = `${udpPct}%`;
  if ($('protocol-donut')) {
    $('protocol-donut').style.setProperty('--tcp-angle', `${tcpPct * 3.6}deg`);
  }
}

function applyPortHighlight(portValue) {
  const value = portValue == null || portValue === '' ? null : String(portValue);
  const current = state.selectedPort == null ? null : String(state.selectedPort);

  if (value && current === value) {
    state.selectedPort = null;
    state.colFilters.port = { selected: new Set() };
  } else if (value) {
    state.selectedPort = value;
    const matches = new Set();
    state.ports.forEach((row) => {
      if (row.port == null) return;
      if (String(row.port) !== value) return;
      const proto = row.protocol && row.protocol !== '—' ? row.protocol : '';
      matches.add(proto ? `${row.port}/${proto}` : String(row.port));
    });
    state.colFilters.port = { selected: matches };
  } else {
    state.selectedPort = null;
    state.colFilters.port = { selected: new Set() };
  }

  applyFilters();
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

function columnCellText(row, col) {
  const meta = COLUMN_META[col];
  if (col === 'port') return portDisplayText(row);
  if (col === 'sources') return sourcesDisplayText(row);
  if (meta.getText) return meta.getText(row);
  return String(row[col] == null ? '' : row[col]);
}

function assetGroupKey(row) {
  return row.assetId || `${row.name || ''}::${row.ipAddress || ''}`;
}

function buildAssetGroups(rows) {
  const map = new Map();
  rows.forEach((row) => {
    const key = assetGroupKey(row);
    let group = map.get(key);
    if (!group) {
      group = {
        key,
        assetId: row.assetId,
        name: row.name || '—',
        ipAddress: row.ipAddress || '—',
        sources: row.sources || '—',
        sourcesRaw: row.sourcesRaw || [],
        ports: [],
      };
      map.set(key, group);
    }
    group.ports.push(row);
  });

  map.forEach((group) => {
    group.ports.sort((a, b) => {
      const ap = Number(a.port);
      const bp = Number(b.port);
      if (ap !== bp) return (Number.isFinite(ap) ? ap : 0) - (Number.isFinite(bp) ? bp : 0);
      return String(a.protocol || '').localeCompare(String(b.protocol || ''));
    });
    group.portCount = group.ports.length;
  });

  return [...map.values()];
}

function applyFilters() {
  state.filtered = state.ports.filter((row) => {
    return Object.keys(COLUMN_META).every((col) => {
      const meta = COLUMN_META[col];
      const f = state.colFilters[col];

      if (meta.type === 'values') {
        if (!f.selected.size) return true;
        const values = meta.getValues(row);
        return values.some((v) => f.selected.has(v));
      }

      const q = (f.text || '').trim().toLowerCase();
      if (!q) return true;
      return columnCellText(row, col).toLowerCase().includes(q);
    });
  });

  state.groups = buildAssetGroups(state.filtered);
  state.page = 1;
  updateFilterButtonStates();
  sortAndRender();
  renderExposureOverview();
}

function sortValue(row, key) {
  if (key === 'port') {
    const n = Number(row.port);
    return Number.isFinite(n) ? n : -1;
  }
  if (key === 'sources') {
    return sourcesDisplayText(row).toLowerCase();
  }
  return String(row[key] == null ? '' : row[key]).toLowerCase();
}

function sortGroupValue(group, key) {
  if (key === 'port') return group.portCount;
  if (key === 'sources') return sourcesDisplayText(group).toLowerCase();
  if (key === 'service') {
    return group.ports.map((p) => p.service || '').join(' ').toLowerCase();
  }
  return String(group[key] == null ? '' : group[key]).toLowerCase();
}

function renderEmpty(message, isError = false) {
  return `<tr><td colspan="5"><div class="empty-state">
    <svg fill="none" stroke="${isError ? '#dc2626' : 'currentColor'}" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
    </svg>
    <p>${escapeHtml(message)}</p>
  </div></td></tr>`;
}

function updateSortHeaders() {
  document.querySelectorAll('.th-sort.sortable').forEach((btn) => {
    const th = btn.closest('.col-th');
    const icon = btn.querySelector('.sort-icon');
    if (btn.dataset.sort === state.sortKey) {
      icon.textContent = state.sortDir === 'asc' ? ' ↑' : ' ↓';
      th.classList.add('sort-active');
    } else {
      icon.textContent = '';
      th.classList.remove('sort-active');
    }
  });
}

function renderIpCell(ipAddress) {
  const ips = String(ipAddress || '—').split(', ');
  const ipText = ipAddress || '—';
  if (ips[0] === '—') return '<span class="cell-time">—</span>';
  return `<span class="cell-ip cell-ellipsis" title="${escapeAttr(ipText)}">${escapeHtml(ips[0])}</span>${ips.length > 1 ? ` <span class="badge badge-more">+${ips.length - 1}</span>` : ''}`;
}

function renderPortChips(ports, limit = 8) {
  const shown = ports.slice(0, limit);
  const chips = shown.map((row) => {
    const text = portChipText(row);
    const isUdp = String(row.protocol || '').toUpperCase() === 'UDP';
    return `<span class="port-chip${isUdp ? ' is-udp' : ''}" title="${escapeAttr(text)}">${escapeHtml(text)}</span>`;
  }).join('');
  const more = ports.length > limit
    ? `<span class="badge badge-more">+${ports.length - limit}</span>`
    : '';
  return `<div class="port-chips">${chips}${more}</div>`;
}

function renderFlatRows(pageItems) {
  return pageItems.map((row) => {
    const portText = portDisplayText(row);
    const serviceText = resolveService(row);
    const sourcesText = sourcesDisplayText(row);
    return `<tr>
      <td><span class="cell-name cell-ellipsis" title="${escapeAttr(row.name)}">${escapeHtml(row.name)}</span></td>
      <td>${renderIpCell(row.ipAddress)}</td>
      <td><span class="cell-ip cell-ellipsis" title="${escapeAttr(portText)}">${escapeHtml(portText)}</span></td>
      <td><span class="cell-os cell-ellipsis" title="${escapeAttr(serviceText)}">${escapeHtml(serviceText)}</span></td>
      <td class="cell-sources"><span class="cell-ellipsis" title="${escapeAttr(sourcesText)}">${escapeHtml(sourcesText)}</span></td>
    </tr>`;
  }).join('');
}

function renderGroupedRows(pageGroups) {
  return pageGroups.map((group) => {
    const expanded = state.expanded.has(group.key);
    const sourcesText = sourcesDisplayText(group);
    const header = `<tr class="asset-group-row${expanded ? ' is-expanded' : ''}" data-group-key="${escapeAttr(group.key)}">
      <td>
        <span class="asset-group-toggle">
          <span class="asset-group-chevron" aria-hidden="true">▶</span>
          <span class="cell-name cell-ellipsis" title="${escapeAttr(group.name)}">${escapeHtml(group.name)}</span>
        </span>
      </td>
      <td>${renderIpCell(group.ipAddress)}</td>
      <td colspan="2">${renderPortChips(group.ports)}</td>
      <td class="cell-sources">
        <span class="badge asset-group-count">${formatNumber(group.portCount)} port${group.portCount === 1 ? '' : 's'}</span>
        <span class="cell-ellipsis" title="${escapeAttr(sourcesText)}" style="margin-left:0.5rem">${escapeHtml(sourcesText)}</span>
      </td>
    </tr>`;

    if (!expanded) return header;

    const children = group.ports.map((row) => {
      const portText = portDisplayText(row);
      const serviceText = resolveService(row);
      return `<tr class="port-child-row">
        <td><span class="port-child-label">Port detail</span></td>
        <td></td>
        <td><span class="cell-ip">${escapeHtml(portText)}</span></td>
        <td><span class="cell-os cell-ellipsis" title="${escapeAttr(serviceText)}">${escapeHtml(serviceText)}</span></td>
        <td></td>
      </tr>`;
    }).join('');

    return header + children;
  }).join('');
}

function sortAndRender() {
  const { sortKey, sortDir, viewMode } = state;
  updateSortHeaders();

  const pageSizeLabel = $('page-size-label');
  if (pageSizeLabel) {
    pageSizeLabel.textContent = viewMode === 'asset' ? 'Assets per page' : 'Rows per page';
  }

  const tbody = $('ports-tbody');

  if (viewMode === 'asset') {
    const sorted = [...state.groups].sort((a, b) => {
      const av = sortGroupValue(a, sortKey);
      const bv = sortGroupValue(b, sortKey);
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return String(a.name).localeCompare(String(b.name));
    });

    const totalPages = Math.max(1, Math.ceil(sorted.length / state.pageSize));
    if (state.page > totalPages) state.page = totalPages;
    const start = (state.page - 1) * state.pageSize;
    const pageGroups = sorted.slice(start, start + state.pageSize);
    const portCount = state.filtered.length;

    $('table-count').textContent = `${formatNumber(sorted.length)} asset${sorted.length === 1 ? '' : 's'} · ${formatNumber(portCount)} port${portCount === 1 ? '' : 's'}`;
    $('page-info').textContent = `Page ${state.page} of ${totalPages}`;
    $('prev-page').disabled = state.page <= 1;
    $('next-page').disabled = state.page >= totalPages;

    if (!pageGroups.length) {
      tbody.innerHTML = renderEmpty('No open ports match your filters.');
      return;
    }
    tbody.innerHTML = renderGroupedRows(pageGroups);
    return;
  }

  const sorted = [...state.filtered].sort((a, b) => {
    const av = sortValue(a, sortKey);
    const bv = sortValue(b, sortKey);
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.max(1, Math.ceil(sorted.length / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;
  const start = (state.page - 1) * state.pageSize;
  const pageItems = sorted.slice(start, start + state.pageSize);

  $('table-count').textContent = `${formatNumber(sorted.length)} port${sorted.length === 1 ? '' : 's'}`;
  $('page-info').textContent = `Page ${state.page} of ${totalPages}`;
  $('prev-page').disabled = state.page <= 1;
  $('next-page').disabled = state.page >= totalPages;

  if (!pageItems.length) {
    tbody.innerHTML = renderEmpty('No open ports match your filters.');
    return;
  }
  tbody.innerHTML = renderFlatRows(pageItems);
}

function setViewMode(mode) {
  if (mode !== 'asset' && mode !== 'flat') return;
  state.viewMode = mode;
  state.page = 1;
  document.querySelectorAll('.view-toggle-btn').forEach((btn) => {
    btn.classList.toggle('is-active', btn.dataset.view === mode);
  });
  sortAndRender();
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
  document.querySelectorAll('#ports-table col[data-col]').forEach((col) => {
    const key = col.dataset.col;
    col.style.width = `${widths[key] ?? DEFAULT_COL_WIDTHS[key]}%`;
  });
}

function initColResize() {
  const table = $('ports-table');
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

  state.ports.forEach((row) => {
    meta.getValues(row).forEach((raw) => {
      const label = meta.formatValue ? meta.formatValue(raw) : raw;
      if (!counts.has(raw)) counts.set(raw, { raw, label, count: 0 });
      counts.get(raw).count += 1;
    });
  });

  return [...counts.values()].sort((a, b) => String(a.label).localeCompare(String(b.label)));
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
      ? values.filter((v) => String(v.label).toLowerCase().includes(q))
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

  if (col === 'port') {
    const ports = new Set([...f.selected].map((v) => String(v).split('/')[0]));
    state.selectedPort = ports.size === 1 ? [...ports][0] : null;
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

  if (col === 'port') state.selectedPort = null;

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

async function loadPorts(forceRefresh = false) {
  hideError();
  const message = forceRefresh
    ? 'Exporting assets with open ports from Tenable — this may take a few minutes…'
    : 'Loading open ports…';
  setLoading(true, message);

  try {
    const url = forceRefresh ? '/api/open-ports?refresh=1' : '/api/open-ports';
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load open ports');

    state.ports = data.ports || [];
    state.lastSync = data.lastSync;
    $('last-sync').textContent = formatSync(state.lastSync, data.cached);
    setStatus(data.stale ? 'error' : 'live');

    if (data.warning) showError(data.warning);

    updateKpis(state.ports);
    applyFilters();
  } catch (err) {
    showError(err.message);
    $('ports-tbody').innerHTML = renderEmpty('Failed to load open ports. Check your API keys and try again.', true);
  } finally {
    setLoading(false);
  }
}

function exportCsv() {
  const rows = state.filtered.length ? state.filtered : state.ports;
  if (!rows.length) return;

  const headers = ['Asset Name', 'IP Address', 'Port', 'Protocol', 'Service', 'Source'];
  const csvRows = [headers.join(',')];

  rows.forEach((row) => {
    csvRows.push([
      `"${String(row.name || '').replace(/"/g, '""')}"`,
      `"${String(row.ipAddress || '').replace(/"/g, '""')}"`,
      `"${row.port == null ? '' : row.port}"`,
      `"${String(row.protocol || '').replace(/"/g, '""')}"`,
      `"${String(resolveService(row) || '').replace(/"/g, '""')}"`,
      `"${sourcesDisplayText(row).replace(/"/g, '""')}"`,
    ].join(','));
  });

  const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `open-ports-${new Date().toISOString().slice(0, 10)}.csv`;
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
$('refresh-btn').addEventListener('click', () => loadPorts(true));
$('export-csv-btn').addEventListener('click', exportCsv);

document.querySelectorAll('.view-toggle-btn').forEach((btn) => {
  btn.addEventListener('click', () => setViewMode(btn.dataset.view));
});

$('ports-tbody').addEventListener('click', (e) => {
  const row = e.target.closest('.asset-group-row');
  if (!row) return;
  const key = row.dataset.groupKey;
  if (!key) return;
  if (state.expanded.has(key)) state.expanded.delete(key);
  else state.expanded.add(key);
  sortAndRender();
});

document.addEventListener('click', (e) => {
  const bars = $('exposure-bars');
  const bar = e.target.closest('.exposure-bar-row');
  if (!bars || !bar || !bars.contains(bar) || !bar.dataset.filterPort) return;
  e.preventDefault();
  e.stopPropagation();
  const port = String(bar.dataset.filterPort);
  setTimeout(() => applyPortHighlight(port), 0);
});

applyColWidths();
initColResize();
initColFilters();
loadPorts();
