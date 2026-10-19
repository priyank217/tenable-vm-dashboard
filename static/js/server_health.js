/* Server Health — last reboot matrix (plugins 56468 / 92366). */

const POLL_MS = 4000;

const Status = {
  order: ['healthy', 'attention', 'warning', 'critical'],
  label: { healthy: 'Healthy', attention: 'Attention', warning: 'Warning', critical: 'Critical' },
  fromDays(d) {
    if (d == null || Number.isNaN(d)) return 'unknown';
    return d < 1 ? 'healthy' : d < 21 ? 'attention' : d <= 30 ? 'warning' : 'critical';
  },
  rank(s) { return this.order.indexOf(s); },
  age(d) {
    if (d == null || Number.isNaN(d)) return 'Unknown';
    return d < 1
      ? `${Math.max(1, Math.round(d * 24))} hours ago`
      : `${Number(d).toFixed(1)} days ago`;
  },
};

const fmt = {
  date(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
  },
  time(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC';
  },
  relativeSync(iso) {
    if (!iso) return 'Last sync: Never';
    const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
    if (Number.isNaN(mins)) return `Last sync: ${iso}`;
    if (mins < 1) return 'Last sync: just now';
    if (mins === 1) return 'Last sync: 1 minute ago';
    if (mins < 60) return `Last sync: ${mins} minutes ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `Last sync: ${hrs} h ago`;
    return `Last sync: ${Math.floor(hrs / 24)} d ago`;
  },
};

const State = {
  servers: [],
  byId: new Map(),
  q: '',
  os: 'all',
  status: 'all',
  sort: 'oldest',
  selected: null,
  lastSync: null,
  plugins: { linux: 56468, windows: 92366 },
  page: 1,
  pageSize: 50,
  tableSortKey: 'age',
  tableSortDir: 'desc',
  colFilters: null,
  openFilterCol: null,
  osGroup: null, // { family: 'linux'|'windows', label: 'RHEL 8' }
};

const $ = (id) => document.getElementById(id);
let pollTimer = null;

function setSyncStatus(state, label) {
  const dot = $('status-dot');
  const text = $('last-sync');
  if (dot) dot.className = 'status-dot' + (state ? ` ${state}` : '');
  if (label && text) text.textContent = label;
}

function showError(message) {
  $('error-banner').classList.remove('hidden');
  $('error-message').textContent = message || 'Unknown error';
}

function hideError() {
  $('error-banner').classList.add('hidden');
}

function showWarning(message) {
  if (!message) {
    $('warning-banner').classList.add('hidden');
    return;
  }
  $('warning-banner').classList.remove('hidden');
  $('warning-message').textContent = message;
}

function setLoading(on, message) {
  const banner = $('loading-banner');
  const btn = $('refresh-btn');
  const icon = $('refresh-icon');
  const label = $('refresh-label');
  if (on) {
    banner.classList.remove('hidden');
    if (message) $('loading-message').textContent = message;
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

async function parseApiResponse(res) {
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    throw new Error(`Server returned non-JSON (HTTP ${res.status}).`);
  }
  return res.json();
}

function normalizeServer(raw) {
  const days = raw.daysSinceReboot == null ? null : Number(raw.daysSinceReboot);
  const status = raw.status && raw.status !== 'unknown'
    ? raw.status
    : Status.fromDays(days);
  return {
    id: String(raw.id || raw.assetUuid || ''),
    assetUuid: raw.assetUuid || '',
    hostname: raw.hostname || '—',
    ip: raw.ip || '—',
    os: (raw.os || 'unknown').toLowerCase(),
    osName: raw.osName || ((raw.os || '') === 'linux' ? 'Linux' : (raw.os || '') === 'windows' ? 'Windows' : '—'),
    daysSinceReboot: days,
    lastReboot: raw.lastReboot || null,
    status,
    tenablePlugin: raw.tenablePlugin,
    pluginOutput: raw.pluginOutput || '',
    firstFound: raw.firstFound || null,
    lastFound: raw.lastFound || null,
  };
}

const COL_META = {
  hostname: { label: 'Hostname', type: 'text', getText: (s) => s.hostname || '' },
  ip: { label: 'IP', type: 'text', getText: (s) => String(s.ip || '') },
  os: {
    label: 'OS',
    type: 'values',
    getText: (s) => s.osName || s.os || '',
    getValues: (s) => [s.osName || (s.os === 'linux' ? 'Linux' : s.os === 'windows' ? 'Windows' : 'Unknown')],
  },
  status: {
    label: 'Status',
    type: 'values',
    getText: (s) => Status.label[s.status] || s.status || '',
    getValues: (s) => [Status.label[s.status] || s.status || 'Unknown'],
  },
  lastReboot: {
    label: 'Last reboot',
    type: 'text',
    getText: (s) => `${fmt.date(s.lastReboot)} ${fmt.time(s.lastReboot)}`.trim(),
  },
  age: {
    label: 'Age',
    type: 'text',
    getText: (s) => (s.daysSinceReboot == null ? '' : String(s.daysSinceReboot)),
  },
  plugin: {
    label: 'Plugin',
    type: 'values',
    getText: (s) => String(s.tenablePlugin
      || (s.os === 'linux' ? State.plugins.linux : State.plugins.windows) || ''),
    getValues: (s) => [String(s.tenablePlugin
      || (s.os === 'linux' ? State.plugins.linux : State.plugins.windows) || '')],
  },
  lastFound: {
    label: 'Last found',
    type: 'text',
    getText: (s) => fmt.date(s.lastFound),
  },
};

function emptyColFilters() {
  const out = {};
  Object.keys(COL_META).forEach((col) => {
    out[col] = COL_META[col].type === 'values'
      ? { selected: new Set() }
      : { text: '' };
  });
  return out;
}

State.colFilters = emptyColFilters();

function attrEsc(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function normalizeOsGroup(osFamily, osName) {
  const raw = String(osName || '').trim();
  const family = String(osFamily || '').toLowerCase();
  if (!raw) return family === 'windows' ? 'Windows (unknown)' : 'Linux (unknown)';

  if (family === 'windows' || /windows/i.test(raw)) {
    const year = raw.match(/Windows\s+Server\s+(\d{4})/i);
    if (year) return `Windows Server ${year[1]}`;
    const win = raw.match(/Windows\s+(\d{2,4})/i);
    if (win) return `Windows ${win[1]}`;
    return 'Windows (other)';
  }

  let m = raw.match(/Red\s+Hat\s+Enterprise\s+Linux(?:\s+Server)?\s+(\d+)/i);
  if (m) return `RHEL ${m[1]}`;
  m = raw.match(/CentOS(?:\s+Linux)?\s+(\d+)/i);
  if (m) return `CentOS ${m[1]}`;
  m = raw.match(/Rocky\s+Linux\s+(\d+)/i);
  if (m) return `Rocky Linux ${m[1]}`;
  m = raw.match(/Alma(?:Linux)?\s+(\d+)/i);
  if (m) return `AlmaLinux ${m[1]}`;
  m = raw.match(/Oracle\s+Linux(?:\s+Server)?\s+(\d+)/i);
  if (m) return `Oracle Linux ${m[1]}`;
  m = raw.match(/Debian(?:\s+Linux)?\s+(\d+)/i);
  if (m) return `Debian ${m[1]}`;
  m = raw.match(/Ubuntu(?:\s+Linux)?\s+(\d+\.\d+|\d+)/i);
  if (m) return `Ubuntu ${m[1]}`;
  m = raw.match(/SUSE\s+Linux\s+Enterprise(?:\s+Server)?\s+(\d+)/i);
  if (m) return `SLES ${m[1]}`;
  m = raw.match(/Amazon\s+Linux\s+(\d+)/i);
  if (m) return `Amazon Linux ${m[1]}`;

  const first = raw.split(/[(\[]/)[0].trim();
  return first || 'Linux (other)';
}

const OsGroups = {
  build(servers) {
    const map = new Map();
    servers.forEach((s) => {
      const family = s.os === 'windows' ? 'windows' : s.os === 'linux' ? 'linux' : null;
      if (!family) return;
      const label = normalizeOsGroup(family, s.osName);
      const key = `${family}::${label}`;
      const cur = map.get(key) || { label, family, count: 0 };
      cur.count += 1;
      map.set(key, cur);
    });
    return [...map.values()].sort((a, b) =>
      b.count - a.count || a.label.localeCompare(b.label, undefined, { numeric: true }));
  },
  render() {
    const rows = this.build(State.servers);
    const totalHosts = rows.reduce((n, r) => n + r.count, 0);
    const el = $('os-groups');
    const badge = $('os-groups-total');
    badge.textContent = `${rows.length} version${rows.length === 1 ? '' : 's'}`;
    if (!rows.length) {
      el.innerHTML = '<div class="sh-os-empty">No OS data yet</div>';
      return;
    }
    el.innerHTML = rows.map((r) => {
      const pct = totalHosts ? ((r.count / totalHosts) * 100).toFixed(1) : '0.0';
      const on = State.osGroup
        && State.osGroup.family === r.family
        && State.osGroup.label === r.label;
      const fam = r.family === 'windows' ? 'Windows' : 'Linux';
      return `<button type="button" class="sh-os-tile${on ? ' on' : ''}"
          data-family="${esc(r.family)}" data-label="${attrEsc(r.label)}"
          aria-pressed="${on ? 'true' : 'false'}"
          title="Filter to ${attrEsc(r.label)}">
        <span class="sh-os-tile-fam">${esc(fam)}</span>
        <span class="sh-os-tile-name">${esc(r.label)}</span>
        <span class="sh-os-tile-count">${r.count}</span>
        <span class="sh-os-tile-pct">${pct}% of estate</span>
      </button>`;
    }).join('');
  },
  init() {
    $('os-groups').addEventListener('click', (e) => {
      const btn = e.target.closest('.sh-os-tile');
      if (!btn) return;
      const family = btn.dataset.family;
      const label = btn.dataset.label;
      const same = State.osGroup
        && State.osGroup.family === family
        && State.osGroup.label === label;
      if (same) {
        State.osGroup = null;
        $('fos').value = 'all';
        State.os = 'all';
      } else {
        State.osGroup = { family, label };
        $('fos').value = family;
        State.os = family;
      }
      State.page = 1;
      UI.sync();
      this.render();
    });
  },
};

const Filter = {
  matchesFilters(s) {
    if (!(State.os === 'all' || s.os === State.os)) return false;
    if (!(State.status === 'all' || s.status === State.status)) return false;
    if (State.osGroup) {
      if (s.os !== State.osGroup.family) return false;
      if (normalizeOsGroup(s.os, s.osName) !== State.osGroup.label) return false;
    }
    return true;
  },
  matchesSearch(s) {
    const q = State.q.trim().toLowerCase();
    if (!q) return true;
    return s.hostname.toLowerCase().includes(q) || String(s.ip).toLowerCase().includes(q);
  },
  matchesColFilters(s) {
    return Object.keys(COL_META).every((col) => {
      const meta = COL_META[col];
      const f = State.colFilters[col];
      if (meta.type === 'values') {
        if (!f.selected.size) return true;
        return meta.getValues(s).some((v) => f.selected.has(String(v)));
      }
      const q = (f.text || '').trim().toLowerCase();
      if (!q) return true;
      return meta.getText(s).toLowerCase().includes(q);
    });
  },
  isVisible(s) {
    return this.matchesFilters(s) && this.matchesSearch(s) && this.matchesColFilters(s);
  },
  isActive() {
    return !!(State.q.trim() || State.os !== 'all' || State.status !== 'all'
      || State.osGroup || this.hasColFilters());
  },
  hasColFilters() {
    return Object.keys(COL_META).some((col) => this.isColFilterActive(col));
  },
  isColFilterActive(col) {
    const meta = COL_META[col];
    const f = State.colFilters[col];
    if (!meta || !f) return false;
    if (meta.type === 'values') return f.selected.size > 0;
    return Boolean(f.text && f.text.trim());
  },
  visibleSorted() {
    return TableSort.apply(State.servers.filter((s) => this.isVisible(s)));
  },
};

const Sort = {
  fns: {
    oldest: (a, b) => (b.daysSinceReboot ?? -1) - (a.daysSinceReboot ?? -1),
    newest: (a, b) => (a.daysSinceReboot ?? 1e9) - (b.daysSinceReboot ?? 1e9),
    name: (a, b) => a.hostname.localeCompare(b.hostname, undefined, { numeric: true }),
    status: (a, b) => Status.rank(b.status) - Status.rank(a.status)
      || (b.daysSinceReboot ?? -1) - (a.daysSinceReboot ?? -1),
  },
  apply(list) {
    return [...list].sort(this.fns[State.sort] || this.fns.oldest);
  },
};

const TableSort = {
  cmp: {
    hostname: (a, b) => a.hostname.localeCompare(b.hostname, undefined, { numeric: true }),
    ip: (a, b) => String(a.ip).localeCompare(String(b.ip), undefined, { numeric: true }),
    os: (a, b) => (a.osName || a.os).localeCompare(b.osName || b.os, undefined, { numeric: true }),
    status: (a, b) => Status.rank(a.status) - Status.rank(b.status),
    lastReboot: (a, b) => String(a.lastReboot || '').localeCompare(String(b.lastReboot || '')),
    age: (a, b) => (a.daysSinceReboot ?? -1) - (b.daysSinceReboot ?? -1),
    plugin: (a, b) => Number(a.tenablePlugin || 0) - Number(b.tenablePlugin || 0),
    lastFound: (a, b) => String(a.lastFound || '').localeCompare(String(b.lastFound || '')),
  },
  apply(list) {
    const fn = this.cmp[State.tableSortKey] || this.cmp.age;
    const dir = State.tableSortDir === 'asc' ? 1 : -1;
    return [...list].sort((a, b) => {
      const r = fn(a, b);
      if (r !== 0) return r * dir;
      return a.hostname.localeCompare(b.hostname, undefined, { numeric: true });
    });
  },
};

const Matrix = {
  build() {
    ['linux', 'windows'].forEach((os) => {
      const grid = $('grid-' + os);
      grid.textContent = '';
      const frag = document.createDocumentFragment();
      const rows = Sort.apply(State.servers.filter((s) => s.os === os));
      rows.forEach((s) => {
        const el = document.createElement('div');
        el.className = 'sh-sq';
        el.dataset.id = s.id;
        el.dataset.s = s.status;
        el.tabIndex = 0;
        el.setAttribute('role', 'listitem');
        el.setAttribute(
          'aria-label',
          `${s.hostname}, ${Status.label[s.status] || s.status}, rebooted ${Status.age(s.daysSinceReboot)}`,
        );
        frag.appendChild(el);
      });
      grid.appendChild(frag);
      const cols = Math.max(8, Math.min(40, Math.ceil(Math.sqrt(rows.length * 1.6)) || 8));
      grid.style.setProperty('--cols', String(cols));
      $('count-' + os).textContent = `${rows.length} server${rows.length === 1 ? '' : 's'}`;
    });
    this.paint();
  },
  paint() {
    const searching = !!State.q.trim();
    const filtering = State.os !== 'all' || State.status !== 'all' || !!State.osGroup || Filter.hasColFilters();
    let shown = 0;
    document.querySelectorAll('.sh-sq').forEach((el) => {
      const s = State.byId.get(el.dataset.id);
      if (!s) return;
      const inF = Filter.matchesFilters(s) && Filter.matchesColFilters(s);
      const hit = searching && Filter.matchesSearch(s);
      const visible = Filter.isVisible(s);
      if (visible) shown += 1;
      el.classList.toggle('dim', (filtering || searching) && !visible);
      el.classList.toggle('match', searching && hit && inF);
      el.classList.toggle('sel', State.selected === s.id);
    });
    $('g-linux').classList.toggle('hidden', State.os === 'windows' || !State.servers.some((s) => s.os === 'linux'));
    $('g-windows').classList.toggle('hidden', State.os === 'linux' || !State.servers.some((s) => s.os === 'windows'));
    $('empty-state').classList.toggle('hidden', State.servers.length > 0);
    this.minis();
    UI.count(shown, searching || filtering);
  },
  minis() {
    ['linux', 'windows'].forEach((os) => {
      const c = { attention: 0, warning: 0, critical: 0 };
      State.servers.forEach((s) => {
        if (s.os === os && c[s.status] !== undefined) c[s.status] += 1;
      });
      $('mini-' + os).innerHTML = ['attention', 'warning', 'critical'].map((k) =>
        `<span><b style="color:var(--sh-${k})">${c[k]}</b> ${Status.label[k].toLowerCase()}</span>`).join('');
    });
  },
};

const Tooltip = {
  el: null,
  init() {
    this.el = $('tip');
    const grid = $('mbody');
    grid.addEventListener('mouseover', (e) => {
      const sq = e.target.closest('.sh-sq');
      if (sq) this.show(sq, e);
    });
    grid.addEventListener('mousemove', (e) => {
      if (e.target.closest('.sh-sq')) this.move(e.clientX, e.clientY);
    });
    grid.addEventListener('mouseout', (e) => {
      if (e.target.closest('.sh-sq')) this.hide();
    });
    grid.addEventListener('focusin', (e) => {
      const sq = e.target.closest('.sh-sq');
      if (sq) {
        this.show(sq);
        const r = sq.getBoundingClientRect();
        this.move(r.right, r.top);
      }
    });
    grid.addEventListener('focusout', () => this.hide());
    window.addEventListener('scroll', () => this.hide(), true);
  },
  show(sq, e) {
    const s = State.byId.get(sq.dataset.id);
    if (!s) return;
    this.el.innerHTML = `<div class="h"><b>${esc(s.hostname)}</b><span class="sh-pill" data-s="${esc(s.status)}">${esc(Status.label[s.status] || s.status)}</span></div>
      <dl><dt>IP</dt><dd>${esc(s.ip)}</dd><dt>OS</dt><dd>${esc(s.osName)}</dd><dt>Last reboot</dt><dd>${esc(Status.age(s.daysSinceReboot))}</dd></dl>`;
    this.el.classList.add('show');
    if (e) this.move(e.clientX, e.clientY);
  },
  move(x, y) {
    const w = this.el.offsetWidth;
    const h = this.el.offsetHeight;
    const m = 14;
    let left = x + m;
    let top = y + m;
    if (left + w > innerWidth - 8) left = x - w - m;
    if (top + h > innerHeight - 8) top = y - h - m;
    this.el.style.left = `${Math.max(8, left)}px`;
    this.el.style.top = `${Math.max(8, top)}px`;
  },
  hide() { this.el.classList.remove('show'); },
};

function esc(text) {
  const div = document.createElement('div');
  div.textContent = text ?? '';
  return div.innerHTML;
}

const Drawer = {
  init() {
    $('mbody').addEventListener('click', (e) => {
      const sq = e.target.closest('.sh-sq');
      if (sq) this.open(sq.dataset.id);
    });
    $('mbody').addEventListener('keydown', (e) => {
      const sq = e.target.closest('.sh-sq');
      if (sq && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        this.open(sq.dataset.id);
      }
    });
    $('dclose').addEventListener('click', () => this.close());
    $('scrim').addEventListener('click', () => this.close());
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && State.selected && $('col-filter-menu').classList.contains('hidden')) {
        this.close();
      }
    });
  },
  open(id) {
    const s = State.byId.get(id);
    if (!s) return;
    State.selected = id;
    const days = s.daysSinceReboot == null ? 0 : s.daysSinceReboot;
    const pos = Math.min(100, (days / 45) * 100);
    const plugin = s.tenablePlugin
      || (s.os === 'linux' ? State.plugins.linux : State.plugins.windows);
    const output = (s.pluginOutput || '').trim();
    $('dbody').innerHTML = `
      <h2 class="sh-dname">${esc(s.hostname)}</h2>
      <div class="sh-chips">
        <span class="sh-pill" data-s="${esc(s.status)}">${esc(Status.label[s.status] || s.status)}</span>
        <span class="sh-chip">${s.os === 'linux' ? 'Linux' : s.os === 'windows' ? 'Windows' : 'Unknown'}</span>
        <span class="sh-chip m">${esc(s.ip)}</span>
      </div>
      <div class="sh-sec"><h4>Last reboot</h4><div class="sh-big">${esc(Status.age(s.daysSinceReboot))}</div>
        <div class="sh-v2">${esc(fmt.date(s.lastReboot))} · ${esc(fmt.time(s.lastReboot))}</div></div>
      <div class="sh-sec"><h4>Reboot age</h4><div class="sh-v">${s.daysSinceReboot == null ? '—' : `${Number(s.daysSinceReboot).toFixed(1)} days`}</div>
        <div class="sh-age"><span class="mk" style="left:${pos}%"></span></div>
        <div class="sh-agel"><span>Now</span><span>3 wk</span><span>1 mo+</span></div></div>
      <div class="sh-sec"><h4>Operating system</h4><div class="sh-v">${esc(s.osName)}</div></div>
      <div class="sh-sec"><h4>Tenable</h4>
        <div class="sh-v">Plugin ${esc(plugin)}</div>
        <div class="sh-v2" style="margin-top:0.35rem">Asset ${esc(s.assetUuid || '—')}</div>
        <div class="sh-v2">First found ${esc(fmt.date(s.firstFound))} · Last found ${esc(fmt.date(s.lastFound))}</div>
      </div>
      ${output ? `<div class="sh-sec"><h4>Plugin output</h4><pre class="sh-pre">${esc(output.slice(0, 4000))}${output.length > 4000 ? '\n…' : ''}</pre></div>` : ''}`;
    $('drawer').classList.add('open');
    $('scrim').classList.add('open');
    $('drawer').setAttribute('aria-hidden', 'false');
    Tooltip.hide();
    Matrix.paint();
    Table.paintSelection();
    $('dclose').focus({ preventScroll: true });
  },
  close() {
    const prev = State.selected;
    State.selected = null;
    $('drawer').classList.remove('open');
    $('scrim').classList.remove('open');
    $('drawer').setAttribute('aria-hidden', 'true');
    Matrix.paint();
    Table.paintSelection();
    const el = document.querySelector(`.sh-sq[data-id="${CSS.escape(String(prev || ''))}"]`);
    if (el) el.focus({ preventScroll: true });
  },
};

const Table = {
  init() {
    $('sh-tbody').addEventListener('click', (e) => {
      const tr = e.target.closest('tr[data-id]');
      if (tr) Drawer.open(tr.dataset.id);
    });
    $('sh-tbody').addEventListener('keydown', (e) => {
      const tr = e.target.closest('tr[data-id]');
      if (tr && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        Drawer.open(tr.dataset.id);
      }
    });
    $('sh-prev').addEventListener('click', () => {
      if (State.page > 1) {
        State.page -= 1;
        this.render();
      }
    });
    $('sh-next').addEventListener('click', () => {
      const pages = this.pageCount();
      if (State.page < pages) {
        State.page += 1;
        this.render();
      }
    });

    document.querySelectorAll('#sh-table .th-sort.sortable').forEach((btn) => {
      btn.addEventListener('click', () => {
        const key = btn.dataset.sort;
        if (State.tableSortKey === key) {
          State.tableSortDir = State.tableSortDir === 'asc' ? 'desc' : 'asc';
        } else {
          State.tableSortKey = key;
          State.tableSortDir = key === 'age' || key === 'status' ? 'desc' : 'asc';
        }
        State.page = 1;
        this.render();
      });
    });

    document.querySelectorAll('#sh-table .col-filter-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.openFilter(btn.dataset.filter, btn);
      });
    });

    $('col-filter-close').addEventListener('click', () => this.closeFilter());
    $('col-filter-apply').addEventListener('click', () => this.applyFilterMenu());
    $('col-filter-clear').addEventListener('click', () => this.clearFilterMenu());
    document.addEventListener('mousedown', (e) => {
      const menu = $('col-filter-menu');
      if (menu.classList.contains('hidden')) return;
      if (menu.contains(e.target) || e.target.closest('#sh-table .col-filter-btn')) return;
      this.closeFilter();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !$('col-filter-menu').classList.contains('hidden')) {
        this.closeFilter();
      }
    });
  },
  pageCount() {
    const n = Filter.visibleSorted().length;
    return Math.max(1, Math.ceil(n / State.pageSize) || 1);
  },
  updateSortHeaders() {
    document.querySelectorAll('#sh-table .th-sort.sortable').forEach((btn) => {
      const th = btn.closest('.col-th');
      const icon = btn.querySelector('.sort-icon');
      if (btn.dataset.sort === State.tableSortKey) {
        icon.textContent = State.tableSortDir === 'asc' ? ' ↑' : ' ↓';
        th.classList.add('sort-active');
      } else {
        icon.textContent = '';
        th.classList.remove('sort-active');
      }
    });
  },
  updateFilterButtons() {
    document.querySelectorAll('#sh-table .col-filter-btn').forEach((btn) => {
      btn.classList.toggle('is-active', Filter.isColFilterActive(btn.dataset.filter));
    });
  },
  uniqueValues(col) {
    const meta = COL_META[col];
    const counts = new Map();
    State.servers.forEach((s) => {
      meta.getValues(s).forEach((v) => {
        const raw = String(v || '');
        if (!raw) return;
        const cur = counts.get(raw) || { raw, label: raw, count: 0 };
        cur.count += 1;
        counts.set(raw, cur);
      });
    });
    return [...counts.values()].sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  },
  positionFilter(anchor) {
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
  },
  buildFilterBody(col) {
    const meta = COL_META[col];
    const body = $('col-filter-body');
    const f = State.colFilters[col];
    if (meta.type === 'text') {
      body.innerHTML = `
        <input type="text" id="col-filter-text" class="col-filter-text"
          placeholder="Contains…" value="${attrEsc(f.text || '')}" autocomplete="off">`;
      const input = $('col-filter-text');
      input.focus();
      input.select();
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') this.applyFilterMenu();
      });
      return;
    }
    const values = this.uniqueValues(col);
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
          <input type="checkbox" value="${attrEsc(v.raw)}" ${selected.has(v.raw) ? 'checked' : ''}>
          <span>${esc(v.label)} <span class="cell-time">(${v.count})</span></span>
        </label>`).join('');
    };
    renderList('');
    $('col-filter-search').addEventListener('input', (e) => renderList(e.target.value));
    $('col-filter-search').focus();
  },
  openFilter(col, anchor) {
    if (State.openFilterCol === col && !$('col-filter-menu').classList.contains('hidden')) {
      this.closeFilter();
      return;
    }
    State.openFilterCol = col;
    $('col-filter-title').textContent = `Filter: ${COL_META[col].label}`;
    this.buildFilterBody(col);
    this.positionFilter(anchor);
  },
  closeFilter() {
    State.openFilterCol = null;
    $('col-filter-menu').classList.add('hidden');
    $('col-filter-menu').setAttribute('aria-hidden', 'true');
  },
  applyFilterMenu() {
    const col = State.openFilterCol;
    if (!col) return;
    const meta = COL_META[col];
    const f = State.colFilters[col];
    if (meta.type === 'text') {
      const input = $('col-filter-text');
      f.text = input ? input.value : '';
    } else {
      f.selected = new Set();
      document.querySelectorAll('#col-filter-list input[type="checkbox"]:checked').forEach((cb) => {
        f.selected.add(cb.value);
      });
    }
    this.closeFilter();
    State.page = 1;
    Matrix.paint();
    this.render();
    $('reset').classList.toggle('hidden', !Filter.isActive());
  },
  clearFilterMenu() {
    const col = State.openFilterCol;
    if (!col) return;
    if (COL_META[col].type === 'text') {
      State.colFilters[col].text = '';
      const input = $('col-filter-text');
      if (input) input.value = '';
    } else {
      State.colFilters[col].selected = new Set();
      document.querySelectorAll('#col-filter-list input[type="checkbox"]').forEach((cb) => {
        cb.checked = false;
      });
    }
  },
  clearAllColFilters() {
    State.colFilters = emptyColFilters();
    this.closeFilter();
  },
  render() {
    const rows = Filter.visibleSorted();
    const pages = Math.max(1, Math.ceil(rows.length / State.pageSize) || 1);
    if (State.page > pages) State.page = pages;
    if (State.page < 1) State.page = 1;
    const start = (State.page - 1) * State.pageSize;
    const pageRows = rows.slice(start, start + State.pageSize);
    const tbody = $('sh-tbody');
    if (!pageRows.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><p>${State.servers.length ? 'No servers match the current filters.' : 'No server health data yet. Click Refresh to sync from Tenable.'}</p></div></td></tr>`;
    } else {
      tbody.innerHTML = pageRows.map((s) => {
        const plugin = s.tenablePlugin
          || (s.os === 'linux' ? State.plugins.linux : State.plugins.windows);
        const age = s.daysSinceReboot == null
          ? '—'
          : `${Number(s.daysSinceReboot).toFixed(1)} d`;
        return `<tr data-id="${esc(s.id)}" class="${State.selected === s.id ? 'sel' : ''}" tabindex="0">
          <td><span class="sh-host" title="${esc(s.hostname)}">${esc(s.hostname)}</span></td>
          <td class="sh-muted">${esc(s.ip)}</td>
          <td class="sh-os" title="${esc(s.osName)}">${esc(s.osName || '—')}</td>
          <td><span class="sh-pill" data-s="${esc(s.status)}">${esc(Status.label[s.status] || s.status)}</span></td>
          <td class="sh-muted">${esc(fmt.date(s.lastReboot))}<div class="sh-muted">${esc(fmt.time(s.lastReboot))}</div></td>
          <td class="sh-muted">${esc(age)}</td>
          <td class="sh-muted">${esc(plugin)}</td>
          <td class="sh-muted">${esc(fmt.date(s.lastFound))}</td>
        </tr>`;
      }).join('');
    }
    const meta = Filter.isActive()
      ? `Showing ${rows.length} of ${State.servers.length} servers`
      : `${rows.length} server${rows.length === 1 ? '' : 's'}`;
    $('sh-table-meta').textContent = meta;
    $('table-count').textContent = meta;
    $('sh-page-info').textContent = `Page ${State.page} of ${pages}`;
    $('sh-prev').disabled = State.page <= 1;
    $('sh-next').disabled = State.page >= pages;
    this.updateSortHeaders();
    this.updateFilterButtons();
  },
  paintSelection() {
    document.querySelectorAll('#sh-tbody tr[data-id]').forEach((tr) => {
      tr.classList.toggle('sel', tr.dataset.id === State.selected);
    });
  },
};

const UI = {
  summaryBound: false,
  summary() {
    const c = { healthy: 0, attention: 0, warning: 0, critical: 0 };
    State.servers.forEach((s) => {
      if (c[s.status] !== undefined) c[s.status] += 1;
    });
    const t = State.servers.length;
    const linux = State.servers.filter((s) => s.os === 'linux').length;
    const windows = State.servers.filter((s) => s.os === 'windows').length;
    $('sumrow').innerHTML =
      `<div class="sh-metric"><div class="n">${t}</div><div class="l">Total servers</div><div class="pct">${linux} Linux · ${windows} Windows</div></div>`
      + Status.order.map((k) => `<div class="sh-metric" data-k="${k}"><button type="button" aria-label="Filter ${Status.label[k]}">
        <div class="n">${c[k]}</div><div class="l"><b style="background:var(--sh-${k})"></b>${Status.label[k]}</div>
        <div class="pct">${t ? ((c[k] / t) * 100).toFixed(1) : '0.0'}%</div></button></div>`).join('');
    $('sumbar').innerHTML = Status.order.map((k) =>
      `<span style="flex:${Math.max(c[k], 0)} 1 0;background:var(--sh-${k})"></span>`).join('');
    if (!this.summaryBound) {
      $('sumrow').addEventListener('click', (e) => {
        const m = e.target.closest('.sh-metric[data-k]');
        if (!m) return;
        $('fst').value = State.status === m.dataset.k ? 'all' : m.dataset.k;
        UI.sync();
      });
      this.summaryBound = true;
    }
  },
  sync() {
    State.q = $('q').value;
    State.os = $('fos').value;
    State.status = $('fst').value;
    if (State.osGroup && State.os !== 'all' && State.os !== State.osGroup.family) {
      State.osGroup = null;
    }
    const resort = State.sort !== $('fsort').value;
    State.sort = $('fsort').value;
    State.page = 1;
    if (resort) Matrix.build();
    else Matrix.paint();
    Table.render();
    OsGroups.render();
    document.querySelectorAll('.sh-metric[data-k]').forEach((m) => {
      m.classList.toggle('on', m.dataset.k === State.status);
    });
    $('reset').classList.toggle('hidden', !Filter.isActive());
  },
  count(n, active) {
    $('count').textContent = active
      ? `Showing ${n} of ${State.servers.length} servers`
      : `${State.servers.length} server${State.servers.length === 1 ? '' : 's'}`;
  },
  controls() {
    ['q', 'fos', 'fst', 'fsort'].forEach((id) => {
      $(id).addEventListener(id === 'q' ? 'input' : 'change', () => UI.sync());
    });
    $('reset').addEventListener('click', () => {
      $('q').value = '';
      $('fos').value = 'all';
      $('fst').value = 'all';
      State.osGroup = null;
      Table.clearAllColFilters();
      UI.sync();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        $('q').focus();
      }
    });
  },
};

function applyPayload(data) {
  State.plugins = data.plugins || State.plugins;
  State.lastSync = data.lastSync || null;
  State.servers = (data.servers || []).map(normalizeServer);
  State.byId = new Map(State.servers.map((s) => [s.id, s]));
  setSyncStatus(State.lastSync ? 'live' : '', fmt.relativeSync(State.lastSync));
  showWarning(data.warning || '');
  UI.summary();
  OsGroups.render();
  Matrix.build();
  UI.sync();
}

async function pollStatus() {
  try {
    const res = await fetch('/api/server-health/status', { cache: 'no-store' });
    const status = await parseApiResponse(res);
    if (status.sync_in_progress) {
      const progress = status.progress || {};
      setLoading(true, progress.message || 'Syncing…');
      if (!pollTimer) pollTimer = setInterval(pollStatus, POLL_MS);
      return;
    }
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
      await loadData({ quiet: true });
    }
    setLoading(false);
  } catch (err) {
    console.warn('Server health status poll failed:', err);
  }
}

async function loadData({ refresh = false, quiet = false } = {}) {
  hideError();
  if (!quiet) setLoading(true, refresh ? 'Exporting last-reboot plugins from Tenable…' : 'Loading server health…');
  try {
    const url = refresh ? '/api/server-health?refresh=1' : '/api/server-health';
    const res = await fetch(url, { cache: 'no-store' });
    const data = await parseApiResponse(res);
    if (res.status === 409 || data.sync_in_progress) {
      setLoading(true, data.progress?.message || 'Sync already in progress…');
      if (!pollTimer) pollTimer = setInterval(pollStatus, POLL_MS);
      return;
    }
    if (!res.ok) throw new Error(data.error || data.detail || 'Failed to load server health');
    applyPayload(data);
    if (data.sync_in_progress) {
      setLoading(true, data.progress?.message || 'Syncing…');
      if (!pollTimer) pollTimer = setInterval(pollStatus, POLL_MS);
    } else {
      setLoading(false);
    }
  } catch (err) {
    setLoading(false);
    if (!quiet) showError(err.message || 'Failed to load server health');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  UI.controls();
  Tooltip.init();
  Drawer.init();
  Table.init();
  OsGroups.init();
  $('refresh-btn').addEventListener('click', () => loadData({ refresh: true }));
  loadData().then(() => pollStatus());
  setInterval(() => {
    if (State.lastSync && !pollTimer) {
      setSyncStatus('live', fmt.relativeSync(State.lastSync));
    }
  }, 30000);
});
