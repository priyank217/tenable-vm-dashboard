/** Tags Management — categories & values from /api/tags */

const state = {
  categories: [],
  filteredCategories: [],
  selectedIndex: 0,
  editingUuid: null,
  loading: false,
};

const $ = (id) => document.getElementById(id);

function fmt(n) {
  if (n == null || Number.isNaN(n)) return '—';
  return Number(n).toLocaleString();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text ?? '';
  return div.innerHTML;
}

function typeLabel(type) {
  return type === 'dynamic' ? 'Dynamic' : 'Static';
}

function groupCategoriesFromTags(tags) {
  const groups = new Map();
  for (const tag of tags) {
    const category = tag.key || tag.category || 'Uncategorized';
    if (!groups.has(category)) {
      groups.set(category, {
        category,
        categoryUuid: tag.categoryUuid || '',
        values: [],
        assetCount: 0,
        staticCount: 0,
        dynamicCount: 0,
        typeLabel: 'Static',
      });
    }
    const group = groups.get(category);
    group.values.push(tag);
    if (tag.type === 'dynamic') group.dynamicCount += 1;
    else group.staticCount += 1;
  }

  return [...groups.values()]
    .map((group) => {
      if (group.dynamicCount > 0 && group.staticCount > 0) group.typeLabel = 'Mixed';
      else if (group.dynamicCount > 0) group.typeLabel = 'Dynamic';
      else group.typeLabel = 'Static';
      group.values.sort((a, b) => (a.value || '').localeCompare(b.value || ''));
      return group;
    })
    .sort((a, b) => a.category.localeCompare(b.category));
}

function normalizeApiPayload(data) {
  let categories = Array.isArray(data.categories) ? data.categories : [];
  const tags = Array.isArray(data.tags) ? data.tags : [];

  if (!categories.length && tags.length) {
    categories = groupCategoriesFromTags(tags);
  }

  categories = categories.map((cat) => {
    const values = Array.isArray(cat.values) ? cat.values : [];
    let assetCount = cat.assetCount ?? 0;
    if (!assetCount && values.length) {
      assetCount = Math.max(0, ...values.map((v) => v.assets || 0));
    }
    return {
      ...cat,
      category: cat.category || cat.key || 'Uncategorized',
      values,
      assetCount,
    };
  });

  const stats = data.stats || {};
  return {
    categories,
    tags,
    stats: {
      categoryCount: stats.categoryCount ?? data.categoryCount ?? categories.length,
      tagValueCount: stats.tagValueCount ?? data.count ?? tags.length,
      taggedAssetCount: stats.taggedAssetCount ?? 0,
      totalAssetCount: stats.totalAssetCount ?? 0,
    },
    lastSync: data.lastSync,
    cached: data.cached,
    warning: data.warning,
  };
}

function showError(message) {
  $('error-text').textContent = message;
  $('error-banner').classList.remove('hidden');
}

function hideError() {
  $('error-banner').classList.add('hidden');
}

function setLoading(loading) {
  state.loading = loading;
  $('loading-banner').classList.toggle('hidden', !loading);
  $('refresh-tags-btn').disabled = loading;
  $('refresh-tags-icon').classList.toggle('spinner', loading);
  $('add-category-btn').disabled = loading;
  $('add-value-btn').disabled = loading || !getSelectedCategoryData();
}

function updateSyncStatus(lastSync, cached) {
  const dot = $('status-dot');
  const label = $('last-sync');
  if (!lastSync) {
    dot.className = 'status-dot';
    label.textContent = 'Last sync: Never';
    return;
  }
  dot.className = `status-dot ${cached ? 'cached' : 'live'}`;
  const when = new Date(lastSync);
  const suffix = cached ? ' (cached)' : '';
  label.textContent = `Last sync: ${when.toLocaleString()}${suffix}`;
}

function updateKpis(stats) {
  $('kpi-categories').textContent = fmt(stats.categoryCount);
  $('kpi-tag-values').textContent = fmt(stats.tagValueCount);
  $('kpi-tagged-assets').textContent = fmt(stats.taggedAssetCount);
  const total = stats.totalAssetCount ?? 0;
  $('kpi-total-assets').textContent = total
    ? `of ${fmt(total)} total inventory`
    : 'open Asset Inventory for counts';
  $('cat-panel-meta').textContent = `${fmt(stats.categoryCount)} total`;
}

function updateCategoryDatalist(categories) {
  const datalist = $('tag-category-datalist');
  if (!datalist) return;
  datalist.innerHTML = categories
    .map((c) => `<option value="${escapeHtml(c.category)}">`)
    .join('');
}

function getFilteredCategories() {
  const q = ($('cat-search')?.value || '').trim().toLowerCase();
  if (!q) return state.categories;
  return state.categories.filter((c) => c.category.toLowerCase().includes(q));
}

function renderCategoryList() {
  const list = $('cat-list');
  if (!list) return;

  state.filteredCategories = getFilteredCategories();

  if (!state.filteredCategories.length) {
    list.innerHTML = '<div class="cat-empty">No categories found.</div>';
    $('cat-panel-meta').textContent = '0 total';
    return;
  }

  if (state.selectedIndex >= state.filteredCategories.length) {
    state.selectedIndex = 0;
  }

  list.innerHTML = state.filteredCategories.map((cat, idx) => {
    const active = state.selectedIndex === idx ? ' active' : '';
    const valueCount = (cat.values || []).length;
    const valueLabel = `${valueCount} value${valueCount === 1 ? '' : 's'}`;
    return `
      <button type="button" class="cat${active}" data-idx="${idx}">
        <div class="cat-top">
          <span class="cat-name">${escapeHtml(cat.category)}</span>
          <span class="cat-badge">${valueLabel}</span>
        </div>
        <div class="cat-meta">${fmt(cat.assetCount)} assets · ${escapeHtml(cat.typeLabel || 'Static')}</div>
      </button>
    `;
  }).join('');

  $('cat-panel-meta').textContent = `${state.filteredCategories.length} shown`;
}

function getSelectedCategoryData() {
  return state.filteredCategories[state.selectedIndex] || null;
}

function getFilteredValues(category) {
  if (!category) return [];
  const type = $('filter-type')?.value || '';
  return (category.values || []).filter((v) => !type || v.type === type);
}

function renderValuesTable() {
  const category = getSelectedCategoryData();
  const tbody = $('tag-values-tbody');
  const addBtn = $('add-value-btn');
  if (!tbody) return;

  if (!category) {
    $('panel-title').textContent = 'Select a category';
    if (addBtn) addBtn.disabled = true;
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>Select a category to view its tag values.</p></div></td></tr>';
    $('values-page-info').textContent = 'Showing 0 of 0 values';
    return;
  }

  $('panel-title').textContent = `${category.category} values`;
  if (addBtn) addBtn.disabled = state.loading;

  const values = getFilteredValues(category);
  if (!values.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>No values match your filters.</p></div></td></tr>';
    $('values-page-info').textContent = `Showing 0 of ${(category.values || []).length} values`;
    return;
  }

  tbody.innerHTML = values.map((tag) => {
    const isDynamic = tag.type === 'dynamic';
    const editDisabled = isDynamic ? ' disabled title="Dynamic tags are rule-based in Tenable"' : '';
    return `
      <tr>
        <td><span class="cell-name">${escapeHtml(tag.value)}</span></td>
        <td><span class="asset-num">${fmt(tag.assets)}</span></td>
        <td><span class="badge badge-${isDynamic ? 'dynamic' : 'static'}">${typeLabel(tag.type)}</span></td>
        <td><span class="badge-active"><span class="badge-dot"></span>Active</span></td>
        <td>
          <div class="row-acts">
            <button class="icon-btn" aria-label="Edit" data-edit="${escapeHtml(tag.uuid)}"${editDisabled}>
              <i class="ti ti-edit"></i>
            </button>
            <button class="icon-btn danger" aria-label="Delete" data-delete="${escapeHtml(tag.uuid)}"${isDynamic ? ' disabled' : ''}>
              <i class="ti ti-trash"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  $('values-page-info').textContent = `Showing ${values.length} of ${(category.values || []).length} values`;
}

function selectCategory(index) {
  state.selectedIndex = index;
  renderCategoryList();
  renderValuesTable();
}

async function loadTags(forceRefresh = false) {
  hideError();
  setLoading(true);
  try {
    const url = forceRefresh ? '/api/tags?refresh=1' : '/api/tags';
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load tags');

    const payload = normalizeApiPayload(data);
    state.categories = payload.categories;
    state.selectedIndex = 0;

    updateKpis(payload.stats);
    updateCategoryDatalist(state.categories);
    updateSyncStatus(payload.lastSync, payload.cached);
    renderCategoryList();
    renderValuesTable();

    if (payload.warning) showError(payload.warning);
  } catch (err) {
    showError(err.message);
    const list = $('cat-list');
    if (list) {
      list.innerHTML = `<div class="cat-empty">Failed to load categories.<br>${escapeHtml(err.message)}</div>`;
    }
    const tbody = $('tag-values-tbody');
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>Failed to load tag values.</p></div></td></tr>';
    }
  } finally {
    setLoading(false);
  }
}

function openModal(tag = null, categoryName = '') {
  state.editingUuid = tag?.uuid || null;
  const isEdit = Boolean(tag);
  const isAddToCategory = !isEdit && Boolean(categoryName);

  $('tag-modal-title').textContent = isEdit
    ? 'Edit Tag Value'
    : isAddToCategory
      ? `Add Value to ${categoryName}`
      : 'Create Category & Value';
  $('tag-modal-subtitle').textContent = isEdit
    ? 'Update the tag value name.'
    : 'Pick an existing category or type a new name to create one.';
  $('tag-category').value = tag?.key || categoryName || '';
  $('tag-category').disabled = isEdit || isAddToCategory;
  $('tag-value').value = tag?.value || '';
  $('tag-modal').classList.remove('hidden');
  if (!isEdit) $('tag-value').focus();
}

function closeModal() {
  state.editingUuid = null;
  $('tag-category').disabled = false;
  $('tag-modal').classList.add('hidden');
}

async function saveTag() {
  const category = $('tag-category').value.trim();
  const value = $('tag-value').value.trim();
  if (!category || !value) {
    showError('Category and value are required.');
    return;
  }

  hideError();
  setLoading(true);
  try {
    const url = state.editingUuid ? `/api/tags/${state.editingUuid}` : '/api/tags';
    const method = state.editingUuid ? 'PUT' : 'POST';
    const body = state.editingUuid ? { value } : { category, value };

    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to save tag');

    closeModal();
    await loadTags(true);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

async function deleteTag(uuid) {
  if (!window.confirm('Delete this tag value? It will be removed from all assigned assets.')) return;

  hideError();
  setLoading(true);
  try {
    const res = await fetch(`/api/tags/${uuid}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to delete tag');
    await loadTags(true);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

$('cat-search')?.addEventListener('input', () => {
  state.selectedIndex = 0;
  renderCategoryList();
  renderValuesTable();
});

$('filter-type')?.addEventListener('change', renderValuesTable);

$('cat-list')?.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-idx]');
  if (btn) selectCategory(Number(btn.dataset.idx));
});

$('tag-values-tbody')?.addEventListener('click', (e) => {
  const editBtn = e.target.closest('[data-edit]');
  const deleteBtn = e.target.closest('[data-delete]');
  if (editBtn && !editBtn.disabled) {
    const category = getSelectedCategoryData();
    const tag = category?.values.find((t) => t.uuid === editBtn.dataset.edit);
    if (tag) openModal(tag);
  }
  if (deleteBtn && !deleteBtn.disabled) {
    deleteTag(deleteBtn.dataset.delete);
  }
});

$('add-category-btn')?.addEventListener('click', () => openModal());
$('add-value-btn')?.addEventListener('click', () => {
  const category = getSelectedCategoryData();
  if (category) openModal(null, category.category);
});
$('refresh-tags-btn')?.addEventListener('click', () => loadTags(true));
$('modal-cancel')?.addEventListener('click', closeModal);
$('modal-save')?.addEventListener('click', saveTag);
$('tag-modal')?.addEventListener('click', (e) => {
  if (e.target === $('tag-modal')) closeModal();
});

loadTags();
