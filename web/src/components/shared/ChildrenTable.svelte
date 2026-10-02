<script>
  import DataTable from './DataTable.svelte';
  import EmptyState from './EmptyState.svelte';
  import { formatDate } from '../../lib/utils.js';
  import { childRoleLabel } from '../../lib/nodeKind.js';

  /**
   * ChildrenTable — the single children table shared by every admin page.
   *
   * One column set for both node kinds: a row is a `node` child (child node)
   * or a `user` child (user account), labelled from the row's `kind` rather
   * than from a page-level branch. `balance` renders as an em dash when the
   * source has no ledger data (P1 never fabricates balances) and `status`
   * renders "Unknown" when the source carries no liveness.
   *
   * @param {Array} rows
   * @param {string} [emptyTitle]
   * @param {string} [emptyMessage]
   * @param {string} [actionLabel]
   * @param {function} [onAction]
   * @param {string|null} [selectedId] child `endpointId` to highlight
   * @param {function} [onSelect] called with the clicked row (for an actions panel)
   */
  let {
    rows = [],
    emptyTitle = 'No children yet',
    emptyMessage = 'This node has no children in its topology snapshot.',
    actionLabel = '',
    onAction = undefined,
    selectedId = null,
    onSelect = undefined,
  } = $props();

  function handleRowClick(row) {
    onSelect?.(row);
  }

  let sortKey = $state('address');
  let sortDir = $state('asc');

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function statusLabel(online) {
    if (online === true) return 'Online';
    if (online === false) return 'Offline';
    return 'Unknown';
  }

  function statusStyle(online) {
    if (online === true) return 'color:var(--ok);background:var(--ok-dim)';
    if (online === false) return 'color:var(--muted);background:var(--bg-hover)';
    return 'color:var(--muted);background:var(--bg-hover)';
  }

  const columns = [
    {
      key: 'address',
      label: 'Address',
      mono: true,
      sortable: true,
      render: (v) => (v ? `<span class="mono">${esc(v)}</span>` : '<span class="muted">&mdash;</span>'),
    },
    {
      key: 'kind',
      label: 'Role',
      sortable: true,
      render: (v) => `<span class="muted text-sm">${esc(childRoleLabel(v))}</span>`,
    },
    {
      key: 'balance',
      label: 'Balance',
      align: 'right',
      mono: true,
      sortable: true,
      render: (v) => {
        if (v == null) return '<span class="muted">&mdash;</span>';
        const color = v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)';
        return `<span style="color:${color}">${v.toLocaleString()}</span>`;
      },
    },
    {
      key: 'seniority',
      label: 'Joined',
      sortable: true,
      render: (v) => `<span class="text-sm">${v ? esc(formatDate(v)) : '&mdash;'}</span>`,
    },
    { key: 'slot', label: 'Slot', align: 'right', sortable: true },
    {
      key: 'online',
      label: 'Status',
      sortable: true,
      render: (v) =>
        `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;${statusStyle(v)}">${statusLabel(v)}</span>`,
    },
  ];

  function compare(a, b, key) {
    const av = a[key];
    const bv = b[key];
    // Unknown/null sorts last in either direction.
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (typeof av === 'number' && typeof bv === 'number') return av - bv;
    return String(av).localeCompare(String(bv));
  }

  let sorted = $derived(
    [...rows].sort((a, b) => {
      const cmp = compare(a, b, sortKey);
      return sortDir === 'asc' ? cmp : -cmp;
    }),
  );

  function handleSort(key, dir) {
    sortKey = key;
    sortDir = dir;
  }
</script>

{#if rows.length === 0}
  <EmptyState title={emptyTitle} message={emptyMessage} {actionLabel} {onAction} />
{:else}
  <DataTable
    {columns}
    rows={sorted}
    {sortKey}
    {sortDir}
    onSort={handleSort}
    {selectedId}
    onRowClick={onSelect ? handleRowClick : undefined}
  />
{/if}
