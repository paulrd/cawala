<script>
  import Card from '../shared/Card.svelte';
  import Badge from '../shared/Badge.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import Address from '../shared/Address.svelte';
  import Balance from '../shared/Balance.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import { nodeState, loadingState, errorState } from '../../lib/stores.js';
  import { getActivityLog } from '../../lib/api.js';
  import { ACTIVITY_LABELS } from '../../lib/constants.js';
  import { formatDate } from '../../lib/utils.js';

  let loaded = $state(false);
  let filterType = $state('');

  $effect(() => {
    if (!loaded) loadData();
  });

  async function loadData() {
    loadingState.activity = true;
    try {
      nodeState.activity = await getActivityLog(filterType ? { type: filterType } : undefined);
      loaded = true;
    } catch (err) {
      errorState.activity = err.message;
    } finally {
      loadingState.activity = false;
    }
  }

  function handleFilter() {
    loaded = false;
    loadData();
  }

  const typeBadgeVariant = {
    transfer: 'info',
    issue: 'ok',
    burn: 'danger',
    join_approved: 'ok',
    join_rejected: 'danger',
    topo_create: 'info',
    topo_move: 'warn',
    topo_detach: 'danger',
  };

  const columns = [
    { key: 'type', label: 'Type',
      render: (v) => {
        const variant = typeBadgeVariant[v] || 'muted';
        const label = ACTIVITY_LABELS[v] || v;
        const colors = { ok: 'var(--ok)', danger: 'var(--danger)', warn: 'var(--warn)', info: 'var(--accent)', muted: 'var(--muted)' };
        const bgs = { ok: 'var(--ok-dim)', danger: 'var(--danger-dim)', warn: 'var(--warn-dim)', info: 'var(--accent-dim)', muted: 'var(--bg-hover)' };
        return `<span style="display:inline-flex;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${bgs[variant]};color:${colors[variant]}">${label}</span>`;
      }
    },
    { key: 'from', label: 'From', mono: true,
      render: (v) => v
        ? `<span style="font-family:var(--mono);font-size:0.875rem">${v}</span>`
        : '<span style="color:var(--muted);font-size:0.75rem">system</span>' },
    { key: 'to', label: 'To', mono: true,
      render: (v) => `<span style="font-family:var(--mono);font-size:0.875rem">${v}</span>` },
    { key: 'amount', label: 'Amount', align: 'right', mono: true,
      render: (v) => v != null
        ? `<span style="font-family:var(--mono);font-weight:600;color:${v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)'}">${v > 0 ? '+' : ''}${v.toLocaleString()}</span>`
        : '<span style="color:var(--muted);font-size:0.75rem">\u2014</span>' },
    { key: 'timestamp', label: 'Time',
      render: (v) => `<span class="text-sm">${formatDate(v)}</span>` },
  ];
</script>

<div class="activity-page">
  <Card title="Activity Log">
    <div class="toolbar">
      <select bind:value={filterType} onchange={handleFilter} aria-label="Filter by type">
        <option value="">All types</option>
        <option value="transfer">Transfers</option>
        <option value="issue">Issues</option>
        <option value="burn">Burns</option>
        <option value="join_approved">Join Approved</option>
        <option value="topo_create">Child Created</option>
        <option value="topo_move">Child Moved</option>
        <option value="topo_detach">Child Detached</option>
      </select>
    </div>

    {#if loadingState.activity && !loaded}
      <LoadingSkeleton rows={5} />
    {:else if errorState.activity}
      <ErrorState message="Failed to load activity" onRetry={loadData} />
    {:else if nodeState.activity.length === 0}
      <EmptyState title="No activity yet" message="Activity will appear here as operations are performed." />
    {:else}
      <DataTable columns={columns} rows={nodeState.activity} />
    {/if}
  </Card>
</div>

<style>
  .activity-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    margin-bottom: var(--sp-4);
  }
  select {
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font: inherit;
    font-size: var(--text-sm);
  }
</style>
