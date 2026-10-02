<script>
  import Card from '../shared/Card.svelte';
  import Badge from '../shared/Badge.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import GrantEmptyState from '../admin/GrantEmptyState.svelte';
  import {
    nodeState,
    loadingState,
    errorState,
    ledgerState,
    apiCapabilities,
    administeredNode,
    adminCapabilities,
    targetEpoch,
  } from '../../lib/stores.svelte.js';
  import { getActivityLog } from '../../lib/api.js';
  import { ACTIVITY_TYPES, ACTIVITY_LABELS, ORDER_STATUS_LABELS, ORDER_STATUS_DESCRIPTIONS } from '../../lib/constants.js';
  import { formatDate } from '../../lib/utils.js';

  let loaded = $state(false);
  let filterType = $state('');
  let view = administeredNode;
  let canQuery = $derived(adminCapabilities.canQueryNode);

  $effect(() => {
    void targetEpoch.value;
    // The ledger poller appends entries in live mode: refetch so the table
    // stays current instead of only updating on a manual refresh.
    void ledgerState.activity.length;
    if (!canQuery) return;
    void loadData();
  });

  async function loadData() {
    loadingState.activity = true;
    errorState.activity = null;
    try {
      nodeState.activity = await getActivityLog(filterType ? { type: filterType } : undefined);
      loaded = true;
    } catch (err) {
      errorState.activity = err?.message || 'Failed to load activity';
    } finally {
      loadingState.activity = false;
    }
  }

  function handleFilter() {
    loaded = false;
    loadData();
  }

  // One row shape for both sources (mock log and leaf-reported history), so
  // the table never branches on mode.
  let rows = $derived(
    nodeState.activity
      .map((entry) => ({
        ...entry,
        label: ACTIVITY_LABELS[entry.type] || entry.type,
        status: entry.status ?? null,
        reason: entry.reason ?? null,
        orderHash: entry.orderHash ?? null,
      }))
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
  );

  let emptyMessage = $derived(
    view.isSelf
      ? 'Your outbound payments will appear here once they are confirmed.'
      : "This node's own activity log is not shared with delegated keys, and this browser's payments are never listed under another node's name.",
  );

  const typeBadgeVariant = {
    transfer: 'info',
    settlement: 'info',
    issue: 'ok',
    burn: 'danger',
    join_approved: 'ok',
    join_rejected: 'danger',
    topo_create: 'info',
    topo_move: 'warn',
    topo_detach: 'danger',
    balance_update: 'ok',
  };

  const settlementStatusVariant = {
    applied: 'ok',
    duplicate: 'ok',
    partial: 'warn',
    indeterminate: 'warn',
    unverified: 'warn',
    rejected: 'danger',
  };
</script>

<div class="activity-page">
  <Card title="Activity Log">
    {#snippet actions()}
      <button
        type="button"
        class="btn btn--ghost btn--sm"
        onclick={() => { loaded = false; loadData(); }}
        disabled={loadingState.activity || !canQuery}
      >
        {loadingState.activity ? 'Loading…' : 'Refresh'}
      </button>
    {/snippet}

    <div class="toolbar">
      <select bind:value={filterType} onchange={handleFilter} aria-label="Filter by type" disabled={!canQuery}>
        <option value="">All types</option>
        <option value="transfer">Transfers</option>
        <option value="issue">Issues</option>
        <option value="burn">Burns</option>
        <option value="join_approved">Join Approved</option>
        <option value="topo_create">Child Created</option>
        <option value="topo_move">Child Moved</option>
        <option value="topo_detach">Child Detached</option>
      </select>
      {#if view.isSelf}
        <span class="text-sm muted">
          Only payments sent from this browser are listed. Incoming value updates your balance but
          is not shown as a separate row.
        </span>
      {/if}
    </div>

    {#if !canQuery}
      <GrantEmptyState
        title="Activity needs a delegated admin key"
        message="This browser cannot query the selected node yet. Generate an admin key in Settings and ask the operator to grant it."
      />
    {:else if loadingState.activity && !loaded}
      <LoadingSkeleton rows={5} />
    {:else if errorState.activity}
      <ErrorState message={errorState.activity} onRetry={loadData} />
    {:else if rows.length === 0}
      <EmptyState title="No activity yet" message={emptyMessage} />
    {:else}
      <div class="activity-table">
        {#each rows as entry (entry.id)}
          <div class="activity-row">
            <div class="activity-cell activity-cell--type">
              <Badge variant={typeBadgeVariant[entry.type] || 'muted'} label={entry.label} />
              {#if entry.status}
                <span title={ORDER_STATUS_DESCRIPTIONS[entry.status] || ''}>
                  <Badge
                    variant={settlementStatusVariant[entry.status] || 'muted'}
                    label={ORDER_STATUS_LABELS[entry.status] || entry.status}
                  />
                </span>
              {/if}
            </div>
            <div class="activity-cell activity-cell--from">
              {#if entry.from}
                <span class="mono-text text-sm">{entry.from}</span>
              {:else}
                <span class="text-xs muted">system</span>
              {/if}
            </div>
            <div class="activity-cell activity-cell--to">
              <span class="mono-text text-sm">{entry.to ?? '\u2014'}</span>
            </div>
            <div class="activity-cell activity-cell--amount">
              {#if entry.amount != null}
                <span class="mono-text text-sm" style="font-weight:600;color:{entry.amount > 0 ? 'var(--ok)' : entry.amount < 0 ? 'var(--danger)' : 'var(--muted)'}">
                  {entry.amount > 0 ? '+' : ''}{entry.amount.toLocaleString()}
                </span>
              {:else}
                <span class="text-xs muted">&mdash;</span>
              {/if}
            </div>
            <div class="activity-cell activity-cell--time">
              <span class="text-sm">{formatDate(entry.timestamp)}</span>
            </div>
          </div>
        {/each}
      </div>
    {/if}

    {#if canQuery}
    <div class="activity-footnote">
      <Badge variant="muted" label={apiCapabilities.mock ? 'Sample data' : 'Reported by your leaf'} />
      <span class="text-xs muted">
        {apiCapabilities.mock
          ? 'Synthetic entries used while the console runs without a node.'
          : 'Activity data comes from the leaf process and is not independently attested.'}
      </span>
    </div>
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
    flex-wrap: wrap;
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
  select:disabled {
    opacity: 0.5;
  }

  .activity-table {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .activity-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-2) 0;
    border-bottom: 1px solid var(--border);
  }
  .activity-row:last-child {
    border-bottom: none;
  }
  .activity-cell {
    display: flex;
    align-items: center;
  }
  .activity-cell--type {
    flex-shrink: 0;
    min-width: 80px;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .activity-cell--from {
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }
  .activity-cell--to {
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }
  .activity-cell--amount {
    flex-shrink: 0;
    text-align: right;
    min-width: 80px;
    justify-content: flex-end;
  }
  .activity-cell--time {
    flex-shrink: 0;
    text-align: right;
    min-width: 100px;
    justify-content: flex-end;
    color: var(--muted);
  }
  .mono-text {
    font-family: var(--mono);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .activity-footnote {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding-top: var(--sp-3);
    border-top: 1px solid var(--border);
    margin-top: var(--sp-3);
    flex-wrap: wrap;
  }

  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn--ghost {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .btn--sm {
    font-size: var(--text-xs);
    padding: var(--sp-1) var(--sp-3);
  }
</style>
