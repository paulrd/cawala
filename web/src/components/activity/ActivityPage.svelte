<script>
  import Card from '../shared/Card.svelte';
  import Badge from '../shared/Badge.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import Address from '../shared/Address.svelte';
  import Balance from '../shared/Balance.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import { nodeState, loadingState, errorState, ledgerState } from '../../lib/stores.svelte.js';
  import { getActivityLog, isMockMode } from '../../lib/api.js';
  import { ACTIVITY_LABELS } from '../../lib/constants.js';
  import { formatDate, formatTime } from '../../lib/utils.js';

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

  let isLive = $derived(!isMockMode());

  // ── Derived activity for live mode ────────────────────────
  // Merge the leaf-reported outbound transfers with any derived
  // balance-change entries from balance_receipt events.
  let liveActivity = $derived.by(() => {
    const rows = [];

    // Outbound transfers recorded by the ledger-event poller
    for (const entry of ledgerState.activity) {
      rows.push({
        id: entry.id,
        type: 'transfer',
        label: 'Transfer',
        from: entry.from,
        to: entry.to,
        amount: entry.amount,
        timestamp: entry.timestamp,
        reported: true,
      });
    }

    // Sort by timestamp descending (newest first)
    rows.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    return rows;
  });

  const typeBadgeVariant = {
    transfer: 'info',
    issue: 'ok',
    burn: 'danger',
    join_approved: 'ok',
    join_rejected: 'danger',
    topo_create: 'info',
    topo_move: 'warn',
    topo_detach: 'danger',
    balance_update: 'ok',
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
    {#if isLive}
      <div class="live-notice">
        <p class="text-sm muted">
          Only payments sent from this browser are listed here. Incoming value updates your balance but is not shown as a separate activity row.
        </p>
      </div>

      {#if liveActivity.length === 0}
        <EmptyState
          title="No activity yet"
          message="Your outbound payments will appear here once they are confirmed."
        />
      {:else}
        <div class="activity-table">
          {#each liveActivity as entry (entry.id)}
            <div class="activity-row">
              <div class="activity-cell activity-cell--type">
                <Badge variant={typeBadgeVariant[entry.type] || 'muted'} label={entry.label} />
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
                  <span class="text-xs muted">\u2014</span>
                {/if}
              </div>
              <div class="activity-cell activity-cell--time">
                <span class="text-sm">{formatDate(entry.timestamp)}</span>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      <div class="activity-footnote">
        <Badge variant="muted" label="Reported by your leaf" />
        <span class="text-xs muted">
          Activity data comes from the leaf process and is not independently attested.
        </span>
      </div>
    {:else}
      <!-- Mock mode: original filter + table -->
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

  /* Live activity */
  .live-notice {
    padding-bottom: var(--sp-3);
    border-bottom: 1px solid var(--border);
    margin-bottom: var(--sp-3);
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
  }
</style>
