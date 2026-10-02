<script>
  import Card from '../shared/Card.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import GrantEmptyState from '../admin/GrantEmptyState.svelte';
  import {
    nodeState,
    loadingState,
    errorState,
    ledgerState,
    administeredNode,
    adminCapabilities,
    targetEpoch,
  } from '../../lib/stores.svelte.js';
  import { getAccounts } from '../../lib/api.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

  let loaded = $state(false);
  let view = administeredNode;
  let canQuery = $derived(adminCapabilities.canQueryNode);

  $effect(() => {
    void targetEpoch.value;
    if (!canQuery) return;
    void loadData();
  });

  async function loadData() {
    loadingState.accounts = true;
    errorState.accounts = null;
    try {
      const rows = await getAccounts();
      nodeState.accounts = rows;
      nodeState.accountsTruncated = Array.isArray(rows) ? Boolean(rows.truncated) : false;
      loaded = true;
    } catch (err) {
      errorState.accounts = err?.message || 'Failed to load accounts';
    } finally {
      loadingState.accounts = false;
    }
  }

  const columns = [
    { key: 'label', label: 'Account' },
    { key: 'type', label: 'Type',
      render: (v) => {
        const colors = { asset: 'var(--accent)', liability: 'var(--warn)', equity: 'var(--muted)' };
        const bgs = { asset: 'var(--accent-dim)', liability: 'var(--warn-dim)', equity: 'var(--bg-hover)' };
        return `<span style="display:inline-flex;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${bgs[v] || 'var(--bg-hover)'};color:${colors[v] || 'var(--muted)'}">${v}</span>`;
      }
    },
    { key: 'balance', label: 'Balance', align: 'right', mono: true,
      render: (v) => `<span style="font-family:var(--mono);font-weight:600;color:${v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)'}">${v != null ? (v > 0 ? '+' : '') + v.toLocaleString() : '\u2014'}</span>` },
  ];

  let totalAssets = $derived(
    nodeState.accounts
      .filter((a) => a.type === 'asset')
      .reduce((sum, a) => sum + a.balance, 0),
  );
  let totalLiability = $derived(
    nodeState.accounts
      .filter((a) => a.type === 'liability')
      .reduce((sum, a) => sum + a.balance, 0),
  );
  // Equity is a row when the node publishes one, otherwise assets − liabilities
  // (the same derivation the mock data applies), so the equation is honest in
  // both modes.
  let equity = $derived(
    nodeState.accounts.find((a) => a.type === 'equity')?.balance ??
      totalAssets - totalLiability,
  );
  let hasRows = $derived(nodeState.accounts.length > 0);
  let balanceReady = $derived(ledgerState.balance != null);
  let truncated = $derived(Boolean(nodeState.accountsTruncated));

  let emptyMessage = $derived.by(() => {
    if (view.isSelf) {
      return 'Your verified balance will appear here once a receipt arrives from your leaf process.';
    }
    if (!adminCapabilities.scopes.value) {
      return 'Reading an administered node\u2019s balances needs a value-scoped grant. This browser holds a joins-only or topology-only grant.';
    }
    return 'This node reported no accounts yet.';
  });
</script>

<div class="accounts-page">
  <Card title="Balance">
    {#snippet actions()}
      <button
        type="button"
        class="btn btn--ghost btn--sm"
        onclick={loadData}
        disabled={loadingState.accounts}
      >
        {loadingState.accounts ? 'Loading…' : 'Refresh'}
      </button>
    {/snippet}

    {#if !canQuery}
      <GrantEmptyState
        title="Account data needs a delegated admin key"
        message="This browser cannot query the selected node yet. Generate an admin key in Settings and ask the operator to grant it."
      />
    {:else if loadingState.accounts && !loaded}
      <LoadingSkeleton rows={2} />
    {:else if errorState.accounts}
      <ErrorState message={errorState.accounts} onRetry={loadData} />
    {:else if balanceReady}
      <div class="my-account">
        <div class="account-balance">
          <Balance amount={ledgerState.balance} size="lg" showSign={false} />
        </div>
        <p class="account-note text-sm muted">
          Your verified balance from the leaf process, updated when a balance receipt arrives.
        </p>
        <div class="account-meta">
          <Badge variant="ok" label="Verified" />
          {#if ledgerState.height != null}
            <span class="text-sm muted">Height {ledgerState.height}</span>
          {/if}
        </div>
        <button type="button" class="link-btn" onclick={() => navigate(ROUTES.MY_ACCOUNT)}>
          Go to My Account to send payments
        </button>
      </div>
    {:else if hasRows}
      <div class="my-account">
        <div class="account-balance">
          <Balance amount={equity} size="lg" showSign={false} />
        </div>
        <p class="account-note text-sm muted">
          Node equity (assets &minus; liabilities) from this node's accounting snapshot.
        </p>
      </div>
    {:else}
      <EmptyState title="No account data yet" message={emptyMessage} />
    {/if}
  </Card>

  <Card title="Accounting Equation">
    {#if hasRows}
      <div class="equation">
        <div class="eq-item">
          <span class="eq-label muted">Assets</span>
          <Balance amount={totalAssets} size="lg" />
        </div>
        <span class="eq-op muted">&minus;</span>
        <div class="eq-item">
          <span class="eq-label muted">Liabilities</span>
          <Balance amount={totalLiability} size="lg" />
        </div>
        <span class="eq-op muted">=</span>
        <div class="eq-item">
          <span class="eq-label muted">Equity</span>
          <Balance amount={equity} size="lg" />
        </div>
      </div>
    {:else}
      <p class="text-sm muted">
        The node accounting equation (assets &minus; liabilities = equity) applies to node
        operators. As a leaf user your balance comes from your parent node and is shown above.
      </p>
    {/if}
  </Card>

  <Card title="All Accounts">
    {#if !canQuery}
      <p class="text-sm muted">No rows to show for this selection.</p>
    {:else if loadingState.accounts && !loaded}
      <LoadingSkeleton rows={3} />
    {:else if errorState.accounts}
      <ErrorState message="Failed to load accounts" onRetry={loadData} />
    {:else if !hasRows}
      <EmptyState title="No accounts" message={emptyMessage} />
    {:else}
      <DataTable {columns} rows={nodeState.accounts} />
      {#if truncated}
        <div class="truncated-note">
          <Badge variant="warn" label="Truncated" />
          <span class="text-xs muted">
            This node&rsquo;s account list exceeded its display limit and was shortened.
            The totals above still cover every balance.
          </span>
        </div>
      {/if}
    {/if}
  </Card>
</div>

<style>
  .accounts-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }

  .my-account {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .account-balance {
    display: flex;
    align-items: baseline;
    gap: var(--sp-2);
  }
  .account-note {
    line-height: var(--leading-normal);
  }
  .account-meta {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
  }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
    text-align: left;
    align-self: flex-start;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  .equation {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    flex-wrap: wrap;
  }
  .eq-item {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .eq-label {
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .eq-op {
    font-size: var(--text-2xl);
    font-weight: 300;
    line-height: 1;
  }

  .truncated-note {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
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
