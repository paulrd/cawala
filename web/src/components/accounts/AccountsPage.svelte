<script>
  import Card from '../shared/Card.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { nodeState, loadingState, errorState } from '../../lib/stores.js';
  import { getAccounts, isMockMode } from '../../lib/api.js';

  let loaded = $state(false);

  $effect(() => {
    if (!loaded) loadData();
  });

  async function loadData() {
    loadingState.accounts = true;
    try {
      nodeState.accounts = await getAccounts();
      loaded = true;
    } catch (err) {
      errorState.accounts = err.message;
    } finally {
      loadingState.accounts = false;
    }
  }

  let isLive = $derived(!isMockMode());

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
  let equity = $derived(
    nodeState.accounts.find((a) => a.type === 'equity')?.balance ?? 0,
  );
</script>

<div class="accounts-page">
  {#if isLive && nodeState.accounts.length === 0 && loaded}
    <!-- Live mode: accounts not available -->
    <Card title="Accounts">
      <div class="live-unavailable">
        <Badge variant="info" label="Live mode" />
        <p class="unavailable-desc">
          Account balances are not available in the web client yet. This node does not expose a ledger API to the browser.
        </p>
        <p class="unavailable-cli muted text-sm">
          Account data is managed by the node process. Check the node CLI for balance information.
        </p>
      </div>
    </Card>
  {:else if loadingState.accounts && !loaded}
    <LoadingSkeleton rows={3} />
  {:else if errorState.accounts}
    <ErrorState message="Failed to load accounts" onRetry={loadData} />
  {:else}
    <Card title="Accounting Equation">
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
    </Card>

    <Card title="All Accounts">
      <DataTable columns={columns} rows={nodeState.accounts} />
    </Card>
  {/if}
</div>

<style>
  .accounts-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
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
  .live-unavailable {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4) 0;
  }
  .unavailable-desc {
    font-size: var(--text-sm);
    line-height: var(--leading-normal);
  }
  .unavailable-cli {
    font-size: var(--text-sm);
  }
</style>
