<script>
  import Card from '../shared/Card.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { nodeState, loadingState, errorState, ledgerState } from '../../lib/stores.svelte.js';
  import { getAccounts, isMockMode } from '../../lib/api.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

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

  // ── Live mode: show the verified balance as the headline ──
  let liveAccountReady = $derived(isLive && ledgerState.balance != null);
  let liveAccountLoading = $derived(isLive && ledgerState.balance == null);

  // ── Mock mode: accounting equation ────────────────────────
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
  {#if isLive}
    <!-- ── Live mode: "My account" semantics ──────────── -->
    {#if liveAccountReady}
      <Card title="My Account">
        <div class="my-account">
          <div class="account-balance">
            <Balance amount={ledgerState.balance} size="lg" showSign={false} />
          </div>
          <p class="account-note text-sm muted">
            This is your verified balance from the leaf process. It is updated when a balance receipt arrives.
          </p>
          <div class="account-meta">
            <Badge variant="ok" label="Verified" />
            {#if ledgerState.height != null}
              <span class="text-sm muted">Height {ledgerState.height}</span>
            {/if}
          </div>
        </div>
      </Card>

      <div class="live-guidance">
        <p class="text-sm muted">
          The node accounting equation (assets &minus; liabilities = equity) applies to node operators, not leaf users. Your account balance is managed by your parent node.
        </p>
        <button
          type="button"
          class="link-btn"
          onclick={() => navigate(ROUTES.MY_ACCOUNT)}
        >
          Go to My Account to send payments
        </button>
      </div>
    {:else if liveAccountLoading}
      <Card title="My Account">
        <LoadingSkeleton rows={2} />
        <p class="text-sm muted" style="margin-top: var(--sp-3);">
          Balance not yet verified. Waiting for a receipt from your leaf.
        </p>
      </Card>
    {:else}
      <Card title="Accounts">
        <EmptyState
          title="No account data yet"
          message="Your verified balance will appear here once a receipt arrives from your leaf process."
        />
      </Card>
    {/if}

  {:else}
    <!-- ── Mock mode: original accounting-equation UI ──── -->
    {#if loadingState.accounts && !loaded}
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
  {/if}
</div>

<style>
  .accounts-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }

  /* Live mode */
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
  .live-guidance {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
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
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  /* Mock mode */
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
</style>
