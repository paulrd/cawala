<script>
  import Card from '../shared/Card.svelte';
  import StatCard from '../shared/StatCard.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import Balance from '../shared/Balance.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import ChildrenTable from '../shared/ChildrenTable.svelte';
  import {
    clientState,
    ledgerState,
    nodeState,
    loadingState,
    errorState,
    apiCapabilities,
    administeredNode,
    targetEpoch,
    showToast,
  } from '../../lib/stores.svelte.js';
  import { getChildren, getAccounts, getJoinRequests, requestBalance, getLastControlEvent } from '../../lib/api.js';
  import { ROUTES, CONTROL_EVENT } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { timeAgo } from '../../lib/utils.js';

  let loaded = $state(false);
  let view = administeredNode;

  $effect(() => {
    void targetEpoch.value;
    void loadData();
  });

  async function loadData() {
    loadingState.children = true;
    loadingState.accounts = true;
    loadingState.joinRequests = true;
    errorState.children = null;
    errorState.accounts = null;
    errorState.joinRequests = null;

    try {
      const [children, accounts, joinRequests] = await Promise.all([
        getChildren(),
        getAccounts(),
        getJoinRequests(),
      ]);
      nodeState.children = children;
      nodeState.accounts = accounts;
      nodeState.joinRequests = joinRequests;
      loaded = true;
    } catch (err) {
      errorState.children = err.message;
      errorState.accounts = err.message;
      errorState.joinRequests = err.message;
    } finally {
      loadingState.children = false;
      loadingState.accounts = false;
      loadingState.joinRequests = false;
    }
  }

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
  // Match AccountsPage: use an explicit equity row when the node publishes one,
  // else derive assets - liabilities (the no-Equity ledger model). A `?? 0`
  // fallback here would misreport a leaf's balance as 0 equity.
  let equity = $derived(
    nodeState.accounts.find((a) => a.type === 'equity')?.balance ??
      totalAssets - totalLiability,
  );
  let pendingJoins = $derived(
    nodeState.joinRequests.filter((r) => r.status === 'pending').length,
  );
  let hasAccounting = $derived(nodeState.accounts.length > 0);
  let balanceReady = $derived(ledgerState.balance != null);
  let balanceFresh = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) < 30000
  );
  let balanceStale = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) >= 30000
  );

  // Show the join CTA whenever this browser has no address yet (in mock mode
  // an address always exists, so the same condition never fires there).
  let showJoinCta = $derived(clientState.address == null);

  // Detect the "detached" event from the control drain so the Dashboard can
  // show "Left the network" instead of the generic "not connected" copy.
  let hasLeft = $state(false);
  // Interval handle must NOT be reactive: the `$effect` below reads and writes
  // it, so making it `$state` would self-invalidate the effect on every write
  // (the interval restart writes it), tripping Svelte's infinite-loop guard.
  let _detachedPoller = null;

  $effect(() => {
    if (showJoinCta) {
      _startDetachedPoller();
    } else {
      _stopDetachedPoller();
    }
    return () => _stopDetachedPoller();
  });

  function _startDetachedPoller() {
    _stopDetachedPoller();
    // Check immediately, then every 2 s.
    _checkDetached();
    _detachedPoller = setInterval(_checkDetached, 2000);
  }

  function _stopDetachedPoller() {
    if (_detachedPoller) {
      clearInterval(_detachedPoller);
      _detachedPoller = null;
    }
  }

  function _checkDetached() {
    if (hasLeft) { _stopDetachedPoller(); return; }
    const ev = getLastControlEvent();
    if (ev?.kind === CONTROL_EVENT.DETACHED) {
      hasLeft = true;
      _stopDetachedPoller();
    }
  }

  async function handleBalanceRequest() {
    await requestBalance();
    showToast('Balance refresh requested', 'info', 2000);
  }
</script>

<div class="dashboard">
  {#if !loaded && loadingState.children}
    <LoadingSkeleton rows={4} />
  {:else if errorState.children}
    <ErrorState message="Failed to load node data" onRetry={loadData} />
  {:else}
    <!-- Identity persistence warning (live mode only: nothing to lose in mock) -->
    {#if !apiCapabilities.mock && !apiCapabilities.identityPersistent}
      <div class="persistence-warning">
        <Badge variant="warn" label="Session only" />
        <span class="text-sm muted">Identity won't persist on this device. If you close this tab, your identity will be lost.</span>
      </div>
    {/if}

    {#if showJoinCta}
      <div class="join-cta">
        <div class="join-cta-body">
          {#if hasLeft}
            <h3 class="join-cta-title">Not connected to a network</h3>
            <p class="join-cta-text">You have left your previous network. You can join a new one or re-join using a fresh invitation from a node operator.</p>
          {:else}
            <h3 class="join-cta-title">Join the network</h3>
            <p class="join-cta-text">You are not connected to a node yet. Paste an invite from a node operator to join.</p>
          {/if}
          <button
            type="button"
            class="btn btn--primary"
            onclick={() => navigate(ROUTES.JOIN_FLOW)}
          >
            Go to Join
          </button>
        </div>
      </div>
    {/if}

    <!-- ── One summary grid for every target ─────────────── -->
    <div class="summary-grid">
      <StatCard title="Balance">
        {#if balanceReady}
          <Balance amount={ledgerState.balance} size="lg" showSign={false} />
        {:else if hasAccounting}
          <Balance amount={equity} size="lg" showSign={false} />
        {:else}
          <span class="muted">&mdash;</span>
        {/if}

        {#snippet meta()}
          {#if balanceReady}
            <div class="meta-row">
              {#if balanceFresh}
                <Badge variant="ok" label="Verified" />
              {:else if balanceStale}
                <Badge variant="warn" label="Stale — re-verifying" />
              {/if}
              {#if ledgerState.height != null}
                <span class="text-sm muted">Height {ledgerState.height}</span>
              {/if}
            </div>
            {#if ledgerState.verifiedAt}
              <span class="text-xs muted">Last verified: {timeAgo(new Date(ledgerState.verifiedAt))}</span>
            {/if}
            <button type="button" class="btn btn--ghost btn--sm" onclick={handleBalanceRequest}>
              Refresh balance
            </button>
          {:else if hasAccounting}
            <span class="text-sm muted">Node equity (assets &minus; liabilities)</span>
          {:else if apiCapabilities.mock}
            <span class="text-sm muted">Mock mode keeps no ledger balance.</span>
          {:else}
            <span class="text-sm muted">Balance not yet verified. Waiting for a receipt from your leaf.</span>
            <button type="button" class="btn btn--ghost btn--sm" onclick={handleBalanceRequest}>
              Request balance
            </button>
          {/if}
        {/snippet}
      </StatCard>

      <StatCard title="Address">
        <Address address={clientState.address} size="lg" />

        {#snippet meta()}
          <EndpointId id={clientState.endpointId} />
        {/snippet}
      </StatCard>

      <StatCard title="Pending">
        <span class="children-count">{ledgerState.pending}</span>

        {#snippet meta()}
          <span class="text-sm muted">
            {#if ledgerState.pending > 0}
              Orders awaiting confirmation
            {:else}
              No pending orders
            {/if}
          </span>
        {/snippet}
      </StatCard>

      <StatCard title="Children">
        <span class="children-count">{nodeState.children.length}<span class="children-max">/8</span></span>

        {#snippet meta()}
          {#if pendingJoins > 0}
            <button type="button" class="link-btn" onclick={() => navigate(ROUTES.ADMIN)}>
              {pendingJoins} pending join{pendingJoins !== 1 ? 's' : ''}
            </button>
          {:else}
            <span class="text-sm muted">No pending joins</span>
          {/if}
        {/snippet}
      </StatCard>
    </div>

    <!-- Quick actions -->
    <div class="quick-actions">
      <button
        type="button"
        class="btn btn--primary"
        onclick={() => navigate(ROUTES.MY_ACCOUNT)}
      >
        Go to My Account
      </button>
      <button
        type="button"
        class="btn btn--ghost"
        onclick={() => navigate(ROUTES.ACTIVITY)}
      >
        View Activity
      </button>
    </div>

    <Card title="Children">
      {#snippet actions()}
        <button
          type="button"
          class="btn btn--ghost btn--sm"
          onclick={loadData}
          disabled={loadingState.children}
        >
          {loadingState.children ? 'Loading…' : 'Refresh'}
        </button>
      {/snippet}
      <ChildrenTable
        rows={nodeState.children}
        emptyTitle="No children yet"
        emptyMessage={view.isSelf
          ? 'This node has no children in its local topology snapshot.'
          : 'The administered node reports no children in its topology snapshot.'}
        actionLabel={view.isSelf ? 'View Join Requests' : ''}
        onAction={view.isSelf ? () => navigate(ROUTES.ADMIN) : undefined}
      />
    </Card>

    <!-- Node accounting: real figures when the node shares them, honest text otherwise -->
    <Card title="Node Accounting" compact>
      {#if hasAccounting}
        <div class="summary-grid summary-grid--accounting">
          <div class="summary-value">
            <Balance amount={equity} size="lg" />
          </div>
          <div class="summary-meta muted text-sm">Node equity (assets &minus; liabilities)</div>
          <div class="summary-value">
            <Balance amount={totalLiability} size="lg" />
          </div>
          <div class="summary-meta muted text-sm">Owed to children</div>
        </div>
      {:else}
        <p class="text-sm muted">
          The node accounting equation (assets &minus; liabilities = equity) applies to node
          operators. As a leaf user your balance comes from your parent node and is shown above.
          {#if !view.isSelf}
            Balances stay with the node operator: this console reads topology and joins for an
            administered node, never its ledger.
          {/if}
        </p>
      {/if}
    </Card>

    {#if apiCapabilities.mock}
      <div class="mock-banner">
        <Badge variant="info" label="Mock mode" />
        <span>Showing sample data. Connect a node for live data.</span>
      </div>
    {/if}
  {/if}
</div>

<style>
  .dashboard {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: var(--sp-4);
  }
  .summary-grid--accounting {
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    align-items: end;
  }
  .summary-value {
    font-size: var(--text-xl);
    font-weight: 700;
    margin-bottom: var(--sp-2);
  }
  .summary-meta {
    font-size: var(--text-sm);
  }
  .meta-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    margin-bottom: var(--sp-1);
  }
  .children-count {
    font-family: var(--mono);
    font-size: var(--text-xl);
    font-weight: 700;
  }
  .children-max {
    color: var(--muted);
    font-weight: 400;
  }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: inherit;
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }
  .quick-actions {
    display: flex;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .mock-banner {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-3) var(--sp-4);
    background: var(--accent-dim);
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    color: var(--muted);
  }
  .persistence-warning {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-3) var(--sp-4);
    background: var(--warn-dim);
    border: 1px solid var(--warn);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    color: var(--muted);
  }
  .join-cta {
    padding: var(--sp-6) var(--sp-5);
    background: var(--bg-raised);
    border: 1px solid var(--accent);
    border-radius: var(--radius-lg);
  }
  .join-cta-body {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--sp-3);
  }
  .join-cta-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--fg);
  }
  .join-cta-text {
    font-size: var(--text-sm);
    color: var(--muted);
    max-width: 480px;
  }

  /* Shared button styles */
  .btn {
    padding: var(--sp-2) var(--sp-4);
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
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover {
    background: var(--accent-hover);
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

  @media (max-width: 767px) {
    .summary-grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  @media (max-width: 480px) {
    .summary-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
