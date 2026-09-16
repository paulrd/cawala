<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import { clientState, ledgerState, nodeState, loadingState, errorState, apiCapabilities, showToast } from '../../lib/stores.svelte.js';
  import { getChildren, getAccounts, getJoinRequests, isMockMode, requestBalance, getLastControlEvent } from '../../lib/api.js';
  import { ROUTES, CONTROL_EVENT } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { formatDate, timeAgo } from '../../lib/utils.js';

  let loaded = $state(false);

  $effect(() => {
    if (!loaded) loadData();
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

  let totalLiability = $derived(
    nodeState.accounts
      .filter((a) => a.type === 'liability')
      .reduce((sum, a) => sum + a.balance, 0),
  );
  let equity = $derived(
    nodeState.accounts.find((a) => a.type === 'equity')?.balance ?? 0,
  );
  let pendingJoins = $derived(
    nodeState.joinRequests.filter((r) => r.status === 'pending').length,
  );

  let isLive = $derived(!isMockMode());

  // Show join CTA when live and not yet joined (no address assigned).
  let showJoinCta = $derived(isLive && clientState.address == null);

  // Detect the "detached" event from the control drain so the Dashboard can
  // show "Left the network" instead of the generic "not connected" copy.
  let hasLeft = $state(false);
  let _detachedPoller = $state(null);

  $effect(() => {
    if (showJoinCta && isLive) {
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

  // Live mode: balance availability
  let balanceReady = $derived(isLive && ledgerState.balance != null);
  let balanceFresh = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) < 30000
  );
  let balanceStale = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) >= 30000
  );
  let balanceUnverified = $derived(ledgerState.balance == null);

  async function handleBalanceRequest() {
    await requestBalance();
    showToast('Balance refresh requested', 'info', 2000);
  }

  const childColumns = [
    { key: 'address', label: 'Address', mono: true, sortable: true },
    { key: 'balance', label: 'Balance', align: 'right', mono: true, sortable: true,
      render: (v) => {
        if (v == null) return '<span style="color:var(--muted)">&mdash;</span>';
        return `<span style="color: ${v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)'}">${v.toLocaleString()}</span>`;
      } },
    { key: 'seniority', label: 'Joined', sortable: true,
      render: (v) => `<span class="text-sm">${formatDate(v)}</span>` },
    { key: 'online', label: 'Status',
      render: (v, row) => {
        const label = isLive && !v ? 'Unknown' : v ? 'Online' : 'Offline';
        const color = v ? 'var(--ok)' : 'var(--muted)';
        const bg = v ? 'var(--ok-dim)' : 'var(--bg-hover)';
        return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${bg};color:${color}">${label}</span>`;
      } },
  ];
</script>

<div class="dashboard">
  {#if !loaded && loadingState.children}
    <LoadingSkeleton rows={4} />
  {:else if errorState.children}
    <ErrorState message="Failed to load node data" onRetry={loadData} />
  {:else}
    <!-- Identity persistence warning (subtle) -->
    {#if isLive && !apiCapabilities.identityPersistent}
      <div class="persistence-warning">
        <Badge variant="warn" label="Session only" />
        <span class="text-sm muted">Identity won't persist on this device. If you close this tab, your identity will be lost.</span>
      </div>
    {/if}

    {#if isLive}
      <!-- ── Live mode: user-leaf dashboard ──────────── -->

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

      <div class="summary-grid">
        <Card title="My Balance">
          <div class="summary-value">
            {#if balanceReady}
              <Balance amount={ledgerState.balance} size="lg" showSign={false} />
            {:else}
              <span class="muted">&mdash;</span>
            {/if}
          </div>
          <div class="summary-meta">
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
              <button
                type="button"
                class="btn btn--ghost btn--sm"
                onclick={handleBalanceRequest}
              >
                Refresh balance
              </button>
            {:else}
              <span class="text-sm muted">Balance not yet verified. Waiting for a receipt from your leaf.</span>
              <button
                type="button"
                class="btn btn--ghost btn--sm"
                onclick={handleBalanceRequest}
              >
                Request balance
              </button>
            {/if}
          </div>
        </Card>

        <Card title="My Address">
          <div class="summary-value">
            <Address address={clientState.address} size="lg" />
          </div>
          <div class="summary-meta">
            <EndpointId id={clientState.endpointId} />
          </div>
        </Card>

        <Card title="Pending">
          <div class="summary-value">
            <span class="children-count">{ledgerState.pending}</span>
          </div>
          <div class="summary-meta muted text-sm">
            {#if ledgerState.pending > 0}
              Orders awaiting confirmation
            {:else}
              No pending orders
            {/if}
          </div>
        </Card>

        <Card title="Children">
          <div class="summary-value">
            <span class="children-count">{nodeState.children.length}<span class="children-max">/8</span></span>
          </div>
          <div class="summary-meta muted text-sm">
            {#if pendingJoins > 0}
              <button type="button" class="link-btn" onclick={() => navigate(ROUTES.JOINS)}>
                {pendingJoins} pending join{pendingJoins !== 1 ? 's' : ''}
              </button>
            {:else if isLive}
              Pending joins not available in the web client
            {:else}
              No pending joins
            {/if}
          </div>
        </Card>
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
        {#if nodeState.children.length === 0}
          <EmptyState
            title="No children yet"
            message="This node has no children in its local topology snapshot."
          />
        {:else}
          <DataTable
            columns={childColumns}
            rows={nodeState.children}
            emptyMessage="No children"
          />
        {/if}
      </Card>

      <!-- Node accounting info (collapsed) -->
      <Card title="Node Accounting" compact>
        <p class="text-sm muted">
          The node accounting equation (assets &minus; liabilities = equity) applies to node operators. As a leaf user, your balance is managed by your parent node and shown above.
        </p>
      </Card>

    {:else}
      <!-- ── Mock mode: original dashboard ───────────── -->
      <div class="summary-grid">
        <Card title="Node Address">
          <div class="summary-value">
            <Address address={clientState.address} size="lg" />
          </div>
          <div class="summary-meta">
            <EndpointId id={clientState.endpointId} />
          </div>
        </Card>

        <Card title="Equity">
          <div class="summary-value">
            {#if nodeState.accounts.length === 0}
              <span class="muted">&mdash;</span>
            {:else}
              <Balance amount={equity} size="lg" />
            {/if}
          </div>
          <div class="summary-meta muted text-sm">
            {#if nodeState.accounts.length === 0}
              No accounting data from this node
            {:else}
              Node equity (assets &minus; liabilities)
            {/if}
          </div>
        </Card>

        <Card title="Children">
          <div class="summary-value">
            <span class="children-count">{nodeState.children.length}<span class="children-max">/8</span></span>
          </div>
          <div class="summary-meta muted text-sm">
            {#if pendingJoins > 0}
              <button type="button" class="link-btn" onclick={() => navigate(ROUTES.JOINS)}>
                {pendingJoins} pending join{pendingJoins !== 1 ? 's' : ''}
              </button>
            {:else}
              No pending joins
            {/if}
          </div>
        </Card>

        <Card title="Total Liability">
          <div class="summary-value">
            {#if nodeState.accounts.length === 0}
              <span class="muted">&mdash;</span>
            {:else}
              <Balance amount={totalLiability} size="lg" />
            {/if}
          </div>
          <div class="summary-meta muted text-sm">
            {#if nodeState.accounts.length === 0}
              No accounting data from this node
            {:else}
              Owed to children
            {/if}
          </div>
        </Card>
      </div>

      <Card title="Children">
        {#if nodeState.children.length === 0}
          <EmptyState
            title="No children yet"
            message="Create a child node or approve a pending join request."
            actionLabel="View Join Requests"
            onAction={() => navigate(ROUTES.JOINS)}
          />
        {:else}
          <DataTable
            columns={childColumns}
            rows={nodeState.children}
            emptyMessage="No children"
          />
        {/if}
      </Card>

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
  .btn--ghost:hover {
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
