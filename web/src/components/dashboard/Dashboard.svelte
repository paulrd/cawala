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
  import { clientState, nodeState, loadingState, errorState, apiCapabilities } from '../../lib/stores.js';
  import { getChildren, getAccounts, getJoinRequests, isMockMode } from '../../lib/api.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.js';
  import { formatDate } from '../../lib/utils.js';

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

  // In live mode, balance is always null and online is always false.
  // Render em-dash for null balance, "Unknown" for online status.
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
        // In live mode, show "Unknown" instead of lying about online status
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
          {#if isLive && nodeState.accounts.length === 0}
            <span class="muted">&mdash;</span>
          {:else}
            <Balance amount={equity} size="lg" />
          {/if}
        </div>
        <div class="summary-meta muted text-sm">
          {#if isLive && nodeState.accounts.length === 0}
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
          {:else if isLive}
            Pending joins not available in the web client
          {:else}
            No pending joins
          {/if}
        </div>
      </Card>

      <Card title="Total Liability">
        <div class="summary-value">
          {#if isLive && nodeState.accounts.length === 0}
            <span class="muted">&mdash;</span>
          {:else}
            <Balance amount={totalLiability} size="lg" />
          {/if}
        </div>
        <div class="summary-meta muted text-sm">
          {#if isLive && nodeState.accounts.length === 0}
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
          message={isLive
            ? "This node has no children in its local topology snapshot."
            : "Create a child node or approve a pending join request."}
          actionLabel={isLive ? undefined : "View Join Requests"}
          onAction={isLive ? undefined : () => navigate(ROUTES.JOINS)}
        />
      {:else}
        <DataTable
          columns={childColumns}
          rows={nodeState.children}
          emptyMessage="No children"
        />
      {/if}
    </Card>

    {#if isMockMode()}
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
