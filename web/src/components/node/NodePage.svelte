<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { clientState, nodeState } from '../../lib/stores.svelte.js';
  import { isMockMode } from '../../lib/api.js';
  import { formatDate } from '../../lib/utils.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';

  let isLive = $derived(!isMockMode());

  const childColumns = [
    { key: 'address', label: 'Address', mono: true },
    { key: 'balance', label: 'Balance', align: 'right', mono: true,
      render: (v) => {
        if (v == null) return '<span style="color:var(--muted)">&mdash;</span>';
        return `<span style="font-family:var(--mono);font-weight:600;color:${v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)'}">${v.toLocaleString()}</span>`;
      } },
    { key: 'seniority', label: 'Joined',
      render: (v) => `<span class="text-sm">${formatDate(v)}</span>` },
    { key: 'online', label: 'Status',
      render: (v, row) => {
        const label = isLive && !v ? 'Unknown' : v ? 'Online' : 'Offline';
        const color = v ? 'var(--ok)' : 'var(--muted)';
        const bg = v ? 'var(--ok-dim)' : 'var(--bg-hover)';
        return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${bg};color:${color}">${label}</span>`;
      } },
    { key: 'slot', label: 'Slot', align: 'right' },
  ];
</script>

<div class="node-page">
  <Card title="This Node">
    <div class="node-info">
      <div class="info-row">
        <span class="info-label muted">Address</span>
        {#if clientState.address}
          <Address address={clientState.address} size="md" />
        {:else}
          <span class="text-sm muted">Not assigned yet</span>
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label muted">Endpoint ID</span>
        <EndpointId id={clientState.endpointId} />
      </div>
      {#if clientState.address}
        <div class="info-row">
          <span class="info-label muted">Parent</span>
          <span class="text-sm muted">Derived from join handshake</span>
        </div>
      {/if}
    </div>
  </Card>

  <Card title="Children">
    {#if nodeState.children.length === 0}
      <EmptyState
        title="No children"
        message={isLive
          ? "This node's local topology snapshot shows no children."
          : "Create a child node or approve a pending join."}
        actionLabel={isLive ? undefined : "View Join Requests"}
        onAction={isLive ? undefined : () => navigate(ROUTES.JOINS)}
      />
    {:else}
      <DataTable columns={childColumns} rows={nodeState.children} />
    {/if}
  </Card>
</div>

<style>
  .node-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .node-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .info-row {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
  }
  .info-label {
    min-width: 100px;
    font-size: var(--text-sm);
    font-weight: 500;
  }
</style>
