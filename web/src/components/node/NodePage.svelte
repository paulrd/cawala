<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState, nodeState } from '../../lib/stores.js';
  import { formatDate } from '../../lib/utils.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.js';

  const childColumns = [
    { key: 'address', label: 'Address', mono: true },
    { key: 'balance', label: 'Balance', align: 'right', mono: true },
    { key: 'seniority', label: 'Joined' },
    { key: 'online', label: 'Status' },
    { key: 'slot', label: 'Slot', align: 'right' },
  ];
</script>

<div class="node-page">
  <Card title="This Node">
    <div class="node-info">
      <div class="info-row">
        <span class="info-label muted">Address</span>
        <Address address={clientState.address ?? '0.3.1'} size="md" />
      </div>
      <div class="info-row">
        <span class="info-label muted">Endpoint ID</span>
        <EndpointId id={clientState.endpointId} />
      </div>
      <div class="info-row">
        <span class="info-label muted">Parent</span>
        <Address address="0.3" size="md" />
      </div>
    </div>
  </Card>

  <Card title="Children">
    {#if nodeState.children.length === 0}
      <EmptyState
        title="No children"
        message="Create a child node or approve a pending join."
        actionLabel="View Join Requests"
        onAction={() => navigate(ROUTES.JOINS)}
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
