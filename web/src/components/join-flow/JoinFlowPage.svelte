<script>
  import Card from '../shared/Card.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState } from '../../lib/stores.js';
  import { isMockMode } from '../../lib/api.js';

  // Placeholder for the join flow wizard
  // TODO(control): implement full multi-step wizard when control API is ready
</script>

<div class="join-flow-page">
  <Card title="Join the Network">
    {#if clientState.address}
      <div class="join-status">
        <p>You are already connected to the network.</p>
        <p class="muted text-sm">Address: {clientState.address}</p>
      </div>
    {:else}
      <EmptyState
        title="Connect to a node"
        message="To join the Cawala network, you need a parent node's endpoint ID. Contact a node administrator to get started."
        actionLabel="Learn more [placeholder]"
        onAction={() => {}}
      />
    {/if}
  </Card>

  {#if isMockMode()}
    <div class="mock-notice">
      <p class="text-sm muted">
        Join flow will be available when the control message layer is implemented. Currently running in mock mode.
      </p>
    </div>
  {/if}
</div>

<style>
  .join-flow-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
    max-width: 560px;
  }
  .join-status {
    text-align: center;
    padding: var(--sp-4) 0;
  }
  .mock-notice {
    padding: var(--sp-3) var(--sp-4);
    background: var(--warn-dim);
    border: 1px solid var(--warn);
    border-radius: var(--radius-md);
  }
</style>
