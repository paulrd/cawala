<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Balance from '../shared/Balance.svelte';
  import Badge from '../shared/Badge.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState } from '../../lib/stores.js';
  import { isMockMode } from '../../lib/api.js';

  let isLive = $derived(!isMockMode());
</script>

<div class="my-account-page">
  <Card title="My Account">
    <div class="account-info">
      <div class="info-row">
        <span class="info-label muted">Endpoint ID</span>
        <EndpointId id={clientState.endpointId} full={true} />
      </div>
      <div class="info-row">
        <span class="info-label muted">Address</span>
        {#if clientState.address}
          <Address address={clientState.address} size="md" />
        {:else}
          <span class="text-sm muted">Not assigned yet</span>
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label muted">Balance</span>
        {#if isLive}
          <span class="text-sm muted">Not available in the web client</span>
        {:else}
          <Balance amount={1200} size="lg" />
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label muted">Mode</span>
        <Badge variant={isLive ? 'ok' : 'warn'} label={isLive ? 'Live' : 'Mock'} />
      </div>
    </div>
  </Card>

  <Card title="Recent Transactions">
    {#if isLive}
      <div class="live-unavailable">
        <p class="text-sm muted">
          Transaction history is not available in the web client yet.
        </p>
      </div>
    {:else}
      <EmptyState
        title="No transactions yet"
        message="Your transaction history will appear here."
      />
    {/if}
  </Card>
</div>

<style>
  .my-account-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .account-info {
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
  .live-unavailable {
    padding: var(--sp-4) 0;
  }
</style>
