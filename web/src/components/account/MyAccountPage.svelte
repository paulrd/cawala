<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import Balance from '../shared/Balance.svelte';
  import Badge from '../shared/Badge.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState } from '../../lib/stores.js';
</script>

<div class="my-account-page">
  <Card title="My Account">
    <div class="account-info">
      <div class="info-row">
        <span class="info-label muted">Address</span>
        <Address address={clientState.address ?? '0.3.1'} size="md" />
      </div>
      <div class="info-row">
        <span class="info-label muted">Balance</span>
        <Balance amount={1200} size="lg" />
      </div>
    </div>
  </Card>

  <Card title="Recent Transactions">
    <EmptyState
      title="No transactions yet"
      message="Your transaction history will appear here."
    />
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
</style>
