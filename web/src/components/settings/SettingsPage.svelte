<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';
  import { clientState, ledgerState, apiCapabilities, showToast } from '../../lib/stores.svelte.js';
  import { isMockMode, isIdentityPersistent, getCapabilities } from '../../lib/api.js';

  let caps = $derived(getCapabilities());

  async function handleExportKey() {
    showToast('Key export not yet implemented', 'warn');
  }
</script>

<div class="settings-page">
  <Card title="Connection">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Status</span>
        <ConnectionIndicator status={clientState.connectionStatus} />
      </div>
      <div class="setting-row">
        <span class="setting-label">Mode</span>
        <Badge variant={isMockMode() ? 'warn' : 'ok'} label={isMockMode() ? 'Mock (no live node)' : 'Live'} />
      </div>
    </div>
  </Card>

  <Card title="Identity">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Endpoint ID</span>
        <EndpointId id={clientState.endpointId} full={true} />
      </div>
      <div class="setting-row">
        <span class="setting-label">Address</span>
        {#if clientState.address}
          <Address address={clientState.address} size="md" />
        {:else}
          <span class="text-sm muted">Not assigned yet</span>
        {/if}
      </div>
      {#if !isMockMode()}
        <div class="setting-row">
          <span class="setting-label">Identity</span>
          {#if caps.identityPersistent}
            <Badge variant="ok" label="Persisted" />
          {:else}
            <div class="persistence-warn">
              <Badge variant="warn" label="Session only" />
              <span class="text-xs muted">Identity won't persist after closing this tab (storage unavailable).</span>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </Card>

  {#if !isMockMode() && ledgerState.pinnedLedger}
    <Card title="Leaf Ledger Trust">
      <div class="settings-section">
        <div class="setting-row">
          <span class="setting-label">Pinned ledger</span>
          <code class="text-sm" style="word-break: break-all; font-family: var(--mono);">
            {ledgerState.pinnedLedger}
          </code>
        </div>
        <p class="muted text-sm" style="margin-top: var(--sp-1);">
          This is the leaf's ledger public key, pinned on first use (TOFU). Your balance and payment receipts are verified against this key.
        </p>
      </div>
    </Card>
  {/if}

  {#if caps.multiTabWarning}
    <Card title="Multi-Tab" variant="warn">
      <div class="settings-section">
        <p class="text-sm" style="color: var(--warn);">
          {caps.multiTabWarning}
        </p>
      </div>
    </Card>
  {/if}

  <Card title="Keys">
    <div class="settings-section">
      <p class="muted text-sm" style="margin-bottom: var(--sp-3);">
        In live mode, keys are generated and managed by the wasm client in this browser. In mock mode, keys are placeholder values.
      </p>
      <button type="button" class="btn btn--ghost" onclick={handleExportKey}>
        Export identity seed [not yet implemented]
      </button>
    </div>
  </Card>

  <Card title="Location Service">
    <div class="settings-section">
      <p class="muted text-sm">
        An optional companion service that suggests an octal address based on your geographic region. This is a separate, external service &mdash; not required to use Cawala. Your parent node assigns the final address regardless.
      </p>
      <div class="setting-row" style="margin-top: var(--sp-3);">
        <span class="setting-label">Service</span>
        <code class="text-sm">location.cawala.net</code>
      </div>
      <div class="setting-row">
        <span class="setting-label">Status</span>
        {#if isMockMode()}
          <span class="text-sm muted">Mock mode (not connected)</span>
        {:else}
          <span class="text-sm muted">Not available in the web client</span>
        {/if}
      </div>
    </div>
  </Card>

  <Card title="About">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Version</span>
        <span class="text-sm">Cawala M4</span>
      </div>
      <div class="setting-row">
        <span class="setting-label">WASM</span>
        <span class="text-sm">{isMockMode() ? 'Not loaded (mock mode)' : 'Loaded'}</span>
      </div>
    </div>
  </Card>
</div>

<style>
  .settings-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .settings-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .setting-row {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
  }
  .setting-label {
    min-width: 120px;
    font-size: var(--text-sm);
    font-weight: 500;
    color: var(--muted);
  }
  .persistence-warn {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }
  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .btn--ghost {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover {
    background: var(--bg-hover);
  }
</style>
