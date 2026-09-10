<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';
  import { clientState, showToast } from '../../lib/stores.js';
  import { isMockMode } from '../../lib/api.js';

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
        <Address address={clientState.address ?? 'Not assigned'} size="md" />
      </div>
    </div>
  </Card>

  <Card title="Keys">
    <div class="settings-section">
      <p class="muted text-sm" style="margin-bottom: var(--sp-3);">
        Keys are managed by the cawala-node process. The PWA has read-only access.
      </p>
      <button type="button" class="btn btn--ghost" onclick={handleExportKey}>
        Export operator key [placeholder]
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
        <span class="text-sm muted">Not connected</span>
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
