<script>
  import Card from '../shared/Card.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import { clientState, showToast } from '../../lib/stores.js';
  import { parseInvite, requestJoin, isMockMode } from '../../lib/api.js';
  import { truncateMiddle, copyToClipboard } from '../../lib/utils.js';

  // ── State ───────────────────────────────────────────────────
  // One of: 'idle' | 'parsing' | 'valid' | 'invalid' | 'connecting' | 'waiting' | 'approved' | 'error'
  let flowState = $state('idle');
  let rawInput = $state('');
  let parsedInvite = $state(null);
  let errorMessage = $state('');
  let assignedAddress = $state(null);

  // ── Derived ─────────────────────────────────────────────────
  let expiryFormatted = $derived.by(() => {
    if (!parsedInvite?.expiry) return null;
    const d = new Date(parsedInvite.expiry * 1000);
    if (isNaN(d.getTime())) return null;
    return d.toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  });

  let isExpired = $derived.by(() => {
    if (!parsedInvite?.expiry) return false;
    return Date.now() > parsedInvite.expiry * 1000;
  });

  let operatorTruncated = $derived(
    parsedInvite?.operator ? truncateMiddle(parsedInvite.operator, 8) : '',
  );

  // ── Actions ─────────────────────────────────────────────────

  async function handleParse() {
    if (!rawInput.trim()) return;
    flowState = 'parsing';
    errorMessage = '';
    parsedInvite = null;

    try {
      parsedInvite = await parseInvite(rawInput);
      flowState = 'valid';
    } catch (e) {
      errorMessage = e.message || 'Invalid invite.';
      flowState = 'invalid';
    }
  }

  function handleInputKeydown(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleParse();
    }
  }

  function handleReset() {
    flowState = 'idle';
    rawInput = '';
    parsedInvite = null;
    errorMessage = '';
    assignedAddress = null;
  }

  async function handleConnect() {
    if (!parsedInvite) return;
    flowState = 'connecting';

    try {
      const result = await requestJoin(parsedInvite.parent, null);
      if (result.status === 'pending') {
        flowState = 'waiting';
        showToast('Join request sent. Waiting for approval.', 'info');
      } else if (result.status === 'approved' && result.address) {
        assignedAddress = result.address;
        flowState = 'approved';
        clientState.address = result.address;
        showToast(`Approved. Your address is ${result.address}.`, 'ok');
      } else {
        flowState = 'error';
        errorMessage = 'Unexpected response from the parent node.';
      }
    } catch (e) {
      flowState = 'error';
      errorMessage = e.message || 'Failed to send join request.';
    }
  }

  async function handleCopyOperator() {
    if (parsedInvite?.operator) {
      const ok = await copyToClipboard(parsedInvite.operator);
      if (ok) showToast('Operator key copied', 'ok', 2000);
    }
  }

  async function handleCopyParent() {
    if (parsedInvite?.parent) {
      const ok = await copyToClipboard(parsedInvite.parent);
      if (ok) showToast('Parent endpoint ID copied', 'ok', 2000);
    }
  }

  // If already connected, show a different view
  let alreadyConnected = $derived(!!clientState.address);
</script>

<div class="join-flow-page">
  <Card title="Join the Network">
    {#if alreadyConnected}
      <div class="join-status">
        <p>You are already connected to the network.</p>
        <p class="muted text-sm">Address: {clientState.address}</p>
      </div>

    {:else if flowState === 'idle' || flowState === 'invalid'}
      <!-- Invite input -->
      <div class="invite-input-section">
        <p class="section-desc">
          Paste an invite code or link from a node operator to join their node.
        </p>
        <div class="input-group">
          <label for="invite-input" class="sr-only">Invite code or link</label>
          <input
            id="invite-input"
            type="text"
            class="invite-input"
            class:input-error={flowState === 'invalid'}
            placeholder="cawala://join?parent=...&op=..."
            bind:value={rawInput}
            onkeydown={handleInputKeydown}
            disabled={flowState === 'parsing'}
            autocomplete="off"
            spellcheck="false"
          />
          <button
            type="button"
            class="btn btn--primary parse-btn"
            onclick={handleParse}
            disabled={!rawInput.trim() || flowState === 'parsing'}
          >
            {#if flowState === 'parsing'}
              <span class="spinner" aria-hidden="true"></span>
              Checking
            {:else}
              Paste &amp; check
            {/if}
          </button>
        </div>
        {#if flowState === 'invalid' && errorMessage}
          <p class="input-error-msg" role="alert">{errorMessage}</p>
        {/if}
        <p class="input-hint muted text-sm">
          The invite is a link that starts with <code>cawala://join</code> or a code the operator shared with you.
        </p>
      </div>

    {:else if flowState === 'parsing'}
      <div class="parsing-state">
        <LoadingSkeleton rows={2} widths={[80, 50]} />
        <p class="muted text-sm">Checking invite…</p>
      </div>

    {:else if flowState === 'valid' && parsedInvite}
      <!-- Invite summary card -->
      <div class="invite-summary">
        <p class="section-desc">
          This invite will connect you to a node on the Cawala network.
          Review the details below before connecting.
        </p>

        <div class="detail-card">
          <div class="detail-row">
            <span class="detail-label">Parent node</span>
            <div class="detail-value">
              <EndpointId id={parsedInvite.parent} full={false} />
              <button
                type="button"
                class="copy-inline"
                onclick={handleCopyParent}
                title="Copy full endpoint ID"
                aria-label="Copy parent endpoint ID"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
              </button>
            </div>
          </div>

          <div class="detail-row">
            <span class="detail-label">Operator key</span>
            <div class="detail-value">
              <span class="mono text-xs">{operatorTruncated}</span>
              <button
                type="button"
                class="copy-inline"
                onclick={handleCopyOperator}
                title="Copy full operator key"
                aria-label="Copy operator key"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
              </button>
            </div>
          </div>

          {#if parsedInvite.slot != null}
            <div class="detail-row">
              <span class="detail-label">Slot</span>
              <span class="detail-value"><Badge variant="info" label={String(parsedInvite.slot)} /></span>
            </div>
          {/if}

          {#if parsedInvite.label}
            <div class="detail-row">
              <span class="detail-label">Label</span>
              <span class="detail-value text-sm">{parsedInvite.label}</span>
            </div>
          {/if}

          {#if expiryFormatted}
            <div class="detail-row">
              <span class="detail-label">Expires</span>
              <span class="detail-value">
                <span class="text-sm" class:text-warn={isExpired} class:text-danger={isExpired}>
                  {expiryFormatted}
                </span>
                {#if isExpired}
                  <Badge variant="danger" label="Expired" />
                {/if}
              </span>
            </div>
          {/if}
        </div>

        <div class="invite-actions">
          <button
            type="button"
            class="btn btn--ghost"
            onclick={handleReset}
          >
            Use a different invite
          </button>
          <button
            type="button"
            class="btn btn--primary"
            onclick={handleConnect}
            disabled={isExpired}
          >
            Connect
          </button>
        </div>
      </div>

    {:else if flowState === 'connecting'}
      <div class="connecting-state">
        <LoadingSkeleton rows={1} widths={[60]} />
        <p class="muted text-sm">Sending join request to parent node…</p>
      </div>

    {:else if flowState === 'waiting'}
      <div class="waiting-state">
        <div class="waiting-icon" aria-hidden="true">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
        </div>
        <h3 class="waiting-title">Waiting for approval</h3>
        <p class="waiting-desc muted text-sm">
          Your join request has been sent to the parent node. The operator needs to approve it before you can use the network.
        </p>
        <button type="button" class="btn btn--ghost" onclick={handleReset}>
          Cancel and use a different invite
        </button>
      </div>

    {:else if flowState === 'approved'}
      <div class="approved-state">
        <div class="approved-icon" aria-hidden="true">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <path d="M22 4L12 14.01l-3-3"/>
          </svg>
        </div>
        <h3 class="approved-title">You're connected</h3>
        <p class="approved-desc muted text-sm">
          Your join request was approved. Your address on the network:
        </p>
        <div class="approved-address">
          <code class="mono">{assignedAddress}</code>
        </div>
        <p class="muted text-xs">
          You can find this in My Node &rarr; Identity.
        </p>
      </div>

    {:else if flowState === 'error'}
      <div class="error-section">
        <p class="error-text" role="alert">{errorMessage}</p>
        <div class="error-actions">
          <button type="button" class="btn btn--ghost" onclick={handleReset}>
            Start over
          </button>
        </div>
      </div>
    {/if}
  </Card>

  {#if isMockMode() && flowState !== 'approved'}
    <div class="mock-notice">
      <p class="text-sm muted">
        Running in mock mode. The invite will be parsed locally but no real network connection will be made.
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

  /* ── Already connected ── */
  .join-status {
    text-align: center;
    padding: var(--sp-4) 0;
  }

  /* ── Input section ── */
  .section-desc {
    font-size: var(--text-sm);
    color: var(--muted);
    margin-bottom: var(--sp-4);
    line-height: var(--leading-normal);
  }

  .input-group {
    display: flex;
    gap: var(--sp-2);
  }

  .invite-input {
    flex: 1;
    min-width: 0;
    font-family: var(--mono);
    font-size: var(--text-sm);
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    transition: border-color var(--duration-fast) var(--ease);
  }

  .invite-input:focus {
    border-color: var(--accent);
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-dim);
  }

  .invite-input.input-error {
    border-color: var(--danger);
  }

  .invite-input.input-error:focus {
    box-shadow: 0 0 0 2px var(--danger-dim);
  }

  .input-error-msg {
    color: var(--danger);
    font-size: var(--text-sm);
    margin-top: var(--sp-2);
    line-height: var(--leading-normal);
  }

  .input-hint {
    margin-top: var(--sp-3);
  }

  .input-hint code {
    font-size: var(--text-xs);
  }

  /* ── Parsing / Connecting states ── */
  .parsing-state,
  .connecting-state {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-2) 0;
  }

  /* ── Invite summary ── */
  .invite-summary {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .detail-card {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--sp-4);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .detail-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
  }

  .detail-label {
    font-size: var(--text-sm);
    font-weight: 500;
    color: var(--muted);
    flex-shrink: 0;
  }

  .detail-value {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    min-width: 0;
    justify-content: flex-end;
  }

  .copy-inline {
    display: inline-flex;
    align-items: center;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: 2px;
    border-radius: var(--radius-sm);
    transition: color var(--duration-fast) var(--ease);
    flex-shrink: 0;
  }

  .copy-inline:hover {
    color: var(--accent);
  }

  .invite-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-3);
    padding-top: var(--sp-2);
  }

  /* ── Waiting state ── */
  .waiting-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--sp-3);
    padding: var(--sp-4) 0;
  }

  .waiting-icon {
    color: var(--warn);
    margin-bottom: var(--sp-1);
  }

  .waiting-title {
    font-size: var(--text-base);
    font-weight: 600;
  }

  .waiting-desc {
    max-width: 360px;
    line-height: var(--leading-normal);
  }

  /* ── Approved state ── */
  .approved-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--sp-3);
    padding: var(--sp-4) 0;
  }

  .approved-icon {
    color: var(--ok);
    margin-bottom: var(--sp-1);
  }

  .approved-title {
    font-size: var(--text-base);
    font-weight: 600;
  }

  .approved-desc {
    max-width: 360px;
    line-height: var(--leading-normal);
  }

  .approved-address {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--sp-3) var(--sp-5);
    margin-top: var(--sp-2);
  }

  .approved-address code {
    font-size: var(--text-lg);
    letter-spacing: 0.05em;
  }

  /* ── Error section ── */
  .error-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .error-text {
    color: var(--danger);
    font-size: var(--text-sm);
    line-height: var(--leading-normal);
  }

  .error-actions {
    display: flex;
    justify-content: flex-end;
    padding-top: var(--sp-1);
  }

  /* ── Shared button styles ── */
  .btn {
    padding: var(--sp-2) var(--sp-4);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease), opacity var(--duration-fast) var(--ease);
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }

  .btn--primary:hover:not(:disabled) {
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

  .parse-btn {
    flex-shrink: 0;
    min-width: 120px;
    justify-content: center;
  }

  /* ── Spinner ── */
  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--fg);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  /* ── Text helpers ── */
  .text-warn { color: var(--warn); }
  .text-danger { color: var(--danger); }

  /* ── Mock notice ── */
  .mock-notice {
    padding: var(--sp-3) var(--sp-4);
    background: var(--warn-dim);
    border: 1px solid var(--warn);
    border-radius: var(--radius-md);
  }

  /* ── Responsive ── */
  @media (max-width: 480px) {
    .input-group {
      flex-direction: column;
    }

    .parse-btn {
      width: 100%;
    }

    .detail-row {
      flex-direction: column;
      align-items: flex-start;
      gap: var(--sp-1);
    }

    .detail-value {
      justify-content: flex-start;
    }

    .invite-actions {
      flex-direction: column;
    }

    .invite-actions .btn {
      width: 100%;
      justify-content: center;
    }
  }
</style>
