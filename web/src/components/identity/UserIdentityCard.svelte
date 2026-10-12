<script>
  import Card from '../shared/Card.svelte';
  import Badge from '../shared/Badge.svelte';
  import EthAddressBlock from './EthAddressBlock.svelte';
  import PasskeyPanel from './PasskeyPanel.svelte';
  import { userIdentityState } from '../../lib/stores.svelte.js';
  import { isPasskeyAvailable } from '../../lib/api.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';
  import { formatDate } from '../../lib/utils.js';

  /**
   * UserIdentityCard — the R3 user identity as it appears in Settings.
   *
   * Not established → a plain explanation and one entry point into the
   * setup/restore flow. Established → the EIP-55 account address with its
   * explanation, where the phrase was set, the passkey affordance (only when
   * the context supports passkeys), and the trust/backup warning.
   */

  let passkeyAvailable = $derived(isPasskeyAvailable());
  let status = $derived(userIdentityState);

  function openSetup() {
    navigate(ROUTES.IDENTITY);
  }
</script>

<Card title="Your Account Identity">
  <div class="identity-section">
    {#if !status.established}
      <p class="lead">
        Your identity comes from a 12-word recovery phrase. From it, Cawala
        derives your account address — the <span class="mono">0x…</span> code
        that names you across the network — plus the keys this browser uses.
        The phrase is the only thing that can recover this account.
      </p>
      <div class="actions">
        <button type="button" class="btn btn--primary" onclick={openSetup}>
          Set up identity
        </button>
        <span class="actions-hint text-sm muted">
          New phrase or one you already wrote down — you choose on the next screen.
        </span>
      </div>
    {:else}
      <EthAddressBlock
        address={status.address}
        explanation="This address comes from your recovery phrase. Share it like an account number — knowing it lets people send you things, not take them."
        animate={false}
      />

      <div class="setting-row">
        <span class="setting-label">Recovery phrase</span>
        {#if status.source === 'restored'}
          <span class="text-sm muted">Restored here on {formatDate(status.createdAt)}</span>
        {:else}
          <span class="text-sm muted">Created here on {formatDate(status.createdAt)}</span>
        {/if}
      </div>

      {#if passkeyAvailable}
        <PasskeyPanel />
      {/if}

      <div class="warn-box">
        <span class="warn-icon" aria-hidden="true">!</span>
        <span>
          This phrase is the only way to recover this account. A passkey unlocks
          it on this device but cannot bring it back. If you lose both the
          phrase and this device, nobody — including Cawala — can restore the
          account.
        </span>
      </div>

      <div class="manage-link-row">
        <button type="button" class="link-btn" onclick={openSetup}>
          View and manage identity
        </button>
      </div>
    {/if}
  </div>
</Card>

<style>
  .identity-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .lead {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .lead .mono {
    font-family: var(--mono);
    color: var(--fg);
  }

  .actions {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .actions-hint {
    line-height: var(--leading-normal);
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

  /* ── Warning box (matches Settings) ───────────── */
  .warn-box {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--warn-dim);
    border: 1px solid color-mix(in srgb, var(--warn) 30%, transparent);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    color: var(--warn);
    line-height: var(--leading-normal);
  }
  .warn-icon {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--warn);
    color: #000;
    font-weight: 700;
    font-size: 11px;
    margin-top: 1px;
  }

  .manage-link-row {
    display: flex;
    justify-content: flex-start;
  }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 600;
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  /* ── Buttons (same shape as the app's) ────────── */
  .btn {
    padding: var(--sp-2) var(--sp-3);
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

  .text-sm { font-size: var(--text-sm); }
  .muted { color: var(--muted); }
</style>
