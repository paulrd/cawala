<script>
  import Badge from '../shared/Badge.svelte';
  import {
    isPasskeyAvailable,
    enrollPasskey,
    unlockWithPasskey,
    removePasskey,
    refreshUserIdentity,
    IdentityBackendUnavailableError,
    PasskeyUnavailableError,
  } from '../../lib/api.js';
  import { userIdentityState, showToast } from '../../lib/stores.svelte.js';

  /**
   * PasskeyPanel — biometric unlock affordance.
   *
   * Feature-detected: renders NOTHING when passkeys cannot work here
   * (`file://`, plain http) — the flow is hidden, never faked. States once
   * available and an identity exists: not enrolled → set up; enrolled →
   * unlock / remove; honest inline notice when the crypto backend for the
   * WebAuthn PRF wrap is not connected yet.
   *
   * @param {() => void} [onChanged] - Called after any successful mutation.
   */
  let { onChanged } = $props();

  let available = $derived(isPasskeyAvailable());
  let status = $derived(userIdentityState);
  let busy = $state(false);
  // Inline (non-toast) notices: honest "why that didn't work" copy.
  let notice = $state(null); // { variant: 'warn'|'info', text: string } | null

  async function run(action, successText) {
    notice = null;
    busy = true;
    try {
      await action();
      refreshUserIdentity();
      showToast(successText, 'ok');
      onChanged?.();
    } catch (err) {
      if (err instanceof IdentityBackendUnavailableError || err instanceof PasskeyUnavailableError) {
        // Expected states, not failures: explain in place instead of alarming.
        notice = {
          variant: err instanceof IdentityBackendUnavailableError ? 'info' : 'warn',
          text: err.message,
        };
      } else {
        showToast(err?.message || 'That didn’t work.', 'danger');
      }
    } finally {
      busy = false;
    }
  }

  function handleEnroll() {
    return run(() => enrollPasskey(), 'Biometric unlock set up for this device.');
  }
  function handleUnlock() {
    return run(() => unlockWithPasskey(), 'Unlocked with your passkey.');
  }
  function handleRemove() {
    return run(() => removePasskey(), 'Passkey removed. Your recovery phrase is unchanged.');
  }
</script>

{#if available && status.established}
  <div class="passkey">
    <div class="passkey-head">
      <span class="passkey-icon" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
          <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
          <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
          <path d="M2 12a10 10 0 0 1 18-6" />
          <path d="M2 16h.01" />
          <path d="M21.8 16c.2-2 .131-5.354 0-6" />
          <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
          <path d="M8.65 22c.21-.66.45-1.32.57-2" />
          <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
        </svg>
      </span>
      <div class="passkey-head-text">
        <h4 class="passkey-title">Unlock with a passkey</h4>
        <p class="passkey-sub text-xs muted">
          Use your fingerprint, face, or device PIN to unlock Cawala on this device.
        </p>
      </div>
      {#if status.passkeyEnrolled}
        <Badge variant="ok" label="Set up" />
      {:else}
        <Badge variant="muted" label="Not set up" />
      {/if}
    </div>

    <p class="passkey-note text-xs muted">
      A passkey is a shortcut, not a backup: it only unlocks here, and it can’t
      recover your account. Your recovery phrase does that.
    </p>

    {#if notice}
      <p
        class="passkey-notice passkey-notice--{notice.variant}"
        role="status"
      >
        {notice.text}
      </p>
    {/if}

    <div class="passkey-actions">
      {#if !status.passkeyEnrolled}
        <button type="button" class="btn btn--primary" disabled={busy} onclick={handleEnroll}>
          {#if busy}Setting up…{:else}Set up biometric unlock{/if}
        </button>
      {:else}
        <button type="button" class="btn btn--ghost" disabled={busy} onclick={handleUnlock}>
          {#if busy}Checking…{:else}Unlock with passkey{/if}
        </button>
        <button type="button" class="btn btn--quiet" disabled={busy} onclick={handleRemove}>
          Remove passkey
        </button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .passkey {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg);
  }

  .passkey-head {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
  }
  .passkey-icon {
    display: flex;
    flex-shrink: 0;
    color: var(--accent);
    margin-top: 2px;
  }
  .passkey-head-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .passkey-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .passkey-sub {
    line-height: var(--leading-normal);
  }

  .passkey-note {
    line-height: var(--leading-normal);
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .passkey-notice {
    font-size: var(--text-xs);
    line-height: var(--leading-normal);
    padding: var(--sp-2) var(--sp-3);
    border-radius: var(--radius-md);
    border: 1px solid transparent;
  }
  .passkey-notice--info {
    background: var(--accent-dim);
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
  }
  .passkey-notice--warn {
    background: var(--warn-dim);
    color: var(--warn);
    border-color: color-mix(in srgb, var(--warn) 30%, transparent);
  }

  .passkey-actions {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    flex-wrap: wrap;
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
    transition: background var(--duration-fast) var(--ease),
                color var(--duration-fast) var(--ease),
                opacity var(--duration-fast) var(--ease);
  }
  .btn:disabled {
    opacity: 0.4;
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
    color: var(--fg);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .btn--quiet {
    background: transparent;
    color: var(--muted);
  }
  .btn--quiet:hover:not(:disabled) {
    color: var(--danger);
  }

  .text-xs { font-size: var(--text-xs); }
  .muted { color: var(--muted); }
</style>
