<script>
  import Badge from '../shared/Badge.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import {
    getPasskeyStatus,
    enrollPasskey,
    unlockWithPasskey,
    removePasskey,
    refreshUserIdentity,
    IdentityBackendUnavailableError,
    PasskeyUnavailableError,
    PasskeyUnsupportedError,
  } from '../../lib/api.js';
  import { userIdentityState, showToast } from '../../lib/stores.svelte.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

  /**
   * PasskeyPanel — the OPTIONAL passkey lock.
   *
   * A passkey is an unlock factor only: it never signs and it never recovers
   * the account. The recovery phrase stays the only recovery credential, and
   * every state that could strand the user points at it.
   *
   * Renders `getPasskeyStatus()` → `{ available, prfSupported, enrolled,
   * locked }` as one of five states:
   *   checking    – PRF support not determined yet: neutral badge, no actions.
   *   unsupported – `prfSupported === false`: muted badge + short honest note,
   *                 no set-up button and no weaker fallback offered.
   *   setup       – secure origin, supported, not enrolled → set-up CTA.
   *   locked      – enrolled but the secret is not installed (boot, or just
   *                 after setup): unlock CTA + the recovery phrase as the
   *                 visible escape hatch.
   *   unlocked    – enrolled and installed → remove, with the trade-off stated.
   *
   * Nothing renders outside a secure origin or before an identity exists —
   * the flow is hidden, never faked. Failures that are expected conditions
   * (unsupported PRF, no passkey here, a wrong assertion that changed
   * nothing) land in an inline notice instead of an alarm.
   *
   * @param {() => void} [onChanged] - Called after any successful mutation.
   * @param {() => void} [onUseRecoveryPhrase] - Where "use my recovery phrase"
   *   goes; defaults to the identity page.
   */
  let { onChanged, onUseRecoveryPhrase } = $props();

  // PRF support is detected in the background: read now, then re-read while it
  // is undetermined (bounded) so the panel settles instead of parking.
  const PROBE_ATTEMPTS = 8;
  const PROBE_INTERVAL_MS = 250;

  let status = $state(getPasskeyStatus());
  let busy = $state(false);
  let busyLabel = $state('');
  // Inline (non-toast) notices: honest "why that didn't work" copy.
  let notice = $state(null); // { variant: 'warn'|'info', text: string } | null
  let removeConfirmOpen = $state(false);
  let probesLeft = $state(PROBE_ATTEMPTS);

  function readStatus() {
    status = getPasskeyStatus();
  }

  // Re-read whenever the identity view itself changes (create/restore/reset
  // elsewhere in the app).
  $effect(() => {
    void userIdentityState.established;
    void userIdentityState.passkeyEnrolled;
    readStatus();
  });

  // Re-read while PRF support is undetermined. Bounded: a browser that never
  // answers falls through to the set-up state, where the create-time PRF
  // result makes the final call (and says so honestly if it is no).
  $effect(() => {
    if (!status || !status.available || status.prfSupported != null || probesLeft <= 0) return;
    const timer = setTimeout(() => {
      probesLeft -= 1;
      readStatus();
    }, PROBE_INTERVAL_MS);
    return () => clearTimeout(timer);
  });

  let phase = $derived.by(() => {
    if (!status || !status.available || !userIdentityState.established) return null;
    if (status.enrolled) return status.locked ? 'locked' : 'unlocked';
    if (status.prfSupported === false) return 'unsupported';
    if (status.prfSupported == null && probesLeft > 0) return 'checking';
    return 'setup';
  });

  let view = $derived.by(() => {
    switch (phase) {
      case 'checking':
        return {
          badge: { variant: 'muted', label: 'Checking…' },
          title: 'Unlock with a passkey',
          sub: 'Checking whether this browser can offer passkey unlock.',
          note: null,
          lockIcon: false,
        };
      case 'unsupported':
        return {
          badge: { variant: 'muted', label: 'Not available' },
          title: 'Unlock with a passkey',
          sub: 'Passkeys can’t unlock Cawala in this browser — the device feature behind it (WebAuthn PRF) isn’t supported here.',
          note: 'Nothing is wrong with your account: your recovery phrase still opens it, on any device.',
          lockIcon: false,
        };
      case 'setup':
        return {
          badge: { variant: 'muted', label: 'Not set up' },
          title: 'Unlock with a passkey',
          sub: 'Use your fingerprint, face, or device PIN to unlock Cawala on this device.',
          note: 'A passkey is a shortcut, not a backup: it only unlocks this device and can’t recover your account — your recovery phrase does that. Once it’s on, opening Cawala here asks for the passkey.',
          lockIcon: false,
        };
      case 'locked':
        return {
          badge: { variant: 'warn', label: 'Locked' },
          title: 'Cawala is locked on this device',
          sub: 'Your keys are sealed behind your passkey. Unlock with your fingerprint, face, or device PIN to use Cawala again.',
          note: 'No passkey here? Your recovery phrase is the only way back in — restore those words on this device to open your account.',
          lockIcon: true,
        };
      case 'unlocked':
        return {
          badge: { variant: 'ok', label: 'Unlocked' },
          title: 'Biometric unlock is on',
          sub: 'Your fingerprint, face, or device PIN opens Cawala on this device.',
          note: 'Remove it and your key goes back to plain storage on this device — Cawala then opens here with no unlock at all. Your recovery phrase is unchanged.',
          lockIcon: false,
        };
      default:
        return null;
    }
  });

  /**
   * Map an error to an inline notice. Expected conditions explain themselves
   * in place; anything else is left to the caller's toast.
   * @param {unknown} err
   * @param {string} [untypedFailure] Copy for a failure with no dedicated class
   *   (a wrong assertion during unlock — a no-op that changed nothing).
   */
  function toNotice(err, untypedFailure) {
    if (err instanceof PasskeyUnsupportedError) return { variant: 'warn', text: err.message };
    if (err instanceof PasskeyUnavailableError) return { variant: 'warn', text: err.message };
    if (err instanceof IdentityBackendUnavailableError) return { variant: 'info', text: err.message };
    if (untypedFailure) return { variant: 'warn', text: untypedFailure };
    return null;
  }

  async function run(action, opts) {
    notice = null;
    busy = true;
    busyLabel = opts.busyLabel;
    try {
      await action();
      refreshUserIdentity();
      readStatus();
      showToast(opts.success, 'ok');
      onChanged?.();
    } catch (err) {
      readStatus();
      const inline = toNotice(err, opts.untypedFailure);
      if (inline) notice = inline;
      else showToast(err?.message || 'That didn’t work.', 'danger');
    } finally {
      busy = false;
    }
  }

  function handleEnroll() {
    return run(() => enrollPasskey(), {
      busyLabel: 'Setting up…',
      success: 'Passkey set up. This device now needs it to open Cawala.',
    });
  }

  function handleUnlock() {
    return run(() => unlockWithPasskey(), {
      busyLabel: 'Unlocking…',
      success: 'Unlocked with your passkey.',
      untypedFailure:
        'That passkey didn’t unlock this device — nothing changed. Try again, or use your recovery phrase.',
    });
  }

  function handleRemove() {
    removeConfirmOpen = true;
  }

  function confirmRemove() {
    removeConfirmOpen = false;
    return run(() => removePasskey(), {
      busyLabel: 'Removing…',
      success: 'Passkey removed. Your recovery phrase is unchanged.',
    });
  }

  function useRecoveryPhrase() {
    if (onUseRecoveryPhrase) onUseRecoveryPhrase();
    else navigate(ROUTES.IDENTITY);
  }
</script>

{#if view}
  <div
    class="passkey"
    class:passkey--locked={phase === 'locked'}
    class:passkey--unsupported={phase === 'unsupported'}
  >
    <div class="passkey-head">
      <span
        class="passkey-icon"
        class:passkey-icon--lock={view.lockIcon}
        class:passkey-icon--dim={phase === 'unsupported'}
        aria-hidden="true"
      >
        {#if view.lockIcon}
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        {:else}
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
        {/if}
      </span>
      <div class="passkey-head-text">
        <h4 class="passkey-title">{view.title}</h4>
        <p class="passkey-sub text-xs muted">{view.sub}</p>
      </div>
      <Badge variant={view.badge.variant} label={view.badge.label} />
    </div>

    {#if view.note}
      <p class="passkey-note text-xs muted">{view.note}</p>
    {/if}

    {#if notice}
      <p
        class="passkey-notice passkey-notice--{notice.variant}"
        role="status"
      >
        {notice.text}
      </p>
    {/if}

    {#if phase === 'setup' || phase === 'locked' || phase === 'unlocked'}
      <div class="passkey-actions">
        {#if phase === 'setup'}
          <button type="button" class="btn btn--primary" disabled={busy} onclick={handleEnroll}>
            {busy ? busyLabel : 'Set up biometric unlock'}
          </button>
        {:else if phase === 'locked'}
          <button type="button" class="btn btn--primary" disabled={busy} onclick={handleUnlock}>
            {busy ? busyLabel : 'Unlock with passkey'}
          </button>
          <button type="button" class="passkey-link" disabled={busy} onclick={useRecoveryPhrase}>
            Use my recovery phrase
          </button>
        {:else}
          <button type="button" class="btn btn--quiet" disabled={busy} onclick={handleRemove}>
            {busy ? busyLabel : 'Remove passkey'}
          </button>
        {/if}
      </div>
    {/if}
  </div>

  <!-- Removing puts the key back in plain storage: one explicit confirm. -->
  <ConfirmDialog
    open={removeConfirmOpen}
    title="Remove passkey?"
    message="Your key goes back to plain storage on this device, so Cawala opens here without any unlock — anyone who can use this browser can use your account. Your recovery phrase is unchanged."
    confirmLabel="Remove passkey"
    variant="danger"
    onConfirm={confirmRemove}
    onCancel={() => (removeConfirmOpen = false)}
  />
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
    transition: border-color var(--duration-normal) var(--ease),
                background var(--duration-normal) var(--ease);
  }

  /* Locked is a blocking state, not a setting: say so in the surface itself. */
  .passkey--locked {
    border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
    background: color-mix(in srgb, var(--warn-dim) 55%, var(--bg));
  }

  /* Unsupported: present but inert — dashed edge reads "not offered here". */
  .passkey--unsupported {
    border-style: dashed;
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
    transition: color var(--duration-normal) var(--ease);
  }
  .passkey-icon--lock {
    color: var(--warn);
  }
  .passkey-icon--dim {
    color: var(--muted);
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
  .passkey--locked .passkey-note {
    background: color-mix(in srgb, var(--bg) 72%, transparent);
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
  .btn--quiet {
    background: transparent;
    color: var(--muted);
  }
  .btn--quiet:hover:not(:disabled) {
    color: var(--danger);
  }

  /* The escape hatch out of a locked state: quieter than the unlock action,
     but never hidden. */
  .passkey-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--accent);
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
    transition: color var(--duration-fast) var(--ease),
                opacity var(--duration-fast) var(--ease);
  }
  .passkey-link:hover:not(:disabled) {
    color: var(--accent-hover);
  }
  .passkey-link:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .text-xs { font-size: var(--text-xs); }
  .muted { color: var(--muted); }
</style>
