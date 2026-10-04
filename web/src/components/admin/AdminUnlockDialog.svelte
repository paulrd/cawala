<script>
  import { tick } from 'svelte';
  import { adminPolicyInfo, unlockAdmin } from '../../lib/api.js';

  /**
   * AdminUnlockDialog — the R6 gate.
   *
   * Renders the whole `ADMIN_POLICY.md` in the dialog (never a summary), makes
   * the operator tick an explicit acknowledgement of *this* version, and only
   * then unlocks admin mode for the session. The acknowledgement is recorded
   * under the policy hash, so editing the document invalidates it and the gate
   * says so the next time it opens.
   *
   * @param {boolean} open
   * @param {function} [onCancel]
   * @param {function} [onUnlocked] called after a successful unlock
   */
  let { open = false, onCancel = () => {}, onUnlocked = () => {} } = $props();

  /** Where the rendered document lives, so the gate is auditable. */
  const POLICY_SOURCE = 'ADMIN_POLICY.md';

  let acknowledged = $state(false);
  let busy = $state(false);
  let error = $state(null);
  let dialogEl = $state(null);
  let previousFocus = $state(null);

  let policy = $derived(open ? adminPolicyInfo() : null);

  // Reset the acknowledgement every time the gate opens: unlocking always
  // requires a fresh read, even when this browser acknowledged it before.
  $effect(() => {
    if (open) {
      acknowledged = false;
      error = null;
      busy = false;
      previousFocus = document.activeElement;
      tick().then(() => {
        const first = dialogEl?.querySelector('button, input, [href], [tabindex]:not([tabindex="-1"])');
        first?.focus();
      });
    } else if (previousFocus) {
      previousFocus.focus();
      previousFocus = null;
    }
  });

  function handleKeydown(e) {
    if (!open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
      return;
    }
    if (e.key === 'Tab' && dialogEl) {
      const focusable = dialogEl.querySelectorAll('button, input, [href], [tabindex]:not([tabindex="-1"])');
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function handleBackdropClick(e) {
    if (e.target === e.currentTarget && !busy) onCancel();
  }

  async function handleUnlock() {
    if (!acknowledged || busy) return;
    busy = true;
    error = null;
    try {
      const result = await unlockAdmin();
      onUnlocked(result);
    } catch (err) {
      error = err?.message || 'Could not unlock admin mode.';
    } finally {
      busy = false;
    }
  }

  /** `a1b2c3d4` from a full hash, for the footer line. */
  function shortHash(hash) {
    return hash ? hash.slice(0, 8) : '—';
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open && policy}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="backdrop" onclick={handleBackdropClick}>
    <div
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="unlock-title"
      bind:this={dialogEl}
    >
      <header class="head">
        <span class="lock" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
        </span>
        <div>
          <h3 id="unlock-title" class="title">Unlock admin mode</h3>
          <p class="sub">Session only — reloading the page locks it again.</p>
        </div>
      </header>

      <p class="lede">
        Admin mode exposes join approval, topology changes and value issue/burn.
        Read the policy below before you continue.
      </p>

      {#if policy.acknowledgedHash && !policy.acknowledgementCurrent}
        <p class="stale" role="status">
          This browser previously acknowledged a different version of this policy
          ({shortHash(policy.acknowledgedHash)}…). The document has changed since — read the
          current version below.
        </p>
      {/if}

      <!-- The document scroller must be reachable from the keyboard: role +
           tabindex turn it into a focusable scroll region (the alertdialog
           itself does not scroll). -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <div class="policy" role="region" tabindex="0" aria-label="Admin policy">
        <pre>{policy.text}</pre>
      </div>

      <label class="ack">
        <input type="checkbox" bind:checked={acknowledged} disabled={busy} />
        <span>I have read and understand the admin policy above.</span>
      </label>

      <p class="hash mono text-xs">
        Policy {shortHash(policy.hash)}… · {POLICY_SOURCE}
      </p>

      {#if error}
        <p class="error" role="alert">{error}</p>
      {/if}

      <div class="actions">
        <button type="button" class="btn btn--ghost" onclick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button type="button" class="btn btn--primary" onclick={handleUnlock} disabled={!acknowledged || busy}>
          {#if busy}Unlocking…{:else}Unlock for this session{/if}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(2px);
    padding: var(--sp-4);
  }
  .dialog {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    width: 100%;
    max-width: 640px;
    max-height: calc(100vh - var(--sp-8));
    padding: var(--sp-6);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
    overflow: hidden;
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
  }
  .lock {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    flex-shrink: 0;
    border-radius: var(--radius-md);
    background: var(--accent-dim);
    color: var(--accent);
  }
  .title {
    font-size: var(--text-lg);
    font-weight: 600;
  }
  .sub {
    font-size: var(--text-xs);
    color: var(--muted);
  }
  .lede {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .stale {
    font-size: var(--text-xs);
    color: var(--warn);
    border: 1px solid var(--warn);
    border-radius: var(--radius-md);
    padding: var(--sp-2) var(--sp-3);
  }
  .policy {
    flex: 1;
    min-height: 160px;
    max-height: 42vh;
    overflow: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--sp-3);
    font-size: var(--text-xs);
    line-height: var(--leading-normal);
    color: var(--muted);
  }
  .policy pre {
    font-family: var(--mono);
    white-space: pre-wrap;
    word-break: break-word;
  }
  .ack {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-2);
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .ack input {
    margin-top: 2px;
    accent-color: var(--accent);
  }
  .hash {
    color: var(--muted);
  }
  .error {
    font-size: var(--text-sm);
    color: var(--danger);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-3);
  }
  .btn {
    padding: var(--sp-2) var(--sp-4);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
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
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover:not(:disabled) {
    background: var(--bg-hover);
  }
</style>
