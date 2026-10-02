<script>
  import ConfirmDialog from './ConfirmDialog.svelte';

  /**
   * UnlockAdminKeyDialog — passphrase prompt for a protected (passphrase-wrapped)
   * admin value seed. A thin wrapper over `ConfirmDialog` so the modal, focus
   * trap, and escape/cancel patterns are shared.
   *
   * Honest copy: the passphrase is used locally to unwrap the key; it is never
   * sent anywhere. The wrap adds an unlock step and protects at-rest copies, but
   * it does not stop in-session XSS while unlocked.
   *
   * @param {boolean} open
   * @param {string} [title]
   * @param {string} [message]
   * @param {string} [confirmLabel]
   * @param {boolean} [busy]
   * @param {string|null} [error]
   * @param {boolean} [requireConfirm] require a matching confirmation field (protect)
   * @param {function} [onSubmit] - (passphrase) => void
   * @param {function} [onCancel]
   */
  let {
    open = false,
    title = 'Unlock value key',
    message = 'Enter the passphrase that protects this value key. It is used locally to unwrap the key and is never sent anywhere.',
    confirmLabel = 'Unlock',
    busy = false,
    error = null,
    requireConfirm = false,
    onSubmit,
    onCancel,
  } = $props();

  let passphrase = $state('');
  let confirmPassphrase = $state('');
  let localError = $state(null);

  // Reset the fields each time the dialog opens.
  $effect(() => {
    if (open) {
      passphrase = '';
      confirmPassphrase = '';
      localError = null;
    }
  });

  let displayedError = $derived(localError ?? error);

  function handleConfirm() {
    if (requireConfirm && passphrase !== confirmPassphrase) {
      localError = 'Passphrases do not match.';
      return;
    }
    localError = null;
    onSubmit?.(passphrase);
  }
</script>

<ConfirmDialog
  {open}
  {title}
  {message}
  confirmLabel={busy ? 'Working…' : confirmLabel}
  onConfirm={handleConfirm}
  {onCancel}
>
  <div class="passphrase-field">
    <label class="field-label" for="unlock-passphrase">Passphrase</label>
    <input
      id="unlock-passphrase"
      type="password"
      class="field-input"
      bind:value={passphrase}
      disabled={busy}
      autocomplete="off"
    />
    {#if requireConfirm}
      <label class="field-label" for="unlock-passphrase-confirm">Confirm passphrase</label>
      <input
        id="unlock-passphrase-confirm"
        type="password"
        class="field-input"
        bind:value={confirmPassphrase}
        disabled={busy}
        autocomplete="off"
      />
    {/if}
    {#if displayedError}
      <span class="field-error">{displayedError}</span>
    {/if}
  </div>
</ConfirmDialog>

<style>
  .passphrase-field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .field-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .field-input {
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-sm);
  }
  .field-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .field-error {
    font-size: var(--text-xs);
    color: var(--danger);
  }
</style>
