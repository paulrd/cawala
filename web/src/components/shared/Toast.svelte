<script>
  import { getToasts, dismissToast } from '../../lib/stores.js';

  /**
   * Toast — notification toasts.
   * Reads directly from the global toast store.
   */
  let toasts = $derived(getToasts());
</script>

{#if toasts.length > 0}
  <div class="toast-container" aria-live="polite" aria-label="Notifications">
    {#each toasts as toast (toast.id)}
      <div
        class="toast toast--{toast.variant}"
        role="alert"
      >
        <span class="toast-icon" aria-hidden="true">
          {#if toast.variant === 'ok'}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
          {:else if toast.variant === 'danger'}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          {:else if toast.variant === 'warn'}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
          {:else}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
          {/if}
        </span>
        <span class="toast-message">{toast.message}</span>
        <button
          type="button"
          class="toast-dismiss"
          onclick={() => dismissToast(toast.id)}
          aria-label="Dismiss"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg>
        </button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .toast-container {
    position: fixed;
    top: var(--sp-4);
    right: var(--sp-4);
    z-index: 2000;
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    pointer-events: none;
    max-width: 380px;
  }
  .toast {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-3) var(--sp-4);
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--bg-raised);
    box-shadow: var(--shadow-md);
    font-size: var(--text-sm);
    pointer-events: auto;
  }
  .toast--ok { border-color: var(--ok); }
  .toast--danger { border-color: var(--danger); }
  .toast--warn { border-color: var(--warn); }
  .toast--info { border-color: var(--accent); }
  .toast-icon {
    flex-shrink: 0;
    display: flex;
  }
  .toast--ok .toast-icon { color: var(--ok); }
  .toast--danger .toast-icon { color: var(--danger); }
  .toast--warn .toast-icon { color: var(--warn); }
  .toast--info .toast-icon { color: var(--accent); }
  .toast-message {
    flex: 1;
    color: var(--fg);
  }
  .toast-dismiss {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: var(--sp-1);
    border-radius: var(--radius-sm);
  }
  .toast-dismiss:hover {
    color: var(--fg);
  }
</style>
