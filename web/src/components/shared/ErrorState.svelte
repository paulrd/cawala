<script>
  /**
   * ErrorState — error display with retry.
   * @param {string} message
   * @param {function} [onRetry]
   */
  let { message = 'Something went wrong', onRetry } = $props();
</script>

<div class="error-state">
  <div class="error-icon" aria-hidden="true">
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M12 8v4"/>
      <path d="M12 16h.01"/>
    </svg>
  </div>
  <p class="error-message">{message}</p>
  {#if onRetry}
    <button type="button" class="retry-btn" onclick={onRetry}>
      Retry
    </button>
  {/if}
</div>

<style>
  .error-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    padding: var(--sp-8) var(--sp-6);
    gap: var(--sp-3);
  }
  .error-icon {
    color: var(--danger);
  }
  .error-message {
    font-size: var(--text-sm);
    color: var(--muted);
    max-width: 360px;
  }
  .retry-btn {
    margin-top: var(--sp-2);
    padding: var(--sp-2) var(--sp-4);
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .retry-btn:hover {
    background: var(--accent-dim);
  }
</style>
