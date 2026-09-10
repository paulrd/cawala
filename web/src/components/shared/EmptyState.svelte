<script>
  /**
   * EmptyState — shown when a list/section has no data.
   * @param {string} title
   * @param {string} [message]
   * @param {string} [actionLabel]
   * @param {function} [onAction]
   */
  let { title = 'Nothing here yet', message = '', actionLabel = '', onAction } = $props();
</script>

<div class="empty-state">
  <div class="empty-icon" aria-hidden="true">
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M8 12h8"/>
    </svg>
  </div>
  <p class="empty-title">{title}</p>
  {#if message}
    <p class="empty-message">{message}</p>
  {/if}
  {#if actionLabel && onAction}
    <button type="button" class="empty-action" onclick={onAction}>
      {actionLabel}
    </button>
  {/if}
</div>

<style>
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    padding: var(--sp-10) var(--sp-6);
    gap: var(--sp-3);
  }
  .empty-icon {
    color: var(--border);
    margin-bottom: var(--sp-2);
  }
  .empty-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--fg);
  }
  .empty-message {
    font-size: var(--text-sm);
    color: var(--muted);
    max-width: 360px;
  }
  .empty-action {
    margin-top: var(--sp-2);
    padding: var(--sp-2) var(--sp-4);
    background: var(--accent);
    color: var(--fg);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .empty-action:hover {
    background: var(--accent-hover);
  }
</style>
