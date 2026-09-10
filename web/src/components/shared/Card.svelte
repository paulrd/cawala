<script>
  /**
   * Card — reusable container with optional title and action slot.
   * @param {string} [title]
   * @param {string} [variant='default'] - 'default' | 'error' | 'warn'
   * @param {boolean} [compact=false]
   */
  let { title, variant = 'default', compact = false, children, actions } = $props();
</script>

<div class="card" class:card--error={variant === 'error'} class:card--warn={variant === 'warn'} class:card--compact={compact}>
  {#if title || actions}
    <div class="card-header">
      {#if title}
        <h3 class="card-title">{title}</h3>
      {/if}
      {#if actions}
        <div class="card-actions">{@render actions()}</div>
      {/if}
    </div>
  {/if}
  <div class="card-body">
    {@render children()}
  </div>
</div>

<style>
  .card {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .card--error {
    border-color: var(--danger);
  }
  .card--warn {
    border-color: var(--warn);
  }
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-4) var(--sp-5);
    border-bottom: 1px solid var(--border);
  }
  .card-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .card-actions {
    display: flex;
    gap: var(--sp-2);
  }
  .card-body {
    padding: var(--sp-5);
  }
  .card--compact .card-body {
    padding: var(--sp-3) var(--sp-5);
  }
</style>
