<script>
  /**
   * Badge — small status indicator.
   * @param {string} variant - 'ok' | 'warn' | 'danger' | 'info' | 'muted'
   * @param {string} label
   * @param {boolean} [dot=false] - Show a dot instead of full badge.
   */
  let { variant = 'info', label = '', dot = false } = $props();
</script>

{#if dot}
  <span class="dot dot--{variant}" title={label} aria-label={label}></span>
{:else}
  <span class="badge badge--{variant}">{label}</span>
{/if}

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    padding: 2px var(--sp-2);
    border-radius: var(--radius-sm);
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 1.4;
    white-space: nowrap;
  }
  .badge--ok {
    background: var(--ok-dim);
    color: var(--ok);
  }
  .badge--warn {
    background: var(--warn-dim);
    color: var(--warn);
  }
  .badge--danger {
    background: var(--danger-dim);
    color: var(--danger);
  }
  .badge--info {
    background: var(--accent-dim);
    color: var(--accent);
  }
  .badge--muted {
    background: var(--bg-hover);
    color: var(--muted);
  }
  .dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot--ok { background: var(--ok); }
  .dot--warn { background: var(--warn); }
  .dot--danger { background: var(--danger); }
  .dot--info { background: var(--accent); }
  .dot--muted { background: var(--muted); }
</style>
