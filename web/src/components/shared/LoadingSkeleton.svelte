<script>
  /**
   * LoadingSkeleton — pulse-animated placeholder rows.
   * @param {number} [rows=3]
   * @param {number[]} [widths] - Array of percentage widths per column per row.
   */
  let { rows = 3, widths } = $props();

  const defaultWidths = [70, 40, 55, 30];
</script>

<div class="skeleton-table" role="status" aria-label="Loading">
  <span class="sr-only">Loading…</span>
  {#each Array(rows) as _, i}
    <div class="skeleton-row">
      {#each (widths || defaultWidths).slice(0, 4) as w, j}
        <div class="skeleton-cell">
          <div class="skeleton" style="width: {w}%; height: 16px;"></div>
        </div>
      {/each}
    </div>
  {/each}
</div>

<style>
  .skeleton-table {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .skeleton-row {
    display: flex;
    gap: var(--sp-4);
    padding: var(--sp-2) 0;
  }
  .skeleton-cell {
    flex: 1;
  }
</style>
