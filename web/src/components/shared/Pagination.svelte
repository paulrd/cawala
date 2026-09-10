<script>
  /**
   * Pagination — simple page controls.
   * @param {number} page - Current page (0-indexed).
   * @param {number} totalPages
   * @param {function} onPageChange - (newPage) => void
   */
  let { page = 0, totalPages = 1, onPageChange } = $props();

  function prev() {
    if (page > 0) onPageChange?.(page - 1);
  }
  function next() {
    if (page < totalPages - 1) onPageChange?.(page + 1);
  }
</script>

{#if totalPages > 1}
  <nav class="pagination" aria-label="Pagination">
    <button
      type="button"
      class="page-btn"
      disabled={page === 0}
      onclick={prev}
      aria-label="Previous page"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>
    </button>
    <span class="page-info">
      {page + 1} / {totalPages}
    </span>
    <button
      type="button"
      class="page-btn"
      disabled={page >= totalPages - 1}
      onclick={next}
      aria-label="Next page"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
    </button>
  </nav>
{/if}

<style>
  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-3);
    padding: var(--sp-3) 0;
  }
  .page-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--fg);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .page-btn:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .page-btn:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }
  .page-info {
    font-size: var(--text-xs);
    color: var(--muted);
    min-width: 48px;
    text-align: center;
  }
</style>
