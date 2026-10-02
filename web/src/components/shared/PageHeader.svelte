<script>
  /**
   * PageHeader — the top block of a page: optional title, a one-line
   * description of what the page is scoped to, and right-aligned actions.
   *
   * The TopBar already carries the nav title on desktop, so admin pages
   * normally pass a description only (which node is being administered).
   *
   * @param {string} [title]
   * @param {string} [description]
   * @param {Array} [actions] snippet list rendered on the right
   */
  let { title = '', description = '', actions = null, children = null } = $props();
</script>

<div class="page-header">
  <div class="page-header-text">
    {#if title}
      <h2 class="page-title">{title}</h2>
    {/if}
    {#if description}
      <p class="page-description text-sm muted">{description}</p>
    {:else if children}
      <div class="page-description text-sm muted">{@render children()}</div>
    {/if}
  </div>
  {#if actions}
    <div class="page-actions">{@render actions()}</div>
  {/if}
</div>

<style>
  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--sp-4);
    flex-wrap: wrap;
  }
  .page-header-text {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
  .page-title {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--fg);
  }
  .page-description {
    line-height: var(--leading-normal);
  }
  .page-actions {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-shrink: 0;
  }
</style>
