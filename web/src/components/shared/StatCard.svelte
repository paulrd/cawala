<script>
  import Card from './Card.svelte';

  /**
   * StatCard — one summary figure with an optional meta line.
   * The value is the default content (component or text); `meta` is an
   * optional snippet rendered underneath for badges/links.
   *
   * @param {string} title
   * @param {string} [hint] small muted line under the title
   */
  let { title, hint = '', children = null, meta = null } = $props();
</script>

<Card {title} compact>
  <div class="stat-value">
    {#if children}{@render children()}{:else}<span class="muted">&mdash;</span>{/if}
  </div>
  {#if hint}
    <p class="stat-hint text-sm muted">{hint}</p>
  {/if}
  {#if meta}
    <div class="stat-meta">{@render meta()}</div>
  {/if}
</Card>

<style>
  .stat-value {
    font-size: var(--text-xl);
    font-weight: 700;
    line-height: var(--leading-tight);
    color: var(--fg);
    margin-bottom: var(--sp-1);
    overflow-wrap: anywhere;
  }
  .stat-hint {
    line-height: var(--leading-normal);
  }
  .stat-meta {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
    margin-top: var(--sp-2);
    font-size: var(--text-sm);
  }
</style>
