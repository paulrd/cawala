<script>
  import Badge from '../shared/Badge.svelte';
  import { formatDate } from '../../lib/utils.js';

  /**
   * AdminNodeRow — one administered node, in both surfaces:
   *  - `compact`: a row in the node selector dropdown.
   *  - `full`: a row in Settings' "Administered nodes" list (dates + actions).
   *
   * It renders a normalized item from `lib/adminView.js` (`grantToItem()` or
   * `buildSelectorItems()`), so the selector and Settings can never drift.
   *
   * @param {object} item
   * @param {'compact'|'full'} [variant]
   * @param {function} [onSelect]
   * @param {function} [onRemove]
   */
  let { item, variant = 'full', onSelect = undefined, onRemove = undefined } = $props();
</script>

<div
  class="admin-node-row"
  class:admin-node-row--full={variant === 'full'}
  class:admin-node-row--selected={item.selected}
  class:admin-node-row--disabled={item.disabled}
>
  <div class="admin-node-main">
    <div class="admin-node-title">
      <span class="admin-node-label">{item.label}</span>
      {#if item.kindLabel}
        <Badge variant={item.kindVariant} label={item.kindLabel} />
      {/if}
      <Badge variant={item.statusBadge.variant} label={item.statusBadge.label} />
      {#if item.sourceBadge}
        <Badge variant={item.sourceBadge.variant} label={item.sourceBadge.label} />
      {/if}
      {#if item.selected}
        <Badge variant="info" label="Selected" />
      {/if}
    </div>

    <div class="admin-node-meta text-xs muted">
      {#if item.sublabel}
        <code>{item.sublabel}</code>
      {/if}
      {#if item.nodeAddr}
        <span>Address {item.nodeAddr}</span>
      {/if}
      {#if item.ttl}
        <span>{item.ttl}</span>
      {/if}
      {#if item.isSelf}
        <span>Your own node on this device</span>
      {/if}
    </div>

    {#if variant === 'full'}
      <div class="admin-node-detail text-xs muted">
        {#if item.grantedAt}
          <span>Granted {formatDate(item.grantedAt)}</span>
        {/if}
        {#if item.expiresAt}
          <span>Expires {formatDate(item.expiresAt)}</span>
        {/if}
        {#if item.scopes?.length}
          <span>Scope: {item.scopes.join(', ')}</span>
        {/if}
      </div>
    {/if}
  </div>

  {#if variant === 'full'}
    <div class="admin-node-actions">
      {#if onSelect}
        <button
          type="button"
          class="btn btn--ghost btn--sm"
          disabled={item.selected || item.disabled}
          onclick={() => onSelect(item)}
        >
          {item.selected ? 'In use' : 'Administer'}
        </button>
      {/if}
      {#if onRemove}
        <button type="button" class="btn btn--danger-outline btn--sm" onclick={() => onRemove(item)}>
          Remove
        </button>
      {/if}
    </div>
  {/if}
</div>

<style>
  .admin-node-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    text-align: left;
    width: 100%;
    min-width: 0;
  }
  .admin-node-row--full {
    padding: var(--sp-3) var(--sp-4);
  }
  .admin-node-row--selected {
    border-color: var(--accent);
    background: var(--accent-dim);
  }
  .admin-node-row--disabled {
    opacity: 0.65;
  }
  .admin-node-main {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
  .admin-node-title {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .admin-node-label {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 200px;
  }
  .admin-node-meta,
  .admin-node-detail {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .admin-node-meta code {
    font-family: var(--mono);
    background: none;
    border: none;
    padding: 0;
  }
  .admin-node-actions {
    display: flex;
    gap: var(--sp-2);
    flex-shrink: 0;
  }

  /* Buttons (mirrors the shared page button styles). */
  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
    white-space: nowrap;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn--ghost {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .btn--danger-outline {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .btn--danger-outline:hover {
    background: var(--danger-dim);
  }
  .btn--sm {
    font-size: var(--text-xs);
    padding: var(--sp-1) var(--sp-2);
  }

  @media (max-width: 480px) {
    .admin-node-row {
      flex-direction: column;
      align-items: stretch;
    }
    .admin-node-actions {
      justify-content: flex-end;
    }
  }
</style>
