<script>
  import AdminNodeRow from './AdminNodeRow.svelte';
  import Badge from '../shared/Badge.svelte';
  import { administeredNode, clientState, uiState } from '../../lib/stores.svelte.js';
  import { setAdministeredNode, listAdministeredNodes } from '../../lib/api.js';
  import { buildSelectorItems, shortId, ADMIN_STATUS } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

  /**
   * NodeSelector — switch which node this console administers.
   *
   * @param {'bar'|'chip'} [variant] `bar` sits in the context bar, `chip` in MobileNav.
   * @param {string} [owner] which instance owns the open dropdown ('bar'|'chip').
   */
  let { variant = 'bar', owner = 'bar' } = $props();

  let rootEl = $state(null);
  let nodes = $state([]);
  let now = $state(Date.now());

  // Plain handle (never $state): a $effect that reads and writes a reactive
  // timer handle trips Svelte's infinite-loop guard.
  let _tick = null;

  $effect(() => {
    _tick = setInterval(() => {
      now = Date.now();
    }, 60_000);
    return () => clearInterval(_tick);
  });

  let open = $derived(uiState.selectorOwner === owner);
  let locked = $derived(uiState.dialogOpen || uiState.writeInFlight);

  // The store is the single reactive view of the selection; api re-publishes
  // it after every selection change or probe.
  let view = administeredNode;
  let selectedId = $derived(view.nodeId);
  let selectedLabel = $derived(
    view.nodeId === 'mock'
      ? 'Mock node'
      : view.isSelf
        ? 'This browser'
        : view.label || shortId(view.nodeId || ''),
  );

  let groups = $derived(
    buildSelectorItems({
      self: { endpointId: clientState.endpointId },
      mock: view.mock,
      nodes,
      selected: selectedId,
      now,
    }).groups,
  );

  function toggle() {
    if (locked) return;
    if (open) {
      close();
      return;
    }
    nodes = listAdministeredNodes();
    now = Date.now();
    uiState.selectorOwner = owner;
  }

  function close() {
    if (uiState.selectorOwner === owner) uiState.selectorOwner = null;
  }

  /** @param {{ id: string }} item */
  function select(item) {
    if (item.disabled || item.selected) {
      close();
      return;
    }
    try {
      setAdministeredNode(item.id);
    } catch {
      /* unknown/removed target: keep the current selection */
    }
    close();
  }

  function goToSettings() {
    close();
    navigate(ROUTES.SETTINGS);
  }

  function onDocumentClick(e) {
    if (!open) return;
    if (rootEl && !rootEl.contains(e.target)) close();
  }

  function onDocumentKeydown(e) {
    if (e.key === 'Escape' && open) close();
  }

  $effect(() => {
    document.addEventListener('click', onDocumentClick, true);
    document.addEventListener('keydown', onDocumentKeydown);
    return () => {
      document.removeEventListener('click', onDocumentClick, true);
      document.removeEventListener('keydown', onDocumentKeydown);
    };
  });
</script>

<div class="node-selector node-selector--{variant}" bind:this={rootEl}>
  <button
    type="button"
    class="selector-trigger"
    class:selector-trigger--open={open}
    aria-haspopup="listbox"
    aria-expanded={open}
    aria-label="Select the node to administer"
    title={locked ? 'Finish or cancel the current action to switch nodes' : 'Switch the node you are administering'}
    disabled={locked}
    onclick={toggle}
  >
    <span class="trigger-text">
      <span class="trigger-label">{selectedLabel}</span>
      {#if view.nodeId && !view.isSelf}
        <span class="trigger-id text-xs muted">{shortId(view.nodeId)}</span>
      {/if}
    </span>
    <span class="trigger-badges">
      {#if !view.isSelf || view.status !== ADMIN_STATUS.SELF}
        <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />
      {/if}
    </span>
    <svg class="trigger-chevron" class:trigger-chevron--up={open} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  </button>

  {#if open}
    <div class="selector-menu" role="listbox" aria-label="Administered nodes">
      {#each groups as group (group.id)}
        <div class="menu-group">
          {#if group.id !== 'context'}
            <div class="menu-group-label text-xs muted">{group.label}</div>
          {/if}
          <div class="menu-group-items">
            {#each group.items as item (item.id)}
              <button
                type="button"
                class="menu-item"
                role="option"
                aria-selected={item.selected}
                disabled={item.disabled}
                onclick={() => select(item)}
              >
                <AdminNodeRow {item} variant="compact" />
              </button>
            {/each}
          </div>
        </div>
      {/each}

      {#if groups.every((g) => g.items.length <= (g.id === 'context' ? (view.mock ? 2 : 1) : 0))}
        <p class="menu-empty text-xs muted">No granted nodes yet.</p>
      {/if}

      <div class="menu-footer">
        <button type="button" class="menu-footer-btn" onclick={goToSettings}>
          + Add a node
        </button>
        <button type="button" class="menu-footer-btn" onclick={goToSettings}>
          Manage
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .node-selector {
    position: relative;
    min-width: 0;
  }

  .selector-trigger {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
    max-width: 100%;
    transition:
      background var(--duration-fast) var(--ease),
      border-color var(--duration-fast) var(--ease);
  }
  .selector-trigger:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--accent);
  }
  .selector-trigger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .selector-trigger--open {
    border-color: var(--accent);
    background: var(--bg-hover);
  }
  .node-selector--chip .selector-trigger {
    flex-direction: column;
    gap: 2px;
    padding: var(--sp-1) var(--sp-2);
    font-size: 10px;
    border: none;
    background: transparent;
  }
  .node-selector--chip .trigger-badges,
  .node-selector--chip .trigger-id {
    display: none;
  }
  .node-selector--chip .trigger-chevron {
    display: none;
  }

  .trigger-text {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    line-height: 1.2;
    min-width: 0;
  }
  .trigger-label {
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 180px;
  }
  .trigger-id {
    font-family: var(--mono);
  }
  .trigger-badges {
    display: flex;
    align-items: center;
    gap: var(--sp-1);
  }
  .trigger-chevron {
    flex-shrink: 0;
    color: var(--muted);
    transition: transform var(--duration-fast) var(--ease);
  }
  .trigger-chevron--up {
    transform: rotate(180deg);
  }

  .selector-menu {
    position: absolute;
    top: calc(100% + var(--sp-2));
    left: 0;
    z-index: 200;
    width: min(380px, calc(100vw - var(--sp-8)));
    max-height: 60vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-3);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
  }
  .node-selector--chip .selector-menu {
    left: auto;
    right: 0;
    top: auto;
    bottom: calc(100% + var(--sp-2));
  }

  .menu-group {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .menu-group-label {
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .menu-group-items {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .menu-item {
    display: block;
    width: 100%;
    padding: 0;
    border: none;
    background: transparent;
    font: inherit;
    text-align: left;
    cursor: pointer;
    border-radius: var(--radius-md);
  }
  .menu-item:disabled {
    cursor: not-allowed;
  }
  .menu-item:not(:disabled):hover :global(.admin-node-row) {
    border-color: var(--accent);
  }
  .menu-empty {
    padding: var(--sp-2) 0;
  }
  .menu-footer {
    display: flex;
    gap: var(--sp-2);
    padding-top: var(--sp-2);
    border-top: 1px solid var(--border);
  }
  .menu-footer-btn {
    flex: 1;
    padding: var(--sp-2);
    background: transparent;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    color: var(--muted);
    font: inherit;
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    transition:
      color var(--duration-fast) var(--ease),
      border-color var(--duration-fast) var(--ease);
  }
  .menu-footer-btn:hover {
    color: var(--fg);
    border-color: var(--accent);
  }
</style>
