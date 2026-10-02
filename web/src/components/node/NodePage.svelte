<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ChildrenTable from '../shared/ChildrenTable.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import GrantEmptyState from '../admin/GrantEmptyState.svelte';
  import {
    clientState,
    nodeState,
    loadingState,
    errorState,
    administeredNode,
    adminCapabilities,
    targetEpoch,
  } from '../../lib/stores.svelte.js';
  import { getChildren } from '../../lib/api.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';

  // One layout for both node kinds and both modes: this page reports the
  // selected administered node, not an implicit "first grant".
  let view = administeredNode;

  let nodeIdText = $derived(view.isSelf ? clientState.endpointId || '—' : view.nodeId || '—');
  let addressValue = $derived(view.isSelf ? clientState.address : view.address);
  let canQuery = $derived(adminCapabilities.canQueryNode);

  /** Load the selected node's children (target comes from the api layer). */
  async function loadChildren() {
    loadingState.children = true;
    errorState.children = null;
    try {
      nodeState.children = await getChildren();
    } catch (err) {
      errorState.children = err?.message || 'Failed to load children';
    } finally {
      loadingState.children = false;
    }
  }

  // Refetch on mount and whenever the administered node changes.
  $effect(() => {
    void targetEpoch.value;
    void loadChildren();
  });
</script>

<div class="node-page">
  <Card title="Administered Node">
    <div class="node-info">
      <div class="info-row">
        <span class="info-label muted">Address</span>
        {#if addressValue}
          <Address address={addressValue} size="md" />
        {:else}
          <span class="text-sm muted">Not assigned yet</span>
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label muted">Node ID</span>
        {#if view.isSelf}
          <EndpointId id={clientState.endpointId} />
        {:else}
          <code class="text-sm mono">{nodeIdText}</code>
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label muted">Kind</span>
        <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />
        <span class="text-xs muted">Inferred from the node's children: a node child means internal, only users means leaf.</span>
      </div>
      {#if addressValue}
        <div class="info-row">
          <span class="info-label muted">Parent</span>
          <span class="text-sm muted">Derived from join handshake</span>
        </div>
      {/if}
    </div>
  </Card>

  <Card title="Children">
    {#snippet actions()}
      <button
        type="button"
        class="btn btn--ghost btn--sm"
        onclick={loadChildren}
        disabled={loadingState.children}
      >
        {loadingState.children ? 'Loading…' : 'Refresh'}
      </button>
    {/snippet}

    {#if !canQuery}
      <GrantEmptyState
        title="Children of this node need a delegated key"
        message="This browser cannot query the selected node for its topology. Generate an admin key in Settings and ask the operator to grant it, then refresh."
      />
    {:else if loadingState.children && nodeState.children.length === 0}
      <LoadingSkeleton rows={3} />
    {:else if errorState.children}
      <ErrorState message={errorState.children} onRetry={loadChildren} />
    {:else}
      <ChildrenTable
        rows={nodeState.children}
        emptyTitle="No children"
        emptyMessage="This node's topology snapshot shows no children."
        actionLabel="View Join Requests"
        onAction={() => navigate(ROUTES.JOINS)}
      />
    {/if}
  </Card>
</div>

<style>
  .node-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .node-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .info-row {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    flex-wrap: wrap;
  }
  .info-label {
    min-width: 100px;
    font-size: var(--text-sm);
    font-weight: 500;
  }

  /* Button styles (same shape as every page's buttons). */
  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
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
  .btn--sm {
    font-size: var(--text-xs);
    padding: var(--sp-1) var(--sp-2);
  }
</style>
