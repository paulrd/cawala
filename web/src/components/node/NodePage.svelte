<script>
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ChildrenTable from '../shared/ChildrenTable.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import GrantEmptyState from '../admin/GrantEmptyState.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import {
    clientState,
    nodeState,
    loadingState,
    errorState,
    administeredNode,
    adminCapabilities,
    targetEpoch,
    showToast,
  } from '../../lib/stores.svelte.js';
  import {
    getChildren,
    getAccounts,
    adminDetachChild,
    adminMoveChild,
    canAdministerTopology,
    canMoveChild,
  } from '../../lib/api.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';

  // One layout for both node kinds and both modes: this page reports the
  // selected administered node, not an implicit "first grant".
  let view = administeredNode;

  let nodeIdText = $derived(view.isSelf ? clientState.endpointId || '—' : view.nodeId || '—');
  let addressValue = $derived(view.isSelf ? clientState.address : view.address);
  let canQuery = $derived(adminCapabilities.canQueryNode);
  // Topology actions need a non-self target and a topology-scoped grant.
  let canTopology = $derived(canAdministerTopology(view, adminCapabilities));

  let selectedChild = $state(null);
  let moveOpen = $state(false);
  let moveSlot = $state(0);
  let detachOpen = $state(false);
  let detachBalance = $state(null);
  let actionBusy = $state(false);

  const ALL_SLOTS = [0, 1, 2, 3, 4, 5, 6, 7];

  // Slots held by any *other* child; the selected child's own slot counts free.
  let occupiedSlots = $derived(
    new Set(
      nodeState.children
        .filter((child) => child.endpointId !== selectedChild?.endpointId)
        .map((child) => child.slot)
        .filter((slot) => slot != null),
    ),
  );
  let moveAllowed = $derived(canMoveChild(selectedChild?.kind));

  /** Load the selected node's children (target comes from the api layer). */
  async function loadChildren() {
    loadingState.children = true;
    errorState.children = null;
    try {
      nodeState.children = await getChildren();
      // Drop a selection that no longer names a present child.
      if (
        selectedChild &&
        !nodeState.children.some((child) => child.endpointId === selectedChild.endpointId)
      ) {
        selectedChild = null;
      }
    } catch (err) {
      errorState.children = err?.message || 'Failed to load children';
    } finally {
      loadingState.children = false;
    }
  }

  // Refetch on mount and whenever the administered node changes.
  $effect(() => {
    void targetEpoch.value;
    selectedChild = null;
    void loadChildren();
  });

  function handleSelectChild(row) {
    selectedChild = selectedChild?.endpointId === row.endpointId ? null : row;
  }

  function openMove() {
    if (!selectedChild || !moveAllowed) return;
    moveSlot = selectedChild.slot ?? 0;
    moveOpen = true;
  }

  async function confirmMove() {
    if (!selectedChild) return;
    actionBusy = true;
    try {
      await adminMoveChild(selectedChild.endpointId, moveSlot);
      showToast('Child re-slotted.', 'ok');
      moveOpen = false;
      selectedChild = null;
      await loadChildren();
    } catch (err) {
      showToast(err?.message || 'Move failed.', 'danger');
    } finally {
      actionBusy = false;
    }
  }

  async function openDetach() {
    if (!selectedChild) return;
    detachBalance = null;
    detachOpen = true;
    // The P3 ledger view is only readable with a value scope; when present,
    // show the child's current balance in the confirmation.
    if (adminCapabilities.scopes.value) {
      try {
        const rows = await getAccounts();
        const row = rows.find(
          (entry) => entry.type === 'liability' && entry.id === selectedChild.endpointId,
        );
        detachBalance = row ? row.balance : null;
      } catch {
        detachBalance = null;
      }
    }
  }

  async function confirmDetach() {
    if (!selectedChild) return;
    actionBusy = true;
    try {
      await adminDetachChild(selectedChild.endpointId);
      showToast('Child detached.', 'ok');
      detachOpen = false;
      selectedChild = null;
      await loadChildren();
    } catch (err) {
      showToast(err?.message || 'Detach failed.', 'danger');
    } finally {
      actionBusy = false;
    }
  }
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
        selectedId={selectedChild?.endpointId ?? null}
        onSelect={canTopology ? handleSelectChild : undefined}
      />

      {#if canTopology}
        <div class="topology-actions">
          <h4 class="topology-heading">Child actions</h4>
          {#if !selectedChild}
            <p class="text-sm muted">Select a child row to re-slot or detach it.</p>
          {:else}
            <p class="text-sm muted">
              Selected <code class="mono">{selectedChild.endpointId ? `${selectedChild.endpointId.slice(0, 12)}…` : 'child'}</code>
              {#if selectedChild.address}
                at <code class="mono">{selectedChild.address}</code>
              {/if}
            </p>
            <div class="topology-buttons">
              <button
                type="button"
                class="btn btn--ghost btn--sm"
                disabled={!moveAllowed || actionBusy}
                onclick={openMove}
              >
                Move&hellip;
              </button>
              <button
                type="button"
                class="btn btn--danger-outline btn--sm"
                disabled={actionBusy}
                onclick={openDetach}
              >
                Detach&hellip;
              </button>
            </div>
            {#if !moveAllowed}
              <p class="text-xs muted">Browser leaves cannot be re-slotted (no healing pull).</p>
            {/if}
          {/if}
        </div>
      {:else}
        <div class="topology-gate">
          <GrantEmptyState
            title="Topology actions need a topology grant"
            message="Re-slotting and detaching children requires a topology grant. Ask the node operator to grant topology scope, then refresh."
          />
        </div>
      {/if}
    {/if}
  </Card>
</div>

<ConfirmDialog
  open={moveOpen}
  title="Re-slot child?"
  message="Its address changes immediately; in-flight messages to the old address may fail."
  confirmLabel={actionBusy ? 'Moving…' : 'Move'}
  onConfirm={confirmMove}
  onCancel={() => { moveOpen = false; }}
>
  <div class="slot-picker">
    <span class="field-label">New slot</span>
    <div class="slot-grid">
      {#each ALL_SLOTS as slot (slot)}
        <button
          type="button"
          class="slot-btn"
          class:slot-btn--current={selectedChild?.slot === slot}
          class:slot-btn--selected={moveSlot === slot}
          disabled={occupiedSlots.has(slot)}
          onclick={() => { moveSlot = slot; }}
        >
          {slot}
        </button>
      {/each}
    </div>
    <span class="field-hint">Occupied slots are disabled. The current slot is preselected.</span>
  </div>
</ConfirmDialog>

<ConfirmDialog
  open={detachOpen}
  title="Detach child?"
  message="The child becomes an independent network. Any value on its account is stranded until an operator writes it off. It must re-join with a fresh invitation."
  confirmLabel={actionBusy ? 'Detaching…' : 'Detach'}
  variant="danger"
  onConfirm={confirmDetach}
  onCancel={() => { detachOpen = false; }}
>
  {#if detachBalance != null}
    <p class="text-sm">
      Current balance: <strong>{detachBalance.toLocaleString()}</strong>
    </p>
  {/if}
</ConfirmDialog>

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
  .btn--danger-outline {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .btn--danger-outline:hover:not(:disabled) {
    background: var(--danger-dim);
  }

  /* ── Child actions panel ─────────────────────────── */
  .topology-actions {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-4);
    padding-top: var(--sp-4);
    border-top: 1px solid var(--border);
  }
  .topology-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .topology-buttons {
    display: flex;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .topology-gate {
    margin-top: var(--sp-3);
  }

  /* ── Slot picker (move dialog) ───────────────────── */
  .slot-picker {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .slot-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: var(--sp-1);
  }
  .slot-btn {
    padding: var(--sp-2) 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--fg);
    font: inherit;
    font-family: var(--mono);
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .slot-btn:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .slot-btn--current {
    border-color: var(--accent);
    background: var(--accent-dim);
  }
  .slot-btn--selected {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--fg);
    font-weight: 700;
  }
  .slot-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .field-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .field-hint {
    font-size: var(--text-xs);
    color: var(--muted);
  }
</style>
