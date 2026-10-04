<script>
  import Card from '../shared/Card.svelte';
  import PageHeader from '../shared/PageHeader.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ChildrenTable from '../shared/ChildrenTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import AdminTargetSwitcher from './AdminTargetSwitcher.svelte';
  import AdminUnlockDialog from './AdminUnlockDialog.svelte';
  import {
    clientState,
    nodeState,
    loadingState,
    errorState,
    administeredNode,
    adminCapabilities,
    adminLock,
    targetEpoch,
    showToast,
  } from '../../lib/stores.svelte.js';
  import {
    getJoinRequests,
    approveJoin,
    rejectJoin,
    redeliverJoin,
    getChildren,
    getAdministrators,
    adminDetachChild,
    adminMoveChild,
    adminDesignate,
    adminRevoke,
    canAdministerTopology,
    canMoveChild,
    getAccounts,
    canAdministerValue,
    adminIssue,
    adminBurn,
    readPendingValueOp,
    clearPendingValueOp,
    retryPendingValueOp,
    createChild,
    leave,
    lockAdminMode,
    adminPolicyInfo,
    isMockMode,
    AdminUnavailableError,
  } from '../../lib/api.js';
  import { valueReasonErrorVisible, shortId, statusBadge } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant, childRoleLabel } from '../../lib/nodeKind.js';
  import { formatDate } from '../../lib/utils.js';
  import { ROUTES } from '../../lib/constants.js';

  /**
   * AdminPage — the single admin surface (R8).
   *
   * Everything an operator can do to a node now lives behind this one page:
   * the up/down target switch, pending join decisions, designated
   * administrators, topology edits, value issue/burn and network membership.
   * While admin mode is locked the page shows the acknowledgement gate and
   * nothing about any node at all (R6).
   */
  let view = administeredNode;
  let locked = $derived(!adminLock.unlocked);
  let mock = $derived(isMockMode());
  let policy = $derived(adminPolicyInfo());

  let unlockOpen = $state(false);
  let loaded = $state(false);

  let canTopology = $derived(canAdministerTopology(view, adminCapabilities));
  let canValue = $derived(canAdministerValue(view, adminCapabilities));
  let onSelf = $derived(view.isSelf);

  let scopeLabel = $derived(
    view.isSelf
      ? 'this browser\u2019s own node'
      : `${view.label || shortId(view.nodeId)} at depth ${view.depth ?? '?'}`,
  );

  // ── Pending joins ──────────────────────────────────────────
  let joinConfirmOpen = $state(false);
  let joinAction = $state('approve'); // 'approve' | 'reject' | 'redeliver'
  let joinTarget = $state(null);
  let joinSlot = $state('');
  let joinReason = $state('');

  let pendingJoins = $derived(nodeState.joinRequests.filter((r) => r.status === 'pending'));

  async function loadJoins() {
    loadingState.joinRequests = true;
    errorState.joinRequests = null;
    try {
      nodeState.joinRequests = await getJoinRequests();
    } catch (err) {
      errorState.joinRequests = err?.message || 'Failed to load join requests';
    } finally {
      loadingState.joinRequests = false;
    }
  }

  // ── Topology ──────────────────────────────────────────────
  let selectedChild = $state(null);
  let moveOpen = $state(false);
  let moveSlot = $state(0);
  let detachOpen = $state(false);
  let detachBalance = $state(null);
  let actionBusy = $state(false);
  let designateBusy = $state(null); // endpointId of the in-flight designation

  const ALL_SLOTS = [0, 1, 2, 3, 4, 5, 6, 7];

  let occupiedSlots = $derived(
    new Set(
      nodeState.children
        .filter((child) => child.endpointId !== selectedChild?.endpointId)
        .map((child) => child.slot)
        .filter((slot) => slot != null),
    ),
  );
  let moveAllowed = $derived(canMoveChild(selectedChild?.kind));

  async function loadChildren() {
    loadingState.children = true;
    errorState.children = null;
    try {
      nodeState.children = await getChildren();
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

  async function loadValueAccounts() {
    try {
      const rows = await getAccounts();
      const liability = rows.filter((row) => row.type === 'liability');
      valueAccounts = liability;
      if (valueAccount && !liability.some((row) => row.id === valueAccount)) {
        valueAccount = null;
      }
    } catch {
      valueAccounts = [];
    }
  }

  // ── Designated administrators (read surface) ──────────────
  // The node reports its designated-admin set in the same admin query; this is
  // the authoritative list, not an inference from the child rows.
  let adminIds = $derived(new Set(nodeState.admins ?? []));

  async function loadAdministrators() {
    nodeState.admins = await getAdministrators();
  }

  async function reload() {
    if (locked) return;
    await Promise.all([loadJoins(), loadChildren(), loadAdministrators(), loadValueAccounts()]);
    loaded = true;
  }

  // Every target or lock change re-reads the lists; locked mode reads
  // nothing at all (the gate is the whole page).
  $effect(() => {
    void targetEpoch.value;
    void locked;
    selectedChild = null;
    if (locked) {
      nodeState.joinRequests = [];
      nodeState.children = [];
      nodeState.admins = [];
      valueAccounts = [];
      loaded = false;
      return;
    }
    void reload();
  });

  function handleRefresh() {
    void reload();
  }

  // ── Join decisions ────────────────────────────────────────
  function openJoinConfirm(action, request) {
    joinAction = action;
    joinTarget = request;
    joinSlot = '';
    joinReason = '';
    joinConfirmOpen = true;
  }

  function deliveryBadge(delivery) {
    if (!delivery) return { variant: 'muted', label: 'Unknown' };
    if (delivery === 'delivered') return { variant: 'ok', label: 'Delivered' };
    if (delivery === 'unreachable') return { variant: 'warn', label: 'Unreachable' };
    if (delivery === 'timed_out') return { variant: 'warn', label: 'Timed out' };
    if (delivery.startsWith('rejected:')) return { variant: 'danger', label: `Rejected (${delivery.split(':')[1]})` };
    return { variant: 'muted', label: delivery };
  }

  function showDeliveryToast(delivery, action) {
    if (delivery === 'delivered') {
      showToast(`${action} delivered successfully.`, 'ok');
    } else if (delivery === 'unreachable' || delivery === 'timed_out') {
      showToast(`${action} could not be delivered: ${delivery}. The child may be offline.`, 'warn', 6000);
    } else if (delivery?.startsWith('rejected:')) {
      showToast(`${action} rejected by the network: ${delivery.split(':')[1]}`, 'danger', 6000);
    } else {
      showToast(`${action} sent (delivery: ${delivery}).`, 'info');
    }
  }

  async function confirmJoinAction() {
    if (!joinTarget) return;
    try {
      if (joinAction === 'approve') {
        const slot = joinSlot.trim() ? Number(joinSlot.trim()) : null;
        if (slot !== null && (!Number.isInteger(slot) || slot < 0 || slot > 7)) {
          showToast('Slot must be an integer between 0 and 7.', 'warn');
          return;
        }
        const result = await approveJoin(joinTarget.endpointId, slot);
        showDeliveryToast(result.delivery, 'Approval');
      } else if (joinAction === 'reject') {
        const result = await rejectJoin(joinTarget.endpointId, joinReason.trim() || null);
        showDeliveryToast(result.delivery, 'Rejection');
      } else {
        const result = await redeliverJoin(joinTarget.endpointId);
        showDeliveryToast(result.delivery, 'Redelivery');
      }
      nodeState.joinRequests = nodeState.joinRequests.filter(
        (r) => r.endpointId !== joinTarget.endpointId,
      );
      await loadChildren();
    } catch (err) {
      if (err instanceof AdminUnavailableError) {
        showToast(err.message, 'danger', 8000);
      } else {
        showToast(`Action failed: ${err.message}`, 'danger');
      }
    }
    joinConfirmOpen = false;
    joinTarget = null;
  }

  function cancelJoinConfirm() {
    joinConfirmOpen = false;
    joinTarget = null;
  }

  // ── Designated administrators ─────────────────────────────
  /** Whether `child` is in the node's reported designation set. */
  function isDesignated(child) {
    return adminIds.has(child?.endpointId);
  }

  async function designate(child, on) {
    if (!child?.endpointId) return;
    designateBusy = child.endpointId;
    try {
      if (on) await adminDesignate(child.endpointId);
      else await adminRevoke(child.endpointId);
      showToast(
        on
          ? 'Designation request sent; the node applied or refused it.'
          : 'Revocation request sent; the node applied or refused it.',
        'ok',
      );
      // Re-read the set so the buttons reflect what the node actually applied.
      await loadAdministrators();
    } catch (err) {
      showToast(err?.message || 'Designation request failed.', 'danger', 7000);
    } finally {
      designateBusy = null;
    }
  }

  // ── Topology actions ──────────────────────────────────────
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
    if (canValue) {
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

  // ── New child (mock data source only) ─────────────────────
  let newChildSlot = $state(0);
  let newChildBusy = $state(false);

  async function handleCreateChild() {
    newChildBusy = true;
    try {
      const result = await createChild(newChildSlot);
      showToast(
        result?.address ? `Child created at ${result.address}.` : 'Child created.',
        'ok',
      );
      await loadChildren();
    } catch (err) {
      showToast(err?.message || 'Creating a child is not available here.', 'warn', 7000);
    } finally {
      newChildBusy = false;
    }
  }

  // ── Value issue / burn ────────────────────────────────────
  let valueAccounts = $state([]);
  let valueAccount = $state(null);
  let valueDialog = $state(null); // 'issue' | 'burn' | null
  let valueAmount = $state(0);
  let valueReason = $state('');
  let valueAmountTouched = $state(false);
  let valueReasonTouched = $state(false);
  let valueBusy = $state(false);
  let pendingOp = $state(readPendingValueOp());

  // The wasm value calls take the amount as an i64, so only a positive whole
  // number is valid; anything else is refused before the call.
  let valueAmountValid = $derived(Number.isInteger(valueAmount) && valueAmount > 0);
  let valueReasonValid = $derived(valueReason.trim().length > 0);
  let valueAmountError = $derived(valueReasonErrorVisible(valueAmountTouched, valueAmountValid));
  let valueReasonError = $derived(valueReasonErrorVisible(valueReasonTouched, valueReasonValid));
  let valueAccountRow = $derived(valueAccounts.find((row) => row.id === valueAccount) ?? null);

  function openValueDialog(direction) {
    if (!valueAccount) return;
    valueDialog = direction;
    valueAmount = 0;
    valueReason = '';
    valueAmountTouched = false;
    valueReasonTouched = false;
  }

  async function submitValue() {
    if (!valueAccount) return;
    valueAmountTouched = true;
    valueReasonTouched = true;
    if (!valueAmountValid || !valueReasonValid) return;
    valueBusy = true;
    try {
      const result =
        valueDialog === 'issue'
          ? await adminIssue(valueAccount, valueAmount, valueReason.trim())
          : await adminBurn(valueAccount, valueAmount, valueReason.trim());
      pendingOp = readPendingValueOp();
      if (result.status === 'duplicate') {
        showToast(`Already applied (seq ${result.seq}).`, 'warn');
      } else {
        showToast(
          `${valueDialog === 'issue' ? 'Issued' : 'Burned'} ${valueAmount}; new balance ${result.balanceAfter}.`,
          'ok',
        );
      }
      valueDialog = null;
      await loadValueAccounts();
    } catch (err) {
      pendingOp = readPendingValueOp();
      showToast(err?.message || 'Value operation failed.', 'danger', 8000);
    } finally {
      valueBusy = false;
    }
  }

  async function retryPending() {
    valueBusy = true;
    try {
      const result = await retryPendingValueOp();
      pendingOp = readPendingValueOp();
      if (result) showToast('Pending value operation applied.', 'ok');
      await loadValueAccounts();
    } catch (err) {
      pendingOp = readPendingValueOp();
      showToast(err?.message || 'Retry failed.', 'danger', 8000);
    } finally {
      valueBusy = false;
    }
  }

  function discardPending() {
    clearPendingValueOp();
    pendingOp = null;
    showToast('Pending value operation discarded.', 'warn');
  }

  // ── Membership (leave) ────────────────────────────────────
  let leaveOpen = $state(false);
  let leaveBusy = $state(false);

  async function confirmLeave() {
    leaveBusy = true;
    try {
      await leave();
      leaveOpen = false;
      showToast('Left the network. This browser has no parent now.', 'ok');
    } catch (err) {
      showToast(err?.message || 'Leave failed.', 'danger');
    } finally {
      leaveBusy = false;
    }
  }

  function handleLock() {
    lockAdminMode();
    showToast('Admin mode locked.', 'info');
  }

  let status = $derived(statusBadge(view.status));

  /** Short, stable hash for the "policy changed" note in the gate. */
  function shortHash(hash) {
    return hash ? String(hash).slice(0, 8) : '—';
  }

  /** Row label for one child, from its kind. */
  function childRole(child) {
    return childRoleLabel(child?.kind);
  }
</script>

<div class="admin-page">
  <PageHeader
    description={locked
      ? 'Admin mode is locked. Nothing about any node is shown until you acknowledge the admin policy.'
      : `Administering ${scopeLabel}. Every admin action below runs against that node.`}
  />

  {#if locked}
    <section class="gate" aria-labelledby="gate-title">
      <div class="gate-icon" aria-hidden="true">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" />
          <path d="M7 11V7a5 5 0 0110 0v4" />
        </svg>
      </div>
      <div class="gate-body">
        <h2 id="gate-title" class="gate-title">Admin mode is locked</h2>
        <p class="gate-lede">
          This page shows join requests, children, designated administrators, balances and
          membership controls for one node on the path from this browser to the root. All of
          it is hidden while the mode is locked.
        </p>
        <ul class="gate-list">
          <li>You must read and acknowledge <code>ADMIN_POLICY.md</code> before it unlocks.</li>
          <li>The unlock lasts for this session only &mdash; reloading the page locks it again.</li>
          <li>Only the hash of the policy you acknowledged is stored; the flag itself is memory.</li>
        </ul>
        {#if policy.acknowledgedHash}
          <p class="gate-note text-xs muted">
            {#if policy.acknowledgementCurrent}
              You acknowledged this policy
              {policy.acknowledgedAt ? `on ${formatDate(policy.acknowledgedAt)}` : 'before'}.
              Unlocking still needs a fresh tick.
            {:else}
              The policy changed since you last acknowledged it
              ({shortHash(policy.acknowledgedHash)}&hellip;). Read the current version.
            {/if}
          </p>
        {/if}
        <div class="gate-actions">
          <button type="button" class="btn btn--primary" onclick={() => (unlockOpen = true)}>
            Read the policy and unlock
          </button>
          <a class="link-btn" href="#{ROUTES.SETTINGS}">Admin settings</a>
        </div>
      </div>
    </section>
  {:else}
    <AdminTargetSwitcher variant="page" />

    <Card title="Target">
      {#snippet actions()}
        <button type="button" class="btn btn--ghost btn--sm" onclick={handleRefresh} disabled={loadingState.children && loadingState.joinRequests}>
          {loadingState.children || loadingState.joinRequests ? 'Loading…' : 'Refresh'}
        </button>
        <button type="button" class="btn btn--ghost btn--sm" onclick={handleLock}>
          Lock admin mode
        </button>
      {/snippet}

      <div class="target-grid">
        <div class="target-row">
          <span class="target-label muted">Address</span>
          {#if view.address}
            <Address address={view.address} size="md" />
          {:else}
            <span class="text-sm muted">Not assigned (or not reported)</span>
          {/if}
        </div>
        <div class="target-row">
          <span class="target-label muted">Node</span>
          {#if onSelf}
            <EndpointId id={clientState.endpointId} />
          {:else}
            <code class="text-sm mono">{view.nodeId}</code>
          {/if}
        </div>
        <div class="target-row">
          <span class="target-label muted">Kind</span>
          <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />
          <span class="text-xs muted">Inferred from the node&rsquo;s children.</span>
        </div>
        <div class="target-row">
          <span class="target-label muted">Status</span>
          <Badge variant={status.variant} label={status.label} />
          <span class="text-xs muted">Last observed {view.lastSeenAt ? formatDate(view.lastSeenAt) : 'never'}.</span>
        </div>
      </div>
    </Card>

    <!-- ── Pending joins ─────────────────────────────────── -->
    <Card title="Pending Joins">
      {#snippet actions()}
        <button
          type="button"
          class="btn btn--ghost btn--sm"
          onclick={loadJoins}
          disabled={loadingState.joinRequests}
        >
          {loadingState.joinRequests ? 'Loading…' : 'Refresh'}
        </button>
      {/snippet}

      {#if loadingState.joinRequests && !loaded}
        <LoadingSkeleton rows={2} />
      {:else if errorState.joinRequests}
        <ErrorState message={errorState.joinRequests} onRetry={loadJoins} />
      {:else if pendingJoins.length === 0}
        <EmptyState
          title="No pending requests"
          message={onSelf
            ? 'This browser\u2019s own node has no pending join requests. Step up to an ancestor to see theirs.'
            : `No join request is waiting on ${scopeLabel} right now.`}
        />
      {:else}
        <div class="request-list">
          {#each pendingJoins as request (request.endpointId)}
            <div class="request-row">
              <div class="request-info">
                <EndpointId id={request.endpointId} />
                <span class="muted text-xs">
                  {request.timestamp ? formatDate(request.timestamp) : 'time not reported'}
                </span>
                {#if request.slot != null}
                  <span class="text-xs muted">Slot {request.slot}</span>
                {/if}
                {#if request.kind}
                  <span class="text-xs muted">Kind {request.kind}</span>
                {/if}
              </div>
              <div class="request-actions">
                {#if request.delivery && request.delivery !== 'delivered'}
                  <button type="button" class="btn btn--ghost btn--sm" onclick={() => openJoinConfirm('redeliver', request)}>
                    Resend
                  </button>
                {/if}
                <button type="button" class="btn btn--ghost btn--sm" onclick={() => openJoinConfirm('reject', request)}>
                  Reject
                </button>
                <button type="button" class="btn btn--primary btn--sm" onclick={() => openJoinConfirm('approve', request)}>
                  Approve
                </button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </Card>

    <!-- ── Designated administrators ─────────────────────── -->
    <Card title="Designated Administrators">
      <p class="text-sm muted">
        A node administrator designates which of its children may administer it. Designating
        a child here sends the request to the node, which applies or refuses it.
      </p>
      <div class="notice" role="note">
        <strong class="text-xs">Reported by the node:</strong>
        <span class="text-xs">
          the list below shows this node&rsquo;s children and marks which of them currently
          hold the administrator role. Each button sends an idempotent request; the node has
          the final say and the list refreshes with its answer.
        </span>
      </div>

      {#if loadingState.children && !loaded}
        <LoadingSkeleton rows={2} />
      {:else if nodeState.children.length === 0}
        <EmptyState
          title="No children"
          message={onSelf
            ? 'This browser\u2019s own node has no children, so there is nobody to designate here.'
            : 'This node reports no children, so there is nobody to designate.'}
        />
      {:else}
        <ul class="admin-list">
          {#each nodeState.children as child (child.endpointId)}
            <li class="admin-row">
              <div class="admin-row-info">
                <EndpointId id={child.endpointId} />
                <span class="text-xs muted">
                  {childRole(child)}{child.address ? ` · ${child.address}` : ''}
                </span>
                {#if isDesignated(child)}
                  <Badge variant="ok" label="Designated administrator" />
                {/if}
              </div>
              <div class="admin-row-actions">
                <button
                  type="button"
                  class="btn btn--ghost btn--sm"
                  disabled={!canTopology || designateBusy === child.endpointId || isDesignated(child)}
                  onclick={() => designate(child, true)}
                >
                  {designateBusy === child.endpointId
                    ? 'Sending…'
                    : isDesignated(child)
                      ? 'Designated'
                      : 'Designate'}
                </button>
                <button
                  type="button"
                  class="btn btn--ghost btn--sm"
                  disabled={!canTopology || designateBusy === child.endpointId || !isDesignated(child)}
                  onclick={() => designate(child, false)}
                >
                  Revoke
                </button>
              </div>
            </li>
          {/each}
        </ul>
        {#if !canTopology}
          <p class="text-xs muted">
            Point admin mode at an ancestor (not this browser&rsquo;s own node) to send
            designation requests.
          </p>
        {/if}
      {/if}
    </Card>

    <!-- ── Topology ──────────────────────────────────────── -->
    <Card title="Topology">
      {#snippet actions()}
        <button type="button" class="btn btn--ghost btn--sm" onclick={loadChildren} disabled={loadingState.children}>
          {loadingState.children ? 'Loading…' : 'Refresh'}
        </button>
      {/snippet}

      {#if loadingState.children && nodeState.children.length === 0}
        <LoadingSkeleton rows={3} />
      {:else if errorState.children}
        <ErrorState message={errorState.children} onRetry={loadChildren} />
      {:else}
        <ChildrenTable
          rows={nodeState.children}
          emptyTitle="No children"
          emptyMessage={onSelf
            ? 'This browser\u2019s own node has no children of its own. Step up to an ancestor to administer its topology.'
            : 'This node\u2019s topology snapshot shows no children.'}
          selectedId={selectedChild?.endpointId ?? null}
          onSelect={canTopology ? handleSelectChild : undefined}
        />

        {#if canTopology}
          <div class="child-actions">
            <h4 class="section-heading">Child actions</h4>
            {#if !selectedChild}
              <p class="text-sm muted">Select a child row to re-slot or detach it.</p>
            {:else}
              <p class="text-sm muted">
                Selected <code class="mono">{shortId(selectedChild.endpointId)}</code>
                {#if selectedChild.address}at <code class="mono">{selectedChild.address}</code>{/if}
              </p>
              <div class="child-buttons">
                <button type="button" class="btn btn--ghost btn--sm" disabled={!moveAllowed || actionBusy} onclick={openMove}>
                  Re-slot…
                </button>
                <button type="button" class="btn btn--danger-outline btn--sm" disabled={actionBusy} onclick={openDetach}>
                  Detach…
                </button>
              </div>
              {#if !moveAllowed}
                <p class="text-xs muted">Browser leaves cannot be re-slotted (no healing pull).</p>
              {/if}
            {/if}
          </div>
        {/if}

        <div class="child-actions">
          <h4 class="section-heading">New child</h4>
          {#if mock}
            <div class="new-child">
              <label class="field-label" for="new-child-slot">Slot</label>
              <select id="new-child-slot" class="field-input" bind:value={newChildSlot}>
                {#each ALL_SLOTS as slot (slot)}
                  <option value={slot}>{slot}</option>
                {/each}
              </select>
              <button type="button" class="btn btn--ghost btn--sm" disabled={newChildBusy} onclick={handleCreateChild}>
                {newChildBusy ? 'Creating…' : 'Create child'}
              </button>
            </div>
          {:else}
            <p class="text-xs muted">
              Live mode has no create-child call in this web client: a child appears when you
              approve its join request above, or when the node operator creates one from the
              node&rsquo;s own tooling.
            </p>
          {/if}
        </div>
      {/if}
    </Card>

    <!-- ── Value issue / burn ────────────────────────────── -->
    <Card title="Value Issue &amp; Burn">
      {#snippet actions()}
        <button type="button" class="btn btn--ghost btn--sm" onclick={loadValueAccounts} disabled={!canValue}>
          Refresh
        </button>
      {/snippet}

      {#if !canValue}
        <EmptyState
          title="Point admin mode at an ancestor"
          message={locked
            ? 'Admin mode is locked.'
            : 'Issuing and burning value act on an ancestor node\u2019s books. Step up the chain with the switcher above, then come back here.'}
        />
      {:else}
        <p class="text-sm muted">
          Issue creates value on the target node and changes its equity; burn destroys it.
          Operator-configured limits (per-request, window, per-account) apply and are enforced
          by the node.
        </p>

        <div class="value-form">
          <label class="field-label" for="value-account">Account</label>
          <select id="value-account" class="field-input" bind:value={valueAccount}>
            <option value={null}>Select an account…</option>
            {#each valueAccounts as row (row.id ?? row.address)}
              <option value={row.id ?? row.address}>
                {row.label}{row.balance != null ? ` — ${row.balance}` : ''}
              </option>
            {/each}
          </select>

          {#if valueAccountRow}
            <p class="text-xs muted">
              Selected <code class="mono">{valueAccountRow.label}</code> · balance
              {valueAccountRow.balance}
            </p>
            <div class="value-buttons">
              <button type="button" class="btn btn--ghost btn--sm" disabled={valueBusy} onclick={() => openValueDialog('issue')}>
                Issue…
              </button>
              <button type="button" class="btn btn--danger-outline btn--sm" disabled={valueBusy} onclick={() => openValueDialog('burn')}>
                Burn…
              </button>
            </div>
          {:else if valueAccounts.length === 0}
            <p class="text-xs muted">No liability accounts were reported for this node.</p>
          {/if}
        </div>

        {#if pendingOp}
          <div class="pending-note">
            <span class="text-xs muted">
              A value operation is pending: {pendingOp.direction} {pendingOp.amount} on
              {pendingOp.account || 'an account'}. Retrying reuses the same idempotency key.
            </span>
            <div class="value-buttons">
              <button type="button" class="btn btn--ghost btn--sm" onclick={retryPending}>Retry</button>
              <button type="button" class="btn btn--ghost btn--sm" onclick={discardPending}>Discard</button>
            </div>
          </div>
        {/if}
      {/if}
    </Card>

    <!-- ── Network membership ────────────────────────────── -->
    <Card title="Network Membership">
      <p class="text-sm muted">
        Membership is a property of this browser&rsquo;s own client, not of the target above:
        leaving detaches this browser from its parent and clears its address.
      </p>
      <div class="membership">
        <div class="membership-row">
          <span class="text-sm">
            {#if clientState.address}
              This browser is joined as <code class="mono">{clientState.address}</code>.
            {:else}
              This browser is not joined to any parent.
            {/if}
          </span>
          {#if clientState.address}
            <button type="button" class="btn btn--danger-outline btn--sm" onclick={() => (leaveOpen = true)}>
              Leave network…
            </button>
          {/if}
        </div>
        <p class="text-xs muted">
          {#if clientState.address}
            After leaving, the Join tab reappears and you can rejoin with a fresh invitation.
          {:else}
            Rejoining needs an invitation from the node you want to join under. A non-browser
            node (a <code class="mono">cawala-node</code> instance) joins from its own operator
            tooling &mdash; this client only manages its own browser leaf.
          {/if}
        </p>
      </div>
    </Card>
  {/if}
</div>

<!-- Unlock gate -->
<AdminUnlockDialog open={unlockOpen} onCancel={() => (unlockOpen = false)} onUnlocked={() => (unlockOpen = false)} />

<!-- Join decision -->
<ConfirmDialog
  open={joinConfirmOpen}
  title={joinAction === 'approve' ? 'Approve Join Request' : joinAction === 'reject' ? 'Reject Join Request' : 'Redeliver Decision'}
  message={joinAction === 'approve'
    ? `Approve ${joinTarget?.endpointId?.slice(0, 20)}… as a child of ${scopeLabel}? It gets an address and becomes a permanent child.`
    : joinAction === 'reject'
      ? `Reject the join request from ${joinTarget?.endpointId?.slice(0, 20)}…? The requester must ask again.`
      : `Resend the previous decision for ${joinTarget?.endpointId?.slice(0, 20)}…?`}
  confirmLabel={joinAction === 'approve' ? 'Approve' : joinAction === 'reject' ? 'Reject' : 'Redeliver'}
  variant={joinAction === 'reject' ? 'danger' : 'default'}
  onConfirm={confirmJoinAction}
  onCancel={cancelJoinConfirm}
>
  {#if joinAction === 'approve'}
    <div class="field">
      <label class="field-label" for="join-slot">Slot (optional, 0-7)</label>
      <input id="join-slot" type="number" min="0" max="7" class="field-input" bind:value={joinSlot} />
      <span class="field-hint">Leave empty to let the node pick the lowest free slot.</span>
    </div>
  {:else if joinAction === 'reject'}
    <div class="field">
      <label class="field-label" for="join-reason">Reason (optional)</label>
      <input id="join-reason" type="text" class="field-input" placeholder="e.g. wrong parent" bind:value={joinReason} />
    </div>
  {/if}
</ConfirmDialog>

<!-- Re-slot -->
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

<!-- Detach -->
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
    <p class="text-sm">Current balance: <strong>{detachBalance.toLocaleString()}</strong></p>
  {/if}
</ConfirmDialog>

<!-- Value -->
<ConfirmDialog
  open={valueDialog !== null}
  title={valueDialog === 'burn' ? 'Burn value?' : 'Issue value?'}
  message={`This ${valueDialog === 'burn' ? 'destroys' : 'creates'} value on ${scopeLabel} and changes its equity. Operator limits apply; it cannot be undone except by a compensating operation.`}
  confirmLabel={valueBusy ? 'Working…' : valueDialog === 'burn' ? 'Burn' : 'Issue'}
  variant={valueDialog === 'burn' ? 'danger' : 'default'}
  onConfirm={submitValue}
  onCancel={() => { valueDialog = null; }}
>
  <div class="value-form">
    <label class="field-label" for="value-amount">Amount</label>
    <input
      id="value-amount"
      type="number"
      min="1"
      step="1"
      class="field-input"
      bind:value={valueAmount}
      oninput={() => { valueAmountTouched = true; }}
      disabled={valueBusy}
    />
    {#if valueAmountError}
      <span class="text-xs" style="color: var(--danger);">Enter a positive whole number.</span>
    {/if}
    <label class="field-label" for="value-reason">Reason (required)</label>
    <input
      id="value-reason"
      type="text"
      class="field-input"
      placeholder="e.g. operator top-up"
      bind:value={valueReason}
      oninput={() => { valueReasonTouched = true; }}
      disabled={valueBusy}
    />
    {#if valueReasonError}
      <span class="text-xs" style="color: var(--danger);">A reason is required.</span>
    {/if}
  </div>
</ConfirmDialog>

<!-- Leave -->
<ConfirmDialog
  open={leaveOpen}
  title="Leave the network?"
  message="This detaches this browser from its parent and clears its address. Your balance stops updating until you rejoin with a fresh invitation."
  confirmLabel={leaveBusy ? 'Leaving…' : 'Leave'}
  variant="danger"
  onConfirm={confirmLeave}
  onCancel={() => { leaveOpen = false; }}
/>

<style>
  .admin-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }

  /* ── Lock gate (R6) ─────────────────────────────── */
  .gate {
    display: flex;
    gap: var(--sp-4);
    padding: var(--sp-6);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-lg);
  }
  .gate-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 46px;
    height: 46px;
    flex-shrink: 0;
    border-radius: var(--radius-md);
    background: var(--accent-dim);
    color: var(--accent);
  }
  .gate-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    min-width: 0;
  }
  .gate-title {
    font-size: var(--text-xl);
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  .gate-lede {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
    max-width: 70ch;
  }
  .gate-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    font-size: var(--text-sm);
    color: var(--muted);
    padding-left: var(--sp-4);
  }
  .gate-list code {
    font-family: var(--mono);
    color: var(--fg);
  }
  .gate-note {
    color: var(--muted);
  }
  .gate-actions {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    margin-top: var(--sp-1);
    flex-wrap: wrap;
  }

  /* ── Target card ─────────────────────────────────── */
  .target-grid {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .target-row {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    flex-wrap: wrap;
  }
  .target-label {
    min-width: 90px;
    font-size: var(--text-sm);
    font-weight: 500;
  }

  /* ── Lists shared by joins / administrators ──────── */
  .request-list,
  .admin-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .request-row,
  .admin-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-3) var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    gap: var(--sp-4);
  }
  .request-info,
  .admin-row-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
  .request-actions,
  .admin-row-actions,
  .child-buttons,
  .value-buttons {
    display: flex;
    gap: var(--sp-2);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .notice {
    display: flex;
    gap: var(--sp-2);
    align-items: baseline;
    padding: var(--sp-3);
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--muted);
  }
  .notice strong {
    color: var(--warn);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .section-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .child-actions {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-4);
    padding-top: var(--sp-4);
    border-top: 1px solid var(--border);
  }
  .new-child {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }

  .value-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-3);
    max-width: 460px;
  }
  .pending-note {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-3);
    padding: var(--sp-3);
    border: 1px solid var(--warn);
    background: var(--warn-dim);
    border-radius: var(--radius-md);
  }

  .membership {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    margin-top: var(--sp-3);
  }
  .membership-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    flex-wrap: wrap;
    padding: var(--sp-3) var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  /* ── Controls ────────────────────────────────────── */
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
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover:not(:disabled) {
    background: var(--accent-hover);
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
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 600;
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .field-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .field-input {
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-sm);
  }
  .field-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .field-hint {
    font-size: var(--text-xs);
    color: var(--muted);
  }

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

  .mono {
    font-family: var(--mono);
  }

  @media (max-width: 767px) {
    .gate {
      flex-direction: column;
      padding: var(--sp-5);
    }
    .request-row,
    .admin-row {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
