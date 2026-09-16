<script>
  import Card from '../shared/Card.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { nodeState, loadingState, errorState, showToast } from '../../lib/stores.svelte.js';
  import { getJoinRequests, approveJoin, rejectJoin, redeliverJoin, isMockMode, getAdminNodes, AdminUnavailableError } from '../../lib/api.js';
  import { formatDate } from '../../lib/utils.js';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';

  let loaded = $state(false);

  // Confirm dialog state
  let confirmOpen = $state(false);
  let confirmAction = $state('approve'); // 'approve' | 'reject' | 'redeliver'
  let confirmTarget = $state(null);
  let confirmSlot = $state('');
  let confirmReason = $state('');

  // Live admin grant
  let adminNodes = $state([]);
  let activeGrant = $derived(adminNodes.find((n) => n.active && !isExpiredTs(n.expiresAt)));

  function isExpiredTs(ts) {
    return typeof ts === 'number' && ts < Date.now();
  }

  async function loadAdminInfo() {
    if (isMockMode()) return;
    try {
      adminNodes = getAdminNodes();
    } catch {
      adminNodes = [];
    }
  }

  $effect(() => {
    if (!loaded) loadData();
  });

  async function loadData() {
    loadingState.joinRequests = true;
    try {
      await loadAdminInfo();
      nodeState.joinRequests = await getJoinRequests();
      loaded = true;
    } catch (err) {
      errorState.joinRequests = err.message;
    } finally {
      loadingState.joinRequests = false;
    }
  }

  function handleRefresh() {
    loaded = false;
    loadData();
  }

  function handleApprove(request) {
    confirmAction = 'approve';
    confirmTarget = request;
    confirmSlot = '';
    confirmOpen = true;
  }

  function handleReject(request) {
    confirmAction = 'reject';
    confirmTarget = request;
    confirmReason = '';
    confirmOpen = true;
  }

  function handleRedeliver(request) {
    confirmAction = 'redeliver';
    confirmTarget = request;
    confirmOpen = true;
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
    const badge = deliveryBadge(delivery);
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

  async function confirmAction_fn() {
    if (!confirmTarget) return;
    try {
      if (confirmAction === 'approve') {
        const slot = confirmSlot.trim() ? Number(confirmSlot.trim()) : null;
        if (slot !== null && (!Number.isInteger(slot) || slot < 0 || slot > 7)) {
          showToast('Slot must be an integer between 0 and 7.', 'warn');
          return;
        }
        const result = await approveJoin(confirmTarget.endpointId, slot);
        showDeliveryToast(result.delivery, 'Approval');
        nodeState.joinRequests = nodeState.joinRequests.filter(
          (r) => r.endpointId !== confirmTarget.endpointId,
        );
      } else if (confirmAction === 'reject') {
        const result = await rejectJoin(confirmTarget.endpointId, confirmReason.trim() || null);
        showDeliveryToast(result.delivery, 'Rejection');
        nodeState.joinRequests = nodeState.joinRequests.filter(
          (r) => r.endpointId !== confirmTarget.endpointId,
        );
      } else if (confirmAction === 'redeliver') {
        const result = await redeliverJoin(confirmTarget.endpointId);
        showDeliveryToast(result.delivery, 'Redelivery');
      }
    } catch (err) {
      if (err instanceof AdminUnavailableError) {
        showToast(
          'Admin access expired or revoked. Ask the node operator to re-grant.',
          'danger',
          8000,
        );
      } else {
        showToast(`Action failed: ${err.message}`, 'danger');
      }
    }
    confirmOpen = false;
    confirmTarget = null;
  }

  function cancelConfirm() {
    confirmOpen = false;
    confirmTarget = null;
  }

  let pending = $derived(nodeState.joinRequests.filter((r) => r.status === 'pending'));
  let isLive = $derived(!isMockMode());
</script>

<div class="joins-page">
  <Card title="Pending Join Requests">
    {#if isLive}
      {#if !activeGrant}
        <!-- No active admin grant — setup card -->
        <div class="live-setup">
          <div class="live-setup-header">
            <Badge variant="info" label="Live mode" />
          </div>
          <p class="unavailable-desc">
            Approving join requests requires a delegated admin key. Generate one
            in Settings, then ask the node operator to grant it.
          </p>
          <button
            type="button"
            class="btn btn--primary"
            onclick={() => navigate(ROUTES.SETTINGS)}
          >
            Open Settings
          </button>
          <p class="unavailable-cli muted text-sm">
            Operator command:
          </p>
          <code class="unavailable-code">
            cawala-node control admin grant --key &lt;pubkey&gt; --label browser-admin
          </code>
        </div>
      {:else}
        <!-- Active grant — join requests -->
        <div class="live-header">
          <div class="live-header-left">
            <span class="text-sm muted">Administering:</span>
            <EndpointId id={activeGrant.nodeId} />
            {#if activeGrant.nodeAddr}
              <span class="text-xs muted header-address">
                <code>{activeGrant.nodeAddr}</code>
              </span>
              <Badge variant="ok" label="Tree-routed" />
            {:else}
              <Badge variant="muted" label="Direct only" />
            {/if}
          </div>
          <button
            type="button"
            class="btn btn--ghost btn--sm"
            onclick={handleRefresh}
            disabled={loadingState.joinRequests}
          >
            Refresh
          </button>
        </div>

        {#if loadingState.joinRequests && !loaded}
          <LoadingSkeleton rows={2} />
        {:else if errorState.joinRequests}
          <ErrorState message="Failed to load join requests" onRetry={handleRefresh} />
        {:else if pending.length === 0}
          <EmptyState
            title="No pending requests"
            message="Share your endpoint ID with nodes that want to join under you."
          />
        {:else}
          <div class="request-list">
            {#each pending as request}
              <div class="request-row">
                <div class="request-info">
                  <EndpointId id={request.endpointId} />
                  <span class="request-time muted text-sm">
                    {formatDate(request.timestamp)}
                  </span>
                  {#if request.requestedAddress}
                    <span class="text-xs muted">
                      Requested: <code>{request.requestedAddress}</code>
                    </span>
                  {/if}
                  {#if request.slot != null}
                    <span class="text-xs muted">
                      Slot: {request.slot}
                    </span>
                  {/if}
                  {#if request.kind}
                    <span class="text-xs muted">
                      Kind: {request.kind}
                    </span>
                  {/if}
                </div>
                <div class="request-actions">
                  {#if request.delivery && request.delivery !== 'delivered'}
                    <button type="button" class="btn btn--ghost btn--sm" onclick={() => handleRedeliver(request)}>
                      Resend
                    </button>
                  {/if}
                  <button type="button" class="btn btn--ghost" onclick={() => handleReject(request)}>
                    Reject
                  </button>
                  <button type="button" class="btn btn--primary" onclick={() => handleApprove(request)}>
                    Approve
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    {:else if loadingState.joinRequests && !loaded}
      <LoadingSkeleton rows={2} />
    {:else if errorState.joinRequests}
      <ErrorState message="Failed to load join requests" onRetry={loadData} />
    {:else if pending.length === 0}
      <EmptyState
        title="No pending requests"
        message="Share your endpoint ID with nodes that want to join under you."
      />
    {:else}
      <div class="request-list">
        {#each pending as request}
          <div class="request-row">
            <div class="request-info">
              <EndpointId id={request.endpointId} />
              <span class="request-time muted text-sm">
                {formatDate(request.timestamp)}
              </span>
              {#if request.requestedAddress}
                <span class="text-xs muted">
                  Requested: <code>{request.requestedAddress}</code>
                </span>
              {/if}
            </div>
            <div class="request-actions">
              <button type="button" class="btn btn--ghost" onclick={() => handleReject(request)}>
                Reject
              </button>
              <button type="button" class="btn btn--primary" onclick={() => handleApprove(request)}>
                Approve
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </Card>
</div>

<ConfirmDialog
  open={confirmOpen}
  title={confirmAction === 'approve' ? 'Approve Join Request' : confirmAction === 'reject' ? 'Reject Join Request' : 'Redeliver'}
  message={confirmAction === 'approve'
    ? `Approve ${confirmTarget?.endpointId?.slice(0, 20)}... as a child node? They will be assigned an address and become a permanent child of your node.`
    : confirmAction === 'reject'
    ? `Reject this join request? The node will need to request again.`
    : `Resend the previous decision for ${confirmTarget?.endpointId?.slice(0, 20)}...?`}
  confirmLabel={confirmAction === 'approve' ? 'Approve' : confirmAction === 'reject' ? 'Reject' : 'Redeliver'}
  variant={confirmAction === 'reject' ? 'danger' : 'default'}
  onConfirm={confirmAction_fn}
  onCancel={cancelConfirm}
/>

<style>
  .joins-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .request-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .request-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-3) var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    gap: var(--sp-4);
  }
  .request-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .request-time {
    font-size: var(--text-xs);
  }
  .request-actions {
    display: flex;
    gap: var(--sp-2);
    flex-shrink: 0;
  }
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
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover {
    background: var(--accent-hover);
  }
  .btn--ghost {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover {
    background: var(--bg-hover);
    color: var(--fg);
  }

  /* ── Live unavailable state ── */
  .live-setup {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4) 0;
  }
  .live-setup-header {
    margin-bottom: var(--sp-1);
  }
  .live-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-3) 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: var(--sp-2);
  }
  .live-header-left {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .header-address {
    display: inline-flex;
    align-items: center;
  }
  .btn--sm {
    padding: var(--sp-1) var(--sp-2);
    font-size: var(--text-xs);
  }
  .unavailable-desc {
    font-size: var(--text-sm);
    line-height: var(--leading-normal);
  }
  .unavailable-cli {
    font-size: var(--text-sm);
  }
  .unavailable-code {
    display: block;
    padding: var(--sp-3) var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font-family: var(--mono);
    font-size: var(--text-sm);
    color: var(--fg);
    overflow-x: auto;
  }

  @media (max-width: 480px) {
    .request-row {
      flex-direction: column;
      align-items: flex-start;
    }
    .request-actions {
      width: 100%;
    }
    .request-actions .btn {
      flex: 1;
    }
  }
</style>
