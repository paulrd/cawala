<script>
  import Card from '../shared/Card.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { nodeState, loadingState, errorState, showToast } from '../../lib/stores.svelte.js';
  import { getJoinRequests, approveJoin, rejectJoin, isMockMode, AdminUnavailableError } from '../../lib/api.js';
  import { formatDate } from '../../lib/utils.js';

  let loaded = $state(false);

  // Confirm dialog state
  let confirmOpen = $state(false);
  let confirmAction = $state('approve'); // 'approve' | 'reject'
  let confirmTarget = $state(null);

  $effect(() => {
    if (!loaded) loadData();
  });

  async function loadData() {
    loadingState.joinRequests = true;
    try {
      nodeState.joinRequests = await getJoinRequests();
      loaded = true;
    } catch (err) {
      errorState.joinRequests = err.message;
    } finally {
      loadingState.joinRequests = false;
    }
  }

  function handleApprove(request) {
    confirmAction = 'approve';
    confirmTarget = request;
    confirmOpen = true;
  }

  function handleReject(request) {
    confirmAction = 'reject';
    confirmTarget = request;
    confirmOpen = true;
  }

  async function confirmAction_fn() {
    if (!confirmTarget) return;
    try {
      if (confirmAction === 'approve') {
        const result = await approveJoin(confirmTarget.endpointId);
        showToast(`Approved. Address ${result.address} assigned.`, 'ok');
      } else {
        await rejectJoin(confirmTarget.endpointId);
        showToast('Join request rejected.', 'info');
      }
      // Remove from pending list
      nodeState.joinRequests = nodeState.joinRequests.filter(
        (r) => r.endpointId !== confirmTarget.endpointId,
      );
    } catch (err) {
      if (err instanceof AdminUnavailableError) {
        showToast(
          'Admin actions are not available in the web client. Run this from the node CLI:\ncawala-node control approve|reject <endpoint-id>',
          'warn',
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
      <!-- Live mode: admin actions not available in the web client -->
      <div class="live-unavailable">
        <div class="unavailable-header">
          <Badge variant="info" label="Live mode" />
        </div>
        <p class="unavailable-desc">
          Pending join requests and admin actions are not available in the web client yet.
        </p>
        <p class="unavailable-cli muted text-sm">
          To manage join requests, use the node CLI:
        </p>
        <code class="unavailable-code">
          cawala-node control joins
        </code>
        <p class="unavailable-cli muted text-sm" style="margin-top: var(--sp-2);">
          To approve or reject:
        </p>
        <code class="unavailable-code">
          cawala-node control approve|reject &lt;endpoint-id&gt;
        </code>
      </div>
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
  title={confirmAction === 'approve' ? 'Approve Join Request' : 'Reject Join Request'}
  message={confirmAction === 'approve'
    ? `Approve ${confirmTarget?.endpointId?.slice(0, 20)}... as a child node? They will be assigned an address and become a permanent child of your node.`
    : `Reject this join request? The node will need to request again.`}
  confirmLabel={confirmAction === 'approve' ? 'Approve' : 'Reject'}
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
  .live-unavailable {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4) 0;
  }
  .unavailable-header {
    margin-bottom: var(--sp-1);
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
