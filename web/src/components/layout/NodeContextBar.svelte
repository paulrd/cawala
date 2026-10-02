<script>
  import NodeSelector from '../admin/NodeSelector.svelte';
  import GrantStatusBanner from '../admin/GrantStatusBanner.svelte';
  import Badge from '../shared/Badge.svelte';
  import { administeredNode, clientState } from '../../lib/stores.svelte.js';
  import { probeAdminNode } from '../../lib/api.js';
  import { statusBadge, ADMIN_STATUS, needsGrantBanner } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import { formatTtl } from '../../lib/utils.js';
  import { CLIENT_STATUS } from '../../lib/constants.js';

  /**
   * NodeContextBar — the persistent strip under the top bar that says which
   * node this console is administering, what was last observed about it, and
   * whether the delegated key still allows queries.
   *
   * Layout (one shape for leaf and internal alike): selector, kind, address,
   * TTL/status, refresh. Expired/unreachable/revoked selections get the shared
   * GrantStatusBanner underneath.
   */
  let view = administeredNode;

  let probing = $state(false);
  let now = $state(Date.now());

  // Plain handle (never $state): a $effect that reads and writes a reactive
  // timer handle trips Svelte's infinite-loop guard.
  let _tick = null;

  $effect(() => {
    _tick = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => clearInterval(_tick);
  });

  /** Probe the selected node once (never throws). */
  async function runProbe(target) {
    if (!target || probing) return;
    probing = true;
    try {
      await probeAdminNode(target);
    } catch {
      /* probeAdminNode is already best-effort */
    } finally {
      probing = false;
      now = Date.now();
    }
  }

  // Probe on first readiness and whenever the selection changes: the selector
  // must show observed state (kind, address, reachability), never a guess.
  $effect(() => {
    const target = administeredNode.nodeId;
    const ready = clientState.status === CLIENT_STATUS.READY;
    if (!target || !ready) return;
    void runProbe(target);
  });

  let statusView = $derived(statusBadge(view.status));
  let addressText = $derived(view.address ?? view.nodeAddr ?? null);
  let showBanner = $derived(needsGrantBanner(view.status));
</script>

<div class="context-bar">
  <div class="context-row">
    <NodeSelector variant="bar" owner="bar" />

    <div class="context-chips" aria-live="polite">
      <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />

      {#if addressText}
        <span class="chip chip--mono text-xs" title="Last observed node address">
          Address {addressText}
        </span>
      {/if}

      {#if view.mock}
        <Badge variant="info" label="Mock mode" />
      {:else if view.grantExpiresAt}
        <span class="chip text-xs" class:chip--warn={view.grantExpiresAt - now < 6 * 3600_000}>
          Key {formatTtl(view.grantExpiresAt, now)}
        </span>
      {/if}

      <Badge variant={statusView.variant} label={probing ? 'Querying…' : statusView.label} />
    </div>

    <button
      type="button"
      class="context-refresh"
      class:context-refresh--busy={probing}
      disabled={probing}
      title="Re-query the selected node for its kind, address and reachability"
      aria-label="Refresh node status"
      onclick={() => runProbe(view.nodeId)}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M21 12a9 9 0 1 1-3-6.7" />
        <polyline points="21 3 21 9 15 9" />
      </svg>
      <span class="context-refresh-text">Refresh</span>
    </button>
  </div>

  {#if showBanner}
    <div class="context-banner">
      <GrantStatusBanner
        status={view.status}
        label={view.label ?? ''}
        expiresAt={view.grantExpiresAt}
        kind={view.kind}
      />
    </div>
  {/if}
</div>

<style>
  .context-bar {
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    padding: var(--sp-2) var(--sp-6);
  }
  .context-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    min-width: 0;
  }
  .context-chips {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
    min-width: 0;
    flex: 1;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    padding: 2px var(--sp-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--muted);
    white-space: nowrap;
  }
  .chip--mono {
    font-family: var(--mono);
  }
  .chip--warn {
    color: var(--warn);
    border-color: var(--warn);
  }
  .context-refresh {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    margin-left: auto;
    padding: var(--sp-1) var(--sp-2);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--muted);
    font: inherit;
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    transition:
      color var(--duration-fast) var(--ease),
      border-color var(--duration-fast) var(--ease);
  }
  .context-refresh:hover:not(:disabled) {
    color: var(--fg);
    border-color: var(--accent);
  }
  .context-refresh:disabled {
    cursor: not-allowed;
    opacity: 0.7;
  }
  .context-refresh--busy svg {
    animation: context-spin 900ms linear infinite;
  }
  .context-banner {
    margin-top: var(--sp-2);
  }

  @keyframes context-spin {
    to {
      transform: rotate(360deg);
    }
  }

  @media (max-width: 767px) {
    .context-bar {
      padding: var(--sp-2) var(--sp-4);
    }
    .context-refresh-text {
      display: none;
    }
    .chip--mono {
      max-width: 140px;
      overflow: hidden;
      text-overflow: ellipsis;
      display: inline-block;
    }
  }

  @media (max-width: 520px) {
    .context-row {
      flex-wrap: wrap;
    }
    .context-chips {
      order: 3;
      flex-basis: 100%;
    }
  }
</style>
