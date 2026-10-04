<script>
  import { untrack } from 'svelte';
  import AdminTargetSwitcher from '../admin/AdminTargetSwitcher.svelte';
  import Badge from '../shared/Badge.svelte';
  import { administeredNode, adminLock, clientState, targetEpoch } from '../../lib/stores.svelte.js';
  import { probeAdminNode } from '../../lib/api.js';
  import { statusBadge } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import { CLIENT_STATUS } from '../../lib/constants.js';

  /**
   * NodeContextBar — the persistent strip under the top bar that says which
   * ancestor admin mode is pointing at, what was last observed about it, and
   * whether admin mode is even unlocked.
   *
   * Layout (one shape for leaf and internal alike): up/down switcher, kind,
   * address, status, refresh. Nothing grant-shaped is shown here anymore: the
   * only gate is the session lock, which the switcher itself offers to open.
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

  /** Probe the current target once (never throws). */
  async function runProbe(target) {
    // Read the re-entrancy guard untracked: when this runs inside the
    // selection $effect below, a tracked read of `probing` would make the
    // effect depend on a value the probe writes, self-invalidating on every
    // flush and hanging the tab in Svelte's update loop.
    if (!target || untrack(() => probing)) return;
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

  // Probe whenever the target changes: the bar must show observed state
  // (kind, address, reachability), never a guess.
  $effect(() => {
    const target = view.nodeId;
    void targetEpoch.value;
    const ready = clientState.status === CLIENT_STATUS.READY;
    if (!target || !ready) return;
    void runProbe(target);
  });

  let statusView = $derived(statusBadge(view.status));
  let addressText = $derived(view.address ?? null);
</script>

<div class="context-bar">
  <div class="context-row">
    <AdminTargetSwitcher variant="bar" />

    <div class="context-chips" aria-live="polite">
      <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />

      {#if addressText}
        <span class="chip chip--mono text-xs" title="Last observed address of this target">
          Address {addressText}
        </span>
      {/if}

      {#if view.mock}
        <Badge variant="info" label="Mock mode" />
      {:else if adminLock.unlocked && view.isSelf}
        <span class="chip text-xs" title="Admin mode is unlocked but pointed at this browser">
          Unlocked
        </span>
      {/if}

      <Badge variant={statusView.variant} label={probing ? 'Querying…' : statusView.label} />
    </div>

    <button
      type="button"
      class="context-refresh"
      class:context-refresh--busy={probing}
      disabled={probing}
      title="Re-query the current target for its kind, address and reachability"
      aria-label="Refresh target status"
      onclick={() => runProbe(view.nodeId)}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M21 12a9 9 0 1 1-3-6.7" />
        <polyline points="21 3 21 9 15 9" />
      </svg>
      <span class="context-refresh-text">Refresh</span>
    </button>
  </div>
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
